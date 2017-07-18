// Copyright (c) 2016-2017 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! The database reader for KeePass 2 databases.

use byteorder::{LittleEndian, ReadBytesExt};
use compression::gzip;
use crypto::aes256;
use crypto::sha256;
use io::Log;
use std::io::{Cursor, Read};
use super::kdb2;
use super::kdb2_xml_reader;
use types::Comment;
use types::CompositeKey;
use types::Compression;
use types::Error;
use types::HeaderHash;
use types::MasterCipher;
use types::MasterIV;
use types::MasterKey;
use types::MasterSeed;
use types::MetaData;
use types::ProtectedStreamKey;
use types::Result;
use types::StreamCipher;
use types::StreamKey;
use types::StreamStartBytes;
use types::TransformRounds;
use types::TransformSeed;
use types::TransformedKey;
use types::Version;
use types::XmlData;

/// Attempts to read the database content from the reader.
pub fn read<R>(reader: &mut R, composite_key: &CompositeKey) -> Result<(MetaData, XmlData)>
where
    R: Log + Read,
{
    let version = try!(read_version(reader));
    let mut comment: Option<Comment> = None;
    let mut compression: Option<Compression> = None;
    let mut master_cipher: Option<MasterCipher> = None;
    let mut master_iv: Option<MasterIV> = None;
    let mut master_seed: Option<MasterSeed> = None;
    let mut protected_stream_key: Option<ProtectedStreamKey> = None;
    let mut stream_cipher: Option<StreamCipher> = None;
    let mut stream_start_bytes: Option<StreamStartBytes> = None;
    let mut transform_rounds: Option<TransformRounds> = None;
    let mut transform_seed: Option<TransformSeed> = None;

    loop {
        let header_id = try!(reader.read_u8());
        match header_id {
            kdb2::COMMENT_HID => {
                comment = Some(try!(read_comment(reader)));
            }

            kdb2::COMPRESSION_HID => {
                compression = Some(try!(read_compression(reader)));
            }

            kdb2::END_HID => {
                try!(read_end_header(reader));
                break;
            }

            kdb2::MASTER_CIPHER_HID => {
                master_cipher = Some(try!(read_master_cipher(reader)));
            }

            kdb2::MASTER_IV_HID => {
                master_iv = Some(try!(read_master_iv(reader)));
            }

            kdb2::MASTER_SEED_HID => {
                master_seed = Some(try!(read_master_seed(reader)));
            }

            kdb2::PROTECTED_STREAM_KEY_HID => {
                protected_stream_key = Some(try!(read_protected_stream_key(reader)));
            }

            kdb2::STREAM_CIPHER_HID => {
                stream_cipher = Some(try!(read_stream_cipher(reader)));
            }

            kdb2::STREAM_START_BYTES_HID => {
                stream_start_bytes = Some(try!(read_stream_start_bytes(reader)));
            }

            kdb2::TRANSFORM_ROUNDS_HID => {
                transform_rounds = Some(try!(read_transform_rounds(reader)));
            }

            kdb2::TRANSFORM_SEED_HID => {
                transform_seed = Some(try!(read_transform_seed(reader)));
            }

            _ => return Err(Error::UnhandledHeader(header_id)),
        }
    }

    let header_hash = HeaderHash(sha256::hash(&[reader.logged()]).to_vec());
    reader.stop();
    reader.clear();

    let compression = try!(get_header(compression, kdb2::COMPRESSION_HID));
    let master_cipher = try!(get_header(master_cipher, kdb2::MASTER_CIPHER_HID));
    let master_iv = try!(get_header(master_iv, kdb2::MASTER_IV_HID));
    let master_seed = try!(get_header(master_seed, kdb2::MASTER_SEED_HID));
    let protected_stream_key =
        try!(get_header(protected_stream_key, kdb2::PROTECTED_STREAM_KEY_HID));
    let stream_cipher = try!(get_header(stream_cipher, kdb2::STREAM_CIPHER_HID));
    let stream_start_bytes = try!(get_header(stream_start_bytes, kdb2::STREAM_START_BYTES_HID));
    let transform_rounds = try!(get_header(transform_rounds, kdb2::TRANSFORM_ROUNDS_HID));
    let transform_seed = try!(get_header(transform_seed, kdb2::TRANSFORM_SEED_HID));

    let transformed_key = TransformedKey::new(&composite_key, &transform_seed, &transform_rounds);
    let master_key = MasterKey::new(&master_seed, &transformed_key);
    let stream_key = StreamKey::new(&protected_stream_key);

    let encrypted = try!(read_enc_payload(reader));
    let payload = try!(aes256::decrypt(&master_key, &master_iv, &encrypted));

    if payload[0..32] != stream_start_bytes.0 {
        return Err(Error::InvalidKey);
    }

    let xml_bytes = try!(read_xml_bytes(&compression, &payload[32..]));
    let xml_data = try!(kdb2_xml_reader::read(&mut Cursor::new(xml_bytes), &stream_key));
    let meta_data = MetaData {
        comment: comment,
        compression: compression,
        header_hash: header_hash,
        master_cipher: master_cipher,
        stream_cipher: stream_cipher,
        transform_rounds: transform_rounds,
        version: version,
    };

    Ok((meta_data, xml_data))
}

fn read_comment<R: Read>(reader: &mut R) -> Result<Comment> {
    let size = try!(reader.read_u16::<LittleEndian>()) as usize;
    let data = try!(read_bytes_size(reader, &size));
    Ok(Comment(data))
}

fn read_compression<R: Read>(reader: &mut R) -> Result<Compression> {
    let size = try!(reader.read_u16::<LittleEndian>());
    if size == kdb2::COMPRESSION_SIZE {
        let data = try!(reader.read_u32::<LittleEndian>());
        match data {
            0 => Ok(Compression::None),
            1 => Ok(Compression::GZip),
            _ => Err(Error::UnhandledCompression(data)),
        }
    } else {
        Err(Error::InvalidHeaderSize {
            id: kdb2::COMPRESSION_HID,
            expected: kdb2::COMPRESSION_SIZE,
            actual: size,
        })
    }
}

fn read_end_header<R: Read>(reader: &mut R) -> Result<()> {
    let size = try!(reader.read_u16::<LittleEndian>()) as usize;
    try!(read_bytes_size(reader, &size));
    Ok(())
}

fn read_enc_payload<R: Read>(reader: &mut R) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    try!(reader.read_to_end(&mut data));
    Ok(data)
}

fn read_master_cipher<R: Read>(reader: &mut R) -> Result<MasterCipher> {
    let size = try!(reader.read_u16::<LittleEndian>());
    if size == kdb2::MASTER_CIPHER_SIZE {
        let data = try!(read_bytes_16(reader));
        if data == &kdb2::AES_CIPHER_ID[..] {
            Ok(MasterCipher::Aes256)
        } else {
            Err(Error::UnhandledMasterCipher(data))
        }
    } else {
        Err(Error::InvalidHeaderSize {
            id: kdb2::MASTER_CIPHER_HID,
            expected: kdb2::MASTER_CIPHER_SIZE,
            actual: size,
        })
    }
}

fn read_master_iv<R: Read>(reader: &mut R) -> Result<MasterIV> {
    let size = try!(reader.read_u16::<LittleEndian>());
    if size == kdb2::MASTER_IV_SIZE {
        let data = try!(read_bytes_16(reader));
        Ok(MasterIV(data))
    } else {
        Err(Error::InvalidHeaderSize {
            id: kdb2::MASTER_IV_HID,
            expected: kdb2::MASTER_IV_SIZE,
            actual: size,
        })
    }
}

fn read_master_seed<R: Read>(reader: &mut R) -> Result<MasterSeed> {
    let size = try!(reader.read_u16::<LittleEndian>());
    if size == kdb2::MASTER_SEED_SIZE {
        let data = try!(read_bytes_32(reader));
        Ok(MasterSeed(data))
    } else {
        Err(Error::InvalidHeaderSize {
            id: kdb2::MASTER_SEED_HID,
            expected: kdb2::MASTER_SEED_SIZE,
            actual: size,
        })
    }
}

fn read_protected_stream_key<R: Read>(reader: &mut R) -> Result<ProtectedStreamKey> {
    let size = try!(reader.read_u16::<LittleEndian>());
    if size == kdb2::PROTECTED_STREAM_KEY_SIZE {
        let data = try!(read_bytes_32(reader));
        Ok(ProtectedStreamKey(data))
    } else {
        Err(Error::InvalidHeaderSize {
            id: kdb2::PROTECTED_STREAM_KEY_HID,
            expected: kdb2::PROTECTED_STREAM_KEY_SIZE,
            actual: size,
        })
    }
}

fn read_stream_cipher<R: Read>(reader: &mut R) -> Result<StreamCipher> {
    let size = try!(reader.read_u16::<LittleEndian>());
    if size == kdb2::STREAM_CIPHER_SIZE {
        let data = try!(reader.read_u32::<LittleEndian>());
        match data {
            2 => Ok(StreamCipher::Salsa20),
            _ => Err(Error::UnhandledStreamCipher(data)),
        }
    } else {
        Err(Error::InvalidHeaderSize {
            id: kdb2::STREAM_CIPHER_HID,
            expected: kdb2::STREAM_CIPHER_SIZE,
            actual: size,
        })
    }
}

fn read_stream_start_bytes<R: Read>(reader: &mut R) -> Result<StreamStartBytes> {
    let size = try!(reader.read_u16::<LittleEndian>());
    if size == kdb2::STREAM_START_BYTES_SIZE {
        let data = try!(read_bytes_32(reader));
        Ok(StreamStartBytes(data))
    } else {
        Err(Error::InvalidHeaderSize {
            id: kdb2::STREAM_START_BYTES_HID,
            expected: kdb2::STREAM_START_BYTES_SIZE,
            actual: size,
        })
    }
}

fn read_transform_rounds<R: Read>(reader: &mut R) -> Result<TransformRounds> {
    let size = try!(reader.read_u16::<LittleEndian>());
    if size == kdb2::TRANSFORM_ROUNDS_SIZE {
        let data = try!(reader.read_u64::<LittleEndian>());
        Ok(TransformRounds(data))
    } else {
        Err(Error::InvalidHeaderSize {
            id: kdb2::TRANSFORM_ROUNDS_HID,
            expected: kdb2::TRANSFORM_ROUNDS_SIZE,
            actual: size,
        })
    }
}

fn read_transform_seed<R: Read>(reader: &mut R) -> Result<TransformSeed> {
    let size = try!(reader.read_u16::<LittleEndian>());
    if size == kdb2::TRANSFORM_SEED_SIZE {
        let data = try!(read_bytes_32(reader));
        Ok(TransformSeed(data))
    } else {
        Err(Error::InvalidHeaderSize {
            id: kdb2::TRANSFORM_SEED_HID,
            expected: kdb2::TRANSFORM_SEED_SIZE,
            actual: size,
        })
    }
}

fn read_version<R: Read>(reader: &mut R) -> Result<Version> {
    let minor = try!(reader.read_u16::<LittleEndian>());
    let major = try!(reader.read_u16::<LittleEndian>());
    Ok(Version {
        major: major,
        minor: minor,
    })
}

fn read_xml_bytes(compression: &Compression, payload: &[u8]) -> Result<Vec<u8>> {
    let mut reader = Cursor::new(payload);
    let mut xml = Vec::new();

    for block_id in 0..u32::max_value() {
        let id = try!(reader.read_u32::<LittleEndian>());
        let hash = try!(read_bytes_32(&mut reader));
        let size = try!(reader.read_u32::<LittleEndian>()) as usize;
        let raw_data = try!(read_bytes_size(&mut reader, &size));

        if id != block_id {
            return Err(Error::InvalidBlockId(id));
        }

        if size == 0 {
            if hash == kdb2::FINAL_BLOCK_HASH {
                break;
            } else {
                return Err(Error::InvalidFinalBlockHash(hash));
            }
        }

        let block_hash = sha256::hash(&[&raw_data]);
        if block_hash != hash {
            return Err(Error::InvalidBlockHash);
        }

        let mut block_data = try!(decompress(compression, &raw_data));
        xml.append(&mut block_data);

    }

    Ok(xml)
}

fn read_bytes_16<R: Read>(reader: &mut R) -> Result<[u8; 16]> {
    let mut data = [0; 16];
    try!(reader.read(&mut data));
    Ok(data)
}

fn read_bytes_32<R: Read>(reader: &mut R) -> Result<[u8; 32]> {
    let mut data = [0; 32];
    try!(reader.read(&mut data));
    Ok(data)
}

fn read_bytes_size<R: Read>(reader: &mut R, size: &usize) -> Result<Vec<u8>> {
    let mut data = vec![0; *size];
    try!(reader.read(&mut data));
    Ok(data)
}

fn get_header<T>(header: Option<T>, header_id: u8) -> Result<T> {
    header.ok_or(Error::MissingHeader(header_id))
}

fn decompress(compression: &Compression, data: &[u8]) -> Result<Vec<u8>> {
    match *compression {
        Compression::None => Ok(data.to_vec()),
        Compression::GZip => gzip::decode(data),
    }
}
