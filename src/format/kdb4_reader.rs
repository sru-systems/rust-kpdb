// Copyright (c) 2025 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! The database reader for KeePass 4 (KDBX4) databases.

use super::kdb4;
use super::xml_reader;
use super::{kdb4_header::Kdb4Header, kdf};
use crate::compression::gzip;
use crate::crypto::inner_cipher::InnerCipher;
use crate::crypto::{aes256, chacha20, hmac, sha256, sha512};
use crate::io::{HmacBlockReader, Log};
use crate::types::variant_dictionary::read_variant_map;
use crate::types::{BinariesMap, BinaryId, Error, HeaderHash, MetaData, Result, Version, XmlData};
use crate::types::{
    CompositeKey, Compression, MasterCipher, MasterIV, MasterKey, ProtectedStreamKey, StreamCipher,
};
use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{Cursor, Read};

/// Attempts to read the database content from the reader.
pub fn read<R>(
    reader: &mut R,
    composite_key: &CompositeKey,
    version: Version,
) -> Result<(MetaData, XmlData)>
where
    R: Log + Read,
{
    let header = Kdb4Header::read(reader)?;
    let header_data = reader.logged().to_vec();
    reader.stop();
    reader.clear();

    let header_hash = sha256::hash(&[&header_data]);
    let mut expected_hash = [0u8; 32];
    reader.read_exact(&mut expected_hash)?;
    if header_hash != expected_hash {
        return Err(Error::InvalidHeaderHash);
    }

    let mut expected_hmac = [0u8; 32];
    reader.read_exact(&mut expected_hmac)?;

    let compression = header
        .compression
        .ok_or(Error::MissingHeader(kdb4::COMPRESSION_FLAGS_HID))?;
    let master_cipher = header
        .master_cipher
        .ok_or(Error::MissingHeader(kdb4::CIPHER_ID_HID))?;
    let master_seed = header
        .master_seed
        .ok_or(Error::MissingHeader(kdb4::MASTER_SEED_HID))?;
    let encryption_iv = header
        .encryption_iv
        .ok_or(Error::MissingHeader(kdb4::ENCRYPTION_IV_HID))?;

    let kdf_params = header.kdf_parameters.as_ref().ok_or(Error::InvalidData)?;
    let mut cursor = Cursor::new(kdf_params);
    let variant_map = read_variant_map(&mut cursor)?;
    let (kdf_config, kdf_salt, transform_rounds) = kdf::parse_kdf_parameters(&variant_map)?;

    let transformed_key =
        kdf::derive_key(&kdf_config, &transform_rounds, &kdf_salt, composite_key)?;

    let hmac_key = kdf::hmac_key(&master_seed, &transformed_key);

    // Verify the HMAC over the header. The key for the header HMAC is derived
    // by hashing the block index 2^64-1 with the HMAC key.
    let block_index: u64 = 0xffffffffffffffff;
    let header_hmac_key = sha512::hash(&[&block_index.to_le_bytes(), &hmac_key.0]);
    if !hmac::verify(&header_hmac_key, &[&header_data], &expected_hmac)? {
        return Err(Error::InvalidKey);
    }

    let mut hmac_reader = HmacBlockReader::new(reader, hmac_key);
    let mut encrypted_payload = Vec::new();
    hmac_reader.read_to_end(&mut encrypted_payload)?;

    let master_key = MasterKey::new(&master_seed, &transformed_key);
    let master_iv = MasterIV::new(&master_cipher, &encryption_iv)?;

    let decrypted_payload = match master_cipher {
        MasterCipher::Aes256 => aes256::decrypt(&master_key, &master_iv, &encrypted_payload)?,
        MasterCipher::ChaCha20 => {
            chacha20::decrypt_master(&master_key, &master_iv, &encrypted_payload)?
        }
    };

    let decompressed = match compression {
        Compression::None => decrypted_payload,
        Compression::GZip => gzip::decode(&decrypted_payload)?,
    };

    let (stream_cipher, stream_key, binaries, xml_bytes) = read_inner(&decompressed)?;

    let mut cipher = InnerCipher::new(&stream_cipher, &stream_key);
    let mut xml_data = xml_reader::read(&mut Cursor::new(&xml_bytes), &mut cipher)?;
    if !binaries.is_empty() {
        xml_data.binaries = binaries;
    }

    let meta_data = MetaData {
        comment: header.comment,
        compression,
        header_hash: HeaderHash(header_hash.to_vec()),
        master_cipher,
        stream_cipher,
        transform_rounds,
        kdf: kdf_config,
        version,
    };

    Ok((meta_data, xml_data))
}

fn read_inner(data: &[u8]) -> Result<(StreamCipher, ProtectedStreamKey, BinariesMap, Vec<u8>)> {
    let mut cursor = Cursor::new(data);
    let mut stream_cipher: Option<StreamCipher> = None;
    let mut stream_key: Option<ProtectedStreamKey> = None;
    let mut binaries = BinariesMap::new();

    loop {
        let id = cursor.read_u8().map_err(|_| Error::InvalidData)?;
        let size = cursor
            .read_u32::<LittleEndian>()
            .map_err(|_| Error::InvalidData)? as usize;
        let mut field_data = vec![0u8; size];
        if size > 0 {
            cursor
                .read_exact(&mut field_data)
                .map_err(|_| Error::InvalidData)?;
        }

        match id {
            kdb4::INNER_END_HID => break,
            kdb4::INNER_STREAM_ID_HID => {
                if field_data.len() != 4 {
                    return Err(Error::InvalidData);
                }
                let value = Cursor::new(field_data).read_u32::<LittleEndian>()?;
                stream_cipher = Some(match value {
                    2 => StreamCipher::Salsa20,
                    3 => StreamCipher::ChaCha20,
                    _ => return Err(Error::UnhandledStreamCipher(value)),
                });
            }
            kdb4::INNER_STREAM_KEY_HID => {
                stream_key = Some(ProtectedStreamKey(field_data));
            }
            kdb4::INNER_BINARY_HID => {
                if field_data.is_empty() {
                    return Err(Error::InvalidData);
                }
                let index = binaries.len().to_string();
                binaries.insert(BinaryId(index), field_data[1..].to_vec());
            }
            _ => {
                // Unknown inner header fields are ignored.
            }
        }
    }

    let stream_cipher = stream_cipher.ok_or(Error::MissingHeader(kdb4::INNER_STREAM_ID_HID))?;
    let stream_key = stream_key.ok_or(Error::MissingHeader(kdb4::INNER_STREAM_KEY_HID))?;
    let xml_offset = cursor.position() as usize;
    let xml_bytes = data[xml_offset..].to_vec();

    Ok((stream_cipher, stream_key, binaries, xml_bytes))
}
