// Copyright (c) 2025 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Module containing the header of the KeePass 4 (KDBX4) database format.

use super::kdb4;
use crate::types::{Comment, Compression, Error, MasterCipher, MasterSeed, Result};
use byteorder::{LittleEndian, ReadBytesExt};
use std::io::Read;

/// The header of the KDBX4 database.
#[derive(Debug, Default)]
pub struct Kdb4Header {
    /// Content of the comment header.
    pub comment: Option<Comment>,

    /// The compression algorithm.
    pub compression: Option<Compression>,

    /// The master encryption algorithm.
    pub master_cipher: Option<MasterCipher>,

    /// The master seed.
    pub master_seed: Option<MasterSeed>,

    /// The encryption IV (raw, resolved after reading the master cipher).
    pub encryption_iv: Option<Vec<u8>>,

    /// The raw bytes of the KDF parameters variant dictionary.
    pub kdf_parameters: Option<Vec<u8>>,

    /// The public custom data.
    pub public_custom_data: Option<Vec<u8>>,
}

impl Kdb4Header {
    /// Attempts to read the header from the reader.
    pub fn read<R: Read>(reader: &mut R) -> Result<Kdb4Header> {
        let mut header = Kdb4Header::default();
        loop {
            let id = reader.read_u8()?;
            let size = reader.read_u32::<LittleEndian>()?;

            match id {
                kdb4::END_HID => {
                    if size != 0 {
                        if size > u16::MAX as u32 {
                            return Err(Error::InvalidData);
                        }
                        read_bytes(reader, size as usize)?;
                    }
                    break;
                }
                kdb4::COMMENT_HID => {
                    header.comment = Some(Comment(read_bytes(reader, size as usize)?));
                }
                kdb4::CIPHER_ID_HID => {
                    check_header_size(id, size, kdb4::CIPHER_ID_SIZE)?;
                    let bytes = read_bytes_16(reader)?;
                    header.master_cipher = Some(parse_master_cipher(bytes)?);
                }
                kdb4::COMPRESSION_FLAGS_HID => {
                    check_header_size(id, size, kdb4::COMPRESSION_FLAGS_SIZE)?;
                    let value = reader.read_u32::<LittleEndian>()?;
                    header.compression = Some(parse_compression(value)?);
                }
                kdb4::MASTER_SEED_HID => {
                    check_header_size(id, size, kdb4::MASTER_SEED_SIZE)?;
                    header.master_seed = Some(MasterSeed(read_bytes_32(reader)?));
                }
                kdb4::TRANSFORM_SEED_HID => {
                    return Err(Error::UnhandledHeader(id));
                }
                kdb4::TRANSFORM_ROUNDS_HID => {
                    return Err(Error::UnhandledHeader(id));
                }
                kdb4::ENCRYPTION_IV_HID => {
                    if size != kdb4::ENCRYPTION_IV_AES_SIZE as u32
                        && size != kdb4::ENCRYPTION_IV_CHACHA20_SIZE as u32
                    {
                        return Err(error_invalid_header_size(
                            id,
                            size,
                            kdb4::ENCRYPTION_IV_AES_SIZE,
                        ));
                    }
                    header.encryption_iv = Some(read_bytes(reader, size as usize)?);
                }
                kdb4::PROTECTED_STREAM_KEY_HID => {
                    return Err(Error::UnhandledHeader(id));
                }
                kdb4::STREAM_START_BYTES_HID => {
                    return Err(Error::UnhandledHeader(id));
                }
                kdb4::INNER_RANDOM_STREAM_ID_HID => {
                    return Err(Error::UnhandledHeader(id));
                }
                kdb4::KDF_PARAMETERS_HID => {
                    header.kdf_parameters = Some(read_bytes(reader, size as usize)?);
                }
                kdb4::PUBLIC_CUSTOM_DATA_HID => {
                    header.public_custom_data = Some(read_bytes(reader, size as usize)?);
                }
                _ => {
                    // Unknown fields are ignored to remain compatible with implementations
                    // that add custom fields.
                    read_bytes(reader, size as usize)?;
                }
            }
        }
        Ok(header)
    }
}

fn check_header_size(id: u8, actual: u32, expected: u16) -> Result<()> {
    if actual == expected as u32 {
        Ok(())
    } else {
        Err(error_invalid_header_size(id, actual, expected))
    }
}

fn error_invalid_header_size(id: u8, actual: u32, expected: u16) -> Error {
    if actual <= u16::MAX as u32 {
        Error::InvalidHeaderSize {
            id,
            expected,
            actual: actual as u16,
        }
    } else {
        Error::InvalidData
    }
}

fn parse_compression(value: u32) -> Result<Compression> {
    match value {
        0 => Ok(Compression::None),
        1 => Ok(Compression::GZip),
        _ => Err(Error::UnhandledCompression(value)),
    }
}

fn parse_master_cipher(bytes: [u8; 16]) -> Result<MasterCipher> {
    if bytes == kdb4::AES_CIPHER_ID {
        Ok(MasterCipher::Aes256)
    } else if bytes == kdb4::CHACHA20_CIPHER_ID {
        Ok(MasterCipher::ChaCha20)
    } else {
        Err(Error::UnhandledMasterCipher(bytes))
    }
}

fn read_bytes<R: Read>(reader: &mut R, size: usize) -> Result<Vec<u8>> {
    let mut data = vec![0u8; size];
    reader.read_exact(&mut data)?;
    Ok(data)
}

fn read_bytes_16<R: Read>(reader: &mut R) -> Result<[u8; 16]> {
    Ok(read_bytes(reader, 16)?.try_into().unwrap())
}

fn read_bytes_32<R: Read>(reader: &mut R) -> Result<[u8; 32]> {
    Ok(read_bytes(reader, 32)?.try_into().unwrap())
}
