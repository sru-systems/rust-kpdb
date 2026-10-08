// Copyright (c) 2025 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! The database writer for KeePass 4 (KDBX4) databases.

use super::kdb4;
use super::kdf;
use super::xml_writer;
use crate::common;
use crate::compression::gzip;
use crate::crypto::inner_cipher::InnerCipher;
use crate::crypto::random_gen::RandomGen;
use crate::crypto::{aes256, chacha20, hmac, sha256, sha512};
use crate::io::{write_hmac_blocks, Log};
use crate::types::variant_dictionary::{write_variant_map, VariantMap, VariantValue};
use crate::types::{
    Argon2Variant, BinariesMap, BinaryId, Comment, Compression, Database, Error, HeaderHash,
    KdfConfig, MasterCipher, MasterIV, MasterKey, MasterSeed, ProtectedStreamKey, Result,
    StreamCipher, TransformRounds, Version,
};
use byteorder::{LittleEndian, WriteBytesExt};
use std::io::Write;

/// Attempts to write the database content to the writer.
pub fn write<W: Log + Write>(writer: &mut W, db: &Database) -> Result<()> {
    let mut random = RandomGen::new()?;
    let master_seed = MasterSeed(random.next_32_bytes());
    let master_iv = match db.master_cipher {
        MasterCipher::Aes256 => MasterIV::Aes256(random.next_16_bytes()),
        MasterCipher::ChaCha20 => MasterIV::ChaCha20(random.next_12_bytes()),
    };
    let protected_stream_key = ProtectedStreamKey(random.next_64_bytes().to_vec());

    let (transformed_key, kdf_params) = match db.kdf {
        KdfConfig::AesKdf => {
            let transform_seed = random.next_32_bytes();
            let transformed = kdf::derive_key(
                &KdfConfig::AesKdf,
                &db.transform_rounds,
                &transform_seed,
                &db.composite_key,
            )?;
            let mut map = VariantMap::new();
            map.insert(String::from("$UUID"), VariantValue::ByteArray(kdf::AES_KDF_UUID.to_vec()));
            map.insert(String::from("S"), VariantValue::ByteArray(transform_seed.to_vec()));
            map.insert(String::from("R"), VariantValue::Uint64(db.transform_rounds.0));
            (transformed, map)
        }
        KdfConfig::Argon2 {
            iterations,
            memory,
            parallelism,
            version,
            ref variant,
        } => {
            let salt = random.next_32_bytes();
            let transformed =
                kdf::derive_key(&db.kdf, &TransformRounds(iterations), &salt, &db.composite_key)?;
            let uuid = match *variant {
                Argon2Variant::Argon2d => kdf::ARGON2_UUID,
                Argon2Variant::Argon2id => kdf::ARGON2ID_UUID,
            };
            let mut map = VariantMap::new();
            map.insert(String::from("$UUID"), VariantValue::ByteArray(uuid.to_vec()));
            map.insert(String::from("S"), VariantValue::ByteArray(salt.to_vec()));
            map.insert(String::from("I"), VariantValue::Uint64(iterations));
            map.insert(String::from("M"), VariantValue::Uint64(memory));
            map.insert(String::from("P"), VariantValue::Uint32(parallelism));
            map.insert(String::from("V"), VariantValue::Uint32(version));
            (transformed, map)
        }
    };

    write_sig_1(writer)?;
    write_sig_2(writer)?;
    write_version(writer, &db.version)?;
    write_comment(writer, &db.comment)?;
    write_master_cipher(writer, &db.master_cipher)?;
    write_compression(writer, &db.compression)?;
    write_master_seed(writer, &master_seed)?;
    write_encryption_iv(writer, &master_iv)?;
    write_kdf_parameters(writer, &kdf_params)?;
    write_end_header(writer)?;

    let header_hash = sha256::hash(&[writer.logged()]);
    let header_data = writer.logged().to_vec();
    writer.stop();
    writer.clear();

    let master_key = MasterKey::new(&master_seed, &transformed_key);
    let hmac_key = kdf::hmac_key(&master_seed, &transformed_key);
    let block_index: u64 = 0xffffffffffffffff;
    let header_hmac_key = sha512::hash(&[&block_index.to_le_bytes(), &hmac_key.0]);
    let header_hmac = hmac::hash(&header_hmac_key, &[&header_data])?;

    writer.write_all(&header_hash)?;
    writer.write_all(&header_hmac)?;

    let mut xml = Vec::new();
    let mut cipher = InnerCipher::new(&db.stream_cipher, &protected_stream_key);
    let header_hash = HeaderHash(header_hash.to_vec());
    xml_writer::write(&mut xml, db, &header_hash, &BinariesMap::new(), &mut cipher)?;

    let mut payload = Vec::new();
    write_inner_header(&mut payload, &db.stream_cipher, &protected_stream_key, &db.binaries)?;
    payload.extend_from_slice(&xml);

    let compressed = compress(&db.compression, &payload)?;
    let encrypted = match db.master_cipher {
        MasterCipher::Aes256 => aes256::encrypt(&master_key, &master_iv, &compressed)?,
        MasterCipher::ChaCha20 => chacha20::encrypt_master(&master_key, &master_iv, &compressed)?,
    };

    write_hmac_blocks(writer, &encrypted, &hmac_key)?;
    Ok(())
}

fn write_inner_header<W: Write>(
    writer: &mut W,
    stream_cipher: &StreamCipher,
    stream_key: &ProtectedStreamKey,
    binaries: &BinariesMap,
) -> Result<()> {
    write_inner_field(writer, kdb4::INNER_STREAM_ID_HID, |w| {
        let id = match *stream_cipher {
            StreamCipher::Salsa20 => kdb4::SALSA20_STREAM_ID,
            StreamCipher::ChaCha20 => kdb4::CHACHA20_STREAM_ID,
        };
        w.write_u32::<LittleEndian>(id)
    })?;
    write_inner_field(writer, kdb4::INNER_STREAM_KEY_HID, |w| w.write_all(&stream_key.0))?;
    for id in sorted_binary_ids(binaries)? {
        let data = &binaries[&id];
        write_inner_field(writer, kdb4::INNER_BINARY_HID, |w| {
            w.write_u8(0x01)?;
            w.write_all(data)
        })?;
    }
    write_inner_field(writer, kdb4::INNER_END_HID, |_| Ok(()))
}

fn write_inner_field<W: Write>(
    writer: &mut W,
    id: u8,
    write_data: impl FnOnce(&mut Vec<u8>) -> std::io::Result<()>,
) -> Result<()> {
    writer.write_u8(id)?;
    let mut data = Vec::new();
    write_data(&mut data)?;
    writer.write_u32::<LittleEndian>(data.len() as u32)?;
    if !data.is_empty() {
        writer.write_all(&data)?;
    }
    Ok(())
}

fn sorted_binary_ids(binaries: &BinariesMap) -> Result<Vec<BinaryId>> {
    let mut ids: Vec<(usize, BinaryId)> = Vec::new();
    for id in binaries.keys() {
        let index = id.0.parse::<usize>().map_err(|_| Error::InvalidData)?;
        ids.push((index, id.clone()));
    }
    ids.sort_by_key(|x| x.0);
    Ok(ids.into_iter().map(|(_, id)| id).collect())
}

fn write_bytes<W: Write>(writer: &mut W, bytes: &[u8]) -> Result<()> {
    writer.write_all(bytes)?;
    Ok(())
}

fn write_comment<W: Write>(writer: &mut W, comment: &Option<Comment>) -> Result<()> {
    if let Some(ref comment) = *comment {
        write_field(writer, kdb4::COMMENT_HID, comment.0.as_slice())
    } else {
        Ok(())
    }
}

fn write_compression<W: Write>(writer: &mut W, compression: &Compression) -> Result<()> {
    let id = match *compression {
        Compression::None => 0u32,
        Compression::GZip => 1u32,
    };
    write_field(writer, kdb4::COMPRESSION_FLAGS_HID, &id.to_le_bytes())
}

fn write_end_header<W: Write>(writer: &mut W) -> Result<()> {
    let bytes = [0x0d, 0x0a, 0x0d, 0x0a];
    write_field(writer, kdb4::END_HID, &bytes)
}

fn write_encryption_iv<W: Write>(writer: &mut W, iv: &MasterIV) -> Result<()> {
    write_field(writer, kdb4::ENCRYPTION_IV_HID, iv.as_bytes())
}

fn write_field<W: Write>(writer: &mut W, id: u8, data: &[u8]) -> Result<()> {
    writer.write_u8(id)?;
    writer.write_u32::<LittleEndian>(data.len() as u32)?;
    write_bytes(writer, data)
}

fn write_kdf_parameters<W: Write>(writer: &mut W, params: &VariantMap) -> Result<()> {
    let mut data = Vec::new();
    write_variant_map(&mut data, params)?;
    write_field(writer, kdb4::KDF_PARAMETERS_HID, &data)
}

fn write_master_cipher<W: Write>(writer: &mut W, cipher: &MasterCipher) -> Result<()> {
    match *cipher {
        MasterCipher::Aes256 => write_field(writer, kdb4::CIPHER_ID_HID, &kdb4::AES_CIPHER_ID),
        MasterCipher::ChaCha20 => {
            write_field(writer, kdb4::CIPHER_ID_HID, &kdb4::CHACHA20_CIPHER_ID)
        }
    }
}

fn write_master_seed<W: Write>(writer: &mut W, seed: &MasterSeed) -> Result<()> {
    write_field(writer, kdb4::MASTER_SEED_HID, &seed.0)
}

fn write_sig_1<W: Write>(writer: &mut W) -> Result<()> {
    write_bytes(writer, &common::DB_SIGNATURE)
}

fn write_sig_2<W: Write>(writer: &mut W) -> Result<()> {
    write_bytes(writer, &common::KDB2_SIGNATURE)
}

fn write_version<W: Write>(writer: &mut W, version: &Version) -> Result<()> {
    writer.write_u16::<LittleEndian>(version.minor)?;
    writer.write_u16::<LittleEndian>(version.major)?;
    Ok(())
}

fn compress(compression: &Compression, data: &[u8]) -> Result<Vec<u8>> {
    match *compression {
        Compression::None => Ok(data.to_vec()),
        Compression::GZip => gzip::encode(data),
    }
}
