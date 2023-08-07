// Copyright (c) 2016-2017 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! The database writer for KeePass 2 databases.

use super::{kdb2, kdb2_xml_writer};
use crate::common;
use crate::compression::gzip;
use crate::crypto::aes256;
use crate::crypto::random_gen::RandomGen;
use crate::crypto::sha256;
use crate::io::Log;
use crate::types::Comment;
use crate::types::Compression;
use crate::types::Database;
use crate::types::HeaderHash;
use crate::types::MasterCipher;
use crate::types::MasterIV;
use crate::types::MasterKey;
use crate::types::MasterSeed;
use crate::types::ProtectedStreamKey;
use crate::types::Result;
use crate::types::StreamCipher;
use crate::types::StreamKey;
use crate::types::StreamStartBytes;
use crate::types::TransformRounds;
use crate::types::TransformSeed;
use crate::types::TransformedKey;
use crate::types::Version;
use byteorder::{LittleEndian, WriteBytesExt};
use std::io::Write;

/// Attempts to write the database content to the writer.
pub fn write<W: Log + Write>(writer: &mut W, db: &Database) -> Result<()> {
    let mut random = RandomGen::new()?;
    let transform_seed = TransformSeed(random.next_32_bytes());
    let transformed_key =
        TransformedKey::new(&db.composite_key, &transform_seed, &db.transform_rounds);
    let master_iv = MasterIV(random.next_16_bytes());
    let master_seed = MasterSeed(random.next_32_bytes());
    let master_key = MasterKey::new(&master_seed, &transformed_key);
    let protected_stream_key = ProtectedStreamKey(random.next_32_bytes());
    let stream_key = StreamKey::new(&protected_stream_key);
    let stream_start_bytes = StreamStartBytes(random.next_32_bytes());

    write_sig_1(writer)?;
    write_sig_2(writer)?;
    write_version(writer, &db.version)?;
    write_comment(writer, &db.comment)?;
    write_master_cipher(writer, &db.master_cipher)?;
    write_compression(writer, &db.compression)?;
    write_master_seed(writer, &master_seed)?;
    write_transform_seed(writer, &transform_seed)?;
    write_transform_rounds(writer, &db.transform_rounds)?;
    write_master_iv(writer, &master_iv)?;
    write_protected_stream_key(writer, &protected_stream_key)?;
    write_stream_cipher(writer, &db.stream_cipher)?;
    write_stream_start_bytes(writer, &stream_start_bytes)?;
    write_end_header(writer)?;

    let hash = HeaderHash(sha256::hash(&[&writer.logged()]).to_vec());
    writer.stop();
    writer.clear();

    let mut xml = Vec::new();
    kdb2_xml_writer::write(&mut xml, db, &hash, &stream_key)?;

    let mut payload = Vec::new();
    payload.write(&stream_start_bytes.0)?;

    let compressed = compress(&db.compression, &xml)?;
    write_block(&mut payload, 0, &compressed)?;
    write_block_final(&mut payload, 1)?;

    let encrypted = aes256::encrypt(&master_key, &master_iv, &payload)?;
    writer.write(&encrypted)?;

    Ok(())
}

fn write_block<W: Write>(writer: &mut W, id: u32, data: &[u8]) -> Result<()> {
    writer.write_u32::<LittleEndian>(id)?;
    writer.write(&sha256::hash(&[data]))?;
    writer.write_u32::<LittleEndian>(data.len() as u32)?;
    writer.write(data)?;
    Ok(())
}

fn write_block_final<W: Write>(writer: &mut W, id: u32) -> Result<()> {
    writer.write_u32::<LittleEndian>(id)?;
    writer.write(&kdb2::FINAL_BLOCK_HASH)?;
    writer.write_u32::<LittleEndian>(0)?;
    Ok(())
}

fn write_bytes<W: Write>(writer: &mut W, bytes: &[u8]) -> Result<()> {
    writer.write(bytes)?;
    Ok(())
}

fn write_comment<W: Write>(writer: &mut W, opt: &Option<Comment>) -> Result<()> {
    match *opt {
        Some(ref comment) => {
            write_header_id(writer, kdb2::COMMENT_HID)?;
            write_header_size(writer, comment.0.len() as u16)?;
            write_bytes(writer, &comment.0)?;
            Ok(())
        }
        None => Ok(()),
    }
}

fn write_compression<W: Write>(writer: &mut W, compression: &Compression) -> Result<()> {
    write_header_id(writer, kdb2::COMPRESSION_HID)?;
    write_header_size(writer, kdb2::COMPRESSION_SIZE)?;
    let id = match *compression {
        Compression::None => 0u32,
        Compression::GZip => 1u32,
    };
    writer.write_u32::<LittleEndian>(id)?;
    Ok(())
}

fn write_end_header<W: Write>(writer: &mut W) -> Result<()> {
    write_header_id(writer, kdb2::END_HID)?;
    write_header_size(writer, 0)?;
    Ok(())
}

fn write_header_id<W: Write>(writer: &mut W, id: u8) -> Result<()> {
    writer.write_u8(id)?;
    Ok(())
}

fn write_header_size<W: Write>(writer: &mut W, size: u16) -> Result<()> {
    writer.write_u16::<LittleEndian>(size)?;
    Ok(())
}

fn write_master_cipher<W: Write>(writer: &mut W, cipher: &MasterCipher) -> Result<()> {
    write_header_id(writer, kdb2::MASTER_CIPHER_HID)?;
    write_header_size(writer, kdb2::MASTER_CIPHER_SIZE)?;
    match *cipher {
        MasterCipher::Aes256 => write_bytes(writer, &kdb2::AES_CIPHER_ID)?,
    }
    Ok(())
}

fn write_master_iv<W: Write>(writer: &mut W, iv: &MasterIV) -> Result<()> {
    write_header_id(writer, kdb2::MASTER_IV_HID)?;
    write_header_size(writer, kdb2::MASTER_IV_SIZE)?;
    write_bytes(writer, &iv.0)?;
    Ok(())
}

fn write_master_seed<W: Write>(writer: &mut W, seed: &MasterSeed) -> Result<()> {
    write_header_id(writer, kdb2::MASTER_SEED_HID)?;
    write_header_size(writer, kdb2::MASTER_SEED_SIZE)?;
    write_bytes(writer, &seed.0)?;
    Ok(())
}

fn write_protected_stream_key<W: Write>(writer: &mut W, key: &ProtectedStreamKey) -> Result<()> {
    write_header_id(writer, kdb2::PROTECTED_STREAM_KEY_HID)?;
    write_header_size(writer, kdb2::PROTECTED_STREAM_KEY_SIZE)?;
    write_bytes(writer, &key.0)?;
    Ok(())
}

fn write_sig_1<W: Write>(writer: &mut W) -> Result<()> {
    writer.write(&common::DB_SIGNATURE)?;
    Ok(())
}

fn write_sig_2<W: Write>(writer: &mut W) -> Result<()> {
    writer.write(&common::KDB2_SIGNATURE)?;
    Ok(())
}

fn write_stream_cipher<W: Write>(writer: &mut W, cipher: &StreamCipher) -> Result<()> {
    write_header_id(writer, kdb2::STREAM_CIPHER_HID)?;
    write_header_size(writer, kdb2::STREAM_CIPHER_SIZE)?;
    let id = match *cipher {
        StreamCipher::Salsa20 => 2u32,
    };
    writer.write_u32::<LittleEndian>(id)?;
    Ok(())
}

fn write_stream_start_bytes<W: Write>(writer: &mut W, bytes: &StreamStartBytes) -> Result<()> {
    write_header_id(writer, kdb2::STREAM_START_BYTES_HID)?;
    write_header_size(writer, kdb2::STREAM_START_BYTES_SIZE)?;
    write_bytes(writer, &bytes.0)?;
    Ok(())
}

fn write_transform_rounds<W: Write>(writer: &mut W, rounds: &TransformRounds) -> Result<()> {
    write_header_id(writer, kdb2::TRANSFORM_ROUNDS_HID)?;
    write_header_size(writer, kdb2::TRANSFORM_ROUNDS_SIZE)?;
    writer.write_u64::<LittleEndian>(rounds.0)?;
    Ok(())
}

fn write_transform_seed<W: Write>(writer: &mut W, seed: &TransformSeed) -> Result<()> {
    write_header_id(writer, kdb2::TRANSFORM_SEED_HID)?;
    write_header_size(writer, kdb2::TRANSFORM_SEED_SIZE)?;
    write_bytes(writer, &seed.0)?;
    Ok(())
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
