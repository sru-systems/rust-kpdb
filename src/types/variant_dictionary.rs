// Copyright (c) 2025 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Module for reading and writing the variant dictionary (KDBX4).

use super::error::Error;
use super::result::Result;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::collections::HashMap;
use std::io::{Cursor, Read, Write};

/// The value of a variant dictionary entry.
#[derive(Debug, Clone, PartialEq)]
pub enum VariantValue {
    /// 32 bit unsigned integer.
    Uint32(u32),

    /// 64 bit unsigned integer.
    Uint64(u64),

    /// Boolean.
    Bool(bool),

    /// 32 bit signed integer.
    Int32(i32),

    /// 64 bit signed integer.
    Int64(i64),

    /// String.
    String(String),

    /// Byte array.
    ByteArray(Vec<u8>),
}

/// A map with the entries of a variant dictionary.
pub type VariantMap = HashMap<String, VariantValue>;

/// Attempts to read a variant dictionary from the reader.
pub fn read_variant_map<R: Read>(reader: &mut R) -> Result<VariantMap> {
    let version = reader.read_u16::<LittleEndian>()?;
    if version & 0xFF00 > 0x0100 {
        return Err(Error::InvalidVariantDictionaryVersion(version));
    }

    let mut map = HashMap::new();
    loop {
        let field_type = reader.read_u8()?;
        if field_type == 0 {
            break;
        }

        let name_len = reader.read_u32::<LittleEndian>()? as usize;
        let mut name_buf = vec![0u8; name_len];
        reader.read_exact(&mut name_buf)?;
        let name = String::from_utf8(name_buf).map_err(|_| Error::InvalidData)?;

        let value_len = reader.read_u32::<LittleEndian>()? as usize;
        let mut value_buf = vec![0u8; value_len];
        reader.read_exact(&mut value_buf)?;

        let value = match field_type {
            0x04 => VariantValue::Uint32(Cursor::new(value_buf).read_u32::<LittleEndian>()?),
            0x05 => VariantValue::Uint64(Cursor::new(value_buf).read_u64::<LittleEndian>()?),
            0x08 => VariantValue::Bool(value_buf[0] != 0),
            0x0C => VariantValue::Int32(Cursor::new(value_buf).read_i32::<LittleEndian>()?),
            0x0D => VariantValue::Int64(Cursor::new(value_buf).read_i64::<LittleEndian>()?),
            0x18 => {
                VariantValue::String(String::from_utf8(value_buf).map_err(|_| Error::InvalidData)?)
            }
            0x42 => VariantValue::ByteArray(value_buf),
            _ => return Err(Error::UnhandledVariantValueType(field_type)),
        };

        map.insert(name, value);
    }

    Ok(map)
}

/// Attempts to write a variant dictionary to the writer.
pub fn write_variant_map<W: Write>(writer: &mut W, map: &VariantMap) -> Result<()> {
    writer.write_u16::<LittleEndian>(0x0100)?;
    for (name, value) in map {
        let (field_type, data): (u8, Vec<u8>) = match value {
            VariantValue::Uint32(v) => {
                let mut buf = Vec::new();
                buf.write_u32::<LittleEndian>(*v)?;
                (0x04, buf)
            }
            VariantValue::Uint64(v) => {
                let mut buf = Vec::new();
                buf.write_u64::<LittleEndian>(*v)?;
                (0x05, buf)
            }
            VariantValue::Bool(b) => (0x08, vec![if *b { 1 } else { 0 }]),
            VariantValue::Int32(v) => {
                let mut buf = Vec::new();
                buf.write_i32::<LittleEndian>(*v)?;
                (0x0C, buf)
            }
            VariantValue::Int64(v) => {
                let mut buf = Vec::new();
                buf.write_i64::<LittleEndian>(*v)?;
                (0x0D, buf)
            }
            VariantValue::String(s) => (0x18, s.as_bytes().to_vec()),
            VariantValue::ByteArray(b) => (0x42, b.clone()),
        };
        writer.write_u8(field_type)?;
        let name_bytes = name.as_bytes();
        writer.write_u32::<LittleEndian>(name_bytes.len() as u32)?;
        writer.write_all(name_bytes)?;
        writer.write_u32::<LittleEndian>(data.len() as u32)?;
        writer.write_all(&data)?;
    }
    writer.write_u8(0)?;
    Ok(())
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_read_write_round_trip() {
        let mut map = VariantMap::new();
        map.insert("$UUID".to_string(), VariantValue::ByteArray(vec![0x31; 16]));
        map.insert("S".to_string(), VariantValue::ByteArray(vec![0x01; 32]));
        map.insert("R".to_string(), VariantValue::Uint64(6000));
        map.insert("M".to_string(), VariantValue::Uint32(1024));
        map.insert("P".to_string(), VariantValue::Uint32(1));
        map.insert("V".to_string(), VariantValue::Uint32(0x13));
        map.insert("flag".to_string(), VariantValue::Bool(true));

        let mut bytes = Vec::new();
        write_variant_map(&mut bytes, &map).unwrap();

        let mut cursor = Cursor::new(bytes);
        let result = read_variant_map(&mut cursor).unwrap();
        assert_eq!(result, map);
    }

    #[test]
    fn test_read_rejects_unsupported_version() {
        let mut bytes = Vec::new();
        bytes.write_u16::<LittleEndian>(0x0200).unwrap();
        let mut cursor = Cursor::new(bytes);
        let result = read_variant_map(&mut cursor);
        assert!(matches!(result, Err(Error::InvalidVariantDictionaryVersion(_))));
    }

    #[test]
    fn test_read_rejects_unsupported_value_type() {
        let mut bytes = Vec::new();
        bytes.write_u16::<LittleEndian>(0x0100).unwrap();
        bytes.write_u8(0x07).unwrap();
        bytes.write_u32::<LittleEndian>(1).unwrap();
        bytes.write_all(b"X").unwrap();
        bytes.write_u32::<LittleEndian>(0).unwrap();
        let mut cursor = Cursor::new(bytes);
        let result = read_variant_map(&mut cursor);
        assert!(matches!(result, Err(Error::UnhandledVariantValueType(0x07))));
    }
}
