// Variant dictionary parser for KDBX 4
use byteorder::{LittleEndian, ReadBytesExt};
use std::collections::HashMap;
use std::io::{Read, Cursor};
use crate::types::{Result, Error};

#[derive(Debug, Clone)]
pub enum VariantValue {
    Uint32(u32),
    Uint64(u64),
    Bool(bool),
    Int32(i32),
    Int64(i64),
    String(String),
    ByteArray(Vec<u8>),
}

pub type VariantMap = HashMap<String, VariantValue>;

pub fn read_variant_map<R: Read>(reader: &mut R) -> Result<VariantMap> {
    let version_raw = reader.read_u16::<LittleEndian>()?;
    let version = version_raw & 0xFF00;
    if version > 0x0100 {
        return Err(Error::InvalidData);
    }
    
    let mut map = HashMap::new();
    
    loop {
        let field_type = reader.read_u8()?;
        if field_type == 0 { // End
            break;
        }
        
        let name_len = reader.read_u32::<LittleEndian>()?;
        let mut name_buf = vec![0u8; name_len as usize];
        reader.read_exact(&mut name_buf)?;
        let name = String::from_utf8(name_buf).map_err(|_| Error::InvalidData)?;
        
        let value_len = reader.read_u32::<LittleEndian>()?;
        let mut value_buf = vec![0u8; value_len as usize];
        reader.read_exact(&mut value_buf)?;
        
        let value = match field_type {
            0x04 => VariantValue::Uint32(Cursor::new(value_buf).read_u32::<LittleEndian>()?),
            0x05 => VariantValue::Uint64(Cursor::new(value_buf).read_u64::<LittleEndian>()?),
            0x08 => VariantValue::Bool(value_buf[0] != 0),
            0x0C => VariantValue::Int32(Cursor::new(value_buf).read_i32::<LittleEndian>()?),
            0x0D => VariantValue::Int64(Cursor::new(value_buf).read_i64::<LittleEndian>()?),
            0x18 => VariantValue::String(String::from_utf8(value_buf).map_err(|_| Error::InvalidData)?),
            0x42 => VariantValue::ByteArray(value_buf),
            _ => return Err(Error::InvalidData),
        };
        
        map.insert(name, value);
    }
    
    Ok(map)
}

pub fn write_variant_map<W: std::io::Write>(writer: &mut W, map: &VariantMap) -> Result<()> {
    use byteorder::WriteBytesExt;
    writer.write_u16::<LittleEndian>(0x0100)?;
    for (name, value) in map {
        let (field_type, data): (u8, Vec<u8>) = match value {
            VariantValue::Uint32(v) => {
                let mut buf = Vec::new();
                buf.write_u32::<LittleEndian>(*v)?;
                (0x04, buf)
            },
            VariantValue::Uint64(v) => {
                let mut buf = Vec::new();
                buf.write_u64::<LittleEndian>(*v)?;
                (0x05, buf)
            },
            VariantValue::Bool(b) => {
                (0x08, vec![if *b {1} else {0}])
            },
            VariantValue::Int32(v) => {
                let mut buf = Vec::new();
                buf.write_i32::<LittleEndian>(*v)?;
                (0x0C, buf)
            },
            VariantValue::Int64(v) => {
                let mut buf = Vec::new();
                buf.write_i64::<LittleEndian>(*v)?;
                (0x0D, buf)
            },
            VariantValue::String(s) => {
                (0x18, s.as_bytes().to_vec())
            },
            VariantValue::ByteArray(b) => {
                (0x42, b.clone())
            },
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
