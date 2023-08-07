// Copyright (c) 2016-2017 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Module containing functions for reading and writing XML.

use base64;
use crate::crypto::salsa20::{self, Salsa20};
use chrono::{DateTime, Utc};
use crate::compression::gzip;
use secstr::SecStr;
use std::io::{Read, Write};
use crate::types::BinaryId;
use crate::types::BinaryKey;
use crate::types::BinaryValue;
use crate::types::Color;
use crate::types::CustomIconUuid;
use crate::types::Error;
use crate::types::Icon;
use crate::types::Obfuscation;
use crate::types::Result;
use crate::types::StringKey;
use crate::types::StringValue;
use uuid::Uuid;
use xml::attribute::OwnedAttribute;
use xml::common::Position;
use xml::reader::{self, EventReader};
use xml::writer::{self, EventWriter};

/// Attempts to read binary data.
pub fn read_binary<R: Read>(reader: &mut EventReader<R>) -> Result<Vec<u8>> {
    match read_binary_opt(reader)? {
        Some(bytes) => Ok(bytes),
        None => Ok(Vec::new()),
    }
}

/// Attempts to read an optional binary key.
pub fn read_binary_key_opt<R: Read>(reader: &mut EventReader<R>) -> Result<Option<BinaryKey>> {
    match read_string_opt(reader)? {
        Some(string) => Ok(Some(BinaryKey(string))),
        None => Ok(None),
    }
}

/// Attempts to read optional binary data.
pub fn read_binary_opt<R: Read>(reader: &mut EventReader<R>) -> Result<Option<Vec<u8>>> {
    match read_string_opt(reader)? {
        Some(string) => {
            match base64::decode(&string) {
                Ok(bin) => Ok(Some(bin)),
                Err(err) => read_err(reader, format!("Base64 {}", err)),
            }
        }
        None => Ok(None),
    }
}

/// Attempts to read an optional binary value.
pub fn read_binary_value_opt<R: Read>(
    reader: &mut EventReader<R>,
    cipher: &mut Salsa20,
    attrs: &Vec<OwnedAttribute>,
) -> Result<Option<BinaryValue>> {
    let ref_value = search_attr_value(attrs, "ref");
    let protected = get_protected_attr_value(reader, attrs)?;
    match ref_value {
        Some(string) => Ok(Some(BinaryValue::Ref(BinaryId(string)))),
        None => {
            match read_binary_opt(reader)? {
                Some(bytes) => {
                    if protected {
                        let pbytes = salsa20::decrypt(cipher, &bytes);
                        let secstr = SecStr::new(pbytes);
                        Ok(Some(BinaryValue::Protected(secstr)))
                    } else {
                        Ok(Some(BinaryValue::Plain(bytes)))
                    }
                }
                None => {
                    if protected {
                        Ok(Some(BinaryValue::Protected(SecStr::new(Vec::new()))))
                    } else {
                        Ok(Some(BinaryValue::Plain(Vec::new())))
                    }
                }
            }
        }
    }
}

/// Attempts to read a boolean.
pub fn read_bool<R: Read>(reader: &mut EventReader<R>) -> Result<bool> {
    match read_bool_opt(reader)? {
        Some(b) => Ok(b),
        None => read_err(reader, "No Bool value found"),
    }
}

/// Attempts to read an optional boolean.
pub fn read_bool_opt<R: Read>(reader: &mut EventReader<R>) -> Result<Option<bool>> {
    match read_string_opt(reader)? {
        Some(string) => {
            match string.to_lowercase().as_str() {
                "false" => Ok(Some(false)),
                "null" => Ok(None),
                "true" => Ok(Some(true)),
                val => read_err(reader, format!("Bool invalid value: {}", val)),
            }
        }
        None => Ok(None),
    }
}

/// Attempts to read an optional color.
pub fn read_color_opt<R: Read>(reader: &mut EventReader<R>) -> Result<Option<Color>> {
    match read_string_opt(reader)? {
        Some(string) => {
            match Color::from_hex_string(&string) {
                Ok(color) => Ok(Some(color)),
                Err(err) => read_err(reader, format!("Color {}", err)),
            }
        }
        None => Ok(None),
    }
}

/// Attempts to read an optional custom icon UUID.
pub fn read_custom_icon_uuid_opt<R: Read>(
    reader: &mut EventReader<R>,
) -> Result<Option<CustomIconUuid>> {
    match read_uuid_opt(reader)? {
        Some(uuid) => Ok(Some(CustomIconUuid(uuid))),
        None => Ok(None),
    }
}

/// Attempts to read a date and time.
pub fn read_datetime<R: Read>(reader: &mut EventReader<R>) -> Result<DateTime<Utc>> {
    match read_string_opt(reader)? {
        Some(string) => {
            match string.parse::<DateTime<Utc>>() {
                Ok(datetime) => Ok(datetime),
                Err(err) => read_err(reader, format!("DateTime {}", err)),
            }
        }
        None => read_err(reader, "No DateTime value found"),
    }
}

/// Creates a new read error result.
pub fn read_err<S, R, X>(reader: &mut EventReader<R>, msg: S) -> Result<X>
where
    R: Read,
    S: Into<String>,
{
    let msg: String = msg.into();
    let pos = reader.position();
    let err = format!("{} {}", pos, msg);
    Err(Error::XmlError(err))
}

/// Attempts to read GZip compressed binary data.
pub fn read_gzip<R: Read>(reader: &mut EventReader<R>) -> Result<Vec<u8>> {
    match read_binary_opt(reader)? {
        Some(bytes) => {
            let decompressed = gzip::decode(&bytes)?;
            Ok(decompressed)
        }
        None => Ok(Vec::new()),
    }
}

/// Attempts to read an i32.
pub fn read_i32<R: Read>(reader: &mut EventReader<R>) -> Result<i32> {
    match read_i32_opt(reader)? {
        Some(num) => Ok(num),
        None => read_err(reader, "No Number value found"),
    }
}

/// Attempts to read an optional i32.
pub fn read_i32_opt<R: Read>(reader: &mut EventReader<R>) -> Result<Option<i32>> {
    match read_string_opt(reader)? {
        Some(string) => {
            match string.parse::<i32>() {
                Ok(num) => Ok(Some(num)),
                Err(err) => read_err(reader, format!("Number {}", err)),
            }
        }
        None => Ok(None),
    }
}

/// Attempts to read an icon.
pub fn read_icon<R: Read>(reader: &mut EventReader<R>) -> Result<Icon> {
    match read_i32_opt(reader)? {
        Some(num) => {
            match Icon::from_i32(num) {
                Ok(icon) => Ok(icon),
                Err(err) => read_err(reader, format!("{}", err)),
            }
        }
        None => read_err(reader, "No Icon value found"),
    }
}

/// Attempts to read an obfuscation type.
pub fn read_obfuscation<R: Read>(reader: &mut EventReader<R>) -> Result<Obfuscation> {
    match read_i32_opt(reader)? {
        Some(num) => {
            match Obfuscation::from_i32(num) {
                Ok(val) => Ok(val),
                Err(err) => read_err(reader, format!("{}", err)),
            }
        }
        None => read_err(reader, "No Obfuscation value found"),
    }
}

/// Attempts to read a string.
pub fn read_string<R: Read>(reader: &mut EventReader<R>) -> Result<String> {
    match read_string_opt(reader)? {
        Some(string) => Ok(string),
        None => Ok(String::new()),
    }
}

/// Attempts to read an optional string key
pub fn read_string_key_opt<R: Read>(reader: &mut EventReader<R>) -> Result<Option<StringKey>> {
    match read_string_opt(reader)? {
        Some(string) => Ok(Some(StringKey::from_string(&string))),
        None => Ok(None),
    }
}

/// Attempts to read an optional string.
pub fn read_string_opt<R: Read>(reader: &mut EventReader<R>) -> Result<Option<String>> {
    let event = reader.next()?;
    match event {
        reader::XmlEvent::Characters(val) => Ok(Some(val)),
        reader::XmlEvent::EndElement { .. } => Ok(None),
        _ => {
            let _: Result<Option<String>> = read_err(reader, "No characters found")
                .map_err(|err| {
                    eprintln!("{}", err);
                    err
                });
            Ok(None)
        },
//        _ => read_err(reader, "No characters found"),
    }
}

/// Attempts to read an optional string value.
pub fn read_string_value_opt<R: Read>(
    reader: &mut EventReader<R>,
    cipher: &mut Salsa20,
    attrs: &Vec<OwnedAttribute>,
) -> Result<Option<StringValue>> {
    let pmem = get_protect_in_memory_attr_value(reader, attrs)?;
    let pxml = get_protected_attr_value(reader, attrs)?;
    let protected = pmem || pxml;
    if pxml {
        match read_binary_opt(reader)? {
            Some(bytes) => {
                let pbytes = salsa20::decrypt(cipher, &bytes);
                match String::from_utf8(pbytes) {
                    Ok(string) => Ok(Some(StringValue::new(string, protected))),
                    Err(err) => read_err(reader, format!("UTF8 {}", err)),
                }
            }
            None => Ok(Some(StringValue::new("", protected))),
        }
    } else {
        match read_string_opt(reader)? {
            Some(string) => Ok(Some(StringValue::new(string, protected))),
            None => Ok(Some(StringValue::new("", protected))),
        }
    }
}

/// Attempts to read a UUID.
pub fn read_uuid<R: Read>(reader: &mut EventReader<R>) -> Result<Uuid> {
    match read_uuid_opt(reader)? {
        Some(uuid) => Ok(uuid),
        None => read_err(reader, "No UUID value found"),
    }
}

/// Attempts to read an optional UUID.
pub fn read_uuid_opt<R: Read>(reader: &mut EventReader<R>) -> Result<Option<Uuid>> {
    match read_binary_opt(reader)? {
        Some(bytes) => {
            match Uuid::from_bytes(&bytes) {
                Ok(uuid) => Ok(Some(uuid)),
                Err(err) => read_err(reader, format!("UUID {}", err)),
            }
        }
        None => Ok(None),
    }
}

/// Searches the specified attribute in the attributes and returns the value if found.
pub fn search_attr_value(attrs: &Vec<OwnedAttribute>, name: &str) -> Option<String> {
    for attr in attrs {
        if attr.name.local_name.to_lowercase() == name.to_lowercase() {
            return Some(attr.value.clone());
        }
    }
    None
}

/// Attempts to write binary data.
pub fn write_binary<W: Write>(writer: &mut EventWriter<W>, data: &[u8]) -> Result<()> {
    write_string(writer, &base64::encode(&data))
}

/// Attempts to write a tag that contains binary data.
pub fn write_binary_tag<W: Write>(
    writer: &mut EventWriter<W>,
    tag: &str,
    value: &[u8],
) -> Result<()> {
    write_string_tag(writer, tag, &base64::encode(&value))
}

/// Attempts to write a tag that contains optional boolean data.
pub fn write_bool_opt_tag<W: Write>(
    writer: &mut EventWriter<W>,
    tag: &str,
    value: &Option<bool>,
) -> Result<()> {
    match *value {
        Some(false) => write_string_tag(writer, tag, &String::from("false")),
        Some(true) => write_string_tag(writer, tag, &String::from("true")),
        None => write_string_tag(writer, tag, &String::from("null")),
    }
}

/// Attempts to write a tag that contains boolean data.
pub fn write_bool_tag<W: Write>(writer: &mut EventWriter<W>, tag: &str, value: bool) -> Result<()> {
    write_bool_opt_tag(writer, tag, &Some(value))
}

/// Attempts to write a tag that contains an optional color.
pub fn write_color_tag<W: Write>(
    writer: &mut EventWriter<W>,
    tag: &str,
    value: &Option<Color>,
) -> Result<()> {
    match *value {
        Some(ref c) => write_string_tag(writer, tag, &c.to_hex_string()),
        None => write_null_tag(writer, tag),
    }
}

/// Attempts to write a tag that contains an optional custom icon UUID.
pub fn write_custom_icon_uuid_tag<W: Write>(
    writer: &mut EventWriter<W>,
    tag: &str,
    value: &Option<CustomIconUuid>,
) -> Result<()> {
    match *value {
        Some(ref u) => write_uuid_tag(writer, tag, &u.0),
        None => write_null_tag(writer, tag),
    }
}

/// Attempts to write a tag that contains a date and time.
pub fn write_datetime_tag<W: Write>(
    writer: &mut EventWriter<W>,
    tag: &str,
    value: &DateTime<Utc>,
) -> Result<()> {
    write_string_tag(writer, tag, &format!("{:?}", value))
}

/// Attempts to write an end tag.
pub fn write_end_tag<W: Write>(writer: &mut EventWriter<W>) -> Result<()> {
    writer.write(writer::XmlEvent::end_element())?;
    Ok(())
}

/// Attempts to write GZip compressed data.
pub fn write_gzip<W: Write>(writer: &mut EventWriter<W>, data: &[u8]) -> Result<()> {
    let compressed = gzip::encode(data)?;
    write_binary(writer, &compressed)
}

/// Attempts to write a tag that contains an i32.
pub fn write_i32_tag<W: Write>(writer: &mut EventWriter<W>, tag: &str, value: i32) -> Result<()> {
    write_string_tag(writer, tag, &format!("{}", value))
}

/// Attempts to write a tag that contains no data.
pub fn write_null_tag<W: Write>(writer: &mut EventWriter<W>, tag: &str) -> Result<()> {
    write_start_tag(writer, tag)?;
    write_end_tag(writer)?;
    Ok(())
}

/// Attempts to write a start tag.
pub fn write_start_tag<W: Write>(writer: &mut EventWriter<W>, tag: &str) -> Result<()> {
    writer.write(writer::XmlEvent::start_element(tag))?;
    Ok(())
}

/// Attempts to write string data.
pub fn write_string<W: Write>(writer: &mut EventWriter<W>, value: &String) -> Result<()> {
    writer.write(value.as_str())?;
    Ok(())
}

/// Attempts to write a tag that contains a string.
pub fn write_string_tag<W: Write>(
    writer: &mut EventWriter<W>,
    tag: &str,
    value: &String,
) -> Result<()> {
    write_start_tag(writer, tag)?;
    write_string(writer, value)?;
    write_end_tag(writer)?;
    Ok(())
}

/// Attempts to write a tag that contains a UUID.
pub fn write_uuid_tag<W: Write>(writer: &mut EventWriter<W>, tag: &str, uuid: &Uuid) -> Result<()> {
    write_binary_tag(writer, tag, uuid.as_bytes())
}

fn get_protect_in_memory_attr_value<R: Read>(
    reader: &mut EventReader<R>,
    attrs: &Vec<OwnedAttribute>,
) -> Result<bool> {
    match search_attr_value(attrs, "protectinmemory") {
        Some(string) => {
            match string.to_lowercase().parse::<bool>() {
                Ok(val) => Ok(val),
                Err(_) => read_err(reader, "Attribute ProtectInMemory invalid value"),
            }
        }
        None => Ok(false),
    }
}

fn get_protected_attr_value<R: Read>(
    reader: &mut EventReader<R>,
    attrs: &Vec<OwnedAttribute>,
) -> Result<bool> {
    match search_attr_value(attrs, "protected") {
        Some(string) => {
            match string.to_lowercase().parse::<bool>() {
                Ok(val) => Ok(val),
                Err(_) => read_err(reader, "Attribute Protected invalid value"),
            }
        }
        None => Ok(false),
    }
}
