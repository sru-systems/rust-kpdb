// Copyright (c) 2016-2017 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! The reader for key files.

use hex::FromHex;
use secstr::SecStr;
use std::io::{Cursor, Read};
use super::{kf, xml};
use crate::types::{Error, KeyFile, KeyFileType, Result};
use crate::xml::reader::{EventReader, XmlEvent};

/// Attempts to read a key file from the reader.
pub fn read<R: Read>(reader: &mut R) -> Result<KeyFile> {
    let mut data = Vec::new();
    reader.read_to_end(&mut data)?;
    match data.len() {
        kf::BINARY_KEY_FILE_LEN => read_binary(data),
        kf::HEX_KEY_FILE_LEN => read_hex(data),
        _ => read_xml(&mut Cursor::new(data)),
    }
}

fn read_binary(data: Vec<u8>) -> Result<KeyFile> {
    Ok(KeyFile {
        key: SecStr::new(data),
        file_type: KeyFileType::Binary,
    })
}

fn read_hex(data: Vec<u8>) -> Result<KeyFile> {
    match FromHex::from_hex(&data) {
        Ok(key) => {
            Ok(KeyFile {
                key: SecStr::new(key),
                file_type: KeyFileType::Hex,
            })
        }
        Err(_) => Err(Error::InvalidKeyFile),
    }
}

fn read_xml<R: Read>(reader: &mut R) -> Result<KeyFile> {
    let mut opt_key: Option<SecStr> = None;
    let mut reader = EventReader::new(reader);
    loop {
        let event = reader.next()?;
        match event {
            XmlEvent::StartElement { name, .. } => {
                if name.local_name == kf::KEY_FILE_TAG {
                    opt_key = Some(read_xml_key_file(&mut reader)?);
                }
            }
            XmlEvent::EndDocument { .. } => {
                break;
            }
            _ => {}
        }
    }

    match opt_key {
        Some(key) => {
            Ok(KeyFile {
                key: key,
                file_type: KeyFileType::Xml,
            })
        }
        None => xml::read_err(&mut reader, "No KeyFile tag found"),
    }
}

fn read_xml_key_file<R: Read>(reader: &mut EventReader<R>) -> Result<SecStr> {
    let mut opt_key: Option<SecStr> = None;
    loop {
        let event = reader.next()?;
        match event {
            XmlEvent::StartElement { name, .. } => {
                if name.local_name == kf::KEY_TAG {
                    opt_key = Some(read_xml_key(reader)?);
                } else if name.local_name == kf::META_TAG {
                    read_xml_meta(reader)?;
                }
            }
            XmlEvent::EndElement { name, .. } => {
                if name.local_name == kf::KEY_FILE_TAG {
                    break;
                }
            }
            _ => {}
        }
    }

    match opt_key {
        Some(key) => Ok(key),
        None => xml::read_err(reader, "No Key tag found"),
    }
}

fn read_xml_meta<R: Read>(reader: &mut EventReader<R>) -> Result<()> {
    loop {
        let event = reader.next()?;
        match event {
            XmlEvent::StartElement { name, .. } => {
                if name.local_name == kf::VERSION_TAG {
                    let version = xml::read_string(reader)?;
                    if version != kf::XML_KEY_FILE_VERSION {
                        return xml::read_err(reader, "Unsupported key file version");
                    }
                }
            }
            XmlEvent::EndElement { name, .. } => {
                if name.local_name == kf::META_TAG {
                    break;
                }
            }
            _ => {}
        }
    }

    Ok(())
}

fn read_xml_key<R: Read>(reader: &mut EventReader<R>) -> Result<SecStr> {
    let mut opt_key: Option<SecStr> = None;
    loop {
        let event = reader.next()?;
        match event {
            XmlEvent::StartElement { name, .. } => {
                if name.local_name == kf::DATA_TAG {
                    opt_key = Some(SecStr::new(xml::read_binary(reader)?));
                }
            }
            XmlEvent::EndElement { name, .. } => {
                if name.local_name == kf::KEY_TAG {
                    break;
                }
            }
            _ => {}
        }
    }

    match opt_key {
        Some(key) => Ok(key),
        None => xml::read_err(reader, "No Data tag found"),
    }
}
