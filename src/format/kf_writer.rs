// Copyright (c) 2016-2017 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! The writer for key files.

use hex::ToHex;
use std::io::Write;
use super::{kf, xml};
use types::{KeyFile, KeyFileType, Result};
use xml::writer::{EmitterConfig, EventWriter};

/// Attempts to write the key file to the writer.
pub fn write<W: Write>(writer: &mut W, key: &KeyFile) -> Result<()> {
    match key.file_type {
        KeyFileType::Binary => write_binary(writer, key),
        KeyFileType::Hex => write_hex(writer, key),
        KeyFileType::Xml => write_xml(writer, key),
    }
}

fn write_binary<W: Write>(writer: &mut W, key: &KeyFile) -> Result<()> {
    writer.write(key.key.unsecure())?;
    Ok(())
}

fn write_hex<W: Write>(writer: &mut W, key: &KeyFile) -> Result<()> {
    let hex = key.key.unsecure().to_hex();
    writer.write(&hex.into_bytes())?;
    Ok(())
}

fn write_xml<W: Write>(writer: &mut W, key: &KeyFile) -> Result<()> {
    let config = EmitterConfig::new().perform_indent(true).indent_string(
        "\t",
    );

    {
        let mut writer = EventWriter::new_with_config(writer, config);
        write_xml_key_file_section(&mut writer, key)?;
    }
    Ok(())
}

fn write_xml_key_file_section<W: Write>(writer: &mut EventWriter<W>, key: &KeyFile) -> Result<()> {
    xml::write_start_tag(writer, kf::KEY_FILE_TAG)?;
    write_xml_meta_section(writer)?;
    write_xml_key_section(writer, key)?;
    xml::write_end_tag(writer)
}

fn write_xml_meta_section<W: Write>(writer: &mut EventWriter<W>) -> Result<()> {
    xml::write_start_tag(writer, kf::META_TAG)?;
    xml::write_string_tag(writer, kf::VERSION_TAG, &String::from(kf::XML_KEY_FILE_VERSION))?;
    xml::write_end_tag(writer)
}

fn write_xml_key_section<W: Write>(writer: &mut EventWriter<W>, key: &KeyFile) -> Result<()> {
    xml::write_start_tag(writer, kf::KEY_TAG)?;
    xml::write_binary_tag(writer, kf::DATA_TAG, key.key.unsecure())?;
    xml::write_end_tag(writer)
}
