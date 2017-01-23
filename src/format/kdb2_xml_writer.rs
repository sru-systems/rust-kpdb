// Copyright (c) 2016-2017 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! The XML writer for KeePass 2 databases.

use common;
use crypto::salsa20::{self, Salsa20};
use std::io::Write;
use super::{kdb2, xml};
use types::Association;
use types::BinariesMap;
use types::BinaryKey;
use types::BinaryValue;
use types::CustomDataMap;
use types::CustomIconUuid;
use types::CustomIconsMap;
use types::Database;
use types::Entry;
use types::EntryState;
use types::Group;
use types::HeaderHash;
use types::Result;
use types::StreamKey;
use types::StringKey;
use types::StringValue;
use types::Times;
use xml::writer::{EmitterConfig, EventWriter, XmlEvent};

/// Attempts to write the database's XML data to the writer.
pub fn write<W: Write>(
    writer: &mut W,
    db: &Database,
    hash: &HeaderHash,
    key: &StreamKey
) -> Result<()> {
    let mut cipher = salsa20::new_cipher(key);
    let config = EmitterConfig::new().perform_indent(true).indent_string("\t");

    {
        let mut writer = EventWriter::new_with_config(writer, config);
        try!(write_kee_pass_file_section(&mut writer, db, hash, &mut cipher));
    }

    Ok(())
}

fn write_association_section<W: Write>(
    writer: &mut EventWriter<W>,
    assoc: &Association
) -> Result<()> {
    try!(xml::write_start_tag(writer, kdb2::ASSOCIATION_TAG));
    try!(xml::write_string_tag(writer, kdb2::KEYSTROKE_SEQUENCE_TAG, &assoc.keystroke_sequence));
    try!(xml::write_string_tag(writer, kdb2::WINDOW_TAG, &assoc.window));
    xml::write_end_tag(writer)
}

fn write_auto_type_section<W: Write>(writer: &mut EventWriter<W>, entry: &Entry) -> Result<()> {
    try!(xml::write_start_tag(writer, kdb2::AUTO_TYPE_TAG));
    try!(xml::write_i32_tag(writer,
                            kdb2::DATA_TRANSFER_OBFUSCATION_TAG,
                            entry.auto_type_obfuscation.to_i32()));
    try!(xml::write_string_tag(writer, kdb2::DEFAULT_SEQUENCE_TAG, &entry.auto_type_def_sequence));
    try!(xml::write_bool_tag(writer, kdb2::ENABLED_TAG, entry.auto_type_enabled));

    for assoc in &entry.associations {
        try!(write_association_section(writer, assoc));
    }
    xml::write_end_tag(writer)
}

fn write_binary_section<W: Write>(
    writer: &mut EventWriter<W>,
    cipher: &mut Salsa20,
    key: &BinaryKey,
    value: &BinaryValue
) -> Result<()> {
    try!(xml::write_start_tag(writer, kdb2::BINARY_TAG));
    try!(xml::write_start_tag(writer, kdb2::KEY_TAG));
    try!(xml::write_string(writer, &key.0));
    try!(xml::write_end_tag(writer));

    match *value {
        BinaryValue::Plain(ref bytes) => {
            try!(xml::write_start_tag(writer, kdb2::VALUE_TAG));
            try!(xml::write_binary(writer, bytes));
            try!(xml::write_end_tag(writer));
        }
        BinaryValue::Protected(ref sec) => {
            let tag = XmlEvent::start_element(kdb2::VALUE_TAG);
            let tag = tag.attr("Protected", "True");
            try!(writer.write(tag));
            let plain = sec.unsecure().to_vec();
            let encrypted = salsa20::encrypt(cipher, &plain);
            try!(xml::write_binary(writer, encrypted.as_slice()));
            try!(xml::write_end_tag(writer));
        }
        BinaryValue::Ref(ref binary_id) => {
            let tag = XmlEvent::start_element(kdb2::VALUE_TAG);
            let tag = tag.attr("Ref", binary_id.0.as_str());
            try!(writer.write(tag));
            try!(xml::write_end_tag(writer));
        }
    }
    xml::write_end_tag(writer)
}


fn write_binaries_section<W: Write>(
    writer: &mut EventWriter<W>,
    binaries: &BinariesMap
) -> Result<()> {
    try!(xml::write_start_tag(writer, kdb2::BINARIES_TAG));
    for (id, data) in binaries {
        let tag = XmlEvent::start_element(kdb2::BINARY_TAG);
        let tag = tag.attr("ID", id.0.as_str());
        let tag = tag.attr("Compressed", "True");
        try!(writer.write(tag));
        try!(xml::write_gzip(writer, &data));
        try!(xml::write_end_tag(writer));
    }
    xml::write_end_tag(writer)
}

fn write_custom_data_section<W: Write>(
    writer: &mut EventWriter<W>,
    data: &CustomDataMap
) -> Result<()> {
    try!(xml::write_start_tag(writer, kdb2::CUSTOM_DATA_TAG));
    for (key, value) in data {
        try!(write_custom_data_item_section(writer, key, value));
    }
    xml::write_end_tag(writer)
}

fn write_custom_data_item_section<W: Write>(
    writer: &mut EventWriter<W>,
    key: &String,
    value: &String
) -> Result<()> {
    try!(xml::write_start_tag(writer, kdb2::ITEM_TAG));
    try!(xml::write_string_tag(writer, kdb2::KEY_TAG, key));
    try!(xml::write_string_tag(writer, kdb2::VALUE_TAG, value));
    xml::write_end_tag(writer)
}

fn write_custom_icons_section<W: Write>(
    writer: &mut EventWriter<W>,
    icons: &CustomIconsMap
) -> Result<()> {
    try!(xml::write_start_tag(writer, kdb2::CUSTOM_ICONS_TAG));
    for (uuid, icon) in icons {
        try!(write_custom_icon_section(writer, uuid, icon));
    }
    xml::write_end_tag(writer)
}

fn write_custom_icon_section<W: Write>(
    writer: &mut EventWriter<W>,
    uuid: &CustomIconUuid,
    icon: &Vec<u8>
) -> Result<()> {
    try!(xml::write_start_tag(writer, kdb2::ICON_TAG));
    try!(xml::write_uuid_tag(writer, kdb2::UUID_TAG, &uuid.0));
    try!(xml::write_binary_tag(writer, kdb2::DATA_TAG, icon));
    xml::write_end_tag(writer)
}

fn write_entry_section<W: Write>(
    writer: &mut EventWriter<W>,
    db: &Database,
    cipher: &mut Salsa20,
    entry: &Entry,
    state: EntryState
) -> Result<()> {
    try!(xml::write_start_tag(writer, kdb2::ENTRY_TAG));
    try!(xml::write_uuid_tag(writer, kdb2::UUID_TAG, &entry.uuid.0));
    try!(write_auto_type_section(writer, entry));
    try!(xml::write_color_tag(writer, kdb2::BACKGROUND_COLOR_TAG, &entry.background_color));
    try!(xml::write_custom_icon_uuid_tag(writer,
                                         kdb2::CUSTOM_ICON_UUID_TAG,
                                         &entry.custom_icon_uuid));
    try!(xml::write_color_tag(writer, kdb2::FOREGROUND_COLOR_TAG, &entry.foreground_color));
    try!(xml::write_i32_tag(writer, kdb2::ICON_ID_TAG, entry.icon.to_i32()));
    try!(xml::write_string_tag(writer, kdb2::OVERRIDE_URL_TAG, &entry.override_url));
    try!(xml::write_string_tag(writer, kdb2::TAGS_TAG, &entry.tags));
    try!(write_times_section(writer, entry));

    for (key, value) in &entry.binaries {
        try!(write_binary_section(writer, cipher, key, value));
    }

    for (key, value) in &entry.strings {
        try!(write_string_section(writer, cipher, key, value));
    }

    if state == EntryState::Active {
        try!(write_history_section(writer, db, cipher, &db.history.get(&entry.uuid)));
    }
    xml::write_end_tag(writer)
}

fn write_group_section<W: Write>(
    writer: &mut EventWriter<W>,
    db: &Database,
    cipher: &mut Salsa20,
    group: &Group
) -> Result<()> {
    try!(xml::write_start_tag(writer, kdb2::GROUP_TAG));
    try!(xml::write_uuid_tag(writer, kdb2::UUID_TAG, &group.uuid.0));
    try!(xml::write_string_tag(writer,
                               kdb2::DEFAULT_AUTO_TYPE_SEQUENCE_TAG,
                               &group.def_auto_type_sequence));
    try!(xml::write_bool_opt_tag(writer, kdb2::ENABLE_AUTO_TYPE_TAG, &group.enable_auto_type));
    try!(xml::write_bool_opt_tag(writer, kdb2::ENABLE_SEARCHING_TAG, &group.enable_searching));
    try!(xml::write_i32_tag(writer, kdb2::ICON_ID_TAG, group.icon.to_i32()));
    try!(xml::write_bool_tag(writer, kdb2::IS_EXPANDED_TAG, group.is_expanded));
    try!(xml::write_uuid_tag(writer,
                             kdb2::LAST_TOP_VISIBLE_ENTRY_TAG,
                             &group.last_top_visible_entry.0));
    try!(xml::write_string_tag(writer, kdb2::NAME_TAG, &group.name));
    try!(xml::write_string_tag(writer, kdb2::NOTES_TAG, &group.notes));
    try!(write_times_section(writer, group));

    for uuid in &group.entries {
        match db.entries.get(&uuid) {
            Some(ref entry) => {
                try!(write_entry_section(writer, db, cipher, entry, EntryState::Active));
            }
            None => {}
        }
    }

    for uuid in &group.groups {
        match db.groups.get(&uuid) {
            Some(ref subgroup) => {
                try!(write_group_section(writer, db, cipher, subgroup));
            }
            None => {}
        }
    }
    xml::write_end_tag(writer)
}

fn write_history_section<W: Write>(
    writer: &mut EventWriter<W>,
    db: &Database,
    cipher: &mut Salsa20,
    entries: &Option<&Vec<Entry>>
) -> Result<()> {
    try!(xml::write_start_tag(writer, kdb2::HISTORY_TAG));
    match *entries {
        Some(list) => {
            for entry in list {
                try!(write_entry_section(writer, db, cipher, entry, EntryState::History));
            }
        }
        None => {}
    }
    xml::write_end_tag(writer)
}

fn write_kee_pass_file_section<W: Write>(
    writer: &mut EventWriter<W>,
    db: &Database,
    hash: &HeaderHash,
    cipher: &mut Salsa20
) -> Result<()> {
    try!(xml::write_start_tag(writer, kdb2::KEE_PASS_FILE_TAG));
    try!(write_meta_section(writer, db, hash));
    try!(write_root_section(writer, db, cipher));
    xml::write_end_tag(writer)
}

fn write_memory_protection_section<W: Write>(
    writer: &mut EventWriter<W>,
    db: &Database
) -> Result<()> {
    try!(xml::write_start_tag(writer, kdb2::MEMORY_PROTECTION_TAG));
    try!(xml::write_bool_tag(writer, kdb2::PROTECT_NOTES_TAG, db.protect_notes));
    try!(xml::write_bool_tag(writer, kdb2::PROTECT_PASSWORD_TAG, db.protect_password));
    try!(xml::write_bool_tag(writer, kdb2::PROTECT_TITLE_TAG, db.protect_title));
    try!(xml::write_bool_tag(writer, kdb2::PROTECT_URL_TAG, db.protect_url));
    try!(xml::write_bool_tag(writer, kdb2::PROTECT_USERNAME_TAG, db.protect_username));
    xml::write_end_tag(writer)
}

fn write_meta_section<W: Write>(
    writer: &mut EventWriter<W>,
    db: &Database,
    hash: &HeaderHash
) -> Result<()> {
    try!(xml::write_start_tag(writer, kdb2::META_TAG));
    try!(write_binaries_section(writer, &db.binaries));
    try!(xml::write_color_tag(writer, kdb2::COLOR_TAG, &db.color));
    try!(write_custom_data_section(writer, &db.custom_data));
    try!(write_custom_icons_section(writer, &db.custom_icons));
    try!(xml::write_string_tag(writer, kdb2::DATABASE_DESCRIPTION_TAG, &db.description));
    try!(xml::write_datetime_tag(writer,
                                 kdb2::DATABASE_DESCRIPTION_CHANGED_TAG,
                                 &db.description_changed));
    try!(xml::write_string_tag(writer, kdb2::DATABASE_NAME_TAG, &db.name));
    try!(xml::write_datetime_tag(writer, kdb2::DATABASE_NAME_CHANGED_TAG, &db.name_changed));
    try!(xml::write_string_tag(writer, kdb2::DEFAULT_USERNAME_TAG, &db.def_username));
    try!(xml::write_datetime_tag(writer,
                                 kdb2::DEFAULT_USERNAME_CHANGED_TAG,
                                 &db.def_username_changed));
    try!(xml::write_uuid_tag(writer,
                             kdb2::ENTRY_TEMPLATES_GROUP_TAG,
                             &db.entry_templates_group_uuid.0));
    try!(xml::write_datetime_tag(writer,
                                 kdb2::ENTRY_TEMPLATES_GROUP_CHANGED_TAG,
                                 &db.entry_templates_group_changed));
    try!(xml::write_string_tag(writer, kdb2::GENERATOR_TAG, &String::from(common::GENERATOR_NAME)));
    try!(xml::write_binary_tag(writer, kdb2::HEADER_HASH_TAG, &hash.0));
    try!(xml::write_i32_tag(writer, kdb2::HISTORY_MAX_ITEMS_TAG, db.history_max_items));
    try!(xml::write_i32_tag(writer, kdb2::HISTORY_MAX_SIZE_TAG, db.history_max_size));
    try!(xml::write_uuid_tag(writer, kdb2::LAST_SELECTED_GROUP_TAG, &db.last_selected_group.0));
    try!(xml::write_uuid_tag(writer,
                             kdb2::LAST_TOP_VISIBLE_GROUP_TAG,
                             &db.last_top_visible_group.0));
    try!(xml::write_i32_tag(writer,
                            kdb2::MAINTENANCE_HISTORY_DAYS_TAG,
                            db.maintenance_history_days));
    try!(xml::write_i32_tag(writer, kdb2::MASTER_KEY_CHANGE_FORCE_TAG, db.master_key_change_force));
    try!(xml::write_i32_tag(writer, kdb2::MASTER_KEY_CHANGE_REC_TAG, db.master_key_change_rec));
    try!(xml::write_datetime_tag(writer, kdb2::MASTER_KEY_CHANGED_TAG, &db.master_key_changed));

    try!(write_memory_protection_section(writer, &db));
    try!(xml::write_datetime_tag(writer, kdb2::RECYCLE_BIN_CHANGED_TAG, &db.recycle_bin_changed));
    try!(xml::write_bool_tag(writer, kdb2::RECYCLE_BIN_ENABLED_TAG, db.recycle_bin_enabled));
    try!(xml::write_uuid_tag(writer, kdb2::RECYCLE_BIN_UUID_TAG, &db.recycle_bin_uuid.0));
    xml::write_end_tag(writer)
}

fn write_root_section<W: Write>(
    writer: &mut EventWriter<W>,
    db: &Database,
    cipher: &mut Salsa20
) -> Result<()> {
    try!(xml::write_start_tag(writer, kdb2::ROOT_TAG));
    match db.group_uuid {
        Some(ref uuid) => {
            match db.groups.get(uuid) {
                Some(group) => {
                    try!(write_group_section(writer, db, cipher, group));
                }
                None => {}
            }
        }
        None => {}
    }
    xml::write_end_tag(writer)
}

fn write_string_section<W: Write>(
    writer: &mut EventWriter<W>,
    cipher: &mut Salsa20,
    key: &StringKey,
    value: &StringValue
) -> Result<()> {
    try!(xml::write_start_tag(writer, kdb2::STRING_TAG));
    try!(xml::write_string_tag(writer, kdb2::KEY_TAG, &key.to_string()));

    match *value {
        StringValue::Plain(ref string) => {
            try!(xml::write_string_tag(writer, kdb2::VALUE_TAG, string));
        }
        StringValue::Protected(ref sec) => {
            let tag = XmlEvent::start_element(kdb2::VALUE_TAG);
            let tag = tag.attr("Protected", "True");
            try!(writer.write(tag));
            let plain = sec.unsecure().to_vec();
            let encrypted = salsa20::encrypt(cipher, &plain);
            try!(xml::write_binary(writer, encrypted.as_slice()));
            try!(xml::write_end_tag(writer));
        }
    }
    xml::write_end_tag(writer)
}

fn write_times_section<T, W>(writer: &mut EventWriter<W>, node: &T) -> Result<()>
    where T: Times,
          W: Write
{
    try!(xml::write_start_tag(writer, kdb2::TIMES_TAG));
    try!(xml::write_datetime_tag(writer, kdb2::CREATION_TIME_TAG, &node.creation_time()));
    try!(xml::write_datetime_tag(writer, kdb2::EXPIRY_TIME_TAG, &node.expiry_time()));
    try!(xml::write_bool_tag(writer, kdb2::EXPIRES_TAG, node.expires()));
    try!(xml::write_datetime_tag(writer, kdb2::LAST_ACCESS_TIME_TAG, &node.last_accessed()));
    try!(xml::write_datetime_tag(writer, kdb2::LAST_MODIFICATION_TIME_TAG, &node.last_modified()));
    try!(xml::write_datetime_tag(writer, kdb2::LOCATION_CHANGED_TAG, &node.location_changed()));
    try!(xml::write_i32_tag(writer, kdb2::USAGE_COUNT_TAG, node.usage_count()));
    xml::write_end_tag(writer)
}
