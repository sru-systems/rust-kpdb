// Copyright (c) 2016-2017 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! The XML reader for KeePass 2 databases.

use crypto::salsa20::{self, Salsa20};
use std::io::Read;
use super::{kdb2, xml};
use types::Association;
use types::BinariesMap;
use types::BinaryId;
use types::BinaryKey;
use types::BinaryValue;
use types::CustomDataMap;
use types::CustomIconUuid;
use types::CustomIconsMap;
use types::Entry;
use types::EntryState;
use types::EntryUuid;
use types::Group;
use types::GroupUuid;
use types::HeaderHash;
use types::Result;
use types::StreamKey;
use types::StringKey;
use types::StringValue;
use types::Times;
use types::XmlData;
use xml::attribute::OwnedAttribute;
use xml::reader::{EventReader, XmlEvent};

/// Attempts to read the XML data from the reader.
pub fn read<R: Read>(reader: &mut R, stream_key: &StreamKey) -> Result<XmlData> {
    let mut data = XmlData::default();
    let mut reader = EventReader::new(reader);
    let mut cipher = salsa20::new_cipher(stream_key);
    loop {
        let event = reader.next()?;
        match event {
            XmlEvent::StartElement { name, .. } => {
                match name.local_name.as_str() {
                    kdb2::KEE_PASS_FILE_TAG => {
                        read_kee_pass_file(&mut reader, &mut data, &mut cipher)?;
                    }
                    _ => return xml::read_err(&mut reader, "Invalid root node"),
                }
            }

            XmlEvent::EndDocument { .. } => {
                break;
            }

            _ => {}
        }
    }

    Ok(data)
}

fn read_kee_pass_file<R: Read>(
    reader: &mut EventReader<R>,
    data: &mut XmlData,
    cipher: &mut Salsa20,
) -> Result<()> {
    loop {
        let event = reader.next()?;
        match event {
            XmlEvent::StartElement { name, .. } => {
                match name.local_name.as_str() {
                    kdb2::META_TAG => {
                        read_meta(reader, data)?;
                    }
                    kdb2::ROOT_TAG => {
                        read_root(reader, data, cipher)?;
                    }
                    _ => {}
                }
            }

            XmlEvent::EndElement { name, .. } => {
                if name.local_name == kdb2::KEE_PASS_FILE_TAG {
                    break;
                }
            }

            _ => {}
        }
    }

    Ok(())
}

fn read_meta<R: Read>(reader: &mut EventReader<R>, data: &mut XmlData) -> Result<()> {
    loop {
        let event = reader.next()?;
        match event {
            XmlEvent::StartElement { name, .. } => {
                match name.local_name.as_str() {
                    kdb2::BINARIES_TAG => {
                        data.binaries = read_binaries(reader)?;
                    }
                    kdb2::COLOR_TAG => {
                        data.color = xml::read_color_opt(reader)?;
                    }
                    kdb2::CUSTOM_DATA_TAG => {
                        data.custom_data = read_custom_data(reader)?;
                    }
                    kdb2::CUSTOM_ICONS_TAG => {
                        data.custom_icons = read_custom_icons(reader)?;
                    }
                    kdb2::DATABASE_DESCRIPTION_TAG => {
                        data.description = xml::read_string(reader)?;
                    }
                    kdb2::DATABASE_DESCRIPTION_CHANGED_TAG => {
                        data.description_changed = xml::read_datetime(reader)?;
                    }
                    kdb2::DATABASE_NAME_TAG => {
                        data.name = xml::read_string(reader)?;
                    }
                    kdb2::DATABASE_NAME_CHANGED_TAG => {
                        data.name_changed = xml::read_datetime(reader)?;
                    }
                    kdb2::DEFAULT_USERNAME_TAG => {
                        data.def_username = xml::read_string(reader)?;
                    }
                    kdb2::DEFAULT_USERNAME_CHANGED_TAG => {
                        data.def_username_changed = xml::read_datetime(reader)?;
                    }
                    kdb2::ENTRY_TEMPLATES_GROUP_TAG => {
                        data.entry_templates_group_uuid = GroupUuid(xml::read_uuid(reader)?);
                    }
                    kdb2::ENTRY_TEMPLATES_GROUP_CHANGED_TAG => {
                        data.entry_templates_group_changed = xml::read_datetime(reader)?;
                    }
                    kdb2::GENERATOR_TAG => {
                        data.generator = xml::read_string(reader)?;
                    }
                    kdb2::HEADER_HASH_TAG => {
                        data.header_hash = Some(HeaderHash(xml::read_binary(reader)?));
                    }
                    kdb2::HISTORY_MAX_ITEMS_TAG => {
                        data.history_max_items = xml::read_i32(reader)?;
                    }
                    kdb2::HISTORY_MAX_SIZE_TAG => {
                        data.history_max_size = xml::read_i32(reader)?;
                    }
                    kdb2::LAST_SELECTED_GROUP_TAG => {
                        data.last_selected_group = GroupUuid(xml::read_uuid(reader)?);
                    }
                    kdb2::LAST_TOP_VISIBLE_GROUP_TAG => {
                        data.last_top_visible_group = GroupUuid(xml::read_uuid(reader)?);
                    }
                    kdb2::MAINTENANCE_HISTORY_DAYS_TAG => {
                        data.maintenance_history_days = xml::read_i32(reader)?;
                    }
                    kdb2::MASTER_KEY_CHANGE_FORCE_TAG => {
                        data.master_key_change_force = xml::read_i32(reader)?;
                    }
                    kdb2::MASTER_KEY_CHANGE_REC_TAG => {
                        data.master_key_change_rec = xml::read_i32(reader)?;
                    }
                    kdb2::MASTER_KEY_CHANGED_TAG => {
                        data.master_key_changed = xml::read_datetime(reader)?;
                    }
                    kdb2::MEMORY_PROTECTION_TAG => {
                        read_memory_protection(reader, data)?;
                    }
                    kdb2::RECYCLE_BIN_CHANGED_TAG => {
                        data.recycle_bin_changed = xml::read_datetime(reader)?;
                    }
                    kdb2::RECYCLE_BIN_ENABLED_TAG => {
                        data.recycle_bin_enabled = xml::read_bool(reader)?;
                    }
                    kdb2::RECYCLE_BIN_UUID_TAG => {
                        data.recycle_bin_uuid = GroupUuid(xml::read_uuid(reader)?);
                    }
                    _ => {}
                }
            }

            XmlEvent::EndElement { name, .. } => {
                if name.local_name == kdb2::META_TAG {
                    break;
                }
            }

            _ => {}
        }
    }

    Ok(())
}

fn read_root<R: Read>(
    reader: &mut EventReader<R>,
    data: &mut XmlData,
    cipher: &mut Salsa20,
) -> Result<()> {
    loop {
        let event = reader.next()?;
        match event {
            XmlEvent::StartElement { name, .. } => {
                match name.local_name.as_str() {
                    kdb2::GROUP_TAG => {
                        data.root_group = Some(read_group(reader, cipher, GroupUuid::nil())?);
                    }
                    _ => {}
                }
            }

            XmlEvent::EndElement { name, .. } => {
                if name.local_name == kdb2::ROOT_TAG {
                    break;
                }
            }

            _ => {}
        }
    }

    Ok(())
}

fn read_binaries<R: Read>(reader: &mut EventReader<R>) -> Result<BinariesMap> {
    let mut map = BinariesMap::new();
    loop {
        let event = reader.next()?;
        match event {
            XmlEvent::StartElement { name, attributes, .. } => {
                match name.local_name.as_str() {
                    kdb2::BINARY_TAG => {
                        let id = BinaryId(get_id_attr_value(reader, &attributes)?);
                        let compressed = get_compressed_attr_value(reader, &attributes)?;
                        let bytes = if compressed {
                            xml::read_gzip(reader)?
                        } else {
                            xml::read_binary(reader)?
                        };
                        map.insert(id, bytes);
                    }
                    _ => {}
                }
            }

            XmlEvent::EndElement { name, .. } => {
                if name.local_name == kdb2::BINARIES_TAG {
                    break;
                }
            }

            _ => {}
        }
    }

    Ok(map)
}

fn read_custom_data<R: Read>(reader: &mut EventReader<R>) -> Result<CustomDataMap> {
    let mut map = CustomDataMap::new();
    loop {
        let event = reader.next()?;
        match event {
            XmlEvent::StartElement { name, .. } => {
                match name.local_name.as_str() {
                    kdb2::ITEM_TAG => {
                        let (key, value) = read_custom_data_item(reader)?;
                        map.insert(key, value);
                    }
                    _ => {}
                }
            }

            XmlEvent::EndElement { name, .. } => {
                if name.local_name == kdb2::CUSTOM_DATA_TAG {
                    break;
                }
            }

            _ => {}
        }
    }

    Ok(map)
}

fn read_custom_data_item<R: Read>(reader: &mut EventReader<R>) -> Result<(String, String)> {
    let mut key: Option<String> = None;
    let mut value: Option<String> = None;
    loop {
        let event = reader.next()?;
        match event {
            XmlEvent::StartElement { name, .. } => {
                match name.local_name.as_str() {
                    kdb2::KEY_TAG => {
                        key = xml::read_string_opt(reader)?;
                    }
                    kdb2::VALUE_TAG => {
                        value = xml::read_string_opt(reader)?;
                    }
                    _ => {}
                }
            }

            XmlEvent::EndElement { name, .. } => {
                if name.local_name == kdb2::ITEM_TAG {
                    break;
                }
            }

            _ => {}
        }
    }

    let key = match key {
        Some(k) => k,
        None => return xml::read_err(reader, "Key element not found"),
    };

    let value = match value {
        Some(v) => v,
        None => return xml::read_err(reader, "Value element not found"),
    };

    Ok((key, value))
}

fn read_custom_icons<R: Read>(reader: &mut EventReader<R>) -> Result<CustomIconsMap> {
    let mut map = CustomIconsMap::new();
    loop {
        let event = reader.next()?;
        match event {
            XmlEvent::StartElement { name, .. } => {
                match name.local_name.as_str() {
                    kdb2::ICON_TAG => {
                        let (uuid, data) = read_custom_icon(reader)?;
                        map.insert(uuid, data);
                    }
                    _ => {}
                }
            }

            XmlEvent::EndElement { name, .. } => {
                if name.local_name == kdb2::CUSTOM_ICONS_TAG {
                    break;
                }
            }

            _ => {}
        }
    }

    Ok(map)
}

fn read_custom_icon<R: Read>(reader: &mut EventReader<R>) -> Result<(CustomIconUuid, Vec<u8>)> {
    let mut uuid: Option<CustomIconUuid> = None;
    let mut data: Option<Vec<u8>> = None;
    loop {
        let event = reader.next()?;
        match event {
            XmlEvent::StartElement { name, .. } => {
                match name.local_name.as_str() {
                    kdb2::DATA_TAG => {
                        data = xml::read_binary_opt(reader)?;
                    }
                    kdb2::UUID_TAG => {
                        uuid = xml::read_custom_icon_uuid_opt(reader)?;
                    }
                    _ => {}
                }
            }

            XmlEvent::EndElement { name, .. } => {
                if name.local_name == kdb2::ICON_TAG {
                    break;
                }
            }

            _ => {}
        }
    }

    let uuid = match uuid {
        Some(u) => u,
        None => return xml::read_err(reader, "UUID element not found"),
    };

    let data = match data {
        Some(d) => d,
        None => return xml::read_err(reader, "Data element not found"),
    };

    Ok((uuid, data))
}

fn read_memory_protection<R: Read>(reader: &mut EventReader<R>, data: &mut XmlData) -> Result<()> {
    loop {
        let event = reader.next()?;
        match event {
            XmlEvent::StartElement { name, .. } => {
                match name.local_name.as_str() {
                    kdb2::PROTECT_NOTES_TAG => {
                        data.protect_notes = xml::read_bool(reader)?;
                    }
                    kdb2::PROTECT_PASSWORD_TAG => {
                        data.protect_password = xml::read_bool(reader)?;
                    }
                    kdb2::PROTECT_TITLE_TAG => {
                        data.protect_title = xml::read_bool(reader)?;
                    }
                    kdb2::PROTECT_URL_TAG => {
                        data.protect_url = xml::read_bool(reader)?;
                    }
                    kdb2::PROTECT_USERNAME_TAG => {
                        data.protect_username = xml::read_bool(reader)?;
                    }
                    _ => {}
                }
            }

            XmlEvent::EndElement { name, .. } => {
                if name.local_name == kdb2::MEMORY_PROTECTION_TAG {
                    break;
                }
            }

            _ => {}
        }
    }

    Ok(())
}

fn read_group<R: Read>(reader: &mut EventReader<R>, cipher: &mut Salsa20, parent: GroupUuid) -> Result<Group> {
    let mut node = Group::default();
    node.parent = parent;
    loop {
        let event = reader.next()?;
        match event {
            XmlEvent::StartElement { name, .. } => {
                match name.local_name.as_str() {
                    kdb2::CUSTOM_ICON_UUID_TAG => {
                        node.custom_icon_uuid = xml::read_custom_icon_uuid_opt(reader)?;
                    }
                    kdb2::DEFAULT_AUTO_TYPE_SEQUENCE_TAG => {
                        node.def_auto_type_sequence = xml::read_string(reader)?;
                    }
                    kdb2::ENABLE_AUTO_TYPE_TAG => {
                        node.enable_auto_type = xml::read_bool_opt(reader)?;
                    }
                    kdb2::ENABLE_SEARCHING_TAG => {
                        node.enable_searching = xml::read_bool_opt(reader)?;
                    }
                    kdb2::ENTRY_TAG => {
                        node.entries.push(read_entry(reader, cipher, EntryState::Active, GroupUuid::nil())?);
                    }
                    kdb2::GROUP_TAG => {
                        node.groups.push(read_group(reader, cipher, GroupUuid::nil())?);
                    }
                    kdb2::ICON_ID_TAG => {
                        node.icon = xml::read_icon(reader)?;
                    }
                    kdb2::IS_EXPANDED_TAG => {
                        node.is_expanded = xml::read_bool(reader)?;
                    }
                    kdb2::LAST_TOP_VISIBLE_ENTRY_TAG => {
                        node.last_top_visible_entry = EntryUuid(xml::read_uuid(reader)?);
                    }
                    kdb2::NAME_TAG => {
                        node.name = xml::read_string(reader)?;
                    }
                    kdb2::NOTES_TAG => {
                        node.notes = xml::read_string(reader)?;
                    }
                    kdb2::TIMES_TAG => {
                        read_times(reader, &mut node)?;
                    }
                    kdb2::UUID_TAG => {
                        node.uuid = GroupUuid(xml::read_uuid(reader)?);
                    }
                    _ => {}
                }
            }

            XmlEvent::EndElement { name, .. } => {
                if name.local_name == kdb2::GROUP_TAG {
                    break;
                }
            }

            _ => {}
        }
    }
    // Has to be done after building up the entries/groups because the UUID is not known at the time
    // the entries get constructed
    let parent = node.uuid.clone();
    for entry in node.entries.iter_mut() {
        entry.parent = parent;
    }
    for group in node.groups.iter_mut() {
        group.parent = parent;
    }

    Ok(node)
}

fn read_entry<R: Read>(
    reader: &mut EventReader<R>,
    cipher: &mut Salsa20,
    state: EntryState,
    parent: GroupUuid,
) -> Result<Entry> {
    let mut node = Entry::default();
    loop {
        let event = reader.next()?;
        match event {
            XmlEvent::StartElement { name, .. } => {
                node.parent = parent;
                match name.local_name.as_str() {
                    kdb2::AUTO_TYPE_TAG => {
                        read_auto_type(reader, &mut node)?;
                    }
                    kdb2::BACKGROUND_COLOR_TAG => {
                        node.background_color = xml::read_color_opt(reader)?;
                    }
                    kdb2::BINARY_TAG => {
                        let (key, value) = read_binary(reader, cipher)?;
                        node.binaries.insert(key, value);
                    }
                    kdb2::CUSTOM_ICON_UUID_TAG => {
                        node.custom_icon_uuid = xml::read_custom_icon_uuid_opt(reader)?;
                    }
                    kdb2::FOREGROUND_COLOR_TAG => {
                        node.foreground_color = xml::read_color_opt(reader)?;
                    }
                    kdb2::HISTORY_TAG => {
                        if state == EntryState::Active {
                            node.history.append(&mut read_history(reader, cipher, parent.clone())?);
                        }
                    }
                    kdb2::ICON_ID_TAG => {
                        node.icon = xml::read_icon(reader)?;
                    }
                    kdb2::OVERRIDE_URL_TAG => {
                        node.override_url = xml::read_string(reader)?;
                    }
                    kdb2::STRING_TAG => {
                        let (key, value) = read_string(reader, cipher)?;
                        node.strings.insert(key, value);
                    }
                    kdb2::TAGS_TAG => {
                        node.tags = xml::read_string(reader)?;
                    }
                    kdb2::TIMES_TAG => {
                        read_times(reader, &mut node)?;
                    }
                    kdb2::UUID_TAG => {
                        node.uuid = EntryUuid(xml::read_uuid(reader)?);
                    }
                    _ => {}
                }
            }

            XmlEvent::EndElement { name, .. } => {
                if name.local_name == kdb2::ENTRY_TAG {
                    break;
                }
            }

            _ => {}
        }
    }
    Ok(node)
}

fn read_auto_type<R: Read>(reader: &mut EventReader<R>, node: &mut Entry) -> Result<()> {
    loop {
        let event = reader.next()?;
        match event {
            XmlEvent::StartElement { name, .. } => {
                #[allow(unused_must_use)]
                match name.local_name.as_str() {
                    kdb2::ASSOCIATION_TAG => {
                        read_association(reader)
                            .map(|x| node.associations.push(x))
                            .map_err(|err| eprintln!("{}", err))
                        ;
                    }
                    kdb2::DATA_TRANSFER_OBFUSCATION_TAG => {
                        node.auto_type_obfuscation = xml::read_obfuscation(reader)?;
                    }
                    kdb2::DEFAULT_SEQUENCE_TAG => {
                        node.auto_type_def_sequence = xml::read_string(reader)?;
                    }
                    kdb2::ENABLED_TAG => {
                        node.auto_type_enabled = xml::read_bool(reader)?;
                    }
                    _ => {}
                }
            }

            XmlEvent::EndElement { name, .. } => {
                if name.local_name == kdb2::AUTO_TYPE_TAG {
                    break;
                }
            }

            _ => {}
        }
    }
    Ok(())
}

fn read_association<R: Read>(reader: &mut EventReader<R>) -> Result<Association> {
    let mut keystroke: Option<String> = None;
    let mut window: Option<String> = None;
    loop {
        let event = reader.next()?;
        match event {
            XmlEvent::StartElement { name, .. } => {
                match name.local_name.as_str() {
                    kdb2::KEYSTROKE_SEQUENCE_TAG => {
                        keystroke = xml::read_string_opt(reader)?;
                    }
                    kdb2::WINDOW_TAG => {
                        window = xml::read_string_opt(reader)?;
                    }
                    _ => {}
                }
            }

            XmlEvent::EndElement { name, .. } => {
                if name.local_name == kdb2::ASSOCIATION_TAG {
                    break;
                }
            }

            _ => {}
        }
    }

    let keystroke = match keystroke {
        Some(k) => k,
        None => return xml::read_err(reader, "KeystrokeSequence element not found"),
    };

    let window = match window {
        Some(w) => w,
        None => return xml::read_err(reader, "Window element not found"),
    };

    Ok(Association {
        keystroke_sequence: keystroke,
        window: window,
    })
}

fn read_binary<R: Read>(
    reader: &mut EventReader<R>,
    cipher: &mut Salsa20,
) -> Result<(BinaryKey, BinaryValue)> {
    let mut key: Option<BinaryKey> = None;
    let mut value: Option<BinaryValue> = None;
    loop {
        let event = reader.next()?;
        match event {
            XmlEvent::StartElement { name, attributes, .. } => {
                match name.local_name.as_str() {
                    kdb2::KEY_TAG => {
                        key = xml::read_binary_key_opt(reader)?;
                    }
                    kdb2::VALUE_TAG => {
                        value = xml::read_binary_value_opt(reader, cipher, &attributes)?;
                    }
                    _ => {}
                }
            }

            XmlEvent::EndElement { name, .. } => {
                if name.local_name == kdb2::BINARY_TAG {
                    break;
                }
            }

            _ => {}
        }
    }

    let key = match key {
        Some(k) => k,
        None => return xml::read_err(reader, "Key element not found"),
    };

    let value = match value {
        Some(v) => v,
        None => return xml::read_err(reader, "Value element not found"),
    };

    Ok((key, value))
}

fn read_history<R: Read>(reader: &mut EventReader<R>, cipher: &mut Salsa20, parent: GroupUuid ) -> Result<Vec<Entry>> {
    let mut list = Vec::new();
    loop {
        let event = reader.next()?;
        match event {
            XmlEvent::StartElement { name, .. } => {
                match name.local_name.as_str() {
                    kdb2::ENTRY_TAG => {
                        list.push(read_entry(reader, cipher, EntryState::History, parent)?);
                    }
                    _ => {}
                }
            }

            XmlEvent::EndElement { name, .. } => {
                if name.local_name == kdb2::HISTORY_TAG {
                    break;
                }
            }

            _ => {}
        }
    }

    Ok(list)
}

fn read_string<R: Read>(
    reader: &mut EventReader<R>,
    cipher: &mut Salsa20,
) -> Result<(StringKey, StringValue)> {
    let mut key: Option<StringKey> = None;
    let mut value: Option<StringValue> = None;
    loop {
        let event = reader.next()?;
        match event {
            XmlEvent::StartElement { name, attributes, .. } => {
                match name.local_name.as_str() {
                    kdb2::KEY_TAG => {
                        key = xml::read_string_key_opt(reader)?;
                    }
                    kdb2::VALUE_TAG => {
                        value = xml::read_string_value_opt(reader, cipher, &attributes)?;
                    }
                    _ => {}
                }
            }

            XmlEvent::EndElement { name, .. } => {
                if name.local_name == kdb2::STRING_TAG {
                    break;
                }
            }

            _ => {}
        }
    }

    let key = match key {
        Some(k) => k,
        None => return xml::read_err(reader, "Key element not found"),
    };

    let value = match value {
        Some(v) => v,
        None => return xml::read_err(reader, "Value element not found"),
    };

    Ok((key, value))
}

fn read_times<N, R>(reader: &mut EventReader<R>, node: &mut N) -> Result<()>
where
    N: Times,
    R: Read,
{
    loop {
        let event = reader.next()?;
        match event {
            XmlEvent::StartElement { name, .. } => {
                match name.local_name.as_str() {
                    kdb2::CREATION_TIME_TAG => {
                        node.set_creation_time(xml::read_datetime(reader)?);
                    }
                    kdb2::EXPIRY_TIME_TAG => {
                        node.set_expiry_time(xml::read_datetime(reader)?);
                    }
                    kdb2::EXPIRES_TAG => {
                        node.set_expires(xml::read_bool(reader)?);
                    }
                    kdb2::LAST_ACCESS_TIME_TAG => {
                        node.set_last_accessed(xml::read_datetime(reader)?);
                    }
                    kdb2::LAST_MODIFICATION_TIME_TAG => {
                        node.set_last_modified(xml::read_datetime(reader)?);
                    }
                    kdb2::LOCATION_CHANGED_TAG => {
                        node.set_location_changed(xml::read_datetime(reader)?);
                    }
                    kdb2::USAGE_COUNT_TAG => {
                        node.set_usage_count(xml::read_i32(reader)?);
                    }
                    _ => {}
                }
            }

            XmlEvent::EndElement { name, .. } => {
                if name.local_name == kdb2::TIMES_TAG {
                    break;
                }
            }

            _ => {}
        }
    }

    Ok(())
}

fn get_compressed_attr_value<R: Read>(
    reader: &mut EventReader<R>,
    attrs: &Vec<OwnedAttribute>,
) -> Result<bool> {
    match xml::search_attr_value(attrs, "compressed") {
        Some(val) => {
            match val.to_lowercase().parse::<bool>() {
                Ok(val) => Ok(val),
                Err(_) => xml::read_err(reader, "Attribute Compressed invalid value"),
            }
        }
        None => Ok(false),
    }
}

fn get_id_attr_value<R: Read>(
    reader: &mut EventReader<R>,
    attrs: &Vec<OwnedAttribute>,
) -> Result<String> {
    match xml::search_attr_value(attrs, "id") {
        Some(id) => Ok(id),
        None => xml::read_err(reader, "Attribute ID not found"),
    }
}
