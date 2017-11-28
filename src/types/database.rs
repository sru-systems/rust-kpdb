// Copyright (c) 2016-2017 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use chrono::{DateTime, Utc};
use common;
use format::{kdb2_reader, kdb2_writer};
use io::{Log, LogReader, LogWriter};
use std::io::{Read, Write};
use super::binaries_map::BinariesMap;
use super::color::Color;
use super::comment::Comment;
use super::composite_key::CompositeKey;
use super::compression::Compression;
use super::custom_data_map::CustomDataMap;
use super::custom_icons_map::CustomIconsMap;
use super::db_type::DbType;
use super::error::Error;
use super::group::Group;
use super::group_uuid::GroupUuid;
use super::groups_map::GroupsMap;
use super::icon::Icon;
use super::master_cipher::MasterCipher;
use super::result::Result;
use super::stream_cipher::StreamCipher;
use super::transform_rounds::TransformRounds;
use super::version::Version;

/// The KeePass database.
#[derive(Clone, Debug, PartialEq)]
pub struct Database {
    /// Content of the comment header.
    pub comment: Option<Comment>,

    /// Composite key.
    pub composite_key: CompositeKey,

    /// Compression algorithm.
    pub compression: Compression,

    /// Type of the database.
    pub db_type: DbType,

    /// Master encryption algorithm.
    pub master_cipher: MasterCipher,

    /// Stream encryption algorithm (e.g. passwords).
    pub stream_cipher: StreamCipher,

    /// Number of times the composite key must be transformed.
    pub transform_rounds: TransformRounds,

    /// The database version.
    pub version: Version,

    /// Map with binary data.
    pub binaries: BinariesMap,

    /// Optional color.
    pub color: Option<Color>,

    /// Map with custom data.
    pub custom_data: CustomDataMap,

    /// Map with custom icons.
    pub custom_icons: CustomIconsMap,

    /// Default username for new entries.
    pub def_username: String,

    /// The date and time the default username was changed.
    pub def_username_changed: DateTime<Utc>,

    /// Description of this database.
    pub description: String,

    /// The date and time the description was changed.
    pub description_changed: DateTime<Utc>,

    /// The date and time the entry templates group was changed.
    pub entry_templates_group_changed: DateTime<Utc>,

    /// The identifier of the group containing entry templates.
    pub entry_templates_group_uuid: GroupUuid,

    /// Name of the generator.
    pub generator: String,

    /// The identifier of the root group.
    pub group_uuid: Option<GroupUuid>,

    /// Map with groups.
    pub groups: GroupsMap,

    /// Maximum number of history items.
    pub history_max_items: i32,

    /// Maximum size of the history data.
    pub history_max_size: i32,

    /// The identifier of the last selected group.
    pub last_selected_group: GroupUuid,

    /// The identifier of the last top visible group.
    pub last_top_visible_group: GroupUuid,

    /// Number of days until history entries are being deleted.
    pub maintenance_history_days: i32,

    pub master_key_change_force: i32,

    pub master_key_change_rec: i32,

    /// The date and time the master key was changed.
    pub master_key_changed: DateTime<Utc>,

    /// Name of this database.
    pub name: String,

    /// The date and time the name was changed.
    pub name_changed: DateTime<Utc>,

    /// Whether notes must be protected.
    pub protect_notes: bool,

    /// Whether passwords must be protected.
    pub protect_password: bool,

    /// Whether titles must be protected.
    pub protect_title: bool,

    /// Whether URL's must be protected.
    pub protect_url: bool,

    /// Whether usernames must be protected.
    pub protect_username: bool,

    /// The date and time the recycle bin was changed.
    pub recycle_bin_changed: DateTime<Utc>,

    /// Whether the recycle bin is enabled.
    pub recycle_bin_enabled: bool,

    /// The identifier of the recycle bin.
    pub recycle_bin_uuid: GroupUuid,
}

impl Database {
    /// Create a new database.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use kpdb::{CompositeKey, Database};
    ///
    /// let key = CompositeKey::from_password("password");
    /// let db = Database::new(&key);
    /// ```
    pub fn new(key: &CompositeKey) -> Database {
        let now = Utc::now();
        let mut root = Group::new(common::ROOT_GROUP_NAME);
        let mut recycle_bin = Group::new(common::RECYCLE_BIN_NAME);
        let mut groups = GroupsMap::new();

        recycle_bin.enable_auto_type = Some(false);
        recycle_bin.enable_searching = Some(false);
        recycle_bin.icon = Icon::RecycleBin;

        let root_uuid = root.uuid;
        let recycle_bin_uuid = recycle_bin.uuid;
        root.groups.push(recycle_bin_uuid);
        groups.insert(root_uuid, root);
        groups.insert(recycle_bin_uuid, recycle_bin);

        Database {
            comment: None,
            composite_key: key.clone(),
            compression: Compression::GZip,
            db_type: DbType::Kdb2,
            master_cipher: MasterCipher::Aes256,
            stream_cipher: StreamCipher::Salsa20,
            transform_rounds: TransformRounds(10000),
            version: Version::new_kdb2(),
            binaries: BinariesMap::new(),
            color: None,
            custom_data: CustomDataMap::new(),
            custom_icons: CustomIconsMap::new(),
            def_username: String::new(),
            def_username_changed: now,
            description: String::new(),
            description_changed: now,
            entry_templates_group_changed: now,
            entry_templates_group_uuid: GroupUuid::nil(),
            generator: String::from(common::GENERATOR_NAME),
            group_uuid: Some(root_uuid),
            groups: groups,
            history_max_items: common::HISTORY_MAX_ITEMS_DEFAULT,
            history_max_size: common::HISTORY_MAX_SIZE_DEFAULT,
            last_selected_group: GroupUuid::nil(),
            last_top_visible_group: GroupUuid::nil(),
            maintenance_history_days: common::MAINTENANCE_HISTORY_DAYS_DEFAULT,
            master_key_change_force: common::MASTER_KEY_CHANGE_FORCE_DEFAULT,
            master_key_change_rec: common::MASTER_KEY_CHANGE_REC_DEFAULT,
            master_key_changed: now,
            name: String::new(),
            name_changed: now,
            protect_notes: common::PROTECT_NOTES_DEFAULT,
            protect_password: common::PROTECT_PASSWORD_DEFAULT,
            protect_title: common::PROTECT_TITLE_DEFAULT,
            protect_url: common::PROTECT_URL_DEFAULT,
            protect_username: common::PROTECT_USERNAME_DEFAULT,
            recycle_bin_changed: now,
            recycle_bin_enabled: common::RECYCLE_BIN_ENABLED_DEFAULT,
            recycle_bin_uuid: recycle_bin_uuid,
        }
    }

    /// Attempts to open an existing database.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use kpdb::Result;
    /// use kpdb::{CompositeKey, Database};
    /// use std::fs::File;
    ///
    /// # fn open_example() -> Result<()> {
    /// let mut file = try!(File::open("passwords.kdbx"));
    /// let key = CompositeKey::from_password("password");
    /// let db = try!(Database::open(&mut file, &key));
    /// # Ok(())
    /// # }
    /// ```
    pub fn open<R: Read>(reader: &mut R, key: &CompositeKey) -> Result<Database> {
        let mut reader = LogReader::new(reader);
        let mut buffer = [0u8; 4];

        try!(reader.read(&mut buffer));
        if buffer != common::DB_SIGNATURE {
            return Err(Error::InvalidDbSignature(buffer));
        }

        try!(reader.read(&mut buffer));
        if buffer == common::KDB1_SIGNATURE {
            return Err(Error::UnhandledDbType(buffer));
        } else if buffer == common::KDB2_SIGNATURE {
            Database::open_kdb2(&mut reader, key)
        } else {
            return Err(Error::UnhandledDbType(buffer));
        }
    }

    /// Attempts to save the database.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use kpdb::Result;
    /// use kpdb::{CompositeKey, Database};
    /// use std::fs::File;
    ///
    /// # fn save_example() -> Result<()> {
    /// let key = CompositeKey::from_password("password");
    /// let db = Database::new(&key);
    /// let mut file = try!(File::create("new.kdbx"));
    ///
    /// try!(db.save(&mut file));
    /// # Ok(())
    /// # }
    /// ```
    pub fn save<W: Write>(&self, writer: &mut W) -> Result<()> {
        let mut writer = LogWriter::new(writer);
        match self.db_type {
            DbType::Kdb1 => Err(Error::Unimplemented(String::from("KeePass v1 not supported"))),
            DbType::Kdb2 => kdb2_writer::write(&mut writer, self),
        }
    }

    fn open_kdb2<R: Log + Read>(reader: &mut R, key: &CompositeKey) -> Result<Database> {
        let (meta_data, xml_data) = try!(kdb2_reader::read(reader, key));
        match xml_data.header_hash {
            Some(header_hash) => {
                if meta_data.header_hash != header_hash {
                    return Err(Error::InvalidHeaderHash);
                }
            }
            None => {}
        }

        let db = Database {
            comment: meta_data.comment,
            composite_key: key.clone(),
            compression: meta_data.compression,
            db_type: DbType::Kdb2,
            master_cipher: meta_data.master_cipher,
            stream_cipher: meta_data.stream_cipher,
            transform_rounds: meta_data.transform_rounds,
            version: meta_data.version,

            binaries: xml_data.binaries,
            color: xml_data.color,
            custom_data: xml_data.custom_data,
            custom_icons: xml_data.custom_icons,
            def_username: xml_data.def_username,
            def_username_changed: xml_data.def_username_changed,
            description: xml_data.description,
            description_changed: xml_data.description_changed,
            entry_templates_group_changed: xml_data.entry_templates_group_changed,
            entry_templates_group_uuid: xml_data.entry_templates_group_uuid,
            generator: xml_data.generator,
            group_uuid: xml_data.group_uuid,
            groups: xml_data.groups,
            history_max_items: xml_data.history_max_items,
            history_max_size: xml_data.history_max_size,
            last_selected_group: xml_data.last_selected_group,
            last_top_visible_group: xml_data.last_top_visible_group,
            maintenance_history_days: xml_data.maintenance_history_days,
            master_key_change_force: xml_data.master_key_change_force,
            master_key_change_rec: xml_data.master_key_change_rec,
            master_key_changed: xml_data.master_key_changed,
            name: xml_data.name,
            name_changed: xml_data.name_changed,
            protect_notes: xml_data.protect_notes,
            protect_password: xml_data.protect_password,
            protect_title: xml_data.protect_title,
            protect_url: xml_data.protect_url,
            protect_username: xml_data.protect_username,
            recycle_bin_changed: xml_data.recycle_bin_changed,
            recycle_bin_enabled: xml_data.recycle_bin_enabled,
            recycle_bin_uuid: xml_data.recycle_bin_uuid,
        };

        Ok(db)
    }
}

#[cfg(test)]
mod tests {

    use chrono::Utc;
    use super::*;
    use types::BinariesMap;
    use types::CompositeKey;
    use types::Compression;
    use types::CustomDataMap;
    use types::CustomIconsMap;
    use types::DbType;
    use types::GroupUuid;
    use types::MasterCipher;
    use types::StreamCipher;
    use types::TransformRounds;
    use types::Version;
    use utils::test::approx_equal_datetime;

    #[test]
    fn test_new_returns_correct_instance() {
        let now = Utc::now();
        let key = CompositeKey::from_password("5pZ5mgpTkLCDaM46IuH7yGafZFIICyvC");
        let db = Database::new(&key);
        assert_eq!(db.comment, None);
        assert_eq!(db.composite_key, key);
        assert_eq!(db.compression, Compression::GZip);
        assert_eq!(db.db_type, DbType::Kdb2);
        assert_eq!(db.master_cipher, MasterCipher::Aes256);
        assert_eq!(db.stream_cipher, StreamCipher::Salsa20);
        assert_eq!(db.transform_rounds, TransformRounds(10000));
        assert_eq!(db.version, Version::new_kdb2());
        assert_eq!(db.binaries, BinariesMap::new());
        assert_eq!(db.color, None);
        assert_eq!(db.custom_data, CustomDataMap::new());
        assert_eq!(db.custom_icons, CustomIconsMap::new());
        assert_eq!(db.def_username, "");
        assert!(approx_equal_datetime(db.def_username_changed, now));
        assert_eq!(db.description, "");
        assert!(approx_equal_datetime(db.description_changed, now));
        assert!(approx_equal_datetime(db.entry_templates_group_changed, now));
        assert_eq!(db.entry_templates_group_uuid, GroupUuid::nil());
        assert_eq!(db.generator, "rust-kpdb");
        assert!(db.group_uuid != None);
        assert!(db.group_uuid != Some(GroupUuid::nil()));
        assert_eq!(db.groups.len(), 2);
        assert_eq!(db.history_max_items, 10);
        assert_eq!(db.history_max_size, 6291456);
        assert_eq!(db.last_selected_group, GroupUuid::nil());
        assert_eq!(db.last_top_visible_group, GroupUuid::nil());
        assert_eq!(db.maintenance_history_days, 365);
        assert_eq!(db.master_key_change_force, -1);
        assert_eq!(db.master_key_change_rec, -1);
        assert!(approx_equal_datetime(db.master_key_changed, now));
        assert_eq!(db.name, "");
        assert!(approx_equal_datetime(db.name_changed, now));
        assert_eq!(db.protect_notes, false);
        assert_eq!(db.protect_password, true);
        assert_eq!(db.protect_title, false);
        assert_eq!(db.protect_url, false);
        assert_eq!(db.protect_username, false);
        assert!(approx_equal_datetime(db.recycle_bin_changed, now));
        assert_eq!(db.recycle_bin_enabled, true);
        assert!(db.recycle_bin_uuid != GroupUuid::nil());
    }
}
