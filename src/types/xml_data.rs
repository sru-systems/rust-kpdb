// Copyright (c) 2016-2017 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::binaries_map::BinariesMap;
use super::color::Color;
use super::custom_data_map::CustomDataMap;
use super::custom_icons_map::CustomIconsMap;
use super::group::Group;
use super::group_uuid::GroupUuid;
use super::header_hash::HeaderHash;
use crate::common;
use chrono::{DateTime, Utc};

/// Represents the XML data of the database.
#[derive(Clone, Debug, PartialEq)]
pub struct XmlData {
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

    /// Date and time the description was changed.
    pub description_changed: DateTime<Utc>,

    /// The date and time the entry templates group was changed.
    pub entry_templates_group_changed: DateTime<Utc>,

    /// The identifier of the group containing entry templates.
    pub entry_templates_group_uuid: GroupUuid,

    /// Name of the generator.
    pub generator: String,

    /// Hash of the headers as stored in the XML data.
    pub header_hash: Option<HeaderHash>,

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

    /// Whether password must be protected.
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

    /// The root group.
    pub root_group: Option<Group>,
}

impl Default for XmlData {
    fn default() -> XmlData {
        let now = Utc::now();
        XmlData {
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
            generator: String::new(),
            header_hash: None,
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
            recycle_bin_uuid: GroupUuid::nil(),
            root_group: None,
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::types::BinariesMap;
    use crate::types::CustomDataMap;
    use crate::types::CustomIconsMap;
    use crate::types::GroupUuid;
    use crate::utils::test::approx_equal_datetime;
    use chrono::Utc;

    #[test]
    fn test_default_returns_correct_instance() {
        let now = Utc::now();
        let data = XmlData::default();
        assert_eq!(data.binaries, BinariesMap::new());
        assert_eq!(data.color, None);
        assert_eq!(data.custom_data, CustomDataMap::new());
        assert_eq!(data.custom_icons, CustomIconsMap::new());
        assert_eq!(data.def_username, "");
        assert!(approx_equal_datetime(data.def_username_changed, now));
        assert_eq!(data.description, "");
        assert!(approx_equal_datetime(data.description_changed, now));
        assert!(approx_equal_datetime(data.entry_templates_group_changed, now));
        assert_eq!(data.entry_templates_group_uuid, GroupUuid::nil());
        assert_eq!(data.generator, "");
        assert_eq!(data.header_hash, None);
        assert_eq!(data.history_max_items, 10);
        assert_eq!(data.history_max_size, 6291456);
        assert_eq!(data.last_selected_group, GroupUuid::nil());
        assert_eq!(data.last_top_visible_group, GroupUuid::nil());
        assert_eq!(data.maintenance_history_days, 365);
        assert_eq!(data.master_key_change_force, -1);
        assert_eq!(data.master_key_change_rec, -1);
        assert!(approx_equal_datetime(data.master_key_changed, now));
        assert_eq!(data.name, "");
        assert!(approx_equal_datetime(data.name_changed, now));
        assert_eq!(data.protect_notes, false);
        assert_eq!(data.protect_password, true);
        assert_eq!(data.protect_title, false);
        assert_eq!(data.protect_url, false);
        assert_eq!(data.protect_username, false);
        assert!(approx_equal_datetime(data.recycle_bin_changed, now));
        assert_eq!(data.recycle_bin_enabled, true);
        assert_eq!(data.recycle_bin_uuid, GroupUuid::nil());
        assert_eq!(data.root_group, None);
    }
}
