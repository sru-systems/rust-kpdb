// Copyright (c) 2016-2017 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use chrono::{DateTime, Utc};
use common;
use std::collections::HashMap;
use super::association::Association;
use super::binary_key::BinaryKey;
use super::binary_value::BinaryValue;
use super::color::Color;
use super::custom_icon_uuid::CustomIconUuid;
use super::entry_uuid::EntryUuid;
use super::icon::Icon;
use super::obfuscation::Obfuscation;
use super::string_key::StringKey;
use super::string_value::StringValue;
use super::strings_map::StringsMap;
use super::times::Times;

/// An entry in the database.
#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    /// Auto-type associations.
    pub associations: Vec<Association>,

    /// Default auto-type sequence.
    pub auto_type_def_sequence: String,

    /// Whether auto-type is enabled.
    pub auto_type_enabled: bool,

    /// The type of obfuscation to use for auto-typing.
    pub auto_type_obfuscation: Obfuscation,

    /// The background color.
    pub background_color: Option<Color>,

    /// Map with binaries.
    pub binaries: HashMap<BinaryKey, BinaryValue>,

    /// The date and time this entry was created.
    pub creation_time: DateTime<Utc>,

    /// The identifier of this entry's custom icon if any.
    pub custom_icon_uuid: Option<CustomIconUuid>,

    /// Whether this entry expires.
    pub expires: bool,

    /// The date and time this entry will expire if expires is true.
    pub expiry_time: DateTime<Utc>,

    /// The foreground color.
    pub foreground_color: Option<Color>,

    /// This entry's icon.
    pub icon: Icon,

    /// The date and time this entry was last accessed.
    pub last_accessed: DateTime<Utc>,

    /// The date and time this entry was last modified.
    pub last_modified: DateTime<Utc>,

    /// The date and time the location of this entry was changed.
    pub location_changed: DateTime<Utc>,

    /// Override URL.
    pub override_url: String,

    /// Map with strings.
    pub strings: StringsMap,

    /// The tags associated with this entry.
    pub tags: String,

    /// The usage count of this entry.
    pub usage_count: i32,

    /// The identifier of this entry.
    pub uuid: EntryUuid,
}

impl Entry {
    /// Create a new entry.
    pub fn new() -> Entry {
        let mut entry = Entry::default();
        let notes = StringValue::new("", common::PROTECT_NOTES_DEFAULT);
        let password = StringValue::new("", common::PROTECT_PASSWORD_DEFAULT);
        let title = StringValue::new("", common::PROTECT_TITLE_DEFAULT);
        let url = StringValue::new("", common::PROTECT_URL_DEFAULT);
        let username = StringValue::new("", common::PROTECT_USERNAME_DEFAULT);
        entry.strings.insert(StringKey::Notes, notes);
        entry.strings.insert(StringKey::Password, password);
        entry.strings.insert(StringKey::Title, title);
        entry.strings.insert(StringKey::Url, url);
        entry.strings.insert(StringKey::Username, username);
        entry.uuid = EntryUuid::new_random();
        entry
    }
}

impl Default for Entry {
    fn default() -> Entry {
        let now = Utc::now();
        Entry {
            associations: Default::default(),
            auto_type_def_sequence: Default::default(),
            auto_type_enabled: true,
            auto_type_obfuscation: Default::default(),
            background_color: Default::default(),
            binaries: Default::default(),
            creation_time: now,
            custom_icon_uuid: Default::default(),
            expires: false,
            expiry_time: now,
            foreground_color: Default::default(),
            icon: Icon::Key,
            last_accessed: now,
            last_modified: now,
            location_changed: now,
            override_url: Default::default(),
            strings: Default::default(),
            tags: Default::default(),
            usage_count: Default::default(),
            uuid: Default::default(),
        }
    }
}

impl Times for Entry {
    fn creation_time(&self) -> DateTime<Utc> {
        self.creation_time
    }

    fn expires(&self) -> bool {
        self.expires
    }

    fn expiry_time(&self) -> DateTime<Utc> {
        self.expiry_time
    }

    fn last_accessed(&self) -> DateTime<Utc> {
        self.last_accessed
    }

    fn last_modified(&self) -> DateTime<Utc> {
        self.last_modified
    }

    fn location_changed(&self) -> DateTime<Utc> {
        self.location_changed
    }

    fn usage_count(&self) -> i32 {
        self.usage_count
    }

    fn set_creation_time(&mut self, val: DateTime<Utc>) {
        self.creation_time = val;
    }

    fn set_expires(&mut self, val: bool) {
        self.expires = val;
    }

    fn set_expiry_time(&mut self, val: DateTime<Utc>) {
        self.expiry_time = val;
    }

    fn set_last_accessed(&mut self, val: DateTime<Utc>) {
        self.last_accessed = val;
    }

    fn set_last_modified(&mut self, val: DateTime<Utc>) {
        self.last_modified = val;
    }

    fn set_location_changed(&mut self, val: DateTime<Utc>) {
        self.location_changed = val;
    }

    fn set_usage_count(&mut self, val: i32) {
        self.usage_count = val;
    }
}

#[cfg(test)]
mod tests {

    use chrono::Utc;
    use std::collections::HashMap;
    use super::*;
    use types::EntryUuid;
    use types::Icon;
    use types::Obfuscation;
    use types::StringKey;
    use types::StringsMap;
    use utils::test::approx_equal_datetime;

    #[test]
    fn test_new_returns_correct_instance() {
        let now = Utc::now();
        let entry = Entry::new();
        assert_eq!(entry.associations, Vec::new());
        assert_eq!(entry.auto_type_def_sequence, "");
        assert_eq!(entry.auto_type_enabled, true);
        assert_eq!(entry.auto_type_obfuscation, Obfuscation::None);
        assert_eq!(entry.background_color, None);
        assert_eq!(entry.binaries, HashMap::new());
        assert!(approx_equal_datetime(entry.creation_time, now));
        assert_eq!(entry.custom_icon_uuid, None);
        assert_eq!(entry.expires, false);
        assert!(approx_equal_datetime(entry.expiry_time, now));
        assert_eq!(entry.foreground_color, None);
        assert_eq!(entry.icon, Icon::Key);
        assert!(approx_equal_datetime(entry.last_accessed, now));
        assert!(approx_equal_datetime(entry.last_modified, now));
        assert!(approx_equal_datetime(entry.location_changed, now));
        assert_eq!(entry.override_url, "");
        assert_eq!(entry.strings.len(), 5);
        assert!(entry.strings.contains_key(&StringKey::Notes));
        assert!(entry.strings.contains_key(&StringKey::Password));
        assert!(entry.strings.contains_key(&StringKey::Title));
        assert!(entry.strings.contains_key(&StringKey::Url));
        assert!(entry.strings.contains_key(&StringKey::Username));
        assert_eq!(entry.tags, "");
        assert_eq!(entry.usage_count, 0);
        assert!(entry.uuid != EntryUuid::nil());
    }

    #[test]
    fn test_default_returns_correct_instance() {
        let now = Utc::now();
        let entry = Entry::default();
        assert_eq!(entry.associations, Vec::new());
        assert_eq!(entry.auto_type_def_sequence, "");
        assert_eq!(entry.auto_type_enabled, true);
        assert_eq!(entry.auto_type_obfuscation, Obfuscation::None);
        assert_eq!(entry.background_color, None);
        assert_eq!(entry.binaries, HashMap::new());
        assert!(approx_equal_datetime(entry.creation_time, now));
        assert_eq!(entry.custom_icon_uuid, None);
        assert_eq!(entry.expires, false);
        assert!(approx_equal_datetime(entry.expiry_time, now));
        assert_eq!(entry.foreground_color, None);
        assert_eq!(entry.icon, Icon::Key);
        assert!(approx_equal_datetime(entry.last_accessed, now));
        assert!(approx_equal_datetime(entry.last_modified, now));
        assert!(approx_equal_datetime(entry.location_changed, now));
        assert_eq!(entry.override_url, "");
        assert_eq!(entry.strings, StringsMap::new());
        assert_eq!(entry.tags, "");
        assert_eq!(entry.usage_count, 0);
        assert_eq!(entry.uuid, EntryUuid::nil());
    }
}
