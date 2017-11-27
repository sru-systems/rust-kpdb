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
        entry.uuid = EntryUuid::new_random();
        entry
    }

    /// Gets the "Notes" string value if any.
    pub fn notes(&self) -> Option<&StringValue> {
        self.other(StringKey::Notes)
    }

    /// Gets an "Other" string value if any.
    pub fn other(&self, key: StringKey) -> Option<&StringValue> {
        self.strings.get(&key)
    }

    /// Gets the "Password" string value if any.
    pub fn password(&self) -> Option<&StringValue> {
        self.other(StringKey::Password)
    }

    /// Sets the "Notes" string value.
    pub fn set_notes(&mut self, val: StringValue) {
        self.set_other(StringKey::Notes, val);
    }

    /// Sets the "Notes" string value from a string.
    pub fn set_notes_str<S: Into<String>>(&mut self, val: S) {
        self.set_notes(StringValue::new(val, common::PROTECT_NOTES_DEFAULT));
    }

    /// Sets an "Other" string value.
    pub fn set_other(&mut self, key: StringKey, val: StringValue) {
        self.strings.insert(key, val);
    }

    /// Sets an "Other" string value from a string.
    pub fn set_other_str<S: Into<String>>(&mut self, key: StringKey, val: S) {
        self.set_other(key, StringValue::new(val, false));
    }

    /// Sets the "Password" string value.
    pub fn set_password(&mut self, val: StringValue) {
        self.set_other(StringKey::Password, val);
    }

    /// Sets the "Password" string value from a string.
    pub fn set_password_str<S: Into<String>>(&mut self, val: S) {
        self.set_password(StringValue::new(val, common::PROTECT_PASSWORD_DEFAULT));
    }

    /// Sets the "Title" string value.
    pub fn set_title(&mut self, val: StringValue) {
        self.set_other(StringKey::Title, val);
    }

    /// Sets the "Title" string value from a string.
    pub fn set_title_str<S: Into<String>>(&mut self, val: S) {
        self.set_title(StringValue::new(val, common::PROTECT_TITLE_DEFAULT));
    }

    /// Sets the "Url" string value.
    pub fn set_url(&mut self, val: StringValue) {
        self.set_other(StringKey::Url, val);
    }

    /// Sets the "Url" string value from a string.
    pub fn set_url_str<S: Into<String>>(&mut self, val: S) {
        self.set_url(StringValue::new(val, common::PROTECT_URL_DEFAULT));
    }

    /// Sets the "Username" string value.
    pub fn set_username(&mut self, val: StringValue) {
        self.set_other(StringKey::Username, val);
    }

    /// Sets the "Username" string value from a string.
    pub fn set_username_str<S: Into<String>>(&mut self, val: S) {
        self.set_username(StringValue::new(val, common::PROTECT_USERNAME_DEFAULT));
    }

    /// Gets the "Title" string value if any.
    pub fn title(&self) -> Option<&StringValue> {
        self.other(StringKey::Title)
    }

    /// Gets the "Url" string value if any.
    pub fn url(&self) -> Option<&StringValue> {
        self.other(StringKey::Url)
    }

    /// Gets the "Username" string value if any.
    pub fn username(&self) -> Option<&StringValue> {
        self.other(StringKey::Username)
    }
}

impl Default for Entry {
    fn default() -> Entry {
        let now = Utc::now();
        Entry {
            associations: Vec::new(),
            auto_type_def_sequence: String::new(),
            auto_type_enabled: true,
            auto_type_obfuscation: Obfuscation::None,
            background_color: None,
            binaries: HashMap::new(),
            creation_time: now,
            custom_icon_uuid: None,
            expires: false,
            expiry_time: now,
            foreground_color: None,
            icon: Icon::Key,
            last_accessed: now,
            last_modified: now,
            location_changed: now,
            override_url: String::new(),
            strings: StringsMap::new(),
            tags: String::new(),
            usage_count: 0,
            uuid: EntryUuid::nil(),
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
        assert_eq!(entry.strings, StringsMap::new());
        assert_eq!(entry.tags, "");
        assert_eq!(entry.usage_count, 0);
        assert!(entry.uuid != EntryUuid::nil());
    }

    #[test]
    fn test_notes_returns_none_on_default_entry() {
        let entry = Entry::default();
        assert_eq!(entry.notes(), None);
    }

    #[test]
    fn test_other_returns_none_on_default_entry() {
        let entry = Entry::default();
        let key = StringKey::from_string("other");
        assert_eq!(entry.other(key), None);
    }

    #[test]
    fn test_password_returns_none_on_default_entry() {
        let entry = Entry::default();
        assert_eq!(entry.password(), None);
    }

    #[test]
    fn test_set_notes_sets_notes() {
        let mut entry = Entry::default();
        let value = StringValue::new("test", false);
        entry.set_notes(value.clone());
        assert_eq!(entry.notes(), Some(&value));
    }

    #[test]
    fn test_set_notes_str_sets_notes() {
        let mut entry = Entry::default();
        let value = StringValue::new("test", false);
        entry.set_notes_str("test");
        assert_eq!(entry.notes(), Some(&value));
    }

    #[test]
    fn test_set_other_sets_other() {
        let mut entry = Entry::default();
        let key = StringKey::from_string("other");
        let value = StringValue::new("test", false);
        entry.set_other(key.clone(), value.clone());
        assert_eq!(entry.other(key), Some(&value));
    }

    #[test]
    fn test_set_other_str_sets_other() {
        let mut entry = Entry::default();
        let key = StringKey::from_string("other");
        let value = StringValue::new("test", false);
        entry.set_other_str(key.clone(), "test");
        assert_eq!(entry.other(key), Some(&value));
    }

    #[test]
    fn test_set_password_sets_password() {
        let mut entry = Entry::default();
        let value = StringValue::new("test", false);
        entry.set_password(value.clone());
        assert_eq!(entry.password(), Some(&value));
    }

    #[test]
    fn test_set_password_str_sets_password() {
        let mut entry = Entry::default();
        let value = StringValue::new("test", true);
        entry.set_password_str("test");
        assert_eq!(entry.password(), Some(&value));
    }

    #[test]
    fn test_set_title_sets_title() {
        let mut entry = Entry::default();
        let value = StringValue::new("test", false);
        entry.set_title(value.clone());
        assert_eq!(entry.title(), Some(&value));
    }

    #[test]
    fn test_set_title_str_sets_title() {
        let mut entry = Entry::default();
        let value = StringValue::new("test", false);
        entry.set_title_str("test");
        assert_eq!(entry.title(), Some(&value));
    }

    #[test]
    fn test_set_url_sets_url() {
        let mut entry = Entry::default();
        let value = StringValue::new("test", false);
        entry.set_url(value.clone());
        assert_eq!(entry.url(), Some(&value));
    }

    #[test]
    fn test_set_url_str_sets_url() {
        let mut entry = Entry::default();
        let value = StringValue::new("test", false);
        entry.set_url_str("test");
        assert_eq!(entry.url(), Some(&value));
    }

    #[test]
    fn test_set_username_sets_username() {
        let mut entry = Entry::default();
        let value = StringValue::new("test", false);
        entry.set_username(value.clone());
        assert_eq!(entry.username(), Some(&value));
    }

    #[test]
    fn test_set_username_str_sets_username() {
        let mut entry = Entry::default();
        let value = StringValue::new("test", false);
        entry.set_username_str("test");
        assert_eq!(entry.username(), Some(&value));
    }

    #[test]
    fn test_title_returns_none_on_default_entry() {
        let entry = Entry::default();
        assert_eq!(entry.title(), None);
    }

    #[test]
    fn test_url_returns_none_on_default_entry() {
        let entry = Entry::default();
        assert_eq!(entry.url(), None);
    }

    #[test]
    fn test_username_returns_none_on_default_entry() {
        let entry = Entry::default();
        assert_eq!(entry.username(), None);
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
