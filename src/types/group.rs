// Copyright (c) 2016-2017 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use chrono::{DateTime, UTC};
use super::custom_icon_uuid::CustomIconUuid;
use super::entry_uuid::EntryUuid;
use super::group_uuid::GroupUuid;
use super::icon::Icon;
use super::times::Times;

/// A group in the database.
#[derive(Clone, Debug, PartialEq)]
pub struct Group {
    /// The date and time this group was created.
    pub creation_time: DateTime<UTC>,

    /// The identifier of this group's custom icon if any.
    pub custom_icon_uuid: Option<CustomIconUuid>,

    /// Default auto-type sequence.
    pub def_auto_type_sequence: String,

    /// Whether auto-type is enabled.
    pub enable_auto_type: Option<bool>,

    /// Whether searching is enabled.
    pub enable_searching: Option<bool>,

    /// Vector with entry identifiers that belong to this group.
    pub entries: Vec<EntryUuid>,

    /// Whether this group expires.
    pub expires: bool,

    /// The date and time this group will expire if expires is true.
    pub expiry_time: DateTime<UTC>,

    /// Vector with group identifiers that are subgroups of this group.
    pub groups: Vec<GroupUuid>,

    /// This group's icon.
    pub icon: Icon,

    /// Whether this group is expanded.
    pub is_expanded: bool,

    /// The date and time this group was last accessed.
    pub last_accessed: DateTime<UTC>,

    /// The date and time this group was last modified.
    pub last_modified: DateTime<UTC>,

    /// The identifier of the last top visible entry.
    pub last_top_visible_entry: EntryUuid,

    /// The date and time the location of this group was changed.
    pub location_changed: DateTime<UTC>,

    /// The name of this group.
    pub name: String,

    /// The notes of this group.
    pub notes: String,

    /// The usage count of this group.
    pub usage_count: i32,

    /// The identifier of this group.
    pub uuid: GroupUuid,
}

impl Group {
    /// Create a new group.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use kpdb::Group;
    ///
    /// let group = Group::new("Websites");
    /// ```
    pub fn new<S: Into<String>>(name: S) -> Group {
        let mut group = Group::default();
        group.name = name.into();
        group.uuid = GroupUuid::new_random();
        group
    }
}

impl Default for Group {
    fn default() -> Group {
        let now = UTC::now();
        Group {
            creation_time: now,
            custom_icon_uuid: Default::default(),
            def_auto_type_sequence: Default::default(),
            enable_auto_type: Default::default(),
            enable_searching: Default::default(),
            entries: Default::default(),
            expires: false,
            expiry_time: now,
            groups: Default::default(),
            icon: Icon::Folder,
            is_expanded: true,
            last_accessed: now,
            last_modified: now,
            last_top_visible_entry: Default::default(),
            location_changed: now,
            name: Default::default(),
            notes: Default::default(),
            usage_count: Default::default(),
            uuid: Default::default(),
        }
    }
}

impl Times for Group {
    fn creation_time(&self) -> DateTime<UTC> {
        self.creation_time
    }

    fn expires(&self) -> bool {
        self.expires
    }

    fn expiry_time(&self) -> DateTime<UTC> {
        self.expiry_time
    }

    fn last_accessed(&self) -> DateTime<UTC> {
        self.last_accessed
    }

    fn last_modified(&self) -> DateTime<UTC> {
        self.last_modified
    }

    fn location_changed(&self) -> DateTime<UTC> {
        self.location_changed
    }

    fn usage_count(&self) -> i32 {
        self.usage_count
    }

    fn set_creation_time(&mut self, val: DateTime<UTC>) {
        self.creation_time = val;
    }

    fn set_expires(&mut self, val: bool) {
        self.expires = val;
    }

    fn set_expiry_time(&mut self, val: DateTime<UTC>) {
        self.expiry_time = val;
    }

    fn set_last_accessed(&mut self, val: DateTime<UTC>) {
        self.last_accessed = val;
    }

    fn set_last_modified(&mut self, val: DateTime<UTC>) {
        self.last_modified = val;
    }

    fn set_location_changed(&mut self, val: DateTime<UTC>) {
        self.location_changed = val;
    }

    fn set_usage_count(&mut self, val: i32) {
        self.usage_count = val;
    }
}

#[cfg(test)]
mod tests {

    use chrono::{Duration, UTC};
    use super::*;
    use types::EntryUuid;
    use types::GroupUuid;
    use types::Icon;

    #[test]
    fn test_new_returns_correct_instance() {
        let now = UTC::now();
        let name = "Root";
        let group = Group::new(name.clone());
        assert!((group.creation_time - now) < Duration::seconds(1));
        assert_eq!(group.custom_icon_uuid, None);
        assert_eq!(group.def_auto_type_sequence, "");
        assert_eq!(group.enable_auto_type, None);
        assert_eq!(group.enable_searching, None);
        assert_eq!(group.entries, Vec::new());
        assert_eq!(group.expires, false);
        assert!((group.expiry_time - now) < Duration::seconds(1));
        assert_eq!(group.groups, Vec::new());
        assert_eq!(group.icon, Icon::Folder);
        assert_eq!(group.is_expanded, true);
        assert!((group.last_accessed - now) < Duration::seconds(1));
        assert!((group.last_modified - now) < Duration::seconds(1));
        assert_eq!(group.last_top_visible_entry, EntryUuid::nil());
        assert!((group.location_changed - now) < Duration::seconds(1));
        assert_eq!(group.name, name);
        assert_eq!(group.notes, "");
        assert_eq!(group.usage_count, 0);
        assert!(group.uuid != GroupUuid::nil());
    }

    #[test]
    fn test_default_returns_correct_instance() {
        let now = UTC::now();
        let group = Group::default();
        assert!((group.creation_time - now) < Duration::seconds(1));
        assert_eq!(group.custom_icon_uuid, None);
        assert_eq!(group.def_auto_type_sequence, "");
        assert_eq!(group.enable_auto_type, None);
        assert_eq!(group.enable_searching, None);
        assert_eq!(group.entries, Vec::new());
        assert_eq!(group.expires, false);
        assert!((group.expiry_time - now) < Duration::seconds(1));
        assert_eq!(group.groups, Vec::new());
        assert_eq!(group.icon, Icon::Folder);
        assert_eq!(group.is_expanded, true);
        assert!((group.last_accessed - now) < Duration::seconds(1));
        assert!((group.last_modified - now) < Duration::seconds(1));
        assert_eq!(group.last_top_visible_entry, EntryUuid::nil());
        assert!((group.location_changed - now) < Duration::seconds(1));
        assert_eq!(group.name, "");
        assert_eq!(group.notes, "");
        assert_eq!(group.usage_count, 0);
        assert_eq!(group.uuid, GroupUuid::nil());
    }
}
