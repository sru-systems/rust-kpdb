// Copyright (c) 2016-2017 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Library for reading and writing KeePass 2 and KeePassX databases.
//!
//! # Usage
//!
//! To use this crate, add the following to your Cargo.toml:
//!
//! ```toml
//! [dependencies]
//! rust-kpdb = "0.5"
//! ```
//!
//! And the following to your crate root:
//!
//! ```rust
//! extern crate kpdb;
//! ```
//!
//! # Examples
//!
//! Create a new database adding two groups and two entries:
//!
//! ```rust
//! use kpdb::{CompositeKey, Database, Entry, Group};
//!
//! // Create a new database.
//! let key = CompositeKey::from_password("password");
//! let mut db = Database::new(&key);
//!
//! // Create a new group named Email.
//! let mut email_group = Group::new("Email");
//! let email_group_uuid = email_group.uuid;
//!
//! // Create an entry for ProtonMail and add it to the Email group.
//! let mut protonmail = Entry::new();
//! let protonmail_uuid = protonmail.uuid;
//! protonmail.set_title("ProtonMail");
//! protonmail.set_username("mailuser");
//! protonmail.set_password("mailpass");
//! protonmail.set_url("https://mail.protonmail.com");
//! email_group.add_entry(protonmail);
//!
//! // Create a new group named VPN.
//! let mut vpn_group = Group::new("VPN");
//!
//! // Create an entry for ProtonVPN and add it to the VPN group.
//! let mut protonvpn = Entry::new();
//! protonvpn.set_title("ProtonVPN");
//! protonvpn.set_username("vpnuser");
//! protonvpn.set_password("vpnpass");
//! protonvpn.set_url("https://prontvpn.com");
//! vpn_group.add_entry(protonvpn);
//!
//! // Add the Email and VPN groups to the Root group.
//! db.root_group.add_group(email_group);
//! db.root_group.add_group(vpn_group);
//!
//! // Find groups matching "email".
//! let groups = db.find_groups("email");
//! assert_eq!(groups.len(), 1);
//!
//! // Find entries matching "proton".
//! let entries = db.find_entries("proton");
//! assert_eq!(entries.len(), 2);
//!
//! // Retrieve a group by its UUID.
//! let group = db.get_group(email_group_uuid).unwrap();
//! assert_eq!(group.name, "Email");
//!
//! // Retrieve an entry by its UUID.
//! let entry = db.get_entry(protonmail_uuid).unwrap();
//! assert_eq!(entry.title(), Some("ProtonMail"));
//! assert_eq!(entry.username(), Some("mailuser"));
//! assert_eq!(entry.password(), Some("mailpass"));
//! assert_eq!(entry.url(), Some("https://mail.protonmail.com"));
//! assert_eq!(entry.notes(), None);
//! ```
//!
//! Open the existing KeePass database passwords.kdbx using the password
//! "password", print it and save it to new.kdbx:
//!
//! ```rust,no_run
//! use kpdb::{CompositeKey, Database};
//! use std::fs::File;
//!
//! let mut file = File::open("passwords.kdbx").unwrap();
//! let key = CompositeKey::from_password("password");
//! let db = Database::open(&mut file, &key).unwrap();
//!
//! println!("{:?}", db);
//!
//! let mut file = File::create("new.kdbx").unwrap();
//! db.save(&mut file).unwrap();
//! ```
//!
//! Open the existing KeePass database passwords.kdbx using both the password
//! "password" and the key file passwords.key, print it and save it to new.kdbx:
//!
//! ```rust,no_run
//! use kpdb::{CompositeKey, Database, KeyFile};
//! use std::fs::File;
//!
//! let mut file = File::open("passwords.key").unwrap();
//! let key_file = KeyFile::open(&mut file).unwrap();
//! let key = CompositeKey::from_both("password", key_file);
//!
//! let mut file = File::open("passwords.kdbx").unwrap();
//! let db = Database::open(&mut file, &key).unwrap();
//!
//! println!("{:?}", db);
//!
//! let mut file = File::create("new.kdbx").unwrap();
//! db.save(&mut file).unwrap();
//! ```
//!
//!
//! # Not Implemented
//!
//! The following features are currently not implemented:
//!
//! - KeePass 1 databases.

extern crate crypto as rust_crypto;
extern crate xml as rust_xml;

pub use crate::types::Association;
pub use crate::types::BinariesMap;
pub use crate::types::BinaryId;
pub use crate::types::BinaryKey;
pub use crate::types::BinaryValue;
pub use crate::types::Comment;
pub use crate::types::CompositeKey;
pub use crate::types::Compression;
pub use crate::types::CustomDataMap;
pub use crate::types::CustomIconUuid;
pub use crate::types::CustomIconsMap;
pub use crate::types::Database;
pub use crate::types::DbType;
pub use crate::types::Entry;
pub use crate::types::EntryUuid;
pub use crate::types::Error;
pub use crate::types::Group;
pub use crate::types::GroupUuid;
pub use crate::types::KeyFile;
pub use crate::types::KeyFileType;
pub use crate::types::MasterCipher;
pub use crate::types::Result;
pub use crate::types::StreamCipher;
pub use crate::types::StringKey;
pub use crate::types::StringValue;
pub use crate::types::StringsMap;
pub use crate::types::Times;
pub use crate::types::TransformRounds;
pub use crate::types::Version;
pub use crate::types::{Color, ColorError};
pub use crate::types::{Icon, IconError};
pub use crate::types::{Obfuscation, ObfuscationError};

mod common;
mod compression;
mod crypto;
mod format;
mod io;
mod types;
mod utils;

#[cfg(test)]
#[macro_use]
extern crate quickcheck;
