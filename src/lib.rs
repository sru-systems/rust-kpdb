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
//! rust-kpdb = "0.4"
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


extern crate base64;
extern crate byteorder;
extern crate chrono;
extern crate crypto as rust_crypto;
extern crate flate2;
extern crate hex;
extern crate rand;
extern crate secstr;
extern crate uuid;
extern crate xml;

pub use types::Association;
pub use types::BinariesMap;
pub use types::BinaryId;
pub use types::BinaryKey;
pub use types::BinaryValue;
pub use types::Comment;
pub use types::CompositeKey;
pub use types::Compression;
pub use types::CustomDataMap;
pub use types::CustomIconUuid;
pub use types::CustomIconsMap;
pub use types::Database;
pub use types::DbType;
pub use types::Entry;
pub use types::EntryUuid;
pub use types::Error;
pub use types::Group;
pub use types::GroupUuid;
pub use types::KeyFile;
pub use types::KeyFileType;
pub use types::MasterCipher;
pub use types::Result;
pub use types::StreamCipher;
pub use types::StringKey;
pub use types::StringValue;
pub use types::StringsMap;
pub use types::Times;
pub use types::TransformRounds;
pub use types::Version;
pub use types::{Color, ColorError};
pub use types::{Icon, IconError};
pub use types::{Obfuscation, ObfuscationError};

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
