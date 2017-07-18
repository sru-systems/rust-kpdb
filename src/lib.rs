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
//! rust-kpdb = "0.1.0"
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
//! Create a new database:
//!
//! ```rust,no_run
//! use kpdb::{CompositeKey, Database};
//!
//! let key = CompositeKey::from_password("password");
//! let db = Database::new(&key);
//! ```
//!
//! Open the KeePass database passwords.kdbx using the password "password" and
//! print it:
//!
//! ```rust,no_run
//! use kpdb::{CompositeKey, Database};
//! use std::fs::File;
//!
//! fn main() {
//!     let mut file = File::open("passwords.kdbx").unwrap();
//!     let key = CompositeKey::from_password("password");
//!     let db = Database::open(&mut file, &key).unwrap();
//!     println!("{:?}", db);
//! }
//! ```
//!
//! Open the KeePass database passwords.kdbx using both the password "password"
//! and the key file passwords.key and print it:
//!
//! ```rust,no_run
//! use kpdb::{CompositeKey, Database, KeyFile};
//! use std::fs::File;
//!
//! fn main() {
//!     let mut file = File::open("passwords.key").unwrap();
//!     let key_file = KeyFile::open(&mut file).unwrap();
//!     let key = CompositeKey::from_both("password", key_file);
//!
//!     let mut file = File::open("passwords.kdbx").unwrap();
//!     let db = Database::open(&mut file, &key).unwrap();
//!     println!("{:?}", db);
//! }
//! ```
//!
//! Save a new KeePass database to new.kdbx:
//!
//! ```rust,no_run
//! use kpdb::{CompositeKey, Database};
//! use std::fs::File;
//!
//! fn main() {
//!     let key = CompositeKey::from_password("password");
//!     let db = Database::new(&key);
//!     let mut file = File::create("new.kdbx").unwrap();
//!     db.save(&mut file).unwrap();
//! }
//! ```
//!
//! # Not Implemented
//!
//! The following features are currently not implemented:
//!
//! - KeePass 1 databases.


extern crate byteorder;
extern crate chrono;
extern crate crypto as rust_crypto;
extern crate flate2;
extern crate rand;
extern crate rustc_serialize;
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
pub use types::EntriesMap;
pub use types::Entry;
pub use types::EntryUuid;
pub use types::Error;
pub use types::Group;
pub use types::GroupUuid;
pub use types::GroupsMap;
pub use types::HistoryMap;
pub use types::KeyFile;
pub use types::KeyFileType;
pub use types::MasterCipher;
pub use types::Result;
pub use types::StreamCipher;
pub use types::StringKey;
pub use types::StringValue;
pub use types::StringsMap;
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
