// Copyright (c) 2016-2017 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Module containing constants for the application.

/// The database signature.
pub const DB_SIGNATURE: [u8; 4] = [0x03, 0xd9, 0xa2, 0x9a];

/// The name of this generator.
pub const GENERATOR_NAME: &'static str = "rust-kpdb";

/// The default value for history max items.
pub const HISTORY_MAX_ITEMS_DEFAULT: i32 = 10;

/// The default value for history max size.
pub const HISTORY_MAX_SIZE_DEFAULT: i32 = 6291456;

/// The major version for kdb2 databases.
pub const KDB2_MAJOR_VERSION: u16 = 3;

/// The minor version for kdb2 databases.
pub const KDB2_MINOR_VERSION: u16 = 1;

/// The signature for kdb1 databases.
pub const KDB1_SIGNATURE: [u8; 4] = [0x65, 0xfb, 0x4b, 0xb5];

/// The signature for kdb2 databases.
pub const KDB2_SIGNATURE: [u8; 4] = [0x67, 0xfb, 0x4b, 0xb5];

/// The default value for maintenance history days.
pub const MAINTENANCE_HISTORY_DAYS_DEFAULT: i32 = 365;

/// The default value for master key change force.
pub const MASTER_KEY_CHANGE_FORCE_DEFAULT: i32 = -1;

/// The default value for master key change rec.
pub const MASTER_KEY_CHANGE_REC_DEFAULT: i32 = -1;

/// The default value for protect notes.
pub const PROTECT_NOTES_DEFAULT: bool = false;

/// The default value for protect password.
pub const PROTECT_PASSWORD_DEFAULT: bool = true;

/// The default value for protect title.
pub const PROTECT_TITLE_DEFAULT: bool = false;

/// The default value for protect url.
pub const PROTECT_URL_DEFAULT: bool = false;

/// The default value for protect username.
pub const PROTECT_USERNAME_DEFAULT: bool = false;

/// The default value for recycle bin enabled.
pub const RECYCLE_BIN_ENABLED_DEFAULT: bool = true;

/// The name of the root group.
pub const ROOT_GROUP_NAME: &'static str = "Root";
