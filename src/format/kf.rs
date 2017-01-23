// Copyright (c) 2016-2017 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Module containing constants for the key file.

/// The length of a binary key file.
pub const BINARY_KEY_FILE_LEN: usize = 32;

/// The length of a hexadecimal key file.
pub const HEX_KEY_FILE_LEN: usize = 64;

/// The version of the XML key file.
pub const XML_KEY_FILE_VERSION: &'static str = "1.00";

/// The <KeyFile> tag.
pub const KEY_FILE_TAG: &'static str = "KeyFile";

/// The <Meta> tag.
pub const META_TAG: &'static str = "Meta";

/// The <Version> tag.
pub const VERSION_TAG: &'static str = "Version";

/// The <Key> tag.
pub const KEY_TAG: &'static str = "Key";

/// The <Data> tag.
pub const DATA_TAG: &'static str = "Data";
