// Copyright (c) 2016-2017 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::binary_id::BinaryId;
use secstr::SecStr;

/// A value for entry's map with binaries.
#[derive(Clone, Debug, PartialEq)]
pub enum BinaryValue {
    /// Plain binary value.
    Plain(Vec<u8>),

    /// Protected binary value.
    Protected(SecStr),

    /// Reference to an item in the global binaries map.
    Ref(BinaryId),
}
