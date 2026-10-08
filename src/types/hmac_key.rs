// Copyright (c) 2025 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

/// Key used for the HMAC-SHA256 integrity checks of the header and data blocks.
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct HmacKey(pub [u8; 64]);
