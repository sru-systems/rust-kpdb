// Copyright (c) 2025 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Module for SHA512 hashing.

use sha2::{Digest, Sha512};

/// Hashes the given data using SHA512.
pub fn hash(data: &[&[u8]]) -> Vec<u8> {
    let mut hasher = Sha512::new();
    for d in data {
        hasher.update(d);
    }
    hasher.finalize().to_vec()
}
