// Copyright (c) 2025 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Module for the HMAC-SHA256 message authentication code.

use crate::types::{Error, Result};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Computes the HMAC-SHA256 of the parts using the specified key.
pub fn hash(key: &[u8], parts: &[&[u8]]) -> Result<[u8; 32]> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| Error::InvalidKey)?;
    for part in parts {
        mac.update(part);
    }
    let mut result = [0u8; 32];
    result.copy_from_slice(&mac.finalize().into_bytes());
    Ok(result)
}

/// Verifies whether the expected HMAC-SHA256 matches the parts.
pub fn verify(key: &[u8], parts: &[&[u8]], expected: &[u8]) -> Result<bool> {
    let computed = hash(key, parts)?;
    Ok(computed.to_vec() == expected.to_vec())
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_verify_round_trip() {
        let key = [7u8; 64];
        let parts: Vec<&[u8]> = vec![b"header", b"data"];
        let mac = hash(&key, &parts).unwrap();
        assert!(verify(&key, &parts, &mac).unwrap());
        assert!(!verify(&key, &[b"header", b"other"], &mac).unwrap());
    }
}
