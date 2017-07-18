// Copyright (c) 2016-2017 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use rust_crypto::digest::Digest;
use rust_crypto::sha2::Sha256;

/// Hash the input using the SHA256 hashing algorithm.
pub fn hash(inputs: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for input in inputs {
        hasher.input(input);
    }

    let mut result = [0u8; 32];
    hasher.result(&mut result);
    result
}

#[cfg(test)]
mod tests {

    use hex::FromHex;
    use super::*;

    #[test]
    fn test_hash_returns_correct_result() {
        // Wikipedia tests
        let tests = vec![
            ("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            (
                "The quick brown fox jumps over the lazy dog",
                "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
            ),
            (
                "The quick brown fox jumps over the lazy dog.",
                "ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c"
            ),
        ];

        for (input_str, output_str) in tests {
            let input = input_str.as_bytes();
            let expected: Vec<u8> = FromHex::from_hex(output_str).unwrap();
            let actual = hash(&[&input]).to_vec();
            assert_eq!(actual, expected);
        }
    }
}
