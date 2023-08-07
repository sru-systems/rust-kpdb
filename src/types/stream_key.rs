// Copyright (c) 2016-2017 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::protected_stream_key::ProtectedStreamKey;
use crate::crypto::sha256;

/// Key used for encrypting and decrypting the stream data.
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct StreamKey([u8; 32]);

impl StreamKey {
    /// Create a new stream key.
    pub fn new(key: &ProtectedStreamKey) -> StreamKey {
        StreamKey(sha256::hash(&[&key.0]))
    }

    /// Gets the data from this stream key.
    pub fn unpack(&self) -> [u8; 32] {
        self.0
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::types::ProtectedStreamKey;

    #[test]
    fn test_new_returns_correct_instance() {
        let protected_stream_key = ProtectedStreamKey([1u8; 32]);
        let array = [
            114, 205, 110, 132, 34, 196, 7, 251, 109, 9, 134, 144, 241, 19, 11, 125, 237, 126, 194,
            247, 245, 225, 211, 11, 217, 213, 33, 240, 21, 54, 55, 147,
        ];
        let expected = StreamKey(array);
        let actual = StreamKey::new(&protected_stream_key);
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_unpack_returns_correct_array() {
        let expected = [2u8; 32];
        let target = StreamKey(expected.clone());
        let actual = target.unpack();
        assert_eq!(actual, expected);
    }
}
