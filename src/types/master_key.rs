// Copyright (c) 2016-2017 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crypto::sha256;
use secstr::SecStr;
use super::master_seed::MasterSeed;
use super::transformed_key::TransformedKey;

/// Key used for encrypting and decrypting the master data.
///
/// This data type uses secstr's `SecStr` to protect the key data. To
/// retrieve the protected data use the `unsecure` method.
#[derive(Clone, Debug, PartialEq)]
pub struct MasterKey(SecStr);

impl MasterKey {
    /// Create a new master key.
    pub fn new(seed: &MasterSeed, key: &TransformedKey) -> MasterKey {
        MasterKey::secure(sha256::hash(&[&seed.0, &key.unsecure()]))
    }

    /// Gets the protected data from this master key.
    pub fn unsecure(&self) -> [u8; 32] {
        let unsecure = self.0.unsecure();
        let mut array = [0u8; 32];
        for (u, a) in unsecure.iter().zip(array.iter_mut()) {
            *a = *u;
        }
        array
    }

    fn secure(key: [u8; 32]) -> MasterKey {
        MasterKey(SecStr::new(key.to_vec()))
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use types::{CompositeKey, MasterSeed, TransformRounds, TransformSeed, TransformedKey};

    #[test]
    fn test_new_returns_correct_instance() {
        let array = [31, 185, 158, 42, 166, 26, 165, 152, 237, 134, 43, 169, 20, 151, 166, 28,
                     245, 243, 54, 245, 102, 218, 172, 154, 46, 41, 255, 223, 243, 90, 2, 117];
        let expected = MasterKey::secure(array);
        let composite_key = CompositeKey::from_password("secret");
        let rounds = TransformRounds(10);
        let transform_seed = TransformSeed([1u8; 32]);
        let transformed_key = TransformedKey::new(&composite_key, &transform_seed, &rounds);
        let master_seed = MasterSeed([2u8; 32]);
        let actual = MasterKey::new(&master_seed, &transformed_key);
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_unsecure_inverses_secure() {
        let array = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                     22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32];
        let expected = array.clone();
        let actual = MasterKey::unsecure(&MasterKey::secure(array));
        assert_eq!(actual, expected);
    }
}
