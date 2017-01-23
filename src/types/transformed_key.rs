// Copyright (c) 2016-2017 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use rust_crypto::aesni;

use crypto::sha256;
use rust_crypto::aes;
use rust_crypto::aessafe;
use rust_crypto::symmetriccipher::BlockEncryptor;
use rust_crypto::util;
use secstr::SecStr;
use types::composite_key::CompositeKey;
use types::transform_rounds::TransformRounds;
use types::transform_seed::TransformSeed;

/// Key used for generating the master key.
///
/// This data type uses secstr's `SecStr` to protect the key data. To
/// retrieve the protected data use the `unsecure` method.
#[derive(Clone, Debug, PartialEq)]
pub struct TransformedKey(SecStr);

impl TransformedKey {
    /// Create a new transformed key.
    pub fn new(
        key: &CompositeKey,
        seed: &TransformSeed,
        rounds: &TransformRounds
    ) -> TransformedKey {
        let mut tmp_key = key.unsecure().clone();
        let mut output = [0u8; 32];
        if util::supports_aesni() {
            let cipher = aesni::AesNiEncryptor::new(aes::KeySize::KeySize256, &seed.0);
            for _ in 0..rounds.0 {
                cipher.encrypt_block(&tmp_key[0..16], &mut output[0..16]);
                cipher.encrypt_block(&tmp_key[16..32], &mut output[16..32]);
                tmp_key = output;
            }
        } else {
            let cipher = aessafe::AesSafe256Encryptor::new(&seed.0);
            for _ in 0..rounds.0 {
                cipher.encrypt_block(&tmp_key[0..16], &mut output[0..16]);
                cipher.encrypt_block(&tmp_key[16..32], &mut output[16..32]);
                tmp_key = output;
            }
        }

        TransformedKey::secure(sha256::hash(&[&tmp_key]))
    }

    /// Gets the protected data from this transformed key.
    pub fn unsecure(&self) -> [u8; 32] {
        let unsecure = self.0.unsecure();
        let mut array = [0u8; 32];
        for (u, a) in unsecure.iter().zip(array.iter_mut()) {
            *a = *u;
        }
        array
    }

    fn secure(key: [u8; 32]) -> TransformedKey {
        TransformedKey(SecStr::new(key.to_vec()))
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use types::{CompositeKey, TransformRounds, TransformSeed};

    #[test]
    fn test_new_returns_correct_instance() {
        let array = [208, 2, 238, 193, 16, 181, 39, 109, 254, 40, 67, 20, 154, 21, 202, 174, 234,
                     11, 183, 136, 22, 136, 58, 102, 52, 40, 129, 244, 194, 223, 211, 108];
        let expected = TransformedKey::secure(array);
        let key = CompositeKey::from_password("secret");
        let rounds = TransformRounds(10);
        let seed = TransformSeed([1u8; 32]);
        let actual = TransformedKey::new(&key, &seed, &rounds);
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_unsecure_inverses_secure() {
        let array = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                     22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32];
        let expected = array.clone();
        let actual = TransformedKey::unsecure(&TransformedKey::secure(array));
        assert_eq!(actual, expected);
    }
}
