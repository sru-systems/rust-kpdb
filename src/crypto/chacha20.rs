// Copyright (c) 2025 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Module for the ChaCha20 stream cipher.

use crate::crypto::sha512;
use crate::types::{Error, MasterIV, MasterKey, ProtectedStreamKey, Result};
use cipher::{KeyIvInit, StreamCipher};

pub use chacha20::ChaCha20;

/// Create a new ChaCha20 stream cipher from the protected stream key (used for
/// the protected values in the XML). The key and nonce are derived using SHA512
/// as defined by the KeePass2RandomStream.
pub fn new_cipher(key: &ProtectedStreamKey) -> ChaCha20 {
    let hash = sha512::hash(&[key.0.as_slice()]);
    let key: [u8; 32] = hash[0..32].try_into().unwrap();
    let iv: [u8; 12] = hash[32..44].try_into().unwrap();
    ChaCha20::new(&key.into(), &iv.into())
}

/// Decrypt the master payload using the master key and initialization vector.
pub fn decrypt_master(key: &MasterKey, iv: &MasterIV, input: &[u8]) -> Result<Vec<u8>> {
    let mut cipher = master_cipher(key, iv)?;
    Ok(decrypt(&mut cipher, input))
}

/// Encrypt the master payload using the master key and initialization vector.
pub fn encrypt_master(key: &MasterKey, iv: &MasterIV, input: &[u8]) -> Result<Vec<u8>> {
    let mut cipher = master_cipher(key, iv)?;
    Ok(encrypt(&mut cipher, input))
}

/// Decrypt the input using the ChaCha20 stream cipher.
pub fn decrypt(cipher: &mut ChaCha20, input: &[u8]) -> Vec<u8> {
    let mut buffer = input.to_vec();
    cipher.apply_keystream(&mut buffer);
    buffer
}

/// Encrypt the input using the ChaCha20 stream cipher.
pub fn encrypt(cipher: &mut ChaCha20, input: &[u8]) -> Vec<u8> {
    decrypt(cipher, input)
}

fn master_cipher(key: &MasterKey, iv: &MasterIV) -> Result<ChaCha20> {
    let key_bytes = key.unsecure();
    let iv_bytes: [u8; 12] = match iv {
        MasterIV::ChaCha20(ref bytes) => *bytes,
        MasterIV::Aes256(_) => return Err(Error::InvalidData),
    };
    Ok(ChaCha20::new(&key_bytes.into(), &iv_bytes.into()))
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::types::{CompositeKey, MasterSeed, TransformRounds, TransformSeed, TransformedKey};

    #[test]
    fn test_encrypt_master_inverses_decrypt_master() {
        let composite_key = CompositeKey::from_password("secret");
        let transformed =
            TransformedKey::new(&composite_key, &TransformSeed([1u8; 32]), &TransformRounds(10));
        let master_key = MasterKey::new(&MasterSeed([2u8; 32]), &transformed);
        let master_iv = MasterIV::ChaCha20([3u8; 12]);
        let data = b"chacha20 master payload".to_vec();
        let encrypted = encrypt_master(&master_key, &master_iv, &data).unwrap();
        let decrypted = decrypt_master(&master_key, &master_iv, &encrypted).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_master_cipher_rejects_aes_iv() {
        let composite_key = CompositeKey::from_password("secret");
        let transformed =
            TransformedKey::new(&composite_key, &TransformSeed([1u8; 32]), &TransformRounds(10));
        let master_key = MasterKey::new(&MasterSeed([2u8; 32]), &transformed);
        let bad_iv = MasterIV::Aes256([0u8; 16]);
        assert!(encrypt_master(&master_key, &bad_iv, b"data").is_err());
    }
}
