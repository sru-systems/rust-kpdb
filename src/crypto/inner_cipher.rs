// Copyright (c) 2025 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Module for the inner stream cipher used to protect values in the XML.

use crate::crypto::chacha20;
use crate::crypto::salsa20;
use crate::types::{ProtectedStreamKey, StreamCipher, StreamKey};

/// The inner stream cipher protecting values in the XML.
pub enum InnerCipher {
    /// The Salsa20 stream cipher.
    Salsa20(salsa20::Salsa20),

    /// The ChaCha20 stream cipher.
    ChaCha20(chacha20::ChaCha20),
}

impl InnerCipher {
    /// Create a new inner cipher for the specified stream cipher and protected stream key.
    pub fn new(cipher: &StreamCipher, key: &ProtectedStreamKey) -> InnerCipher {
        match *cipher {
            StreamCipher::Salsa20 => {
                let stream_key = StreamKey::new(key);
                InnerCipher::Salsa20(salsa20::new_cipher(&stream_key))
            }
            StreamCipher::ChaCha20 => InnerCipher::ChaCha20(chacha20::new_cipher(key)),
        }
    }

    /// Encrypt the input using this cipher.
    pub fn encrypt(&mut self, input: &[u8]) -> Vec<u8> {
        match *self {
            InnerCipher::Salsa20(ref mut cipher) => salsa20::encrypt(cipher, input),
            InnerCipher::ChaCha20(ref mut cipher) => chacha20::encrypt(cipher, input),
        }
    }

    /// Decrypt the input using this cipher.
    pub fn decrypt(&mut self, input: &[u8]) -> Vec<u8> {
        match *self {
            InnerCipher::Salsa20(ref mut cipher) => salsa20::decrypt(cipher, input),
            InnerCipher::ChaCha20(ref mut cipher) => chacha20::decrypt(cipher, input),
        }
    }
}
