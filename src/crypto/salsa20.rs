// Copyright (c) 2016-2017,2025 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::types::StreamKey;
use salsa20::cipher::{KeyIvInit, StreamCipher};

const SALSA20_NOUNCE: [u8; 8] = [0xe8, 0x30, 0x09, 0x4b, 0x97, 0x20, 0x5d, 0x2a];

pub use salsa20::Salsa20;

/// Decrypt the input using the Salsa20 stream cipher.
pub fn decrypt(cipher: &mut Salsa20, input: &[u8]) -> Vec<u8> {
    process(cipher, input)
}

/// Encrypt the input using the Salsa20 stream cipher.
pub fn encrypt(cipher: &mut Salsa20, input: &[u8]) -> Vec<u8> {
    process(cipher, input)
}

/// Create a new Salsa20 stream cipher using the specified key.
pub fn new_cipher(key: &StreamKey) -> Salsa20 {
    Salsa20::new(&key.unpack().into(), &SALSA20_NOUNCE.into())
}

fn process(cipher: &mut Salsa20, input: &[u8]) -> Vec<u8> {
    let mut buffer = input.to_vec();
    cipher.apply_keystream(&mut buffer);
    buffer
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::types::ProtectedStreamKey;
    use crate::types::StreamKey;

    quickcheck! {
        fn test_decrypt_inverses_encrypt(data: Vec<u8>) -> bool {
            let stream_key = StreamKey::new(&ProtectedStreamKey(vec![1u8; 32]));
            let mut encryptor = new_cipher(&stream_key);
            let mut decryptor = new_cipher(&stream_key);
            let encrypted = encrypt(&mut encryptor, &data);
            let decrypted = decrypt(&mut decryptor, &encrypted);
            decrypted == data
        }
    }
}
