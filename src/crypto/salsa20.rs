// Copyright (c) 2016-2017 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::rust_crypto::symmetriccipher::SynchronousStreamCipher;
use crate::types::StreamKey;

const SALSA20_NOUNCE: [u8; 8] = [0xe8, 0x30, 0x09, 0x4b, 0x97, 0x20, 0x5d, 0x2a];

pub use crate::rust_crypto::salsa20::Salsa20;

/// Decrypt the input using the Salsa20 stream cipher.
pub fn decrypt(cipher: &mut Salsa20, input: &Vec<u8>) -> Vec<u8> {
    process(cipher, input)
}

/// Encrypt the input using the Salsa20 stream cipher.
pub fn encrypt(cipher: &mut Salsa20, input: &Vec<u8>) -> Vec<u8> {
    process(cipher, input)
}

/// Create a new Salsa20 stream cipher using the specified key.
pub fn new_cipher(key: &StreamKey) -> Salsa20 {
    Salsa20::new(&key.unpack(), &SALSA20_NOUNCE)
}

fn process(cipher: &mut Salsa20, input: &Vec<u8>) -> Vec<u8> {
    let mut output = vec![0; input.len()];
    cipher.process(input, &mut output);
    output
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::types::ProtectedStreamKey;
    use crate::types::StreamKey;

    quickcheck! {
        fn test_decrypt_inverses_encrypt(data: Vec<u8>) -> bool {
            let stream_key = StreamKey::new(&ProtectedStreamKey([1u8; 32]));
            let mut encryptor = new_cipher(&stream_key);
            let mut decryptor = new_cipher(&stream_key);
            let encrypted = encrypt(&mut encryptor, &data);
            let decrypted = decrypt(&mut decryptor, &encrypted);
            decrypted == data
        }
    }
}
