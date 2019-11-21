// Copyright (c) 2016-2017 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use rust_crypto::aes::{self, KeySize};
use rust_crypto::blockmodes::PkcsPadding;
use rust_crypto::buffer::{BufferResult, ReadBuffer, RefReadBuffer, RefWriteBuffer, WriteBuffer};
use types::{MasterIV, MasterKey, Result};

/// Decrypt the input using the key and initialization vector.
pub fn decrypt(key: &MasterKey, iv: &MasterIV, input: &[u8]) -> Result<Vec<u8>> {
    let mut cipher = aes::cbc_decryptor(KeySize::KeySize256, &key.unsecure(), &iv.0, PkcsPadding);
    let mut output = Vec::new();
    let mut read_buffer = RefReadBuffer::new(input);
    let mut buffer = [0; 4096];
    let mut write_buffer = RefWriteBuffer::new(&mut buffer);

    loop {
        let result = cipher.decrypt(&mut read_buffer, &mut write_buffer, true)?;
        output.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .map(|&i| i),
        );
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    Ok(output)
}

/// Encrypt the input using the key and initialization vector.
pub fn encrypt(key: &MasterKey, iv: &MasterIV, input: &[u8]) -> Result<Vec<u8>> {
    let mut cipher = aes::cbc_encryptor(KeySize::KeySize256, &key.unsecure(), &iv.0, PkcsPadding);
    let mut output = Vec::new();
    let mut read_buffer = RefReadBuffer::new(input);
    let mut buffer = [0; 4096];
    let mut write_buffer = RefWriteBuffer::new(&mut buffer);

    loop {
        let result = cipher.encrypt(&mut read_buffer, &mut write_buffer, true)?;
        output.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .map(|&i| i),
        );
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    Ok(output)
}

#[cfg(test)]
mod tests {

    use super::*;
    use types::CompositeKey;
    use types::MasterIV;
    use types::MasterKey;
    use types::MasterSeed;
    use types::TransformRounds;
    use types::TransformSeed;
    use types::TransformedKey;

    quickcheck! {
        fn test_decrypt_inverses_encrypt(data: Vec<u8>) -> bool {
            let composite_key = CompositeKey::from_password("secret");
            let rounds = TransformRounds(10);
            let transform_seed = TransformSeed([1u8; 32]);
            let transformed_key = TransformedKey::new(&composite_key, &transform_seed, &rounds);
            let master_seed = MasterSeed([2u8; 32]);
            let master_key = MasterKey::new(&master_seed, &transformed_key);
            let master_iv = MasterIV([3u8; 16]);
            let encrypted = encrypt(&master_key, &master_iv, &data).unwrap();
            let decrypted = decrypt(&master_key, &master_iv, &encrypted).unwrap();
            decrypted == data
        }
    }
}
