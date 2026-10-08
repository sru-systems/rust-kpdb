// Copyright (c) 2016-2017 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::error::Error;
use super::master_cipher::MasterCipher;
use super::result::Result;

/// Initialization vector for the master encryption algorithm.
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum MasterIV {
    /// 16 byte initialization vector for AES.
    Aes256([u8; 16]),

    /// 12 byte initialization vector for ChaCha20.
    ChaCha20([u8; 12]),
}

impl MasterIV {
    /// Create a new initialization vector for the specified master cipher.
    pub fn new(master_cipher: &MasterCipher, data: &[u8]) -> Result<MasterIV> {
        match *master_cipher {
            MasterCipher::Aes256 => {
                let bytes = data.try_into().map_err(|_| Error::InvalidData)?;
                Ok(MasterIV::Aes256(bytes))
            }
            MasterCipher::ChaCha20 => {
                let bytes = data.try_into().map_err(|_| Error::InvalidData)?;
                Ok(MasterIV::ChaCha20(bytes))
            }
        }
    }

    /// Gets the raw bytes of this initialization vector.
    pub fn as_bytes(&self) -> &[u8] {
        match *self {
            MasterIV::Aes256(ref bytes) => bytes,
            MasterIV::ChaCha20(ref bytes) => bytes,
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_new_with_aes_cipher_returns_aes_iv() {
        let iv = MasterIV::new(&MasterCipher::Aes256, &[5u8; 16]).unwrap();
        assert_eq!(iv, MasterIV::Aes256([5u8; 16]));
        assert_eq!(iv.as_bytes(), &[5u8; 16]);
    }

    #[test]
    fn test_new_with_chacha20_cipher_returns_chacha_iv() {
        let iv = MasterIV::new(&MasterCipher::ChaCha20, &[6u8; 12]).unwrap();
        assert_eq!(iv, MasterIV::ChaCha20([6u8; 12]));
        assert_eq!(iv.as_bytes(), &[6u8; 12]);
    }

    #[test]
    fn test_new_with_wrong_size_fails() {
        assert!(MasterIV::new(&MasterCipher::Aes256, &[1u8; 12]).is_err());
        assert!(MasterIV::new(&MasterCipher::ChaCha20, &[1u8; 16]).is_err());
    }
}
