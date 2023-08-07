// Copyright (c) 2016-2017 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::crypto::sha256;
use secstr::SecStr;
use super::KeyFile;

/// Composition of the user's key data.
///
/// This data type uses secstr's `SecStr` to protect the key data. To
/// retrieve the protected data use the `unsecure` method.
#[derive(Clone, Debug, PartialEq)]
pub struct CompositeKey(SecStr);

impl CompositeKey {
    /// Create a composite key from both a password and a key file.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use kpdb::Result;
    /// use kpdb::{CompositeKey, KeyFile};
    /// use std::fs::File;
    ///
    /// # fn from_both_example() -> Result<()> {
    /// let mut file = try!(File::open("database.key"));
    /// let key_file = try!(KeyFile::open(&mut file));
    /// let key = CompositeKey::from_both("secret", key_file);
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_both<S: Into<String>>(password: S, key_file: KeyFile) -> CompositeKey {
        let password = sha256::hash(&[&password.into().into_bytes()]);
        let combined = sha256::hash(&[&password, &key_file.key.unsecure()]);
        CompositeKey::secure(combined)
    }

    /// Create a composite key from a key file.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use kpdb::Result;
    /// use kpdb::{CompositeKey, KeyFile};
    /// use std::fs::File;
    ///
    /// # fn from_key_file_example() -> Result<()> {
    /// let mut file = try!(File::open("database.key"));
    /// let key_file = try!(KeyFile::open(&mut file));
    /// let key = CompositeKey::from_key_file(key_file);
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_key_file(key_file: KeyFile) -> CompositeKey {
        let combined = sha256::hash(&[&key_file.key.unsecure()]);
        CompositeKey::secure(combined)
    }

    /// Create a composite key from a password.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use kpdb::CompositeKey;
    ///
    /// let key = CompositeKey::from_password("secret");
    /// ```
    pub fn from_password<S: Into<String>>(password: S) -> CompositeKey {
        let password = sha256::hash(&[&password.into().into_bytes()]);
        let combined = sha256::hash(&[&password]);
        CompositeKey::secure(combined)
    }

    /// Gets the protected data from this composite key.
    pub fn unsecure(&self) -> [u8; 32] {
        let unsecure = self.0.unsecure();
        let mut array = [0u8; 32];
        for (u, a) in unsecure.iter().zip(array.iter_mut()) {
            *a = *u;
        }
        array
    }

    fn secure(key: [u8; 32]) -> CompositeKey {
        CompositeKey(SecStr::new(key.to_vec()))
    }
}

#[cfg(test)]
mod tests {

    use secstr::SecStr;
    use super::*;
    use crate::types::{KeyFile, KeyFileType};

    #[test]
    fn test_from_both_returns_correct_instance() {
        let array = [
            184,
            53,
            98,
            70,
            154,
            211,
            44,
            121,
            45,
            59,
            104,
            22,
            210,
            47,
            92,
            167,
            10,
            193,
            98,
            121,
            81,
            174,
            1,
            128,
            96,
            122,
            3,
            12,
            5,
            33,
            202,
            40,
        ];
        let key = KeyFile {
            key: SecStr::new(vec![0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64]),
            file_type: KeyFileType::Xml,
        };
        let password = "secret";
        let expected = CompositeKey::secure(array);
        let actual = CompositeKey::from_both(password, key);
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_from_key_file_returns_correct_instance() {
        let array = [
            94,
            136,
            72,
            152,
            218,
            40,
            4,
            113,
            81,
            208,
            229,
            111,
            141,
            198,
            41,
            39,
            115,
            96,
            61,
            13,
            106,
            171,
            189,
            214,
            42,
            17,
            239,
            114,
            29,
            21,
            66,
            216,
        ];
        let key = KeyFile {
            key: SecStr::new(vec![0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64]),
            file_type: KeyFileType::Xml,
        };
        let expected = CompositeKey::secure(array);
        let actual = CompositeKey::from_key_file(key);
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_from_password_returns_correct_instance() {
        let array = [
            56,
            129,
            33,
            157,
            8,
            125,
            217,
            198,
            52,
            55,
            63,
            211,
            61,
            250,
            51,
            162,
            203,
            107,
            252,
            108,
            82,
            11,
            100,
            184,
            187,
            96,
            239,
            44,
            235,
            83,
            74,
            231,
        ];
        let password = "secret";
        let expected = CompositeKey::secure(array);
        let actual = CompositeKey::from_password(password);
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_unsecure_inverses_secure() {
        let array = [
            1,
            2,
            3,
            4,
            5,
            6,
            7,
            8,
            9,
            10,
            11,
            12,
            13,
            14,
            15,
            16,
            17,
            18,
            19,
            20,
            21,
            22,
            23,
            24,
            25,
            26,
            27,
            28,
            29,
            30,
            31,
            32,
        ];
        let expected = array.clone();
        let actual = CompositeKey::unsecure(&CompositeKey::secure(array));
        assert_eq!(actual, expected);
    }
}
