// Copyright (c) 2016-2017 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::key_file_type::KeyFileType;
use super::result::Result;
use crate::crypto::random_gen::RandomGen;
use crate::format::{kf_reader, kf_writer};
use secstr::SecStr;
use std::io::{Read, Write};

/// A key file used for encrypting and decrypting the database.
#[derive(Clone, Debug, PartialEq)]
pub struct KeyFile {
    /// The key data.
    pub key: SecStr,

    /// The type of key file.
    pub file_type: KeyFileType,
}

impl KeyFile {
    /// An convenience alias for `KeyFile::new_xml()`.
    pub fn new() -> Result<KeyFile> {
        KeyFile::new_xml()
    }

    /// Attempts to create a new binary key file.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use kpdb::Result;
    /// use kpdb::KeyFile;
    ///
    /// # fn new_example() -> Result<()> {
    /// let key = KeyFile::new_binary()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new_binary() -> Result<KeyFile> {
        let key = KeyFile::get_random_key()?;
        Ok(KeyFile {
            key: key,
            file_type: KeyFileType::Binary,
        })
    }

    /// Attempts to create a new hexadecimal key file.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use kpdb::Result;
    /// use kpdb::KeyFile;
    ///
    /// # fn new_example() -> Result<()> {
    /// let key = KeyFile::new_hex()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new_hex() -> Result<KeyFile> {
        let key = KeyFile::get_random_key()?;
        Ok(KeyFile {
            key: key,
            file_type: KeyFileType::Hex,
        })
    }

    /// Attempts to create a new XML key file.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use kpdb::Result;
    /// use kpdb::KeyFile;
    ///
    /// # fn new_example() -> Result<()> {
    /// let key = KeyFile::new_xml()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new_xml() -> Result<KeyFile> {
        let key = KeyFile::get_random_key()?;
        Ok(KeyFile {
            key: key,
            file_type: KeyFileType::Xml,
        })
    }

    /// Attempts to open a key file.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use kpdb::Result;
    /// use kpdb::KeyFile;
    /// use std::fs::File;
    ///
    /// # fn open_example() -> Result<()> {
    /// let mut file = File::open("passwords.key")?;
    /// let key = KeyFile::open(&mut file)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn open<R: Read>(reader: &mut R) -> Result<KeyFile> {
        kf_reader::read(reader)
    }

    /// Attempts to save the key file.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use kpdb::Result;
    /// use kpdb::KeyFile;
    /// use std::fs::File;
    ///
    /// # fn save_example() -> Result<()> {
    /// let key = KeyFile::new()?;
    /// let mut file = File::create("new.key")?;
    ///
    /// key.save(&mut file)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn save<W: Write>(&self, writer: &mut W) -> Result<()> {
        kf_writer::write(writer, self)
    }

    fn get_random_key() -> Result<SecStr> {
        let mut random = RandomGen::new()?;
        let bytes = random.next_32_bytes().to_vec();
        Ok(SecStr::new(bytes))
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::types::KeyFileType;

    #[test]
    fn test_new_returns_xml_instance() {
        let target = KeyFile::new().unwrap();
        assert_eq!(target.file_type, KeyFileType::Xml);
    }

    #[test]
    fn test_new_binary_returns_correct_instance() {
        let a = KeyFile::new_binary().unwrap();
        let b = KeyFile::new_binary().unwrap();
        assert!(a.key != b.key);
        assert_eq!(a.file_type, KeyFileType::Binary);
        assert_eq!(b.file_type, KeyFileType::Binary);
    }

    #[test]
    fn test_new_hex_returns_correct_instance() {
        let a = KeyFile::new_hex().unwrap();
        let b = KeyFile::new_hex().unwrap();
        assert!(a.key != b.key);
        assert_eq!(a.file_type, KeyFileType::Hex);
        assert_eq!(b.file_type, KeyFileType::Hex);
    }

    #[test]
    fn test_new_xml_returns_correct_instance() {
        let a = KeyFile::new_xml().unwrap();
        let b = KeyFile::new_xml().unwrap();
        assert!(a.key != b.key);
        assert_eq!(a.file_type, KeyFileType::Xml);
        assert_eq!(b.file_type, KeyFileType::Xml);
    }
}
