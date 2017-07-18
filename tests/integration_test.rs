// Copyright (c) 2017 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

extern crate kpdb;

use kpdb::{CompositeKey, Database, KeyFile, KeyFileType};
use std::fs::File;
use std::io::Cursor;

const PASSWORD: &'static str = "test";

#[test]
fn test_database_open_with_correct_key_file_and_password_succeeds() {
    let mut file = File::open("data/db-both.key").unwrap();
    let key_file = KeyFile::open(&mut file).unwrap();
    let key = CompositeKey::from_both(PASSWORD, key_file);

    let mut file = File::open("data/db-both.kdbx").unwrap();
    let result = Database::open(&mut file, &key);
    assert!(result.is_ok());
}

#[test]
fn test_database_open_with_correct_key_file_succeeds() {
    let mut file = File::open("data/db-key-file.key").unwrap();
    let key_file = KeyFile::open(&mut file).unwrap();
    let key = CompositeKey::from_key_file(key_file);

    let mut file = File::open("data/db-key-file.kdbx").unwrap();
    let result = Database::open(&mut file, &key);
    assert!(result.is_ok());
}

#[test]
fn test_database_open_with_correct_password_succeeds() {
    let mut file = File::open("data/db-password.kdbx").unwrap();
    let key = CompositeKey::from_password(PASSWORD);
    let result = Database::open(&mut file, &key);
    assert!(result.is_ok());
}

#[test]
fn test_database_open_with_incorrect_password_fails() {
    let mut file = File::open("data/db-password.kdbx").unwrap();
    let key = CompositeKey::from_password("wront");
    let result = Database::open(&mut file, &key);
    assert!(result.is_err());
}

#[test]
fn test_database_open_can_read_saved_database() {
    let key = CompositeKey::from_password(PASSWORD);
    let expected = Database::new(&key);
    let mut writer = Vec::new();
    expected.save(&mut writer).unwrap();
    let mut reader = Cursor::new(writer);
    let actual = Database::open(&mut reader, &key).unwrap();
    assert_eq!(expected, actual);
}

#[test]
fn test_key_file_open_with_binary_key_returns_correct_data() {
    let key = [
        122,
        53,
        46,
        141,
        234,
        133,
        167,
        150,
        165,
        177,
        249,
        139,
        78,
        92,
        142,
        101,
        112,
        204,
        228,
        182,
        96,
        171,
        130,
        14,
        37,
        103,
        198,
        32,
        239,
        13,
        55,
        244,
    ];
    let mut file = File::open("data/key-binary.key").unwrap();
    let key_file = KeyFile::open(&mut file).unwrap();
    assert_eq!(key_file.key.unsecure(), key);
    assert_eq!(key_file.file_type, KeyFileType::Binary);
}

#[test]
fn test_key_file_open_with_hex_key_returns_correct_data() {
    let key = [
        49,
        168,
        170,
        217,
        214,
        119,
        198,
        220,
        133,
        57,
        52,
        176,
        162,
        227,
        165,
        197,
        147,
        3,
        41,
        172,
        83,
        62,
        174,
        194,
        56,
        22,
        175,
        241,
        26,
        99,
        190,
        24,
    ];
    let mut file = File::open("data/key-hex.key").unwrap();
    let key_file = KeyFile::open(&mut file).unwrap();
    assert_eq!(key_file.key.unsecure(), key);
    assert_eq!(key_file.file_type, KeyFileType::Hex);
}

#[test]
fn test_key_file_open_with_xml_key_returns_correct_data() {
    let key = [
        159,
        55,
        28,
        192,
        249,
        89,
        40,
        15,
        201,
        29,
        48,
        116,
        39,
        67,
        216,
        110,
        153,
        237,
        153,
        27,
        164,
        3,
        57,
        108,
        231,
        76,
        202,
        121,
        22,
        127,
        130,
        199,
    ];
    let mut file = File::open("data/key-xml.key").unwrap();
    let key_file = KeyFile::open(&mut file).unwrap();
    assert_eq!(key_file.key.unsecure(), key);
    assert_eq!(key_file.file_type, KeyFileType::Xml);
}

#[test]
fn test_key_file_open_can_read_saved_binary_key_file() {
    let expected = KeyFile::new_binary().unwrap();
    let mut writer = Vec::new();
    expected.save(&mut writer).unwrap();
    let mut reader = Cursor::new(writer);
    let actual = KeyFile::open(&mut reader).unwrap();
    assert_eq!(expected, actual);
}

#[test]
fn test_key_file_open_can_read_saved_hex_key_file() {
    let expected = KeyFile::new_hex().unwrap();
    let mut writer = Vec::new();
    expected.save(&mut writer).unwrap();
    let mut reader = Cursor::new(writer);
    let actual = KeyFile::open(&mut reader).unwrap();
    assert_eq!(expected, actual);
}

#[test]
fn test_key_file_open_can_read_saved_xml_key_file() {
    let expected = KeyFile::new_xml().unwrap();
    let mut writer = Vec::new();
    expected.save(&mut writer).unwrap();
    let mut reader = Cursor::new(writer);
    let actual = KeyFile::open(&mut reader).unwrap();
    assert_eq!(expected, actual);
}
