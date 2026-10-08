// Copyright (c) 2016-2017 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Module containing constants for the KeePass 4 (KDBX4) database format.

use super::kdb2;

/// The identifier of the AES cipher.
pub const AES_CIPHER_ID: [u8; 16] = kdb2::AES_CIPHER_ID;

/// The identifier of the ChaCha20 cipher.
pub const CHACHA20_CIPHER_ID: [u8; 16] = [
    0xd6, 0x03, 0x8a, 0x2b, 0x8b, 0x6f, 0x4c, 0xb5, 0xa5, 0x24, 0x33, 0x9a, 0x31, 0xdb, 0xb5, 0x9a,
];

/// The identifier of the end header.
pub const END_HID: u8 = 0;

/// The identifier of the comment header.
pub const COMMENT_HID: u8 = 1;

/// The identifier of the cipher ID header.
pub const CIPHER_ID_HID: u8 = 2;

/// The size of the cipher ID header data.
pub const CIPHER_ID_SIZE: u16 = 16;

/// The identifier of the compression flag header.
pub const COMPRESSION_FLAGS_HID: u8 = 3;

/// The size of the compression flag header data.
pub const COMPRESSION_FLAGS_SIZE: u16 = 4;

/// The identifier of the master seed header.
pub const MASTER_SEED_HID: u8 = 4;

/// The size of the master seed header data.
pub const MASTER_SEED_SIZE: u16 = 32;

/// The identifier of the transform seed header.
pub const TRANSFORM_SEED_HID: u8 = 5;

/// The identifier of the transform rounds header.
pub const TRANSFORM_ROUNDS_HID: u8 = 6;

/// The identifier of the encryption IV header.
pub const ENCRYPTION_IV_HID: u8 = 7;

/// The size of the encryption IV header data for AES.
pub const ENCRYPTION_IV_AES_SIZE: u16 = 16;

/// The size of the encryption IV header data for ChaCha20.
pub const ENCRYPTION_IV_CHACHA20_SIZE: u16 = 12;

/// The identifier of the protected stream key header.
pub const PROTECTED_STREAM_KEY_HID: u8 = 8;

/// The identifier of the stream start bytes header.
pub const STREAM_START_BYTES_HID: u8 = 9;

/// The identifier of the inner random stream ID header.
pub const INNER_RANDOM_STREAM_ID_HID: u8 = 10;

/// The identifier of the KDF parameters header.
pub const KDF_PARAMETERS_HID: u8 = 11;

/// The identifier of the public custom data header.
pub const PUBLIC_CUSTOM_DATA_HID: u8 = 12;

// Inner header ids
/// The identifier of the inner end header.
pub const INNER_END_HID: u8 = 0;

/// The identifier of the inner random stream ID header.
pub const INNER_STREAM_ID_HID: u8 = 1;

/// The identifier of the inner random stream key header.
pub const INNER_STREAM_KEY_HID: u8 = 2;

/// The identifier of the inner binary header.
pub const INNER_BINARY_HID: u8 = 3;

/// The identifier of the salsa20 stream cipher.
pub const SALSA20_STREAM_ID: u32 = 2;

/// The identifier of the ChaCha20 stream cipher.
pub const CHACHA20_STREAM_ID: u32 = 3;
