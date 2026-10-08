// Copyright (c) 2025 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::crypto::hmac;
use crate::crypto::sha512;
use crate::types::{Error, HmacKey, Result};
use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{self, Read};

pub struct HmacBlockReader<R: Read> {
    reader: R,
    key: HmacKey,
    buffer: Vec<u8>,
    buffer_pos: usize,
    block_index: u64,
    eof: bool,
}

impl<R: Read> HmacBlockReader<R> {
    pub fn new(reader: R, key: HmacKey) -> HmacBlockReader<R> {
        HmacBlockReader {
            reader,
            key,
            buffer: Vec::new(),
            buffer_pos: 0,
            block_index: 0,
            eof: false,
        }
    }

    fn read_hashed_block(&mut self) -> Result<()> {
        if self.eof {
            return Ok(());
        }

        let mut hmac_expected = [0u8; 32];
        if self.reader.read_exact(&mut hmac_expected).is_err() {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Invalid HMAC size.",
            )));
        }

        let block_size = match self.reader.read_i32::<LittleEndian>() {
            Ok(size) => size,
            Err(_) => {
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Invalid block size.",
                )))
            }
        };

        if block_size < 0 {
            return Err(Error::InvalidData);
        }

        let mut block_data = vec![0u8; block_size as usize];
        if self.reader.read_exact(&mut block_data).is_err() {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Block too short.",
            )));
        }

        let block_key = self.block_key();
        let size_bytes = block_size.to_le_bytes();
        let valid = hmac::verify(
            &block_key,
            &[&self.block_index.to_le_bytes(), &size_bytes, &block_data],
            &hmac_expected,
        )?;
        if !valid {
            return Err(Error::InvalidBlockHash);
        }

        self.buffer = block_data;
        self.buffer_pos = 0;
        self.block_index += 1;

        if block_size == 0 {
            self.eof = true;
        }

        Ok(())
    }

    fn block_key(&self) -> [u8; 64] {
        sha512::hash(&[&self.block_index.to_le_bytes(), &self.key.0])
            .try_into()
            .unwrap()
    }
}

impl<R: Read> Read for HmacBlockReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.buffer_pos >= self.buffer.len() {
            if self.eof {
                return Ok(0);
            }
            if let Err(e) = self.read_hashed_block() {
                return Err(io::Error::other(format!("{:?}", e)));
            }
            if self.eof && self.buffer.is_empty() {
                return Ok(0);
            }
        }

        let bytes_to_copy = std::cmp::min(buf.len(), self.buffer.len() - self.buffer_pos);
        buf[..bytes_to_copy]
            .copy_from_slice(&self.buffer[self.buffer_pos..self.buffer_pos + bytes_to_copy]);
        self.buffer_pos += bytes_to_copy;
        Ok(bytes_to_copy)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_read_round_trip() {
        let key = HmacKey([7u8; 64]);
        let data = vec![0x01u8; 2_500_000];

        let mut bytes = Vec::new();
        crate::io::write_hmac_blocks(&mut bytes, &data, &key).unwrap();

        let mut reader = HmacBlockReader::new(Cursor::new(bytes), key);
        let mut result = Vec::new();
        reader.read_to_end(&mut result).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_read_rejects_corrupted_data() {
        let key = HmacKey([7u8; 64]);
        let mut bytes = Vec::new();
        crate::io::write_hmac_blocks(&mut bytes, &[0x01u8; 100], &key).unwrap();

        bytes[100] ^= 0xff;

        let mut reader = HmacBlockReader::new(Cursor::new(bytes), key);
        let mut result = Vec::new();
        let err = reader.read_to_end(&mut result).unwrap_err();
        assert!(err.to_string().contains("InvalidBlockHash"));
    }
}
