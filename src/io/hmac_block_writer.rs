// Copyright (c) 2025 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::crypto::hmac;
use crate::crypto::sha512;
use crate::types::{HmacKey, Result};
use byteorder::{LittleEndian, WriteBytesExt};
use std::io::Write;

pub struct HmacBlockWriter<W: Write> {
    inner: W,
    key: HmacKey,
    block_index: u64,
}

impl<W: Write> HmacBlockWriter<W> {
    pub fn new(inner: W, key: HmacKey) -> Self {
        HmacBlockWriter {
            inner,
            key,
            block_index: 0,
        }
    }

    pub fn write_block(&mut self, data: &[u8]) -> Result<()> {
        let block_key = sha512::hash(&[&self.block_index.to_le_bytes(), &self.key.0]);
        let mut size_bytes = Vec::new();
        size_bytes
            .write_i32::<LittleEndian>(data.len() as i32)
            .unwrap();
        let hmac = hmac::hash(&block_key, &[&self.block_index.to_le_bytes(), &size_bytes, data])?;

        self.inner.write_all(&hmac)?;
        self.inner.write_i32::<LittleEndian>(data.len() as i32)?;
        if !data.is_empty() {
            self.inner.write_all(data)?;
        }
        self.block_index += 1;
        Ok(())
    }

    pub fn finish(&mut self) -> Result<()> {
        self.write_block(&[])?;
        Ok(())
    }
}

pub fn write_hmac_blocks<W: Write>(writer: &mut W, data: &[u8], key: &HmacKey) -> Result<()> {
    let mut hmac_writer = HmacBlockWriter::new(writer, key.clone());
    const BLOCK_SIZE: usize = 1024 * 1024;
    let mut offset = 0;
    while offset < data.len() {
        let end = std::cmp::min(offset + BLOCK_SIZE, data.len());
        hmac_writer.write_block(&data[offset..end])?;
        offset = end;
    }
    hmac_writer.finish()?;
    Ok(())
}
