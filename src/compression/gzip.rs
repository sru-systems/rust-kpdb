// Copyright (c) 2016-2017 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use std::io::{Read, Write};
use types::Result;

/// Decode (decompress) the input using GZip.
pub fn decode(input: &[u8]) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut decoder = GzDecoder::new(input)?;
    decoder.read_to_end(&mut output)?;
    Ok(output)
}

/// Encode (compress) the input using GZip.
pub fn encode(input: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::Default);
    encoder.write_all(input)?;
    let output = encoder.finish()?;
    Ok(output)
}

#[cfg(test)]
mod tests {

    use super::*;

    quickcheck! {
        fn test_decode_inverses_encode(data: Vec<u8>) -> bool {
            let encoded = encode(&data).unwrap();
            let decoded = decode(&encoded).unwrap();
            decoded == data
        }
    }
}
