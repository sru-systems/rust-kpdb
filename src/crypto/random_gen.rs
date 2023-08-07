// Copyright (c) 2016-2017 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::types::Result;
use rand::rngs::OsRng;
use rand::RngCore;

/// A cryptographic secure random number generator.
pub struct RandomGen(OsRng);

impl RandomGen {
    /// Attempts to create a new random number generator.
    pub fn new() -> Result<RandomGen> {
        let os_rng = OsRng {};
        Ok(RandomGen(os_rng))
    }

    /// Gets next 16 random bytes.
    pub fn next_16_bytes(&mut self) -> [u8; 16] {
        let mut buffer = [0u8; 16];
        self.0.fill_bytes(&mut buffer);
        buffer
    }

    /// Gets next 32 random bytes.
    pub fn next_32_bytes(&mut self) -> [u8; 32] {
        let mut buffer = [0u8; 32];
        self.0.fill_bytes(&mut buffer);
        buffer
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_next_16_bytes_returns_random_bytes() {
        let mut gen = RandomGen::new().unwrap();
        let a = gen.next_16_bytes();
        let b = gen.next_16_bytes();
        assert!(a != b);
    }

    #[test]
    fn test_next_32_bytes_returns_random_bytes() {
        let mut gen = RandomGen::new().unwrap();
        let a = gen.next_32_bytes();
        let b = gen.next_32_bytes();
        assert!(a != b);
    }
}
