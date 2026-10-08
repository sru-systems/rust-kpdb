// Copyright (c) 2025 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Module for the Argon2 key derivation function.

use crate::types::{Argon2Variant, Error, Result};
use argon2::{Algorithm, Argon2, Params, Version};

/// Derives a 32 byte key from the password using Argon2.
pub fn derive(
    password: &[u8],
    salt: &[u8],
    iterations: u64,
    memory: u64,
    parallelism: u32,
    version: u32,
    variant: &Argon2Variant,
) -> Result<[u8; 32]> {
    let version = match version {
        0x10 => Version::V0x10,
        0x13 => Version::V0x13,
        _ => return Err(Error::InvalidData),
    };
    let algorithm = match *variant {
        Argon2Variant::Argon2d => Algorithm::Argon2d,
        Argon2Variant::Argon2id => Algorithm::Argon2id,
    };
    // The KDBX4 memory parameter is in bytes, while the Argon2 parameters
    // require a minimum of 8 * parallelism KiB.
    let memory_kib = (memory / 1024).max(8) as u32;
    let params = Params::new(memory_kib, iterations as u32, parallelism, None)
        .map_err(|_| Error::InvalidData)?;
    let argon2 = Argon2::new(algorithm, version, params);
    let mut output = [0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut output)
        .map_err(|_| Error::InvalidData)?;
    Ok(output)
}
