// Copyright (c) 2025 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

/// The variant of the Argon2 key derivation function.
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum Argon2Variant {
    /// The Argon2d variant.
    Argon2d,

    /// The Argon2id variant.
    Argon2id,
}

/// The configuration of the key derivation function used to derive the database key.
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum KdfConfig {
    /// The AES key derivation function.
    AesKdf,

    /// The Argon2 key derivation function.
    Argon2 {
        /// Number of iterations.
        iterations: u64,

        /// Amount of memory in bytes.
        memory: u64,

        /// Degree of parallelism.
        parallelism: u32,

        /// The Argon2 version.
        version: u32,

        /// The Argon2 variant.
        variant: Argon2Variant,
    },
}
