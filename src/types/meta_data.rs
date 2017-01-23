// Copyright (c) 2016-2017 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::comment::Comment;
use super::compression::Compression;
use super::header_hash::HeaderHash;
use super::master_cipher::MasterCipher;
use super::stream_cipher::StreamCipher;
use super::transform_rounds::TransformRounds;
use super::version::Version;

/// Represents the meta data of the database.
#[derive(Clone, Debug, PartialEq)]
pub struct MetaData {
    /// Content of the comment header.
    pub comment: Option<Comment>,

    /// Compression algorithm.
    pub compression: Compression,

    /// Hash of the header data.
    pub header_hash: HeaderHash,

    /// Master encryption algorithm.
    pub master_cipher: MasterCipher,

    /// Stream encryption algorithm (e.g. passwords).
    pub stream_cipher: StreamCipher,

    /// Number of times the composite key must be transformed.
    pub transform_rounds: TransformRounds,

    /// Database version.
    pub version: Version,
}
