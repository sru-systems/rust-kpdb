// Copyright (c) 2016-2017,2025 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use cbc::cipher::block_padding::UnpadError;
use std::error;
use std::fmt;
use std::io;
use xml::reader as xmlreader;
use xml::writer as xmlwriter;

/// Error type for database errors.
#[derive(Debug)]
pub enum Error {
    /// Error during the encryption or decryption of the database.
    CryptoError(UnpadError),

    /// The hash of a data block is invalid.
    InvalidBlockHash,

    /// The data block has an invalid identifier.
    InvalidBlockId(u32),

    /// The database signature is invalid.
    InvalidDbSignature([u8; 4]),

    /// The hash of the final data block is invalid.
    InvalidFinalBlockHash([u8; 32]),

    /// The header hash is invalid (doesn't match expected hash).
    InvalidHeaderHash,

    /// The data is invalid.
    InvalidData,

    /// The size of a header is invalid
    InvalidHeaderSize {
        /// Header identifier.
        id: u8,

        /// Expected size.
        expected: u16,

        /// Actual size.
        actual: u16,
    },

    /// The key (user's password and key file) is invalid.
    InvalidKey,

    /// The key file is invalid.
    InvalidKeyFile,

    /// An I/O error has occurred.
    Io(io::Error),

    /// The supplied header is missing.
    MissingHeader(u8),

    /// The version of a variant dictionary is not supported.
    InvalidVariantDictionaryVersion(u16),

    /// The value type of a variant dictionary is not supported.
    UnhandledVariantValueType(u8),

    /// The compression algorithm specified in the headers is not supported.
    UnhandledCompression(u32),

    /// The database type specified in the headers is not supported.
    UnhandledDbType([u8; 4]),

    /// The header type used in the headers is not supported.
    UnhandledHeader(u8),

    /// The master encryption algorithm is not supported.
    UnhandledMasterCipher([u8; 16]),

    /// The stream encryption algorithm is not supported.
    UnhandledStreamCipher(u32),

    /// The specified functionality is not yet supported.
    Unimplemented(String),

    /// The XML contains the specified error.
    XmlError(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::CryptoError(_) => write!(f, "Crypto error: invalid padding."),
            Error::InvalidBlockHash => write!(f, "Invalid block hash"),
            Error::InvalidBlockId(val) => write!(f, "Invalid block id: {}", val),
            Error::InvalidDbSignature(val) => write!(f, "Invalid database signature: {:?}", val),
            Error::InvalidFinalBlockHash(val) => write!(f, "Invalid final block hash: {:?}", val),
            Error::InvalidHeaderSize {
                id,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "Invalid header size: id: {}, expected: {}, actual: {}",
                    id, expected, actual
                )
            }
            Error::InvalidHeaderHash => write!(f, "Invalid header hash"),
            Error::InvalidData => write!(f, "Invalid data"),
            Error::InvalidKey => write!(f, "Invalid key"),
            Error::InvalidKeyFile => write!(f, "Invalid key file"),
            Error::Io(ref err) => write!(f, "IO error: {}", err),
            Error::MissingHeader(val) => write!(f, "Missing header: {}", val),
            Error::InvalidVariantDictionaryVersion(val) => {
                write!(f, "Invalid variant dictionary version: {}", val)
            }
            Error::UnhandledVariantValueType(val) => {
                write!(f, "Unhandled variant dictionary value type: {}", val)
            }
            Error::UnhandledCompression(val) => write!(f, "Unhandled compression: {}", val),
            Error::UnhandledDbType(val) => write!(f, "Unhandled database type: {:?}", val),
            Error::UnhandledHeader(val) => write!(f, "Unhandled header: {}", val),
            Error::UnhandledMasterCipher(val) => write!(f, "Unhandled master cipher: {:?}", val),
            Error::UnhandledStreamCipher(val) => write!(f, "Unhandled stream cipher: {}", val),
            Error::Unimplemented(ref val) => write!(f, "Unimplemented: {}", val),
            Error::XmlError(ref val) => write!(f, "XML error: {}", val),
        }
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            Error::Io(ref err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::Io(err)
    }
}

impl From<xmlreader::Error> for Error {
    fn from(err: xmlreader::Error) -> Error {
        Error::XmlError(format!("{}", err))
    }
}

impl From<xmlwriter::Error> for Error {
    fn from(err: xmlwriter::Error) -> Error {
        Error::XmlError(format!("{}", err))
    }
}

impl From<UnpadError> for Error {
    fn from(err: UnpadError) -> Error {
        Error::CryptoError(err)
    }
}
