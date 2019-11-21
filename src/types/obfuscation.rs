// Copyright (c) 2016-2017 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::error;
use std::fmt;
use std::result::Result;

/// The type of obfuscation to use.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub enum Obfuscation {
    None,
    UseClipboard,
}

impl Obfuscation {
    /// Attempts to convert an integer to an obfuscation type.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use kpdb::Obfuscation;
    /// # use kpdb::ObfuscationError;
    ///
    /// # fn from_i32_example() -> Result<Obfuscation, ObfuscationError> {
    /// let obfuscation = try!(Obfuscation::from_i32(0));
    /// # Ok(obfuscation)
    /// # }
    /// ```
    pub fn from_i32(id: i32) -> Result<Obfuscation, ObfuscationError> {
        match id {
            0 => Ok(Obfuscation::None),
            1 => Ok(Obfuscation::UseClipboard),
            _ => Err(ObfuscationError::InvalidValue),
        }
    }

    /// Gets the integer value of the obfuscation type.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use kpdb::Obfuscation;
    ///
    /// let obfuscation = Obfuscation::None;
    /// let integer = obfuscation.to_i32();
    /// ```
    pub fn to_i32(self) -> i32 {
        self as i32
    }
}

impl Default for Obfuscation {
    fn default() -> Obfuscation {
        Obfuscation::None
    }
}

/// Error type for obfuscation conversion errors.
#[derive(Debug, PartialEq)]
pub enum ObfuscationError {
    /// Invalid value.
    InvalidValue,
}

impl ObfuscationError {
    fn msg(&self) -> &str {
        match *self {
            ObfuscationError::InvalidValue => "invalid value",
        }
    }
}

impl fmt::Display for ObfuscationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ObfuscationError::InvalidValue => write!(f, "Obfuscation error: {}", self.msg()),
        }
    }
}

impl error::Error for ObfuscationError {
    fn description(&self) -> &str {
        self.msg()
    }

    fn cause(&self) -> Option<&dyn error::Error> {
        None
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_from_i32_with_valid_i32_returns_obfuscation() {
        assert_eq!(Obfuscation::from_i32(0), Ok(Obfuscation::None));
        assert_eq!(Obfuscation::from_i32(1), Ok(Obfuscation::UseClipboard));
    }

    #[test]
    fn test_from_i32_with_invalid_i32_returns_error() {
        assert_eq!(Obfuscation::from_i32(-1), Err(ObfuscationError::InvalidValue));
        assert_eq!(Obfuscation::from_i32(2), Err(ObfuscationError::InvalidValue));
    }

    #[test]
    fn test_to_i32_returns_correct_i32() {
        assert_eq!(Obfuscation::None.to_i32(), 0);
        assert_eq!(Obfuscation::UseClipboard.to_i32(), 1);
    }

    #[test]
    fn test_default_returns_correct_value() {
        assert_eq!(Obfuscation::default(), Obfuscation::None);
    }
}
