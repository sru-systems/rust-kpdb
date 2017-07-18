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

const HEX_STRING_LENGTH: usize = 7;

/// A structure representing a color (RGB).
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct Color {
    /// Red part of the color.
    pub red: u8,

    /// Green part of the color.
    pub green: u8,

    /// Blue part of the color.
    pub blue: u8,
}

impl Color {
    /// Attempts to create a color from an hex string.
    ///
    /// # Errors
    ///
    /// This function will return an error when the hex string is not a valid
    /// color.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use kpdb::Color;
    /// # use kpdb::ColorError;
    ///
    /// # fn convert() -> Result<(), ColorError> {
    /// let color = try!(Color::from_hex_string("#abcdef"));
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_hex_string(hex: &str) -> Result<Color, ColorError> {
        let chars: Vec<char> = hex.chars().collect();
        let count: usize = chars.len();
        if count < HEX_STRING_LENGTH {
            Err(ColorError::HexStringTooShort)
        } else if count > HEX_STRING_LENGTH {
            Err(ColorError::HexStringTooLong)
        } else if !hex.starts_with("#") {
            Err(ColorError::HexStringNoHashSign)
        } else {
            let red = try!(from_hex_string_red(hex));
            let green = try!(from_hex_string_green(hex));
            let blue = try!(from_hex_string_blue(hex));
            Ok(Color {
                red: red,
                green: green,
                blue: blue,
            })
        }
    }

    /// Gets the hex string representation of the supplied color.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use kpdb::Color;
    ///
    /// let color = Color { red: 171, green: 205, blue: 239 };
    /// let hex = color.to_hex_string();
    /// ```
    pub fn to_hex_string(&self) -> String {
        format!("#{0:02x}{1:02x}{2:02x}", self.red, self.green, self.blue)
    }
}

/// Error type for color conversion errors.
#[derive(Debug, PartialEq)]
pub enum ColorError {
    /// The hex string doens't start with a '#' character.
    HexStringNoHashSign,

    /// The hex string is too long.
    HexStringTooLong,

    /// The hex string is too short.
    HexStringTooShort,

    /// The hex string's blue part is an invalid value.
    InvalidBlueValue,

    /// The hex string's green part is an invalid value.
    InvalidGreenValue,

    /// The hex string's red part is an invalid value.
    InvalidRedValue,
}

impl ColorError {
    fn msg(&self) -> &str {
        match *self {
            ColorError::HexStringNoHashSign => "hex string without hash sign",
            ColorError::HexStringTooLong => "hex string too long",
            ColorError::HexStringTooShort => "hex string too short",
            ColorError::InvalidBlueValue => "invalid blue value",
            ColorError::InvalidGreenValue => "invalid green value",
            ColorError::InvalidRedValue => "invalid red value",
        }
    }
}

impl fmt::Display for ColorError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ColorError::HexStringNoHashSign => write!(f, "Color error: {}", self.msg()),
            ColorError::HexStringTooLong => write!(f, "Color error: {}", self.msg()),
            ColorError::HexStringTooShort => write!(f, "Color error: {}", self.msg()),
            ColorError::InvalidBlueValue => write!(f, "Color error: {}", self.msg()),
            ColorError::InvalidGreenValue => write!(f, "Color error: {}", self.msg()),
            ColorError::InvalidRedValue => write!(f, "Color error: {}", self.msg()),
        }
    }
}

impl error::Error for ColorError {
    fn description(&self) -> &str {
        self.msg()
    }

    fn cause(&self) -> Option<&error::Error> {
        None
    }
}

fn from_hex_string_blue(hex_str: &str) -> Result<u8, ColorError> {
    match u8::from_str_radix(&hex_str[5..7], 16) {
        Ok(val) => Ok(val),
        Err(_) => Err(ColorError::InvalidBlueValue),
    }
}

fn from_hex_string_green(hex_str: &str) -> Result<u8, ColorError> {
    match u8::from_str_radix(&hex_str[3..5], 16) {
        Ok(val) => Ok(val),
        Err(_) => Err(ColorError::InvalidGreenValue),
    }
}

fn from_hex_string_red(hex_str: &str) -> Result<u8, ColorError> {
    match u8::from_str_radix(&hex_str[1..3], 16) {
        Ok(val) => Ok(val),
        Err(_) => Err(ColorError::InvalidRedValue),
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_from_hex_string_without_hash_sign_returns_error() {
        let expected = Err(ColorError::HexStringNoHashSign);
        let actual = Color::from_hex_string("1234567");
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_from_hex_string_with_too_short_hex_string_returns_error() {
        let expected = Err(ColorError::HexStringTooShort);
        let actual = Color::from_hex_string("#12345");
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_from_hex_string_with_too_long_hex_string_returns_error() {
        let expected = Err(ColorError::HexStringTooLong);
        let actual = Color::from_hex_string("#1234567");
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_from_hex_string_with_invalid_blue_value_returns_error() {
        let expected = Err(ColorError::InvalidBlueValue);
        let actual = Color::from_hex_string("#0000fg");
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_from_hex_string_with_invalid_green_value_returns_error() {
        let expected = Err(ColorError::InvalidGreenValue);
        let actual = Color::from_hex_string("#00fg00");
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_from_hex_string_with_invalid_red_value_returns_error() {
        let expected = Err(ColorError::InvalidRedValue);
        let actual = Color::from_hex_string("#fg0000");
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_from_hex_string_with_valid_hex_string_returns_color() {
        for tuple in get_test_tuples() {
            let color = Color {
                red: tuple.1,
                green: tuple.2,
                blue: tuple.3,
            };
            let expected = Ok(color);
            let actual = Color::from_hex_string(tuple.0);
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn test_to_hex_string_with_valid_color_returns_hex_string() {
        for tuple in get_test_tuples() {
            let color = Color {
                red: tuple.1,
                green: tuple.2,
                blue: tuple.3,
            };
            let expected = tuple.0;
            let actual = color.to_hex_string();
            assert_eq!(actual, expected);

        }
    }

    quickcheck! {
        fn test_from_hex_string_inverses_to_hex_string(red: u8, green: u8, blue: u8) -> bool {
            let color = Color { red: red, green: green, blue: blue };
            Color::from_hex_string(&color.to_hex_string()) == Ok(color)
        }
    }

    fn get_test_tuples() -> Vec<(&'static str, u8, u8, u8)> {
        vec![
            ("#000000", 0, 0, 0),
            ("#ff0000", 255, 0, 0),
            ("#00ff00", 0, 255, 0),
            ("#0000ff", 0, 0, 255),
            ("#ffffff", 255, 255, 255),
        ]
    }
}
