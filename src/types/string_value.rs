// Copyright (c) 2016-2017 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use secstr::SecStr;

/// A value for the map with strings.
#[derive(Clone, Debug, PartialEq)]
pub enum StringValue {
    /// Plain string value.
    Plain(String),

    /// Protected string value.
    Protected(SecStr),
}

impl StringValue {
    /// Create a new string value.
    ///
    /// # Examples
    ///
    /// ```
    /// use kpdb::StringValue;
    ///
    /// let plain_value = StringValue::new("plain", false);
    /// let protected_value = StringValue::new("secret", true);
    /// ```
    pub fn new(value: &str, protected: bool) -> StringValue {
        if protected {
            StringValue::Protected(SecStr::from(value))
        } else {
            StringValue::Plain(String::from(value))
        }
    }
}

#[cfg(test)]
mod tests {

    use secstr::SecStr;
    use super::*;

    #[test]
    fn test_new_with_plain_value_returns_correct_string_value() {
        let value = "FooBar";
        let expected = StringValue::Plain(String::from(value));
        let actual = StringValue::new(value, false);
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_new_with_protected_value_returns_correct_string_value() {
        let value = "FooBar";
        let expected = StringValue::Protected(SecStr::from(value));
        let actual = StringValue::new(value, true);
        assert_eq!(actual, expected);
    }
}
