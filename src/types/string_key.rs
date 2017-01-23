// Copyright (c) 2016-2017 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

/// A key for the map with strings.
#[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub enum StringKey {
    /// The value is a notes string.
    Notes,

    /// The value is an other string with specified name.
    Other(String),

    /// The value is a password string.
    Password,

    /// The value is a title string.
    Title,

    /// The value is a URL string.
    Url,

    /// The value is a username string.
    Username,
}

impl StringKey {
    /// Create a string key from a string.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use kpdb::StringKey;
    ///
    /// let notes_key = StringKey::from_string("Notes");
    /// let password_key = StringKey::from_string("Password");
    /// let title_key = StringKey::from_string("Title");
    /// let url_key = StringKey::from_string("URL");
    /// let username_key = StringKey::from_string("UserName");
    /// let other_key = StringKey::from_string("Foo");
    /// ```
    pub fn from_string(string: &str) -> StringKey {
        match string.to_lowercase().as_str() {
            "notes" => StringKey::Notes,
            "password" => StringKey::Password,
            "title" => StringKey::Title,
            "url" => StringKey::Url,
            "username" => StringKey::Username,
            _ => StringKey::Other(String::from(string)),
        }
    }

    /// Gets the string representation of the string key.
    ///
    /// # Examples
    ///
    /// ```
    /// use kpdb::StringKey;
    ///
    /// let notes_key = StringKey::Notes;
    /// let string = notes_key.to_string();
    /// ```
    pub fn to_string(&self) -> String {
        match *self {
            StringKey::Notes => String::from("Notes"),
            StringKey::Other(ref string) => string.clone(),
            StringKey::Password => String::from("Password"),
            StringKey::Title => String::from("Title"),
            StringKey::Url => String::from("URL"),
            StringKey::Username => String::from("UserName"),
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_from_string_returns_correct_string_key() {
        for tuple in get_test_tuples() {
            let expected = tuple.1;
            let actual = StringKey::from_string(tuple.0);
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn test_to_string_returns_correct_string() {
        for tuple in get_test_tuples() {
            let expected = tuple.0;
            let actual = tuple.1.to_string();
            assert_eq!(actual, expected);
        }
    }

    fn get_test_tuples() -> Vec<(&'static str, StringKey)> {
        vec![("Notes", StringKey::Notes),
             ("Password", StringKey::Password),
             ("Title", StringKey::Title),
             ("URL", StringKey::Url),
             ("UserName", StringKey::Username),
             ("FooBar", StringKey::Other(String::from("FooBar")))]
    }
}
