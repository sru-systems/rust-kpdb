// Copyright (c) 2016-2017 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use uuid::Uuid;
use std::fmt::Display;

/// The identifier for an entry.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct EntryUuid(pub Uuid);

impl EntryUuid {
    /// Create a new random entry identifier.
    pub fn new_random() -> EntryUuid {
        EntryUuid(Uuid::new_v4())
    }

    /// Create a nil/zero entry identifier.
    pub fn nil() -> EntryUuid {
        EntryUuid(Uuid::nil())
    }
}

impl Default for EntryUuid {
    fn default() -> EntryUuid {
        EntryUuid::nil()
    }
}

impl Display for EntryUuid {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> Result<(), ::std::fmt::Error> {
        f.write_str(self.0.to_string().as_str())
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use uuid::Uuid;

    #[test]
    fn test_new_random_returns_random_entry_uuids() {
        let a = EntryUuid::new_random();
        let b = EntryUuid::new_random();
        assert!(a != b);
    }

    #[test]
    fn test_nil_returns_nil_uuid() {
        let expected = Uuid::nil();
        let actual = EntryUuid::nil().0;
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_default_returns_nil_entry_uuid() {
        let expected = EntryUuid::nil();
        let actual = EntryUuid::default();
        assert_eq!(actual, expected);
    }
}
