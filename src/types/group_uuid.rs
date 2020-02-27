// Copyright (c) 2016-2017 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use uuid::Uuid;
use std::fmt::Display;

/// The identifier for a group.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct GroupUuid(pub Uuid);

impl GroupUuid {
    /// Create a new random group identifier.
    pub fn new_random() -> GroupUuid {
        GroupUuid(Uuid::new_v4())
    }

    /// Create a nil/zero group identifier.
    pub fn nil() -> GroupUuid {
        GroupUuid(Uuid::nil())
    }
}

impl Default for GroupUuid {
    fn default() -> GroupUuid {
        GroupUuid::nil()
    }
}

impl Display for GroupUuid {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> Result<(), ::std::fmt::Error> {
        f.write_str(self.0.to_string().as_str())
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use uuid::Uuid;

    #[test]
    fn test_new_random_returns_random_group_uuids() {
        let a = GroupUuid::new_random();
        let b = GroupUuid::new_random();
        assert!(a != b);
    }

    #[test]
    fn test_nil_returns_nil_uuid() {
        let expected = Uuid::nil();
        let actual = GroupUuid::nil().0;
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_default_returns_nil_group_uuid() {
        let expected = GroupUuid::nil();
        let actual = GroupUuid::default();
        assert_eq!(actual, expected);
    }
}
