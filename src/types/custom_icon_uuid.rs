// Copyright (c) 2016-2017 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use uuid::Uuid;

/// The identifier for a custom icon.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CustomIconUuid(pub Uuid);

impl CustomIconUuid {
    /// Create a new random custom icon identifier.
    pub fn new_random() -> CustomIconUuid {
        CustomIconUuid(Uuid::new_v4())
    }

    /// Create a nil/zero custom icon identifier.
    pub fn nil() -> CustomIconUuid {
        CustomIconUuid(Uuid::nil())
    }
}

impl Default for CustomIconUuid {
    fn default() -> CustomIconUuid {
        CustomIconUuid::nil()
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use uuid::Uuid;

    #[test]
    fn test_new_random_returns_random_custom_icon_uuids() {
        let a = CustomIconUuid::new_random();
        let b = CustomIconUuid::new_random();
        assert!(a != b);
    }

    #[test]
    fn test_nil_returns_nil_uuid() {
        let expected = Uuid::nil();
        let actual = CustomIconUuid::nil().0;
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_default_returns_nil_custom_icon_uuid() {
        let expected = CustomIconUuid::nil();
        let actual = CustomIconUuid::default();
        assert_eq!(actual, expected);
    }
}
