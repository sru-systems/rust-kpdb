// Copyright (c) 2016-2017 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use common;

/// The database version.
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct Version {
    /// Major version number.
    pub major: u16,

    /// Minor version number.
    pub minor: u16,
}

impl Version {
    /// Create a new version for a kdb2 database.
    pub fn new_kdb2() -> Version {
        Version {
            major: common::KDB2_MAJOR_VERSION,
            minor: common::KDB2_MINOR_VERSION,
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_new_kdb2_returns_correct_instance() {
        let version = Version::new_kdb2();
        assert_eq!(version.major, 3);
        assert_eq!(version.minor, 1);
    }
}
