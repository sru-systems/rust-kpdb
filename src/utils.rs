// Copyright (c) 2017 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Module containing utility functions.

#[cfg(test)]
pub mod test {

    use chrono::{DateTime, Duration, Utc};

    pub fn approx_equal_datetime(a: DateTime<Utc>, b: DateTime<Utc>) -> bool {
        let duration = a.signed_duration_since(b);
        duration < Duration::seconds(1) && duration > Duration::seconds(-1)
    }
}
