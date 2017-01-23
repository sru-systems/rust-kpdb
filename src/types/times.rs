// Copyright (c) 2016-2017 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use chrono::{DateTime, UTC};

/// Trait for getting and setting of time related data.
pub trait Times {
    /// Gets the date and time the implementor was created.
    fn creation_time(&self) -> DateTime<UTC>;

    /// Gets whether the implementor expires.
    fn expires(&self) -> bool;

    /// Gets the date and time the implementor will expire if expires is true.
    fn expiry_time(&self) -> DateTime<UTC>;

    /// Gets the date and time the implementor was last accessed.
    fn last_accessed(&self) -> DateTime<UTC>;

    /// Gets the date and time the implementor was last modified.
    fn last_modified(&self) -> DateTime<UTC>;

    /// Gets the date and time the location of the implementor was changed.
    fn location_changed(&self) -> DateTime<UTC>;

    /// Gets the usage count for the implementor.
    fn usage_count(&self) -> i32;

    /// Sets the date and time the implementor was created.
    fn set_creation_time(&mut self, DateTime<UTC>);

    /// Sets whether the implementor expires.
    fn set_expires(&mut self, bool);

    /// Sets the date and time the implementor will expire if expires is true.
    fn set_expiry_time(&mut self, DateTime<UTC>);

    /// Sets the date and time the implementor was last accessed.
    fn set_last_accessed(&mut self, DateTime<UTC>);

    /// Sets the date and time the implementor was last modified.
    fn set_last_modified(&mut self, DateTime<UTC>);

    /// Sets the date and time the location of the implementor was changed.
    fn set_location_changed(&mut self, DateTime<UTC>);

    /// Sets the usage count for the implementor.
    fn set_usage_count(&mut self, i32);
}
