// Copyright (c) 2016-2017 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

/// Trait used for readers and writers that support logging.
pub trait Log {
    /// Clears the logged data.
    fn clear(&mut self);

    /// Gets the logged data.
    fn logged(&self) -> &Vec<u8>;

    /// Starts the logging (the default).
    fn start(&mut self);

    /// Stops the logging.
    fn stop(&mut self);
}
