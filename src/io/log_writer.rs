// Copyright (c) 2016-2017 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::log::Log;
use std::io::{Result, Write};

/// A writer that logs the written data.
pub struct LogWriter<W> {
    inner: W,
    is_logging: bool,
    log_data: Vec<u8>,
}

impl<W: Write> LogWriter<W> {
    /// Create a new logging writer.
    pub fn new(inner: W) -> LogWriter<W> {
        LogWriter {
            inner: inner,
            is_logging: true,
            log_data: Vec::new(),
        }
    }
}

impl<W> Log for LogWriter<W> {
    fn clear(&mut self) {
        self.log_data = Vec::new();
    }

    fn logged(&self) -> &Vec<u8> {
        &self.log_data
    }

    fn start(&mut self) {
        self.is_logging = true;
    }

    fn stop(&mut self) {
        self.is_logging = false;
    }
}

impl<W: Write> Write for LogWriter<W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let result = self.inner.write(buf);
        if self.is_logging {
            self.log_data.extend_from_slice(buf);
        }
        result
    }

    fn flush(&mut self) -> Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::io::Log;
    use std::io::Write;

    #[test]
    fn test_clear_clears_logged_data() {
        let mut target = LogWriter::new(Vec::new());
        target.write(&[0, 1, 2, 3]).unwrap();
        assert_eq!(target.logged(), &vec![0, 1, 2, 3]);

        target.clear();
        assert_eq!(target.logged(), &Vec::<u8>::new());
    }

    #[test]
    fn test_logged_returns_correct_data() {
        let mut target = LogWriter::new(Vec::new());
        target.write(&[0, 1, 2, 3]).unwrap();
        assert_eq!(target.logged(), &vec![0, 1, 2, 3]);
    }

    #[test]
    fn test_start_and_stop_starts_and_stops_the_logging() {
        let mut target = LogWriter::new(Vec::new());
        target.write(&[0, 1, 2, 3]).unwrap();
        assert_eq!(target.logged(), &vec![0, 1, 2, 3]);

        target.stop();
        target.write(&[4, 5, 6, 7]).unwrap();
        assert_eq!(target.logged(), &vec![0, 1, 2, 3]);

        target.start();
        target.write(&[8, 9, 10, 11]).unwrap();
        assert_eq!(target.logged(), &vec![0, 1, 2, 3, 8, 9, 10, 11]);
    }
}
