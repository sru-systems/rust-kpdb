// Copyright (c) 2016-2017 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::io::{Read, Result};
use super::log::Log;

/// A reader that logs the read data.
pub struct LogReader<R> {
    inner: R,
    is_logging: bool,
    log_data: Vec<u8>,
}

impl<R: Read> LogReader<R> {
    /// Create a new logging reader.
    pub fn new(inner: R) -> LogReader<R> {
        LogReader {
            inner: inner,
            is_logging: true,
            log_data: Vec::new(),
        }
    }
}

impl<R> Log for LogReader<R> {
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

impl<R: Read> Read for LogReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let result = self.inner.read(buf);
        if self.is_logging {
            self.log_data.extend_from_slice(&buf);
        }
        result
    }
}

#[cfg(test)]
mod tests {

    use std::io::{Cursor, Read};
    use super::*;
    use io::Log;

    #[test]
    fn test_clear_clears_logged_data() {
        let mut target = new_log_reader();
        let mut buffer = vec![0; 4];
        target.read(&mut buffer).unwrap();
        assert_eq!(target.logged(), &vec![0, 1, 2, 3]);

        target.clear();
        assert_eq!(target.logged(), &Vec::<u8>::new());
    }

    #[test]
    fn test_logged_returns_correct_data() {
        let mut target = new_log_reader();
        let mut buffer = vec![0; 4];
        target.read(&mut buffer).unwrap();
        assert_eq!(buffer, vec![0, 1, 2, 3]);
        assert_eq!(target.logged(), &vec![0, 1, 2, 3]);
    }

    #[test]
    fn test_start_and_stop_starts_and_stops_the_logging() {
        let mut target = new_log_reader();
        let mut buffer = vec![0; 4];
        target.read(&mut buffer).unwrap();
        assert_eq!(target.logged(), &vec![0, 1, 2, 3]);

        target.stop();
        target.read(&mut buffer).unwrap();
        assert_eq!(target.logged(), &vec![0, 1, 2, 3]);

        target.start();
        target.read(&mut buffer).unwrap();
        assert_eq!(target.logged(), &vec![0, 1, 2, 3, 8, 9, 10, 11]);
    }

    fn new_log_reader() -> LogReader<Cursor<Vec<u8>>> {
        let vec = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let source = Cursor::new(vec);
        LogReader::new(source)
    }
}
