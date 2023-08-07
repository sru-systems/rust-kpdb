// Copyright (c) 2016-2017 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::string_key::StringKey;
use super::string_value::StringValue;
use std::collections::HashMap;

/// A type alias for the map with strings.
pub type StringsMap = HashMap<StringKey, StringValue>;
