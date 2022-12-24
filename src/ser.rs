
// There is no serializer.

use std::collections::HashMap;
use std::fmt::Write as _;

/// Builds a fedi-to cookie.
pub fn build_cookie(cookie: HashMap<&str, u32>, size_hint: usize) -> String {
    let mut buffer = String::with_capacity(size_hint);
    for (target, h) in cookie.into_iter() {
        buffer.push_str(target);
        write!(buffer, "{}", h).unwrap();
    }
    return buffer;
}
