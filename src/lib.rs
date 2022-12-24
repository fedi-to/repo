
#[cfg(feature="lenient_scheme")]
macro_rules! lenient_scheme_toggle {
    ( { $($lenient:tt)* }, { $($strict:tt)* } $(,)?) => { $($lenient)* }
}
#[cfg(not(feature="lenient_scheme"))]
macro_rules! lenient_scheme_toggle {
    ( { $($lenient:tt)* }, { $($strict:tt)* } $(,)?) => { $($strict)* }
}

mod de;
mod ser;

pub use de::CookieDeserializer;
pub use ser::build_cookie;

#[cfg(feature="lenient_scheme")]
/// Checks if the given scheme is invalid.
pub fn is_scheme_invalid(scheme: &str) -> bool {
    scheme.is_empty() || !scheme.trim_start_matches(|c: char| -> bool {
        // NOTE: unlike registerProtocolHandler as implemented today, we
        // further allow '-'. this enables things like a future `web+ap-post`,
        // for creating ActivityPub posts, similar to `mailto`. then `web+ap`
        // gets used for ActivityPub object references/IDs. (tho there's an
        // argument to be made for `web+apcompose` but eh. let us have `-`!)
        // since we mostly exist outside of registerProtocolHandler, these
        // differences don't really matter, until we go for standardization
        // at least. but we don't really expect much opposition against it.
        // we do forbid schemes starting or ending in - tho. so e.g. `web+-` or
        // `web+-foo` or `web+foo-` or `web+-foo-` are invalid.
        c.is_ascii_lowercase() || c == '-'
    }).is_empty() || scheme.starts_with('-') || scheme.ends_with('-')
}

#[cfg(not(feature="lenient_scheme"))]
/// Checks if the given scheme is invalid.
pub fn is_scheme_invalid(scheme: &str) -> bool {
    scheme.is_empty() || !scheme.trim_start_matches(|c: char| -> bool {
        c.is_ascii_lowercase()
    }).is_empty()
}
