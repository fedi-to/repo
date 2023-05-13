
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

use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};

pub const COMPONENT: &'static AsciiSet = &{
    // start with CONTROLS
    CONTROLS
    // add query
    .add(b' ').add(b'"').add(b'#').add(b'<').add(b'>')
    // add path
    .add(b'?').add(b'`').add(b'{').add(b'}')
    // add userinfo
    .add(b'/').add(b':').add(b';').add(b'=').add(b'@').add(b'[').add(b'\\')
    .add(b']').add(b'^').add(b'|')
    // finish off with component
    .add(b'$').add(b'%').add(b'&').add(b'+').add(b',')
};

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

/// Error kind returned when trying to find the fallback protocol handler.
#[derive(Copy, Clone, Debug)]
pub enum FallbackError {
    /// Returned when the given URL, while valid, does not provide a fallback
    /// handler.
    NoHandler,
    /// Returned when the given target is not an URL.
    NotAnUrl,
}

impl std::error::Error for FallbackError {
}

impl std::fmt::Display for FallbackError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::NoHandler => {
                write!(f, "url does not contain a fallback handler")
            },
            Self::NotAnUrl => {
                write!(f, "url is not an appropriate web+ url")
            },
        }
    }
}

pub fn get_fallback(scheme: &str, target: &str) -> Result<String, FallbackError> {
    use FallbackError::*;
    // replace web+scheme with https
    // this allows us to handle web+ URLs with the semantics we actually
    // want, which is roughly the same as https, with a few differences
    let mut as_if_https = target.to_string();
    as_if_https.replace_range(0..4+scheme.len(), "https");
    // the main difference is that unlike https, authority is optional.
    // so, first check that there should be an authority.
    if !as_if_https.starts_with("https://") {
        return Err(NoHandler);
    }
    // then also check that the authority actually exists.
    // this is necessary so we don't end up parsing web+example:///bar as
    // web+example://bar/ (which would be wrong).
    // note that we do parse web+example://bar\ as an authority! (but
    // everything else - like the path - we treat as opaque to us)
    if as_if_https.starts_with("https:///")
    || as_if_https.starts_with("https://\\") {
        return Err(NoHandler);
    }
    // NOTE: we only do this parse to extract the domain/port, it is up to
    // the protocol-handler to deal with malformed or malicious input.
    // NOTE: this is the same URL parser as used by browsers when handling
    // `href` so this is correct.
    let mut url = url::Url::parse(&*as_if_https).map_err(|_| NoHandler)?;
    url.set_path("/.well-known/protocol-handler");
    let _ = url.set_username("");
    let _ = url.set_password(None);
    let mut params = "target=".to_owned();
    params.extend(utf8_percent_encode(&*target, COMPONENT));
    url.set_query(Some(&*params));
    url.set_fragment(None);
    Ok(url.into())
}
