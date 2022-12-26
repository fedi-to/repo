
use std::borrow::Cow;
use std::collections::HashMap;

use axum::{
    Router,
    body::Body,
    http::{
        header::{self, HeaderValue},
        Request,
        StatusCode,
    },
    response::{Html, IntoResponse, Redirect},
    routing::{any_service, get, get_service},
};
use axum_extra::extract::Query;
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use serde::Deserialize as _;
use tower::util::ServiceExt as _;
use tower_cookies::{Cookie, CookieManagerLayer, Cookies};
use tower_http::{
    services::{ServeDir, ServeFile},
    set_header::SetResponseHeaderLayer,
};

use fedito::CookieDeserializer;
use fedito::build_cookie;
use fedito::is_scheme_invalid;

const COMPONENT: &'static AsciiSet = &{
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

#[derive(serde::Deserialize)]
struct Entry {
    name: Cow<'static, str>,
    // FIXME use well-known location instead
    // /.well-known/protocol-handler?target=
    target_url: Cow<'static, str>,
    homepage: Cow<'static, str>,
    icon: Cow<'static, str>,
    alt: Cow<'static, str>,
    active: bool,
}

static ENTRIES: &'static [Entry] = {
    &[
        Entry {
            name: Cow::Borrowed("System handler"),
            target_url: Cow::Borrowed(""),
            homepage: Cow::Borrowed(""),
            icon: Cow::Borrowed("assets/no_icon.png"),
            alt: Cow::Borrowed("No Icon"),
            active: true,
        },
        Entry {
            name: Cow::Borrowed("GAnarchy on autistic.space"),
            target_url: Cow::Borrowed("https://ganarchy.autistic.space/?url="),
            homepage: Cow::Borrowed("https://ganarchy.autistic.space/"),
            icon: Cow::Borrowed("assets/no_icon.png"),
            alt: Cow::Borrowed("No Icon"),
            active: true,
        },
        Entry {
            name: Cow::Borrowed("GAnarchy on ganarchy.github.io"),
            target_url: Cow::Borrowed("https://ganarchy.github.io/?url="),
            homepage: Cow::Borrowed("https://ganarchy.github.io/"),
            icon: Cow::Borrowed("assets/no_icon.png"),
            alt: Cow::Borrowed("No Icon"),
            active: true,
        },
    ]
};

/// Checks the referer for `POST /register`
fn is_referer_invalid(
    referer: Option<&HeaderValue>,
    host: Option<&HeaderValue>,
) -> bool {
    if referer.is_none() || host.is_none() {
        return true;
    }
    let referer = referer.unwrap().as_bytes();
    let host = host.unwrap().as_bytes();
    referer != b"/register" && !referer.starts_with(b"/register?") && {
        let referer = match referer {
            [b'h', b't', b't', b'p', b's', b':', referer @ ..] => referer,
            [b'h', b't', b't', b'p', b':', referer @ ..] => referer,
            referer => referer,
        };
        if let [b'/', b'/', referer @ ..] = referer {
            !(
                referer.starts_with(host)
                &&
                // use starts_with for implicit length checking.
                // NB: the above starts_with already checks host.len(), so
                // this cannot panic.
                referer[host.len()..].starts_with(b"/")
            )
        } else {
            true
        }
    }
}

#[derive(serde::Deserialize)]
struct GoTo {
    target: String,
    h: Option<u32>,
}

#[derive(serde::Deserialize)]
struct Register {
    protocol: String,
    h: u32,
}

#[tokio::main]
async fn main() {
    let index = ServeFile::new("dist/index.xhtml");
    let tos = ServeFile::new("dist/tos.xhtml");
    let privacy = ServeFile::new("dist/privacy.xhtml");
    let default_referer_policy = SetResponseHeaderLayer::if_not_present(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    let same_origin_referer_policy = SetResponseHeaderLayer::if_not_present(
        header::REFERRER_POLICY,
        HeaderValue::from_static("same-origin"),
    );
    let no_frames = SetResponseHeaderLayer::if_not_present(
        header::X_FRAME_OPTIONS,
        HeaderValue::from_static("DENY"),
    );
    let app = Router::new()
        .route("/", any_service(index).handle_error(handle_io_error))
        .route("/tos", any_service(tos).handle_error(handle_io_error))
        .route("/privacy", any_service(privacy).handle_error(handle_io_error))
        .route("/go", get(go))
        .route("/register", get(axum::handler::Handler::layer(
            register_get,
            same_origin_referer_policy,
        )).post(register_post))
        // for images/scripts/styles/etc
        .nest_service("/assets", any_service(ServeDir::new("assets")).handle_error(handle_io_error))
        .fallback(handle_missing)
        .layer(CookieManagerLayer::new())
        .layer(default_referer_policy)
        .layer(no_frames);
    axum::Server::bind(&"[::]:3000".parse().unwrap()).serve(app.into_make_service()).await.unwrap();
}

#[axum::debug_handler]
async fn go(
    cookies: Cookies,
    params: Query<GoTo>,
) -> Result<Redirect, (StatusCode, Cow<'static, str>)> {
    const NOT_AN_URL: (StatusCode, Cow<'static, str>) = {
        (
            StatusCode::BAD_REQUEST,
            Cow::Borrowed("The specified target is not an acceptable URL"),
        )
    };
    const NO_HANDLER: (StatusCode, Cow<'static, str>) = {
        (
            StatusCode::BAD_REQUEST,
            Cow::Borrowed("The specified URL requires an explicit handler"),
        )
    };
    const BAD_COOKIES: (StatusCode, Cow<'static, str>) = {
        (
            StatusCode::BAD_REQUEST,
            Cow::Borrowed("Could not parse protocol handler preferences. Consider clearing cookies."),
        )
    };
    let scheme = {
        let colon = params.target.find(':').ok_or(NOT_AN_URL)?;
        let scheme = &params.target[..colon];
        if !scheme.starts_with("web+") {
            return Err(NOT_AN_URL);
        }
        let scheme = &scheme[4..];
        if is_scheme_invalid(scheme) {
            return Err(NOT_AN_URL);
        }
        scheme
    };
    let h = cookies.get("d").and_then(|d| {
        let cd = CookieDeserializer::new(d.value());
        HashMap::<&str, u32>::deserialize(cd).map(|d| {
            d.get(scheme).copied()
        }).transpose()
    }).transpose().or(Err(BAD_COOKIES))?;
    // refresh cookie
    if let Some(mut d) = cookies.get("d").map(|d| d.into_owned()) {
        d.make_permanent();
        d.set_same_site(cookie::SameSite::Lax);
        cookies.add(d);
    }
    let Some(h) = h.and(params.h) else {
        let mut as_if_https = params.target.clone();
        // replace web+scheme with https
        // this allows us to handle web+ URLs with the semantics we actually
        // want, which is roughly the same as https, with a few differences
        as_if_https.replace_range(0..4+scheme.len(), "https");
        // the main difference is that unlike https, authority is optional.
        // so, first check that there should be an authority.
        if !as_if_https.starts_with("https://") {
            return Err(NO_HANDLER);
        }
        // then also check that the authority actually exists.
        // this is necessary so we don't end up parsing web+example:///bar as
        // web+example://bar/ (which would be wrong).
        // note that we do parse web+example://bar\ as an authority! (but
        // everything else is opaque)
        if as_if_https.starts_with("https:///")
        || as_if_https.starts_with("https://\\") {
            return Err(NO_HANDLER);
        }
        // NOTE: we only do this parse to extract the domain/port, it is up to
        // the protocol-handler to deal with malformed or malicious input.
        // NOTE: this is the same URL parser as used by browsers when handling
        // `href` so this is correct.
        let mut url = url::Url::parse(&*as_if_https).map_err(|_| NO_HANDLER)?;
        url.set_path("/.well-known/protocol-handler");
        let mut target = "target=".to_owned();
        target.extend(utf8_percent_encode(&*params.target, COMPONENT));
        url.set_query(Some(&*target));
        url.set_fragment(None);
        return Ok(Redirect::temporary(url.as_ref()));
    };
    let entry = ENTRIES.get(h as usize);
    entry.filter(|entry| {
        entry.active
    }).map(|entry| {
        if entry.target_url.is_empty() {
            Redirect::temporary(&*params.target)
        } else {
            let mut target = entry.target_url.to_string();
            target.extend(utf8_percent_encode(&*params.target, COMPONENT));
            Redirect::temporary(&*target)
        }
    }).ok_or_else(|| {
        (StatusCode::NOT_FOUND, Cow::Borrowed("Unknown handler"))
    })
}

#[axum::debug_handler]
async fn register_get(
    cookies: Cookies,
    params: Query<Register>,
) -> Result<Html<String>, (StatusCode, Cow<'static, str>)> {
    const BAD_PROTO: (StatusCode, Cow<'static, str>) = {
        (
            StatusCode::BAD_REQUEST,
            Cow::Borrowed("The specified protocol is not acceptable"),
        )
    };
    let scheme = &params.protocol[..];
    if !scheme.starts_with("web+") {
        return Err(BAD_PROTO);
    }
    let scheme = &scheme[4..];
    if is_scheme_invalid(scheme) {
        return Err(BAD_PROTO);
    }
    let cookie_ok = cookies.get("d").map(|d| {
        let cd = CookieDeserializer::new(d.value());
        HashMap::<&str, u32>::deserialize(cd).is_ok()
    }).unwrap_or(true);
    let entry = ENTRIES.get(params.h as usize);
    entry.filter(|entry| {
        entry.active
    }).map(|entry| {
        // FIXME this should be a template or something
        Html(format!(
            r#"
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml" lang="en">
    <head>
        <meta charset="UTF-8" />
        <meta http-equiv="X-UA-Compatible" content="IE=edge" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Register - Fedi-To</title>
    </head>
    <body class="default">
        <main>
            <h1 class="h1-main">
                <a href="/">
                    Fedi-To
                </a>
            </h1>
            {warning}
            <p>Registering a Protocol Handler</p>
            <p>Would you like to register the following web
            application for handling the
            <strong>{proto}</strong> protocol?</p>
            <img src="{icon}" alt="{alt}" />
            <h2>{title}</h2>
            <h3>Homepage: {homepage}</h3>
            <p>It will have access to the following data:</p>
            <ul>
                <li>The URL of any <strong>{proto}</strong> links you
                visit.</li>
                <li>Your IP address.</li>
                <li>Any information about your browser which is shared with 
                websites in the course of normal web browsing.</li>
            </ul>
            <p>It will <strong>not</strong> have access to the refering site,
            nor your protocol handler preferences.</p>
            <p>Note: By confirming, you agree to allow Fedi-To to
            use cookies so you can store this preference, as outlined in
            our <a href="/privacy">Privacy Policy</a>.</p>
            <form method="post"><button type="submit">Confirm</button></form>
        </main>
        <footer>
            <hr />
            <p><a href="/tos">Terms of Service</a> <a href="/privacy">Privacy Policy</a></p>
            <p>This project is made with love by a queer trans person.</p>
        </footer>
    </body>
</html>
            "#,
            proto = params.protocol,
            title = entry.name,
            homepage = entry.homepage,
            icon = entry.icon,
            alt = entry.alt,
            warning = if cookie_ok { "" } else { "<p>Warning: Could not parse cookie. It will be re-created.</p>" }
        ))
    }).ok_or_else(|| {
        (StatusCode::NOT_FOUND, Cow::Borrowed("Unknown handler"))
    })
}

// NOTE: uses same-origin referer
#[axum::debug_handler]
async fn register_post(
    cookies: Cookies,
    params: Query<Register>,
    request: Request<Body>,
) -> Result<&'static str, (StatusCode, &'static str)> {
    // far easier to just take the whole request and deal with it here than to
    // write a custom extractor for this.
    if is_referer_invalid(
        request.headers().get("referer"),
        request.headers().get("host"),
    ) {
        return Err((
            StatusCode::BAD_REQUEST,
            "Wrong domain",
        ));
    }
    const BAD_PROTO: (StatusCode, &'static str) = {
        (
            StatusCode::BAD_REQUEST,
            "The specified protocol is not acceptable",
        )
    };
    let scheme = {
        let scheme = &params.protocol[..];
        if !scheme.starts_with("web+") {
            return Err(BAD_PROTO);
        }
        let scheme = &scheme[4..];
        if is_scheme_invalid(scheme) {
            return Err(BAD_PROTO);
        }
        scheme
    };
    let entry = ENTRIES.get(params.h as usize);
    entry.filter(|entry| {
        entry.active
    }).map_or(
        Err((StatusCode::NOT_FOUND, "Unknown handler")),
        |_| {
            let new_cookie = cookies.get("d").map(|d| {
                let d = d.value();
                let cd = CookieDeserializer::new(d);
                let mut cookie_data = HashMap::<&str, u32>::deserialize(cd)
                    .unwrap_or(HashMap::new());
                let len = if cookie_data.insert(scheme, params.h).is_some() {
                    // already existed, use old length + size of integer
                    d.len() + 10
                } else {
                    // add new scheme length
                    d.len() + scheme.len() + 10
                };
                build_cookie(cookie_data, len)
            }).unwrap_or_else(|| {
                build_cookie(
                    Some((scheme, params.h)).into_iter().collect(),
                    scheme.len() + 10,
                )
            });
            if new_cookie.len() > 4000 {
                return Err((StatusCode::BAD_REQUEST, ""))
            }
            let new_cookie = Cookie::build("d", new_cookie)
                .permanent()
                // we explicitly want this cookie to be sent with cross-site
                // navigation, so strict is unsuitable here.
                .same_site(cookie::SameSite::Lax)
                .finish();
            cookies.add(new_cookie);
            Ok("Handler registered! You may now close this page.")
        },
    )
}

#[axum::debug_handler]
async fn handle_missing(request: Request<Body>) -> impl IntoResponse {
    let service = ServeFile::new("dist/404.xhtml");
    let service = get_service(service).handle_error(handle_io_error);
    let mut result = service.oneshot(request).await;
    if let Ok(ref mut response) = result {
        if response.status() == StatusCode::OK {
            *response.status_mut() = StatusCode::NOT_FOUND;
        }
    }
    result
}

async fn handle_io_error(err: std::io::Error) -> (StatusCode, String) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("Something went wrong: {}", err),
    )
}
