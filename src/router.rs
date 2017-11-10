use futures::future;
use hyper::header::{ContentLength, ContentType};
use hyper::mime;
use hyper::server::{Service, Request, Response};
use hyper::{Get, Post, StatusCode};
use hyper;
use key::Key;
use cas::CasClient;
use hyper::Uri;
use percent_encoding::{percent_decode, utf8_percent_encode, DEFAULT_ENCODE_SET};
use cookie;
use cas;

#[derive(Clone, Copy)]
pub struct Router<'a> {
    key: &'a Key,
    domain: &'a Uri,
    cas: &'a CasClient,
}

impl<'a> Router<'a> {
    pub fn new(cookie_key: &'a Key, domain: &'a Uri, cas_client: &'a CasClient) -> Router<'a> {
        Router{key: cookie_key, domain: domain, cas: cas_client}
    }

    fn service_url(&self, paths: &Vec<String>) -> String {
        let mut path = paths.join("/");
        if !path.starts_with("/") {
            path = "/".to_string() + &path[..]
        }
        utf8_percent_encode(&(self.domain.to_string()+ &path[..])[..],
            DEFAULT_ENCODE_SET
        ).to_string()
    }
}

impl<'a> Service for Router<'a> {
    type Request = Request;
    type Response = Response;
    type Error = hyper::Error;
    type Future = future::FutureResult<Response, hyper::Error>;

    fn call(&self, req: Request) -> Self::Future {
        print!("[REQUEST] {:?}\n", req);
        if let Ok(paths) = paths(req.path()) {
            //https://tokio-rs.github.io/tokio-middleware/src/tokio_middleware/log.rs.html
            //  print!("[REQUEST] {:?}\n", req); // NOTE req.remote_addr() was None when using 127.0.0.1 host address.
            future::ok(
                match (req.method(), &(paths[0])[..]) {
                    // Health checks. TODO: Verify key files may be accessible
                    (&Get, "health") => {
                        let body: &'static [u8] = b"Up";
                        Response::new()
                            .with_header(ContentType(mime::TEXT_PLAIN))
                            .with_header(ContentLength(body.len() as u64))
                            .with_body(body)
                    }
                    // CSS and image resource files
                    (&Get, "static") => {
                        let body = "<!DOCTYPE html><html><head><meta charset=\"utf-8\" /><title>files</title></head><body>This will be replaced with resource file headers and content</body>";
                        Response::new()
                            .with_header(ContentLength(body.len() as u64))
                            .with_body(body)
                    }
                    // Allow to logout without checking if logged in;
                    // so if a valid CAS user (authentication), but does
                    // NOT have authorization to access any routes, the
                    // user can still log out.
                    (&Get, "logout") => {
                        if let Ok(c) = cookie::Cookie::new(Some(cookie::CookiePrefix::HOST), "id", "", Some(self.key)) {
                            self.cas.logout_redirect(&self.service_url(&vec!["/".to_string()]))
                                .with_header(
                                    hyper::header::SetCookie(vec![
                                        c.with_path(Some("/"))
                                            .clear()
                                            .with_secure(true)
                                            .with_http_only(true)
                                            .with_same_site(Some(cookie::SameSite::LAX))
                                            .get_full_value()
                                    ])
                                )
                        } else {
                            let body = "<!DOCTYPE html><html><head><meta charset=\"utf-8\" /><title>500 logout - clear session error</title></head><body>Unable to clear session.</body>";
                            Response::new()
                                .with_status(StatusCode::InternalServerError)
                                .with_header(ContentLength(body.len() as u64))
                                .with_body(body)
                        }
                    }
                    // CAS infrastructure
                    // Route/Path were single page application will be accessed.
                    (&Get, "/") | (&Get, "files") => {
                        if let Some(c) = cookie::Cookie::from_request(&req, Some(cookie::CookiePrefix::HOST), "id") {
                            // Session cookie found (get ID)
                            if let Ok(id) = c.get_value(Some(self.key)) {
                                // Valid session cookie so manage request
                                let body = "<!DOCTYPE html><html><head><meta charset=\"utf-8\" /><title>get cookie</title></head><body>id = ".to_string() + &id[..] + "</body>";
                                Response::new()
                                    .with_status(StatusCode::InternalServerError)
                                    .with_header(ContentLength(body.len() as u64))
                                    .with_body(body)
                            // Invalid session cookie; so clear out session cookie and redirect CAS login
                            } else {
                                if let Ok(c) = cookie::Cookie::new(Some(cookie::CookiePrefix::HOST), "id", "", Some(self.key)) {
                                    self.cas.login_redirect(&self.service_url(&paths)[..])
                                        .with_header(
                                            hyper::header::SetCookie(vec![
                                                c.with_path(Some("/"))
                                                    .clear()
                                                    .with_secure(true)
                                                    .with_http_only(true)
                                                    .with_same_site(Some(cookie::SameSite::LAX))
                                                    .get_full_value()
                                            ])
                                        )
                                } else {
                                    let body = "<!DOCTYPE html><html><head><meta charset=\"utf-8\" /><title>500 login retry - clear session error</title></head><body>Unable to clear session in attempt to retry login.</body>";
                                    Response::new()
                                        .with_status(StatusCode::InternalServerError)
                                        .with_header(ContentLength(body.len() as u64))
                                        .with_body(body)
                                }
                            }
                            // TODO: Content-Disposition header should be set for downloading videos
                        } else { 
                            // Session cookie was not found
                            match self.cas.verify_from_request(req.uri().query(), &self.service_url(&paths)[..]) {
                                // If this was a redirect from CAS with token then verify and setup session cookie.
                                Ok(cas::ServiceResponse::Success(id)) => {
                                    if let Ok(c) = cookie::Cookie::new(Some(cookie::CookiePrefix::HOST), "id", &id[..], Some(self.key)) {
                                        let body = "<!DOCTYPE html><html><head><meta charset=\"utf-8\" /><title>set session</title></head><body>set id cookie.</body>";
                                        Response::new()
                                            .with_header(ContentLength(body.len() as u64))
                                            .with_header(
                                                hyper::header::SetCookie(vec![
                                                    c.with_path(Some("/"))
                                                        .with_secure(true)
                                                        .with_http_only(true)
                                                        .with_same_site(Some(cookie::SameSite::LAX))
                                                        .get_full_value()
                                                ])
                                            )
                                            .with_body(body)
                                    } else {
                                        let body = "<!DOCTYPE html><html><head><meta charset=\"utf-8\" /><title>500 login - set session error</title></head><body>Unable to set session.</body>";
                                        Response::new()
                                            .with_status(StatusCode::InternalServerError)
                                            .with_header(ContentLength(body.len() as u64))
                                            .with_body(body)
                                    }
                                }
                                // If not a redirect from CAS, or Ticket error, then redirect to CAS (Make sure not to run into infinite loop)
                                Ok(cas::ServiceResponse::Failure(e)) => {
                                    print!("[CAS VERIFY RESPONSE] {:?}\n", e);
                                    self.cas.login_redirect(&self.service_url(&paths)[..])
                                }
                                Err(e) => {
                                    print!("[CAS VERIFY RESPONSE] {:?}\n", e);
                                    self.cas.login_redirect(&self.service_url(&paths)[..])
                                }
                            }
                        }
                    }
                    // Generally CAS server announcements of SSO logouts
                    (&Post, _) => {
                       //print!("[REQUEST] {:?}", req);
                       Response::new()
                    }
                    _ => Response::new().with_status(StatusCode::NotFound),
                }
            )
        } else {
            future::ok(Response::new().with_status(StatusCode::NotFound))
        }
    }
}

// Make sure to leave out directory structures such as:
//   "/", "..", and hidden paths that start with '.' character.
// May also want not include bash commands such as:
//    <, >, ;, *, [, ], (, ), #, !, {, }, ...
#[inline(always)]
fn not_whitelist_char(c: char) -> bool {
    !(c.is_alphanumeric() || c == '_' || c == '-' || c == '.')
}

/// Whitelist allowed characters, remove .. within
/// percent decoded path segments. The result will always
/// be either an Err or a Ok type with a vector of at least
/// one entry.
fn paths(path: &str) -> Result<Vec<String>, &'static str> {
    let mut paths = Vec::new();
    let segments = path.split("/");
    for segment in segments {
        let decoded = percent_decode(segment.as_bytes())
            .decode_utf8()
            .map_err(|_| "Invalid percent decoded value in path.")?;
        if decoded == ".." {
            paths.pop();
        } else if decoded == "" {
            continue;
        } else if decoded.starts_with('.') {
            return Err("Path contains hidden directory.")
        } else if decoded.contains(not_whitelist_char) {
            return Err("Path contains a non-whitelisted character.")
        } else {
            paths.push(decoded.into_owned());
        }
    }
    // NOTE: hyper request path will at the very least should send back
    // a "/" if the path submitted was empty, however we could get a
    // "/.." path which would generate an empty vector which must be fixed
    if paths.len() == 0 {
      paths.push("/".to_string());
    }
    Ok(paths)
}
