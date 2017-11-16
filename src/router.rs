use futures::future;
use tokio_core::reactor::Handle;
use hyper::header::{ContentLength, ContentType};
use hyper::server::{Service, Request, Response};
use hyper::{Head, Get, Post, StatusCode, Uri, mime};
use hyper;
use key::Key;
use cas::CasClient;
use percent_encoding::{percent_decode, utf8_percent_encode, DEFAULT_ENCODE_SET};
use cookie;
use cas;
//use static_file::StaticFile;

// Basic utilities

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
fn normalize_path(path: &str) -> Result<Vec<String>, &'static str> {
    path.split('/').fold(Ok(Vec::new()), |result, p| {
        match result {
            Ok(mut r) => {
                if let Ok(decoded) = percent_decode(p.as_bytes()).decode_utf8() {
                    if decoded == "..".to_string() {
                        r.pop();
                        Ok(r)
                    } else if decoded.starts_with('.') {
                        Err("Path contains hidden directory")
                    } else if decoded.contains(not_whitelist_char) {
                        Err("Path contains a non-whitelisted character")
                    } else if decoded == "".to_string() {
                        Ok(r)
                    } else {
                        r.push(decoded.to_string());
                        Ok(r)
                    }
                } else {
                    Err("Invalide percent decoded utf8 value in path")
                }
            },
            Err(_) => result,
        }
    })
}

// Handlers

////https://stackoverflow.com/questions/41179659/convert-vecstring-into-a-slice-of-str-in-rust
//fn handler<T: AsRef<str>>(id: &str, path: &[T]) -> Response {
//    let res = if path[0][..].as_ref() == "files" {
//        UIFile(id, path[1..])
//    } else {
//        UIClient(id)
//    }
//    if let Some(res) = res {
//        res
//    } else {
//        Response::new().with_status(StatusCode::NotFound)
//    }
//}

//fn UIFile<T: AsRef<str>>(id: &str, path: &[T]) -> Option<Response> {
//    if path.len() == 1 {

//        Response::new()
//            .with_body()
//    } else {
//        None
//    }
//}

//fn UIClient(id: &str) -> Option<Response> {
//}

// Router

#[derive(Clone)]
pub struct Router<'a> {
    handle: Handle,
    dir: &'a str,
    key: &'a Key,
    domain: &'a Uri,
    cas: &'a CasClient,
}

impl<'a> Router<'a> {
    pub fn new(handle: Handle, dir: &'a str, cookie_key: &'a Key, domain: &'a Uri, cas_client: &'a CasClient) -> Router<'a> {
        Router{handle: handle, dir: dir, key: cookie_key, domain: domain, cas: cas_client}
    }

    fn service_url(&self, path: &Vec<String>) -> String {
        let mut path = path.join("/");
        if !path.starts_with("/") {
            path = "/".to_string() + &path[..];
        }
        utf8_percent_encode(&(self.domain.to_string()+ &path[..])[..],
            DEFAULT_ENCODE_SET
        ).to_string()
    }
}

impl<'a> Service for Router<'a,> {
    type Request = Request;
    type Response = Response;
    type Error = hyper::Error;
    type Future = future::FutureResult<Response, hyper::Error>;

    fn call(&self, req: Request) -> Self::Future {
        print!("[REQUEST] {:?}\n", req);
        if let Ok(path) = normalize_path(req.path()) {
            //https://tokio-rs.github.io/tokio-middleware/src/tokio_middleware/log.rs.html
            //https://doc.rust-lang.org/log/env_logger/
            //  print!("[REQUEST] {:?}\n", req); // NOTE req.remote_addr() was None when using 127.0.0.1 host address.
            let mut parent = "";
            if path.len() > 0 {
                parent = &path[0][..];
            }
            future::ok(
                match (req.method(), parent) {
                    // Health checks. TODO: Verify key files may be accessible
                    (&Get, "health") => {
                        let body: &'static [u8] = b"Up";
                        Response::new()
                            .with_header(ContentType(mime::TEXT_PLAIN))
                            .with_header(ContentLength(body.len() as u64))
                            .with_body(body)
                    }
                    // CSS and image resource files
                    (&Get, "resources") => {
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
                    (&Get, "") | (&Get, "files") | (&Head, "files") => {
                        if let Some(c) = cookie::Cookie::from_request(&req, Some(cookie::CookiePrefix::HOST), "id") {
                            // Session cookie found (get ID)
                            if let Ok(id) = c.get_value(Some(self.key)) {
                                // Valid session cookie so manage request
                                // TODO: Content-Disposition header should be set for downloading videos
                                // TODO: UI/File handler
                                let body = "<!DOCTYPE html><html><head><meta charset=\"utf-8\" /><title>get cookie</title></head><body>id = ".to_string() + &id[..] + "</body>";
                                Response::new()
                                    .with_status(StatusCode::InternalServerError)
                                    .with_header(ContentLength(body.len() as u64))
                                    .with_body(body)
                            // Invalid session cookie; so clear out session cookie and redirect CAS login
                            } else {
                                if let Ok(c) = cookie::Cookie::new(Some(cookie::CookiePrefix::HOST), "id", "", Some(self.key)) {
                                    self.cas.login_redirect(&self.service_url(&path)[..])
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
                        } else { 
                            // Session cookie was not found
                            match self.cas.verify_from_request(req.uri().query(), &self.service_url(&path)[..]) {
                                // If this was a redirect from CAS with token then verify and setup session cookie.
                                Ok(cas::ServiceResponse::Success(id)) => {
                                    if let Ok(c) = cookie::Cookie::new(Some(cookie::CookiePrefix::HOST), "id", &id[..], Some(self.key)) {
                                        // TODO: Content-Disposition header should be set for downloading videos
                                        // TODO: UI/File handler along with cookie set (NOTE: design handler to return response were we may add cookie)
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
                                    self.cas.login_redirect(&self.service_url(&path)[..])
                                }
                                Err(e) => {
                                    print!("[CAS VERIFY RESPONSE] {:?}\n", e);
                                    self.cas.login_redirect(&self.service_url(&path)[..])
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
