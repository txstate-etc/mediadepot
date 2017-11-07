extern crate futures;
extern crate hyper;
extern crate rustls;
extern crate tokio_proto;
extern crate tokio_rustls;
extern crate ring;
extern crate base64;
extern crate percent_encoding;

mod key;
mod cookie;

use futures::future::FutureResult;
use hyper::header::{ContentLength, ContentType};
use hyper::mime;
use hyper::server::{Http, Service, Request, Response};
use hyper::{Get, StatusCode}; //Post
use tokio_rustls::proto;
use rustls::internal::pemfile;
use key::Key;

static INDEX: &'static [u8] = b"Service is up\n";

#[derive(Clone, Copy)]
struct Router<'a> {
    key: &'a Key,
}

impl<'a> Service for Router<'a> {
    type Request = Request;
    type Response = Response;
    type Error = hyper::Error;
    type Future = FutureResult<Response, hyper::Error>;

    fn call(&self, req: Request) -> Self::Future {
        futures::future::ok(
            match (req.method(), req.path()) {
                // Health checks. TODO: Verify key files may be accessible
                (&Get, "/health") => {
                    Response::new()
                        .with_header(ContentType(mime::TEXT_PLAIN))
                        .with_header(ContentLength(INDEX.len() as u64))
                        .with_body(INDEX)
                }
                (&Get, "/static") => {
                    // CSS and image resource files
                    let body = "<!DOCTYPE html><html><head><meta charset=\"utf-8\" /><title>files</title></head><body>This will be replaced with resource file headers and content</body>";
                    Response::new()
                        .with_header(ContentLength(body.len() as u64))
                        .with_body(body)
                }
                (&Get, "/logout") => {
                    if let Ok(c) = cookie::Cookie::new(Some(cookie::CookiePrefix::HOST), "id", "", Some(self.key)) {
                        let body = "<!DOCTYPE html><html><head><meta charset=\"utf-8\" /><title>clear cookie</title></head><body>Cleared id cookie.</body>";
                        Response::new()
                            .with_header(ContentLength(body.len() as u64))
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
                            .with_body(body)
                    } else {
                        let body = "<!DOCTYPE html><html><head><meta charset=\"utf-8\" /><title>clear cookie</title></head><body>Unable to clear id cookie.</body>";
                        Response::new()
                            .with_header(ContentLength(body.len() as u64))
                            .with_body(body)
                    }
                }
                (&Get, "/") | (&Get, "/get_set_cookie") => {
                    if let Some(c) = cookie::Cookie::from_request(&req, Some(cookie::CookiePrefix::HOST), "id") {
                        // Cookie was found
                        let body = if let Ok(id) = c.get_value(Some(self.key)) {
                            "<!DOCTYPE html><html><head><meta charset=\"utf-8\" /><title>get cookie</title></head><body>id = ".to_string() + &id[..] + "</body>"
                        } else {
                            "<!DOCTYPE html><html><head><meta charset=\"utf-8\" /><title>get cookie</title></head><body>Error retrieving id cookie.</body>".to_string()
                        };
                        Response::new()
                            .with_header(ContentLength(body.len() as u64))
                            .with_body(body)
                    } else { 
                        // No cookie was found
                        if let Ok(c) = cookie::Cookie::new(Some(cookie::CookiePrefix::HOST), "id", "test-id", Some(self.key)) {
                            let body = "<!DOCTYPE html><html><head><meta charset=\"utf-8\" /><title>set cookie</title></head><body>set id cookie.</body>";
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
                            let body = "<!DOCTYPE html><html><head><meta charset=\"utf-8\" /><title>set cookie</title></head><body>Unable to set id cookie.</body>";
                            Response::new()
                                .with_header(ContentLength(body.len() as u64))
                                .with_body(body)
                        }
                    }
                }
                _ => Response::new().with_status(StatusCode::NotFound),
            }
        )
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
/// percent decoded path segments.
fn paths(path: &str) -> Result<Vec<String>, &'static str> {
    let mut paths = Vec::new();
    let segments = path.split("/");
    for segment in segments {
        let decoded = percent_encoding::percent_decode(segment.as_bytes())
            .decode_utf8()
            .map_err(|_| "Invalid percent decoded value in path.")?;
        if decoded == ".." {
            paths.pop();
        } else if decoded.starts_with('.') {
            return Err("Path contains hidden directory.")
        } else if decoded.contains(not_whitelist_char) {
            return Err("Path contains a non-whitelisted character.")
        } else {
            paths.push(decoded.to_string());
        }
    }
    Ok(paths)
}


fn load_certs(filename: &str) -> Vec<rustls::Certificate> {
    let certfile = std::fs::File::open(filename).expect("cannot open certificate file");
    let mut reader = std::io::BufReader::new(certfile);
    pemfile::certs(&mut reader).unwrap()
}

fn load_private_key(filename: &str) -> rustls::PrivateKey {
    let keyfile = std::fs::File::open(filename).expect("cannot open private key file");
    let mut reader = std::io::BufReader::new(keyfile);
    let keys = pemfile::rsa_private_keys(&mut reader).unwrap();
    assert!(keys.len() == 1);
    keys[0].clone()
}

static mut COOKIE_KEY_OPTION: Option<Key> = None;

fn main() {
    let master_key = "sVdCPIwy2URfikVQiBH1Z+Jz39mibRG7viq42oYapTA=";
    let cookie_key = unsafe {
        COOKIE_KEY_OPTION = Some(Key::new(Some(master_key)).unwrap());
        if let Some(ref cookie_key) = COOKIE_KEY_OPTION {
            cookie_key
        } else {
            panic!("Was not able to get cookie key");
        }
    };
    let router = Router{key: cookie_key};
    let port = match std::env::args().nth(1) {
        Some(ref p) => p.to_owned(),
        None => "8443".to_owned(),
    };
    let addr = format!("127.0.0.1:{}", port).parse().unwrap();
    let certs = load_certs("private/local.pem");
    let certs_key = load_private_key("private/local.key.pem");
    let mut cfg = rustls::ServerConfig::new();
    cfg.set_single_cert(certs, certs_key);
    let tls = proto::Server::new(Http::new(), std::sync::Arc::new(cfg));
    let tcp = tokio_proto::TcpServer::new(tls, addr);
    println!("Starting to serve on https://{}.", addr);
    tcp.serve(move || Ok(router));
}
