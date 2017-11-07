extern crate futures;
extern crate hyper;
extern crate rustls;
extern crate tokio_proto;
extern crate tokio_rustls;
extern crate ring;
extern crate base64;
extern crate percent_encoding;
#[macro_use] extern crate lazy_static;

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
use std::env;

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
        if let Ok(paths) = paths(req.path()) {
            futures::future::ok(
                match (req.method(), &(paths[0])[..]) {
                    // Health checks. TODO: Verify key files may be accessible
                    (&Get, "health") => {
                        Response::new()
                            .with_header(ContentType(mime::TEXT_PLAIN))
                            .with_header(ContentLength(INDEX.len() as u64))
                            .with_body(INDEX)
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
                    // route were single page application will be accessed.
                    (&Get, "/") | (&Get, "get_set_cookie") => {
                        if let Some(c) = cookie::Cookie::from_request(&req, Some(cookie::CookiePrefix::HOST), "id") {
                            // Cookie was found
                            let body = if let Ok(id) = c.get_value(Some(self.key)) {
                                "<!DOCTYPE html><html><head><meta charset=\"utf-8\" /><title>get cookie</title></head><body>id = ".to_string() + &id[..] + "</body>"
                            } else {
                                "<!DOCTYPE html><html><head><meta charset=\"utf-8\" /><title>get cookie</title></head><body>Error retrieving id cookie.</body>".to_string()
                            };
                            // TODO: Content-Disposition header should be set for downloading videos
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
        } else {
            futures::future::ok(Response::new().with_status(StatusCode::NotFound))
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
        let decoded = percent_encoding::percent_decode(segment.as_bytes())
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

//test MASTERKEY: sVdCPIwy2URfikVQiBH1Z+Jz39mibRG7viq42oYapTA=
lazy_static! {
    static ref COOKIE_KEY: Key = {
        let cookie_key_result = match env::var("MASTERKEY") {
           Ok(master_key) => Key::new(Some(&master_key[..])),
           Err(_) => Key::new(None),
        };
        if let Ok(cookie_key) = cookie_key_result {
            cookie_key
        } else {
            panic!("Issue generating cookie key.");
        }
    };
}

fn main() {
    let cookie_key = &COOKIE_KEY;
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
