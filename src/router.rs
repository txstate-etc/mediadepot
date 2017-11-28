use futures::future;
use tokio_core::reactor::Handle;
use hyper::header::{ContentLength, ContentType, Location, CacheControl, CacheDirective, qitem};
use hyper::server::{Service, Request, Response};
use hyper::{Method, Head, Get, Post, Delete, StatusCode, Uri, mime, header};
use hyper;
use key::Key;
use percent_encoding::{percent_decode, utf8_percent_encode, DEFAULT_ENCODE_SET};
use std::fs;
use serde_json;
use chrono::prelude::{DateTime, Local};
use tera::{Tera, Context};
use cookie;
use cas;
use files;


// Basic utilities

#[derive(Serialize, Debug)]
enum MediaStore {
    File { name: String, date: String, size: u64 },
    Dir { name: String, entries: Vec<MediaStore> },
}

fn mediastore(root: &str, name: &str) -> Result<MediaStore, &'static str>  {
    let path = root.to_string() + "/" + name;
    let metadata = fs::metadata(&*path).map_err(|_| "Unable to stat file or directory")?;
    if metadata.is_file() {
        if let Ok(modified) = metadata.modified() {
            let dt = DateTime::<Local>::from(modified); // Add three weeks? + Duration::new(21 * 24 * 60 * 60, 0);
            Ok(MediaStore::File{name: name.to_string(), date: dt.format("%Y-%m-%d").to_string(), size: metadata.len()})
        } else {
            Err("Unable to access file modified time")
        }
    } else if metadata.is_dir() {
        match fs::read_dir(&*path) {
            Err(_) => Err("Unable to access directory"),
            Ok(files) => {
                let mut entries: Vec<MediaStore> = Vec::new();
                for file in files {
                    if let Ok(file) = file {
                        if let Ok(filename) = file.file_name().into_string() {
                            // Skip hidden files and directories
                            if !filename.starts_with(".") {
                                if let Ok(entry) = mediastore(&path[..], &filename[..]) {
                                    entries.push(entry);
                                }
                            }
                        }
                    }
                }
                Ok(MediaStore::Dir{name: name.to_string(), entries: entries})
            },
        }
    } else {
        Err("Unsupported entry type.")
    }
}

#[derive(Serialize, Debug)]
struct Media {
    name: String,
    path: String,
    date: String,
    size: u64,
    thumbnails: Vec<String>,
}

fn media(media_store: Result<MediaStore, &'static str>) -> Result<Vec<Media>, &'static str> {
    let media_store = media_store?;
    let media_list = match media_store {
        MediaStore::Dir{name, entries} => {
            let mut ms = Vec::new();
            let path = name;
            for e in entries {
                match e {
                    MediaStore::Dir{name, entries} => {
                        let path = path.clone() + "/" + &name[..];
                        let mut media_flag = false;
                        let mut media_info = Media{
                            name: "".to_string(),
                            path: "".to_string(),
                            date: "".to_string(),
                            size: 0,
                            thumbnails: Vec::new(),
                        };
                        for e in entries {
                            match e {
                                MediaStore::File{name, date, size} => {
                                    if name.ends_with(".m4v") {
                                        media_flag = true;
                                        media_info.path = path.clone() + "/" + &name[..];
                                        media_info.name = name;
                                        media_info.date = date;
                                        media_info.size = size;
                                    }
                                },
                                MediaStore::Dir{name, entries} => {
                                    if name == "thumbnails" {
                                        for e in entries {
                                            match e {
                                                MediaStore::File{name, date: _, size: _} => {
                                                    if name.ends_with(".jpg") {
                                                        media_info.thumbnails.push(path.clone() + "/thumbnails/" + &name[..])
                                                    }
                                                },
                                                _ => (),
                                            }
                                        }
                                    }
                                },
                            }
                        }
                        if media_flag {
                            ms.push(media_info)
                        }
                    },
                    _ => (),
                }
            }
            ms
        },
        _ => Vec::new(),
    };
    Ok(media_list)
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
fn normalize_req_path(path: &str) -> Result<Vec<String>, &'static str> {
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

// Router

type RouterFuture = future::FutureResult<Response, hyper::Error>;

#[derive(Clone)]
pub struct Router<'a> {
    handle: Handle,
    dir_www: &'a str,
    key: &'a Key,
    domain: &'a Uri,
    cas: &'a cas::CasClient,
    templates: &'a Tera,
}

impl<'a> Router<'a> {
    pub fn new(handle: Handle, dir_www: &'a str, cookie_key: &'a Key, domain: &'a Uri, cas_client: &'a cas::CasClient, templates: &'a Tera) -> Router<'a> {
        Router{handle: handle, dir_www: dir_www, key: cookie_key, domain: domain, cas: cas_client, templates: templates}
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

    // If path is to student directory insert id in path vector
    fn manage_file(&self, req: Request, res: Response, path: &Vec<String>) -> RouterFuture {
        let path = self.dir_www.to_string() + "/" + &*path.join("/");
        let modified = if let Some(&header::IfModifiedSince(ref value)) = req.headers().get() {
            Some(value)
        } else {
            None
        };
        match req.method() {
            &Method::Head => files::serve(self.handle.clone(), true, modified, &*path, res),
            &Method::Get => files::serve(self.handle.clone(), false, modified, &*path, res),
            &Method::Delete => future::ok(res.with_status(StatusCode::MethodNotAllowed)),
            _ => future::ok(res.with_status(StatusCode::MethodNotAllowed)),
        }
    }

    fn get_media(&self, id: &str) -> Result<Vec<Media>, &'static str> {
         let path = self.dir_www.to_string() + "/vcms/" + id;
         media(mediastore(&path[..], "library"))
    }
}


impl<'a> Service for Router<'a> {
    type Request = Request;
    type Response = Response;
    type Error = hyper::Error;
    type Future = RouterFuture;

    fn call(&self, req: Request) -> Self::Future {
        //https://tokio-rs.github.io/tokio-middleware/src/tokio_middleware/log.rs.html
        //https://doc.rust-lang.org/log/env_logger/
        print!("[REQUEST] {:?}\n", req);
        if let Ok(path) = normalize_req_path(req.path()) {
            let mut parent = "";
            if path.len() > 0 {
                parent = &path[0][..];
            }
            let mut accept_json = false;
            if let Some(accept) = req.headers().get::<header::Accept>() {
                for a in &accept.0 {
                    if *a == qitem(mime::APPLICATION_JSON) {
                        accept_json = true;
                    }
                }
            }
            match (req.method(), parent) {
                // Health checks.
                //   TODO: Verify vcms directory with faculty and student video files may be accessible
                //   TODO: Return back total number of files served and currently serving.
                (&Get, "health") | (&Head, "health") => {
                    let body: &'static [u8] = b"Up";
                    let mut res = Response::new()
                        .with_header(ContentType(mime::TEXT_PLAIN))
                        .with_header(ContentLength(body.len() as u64));
                    if req.method() == &Get { 
                        res.set_body(body);
                    }
                    future::ok(res)
                }
                // CSS and image resource files
                (&Get, "static") | (&Head, "static") => {
                    self.manage_file(req, Response::new(), &path)
                }
                // Allow to logout without checking if logged in; so if a valid CAS user (authentication)
                // does NOT have access (authorization) to access any routes, the user can still log out.
                (&Get, "logout") => {
                    if let Ok(c) = cookie::Cookie::new(Some(cookie::CookiePrefix::HOST), "id", "", Some(self.key)) {
                        future::ok(self.cas.logout_redirect(&self.service_url(&vec!["/".to_string()]))
                            .with_header(
                                hyper::header::SetCookie(vec![
                                    c.with_path(Some("/"))
                                        .clear()
                                        .with_secure(true)
                                        .with_http_only(true)
                                        .with_same_site(Some(cookie::SameSite::LAX))
                                        .get_full_value()
                                ])
                            ))
                    } else {
                        let body = "<!DOCTYPE html><html><head><meta charset=\"utf-8\" /><title>500 logout - clear session error</title></head><body>Unable to clear session.</body>";
                        future::ok(Response::new()
                            .with_status(StatusCode::InternalServerError)
                            .with_header(ContentLength(body.len() as u64))
                            .with_body(body))
                    }
                }
                // CAS infrastructure
                // Route/Path were single page application will be accessed.
                (&Get, "") | (&Get, "library") | (&Head, "library") | (&Delete, "library") => {
                    if let Some(c) = cookie::Cookie::from_request(&req, Some(cookie::CookiePrefix::HOST), "id") {
                        // Session cookie found (get ID)
                        // Valid session cookie so manage request
                        if let Ok(id) = c.get_value(Some(self.key)) {
                            // File handler
                            if parent == "library" {
                                let mut path_files = path.clone();
                                path_files.insert(0, id);
                                path_files.insert(0, "vcms".to_string());
                                self.manage_file(req, Response::new(), &path_files)
                            } else {
                                // UI/JSON handler
                                if let Ok(media) = self.get_media(&id[..]) {
                                    let body: String;
                                    let mut res = Response::new();
                                    // JSON
                                    if accept_json {
                                        body = serde_json::to_string(&media).unwrap();
                                        res = res.with_header(ContentType(mime::APPLICATION_JSON));
                                    // Template
                                    } else {
                                        let mut context = Context::new();
                                        context.add("media", &media);
                                        body = match self.templates.render("index.html", &context) {
                                            Ok(s) => s,
                                            Err(e) => {
                                                println!("Error: {}", e);
                                                for e in e.iter().skip(1) {
                                                    println!("Reason: {}", e);
                                                }
                                                "error".to_string()
                                            },
                                        };
                                        res = res.with_header(ContentType(mime::TEXT_HTML_UTF_8));
                                    }
                                    future::ok(res.with_header(ContentLength(body.len() as u64))
                                        .with_body(body))
                                } else {
                                    let body = "<!DOCTYPE html><html><head><meta charset=\"utf-8\" /><title>Error</title></head><body>Unable to retrieve contents for ".to_string() + &id[..] + " id.</body>";
                                    future::ok(Response::new()
                                        .with_status(StatusCode::InternalServerError)
                                        .with_header(ContentLength(body.len() as u64))
                                        .with_body(body))
                                }
                            }
                        // Invalid session cookie; so clear out session cookie and redirect CAS login
                        } else {
                            if let Ok(c) = cookie::Cookie::new(Some(cookie::CookiePrefix::HOST), "id", "", Some(self.key)) {
                                future::ok(self.cas.login_redirect(&self.service_url(&path)[..])
                                    .with_header(
                                        hyper::header::SetCookie(vec![
                                            c.with_path(Some("/"))
                                                .clear()
                                                .with_secure(true)
                                                .with_http_only(true)
                                                .with_same_site(Some(cookie::SameSite::LAX))
                                                .get_full_value()
                                        ])
                                    ))
                            // ERROR: Unable to create clear cookie
                            } else {
                                let body = "<!DOCTYPE html><html><head><meta charset=\"utf-8\" /><title>500 login retry - clear session error</title></head><body>Unable to clear session in attempt to retry login.</body>";
                                future::ok(Response::new()
                                    .with_status(StatusCode::InternalServerError)
                                    .with_header(ContentLength(body.len() as u64))
                                    .with_body(body))
                            }
                        }
                    } else {
                        // Session cookie was not found
                        match self.cas.verify_from_request(req.uri().query(), &self.service_url(&path)[..]) {
                            // If this was a redirect from CAS with token then verify and setup session cookie.
                            Ok(cas::ServiceResponse::Success(id)) => {
                                // Add session cookie with id and redirect to original page
                                // Do not include CAS ticket query
                                if let Ok(c) = cookie::Cookie::new(Some(cookie::CookiePrefix::HOST), "id", &id[..], Some(self.key)) {
                                    let path_url = "/".to_string() + &*path.join("/");
                                    future::ok(Response::new()
                                        .with_status(StatusCode::Found)
                                        .with_header(Location::new(path_url))
                                        .with_header(CacheControl(vec![CacheDirective::NoCache]))
                                        .with_header(
                                            hyper::header::SetCookie(vec![
                                                c.with_path(Some("/"))
                                                    .with_secure(true)
                                                    .with_http_only(true)
                                                    .with_same_site(Some(cookie::SameSite::LAX))
                                                    .get_full_value()
                                            ])
                                        ))
                                // ERROR: unable to set session
                                } else {
                                    let body = "<!DOCTYPE html><html><head><meta charset=\"utf-8\" /><title>500 login - set session error</title></head><body>Unable to set session.</body>";
                                    future::ok(Response::new()
                                        .with_status(StatusCode::InternalServerError)
                                        .with_header(ContentLength(body.len() as u64))
                                        .with_body(body))
                                }
                            },
                            // If not a redirect from CAS, or Ticket error, then redirect to CAS (Make sure not to run into infinite loop)
                            Ok(cas::ServiceResponse::Failure(e)) => {
                                print!("[CAS VERIFY RESPONSE] {:?}\n", e);
                                future::ok(self.cas.login_redirect(&self.service_url(&path)[..]))
                            }
                            Err(e) => {
                                print!("[CAS VERIFY RESPONSE] {:?}\n", e);
                                future::ok(self.cas.login_redirect(&self.service_url(&path)[..]))
                            }
                        }
                    }
                }
                // Generally CAS server announcements of SSO logouts
                (&Post, _) => {
                   print!("[REQUEST] {:?}", req);
                   future::ok(Response::new())
                }
                _ => future::ok(Response::new().with_status(StatusCode::NotFound)),
            }
        } else {
            future::ok(Response::new().with_status(StatusCode::NotFound))
        }
    }
}
