use futures::future;
use tokio_core::reactor::Handle;
use hyper::header::{ContentLength, ContentType, Location, CacheControl, CacheDirective, qitem, Server, StrictTransportSecurity};
use hyper::server::{Service, Request, Response};
use hyper::{Method, Head, Get, Post, Delete, StatusCode, Uri, mime, header};
use hyper;
use key::Key;
use percent_encoding::{percent_decode, utf8_percent_encode, DEFAULT_ENCODE_SET};
use std::fs;
use serde_json;
use chrono::prelude::{DateTime, Local};
use tera;
use cookie;
use cas;
use files;
use jwt;
use context::Context;

// Basic utilities

// Used for proctor access on behalf of id
#[derive(Debug, Deserialize)]
struct User {
    proctor: String,
    id: String,
    //exp: time,
}

#[derive(Serialize, Debug)]
struct Media {
    name: String,
    path: String,
    date: String,
    size: u64,
    //thumbnails: Vec<String>,
}

// Generate a list of media files and their attributes for path under root
fn media(root: &str, path: &str) -> Result<Vec<Media>, &'static str> {
    let base = root.to_string() + "/" + path;
    let metadata = fs::metadata(&*base).map_err(|_| "Unable to stat file or directory")?;

    if metadata.is_dir() {
        match fs::read_dir(&*base) {
            Err(_) => Err("Unable to access directory"),
            Ok(files) => {
                let mut media: Vec<Media> = Vec::new();
                for file in files {
                    if let Ok(file) = file {
                        if let Ok(filename) = file.file_name().into_string() {
                            if filename.ends_with(".m4v") {
                                if let Ok(metadata) = file.metadata() {
                                    if let Ok(modified) = metadata.modified() {
                                        let dt = DateTime::<Local>::from(modified);
                                        media.push(Media{
                                            path: path.to_string() + "/" + &filename[..],
                                            name: filename,
                                            date: dt.format("%Y-%m-%d").to_string(),
                                            size: metadata.len(),
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
                Ok(media)
            },
        }
    } else {
        Err("Invalid location")
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

fn with_mime(req: &Request, m: mime::Mime) -> bool {
    if let Some(accept) = req.headers().get::<header::Accept>() {
        for a in &accept.0 {
            if *a == qitem(m.clone()) {
                return true;
            }
        }
    }
    false
}


// Handlers
////https://stackoverflow.com/questions/41179659/convert-vecstring-into-a-slice-of-str-in-rust

// Router

type RouterFuture = future::FutureResult<Response, hyper::Error>;

#[derive(Clone)]
pub struct Router<'a> {
    handle: Handle,
    dir_www: &'a str,
    jwt: &'a [u8],
    key: &'a Key,
    domain: &'a Uri,
    server: &'a str,
    sts: u64,
    cas: &'a cas::CasClient,
    templates: &'a tera::Tera,
}

impl<'a> Router<'a> {
    pub fn new(handle: Handle,
        dir_www: &'a str,
        jwt_key: &'a [u8],
        cookie_key: &'a Key,
        domain: &'a Uri,
        server: &'a str,
        sts: u64,
        cas_client: &'a cas::CasClient,
        templates: &'a tera::Tera) -> Router<'a> {
        Router{
            handle: handle,
            dir_www: dir_www,
            jwt: jwt_key,
            key: cookie_key,
            domain: domain,
            server: server,
            sts: sts,
            cas: cas_client,
            templates: templates
        }
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

    // If path is to library directory with media files insert vcms/<id> as part of path vector
    fn serve_library_file(&self, context: Context, res: Response, path: &Vec<String>) -> RouterFuture {
        let mut path = path.clone();
        path.insert(0, context.id.as_ref().unwrap().clone());
        path.insert(0, "vcms".to_string());
        self.serve_file(context, res, &path)
    }

    fn serve_file(&self, mut context: Context, res: Response, path: &Vec<String>) -> RouterFuture {
        let path = self.dir_www.to_string() + "/" + &*path.join("/");
        let modified = if let Some(&header::IfModifiedSince(ref value)) = context.req.headers().get() {
            Some(value.clone())
        } else {
            None
        };
        match context.req.method() {
            &Method::Head | &Method::Get => files::serve(context, self.handle.clone(), modified, &*path, res),
            //&Method::Delete => future::ok(res.with_status(StatusCode::MethodNotAllowed)),
            _ => {
                context.status_code = StatusCode::MethodNotAllowed;
                print!("{:?}, ERROR: Invalid request method.\n", context);
                future::ok(res.with_status(StatusCode::MethodNotAllowed))
            },
        }
    }

    fn get_media(&self, id: &str) -> Result<Vec<Media>, &'static str> {
        let root = self.dir_www.to_string() + "/vcms/" + id;
        media(&root[..], "library")
    }

    // Id should be set
    fn protected_content(&self, mut context: Context, parent: &str, path: &Vec<String>) -> RouterFuture {
        // File handler
        if parent == "library" {
            self.serve_library_file(context, Response::new(), &path)
        } else {
            // UI/JSON handler
            if let Ok(media) = self.get_media(&context.id.as_ref().unwrap()[..]) {
                let body: String;
                let mut res = Response::new()
                    .with_header(Server::new(self.server.to_string()))
                    .with_header(StrictTransportSecurity::including_subdomains(self.sts));
                // JSON
                if with_mime(&context.req, mime::APPLICATION_JSON) {
                    body = serde_json::to_string(&media).unwrap();
                    res = res.with_header(ContentType(mime::APPLICATION_JSON));
                // Template
                } else {
                    let mut tera_context = tera::Context::new();
                    tera_context.add("media", &media);
                    body = match self.templates.render("index.html", &tera_context) {
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
                print!("{:?}\n", context);
                future::ok(res.with_header(ContentLength(body.len() as u64))
                    .with_body(body))
            // User does not contain a directory structure such as <id>/library
            } else {
                context.status_code = StatusCode::InternalServerError;
                print!("{:?}, ERROR: No library directory for user.\n", context);
                let mut tera_context = tera::Context::new();
                tera_context.add("error", &"Unable to find a media library");
                let body = match self.templates.render("error.html", &tera_context) {
                    Ok(s) => s,
                    Err(e) => {
                        println!("Error: {}", e);
                        for e in e.iter().skip(1) {
                            println!("Reason: {}", e);
                        }
                        "error".to_string()
                    },
                };
                future::ok(Response::new()
                    .with_header(Server::new(self.server.to_string()))
                    .with_header(StrictTransportSecurity::including_subdomains(self.sts))
                    .with_status(StatusCode::InternalServerError)
                    .with_header(ContentLength(body.len() as u64))
                    .with_body(body))
            }
        }
    }

    fn admin_content(&self, mut context: Context, parent: &str, path: &Vec<String>) -> RouterFuture {
        // TODO: implement JWT check and IP check
        // Admin gets id from JWT https://github.com/Keats/jsonwebtoken
        //    https://github.com/Keats/jsonwebtoken/blob/master/examples/custom_header.rs
        // Generate it from http://search.cpan.org/~mik/Crypt-JWT-0.010/lib/Crypt/JWT.pm
        //    And setup header https://alvinalexander.com/perl/edu/articles/pl010012
        let mut auth = None;
        if let Some(some_auth) = context.req.headers().get::<header::Authorization<header::Bearer>>() {
            auth = Some(some_auth.clone())
        }
        if let Some(auth) = auth {
            match jwt::decode::<User>(&auth.token, self.jwt.as_ref(), &jwt::Validation::new(jwt::Algorithm::HS512)) {
                Ok(user) => {
                    context.proctor = Some(user.claims.proctor);
                    context.id = Some(user.claims.id);
                    return self.protected_content(context, parent, path);
                },
                Err(e) => {
                    context.status_code = StatusCode::Forbidden;
                    print!("{:?}, ERROR: {:?}\n", context, e);
                },
            }
        }
        future::ok(Response::new()
            .with_header(Server::new(self.server.to_string()))
            .with_status(StatusCode::Forbidden))
    }

    fn user_content(&self, mut context: Context, parent: &str, path: &Vec<String>) -> RouterFuture {
        // User gets id from cookie
        if let Some(c) = cookie::Cookie::from_request(&context.req, Some(cookie::CookiePrefix::HOST), "id") {
            // Session cookie found (get ID)
            // Valid session cookie so manage request
            if let Ok(id) = c.get_value(Some(self.key)) {
                 context.id = Some(id);
                 self.protected_content(context, parent, path)
            // Invalid session cookie; so clear out session cookie and redirect CAS login
            } else {
                if let Ok(c) = cookie::Cookie::new(Some(cookie::CookiePrefix::HOST), "id", "", Some(self.key)) {
                    context.status_code = StatusCode::Found;
                    print!("{:?}, ERROR: Invalid session cookie.\n", context);
                    future::ok(self.cas.login_redirect(&self.service_url(&path)[..])
                        .with_header(Server::new(self.server.to_string()))
                        .with_header(StrictTransportSecurity::including_subdomains(self.sts))
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
                    context.status_code = StatusCode::InternalServerError;
                    print!("{:?}, ERROR: Unable to create clear cookie.\n", context);
                    let mut tera_context = tera::Context::new();
                    tera_context.add("error", &"Unable to clear session in attempt to retry login");
                    let body = match self.templates.render("error.html", &tera_context) {
                        Ok(s) => s,
                        Err(e) => {
                            println!("Error: {}", e);
                            for e in e.iter().skip(1) {
                                println!("Reason: {}", e);
                            }
                            "error".to_string()
                        },
                    };
                    future::ok(Response::new()
                        .with_header(Server::new(self.server.to_string()))
                        .with_header(StrictTransportSecurity::including_subdomains(self.sts))
                        .with_status(StatusCode::InternalServerError)
                        .with_header(ContentLength(body.len() as u64))
                        .with_body(body))
                }
            }
        } else {
            // Session cookie was not found
            match self.cas.verify_from_request(context.req.uri().query(), &self.service_url(&path)[..]) {
                // If this was a redirect from CAS with token then verify and setup session cookie.
                Ok(cas::ServiceResponse::Success(id)) => {
                    context.id = Some(id);
                    // Add session cookie with id and redirect to original page
                    // Do not include CAS ticket query
                    if let Ok(c) = cookie::Cookie::new(Some(cookie::CookiePrefix::HOST), "id", &(context.id.as_ref().unwrap())[..], Some(self.key)) {
                        context.status_code = StatusCode::Found;
                        print!("{:?}, Success: Redirect CAS redirect to original page.\n", context);
                        let path_url = "/".to_string() + &*path.join("/");
                        future::ok(Response::new()
                            .with_header(Server::new(self.server.to_string()))
                            .with_header(StrictTransportSecurity::including_subdomains(self.sts))
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
                        context.status_code = StatusCode::InternalServerError;
                        print!("{:?}, ERROR: Unable to set session.\n", context);
                        let mut tera_context = tera::Context::new();
                        tera_context.add("error", &"Unable to set session");
                        let body = match self.templates.render("error.html", &tera_context) {
                            Ok(s) => s,
                            Err(e) => {
                                println!("Error: {}", e);
                                for e in e.iter().skip(1) {
                                    println!("Reason: {}", e);
                                }
                                "error".to_string()
                            },
                        };
                        future::ok(Response::new()
                            .with_header(Server::new(self.server.to_string()))
                            .with_header(StrictTransportSecurity::including_subdomains(self.sts))
                            .with_status(StatusCode::InternalServerError)
                            .with_header(ContentLength(body.len() as u64))
                            .with_body(body))
                    }
                },
                // If not a redirect from CAS, or Ticket error, then redirect to CAS (Make sure not to run into infinite loop)
                Ok(cas::ServiceResponse::Failure(e)) => {
                    context.status_code = StatusCode::Found;
                    print!("{:?}, CAS: {:?}\n", context, e);
                    future::ok(self.cas.login_redirect(&self.service_url(&path)[..])
                        .with_header(Server::new(self.server.to_string()))
                        .with_header(StrictTransportSecurity::including_subdomains(self.sts))
                    )
                }
                Err(e) => {
                    context.status_code = StatusCode::Found;
                    print!("{:?}, CAS: {:?}\n", context, e);
                    future::ok(self.cas.login_redirect(&self.service_url(&path)[..])
                        .with_header(Server::new(self.server.to_string()))
                        .with_header(StrictTransportSecurity::including_subdomains(self.sts))
                    )
                }
            }
        }
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
        let mut context = Context{
            proctor: None,
            id: None,
            status_code: StatusCode::Ok,
            req: req,
        };
        if let Ok(path) = normalize_req_path(context.req.path()) {
            let mut parent = "";
            if path.len() > 0 {
                parent = &path[0][..];
            }
            match (context.req.method(), parent) {
                // Health checks.
                //   TODO: Verify vcms directory with faculty and student video files may be accessible
                //   TODO: Return back total number of files served and currently serving.
                (&Get, "health") | (&Head, "health") => {
                    print!("{:?}\n", context);
                    let body: &'static [u8] = b"Up";
                    let mut res = Response::new()
                        .with_header(Server::new(self.server.to_string()))
                        .with_header(StrictTransportSecurity::including_subdomains(self.sts))
                        .with_header(ContentType(mime::TEXT_PLAIN))
                        .with_header(ContentLength(body.len() as u64));
                    if context.req.method() == &Get { 
                        res.set_body(body);
                    }
                    future::ok(res)
                },
                // CSS and image resource files
                (&Get, "static") | (&Head, "static") | (&Get, "favicon.ico") | (&Head, "favicon.ico") => {
                    if parent == "favicon.ico" {
                        self.serve_file(context, Response::new(), &vec!["static".to_string(), "images".to_string(), "favicon.ico".to_string()])
                    } else {
                        self.serve_file(context, Response::new(), &path)
                    }
                },
                // Allow to logout without checking if logged in; so if a valid CAS user (authentication)
                // does NOT have access (authorization) to access any routes, the user can still log out.
                (&Get, "logout") => {
                    if let Ok(c) = cookie::Cookie::new(Some(cookie::CookiePrefix::HOST), "id", "", Some(self.key)) {
                        context.status_code = StatusCode::Found;
                        print!("{:?}\n", context);
                        future::ok(self.cas.logout_redirect(&self.service_url(&vec!["/".to_string()]))
                            .with_header(Server::new(self.server.to_string()))
                            .with_header(StrictTransportSecurity::including_subdomains(self.sts))
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
                        context.status_code = StatusCode::InternalServerError;
                        print!("{:?}\n", context);
                        let mut tera_context = tera::Context::new();
                        tera_context.add("error", &"Unable to clear session");
                        let body = match self.templates.render("error.html", &tera_context) {
                            Ok(s) => s,
                            Err(e) => {
                                println!("Error: {}", e);
                                for e in e.iter().skip(1) {
                                    println!("Reason: {}", e);
                                }
                                "error".to_string()
                            },
                        };
                        future::ok(Response::new()
                            .with_status(StatusCode::InternalServerError)
                            .with_header(ContentLength(body.len() as u64))
                            .with_body(body))
                    }
                },
                // The following Route/Path of single page application may only be accessed via
                //   an authenticated netid from CAS infrastructure or authorization signature via Whiskers admin tool.
                (&Get, "") | (&Get, "library") | (&Head, "library") | (&Delete, "library") => self.user_content(context, parent, &path),
                // Admin JWT Requests
                (&Get, "admin") | (&Head, "admin") | (&Delete, "admin") => {
                    let mut parent = "".to_string();
                    let mut sub_path = Vec::new();
                    if path.len() > 1 {
                        parent = path[1].clone();
                        sub_path = path[1..].to_vec();
                    }
                    self.admin_content(context, &parent[..], &sub_path)
                },
                // Generally CAS server announcements of SSO logouts
                (&Post, _) => {
                    print!("{:?}\n", context);
                    future::ok(Response::new())
                },
                _ => {
                    context.status_code = StatusCode::NotFound;
                    print!("{:?}\n", context);
                    future::ok(Response::new()
                         .with_status(StatusCode::NotFound)
                         .with_header(Server::new(self.server.to_string()))
                         .with_header(StrictTransportSecurity::including_subdomains(self.sts))
                    )
                },
            }
        } else {
            context.status_code = StatusCode::NotFound;
            print!("{:?}\n", context);
            future::ok(Response::new()
                .with_status(StatusCode::NotFound)
                .with_header(Server::new(self.server.to_string()))
                .with_header(StrictTransportSecurity::including_subdomains(self.sts))
            )
        }
    }
}
