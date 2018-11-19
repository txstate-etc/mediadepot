#![feature(await_macro, async_await, futures_api, custom_attribute, proc_macro_hygiene, extern_crate_item_prelude, impl_trait_in_bindings)]

#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate tower_web;
extern crate tokio;
extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;
extern crate hyper;
extern crate hyper_rustls;
extern crate maud;
extern crate chrono;
extern crate humansize;
extern crate percent_encoding;
extern crate jsonwebtoken as jwt;
extern crate xml;
extern crate tokio_io;
extern crate bytes;
extern crate env_logger;

mod templates;
mod auth;
mod cas;

use futures::{ Future, Stream };
use tokio::prelude::*;
use tokio::{ await, net::TcpListener };
use tower_web::{ ServiceBuilder, error::Error, middleware::log::LogMiddleware };
use http;
use std::{env, str, io, path::PathBuf};
use tokio::fs::{ File, metadata, read_dir };
use hyper::{ Uri, Body };
use hyper_rustls::HttpsConnector;
use chrono::{ DateTime, Local, NaiveDate, Duration };
use humansize::{ FileSize, file_size_opts} ;
use maud::{ html, Markup };
use self::cas::{ CASResponse, CAS_URL, CASError };
use self::auth::Auth;
use percent_encoding::{ utf8_percent_encode, DEFAULT_ENCODE_SET };
use std::net::SocketAddr;
use std::io::BufReader;
use std::sync::Arc;
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        Certificate, NoClientAuth, PrivateKey, ServerConfig,
        internal::pemfile::{ certs, rsa_private_keys },
    },
};

lazy_static! {
    static ref CERTS: Certs = Certs{
        public: env::var("CERTS_PUBLIC").expect("CERTS_PUBLIC environment variable is required").into(),
        private: env::var("CERTS_PRIVATE").expect("CERTS_PRIVATE environment variable is required").into(),
    };
}
struct Certs {
    public: String,
    private: String,
}

fn load_certs(path: &str) -> Vec<Certificate> {
    certs(&mut BufReader::new(std::fs::File::open(path).unwrap())).unwrap()
}

fn load_private_keys(path: &str) -> Vec<PrivateKey> {
    rsa_private_keys(&mut BufReader::new(std::fs::File::open(path).unwrap())).unwrap()
}

// https://github.com/abonander/mime_guess/blob/master/src/mime_types.rs
const FAVICON: &'static str = "static/ico/favicon.ico";

// Example: ROOTDIR=/var/lib/www
lazy_static! {
    static ref ROOT_DIR: PathBuf = match env::var("ROOTDIR") {
        Ok(root_dir) => root_dir.into(),
        Err(_) => "/var/lib/www".to_string().into(),
    };
}

// Example: DOMAIN=https://mediadepot.its.txstate.edu
lazy_static! {
    static ref DOMAIN: String = env::var("DOMAIN").expect("DOMAIN environment variable is required").into();
}

#[derive(Debug, Response)]
#[web(status = "302")]
struct Redirect {
    #[web(header)]
    set_cookie: String,
    #[web(header)]
    location: String,
}

#[derive(Serialize, PartialEq, PartialOrd, Eq, Ord, Debug)]
struct Media {
    date: String, //YYYY-mm-dd 
    name: String,
    size: u64,
    path: String,
}

fn file_date_add(date: &str, days: u64) -> String {
        match NaiveDate::parse_from_str(&date[0..10], "%Y-%m-%d") {
        Ok(d) => {
            let later_date = d.checked_add_signed(Duration::days(days as i64)).unwrap();
            later_date.format("%b %e, %Y").to_string()
        },
        Err(_) => "".to_string(),
    }
}

fn content(library: Vec<Media>) -> Markup {
    html! {
        div.container.main-content {
            h1.sr-only { "Download Your YouStar Files" }
            div.purge-warning.alert.alert-primary role="alert" {
                i.fa.fa-exclamation-circle { }
                " Videos will be permanently deleted after 3 weeks."
            }
            @if library.len() > 0 {
                table.table {
                    thead {
                        tr {
                            th scope="col" { "Name" }
                            th scope="col" { "File Size" }
                            th scope="col" { "Created" }
                            th scope="col" { "Available Until" }
                            th {
                                p.sr-only { "Video Actions" }
                            } // th
                        } // tr
                    } // thead
                    tbody {

                        @for media in &library {

                            tr {
                                td {
                                    div.carded-label { "File Name: " }
                                    (media.name)
                                }
                                td {
                                    div.carded-label { "File Size: " }
                                    (format!("{}", media.size.file_size(file_size_opts::CONVENTIONAL).unwrap()))
                                }
                                td {
                                    div.carded-label { "Created: " }
                                    (file_date_add(&media.date, 0))
                                }
                                td {
                                    div.carded-label { "Available Until: " }
                                    (file_date_add(&media.date, 21))
                                }
                                td {
                                    a.download-link href=(media.path) {
                                        span { "Download" } i.fa.fa-cloud-download aria-hidden="true" { }
                                    }
                                }
                            }

                        }

                    } // </tbody>
                } // </table>

            } @else {
                div.no-content { "No content available." }
            }
        }
    }
}

async fn media(path: PathBuf) -> Vec<Media> {
    let mut library = Vec::new();
    if let Ok(mut dir) = await!(read_dir(path.clone())) {
        while let Some(Ok(entry)) = await!(dir.next()) {
            if let Ok(filename) = entry.file_name().into_string() {
                if filename.ends_with(".m4v") {
                    let mut path = path.clone();
                    path.push(filename.clone());
                    if let Ok(md) = await!(metadata(path)) {
                        if let Ok(modified) = md.modified() {
                            let dt = DateTime::<Local>::from(modified);
                            library.push(Media{
                                path: "library/".to_string() + &filename[..],
                                date: dt.format("%Y-%m-%d %H:%M:%S").to_string(),
                                name: filename,
                                size: md.len(),
                            });
                        }
                    }
                }
            }
        }
    }
    library.sort();
    library.reverse();
    library
}

type HttpsClient = hyper::Client<hyper_rustls::HttpsConnector<hyper::client::HttpConnector>>;

#[derive(Debug)]
pub struct MediaDepot {
    client: HttpsClient,
    root_dir: PathBuf,
    title: String,
    email: String,
    domain: String,
    cas: String,
}

impl_web! {
    impl MediaDepot {

        #[get("/logout")]
        #[content_type("json")]
        fn logout(&self) -> Result<Redirect, ()> {
            Ok(Redirect{
                set_cookie: Auth::clear_cookie().unwrap().to_string(),
                location: self.cas.clone() + "/logout?url=" + &self.domain + "/",
            })
        }

        // Generally CAS will post logouts to this location
        // At some point will want to whitelist IP to this endpoint
        //#[post("/")]

        #[get("/health")]
        fn health(&self) -> Result<String, ()> {
            Ok("Up".to_string())
        }

        fn static_files(&self, relative_path: PathBuf) -> impl Future<Item = File, Error = io::Error> + Send {
            let mut path = self.root_dir.clone();
            path.push(relative_path);
            File::open(path)
        }

        #[get("/favicon.ico")]
        #[content_type("image/x-icon")]
        fn favicon(&self) -> impl Future<Item = File, Error = io::Error> + Send {
            self.static_files(FAVICON.into())
        }

        #[get("/static/jpg/*relative_path")]
        #[content_type("image/jpeg")]
        fn jpg(&self, relative_path: PathBuf) -> impl Future<Item = File, Error = io::Error> + Send {
            let mut path: PathBuf = "static/jpg".into();
            path.push(relative_path);
            self.static_files(path)
        }

        #[get("/static/css/*relative_path")]
        #[content_type("text/css")]
        fn css(&self, relative_path: PathBuf) -> impl Future<Item = File, Error = io::Error> + Send {
            let mut path: PathBuf = "static/css".into();
            path.push(relative_path);
            self.static_files(path)
        }

        #[get("/error/:err")]
        #[content_type("text/html")]
        fn error(&self, err: String) -> Result<String, ()> {
            let content = match err.as_ref() {
                "auth" => "CAS login service was unable to successfully authenticate your account. You may wish to retry and login again.",
                "encode" => "CAS login service is not responding properly. You may wish to retry and login again.",
                "status" => "CAS login service is not responding properly. You may wish to retry and login again.",
                _ => "Encountered an unknown CAS login service error. You may wish to retry and login again.",
            };
            Ok(templates::layout(&self.title, &self.email, templates::error(content)).into_string())
        }

        // If Auth ticket fails to verify then display page with button link to CAS login page so do NOT
        // run into infinite loop.
        // 
        // The URL of your service, which is used as part of login sequence so the CAS server knows where to
        // redirect you back to where you left off (in case your session has expired)
        //   service_url: Uri,
        //
        // When login completes, the CAS server will redirect to your service_url with the added ticket=\<ticket\>
        // parameter.  CASResponse contains \<ticket\> and referer provided by the client, which allows you our
        // service to check back with the CAS server and determin whether or not the login was successful.
        // On success, the service may use the CAS xml parser which will return Auth if client was validated. The
        // Auth structure will contain the lowercased version of the id of the user that logged into the CAS server.
        // On failure it returns `Err(CASError)`, which indicates the reason for the failure, which may be a
        // CAS error, http error, or an xml parsing error.
        //
        // NOTE: Upon successful authentication a session cookie should be returned to the client via a redirect back
        // to the full_path.
        #[get("/cas/")]
        #[content_type("json")]
        async fn cas_no_path(&self, cas_info: CASResponse) -> Redirect {
            let auth = await!(self.cas_verify_ticket("/".into(), cas_info));
            match auth {
                Ok(auth) => Redirect{
                    set_cookie: auth.create_cookie().unwrap().to_string(),
                    location: "/".to_string(),
                },
                //CAS XML Response -- failed unable to authenticate
                Err(CASError::AuthFailure(_)) => Redirect{
                    set_cookie: Auth::clear_cookie().unwrap().to_string(),
                    location: "/error/auth".to_string(),
                },
                // CAS XML response not valid UTF-8
                Err(CASError::InvalidEncoding) => Redirect{
                    set_cookie: Auth::clear_cookie().unwrap().to_string(),
                    location: "/error/encode".to_string(),
                },
                // CAS XML response returned a non200 status code
                Err(CASError::InvalidStatus) => Redirect{
                    set_cookie: Auth::clear_cookie().unwrap().to_string(),
                    location: "/error/status".to_string(),
                },
                _ => Redirect{
                    set_cookie: Auth::clear_cookie().unwrap().to_string(),
                    location: "/error/unknown".to_string(),
                },
            }
        }

        #[get("/cas/*full_path")]
        #[content_type("json")]
        async fn cas_full_path(&self, full_path: PathBuf, cas_info: CASResponse) -> Redirect {
            let path = full_path.to_str().unwrap_or("/");
            let auth = await!(self.cas_verify_ticket(path.into(), cas_info));
            match auth {
                Ok(auth) => Redirect{
                    set_cookie: auth.create_cookie().unwrap().to_string(),
                    location: path.to_string(),
                },
                //CAS XML Response -- failed unable to authenticate
                Err(CASError::AuthFailure(_)) => Redirect{
                    set_cookie: Auth::clear_cookie().unwrap().to_string(),
                    location: "/error/auth".to_string(),
                },
                // CAS XML response not valid UTF-8
                Err(CASError::InvalidEncoding) => Redirect{
                    set_cookie: Auth::clear_cookie().unwrap().to_string(),
                    location: "/error/encode".to_string(),
                },
                // CAS XML response returned a non200 status code
                Err(CASError::InvalidStatus) => Redirect{
                    set_cookie: Auth::clear_cookie().unwrap().to_string(),
                    location: "/error/status".to_string(),
                },
                _ => Redirect{
                    set_cookie: Auth::clear_cookie().unwrap().to_string(),
                    location: "/error/unknown".to_string(),
                },
            }
        }

        async fn cas_verify_ticket(&self, path: String, cas_info: CASResponse) -> Result<Auth, CASError> {
            let url = self.cas.clone()
                + "/p3/serviceValidate"
                + "?ticket=" + &utf8_percent_encode(&cas_info.ticket, DEFAULT_ENCODE_SET).to_string()[..]
                + "&service=" + &utf8_percent_encode(&(self.domain.clone() + "/cas" + &path), DEFAULT_ENCODE_SET).to_string()[..];

            // Issue the request and wait for the response
            let res = await!(self.client.get(url.parse::<Uri>().unwrap())).unwrap();

            if res.status() == 200 {
                // Get the body component of the HTTP response. This is a stream and as such, it must
                // be asynchronously collected.
                let mut body = res.into_body();

                // The body chunks will be appended to this string.
                let mut xml = String::new();

                while let Some(chunk) = await!(body.next()) {
                    let chunk = chunk.unwrap();

                    // Convert to a string
                    let chunk = str::from_utf8(&chunk[..]).unwrap();

                    // Append to buffer
                    xml.push_str(chunk);
                }
                // Verify that response is valid UTF-8 before parsing
                let xml = str::from_utf8(xml.as_bytes());
                eprintln!("DEBUG [CAS Response] {:?}", xml.unwrap_or("Not valid UTF-8"));
                if let Ok(xml) = xml {
                    cas::parse_xml(xml)
                } else {
                    // CAS XML response not valid UTF-8
                    Err(CASError::InvalidEncoding)
                }
            } else {
                // CAS XML response returned a non200 status code
                Err(CASError::InvalidStatus)
            }
        }

        // Following endpoints require CAS cookie, JWT or CAS token check.

        #[get("/")]
        #[content_type("text/html")]
        async fn index(&self, auth: auth::Auth) -> String {
            let mut path = self.root_dir.clone();
            let relative_path: PathBuf = ("vcms/".to_string() + &auth.id + "/library").into();
            path.push(relative_path);
            let library = await!(media(path));
            templates::layout(&self.title, &self.email, content(library)).into_string()
        }

        #[get("/library")]
        #[content_type("application/json")]
        async fn library(&self, auth: auth::Auth) -> Vec<Media> {
            let mut path = self.root_dir.clone();
            let relative_path: PathBuf = ("vcms/".to_string() + &auth.id + "/library").into();
            path.push(relative_path);
            let library = await!(media(path));
            library
        }

        #[get("/library/*relative_path")]
        #[content_type("video/x-m4v")]
        //#[content_type("application/octet-stream")]
        //  *res.header_mut(header::CONTENT_DISPOSITION, format!("attachment; filename=\"{}\"", filename).parse().unwrap())
        //  Attempted to forcing the content type to utilize the default type of
        //  "application/octet-stream" as octet-stream header the browser will default to
        //  downloading the file rather then attempt to play the video, however, it seems
        //  that firefox is now automatically detecting the file type and still plays it.
        fn m4v(&self, auth: auth::Auth, relative_path: PathBuf) -> impl Future<Item = File, Error = io::Error> + Send {
            let mut path: PathBuf = ("vcms/".to_string() + &auth.id + "/library").into();
            path.push(relative_path);
            self.static_files(path)
        }
    }
}

pub fn main() {
    let _ = env_logger::try_init();
    let addr = match env::var("ADDRESS") {
        Ok(a) => a.to_owned(),
        Err(_)  => "127.0.0.1:8443".to_owned(),
    };
    let addr: SocketAddr = addr.parse().unwrap();
    let title = "YouStar Media Depot";
    let email = "YouStarStudio@txstate.edu";
    let https = HttpsConnector::new(4);
    let client = hyper::Client::builder()
        .build::<_, hyper::Body>(https);
    let router = MediaDepot{
            client,
            root_dir: ROOT_DIR.clone().to_path_buf(), 
            title: title.to_string(),
            email: email.to_string(),
            domain: DOMAIN.clone(),
            cas: CAS_URL.clone(),
    };

    let wrap_with_tls = {
        let mut config = ServerConfig::new(NoClientAuth::new());
        config.set_single_cert(load_certs(&*CERTS.public), load_private_keys(&*CERTS.private).remove(0))
            .expect("invalid key or certificate");
        TlsAcceptor::from(Arc::new(config))
    };

    let incoming = TcpListener::bind(&addr).unwrap()
        .incoming()
        .map(move |tcp_stream| wrap_with_tls.accept(tcp_stream))
        .and_then(|tls_stream| tls_stream)
        .then(|r| match r {
            Ok(x) => Ok::<_, io::Error>(Some(x)),
            Err(e) => {
                eprintln!("ERROR [TLS]: {:?}", e);
                Ok(None)
            },
        })
        .filter_map(|x| x);

    println!("Listening on http://{}", addr);
    tokio::run({
        ServiceBuilder::new()
        .resource(router)
        .middleware(LogMiddleware::new("media_depot::web"))
        .catch(move |req: &http::Request<()>, err: Error| {
            eprintln!("ERROR [Catch]: {:?}, {:?}", req, err);
            let (status, content) = if err.kind().is_not_found() {
                (404, "Not Found")
            } else if err.kind().is_bad_request() {
                (400, "Bad Request")
            } else {
                (500, "Internal Server Error")
            };

            let path = req.uri().path();
            if path == "" {
                let res: http::Response<hyper::Body> = http::response::Builder::new()
                    .status(302)
                    .header("location", "/")
                    .body(Body::empty())
                    .unwrap();
                Ok(res)
            } else if path == "/"
                || path == "/library"
                || path.starts_with("/library/") {
                // CAS Controlled locations. Authentication session has expired or has not been
                // generated
                //let service_url = utf8_percent_encode(&(DOMAIN.clone() + "/cas" + path), DEFAULT_ENCODE_SET);
                let service_url = DOMAIN.clone() + "/cas" + path;
                let res: http::Response<hyper::Body> = http::response::Builder::new()
                    .status(302)
                    .header("location", CAS_URL.clone() + "/login?service=" + &service_url)
                    .header("set-cookie", Auth::clear_cookie().unwrap().to_string())
                    .body(Body::empty())
                    .unwrap();
                Ok(res)
            } else {
                // TODO: if req has header content accept of application/json
                // then return error in json format
                // TODO: if 400 bad request and not json then redirect to CAS Login
                let msg = templates::layout(title, email, templates::error(content)).into_string();
                let res: http::Response<hyper::Body> = http::response::Builder::new()
                    .status(status)
                    .header("content-type", "text/html")
                    .body(msg.into())
                    .unwrap();
                Ok(res)
            }
        })
        .serve(incoming)
    })
}
