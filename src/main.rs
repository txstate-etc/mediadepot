extern crate futures;
extern crate hyper;
extern crate rustls;
extern crate tokio_core;
extern crate tokio_proto;
extern crate tokio_rustls;
extern crate hyper_rustls;
extern crate hyper_openssl;
extern crate ring;
extern crate base64;
extern crate percent_encoding;
extern crate xml;
#[macro_use] extern crate lazy_static;

mod key;
mod cookie;
mod cas;
mod router;

use futures::{Future, Stream};
use tokio_core::net::TcpListener;
use tokio_core::reactor::Core;
use rustls::internal::pemfile;
use std::env;
use key::Key;
use cas::CasClient;
use hyper::Uri;
use hyper::server::Http;
use router::Router;
use tokio_rustls::ServerConfigExt;

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

// ```openssl rand -base64 32```
// example: MASTERKEY=sVdCPIwy2URfikVQiBH1Z+Jz39mibRG7viq42oYapTA=
lazy_static! {
    static ref COOKIE_KEY: Key = {
        match env::var("MASTERKEY") {
           Ok(master_key) => Key::new(Some(&master_key[..])).unwrap(),
           Err(_) => Key::new(None).unwrap(),
        }
    };
}

// example: DOMAIN=https://mediadepot-qa1.its.txstate.edu:8443
lazy_static! {
    static ref DOMAIN: Uri = {
        match env::var("DOMAIN") {
           Ok(domain) => domain.parse::<Uri>().unwrap(),
           Err(_) => panic!("No DOMAIN defined."),
        }
    };
}

// example: CASURL=https://login.its.qual.txstate.edu/cas
lazy_static! {
    static ref CAS_CLIENT: CasClient = {
        match env::var("CASURL") {
           Ok(cas_url) => CasClient::new(&cas_url[..], "/login", "/logout", "/p3/serviceValidate").unwrap(),
           Err(_) => panic!("No CASURL defined."),
        }
    };
}

fn main() {
    let address = match std::env::var("ADDRESS") {
        Ok(a) => a.to_owned(),
        Err(_)  => "127.0.0.1:8443".to_owned(),
    };
    let addr = address.parse().unwrap();
    let certs = load_certs("private/local.cert.pem");
    let certs_key = load_private_key("private/local.key.pem");
    let mut config = rustls::ServerConfig::new();
    config.set_single_cert(certs, certs_key);
    let arc_config = std::sync::Arc::new(config);
    let mut core = Core::new().unwrap();
    let handle = core.handle();
    let socket = TcpListener::bind(&addr, &handle).unwrap();
    let http = std::rc::Rc::new(Http::new());
    let done = socket.incoming()
        .for_each(|(sock, remote_addr)| {
            println!("Info: {:?}", remote_addr);
            let h = handle.clone();
            let http = http.clone();
            let done = arc_config.accept_async(sock)
                .map(move |stream| {
                    let r = Router::new(h.clone(), &COOKIE_KEY, &DOMAIN, &CAS_CLIENT);
                    http.bind_connection(&h, stream, remote_addr, r);
                })
                .map_err(move |err| println!("Error: {:?} - {}", err, remote_addr));
            handle.spawn(done);
            Ok(())
        });
    println!("Starting to serve on https://{} ...", addr);
    core.run(done).unwrap();
}
