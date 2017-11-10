use std::str;
use std::io;
use hyper::server::Response;
use hyper::StatusCode;
use hyper::header::Location;
use hyper::Client;
use hyper::Uri;
use hyper::error::UriError;
use hyper::error::Error as HyperError;
use futures::{Future, Stream};
use xml::reader::{EventReader, XmlEvent, Error as XmlError};
use tokio_core::reactor::Core;
use percent_encoding::{utf8_percent_encode, DEFAULT_ENCODE_SET};
//use hyper_rustls::HttpsConnector;
use hyper_openssl::HttpsConnector;
use hyper_openssl::openssl::error::ErrorStack;

/// The username returned by `verify_ticket` on success
pub type Name = String;
/// The error returned by `verify_ticket` on failure
pub type TicketError = String;

/// The details of a CAS server.  All URLs are the full urls
#[derive(Debug)]
pub struct CasClient {
    /// Login url (such as https://login.its.txstate.edu/login)
    login_url: Uri,
    /// Logout url (such as https://login.its.txstate.edu/logout)
    logout_url: Uri,
    /// Verify url, accessed by the server
    /// (such as https://login.its.txstate.edu/p3/serviceValidate)
    verify_url: Uri,
}

/// The URL of your service, which is used in the login sequence and
/// so the login server knows where to redirect you back to
///service_url: Uri,

/// The response from the server from `verify_ticket`
#[derive(Debug)]
pub enum ServiceResponse {
    /// Returned on successful login
    Success(Name),
    /// Returned on unsuccessful login
    Failure(TicketError),
}

#[derive(Debug)]
enum XmlMatchStatus {
    None,
    ExpectSuccess,
}

/// Errors that can happen when verifying.  Xml is unlikely.
#[derive(Debug)]
pub enum VerifyError {
    Hyper(HyperError),
    Tokio(io::Error),
    Xml(XmlError),
    Uri(UriError),
    UnsupportedUriType,
    NoTicketFound,
    OpenSSL(ErrorStack)
}

impl From<HyperError> for VerifyError {
    fn from(err: HyperError) -> VerifyError {
        VerifyError::Hyper(err)
    }
}
impl From<io::Error> for VerifyError {
    fn from(err: io::Error) -> VerifyError {
        VerifyError::Tokio(err)
    }
}
impl From<XmlError> for VerifyError {
    fn from(err: XmlError) -> VerifyError {
        VerifyError::Xml(err)
    }
}
impl From<UriError> for VerifyError {
    fn from(err: UriError) -> VerifyError {
        VerifyError::Uri(err)
    }
}
impl From<ErrorStack> for VerifyError {
    fn from(err:ErrorStack) -> VerifyError {
        VerifyError::OpenSSL(err)
    }
}
impl CasClient {
    /// Construct a new CasClient.
    /// Each path will will be appended to the base_url to form the full url.
    pub fn new(base_url: &str,
               login_path: &str,
               logout_path: &str,
               verify_path: &str)
               -> Result<CasClient, UriError> {
        Ok(CasClient {
            login_url: (&format!("{}{}", base_url, login_path)).parse::<Uri>()?,
            logout_url: (&format!("{}{}", base_url, logout_path)).parse::<Uri>()?,
            verify_url: (&format!("{}{}", base_url, verify_path)).parse::<Uri>()?,
        })
    }

    /// Returns a 302 redirect Response to the CAS login url.
    pub fn login_redirect(&self, referrer: &str) -> Response {
        Response::new()
            .with_status(StatusCode::Found)
            .with_header(Location::new(self.login_url.to_string() + "?service=" + referrer))
    }

    /// Returns a 302 redirect Response to the CAS logout url.
    /// Does not clear any session cookies; so those set-cookies must
    /// be added to this response before returning the response to the
    /// client.
    pub fn logout_redirect(&self, service_url: &str) -> Response {
        Response::new()
            .with_status(StatusCode::Found)
            .with_header(Location::new(self.logout_url.to_string() + "?url=" + service_url ))
    }

    /// When login completes, the CAS server will redirect to your service_url
    /// with the added parameter ticket=\<ticket\>.  You pass \<ticket\> here,
    /// and it checks with the CAS server whether or not the login was
    /// successful.  On success, this will return
    /// `Ok(ServiceResponse::Success(username))`, where username is the username
    /// from the CAS server.  On failure it returns
    /// `Ok(ServiceResponse::Failure(reason))`, where reason is the reason for
    /// the failure.  In the event of an http error or an xml error, this
    /// returns Err(VerifyError)
    pub fn verify_ticket(&self, ticket: &str, service_url: &str) -> Result<ServiceResponse, VerifyError> {
        let uri = (self.verify_url.to_string()
           + "?ticket=" + &(utf8_percent_encode(ticket, DEFAULT_ENCODE_SET).to_string())[..]
           + "&service=" + &(utf8_percent_encode(service_url, DEFAULT_ENCODE_SET).to_string()[..])).parse::<Uri>()?;
        print!("[SERVICE URL]{:?}\n", uri);
        let mut core = Core::new()?;
        let client = Client::configure()
            .connector(HttpsConnector::new(4, &core.handle())?)
            .build(&core.handle());
        let work = client.get(uri).and_then(|res| {
            println!("[CAS RES STATUS] {}", res.status());
            //res.body().concat2().and_then(move |body| {
            res.body().concat2().map(move |body| {
                print!("[CAS RES BODY] {:?}\n", str::from_utf8(&*body).unwrap_or("Error: Not valid UTF-8"));
                let parser = EventReader::new(&*body);
                let mut status = XmlMatchStatus::None;
                for e in parser {
                    //match try!(e) {
                    match e {
                        Ok(XmlEvent::StartElement { name, attributes, .. }) => {
                            if name.local_name == "authenticationSuccess" {
                                status = XmlMatchStatus::ExpectSuccess;
                            } else if name.local_name == "authenticationFailure" {
                                let reason = attributes[0].value.clone();
                                return ServiceResponse::Failure(reason);
                            }
                        }
                        Ok(XmlEvent::Characters(s)) => {
                            match status {
                                XmlMatchStatus::None => {}
                                XmlMatchStatus::ExpectSuccess => {
                                    return ServiceResponse::Success(s);
                                }
                            }
                        }
                        _ => {}
                    }
                }
                let error = "did not detect authentication reply from CAS server".to_owned();
                ServiceResponse::Failure(error)
            })

        });
        let res = core.run(work)?;
        Ok(res)
    }

    /// Takes a reference to a request, and verifies the ticket in that request.
    /// Will return an `Err(VerifyError::NoTicketFound)` if it can't find the
    /// ticket in the url query
    pub fn verify_from_request(&self, query: Option<&str>, service_url: &str) -> Result<ServiceResponse, VerifyError> {
        if let Some(query) = query {
            // TODO: we cannot assume ticket is the first query entry.
            if !query.starts_with("ticket=") {
                return Err(VerifyError::NoTicketFound);
            }
            let (_, ticket) = query.split_at(7);
            self.verify_ticket(&ticket, service_url)
        } else {
            Err(VerifyError::NoTicketFound)
        }
    }
}
