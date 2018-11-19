use std::{ env, str, io };
use hyper::error::Error as HyperError;
use http::uri::InvalidUri;
use xml::reader::{EventReader, XmlEvent, Error as XmlError};
use tower_web::extract::{Context, Error, Extract, Immediate};
use tower_web::util::buf_stream::BufStream;
use super::auth::Auth;
//use percent_encoding::{utf8_percent_encode, DEFAULT_ENCODE_SET};

// Example: CASURL=https://login.example.com/cas
lazy_static! {
    pub static ref CAS_URL: String = env::var("CASURL").expect("CAS_URL environment variable is required").into();
}

//#[derive(Extract)]
#[derive(Debug)]
pub struct CASResponse {
//    #[web(header)]
//    pub referer: String,
    pub ticket: String,
}

impl<B: BufStream> Extract<B> for CASResponse {
    type Future = Immediate<Self>;

    fn extract(ctx: &Context) -> Self::Future {
        let query = ctx.request().uri().query().unwrap_or("");
        // WARN: cannot assume that ticket is the first and only part of the query,
        // however, at the momment have not seen any other form of return from CAS.
        if !query.starts_with("ticket=") {
            return Immediate::err(Error::missing_argument());
        }
        let (_, ticket) = query.split_at(7);
        Immediate::ok(CASResponse{
            ticket: ticket.to_string(),
        })
    }
}

#[derive(Debug)]
enum XmlMatchStatus {
    None,
    ExpectSuccess,
}

/// Errors that can happen when verifying.
/// NOTE: Xml error is unlikely.
#[derive(Debug)]
pub enum CASError {
    Hyper(HyperError),
    Tokio(io::Error),
    Xml(XmlError),
    Uri(InvalidUri),
    AuthFailure(String),
    InvalidEncoding,
    InvalidStatus,

}

impl From<HyperError> for CASError {
    fn from(err: HyperError) -> CASError {
        CASError::Hyper(err)
    }
}
impl From<io::Error> for CASError {
    fn from(err: io::Error) -> CASError {
        CASError::Tokio(err)
    }
}
impl From<XmlError> for CASError {
    fn from(err: XmlError) -> CASError {
        CASError::Xml(err)
    }
}
impl From<InvalidUri> for CASError {
    fn from(err: InvalidUri) -> CASError {
        CASError::Uri(err)
    }
}

// Login url example: https://login.example.edu/login
// Logout url example: https://login.example.edu/logout
// Verify_url example: https://login.example.edu/p3/serviceValidate

pub fn parse_xml(xml: &str) -> Result<Auth, CASError> {
    let parser = EventReader::new(xml.as_bytes());
    let mut status = XmlMatchStatus::None;
    for e in parser {
        match e {
            Ok(XmlEvent::StartElement { name, attributes, .. }) => {
                if name.local_name == "authenticationSuccess" {
                    status = XmlMatchStatus::ExpectSuccess;
                } else if name.local_name == "authenticationFailure" {
                    let reason = attributes[0].value.clone();
                    return Err(CASError::AuthFailure(reason));
                }
            }
            Ok(XmlEvent::Characters(s)) => {
                match status {
                    XmlMatchStatus::None => {}
                    XmlMatchStatus::ExpectSuccess => {
                        return Ok(Auth{ proctor: None, id: s[..].to_lowercase() });
                    }
                }
            }
            _ => {}
        }
    }
    let error = "did not detect authentication reply from CAS server".to_owned();
    Err(CASError::AuthFailure(error))
}
