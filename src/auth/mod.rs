mod cookie;
mod key;

use tower_web::extract::{Context, Error, Extract, Immediate};
use tower_web::util::buf_stream::BufStream;
use hyper::{ Request, header };
use std::env;
use base64;
use jwt;
use self::cookie::Cookie;
use self::key::Key;


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

// ```openssl rand -base64 32```
// example: JWTKEY=95C/LUVqguoqHsVz4ATVm6yhJczhp5/zxoJVHr3eagw=
lazy_static! {
    static ref JWT_KEY: Vec<u8> = {
        match env::var("JWTKEY") {
           Ok(jwt_key) => {
               if let Ok(k) = base64::decode(&jwt_key) {
                   k
               } else {
                   panic!("ERROR: Invalid JWTKEY Base64 encoding.");
               }
           },
           Err(_) => panic!("ERROR: No JWTKEY defined."),
        }
    };
}

#[derive(Debug, Deserialize, Default)]
pub struct Auth {
    pub proctor: Option<String>,
    pub id: String,
    //exp: time,
}

impl<B: BufStream> Extract<B> for Auth {
    type Future = Immediate<Self>;

    fn extract(ctx: &Context) -> Self::Future {
        match Auth::retrieve(ctx.request()) {
            Ok(Some(auth)) => Immediate::ok(auth),
            Ok(None) => {
                eprintln!("ERROR [Auth Extract]: No Authentication found");
                Immediate::err(Error::missing_argument())
            },
            Err(e) => {
                eprintln!("ERROR [Auth Extract]: Authentication failure: {:?}", e);
                Immediate::err(Error::missing_argument())
            },
        }
    }
}

impl<'d, 'p> Auth {
    pub fn clear_cookie() -> Result<Cookie<'d, 'p>, AuthError> {
        match Cookie::new(Some(cookie::CookiePrefix::HOST), "id", "", Some(&*COOKIE_KEY)) {
            Ok(c) => Ok(c.with_path(Some("/"))
                .clear()
                .with_secure(true)
                .with_http_only(true)
                .with_same_site(Some(cookie::SameSite::LAX))),
            Err(e) => Err(AuthError::CookieError(format!("{:?}", e))),
        }
    }

    pub fn create_cookie(&self) -> Result<Cookie<'d, 'p>, AuthError> {
        match Cookie::new(Some(cookie::CookiePrefix::HOST), "id", &self.id[..], Some(&*COOKIE_KEY)) {
            Ok(c) => Ok(c.with_path(Some("/"))
                .with_secure(true)
                .with_http_only(true)
                .with_same_site(Some(cookie::SameSite::LAX))),
            Err(e) => Err(AuthError::CookieError(format!("{:?}", e))),
        }
    }

    pub fn retrieve(req: &Request<()>) -> Result<Option<Auth>, AuthError> {
        // Admin gets proctor (aid) and id from JWT https://github.com/Keats/jsonwebtoken
        //    https://github.com/Keats/jsonwebtoken/blob/master/examples/custom_header.rs
        // Generate it from http://search.cpan.org/~mik/Crypt-JWT-0.010/lib/Crypt/JWT.pm
        //    And setup header https://alvinalexander.com/perl/edu/articles/pl010012
        if let Some(a) = req.headers().get(header::AUTHORIZATION) {
            let mut a = a.to_str()?.splitn(2, " ");
            if Some("Bearer") == a.next() {
                if let Some(token) = a.next() {
                    match jwt::decode::<Auth>(&token, &*JWT_KEY, &jwt::Validation::new(jwt::Algorithm::HS512)) {
                        Ok(user) => Ok(Some(Auth{
                                proctor: user.claims.proctor,
                                id: user.claims.id,
                            })),
                        Err(e) => Err(AuthError::JWTError(format!("{:?}", e))),
                    }
                } else {
                    Err(AuthError::JWTError("Empty Authorization Bearer Value".to_string()))
                }
            } else {
                Err(AuthError::JWTError("Invalid Authorization type".to_string()))
            }
        } else if let Some(c) = cookie::Cookie::from_request(req, Some(cookie::CookiePrefix::HOST), "id") {
            // User gets id from cookie
            // Session cookie found (get ID)
            // Valid session cookie so manage request
            match c.get_value(Some(&*COOKIE_KEY)) {
                 Ok(id) => Ok(Some(Auth{
                         proctor: None,
                         id: id
                     })),
                 Err(e) => Err(AuthError::CookieError(format!("{:?}", e))),
            }
        } else {
            Ok(None)
        }
    }
}

#[derive(Debug)]
pub enum AuthError {
    JWTError(String),
    CookieError(String),
}

impl From<header::ToStrError> for AuthError {
    fn from(e: header::ToStrError) -> AuthError {
        let e = format!("{:?}", e);
        AuthError::JWTError(e.to_string())
    }
}
