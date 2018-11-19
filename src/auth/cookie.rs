use hyper::{ Request, header };
use std::fmt;
use std::time::Duration;
use base64;
use percent_encoding::{utf8_percent_encode, DEFAULT_ENCODE_SET};
use super::key::Key;

#[allow(dead_code)]
#[derive(Clone, PartialEq, Debug)]
pub enum SameSite {
  STRICT,
  LAX,
}

#[allow(dead_code)]
#[derive(Clone, PartialEq, Debug)]
pub enum CookiePrefix {
    SECURE,
    HOST,
}

impl CookiePrefix {
    fn to_string(&self) -> String {
       match *self {
           CookiePrefix::SECURE => "__Secure-".to_string(),
           CookiePrefix::HOST => "__Host-".to_string(),
       }
    }
}

/// This Private Cookie Module is server based; thus we do not parse
/// SetCookie data, but rather only construct it.
///
/// Cookie header parser for server incoming requests:
/// Cookie: <[__Secure-|__Host-]name>=<value>[; <[__Secure-|__Host-]name2>=<value2>[; ...]][;]
///
/// Set cookie header options for server outgoing responses:
/// Set-Cookie: <[__Secure-|__Host-]name>=<value>
/// [; Domain=<domain_name>][; Path=<some_path>]
/// [; Max-Age=<age>][; Expires=<date>]
/// [; Secure][; HttpOnly][; SameSite=<Strict|Lax>]
///
///
/// Both `encoded_name` and `value` are String types as we percent encode
/// the `encoded_name` and base64 encode the `value` which means we need
/// to allocate space for such data. As it would be unusual to return
/// that unencoded data back within the same request, more likely upon
/// the return request which will contain the encoded data, we do NOT
/// believe it to be worth storing the original value. We encode because
/// of the Cookie name and value limitions:
///
/// * Cookie name limitation:
///   A <cookie-name> can be any US-ASCII characters except control
/// characters (CTLs), spaces, or tabs. It also must not contain a
/// separator character like the following:
///    ( ) < > @ , ; : \ " /  [ ] ? = { }.
///
/// * Cookie value limitation:
///   A <cookie-value> can optionally be set in double quotes and
/// any US-ASCII characters are allowed, excluding CTLs, whitespace,
/// double quotes, comma, semicolon, and backslash.
///
/// Cookie "__Secure-" and "__Host-" prefixes:
///   Cookie prefixes are a way to prevent insecure sites (i.e. http)
/// from overwriting secure site cookies from within the same domain.
/// Cookie names with the prefixes "__Secure-" and "__Host-" may be
/// used only if they are set with the secure directive from a secure
/// (HTTPS) origin. In addition, cookies with the __Host- prefix
/// must have a path of "/" (the entire host) and must not have
/// the more permissive domain attribute. If a cookie is created with
/// a cookie prefix then it automatically gets prepended to the name,
/// and thus becomes part of the associated data used to encrypt the
/// value.
#[derive(Debug, Clone)]
pub struct Cookie<'d, 'p> {
    /// The cookie's name.
    /// Url percent encoded.
    name: String,
    /// The cookie's value.
    /// We will not manage tokens (cookies with name and no value.)
    /// The value is base64 encoded, which may represent an encrypted
    /// binary value.
    value: String,
    /// The cookie's domain, if any.
    /// Specifies those hosts to which the browser will send the cookie.
    ///   If not specified, defaults to the host portion of the current
    /// document location (but not including subdomains). Leading dots
    /// in domain names are ignored.
    ///   If a domain is specified, subdomains are always included.
    domain: Option<&'d str>,
    /// The cookie's path if any.
    /// Indicates a URL path that must exist in the requested
    /// resource before the browser will send the Cookie header
    path: Option<&'p str>,
    ///   If neither expires nor Max-Age are specified then
    /// cookies is treated as a sessions cookie, i.e. removed
    /// after client is shutdown.  WARN: web browsers often
    /// enable session restoring.
    ///
    /// The cookie's expires in GMT time, if any.
    /// This is deprecated and will not be used
    /// expires: Option<Tm>,
    ///
    /// The cookie's MaxAge, if any.
    /// MaxAge is not supported by IE, thus treated as session cookie.
    max_age: Option<Duration>,
    /// The `Secure` directive:
    /// Whether this cookie was marked Secure.
    /// Browsers which support the secure flag will only
    /// send cookies with the secure flag when the request
    /// is going to a HTTPS page. This prevents cookies
    /// from being observed in clear text.
    secure: bool,
    /// The `HttpOnly` directive:
    /// Used to prevent Cross-Site Scripting (XSS).
    /// Whether this cookie was marked HttpOnly.
    /// Using the HttpOnly flag when generating a
    /// cookie helps mitigate the risk of client
    /// side script accessing the protected cookie.
    http_only: bool,
    /// SameSite=Lax/Strict
    /// The `SameSite` attribute:
    /// Used to prevent Cross-site Request Forgery (CSRF)
    /// Note that by setting a cookie as Strict you may negatively affect
    /// browsing experience.
    ///   The following would be such an example of a negative experience:
    /// Should you click on a link that points to a Facebook profile page,
    /// and if Facebook.com has set its cookie as SameSite=Strict, you cannot
    /// would not be allowed to view the Facebook page, until you log into
    /// Facebook again. The reason for this is because Facebook`s session
    /// information cookie would not have been sent buy the browser along
    /// with this request.
    ///   SameSite Lax request exclusions and inclusions:
    /// * LAX Requests Non-TOP LEVEL navigation are all excluded:
    ///   Resources loaded by iframe, img tags, and script tags do not cause
    /// TOP LEVEL navigation, as can be seen by the fact that they do not
    /// change the URL in your address bar. Because of this these GET requests
    /// will not contain Lax set cookie with them.
    /// * table with Lax request inclusions for more clarification:
    ///   Request Type  Example Code                       Cookies sent
    ///   Link          <a href="..."></a>                 Normal, Lax
    ///   Perender      <link rel="prerender" href=".."/>  Normal, Lax
    ///   Form GET      <form method="GET" action="...">   Normal, Lax
    ///   Form POST     <form method="POST" action="...">  Normal
    ///   iframe        <iframe src="..."></iframe>        Normal
    ///   AJAX          $.get("...")                       Normal
    ///   Image         <img src="...">                    Normal
    same_site: Option<SameSite>,
}

impl<'d, 'p> fmt::Display for Cookie<'d, 'p> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut cookie = String::new();
        cookie += &self.name[..];
        cookie = cookie + "=" + &self.value[..];
        if let Some(domain) = self.domain {
            cookie = cookie + "; Domain=" + domain;
        }
        if let Some(path) = self.path {
            cookie = cookie + "; Path=" + path;
        }
        if let Some(max_age) = self.max_age {
            cookie = cookie + "; Max-Age=" + &(max_age.as_secs().to_string())[..];
        }
        if self.secure {
            cookie += "; Secure";
        }
        if self.http_only {
            cookie += "; HttpOnly";
        }
        if let Some(ref same_site) = self.same_site {
            cookie += match same_site {
                &SameSite::STRICT => "; SameSite=Strict",
                &SameSite::LAX => "; SameSite=Lax",
            };
        }
        write!(f, "{}", cookie)
    }
}

// TODO: url percent encode:
// TODO: z85 encode:
// TODO: Cookie building should verify domain
// TODO: Cookie::new() and Cookie::build() should only allow absolute paths
//   and not allow empty strings such as " " or "".
// https://docs.rs/hyper/0.11.6/hyper/header/struct.SetCookie.html
impl<'d, 'p> Cookie<'d, 'p> {
    /// Create cookie with `name` and `value`, where `key` Key type is
    /// used to encrypt the `value` unless set to None.
    pub fn new(prefix: Option<CookiePrefix>, name: &str, value: &str, key: Option<&Key>) -> Result<Cookie<'d, 'p>, &'static str> {
        let mut name = utf8_percent_encode(name, DEFAULT_ENCODE_SET).to_string();
        if let Some(prefix) = prefix {
            name = prefix.to_string() + &name[..];
        }
        Ok(Cookie{
            value: if let Some(key) = key { key.seal(&name[..], value)? } else { base64::encode(value) },
            name: name,
            domain: None,
            path: None,
            max_age: None,
            secure: false,
            http_only: false,
            same_site: None,
        })
    }

    /// Create a cookie from a hyper request struct, if it exists within the request.
    pub fn from_request(req: &Request<()>, prefix: Option<CookiePrefix>, name: &str) -> Option<Cookie<'d, 'p>> {
        if let Some(cookies) = req.headers().get(header::COOKIE) {
            let mut name = utf8_percent_encode(name, DEFAULT_ENCODE_SET).to_string();
            if let Some(prefix) = prefix {
                name = prefix.to_string() + &name[..];
            }
            let tag = name.clone() + "=";
            // WARN: There may be multiple Cookie headers, as well as multiple Cookie values per
            //   header, as well as same names used within a single cookie header.
            // We will only look at first cookie header, break it up and return the value from
            //   the first name that matches.
            // Example: Cookie: _ga=<google info>; _ga=<more google info>; __Host-id=<base64 representation of encrypted value>
            if let Ok(cookies) = cookies.to_str() {
                for cookie in cookies.split("; ") {
                    if cookie.starts_with(&tag) {
                        return Some(Cookie{
                            value: cookie[tag.len()..].to_string(),
                            name: name,
                            domain: None,
                            path: None,
                            max_age: None,
                            secure: false,
                            http_only: false,
                            same_site: None,
                        });
                    }
                }
            }
        }
        None
    }

    pub fn get_value(&self, key: Option<&Key>) -> Result<String, &'static str> {
        if let Some(key) = key {
            key.unseal(&self.name[..], &self.value[..])
        } else {
            let value = base64::decode(&self.value[..]).map_err(|_| "Invalid base64 encoded value.")?;
            ::std::str::from_utf8(&value[..])
                .map(|s| s.to_string())
                .map_err(|_| "Invalid unsealed UTF-8.")
        }
    }

    /// WARNING:
    /// We do not check for Cookie Prefix __HOST validity
    /// where domain attribute is prohibited and path
    /// attribute must be present. If an invalid SetCookie
    /// is created because of this the browser will not
    /// return this cookie and thus silently fail. 
    pub fn get_full_value (&self) -> String {
        (format!("{}", self)).to_string()
    }

    pub fn clear (self) -> Self {
        self.with_max_age(Some(Duration::new(0, 0)))
    }

    pub fn with_max_age(mut self, max_age: Option<Duration>) -> Self {
        self.max_age = max_age;
        self
    }

    pub fn with_domain(mut self, domain: Option<&'d str>) -> Self {
        self.domain = domain;
        self
    }

    pub fn with_path(mut self, path: Option<&'p str>) -> Self {
        self.path = path;
        self
    }

    pub fn with_secure(mut self, secure: bool) -> Self {
        self.secure = secure;
        self
    }

    pub fn with_http_only(mut self, http_only: bool) -> Self {
        self.http_only = http_only;
        self
    }

    pub fn with_same_site(mut self, same_site: Option<SameSite>) -> Self {
        self.same_site = same_site;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_cookie_display() {
        let mut cookie = Cookie::new(Some(CookiePrefix::SECURE), "test name", "test value", None).unwrap()
            .with_domain(Some("example.com"))
            .with_path(Some("/"))
            .with_max_age(Some(Duration::new(5, 0)))
            .with_secure(true)
            .with_http_only(true)
            .with_same_site(Some(SameSite::STRICT));
        assert_eq!(cookie.get_full_value(),"__Secure-test%20name=dGVzdCB2YWx1ZQ==; Domain=example.com; Path=/; Max-Age=5; Secure; HttpOnly; SameSite=Strict");
        cookie = cookie.clear();
        assert_eq!(cookie.get_full_value(),"__Secure-test%20name=dGVzdCB2YWx1ZQ==; Domain=example.com; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict");
    }

    #[test]
    fn test_encrypted_cookie_from_request() {
        // Create Request with cookie
        let master_key = "sVdCPIwy2URfikVQiBH1Z+Jz39mibRG7viq42oYapTA=";
        let key = &(Key::new(Some(master_key)).unwrap());
        let name = "test name";
        let prefix_encoded_name = "__Host-test%20name";
        let value = "Hello World";
        let value_encrypted = key.seal(prefix_encoded_name, value).unwrap();
        let uri = Uri::from_str("https://localhost/").unwrap();
        let mut req = Request::new(Method::Get, uri);
        let mut cookies = header::Cookie::new();
        cookies.append(prefix_encoded_name, value_encrypted);
        {
          let headers = req.headers_mut();
          headers.set(cookies);
        }
        // Create our Cookie from this request
        let cookie = Cookie::from_request(&req, Some(CookiePrefix::HOST), name).unwrap();
        // Test if we can retrieve original plain text value
        assert_eq!(cookie.get_value(Some(key)), Ok(value.to_string()));
    }
}
