use hyper::StatusCode;
use hyper::server::Request;

#[derive(Debug)]
pub struct Context {
  pub proctor: Option<String>,
  pub id: Option<String>,
  pub status_code: StatusCode,
  pub req: Request,
}
