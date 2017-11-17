use std::fs::{self, File};
use std::io::{Read, ErrorKind as IoErrorKind};
use std::time;
use futures::{Future, Stream, Sink, Poll, Async, future};
use futures::sync::mpsc::SendError;
use hyper;
use hyper::{Chunk, StatusCode, Body, header};
use hyper::server::Response;
use tokio_core::reactor::Handle;

/// A stream that produces Hyper chunks from a file.
struct FileChunkStream(File);
impl Stream for FileChunkStream {
    type Item = Result<Chunk, hyper::Error>;
    type Error = SendError<Self::Item>;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        // TODO: non-blocking read
        // uninitialized would be faster:
        //   let mut buf: [u8; 16384] = unsafe { mem::uninitialized() };
        // but don't want to use unsafe rust
        let mut buf: [u8; 16384] = [0; 16384];
        match self.0.read(&mut buf) {
            Ok(0) => Ok(Async::Ready(None)),
            Ok(size) => Ok(Async::Ready(Some(Ok(
                Chunk::from(buf[0..size].to_owned())
            )))),
            Err(err) => Ok(Async::Ready(Some(Err(hyper::Error::Io(err))))),
        }
    }
}

/// Serving up a static file as Hyper Chunks.
///
/// This service serves files from a single filesystem path, which may be absolute or relative.
/// Incoming requests are mapped onto the filesystem by appending their URL path to the service
/// root path. If the filesystem path corresponds to a regular file, the service will attempt to
/// serve it.
///
/// If the path doesn't match any real object in the filesystem, the service will respond with
/// a 404.
///
/// Permission errors responde with a 403.
///
/// If an IO error occurs whilst attempting to serve a file, `hyper::Error(Io)` will be returned.
/// path should already be normalized via normalize_req_path function
pub fn serve(handle: Handle, method_head: bool, modified_req: Option<&header::HttpDate>, path: &str, res: Response) -> future::FutureResult<hyper::Response, hyper::Error> {
    // Do not return directory structures.
    if path.len() == 0 {
        return future::ok(res.with_status(StatusCode::Forbidden))
    }

    let metadata = match fs::metadata(path) {
        Ok(meta) => meta,
        Err(e) => {
            return match e.kind() {
                IoErrorKind::NotFound => future::ok(res.with_status(StatusCode::NotFound)),
                IoErrorKind::PermissionDenied => future::ok(res.with_status(StatusCode::Forbidden)),
                _ => future::err(hyper::Error::Io(e)),
            };
        },
    };
    if !metadata.is_file() {
        return future::ok(res.with_status(StatusCode::NotFound));
    }

    // Check If-Modified-Since header.
    let modified = match metadata.modified() {
        Ok(time) => time,
        Err(err) => return future::err(hyper::Error::Io(err)),
    };

    let modified_http = header::HttpDate::from(modified);
    if let Some(http_date) = modified_req {
        if modified_http <= *http_date {
            return future::ok(res.with_status(StatusCode::NotModified));
        }
    }

    // Build response headers.
    let mut res = res.with_header(header::ContentLength(metadata.len()))
        .with_header(header::LastModified(modified_http));
    if let Ok(delta_modified) = modified.duration_since(time::UNIX_EPOCH) {
        let size = metadata.len();
        let etag = format!("{0:x}-{1:x}.{2:x}", size, delta_modified.as_secs(), delta_modified.subsec_nanos());
        res = res.with_header(header::ETag(header::EntityTag::weak(etag)));
    }

    // Stream response body.
   if method_head {
        {}
   } else {
        let file = match File::open(path) {
            Ok(file) => file,
            Err(err) => return future::err(hyper::Error::Io(err)),
        };
        let (sender, body) = Body::pair();
        handle.spawn(
            sender.send_all(FileChunkStream(file))
                .map(|_| ())
                .map_err(|_| ())
        );
        res.set_body(body);
    }

    future::ok(res)
}
