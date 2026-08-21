use std::cmp;
use std::convert::TryFrom;
use std::io;
use std::str;
use std::{net::IpAddr, pin::Pin, task::Context, task::Poll};

use ::http::{Method, Uri};
use anyhow::Result;
use async_trait::async_trait;
use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadBuf};

use crate::{
    proxy::*,
    session::{Session, SocksAddr},
};

const BUFFER_SIZE: usize = 1024;
const EOL: [u8; 2] = [13, 10];
const EOH: [u8; 4] = [13, 10, 13, 10];

fn bad_request() -> io::Error {
    io::Error::other("bad request")
}

fn unauthorized() -> io::Error {
    io::Error::other("proxy authentication required")
}

/// Constant-time comparison, so a wrong password cannot be recovered by timing
/// the 407. wireproxy used `subtle.ConstantTimeCompare` here for the same reason.
fn secret_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    // Length is not secret (it leaks through the encoded credential anyway),
    // but the content comparison must not short-circuit.
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

fn split_slice_once(s: &[u8], sep: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    s.windows(sep.len())
        .position(|w| w == sep)
        .map(|loc| (s[..loc].to_vec(), s[loc..].to_vec()))
}

/// Parse destination
impl TryFrom<&Uri> for SocksAddr {
    type Error = io::Error;
    fn try_from(uri: &Uri) -> Result<Self, Self::Error> {
        let (host, port) = (
            uri.host().ok_or(bad_request())?,
            uri.port_u16()
                .or_else(|| match uri.scheme_str() {
                    Some("http") => Some(80),
                    Some("https") => Some(443),
                    _ => None,
                })
                .ok_or(bad_request())?,
        );
        let addr = if let Ok(host) = host.parse::<IpAddr>() {
            SocksAddr::from((host, port))
        } else {
            SocksAddr::try_from((host, port))?
        };
        Ok(addr)
    }
}

/// https://www.rfc-editor.org/rfc/rfc7230#section-5.3
enum TargetFormat {
    Origin,
    Absolute,
    Authority,
    Asterisk,
}

struct RequestHead {
    method: Method,
    uri: Uri,
    version: String,
    headers: Vec<(String, String)>,
    target_format: TargetFormat,
}

impl RequestHead {
    fn parse_request_line(request_line: &[u8]) -> io::Result<(Method, Uri, String)> {
        let mut tokens = str::from_utf8(request_line).unwrap_or("").splitn(3, ' ');
        let method = match Method::try_from(tokens.next().unwrap_or("")) {
            Ok(v) => v,
            Err(_e) => return Err(bad_request()),
        };
        let uri = match Uri::try_from(tokens.next().unwrap_or("")) {
            Ok(v) => v,
            Err(_e) => return Err(bad_request()),
        };
        let version = tokens.next().unwrap_or("HTTP/1.1");
        Ok((method, uri, version.to_string()))
    }

    fn parse_headers(header_lines: &[u8]) -> io::Result<Vec<(String, String)>> {
        let mut headers = Vec::new();
        let lines = str::from_utf8(header_lines).unwrap_or("").split("\r\n");
        for line in lines {
            let (name, value) = match line.split_once(':') {
                Some((n, v)) => (n.trim(), v.trim()),
                None => continue,
            };
            headers.push((name.to_string(), value.to_string()));
        }
        Ok(headers)
    }

    fn get_header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn set_header(&mut self, name: String, value: String) {
        for (i, (n, _v)) in self.headers.iter().enumerate() {
            if n.to_lowercase() == name.to_lowercase() {
                self.headers[i] = (n.clone(), value);
                return;
            }
        }
        self.headers.push((name, value));
    }
}

impl From<RequestHead> for Vec<u8> {
    fn from(v: RequestHead) -> Self {
        let mut head = Vec::new();
        let request_line = format!("{} {} {}\r\n", v.method, v.uri, v.version);
        head.append(&mut request_line.into_bytes());
        for (name, value) in v.headers {
            let header = format!("{}: {}\r\n", name, value);
            head.append(&mut header.into_bytes());
        }
        head.extend_from_slice("\r\n".as_bytes());
        head
    }
}

impl TryFrom<Vec<u8>> for RequestHead {
    type Error = io::Error;
    fn try_from(head: Vec<u8>) -> Result<Self, Self::Error> {
        let (request_line, header) = split_slice_once(&head, &EOL).unwrap_or((head, Vec::new()));
        let (method, uri, version) = RequestHead::parse_request_line(&request_line)?;
        let headers = RequestHead::parse_headers(&header)?;
        let target_format = if uri == "*" {
            TargetFormat::Asterisk
        } else if uri.scheme().is_some() {
            TargetFormat::Absolute
        } else if method == Method::CONNECT {
            TargetFormat::Authority
        } else {
            TargetFormat::Origin
        };
        Ok(RequestHead {
            method,
            uri,
            version,
            headers,
            target_format,
        })
    }
}

struct HttpStream {
    cache: Vec<u8>,
    destination: Option<SocksAddr>,
    origin: AnyStream,
    username: Option<String>,
    password: Option<String>,
}

impl HttpStream {
    async fn sniff(&mut self) -> io::Result<()> {
        let (head_buf, mut rest_buf) = self.drain(&EOH).await?;
        let mut head = RequestHead::try_from(head_buf)?;

        self.authenticate(&head).await?;

        let addr = SocksAddr::try_from(&head.uri)?;
        self.destination = Some(addr.clone());

        match head.target_format {
            TargetFormat::Absolute => {
                // drain() returns (before EOH, starting at EOH). To avoid duplicating
                // the CRLFCRLF boundary when we rebuild headers below, drop the
                // leading EOH from the remainder.
                if rest_buf.starts_with(&EOH) {
                    let _ = rest_buf.drain(..EOH.len());
                }
                let path_and_query = head
                    .uri
                    .path_and_query()
                    .map(|paq| paq.as_str())
                    .unwrap_or("/");
                head.uri = path_and_query.parse().unwrap();
                head.set_header("host".to_string(), addr.to_string());
                self.cache.clear();
                self.cache.append(&mut head.into());
                self.cache.append(&mut rest_buf);
                Ok(())
            }
            TargetFormat::Authority => {
                self.origin
                    .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .await?;
                Ok(())
            }
            _ => Err(bad_request()),
        }
    }

    /// RFC 7235 Basic proxy auth. A no-op when no credentials are configured,
    /// which keeps the existing unauthenticated behaviour intact.
    async fn authenticate(&mut self, head: &RequestHead) -> io::Result<()> {
        let (Some(username), Some(password)) = (self.username.as_ref(), self.password.as_ref())
        else {
            return Ok(());
        };

        let presented = head
            .get_header("proxy-authorization")
            .and_then(|v| v.trim().strip_prefix("Basic ").map(str::trim))
            .and_then(|b64| {
                base64::engine::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    b64.as_bytes(),
                )
                .ok()
            })
            .and_then(|raw| String::from_utf8(raw).ok());

        let ok = match presented.as_deref().and_then(|c| c.split_once(':')) {
            Some((u, p)) => secret_eq(u, username) && secret_eq(p, password),
            None => false,
        };

        if ok {
            return Ok(());
        }

        // Challenge the client rather than dropping the connection, so a proxy
        // client can retry with credentials.
        let _ = self
            .origin
            .write_all(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                  Proxy-Authenticate: Basic realm=\"Proxy\"\r\n\
                  Content-Length: 0\r\n\
                  Connection: close\r\n\r\n",
            )
            .await;
        Err(unauthorized())
    }

    async fn drain(&mut self, stop_sign: &[u8]) -> io::Result<(Vec<u8>, Vec<u8>)> {
        let mut data = Vec::new();
        let mut buf = BytesMut::with_capacity(BUFFER_SIZE);
        loop {
            buf.clear();
            let n = self.origin.read_buf(&mut buf).await?;
            data.extend_from_slice(&buf[..n]);
            match split_slice_once(&data, stop_sign) {
                Some(v) => return Ok(v),
                None => continue,
            }
        }
    }
}

impl AsyncRead for HttpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.cache.is_empty() {
            let n = cmp::min(buf.capacity(), self.cache.len());
            let cached_data = self.cache.drain(..n);
            buf.put_slice(cached_data.as_slice());
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.origin).poll_read(cx, buf)
    }
}

impl AsyncWrite for HttpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.origin).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.origin).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.origin).poll_shutdown(cx)
    }
}

pub struct Handler {
    pub username: Option<String>,
    pub password: Option<String>,
}

#[async_trait]
impl InboundStreamHandler for Handler {
    async fn handle<'a>(
        &'a self,
        mut sess: Session,
        stream: AnyStream,
    ) -> std::io::Result<AnyInboundTransport> {
        tracing::trace!("handling inbound stream");
        let mut http_stream = HttpStream {
            cache: Vec::new(),
            destination: None,
            origin: stream,
            username: self.username.clone(),
            password: self.password.clone(),
        };
        http_stream.sniff().await?;

        sess.destination = http_stream.destination.clone().ok_or(bad_request())?;

        Ok(InboundTransport::Stream(Box::new(http_stream), sess))
    }
}
