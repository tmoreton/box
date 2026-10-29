//! The upstream side of one exchange: TLS to the pinned upstream, and hyper's HTTP/1.1 client.

use std::cell::Cell;
use std::io;
use std::net::TcpStream;
use std::pin::Pin;
use std::task::{Context, Poll, Waker, ready};

use http_body_util::Empty;
use hyper::Request;
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, timeout_at};
use tokio_rustls::TlsConnector;

use super::SharedState;
use super::http1::{self, HeaderCase};
use super::socket::{self, Counted, MAX_HEAD_BYTES, Socket, WriteCount};
use crate::boundary::InterceptedResponse;
use crate::effect::EffectOutcome;
use crate::error::{ProxyError, Result};

/// The pinned upstream socket, and the deadline of the one exchange on it.
pub(super) struct Upstream {
    socket: TcpStream,
    /// The name to verify, when the exchange runs inside TLS.
    tls: Option<ServerName<'static>>,
    deadline: Instant,
}

/// Why an exchange produced no response head, and the I/O kind its request outcome records.
type NoResponse = (io::ErrorKind, ProxyError);

impl Upstream {
    /// The listener already opened this exact pinned socket under the Connect lifecycle. A TLS
    /// handshake failure is a hard-fail drop, never a second socket attempt.
    pub(super) fn new(
        socket: TcpStream,
        tls: Option<ServerName<'static>>,
        state: &SharedState,
    ) -> Self {
        Self {
            socket,
            tls,
            deadline: Instant::now() + state.config.upstream_read_deadline,
        }
    }

    /// Whether the exchange runs inside TLS. Only a CONNECT tunnel does, and it is also the only
    /// path whose plaintext the gateway saw through TLS interception.
    pub(super) fn is_tls(&self) -> bool {
        self.tls.is_some()
    }

    /// Send a request for `method`, serialized as `head` and `body`, and read the whole response
    /// before the deadline. Returns the request's outcome and the response.
    pub(super) async fn send(
        self,
        state: &SharedState,
        method: &str,
        head: &[u8],
        body: &[u8],
    ) -> (EffectOutcome, Result<(InterceptedResponse, HeaderCase)>) {
        let Self {
            socket,
            tls,
            deadline,
        } = self;
        let writes = WriteCount::default();
        let status = Cell::new(None);
        let max_body = state.config.response_limits.max_body_bytes;
        let exchange = async {
            let lost = |what: &str, error: io::Error| {
                (error.kind(), ProxyError::Io(format!("{what}: {error}")))
            };
            let tcp = socket
                .into_async()
                .map_err(|e| lost("upstream socket", e))?;
            let request = (method, head, body);
            match tls {
                None => round_trip(tcp, &writes, request, &status, max_body).await,
                Some(name) => {
                    let tls = TlsConnector::from(state.upstream_config.clone())
                        .connect(name, tcp)
                        .await
                        .map_err(|e| lost("upstream TLS handshake", e))?;
                    round_trip(tls, &writes, request, &status, max_body).await
                }
            }
        };
        let (kind, response) = match timeout_at(deadline, exchange).await {
            Ok(Ok(response)) => (None, Ok(response)),
            Ok(Err((kind, error))) => (Some(kind), Err(error)),
            Err(_) => (
                Some(io::ErrorKind::TimedOut),
                Err(ProxyError::Io("upstream deadline passed".to_string())),
            ),
        };
        let outcome = match status.get() {
            Some(status) => EffectOutcome::Replied {
                accepted_bytes: writes.get().accepted,
                status,
            },
            None => writes.get().outcome(0, kind),
        };
        (outcome, response)
    }
}

/// Send `request` (its method, head, and body) on `upstream` through hyper, and read the response.
///
/// hyper encodes a request head into a buffer that it never wipes, and one header may hold the
/// operator's real secret. So hyper gets a stand-in that names only the method, which hyper needs
/// to read the response, and [`Prepared`] sends the box's own serialization in its place.
async fn round_trip<S>(
    upstream: S,
    writes: &WriteCount,
    (method, head, body): (&str, &[u8], &[u8]),
    status: &Cell<Option<u16>>,
    max_body: usize,
) -> std::result::Result<(InterceptedResponse, HeaderCase), NoResponse>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let lost = |error: hyper::Error| {
        let kind = socket::error_kind(&error);
        (kind, ProxyError::Io(format!("upstream exchange: {error}")))
    };
    let stand_in = Request::builder()
        .method(method)
        .uri("/")
        .body(Empty::<Bytes>::new())
        .map_err(|e| {
            let error = ProxyError::Intercept(format!("upstream request: {e}"));
            (io::ErrorKind::InvalidInput, error)
        })?;
    let upstream = Prepared::new(Counted::new(upstream, writes.clone(), None), head, body);
    let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
        .preserve_header_case(true)
        .max_headers(64)
        .max_buf_size(MAX_HEAD_BYTES)
        .handshake(TokioIo::new(upstream))
        .await
        .map_err(lost)?;
    let exchange = async move {
        let response = sender.send_request(stand_in).await.map_err(lost)?;
        status.set(Some(response.status().as_u16()));
        http1::read_response(response, max_body)
            .await
            .map_err(|error| (io::ErrorKind::Other, error))
    };
    // hyper's connection moves the bytes. It runs until the response has been read; then the
    // exchange is over, and dropping it closes the upstream.
    let connection = async {
        let _ = connection.await;
        std::future::pending::<()>().await
    };
    tokio::select! {
        response = exchange => response,
        () = connection => unreachable!("the connection future never completes"),
    }
}

/// The upstream stream that sends the box's own request bytes in place of hyper's stand-in.
///
/// The first write sends the whole of `head` and `body`, flushes them, then reports hyper's bytes
/// as written. Nothing is read until then, for two reasons: the outcome counts a request that left
/// whole, and hyper treats bytes that arrive while it thinks the connection is idle as
/// an error.
struct Prepared<'a, S> {
    inner: S,
    head: &'a [u8],
    body: &'a [u8],
    sent: usize,
    flushed: bool,
    reader: Option<Waker>,
}

impl<'a, S> Prepared<'a, S> {
    fn new(inner: S, head: &'a [u8], body: &'a [u8]) -> Self {
        Self {
            inner,
            head,
            body,
            sent: 0,
            flushed: false,
            reader: None,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prepared<'_, S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.flushed {
            this.reader = Some(cx.waker().clone());
            return Poll::Pending;
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prepared<'_, S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        stand_in: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        while !this.flushed {
            let rest = match this.sent.checked_sub(this.head.len()) {
                None => &this.head[this.sent..],
                Some(at) => &this.body[at..],
            };
            if rest.is_empty() {
                ready!(Pin::new(&mut this.inner).poll_flush(cx))?;
                this.flushed = true;
                if let Some(reader) = this.reader.take() {
                    reader.wake();
                }
                break;
            }
            let written = ready!(Pin::new(&mut this.inner).poll_write(cx, rest))?;
            if written == 0 {
                return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
            }
            this.sent += written;
        }
        Poll::Ready(Ok(stand_in.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const HEAD: &[u8] =
        b"POST /v1 HTTP/1.1\r\nAuthorization: Bearer real\r\nConnection: close\r\nContent-Length: 2\r\n\r\n";

    /// The result of one exchange.
    type Exchange = std::result::Result<(InterceptedResponse, HeaderCase), NoResponse>;

    /// Run one exchange against an upstream that reads the request, answers `response`, and
    /// closes. Returns what the upstream read, the result, the status, and the accepted bytes.
    fn answered_with(response: &[u8]) -> (Vec<u8>, Exchange, Option<u16>, usize) {
        socket::block_on(async {
            let (gateway, mut upstream) = tokio::io::duplex(256 * 1024);
            let status = Cell::new(None);
            let writes = WriteCount::default();
            let server = async {
                let mut seen = vec![0u8; HEAD.len() + 2];
                upstream.read_exact(&mut seen).await.unwrap();
                let _ = upstream.write_all(response).await;
                let _ = upstream.shutdown().await;
                let mut rest = Vec::new();
                let _ = upstream.read_to_end(&mut rest).await;
                seen.extend(rest);
                seen
            };
            let client = round_trip(gateway, &writes, ("POST", HEAD, b"ok"), &status, 1024);
            let (result, seen) = tokio::join!(client, server);
            (seen, result, status.get(), writes.get().accepted)
        })
        .unwrap()
    }

    /// The upstream receives the box's bytes and never hyper's stand-in.
    #[test]
    fn the_upstream_receives_the_box_bytes_not_the_stand_in() {
        let (seen, result, status, accepted) =
            answered_with(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nyes");
        assert_eq!(seen, [HEAD, b"ok"].concat(), "exactly the box's bytes");
        assert_eq!(accepted, HEAD.len() + 2);
        assert_eq!(status, Some(200));
        assert_eq!(result.unwrap().0.body, b"yes");
    }

    #[test]
    fn a_response_that_fails_after_its_head_keeps_its_status() {
        let (_, result, status, _) =
            answered_with(b"HTTP/1.1 500 Internal\r\nContent-Length: 100\r\n\r\nshort");
        assert!(result.is_err());
        assert_eq!(status, Some(500));

        let (_, result, status, _) = answered_with(b"HTTP/1.1 5");
        assert!(result.is_err());
        assert_eq!(status, None);
    }

    #[test]
    fn an_upgrade_response_is_refused() {
        let (_, result, _, _) = answered_with(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: upgrade\r\n\r\n",
        );
        assert!(result.is_err());
    }

    /// hyper checks its buffer limit before each read, and one read can fill the buffer's spare
    /// capacity, so a head can pass [`MAX_HEAD_BYTES`] by up to one read. Twice the limit is
    /// refused.
    #[test]
    fn an_oversized_response_head_is_refused() {
        let mut response = b"HTTP/1.1 200 OK\r\nX-Big: ".to_vec();
        response.extend(std::iter::repeat_n(b'a', 2 * MAX_HEAD_BYTES));
        response.extend_from_slice(b"\r\nContent-Length: 0\r\n\r\n");
        let (_, result, status, _) = answered_with(&response);
        assert!(result.is_err());
        assert_eq!(status, None);
    }

    /// hyper keeps every framing header of a response, so the box's rules see them and refuse.
    #[test]
    fn a_response_that_states_two_framings_is_refused() {
        for response in [
            &b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n"[..],
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\nok",
        ] {
            let (_, result, status, _) = answered_with(response);
            assert!(matches!(result, Err((_, ProxyError::Intercept(_)))));
            assert_eq!(status, Some(200));
        }
    }
}
