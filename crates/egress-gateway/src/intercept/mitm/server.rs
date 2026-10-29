//! The workload side: hyper reads every HTTP message the workload sends, and writes every answer.

use std::cell::Cell;
use std::future::Future;
use std::net::TcpStream;
use std::sync::Arc;

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::header::{HeaderName, HeaderValue, PROXY_AUTHORIZATION};
use hyper::upgrade::OnUpgrade;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsAcceptor;

use super::connect::{self, ConnectRequest};
use super::http1;
use super::l7::{self, WorkloadResponse};
use super::listener::open_governed_upstream;
use super::socket::{self, Counted, HeadCopy, MAX_HEAD_BYTES, Socket, WriteCount};
use super::{SharedState, tls};
use crate::audit::RequestId;
use crate::error::{ProxyError, Result};

/// Serve one accepted connection: its first request, and the requests inside a CONNECT tunnel.
///
/// `connect_only` refuses a plain-HTTP request, for the AF_UNIX transport, which has no plain-HTTP
/// client.
pub(super) fn serve_connection<C: Socket>(
    client: C,
    state: &SharedState,
    connect_only: bool,
) -> Result<()> {
    socket::block_on(async {
        let client = client
            .into_async()
            .map_err(|e| ProxyError::Io(format!("client socket: {e}")))?;
        let tunnel = Cell::new(None);
        serve(client, |request, head| {
            first_request(request, head, state, connect_only, &tunnel)
        })
        .await?;
        match tunnel.take() {
            Some(tunnel) => intercept_tls(tunnel, state).await,
            None => Ok(()),
        }
    })?
}

/// A CONNECT the gateway admitted: the workload's side waits for the upgrade, and the upstream is
/// already open.
struct Tunnel {
    upgrade: OnUpgrade,
    connect: ConnectRequest,
    upstream: TcpStream,
    correlation: RequestId,
}

/// Answer the first request on a connection: a CONNECT, or a plain-HTTP absolute-form request.
async fn first_request(
    mut request: Request<Incoming>,
    head: Vec<u8>,
    state: &SharedState,
    connect_only: bool,
    tunnel: &Cell<Option<Tunnel>>,
) -> Result<WorkloadResponse> {
    // The proxy token, read before `read_request` strips `Proxy-Authorization` (a hop-by-hop
    // header).
    let token = request
        .headers()
        .get(PROXY_AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_string());
    if request.method() == Method::CONNECT {
        let Some((host, port)) = request
            .uri()
            .authority()
            .and_then(|authority| connect::parse_authority(authority.as_str(), None))
        else {
            return Ok(WorkloadResponse::bare(400));
        };
        let connect = ConnectRequest { host, port };
        let correlation = RequestId::unique();
        // Claimed and opened BEFORE the CONNECT ack, so a denial returns 403 without creating a
        // socket or exposing a false tunnel.
        let upstream = match admit(state, &connect, token.as_deref(), &correlation) {
            Ok(upstream) => upstream,
            Err(refusal) => return Ok(refusal),
        };

        // Every connection is terminated and inspected. There is no un-inspected path: a
        // connection whose plaintext the boundary cannot see could not raise `http:request`, so it
        // would be exempt from the request authorization and would carry no credential decision
        // either.
        //
        // The two decisions are `net:connect` and `http:request`. The response leg takes **no
        // decision**: `policy`'s egress adapter matches `ResponseRelease` and returns `Ok(())`, so
        // a rule cannot refuse a release or budget on a response size. The response reaches history
        // once, on the request permit, as `output.status` of the one `http:request::response` an
        // exchange records. The gateway would honour a refusal there and withhold the bytes; the
        // shipped interceptor never issues one.
        //
        // A handshake or pin failure hard-fails (drop), never a downgrade.
        tunnel.set(Some(Tunnel {
            upgrade: hyper::upgrade::on(&mut request),
            connect,
            upstream,
            correlation,
        }));
        // The upstream is open and its outcome was recorded; now let the client proceed.
        return Ok(WorkloadResponse::connected());
    }
    if connect_only {
        return Ok(WorkloadResponse::bare(400));
    }

    // A workload dialing an `http://` URL through the proxy sends an absolute-form request rather
    // than a CONNECT. The same controls run as on the CONNECT path — `net:connect`, then the L7
    // legs over plaintext (`http:request` + credential injection). There is no TLS termination and
    // no CONNECT ack.
    let max_body = state.config.response_limits.max_body_bytes;
    let Ok(parsed) = http1::read_request(&head, request.into_body(), max_body).await else {
        return Ok(WorkloadResponse::bare(400));
    };
    // Absolute-form only: a plain-HTTP proxy request names the full URL. An origin-form target
    // with no CONNECT has no destination and is refused.
    let Some((host, port, origin_target)) = connect::parse_absolute_target(&parsed.target) else {
        return Ok(WorkloadResponse::bare(400));
    };
    let connect = ConnectRequest { host, port };
    let correlation = RequestId::unique().with_headers(&parsed.headers);
    // A plain-HTTP proxy request may carry `Proxy-Authorization` too (RFC 7235), so the token
    // check runs on this transport as well.
    let upstream = match admit(state, &connect, token.as_deref(), &correlation) {
        Ok(upstream) => upstream,
        Err(refusal) => return Ok(refusal),
    };
    // Run the L7 legs over plaintext, reusing request_leg/response_leg/effects.
    l7::forward_plain(
        upstream,
        &connect,
        parsed,
        origin_target,
        state,
        correlation,
    )
    .await
}

/// The checks before any upstream socket, the same for both request shapes: the best-effort token
/// check (never the primary defense), then the shared L4 controls — the pre-resolution
/// `net:connect`, resolve-once/pin, and the per-address `net:connect` effect.
fn admit(
    state: &SharedState,
    connect: &ConnectRequest,
    token: Option<&str>,
    correlation: &RequestId,
) -> std::result::Result<TcpStream, WorkloadResponse> {
    if !connect::token_ok(state.config.expected_token.as_deref(), token) {
        return Err(WorkloadResponse::bare(407));
    }
    open_governed_upstream(state, connect, correlation).map_err(|error| error.response())
}

/// Terminate the workload's TLS inside an admitted tunnel, and serve the request it carries.
async fn intercept_tls(tunnel: Tunnel, state: &SharedState) -> Result<()> {
    // --- Server side: present a per-host leaf to the workload ---
    let server_config = tls::server_config_for_host(&state.ca, &tunnel.connect.host)?;
    let raw = tunnel
        .upgrade
        .await
        .map_err(|e| ProxyError::Io(format!("CONNECT upgrade: {e}")))?;
    let client = TlsAcceptor::from(Arc::new(server_config))
        .accept(TokioIo::new(raw))
        .await
        .map_err(|e| ProxyError::Intercept(format!("server TLS handshake: {e}")))?;
    let Tunnel {
        connect,
        upstream,
        correlation,
        ..
    } = tunnel;
    serve(client, |request, head| async move {
        let max_body = state.config.response_limits.max_body_bytes;
        let parsed = http1::read_request(&head, request.into_body(), max_body).await?;
        l7::forward_tls(parsed, upstream, &connect, state, correlation).await
    })
    .await
}

/// Serve the one request on `client` with hyper, answer it with `handle`'s [`WorkloadResponse`],
/// and record the release outcome once hyper has written that response. `handle` also gets the
/// raw head, as the workload sent it.
async fn serve<S, H, F>(client: S, handle: H) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    H: FnOnce(Request<Incoming>, Vec<u8>) -> F,
    F: Future<Output = Result<WorkloadResponse>>,
{
    let writes = WriteCount::default();
    let head = HeadCopy::default();
    let stream = Counted::new(client, writes.clone(), Some(head.clone()));
    let handle = Cell::new(Some(handle));
    let release = Cell::new(None);
    let (handle, release, writes, head) = (&handle, &release, &writes, &head);
    let service = hyper::service::service_fn(move |request| async move {
        let handle = handle
            .take()
            .ok_or_else(|| ProxyError::Intercept("one request per connection".to_string()))?;
        let head = head
            .take()
            .ok_or_else(|| ProxyError::Intercept("HTTP head exceeds limit".to_string()))?;
        let mut response = handle(request, head).await?;
        if let Some(permit) = response.release.take() {
            release.set(Some((permit, writes.get().accepted)));
        }
        Ok::<_, ProxyError>(hyper_response(response))
    });
    let served = hyper::server::conn::http1::Builder::new()
        .keep_alive(false)
        .half_close(true)
        .auto_date_header(false)
        .max_headers(64)
        .max_buf_size(MAX_HEAD_BYTES)
        .serve_connection(TokioIo::new(stream), service)
        .with_upgrades()
        .await;
    if let Some((permit, start)) = release.take() {
        let error = served.as_ref().err().map(|error| socket::error_kind(error));
        permit
            .record_outcome(writes.get().outcome(start, error))
            .map_err(|error| {
                ProxyError::Io(format!(
                    "recording governed response outcome after I/O: {error}"
                ))
            })?;
    }
    served.map_err(|error| ProxyError::Io(format!("serving the workload: {error}")))
}

/// The response as hyper writes it. hyper frames a body itself, so a stale length is dropped. An
/// empty body keeps the stated length, which hyper writes only for a `HEAD` response.
fn hyper_response(response: WorkloadResponse) -> Response<Full<Bytes>> {
    let keep_length = response.body.is_empty() && response.status != 204;
    let mut out = Response::new(Full::new(Bytes::from(response.body)));
    *out.status_mut() = StatusCode::from_u16(response.status).unwrap_or(StatusCode::BAD_GATEWAY);
    *out.extensions_mut() = response.header_case;
    if let Some(reason) = response.reason {
        out.extensions_mut()
            .insert(hyper::ext::ReasonPhrase::from_static(reason.as_bytes()));
    }
    for (name, value) in response.headers.iter() {
        if name.eq_ignore_ascii_case("content-length") && !keep_length {
            continue;
        }
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_bytes(value.as_bytes()),
        ) {
            out.headers_mut().append(name, value);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boundary::HeaderMap;

    fn response(status: u16, body: &[u8]) -> WorkloadResponse {
        let mut headers = HeaderMap::new();
        headers.set("Content-Length", "42");
        WorkloadResponse {
            status,
            reason: None,
            headers,
            body: body.to_vec(),
            release: None,
            header_case: http1::HeaderCase::new(),
        }
    }

    /// A body drops the stale length, an empty body keeps the length a `HEAD` response states, and
    /// a `204` keeps none.
    #[test]
    fn an_empty_body_keeps_the_stated_length() {
        let length = |status, body: &[u8]| {
            hyper_response(response(status, body))
                .headers()
                .get("content-length")
                .map(|value| value.to_str().unwrap().to_string())
        };
        assert_eq!(length(200, b"").as_deref(), Some("42"));
        assert_eq!(length(200, b"abc"), None);
        assert_eq!(length(204, b""), None);
    }

    /// A refusal the gateway writes names its marker in lowercase, and a bare refusal keeps the
    /// gateway's own reason phrase.
    #[test]
    fn a_refusal_keeps_the_gateway_bytes() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let written = |response: fn() -> WorkloadResponse| {
            socket::block_on(async {
                let (mut workload, gateway) = tokio::io::duplex(4096);
                let server = serve(gateway, |_, _| async move { Ok(response()) });
                let client = async {
                    workload
                        .write_all(b"GET / HTTP/1.1\r\nHost: h\r\n\r\n")
                        .await
                        .unwrap();
                    let mut out = Vec::new();
                    workload.read_to_end(&mut out).await.unwrap();
                    String::from_utf8(out).unwrap()
                };
                tokio::join!(server, client).1
            })
            .unwrap()
        };
        let refusal = written(|| WorkloadResponse::refusal(403, b"no"));
        assert!(
            refusal.starts_with("HTTP/1.1 403 Forbidden\r\n"),
            "{refusal}"
        );
        assert!(
            refusal.contains("\r\nx-strands-box-egress: refused\r\n"),
            "{refusal}"
        );
        let bare = written(|| WorkloadResponse::bare(400));
        assert!(bare.starts_with("HTTP/1.1 400 bad request\r\n"), "{bare}");
    }
}
