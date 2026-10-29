//! The sockets of one connection: its runtime, the async sockets, and what each socket accepted.

use std::future::Future;
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::effect::EffectOutcome;
use crate::error::{ProxyError, Result};

/// Run `future` on a runtime that serves this one connection, on the connection's own thread.
///
/// A synchronous policy call inside `future` therefore blocks this connection and no other, and
/// each decision and its record stay on one thread.
pub(super) fn block_on<F: Future>(future: F) -> Result<F::Output> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|e| ProxyError::Io(format!("connection runtime: {e}")))?;
    Ok(runtime.block_on(future))
}

/// A blocking socket from the accept loop, made async inside the connection's runtime.
pub(super) trait Socket {
    type Async: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    fn into_async(self) -> io::Result<Self::Async>;
}

impl Socket for std::net::TcpStream {
    type Async = tokio::net::TcpStream;

    fn into_async(self) -> io::Result<Self::Async> {
        self.set_nonblocking(true)?;
        tokio::net::TcpStream::from_std(self)
    }
}

impl Socket for std::os::unix::net::UnixStream {
    type Async = tokio::net::UnixStream;

    fn into_async(self) -> io::Result<Self::Async> {
        self.set_nonblocking(true)?;
        tokio::net::UnixStream::from_std(self)
    }
}

/// What one stream accepted for writing, and how its writes ended.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Writes {
    /// Bytes the stream accepted.
    pub(super) accepted: usize,
    /// Whether a flush succeeded after the last accepted byte.
    flushed: bool,
    /// The first write or flush error, and whether it came from a flush.
    failure: Option<(io::ErrorKind, bool)>,
}

impl Writes {
    /// The outcome of a message whose first byte was accepted at `start`, for an exchange that
    /// ended with `error`, or cleanly.
    ///
    /// A message flushed whole is completed, whatever failed after it. A failed flush is
    /// indeterminate. A message that stopped short is failed or partial, with the write error, else
    /// with the error that ended the exchange.
    pub(super) fn outcome(self, start: usize, error: Option<io::ErrorKind>) -> EffectOutcome {
        let accepted_bytes = self.accepted.saturating_sub(start);
        let short = match (self.failure, error) {
            (Some((_, true)), _) => return EffectOutcome::Indeterminate { accepted_bytes },
            (Some((kind, false)), _) => kind,
            (None, Some(kind)) if !self.flushed => kind,
            (None, _) => return EffectOutcome::Completed(accepted_bytes),
        };
        if accepted_bytes == 0 {
            EffectOutcome::Failed {
                accepted_bytes,
                error_kind: short,
            }
        } else {
            EffectOutcome::Partial {
                accepted_bytes,
                error_kind: short,
            }
        }
    }
}

/// The [`Writes`] of one stream, shared by the stream and the exchange that reads them.
#[derive(Clone, Debug, Default)]
pub(super) struct WriteCount(Arc<Mutex<Writes>>);

impl WriteCount {
    pub(super) fn get(&self) -> Writes {
        *self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn note<T>(&self, result: &io::Result<T>, accepted: usize, flush: bool) {
        let mut writes = self.0.lock().unwrap_or_else(|e| e.into_inner());
        match result {
            Ok(_) if flush => writes.flushed = true,
            Ok(_) if accepted > 0 => {
                writes.accepted += accepted;
                writes.flushed = false;
            }
            Ok(_) => {}
            Err(error) => {
                writes.failure.get_or_insert((error.kind(), flush));
            }
        }
    }
}

/// The raw head of the first request that one stream read, shared by the stream and the exchange.
///
/// hyper drops a `Content-Length` that a `Transfer-Encoding` overrides, and a repeated equal
/// length, before the box sees the head. The box refuses a message that states more than one
/// framing, so it judges the head as the workload sent it. The copy ends where `httparse`, hyper's
/// parser, ends the head.
#[derive(Clone, Debug, Default)]
pub(super) struct HeadCopy(Arc<Mutex<Head>>);

#[derive(Debug, Default)]
struct Head {
    bytes: Vec<u8>,
    /// `Some(true)` once the head is whole within [`MAX_HEAD_BYTES`]; `Some(false)` once it is not.
    whole: Option<bool>,
}

impl HeadCopy {
    /// Take the head, or `None` when it passed [`MAX_HEAD_BYTES`]. hyper checks its own limit only
    /// before each read, so a head can pass it by one read; the box's limit is exact.
    pub(super) fn take(&self) -> Option<Vec<u8>> {
        let mut head = self.0.lock().unwrap_or_else(|e| e.into_inner());
        (head.whole == Some(true)).then(|| std::mem::take(&mut head.bytes))
    }

    /// Copy `bytes`, and report whether the head is done.
    fn note(&self, bytes: &[u8]) -> bool {
        let mut head = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if head.whole.is_some() {
            return true;
        }
        let from = head.bytes.len().saturating_sub(2);
        head.bytes.extend_from_slice(bytes);
        // Parse only when the new bytes can end a head, as hyper does.
        let blank_line = head.bytes[from..]
            .windows(2)
            .any(|pair| pair == b"\n\n" || pair == b"\n\r");
        if blank_line {
            let mut fields = [httparse::EMPTY_HEADER; 64];
            if let Ok(httparse::Status::Complete(end)) =
                httparse::Request::new(&mut fields).parse(&head.bytes)
            {
                head.bytes.truncate(end);
                head.whole = Some(end <= MAX_HEAD_BYTES);
                return true;
            }
        }
        if head.bytes.len() > MAX_HEAD_BYTES {
            head.whole = Some(false);
        }
        head.whole.is_some()
    }
}

/// The largest head the box reads from the workload, exactly. On the upstream side it is hyper's
/// buffer limit, which a head can pass by up to one read.
pub(super) const MAX_HEAD_BYTES: usize = 64 * 1024;

/// A stream that counts what it accepts for writing, and can keep a copy of the first head it
/// reads.
pub(super) struct Counted<S> {
    inner: S,
    writes: WriteCount,
    head: Option<HeadCopy>,
}

impl<S> Counted<S> {
    pub(super) fn new(inner: S, writes: WriteCount, head: Option<HeadCopy>) -> Self {
        Self {
            inner,
            writes,
            head,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Counted<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let result = ready!(Pin::new(&mut this.inner).poll_read(cx, buf));
        if let Some(head) = &this.head
            && head.note(&buf.filled()[before..])
        {
            this.head = None;
        }
        Poll::Ready(result)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counted<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = ready!(Pin::new(&mut this.inner).poll_write(cx, buf));
        this.writes
            .note(&result, *result.as_ref().unwrap_or(&0), false);
        Poll::Ready(result)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = ready!(Pin::new(&mut this.inner).poll_write_vectored(cx, bufs));
        this.writes
            .note(&result, *result.as_ref().unwrap_or(&0), false);
        Poll::Ready(result)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = ready!(Pin::new(&mut this.inner).poll_flush(cx));
        this.writes.note(&result, 0, true);
        Poll::Ready(result)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// The kind of the first I/O error in `error`'s chain.
pub(super) fn error_kind(error: &(dyn std::error::Error + 'static)) -> io::ErrorKind {
    let mut source = Some(error);
    while let Some(error) = source {
        if let Some(error) = error.downcast_ref::<io::Error>() {
            return error.kind();
        }
        source = error.source();
    }
    io::ErrorKind::Other
}

#[cfg(test)]
mod tests {
    use super::*;

    fn writes(accepted: usize, flushed: bool, failure: Option<(io::ErrorKind, bool)>) -> Writes {
        Writes {
            accepted,
            flushed,
            failure,
        }
    }

    #[test]
    fn the_head_copy_ends_where_httparse_ends_the_head() {
        let head = HeadCopy::default();
        assert!(!head.note(b"POST / HTTP/1.1\r\nContent-Length: 4\r"));
        assert!(!head.note(b"\nTransfer-Encoding: chunked\r\n\r"));
        assert!(head.note(b"\nbody"));
        assert_eq!(
            head.take().unwrap(),
            b"POST / HTTP/1.1\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n"
        );

        // Blank lines before the request line are part of the head, as hyper's parser skips them.
        let leading = HeadCopy::default();
        leading.note(b"\r\n\r\nGET / HTTP/1.1\r\nHost: h\r\n\r\nrest");
        assert_eq!(
            leading.take().unwrap(),
            b"\r\n\r\nGET / HTTP/1.1\r\nHost: h\r\n\r\n"
        );

        let bare = HeadCopy::default();
        bare.note(b"GET / HTTP/1.1\nHost: h\n\nrest");
        assert_eq!(bare.take().unwrap(), b"GET / HTTP/1.1\nHost: h\n\n");

        let large = HeadCopy::default();
        large.note(b"GET / HTTP/1.1\r\nX-Big: ");
        large.note(&vec![b'a'; MAX_HEAD_BYTES]);
        large.note(b"\r\n\r\n");
        assert_eq!(large.take(), None, "a head over the limit is refused");
    }

    #[test]
    fn a_message_flushed_whole_is_completed() {
        assert_eq!(
            writes(7, true, None).outcome(0, None),
            EffectOutcome::Completed(7)
        );
        // The response failed after the request left whole.
        assert_eq!(
            writes(7, true, None).outcome(0, Some(io::ErrorKind::ConnectionReset)),
            EffectOutcome::Completed(7)
        );
        // Bytes accepted before the message started are not its own.
        assert_eq!(
            writes(32, true, None).outcome(25, None),
            EffectOutcome::Completed(7)
        );
    }

    #[test]
    fn a_write_error_is_failed_or_partial() {
        let broken = Some((io::ErrorKind::BrokenPipe, false));
        assert_eq!(
            writes(0, false, broken).outcome(0, Some(io::ErrorKind::Other)),
            EffectOutcome::Failed {
                accepted_bytes: 0,
                error_kind: io::ErrorKind::BrokenPipe,
            }
        );
        assert_eq!(
            writes(3, false, broken).outcome(0, Some(io::ErrorKind::Other)),
            EffectOutcome::Partial {
                accepted_bytes: 3,
                error_kind: io::ErrorKind::BrokenPipe,
            }
        );
    }

    #[test]
    fn a_failed_flush_is_indeterminate() {
        assert_eq!(
            writes(7, false, Some((io::ErrorKind::TimedOut, true))).outcome(0, None),
            EffectOutcome::Indeterminate { accepted_bytes: 7 }
        );
    }

    #[test]
    fn a_message_cut_short_takes_the_error_that_ended_the_exchange() {
        assert_eq!(
            writes(3, false, None).outcome(0, Some(io::ErrorKind::TimedOut)),
            EffectOutcome::Partial {
                accepted_bytes: 3,
                error_kind: io::ErrorKind::TimedOut,
            }
        );
        assert_eq!(
            writes(0, false, None).outcome(0, Some(io::ErrorKind::TimedOut)),
            EffectOutcome::Failed {
                accepted_bytes: 0,
                error_kind: io::ErrorKind::TimedOut,
            }
        );
    }
}
