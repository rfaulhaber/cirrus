//! A response body handed over as it arrives instead of buffered whole.

use crate::error::{CirrusError, CirrusResult};
use bytes::Bytes;
use futures::Stream;
use reqwest::header::HeaderMap;
use std::pin::Pin;
use std::task::{Context, Poll};

/// A 2xx response body streamed chunk by chunk.
///
/// Returned by the streaming downloads, such as
/// [`EventMonitoringHandler::download_stream`]. The request that
/// produced it went through the client's usual loop up to the first
/// body byte: the retry policy, the refresh after an
/// `INVALID_SESSION_ID` 401 and `Sforce-Limit-Info` capture all
/// applied, and a non-2xx answer was returned as an error before this
/// value existed. From here on nothing is replayed: a transport failure
/// mid-body ends the stream with a [`CirrusError::Http`] item, and a
/// caller that wants another attempt starts the download again. Each
/// chunk is handed over and forgotten, so the body is not subject to
/// [`CirrusBuilder::max_response_size`].
///
/// Implements [`futures::Stream`] with `Item = CirrusResult<Bytes>` and
/// nothing runtime-specific, but the chunks arrive through the client's
/// [`reqwest`] transport, whose read timeout is a Tokio timer, so poll
/// it from inside a Tokio runtime with its time driver enabled.
///
/// [`EventMonitoringHandler::download_stream`]: crate::handlers::event_monitoring::EventMonitoringHandler::download_stream
/// [`CirrusBuilder::max_response_size`]: crate::CirrusBuilder::max_response_size
/// [`CirrusError::Http`]: crate::CirrusError::Http
pub struct ByteStream {
    status: u16,
    headers: HeaderMap,
    body: Pin<Box<dyn Stream<Item = CirrusResult<Bytes>> + Send>>,
}

impl ByteStream {
    pub(crate) fn new(status: u16, headers: HeaderMap, response: reqwest::Response) -> Self {
        // `Response::chunk` borrows the response for each read, so the
        // response is threaded through the unfold state rather than
        // captured, which keeps the stream `'static`.
        let body = futures::stream::try_unfold(response, |mut response| async move {
            match response.chunk().await {
                Ok(Some(chunk)) => Ok(Some((chunk, response))),
                Ok(None) => Ok(None),
                Err(e) => Err(CirrusError::from(e)),
            }
        });
        Self {
            status,
            headers,
            body: Box::pin(body),
        }
    }

    /// The response's HTTP status, always in the 2xx range.
    pub fn status(&self) -> u16 {
        self.status
    }

    /// The response headers, read before the body started.
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }
}

impl Stream for ByteStream {
    type Item = CirrusResult<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.body.as_mut().poll_next(cx)
    }
}

impl std::fmt::Debug for ByteStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ByteStream")
            .field("status", &self.status)
            .field("headers", &self.headers)
            .finish_non_exhaustive()
    }
}
