//! Lazy, runtime-agnostic pagination over Salesforce query results.
//!
//! Salesforce paginates SOQL queries (and several adjacent endpoints)
//! via the `nextRecordsUrl` cursor pattern: a [`QueryResult<R>`] carries
//! at most ~2000 records plus an optional locator URL pointing at the
//! next batch. Manually walking that locator works but is verbose:
//!
//! ```ignore
//! let mut page = sf.query_as::<Acct>("SELECT Id, Name FROM Account").await?;
//! loop {
//!     for rec in page.records {
//!         /* ... */
//!     }
//!     match page.next_records_url {
//!         Some(url) => page = sf.query_more_as::<Acct>(&url).await?,
//!         None => break,
//!     }
//! }
//! ```
//!
//! [`Records<R>`] flattens that into a single
//! [`futures::Stream`](futures::stream::Stream) that yields one record
//! at a time, fetching each subsequent page lazily as items are
//! consumed:
//!
//! ```ignore
//! use futures::StreamExt;
//!
//! let mut records = sf.query_stream_as::<Acct>("SELECT Id, Name FROM Account");
//! while let Some(rec) = records.next().await {
//!     let rec = rec?;
//!     /* ... */
//! }
//! ```
//!
//! All of the standard `Stream` / `TryStreamExt` combinators apply —
//! `take`, `try_collect`, `try_filter`, `chunks`, `try_for_each`, etc.
//!
//! # Runtime independence
//!
//! [`Records<R>`] only implements [`futures::stream::Stream`]; it does
//! not depend on a specific async runtime. Whatever executor your
//! application uses to drive the stream is fine, provided
//! [`reqwest`]'s connection pool can run on it (i.e. a Tokio runtime
//! is *eventually* required at the transport layer, but consumers
//! aren't forced to write `#[tokio::main]`).
//!
//! # Cancellation and back-pressure
//!
//! The stream is naturally cancellable — drop the stream and no further
//! HTTP requests fire. There's no pre-fetching: each page fetch is
//! initiated only when the previous page's records are exhausted, so a
//! consumer that breaks early after the first page issues exactly one
//! HTTP request total.
//!
//! # What this *doesn't* cover
//!
//! - **Bulk 2.0 query results** use a different cursor shape (the
//!   `Sforce-Locator` response header carrying the literal string
//!   `"null"` at end-of-stream) and yield CSV bytes, not JSON records.
//!   Use [`crate::handlers::bulk::BulkQueryHandler::results`] instead.
//! - **Search results** aren't paginated — Salesforce returns the full
//!   `searchRecords` array in one response.
//!
//! [`QueryResult<R>`]: crate::QueryResult
//! [`reqwest`]: reqwest

use crate::Cirrus;
use crate::error::CirrusResult;
use crate::response::QueryResult;
use futures::future::BoxFuture;
use futures::stream::Stream;
use serde::de::DeserializeOwned;
use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Future producing a single page of query records.
type PageFuture<R> = BoxFuture<'static, CirrusResult<QueryResult<R>>>;

/// A lazy stream of query records that walks `nextRecordsUrl` locators
/// transparently.
///
/// Yields [`CirrusResult<R>`] — the first error from any page fetch
/// terminates the stream after surfacing it once. Construct via
/// [`Cirrus::query_stream`] / [`Cirrus::query_stream_as`] /
/// [`Cirrus::query_all_stream`] / [`Cirrus::query_all_stream_as`]
/// or the equivalent methods on
/// [`crate::handlers::tooling::ToolingHandler`].
///
/// [`Cirrus::query_stream`]: crate::Cirrus::query_stream
/// [`Cirrus::query_stream_as`]: crate::Cirrus::query_stream_as
/// [`Cirrus::query_all_stream`]: crate::Cirrus::query_all_stream
/// [`Cirrus::query_all_stream_as`]: crate::Cirrus::query_all_stream_as
#[must_use = "Records is a lazy Stream: no request is issued until it is polled"]
pub struct Records<R> {
    client: Cirrus,
    state: State<R>,
}

impl<R> std::fmt::Debug for Records<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Don't expose the BoxFuture or buffered records — the former
        // has no useful Debug; the latter is large and may carry PII.
        let state_label = match &self.state {
            State::Fetching(_) => "Fetching",
            State::Buffered { records, next } => {
                return f
                    .debug_struct("Records")
                    .field("state", &"Buffered")
                    .field("buffered_records", &records.len())
                    .field("has_next_page", &next.is_some())
                    .finish_non_exhaustive();
            }
            State::Done => "Done",
        };
        f.debug_struct("Records")
            .field("state", &state_label)
            .finish_non_exhaustive()
    }
}

enum State<R> {
    /// A page fetch is in flight (the initial query, or a follow-up
    /// `query_more` after exhausting the current buffer).
    Fetching(PageFuture<R>),
    /// We have a page; serve from `records` until empty, then either
    /// fetch the next page (via `next`) or transition to [`State::Done`].
    Buffered {
        records: VecDeque<R>,
        next: Option<String>,
    },
    /// Stream is fully drained or surfaced an error. Subsequent polls
    /// return `None`.
    Done,
}

impl<R: DeserializeOwned + Send + Unpin + 'static> Records<R> {
    /// Constructs a `Records` stream from a future yielding the first
    /// page. Internal — call sites supply the appropriate initial-page
    /// future (a `query_as`, `query_all_as`, or
    /// `tooling().query_as` call, all of which return
    /// `QueryResult<R>`).
    pub(crate) fn new(client: Cirrus, initial: PageFuture<R>) -> Self {
        Self {
            client,
            state: State::Fetching(initial),
        }
    }
}

impl<R: DeserializeOwned + Send + Unpin + 'static> Stream for Records<R> {
    type Item = CirrusResult<R>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Records<R> contains only owned, Unpin fields (Cirrus is
        // Clone+Send+Sync; State<R> wraps Unpin variants — the
        // BoxFuture is `Pin<Box<...>>` which is itself Unpin). So
        // get_mut() is sound without structural pinning.
        let this = self.get_mut();
        loop {
            match &mut this.state {
                State::Fetching(fut) => match fut.as_mut().poll(cx) {
                    Poll::Ready(Ok(qr)) => {
                        this.state = State::Buffered {
                            records: qr.records.into(),
                            next: qr.next_records_url,
                        };
                        // Loop around to drain the new page immediately.
                    }
                    Poll::Ready(Err(e)) => {
                        // Surface the error once, then short-circuit
                        // further polls. Salesforce errors are usually
                        // permanent for the duration of the query
                        // (query timeout, malformed locator), so
                        // continuing past the first error would waste
                        // requests.
                        this.state = State::Done;
                        return Poll::Ready(Some(Err(e)));
                    }
                    Poll::Pending => return Poll::Pending,
                },
                State::Buffered { records, next } => {
                    if let Some(rec) = records.pop_front() {
                        return Poll::Ready(Some(Ok(rec)));
                    }
                    // Current page drained — start the next one (or
                    // finish, if the locator is None).
                    if let Some(next_url) = next.take() {
                        let client = this.client.clone();
                        let fut: PageFuture<R> =
                            Box::pin(async move { client.query_more_as::<R>(&next_url).await });
                        this.state = State::Fetching(fut);
                    } else {
                        this.state = State::Done;
                        return Poll::Ready(None);
                    }
                }
                State::Done => return Poll::Ready(None),
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use crate::Cirrus;
    use crate::auth::StaticTokenAuth;
    use futures::StreamExt;
    use serde_json::{Value, json};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    fn fixture(uri: String) -> Cirrus {
        // Disable retries so error-path tests can assert exact call
        // counts. Retry behavior gets its own dedicated tests in
        // retry.rs / lib.rs.
        let auth = Arc::new(StaticTokenAuth::new("tok", uri));
        Cirrus::builder()
            .auth(auth)
            .retry_policy(crate::RetryPolicy::none())
            .build()
            .unwrap()
    }

    /// A response that echoes a single page with no `nextRecordsUrl` —
    /// the stream should drain in one fetch.
    #[tokio::test]
    async fn stream_drains_single_page_without_extra_fetches() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/query"))
            .and(query_param("q", "SELECT Id FROM Account"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "totalSize": 2,
                "done": true,
                "records": [
                    {"attributes": {"type": "Account"}, "Id": "001a"},
                    {"attributes": {"type": "Account"}, "Id": "001b"}
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let records: Vec<Value> = sf
            .query_stream("SELECT Id FROM Account")
            .map(|r| r.unwrap())
            .collect()
            .await;
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["Id"], "001a");
        assert_eq!(records[1]["Id"], "001b");
    }

    /// 3-page paginated response. Verifies the stream walks every page,
    /// preserves order, and stops cleanly when the last page reports
    /// `done: true` with no `nextRecordsUrl`.
    #[tokio::test]
    async fn stream_walks_three_paginated_pages_in_order() {
        let server = MockServer::start().await;

        // Page 1 — initial query.
        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/query"))
            .and(query_param("q", "SELECT Id FROM Account"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "totalSize": 6,
                "done": false,
                "nextRecordsUrl": "/services/data/v66.0/query/01gAA-2",
                "records": [
                    {"attributes": {"type": "Account"}, "Id": "001a"},
                    {"attributes": {"type": "Account"}, "Id": "001b"}
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;

        // Page 2 — first nextRecordsUrl follow-up.
        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/query/01gAA-2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "totalSize": 6,
                "done": false,
                "nextRecordsUrl": "/services/data/v66.0/query/01gAA-4",
                "records": [
                    {"attributes": {"type": "Account"}, "Id": "001c"},
                    {"attributes": {"type": "Account"}, "Id": "001d"}
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;

        // Page 3 — final follow-up.
        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/query/01gAA-4"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "totalSize": 6,
                "done": true,
                "records": [
                    {"attributes": {"type": "Account"}, "Id": "001e"},
                    {"attributes": {"type": "Account"}, "Id": "001f"}
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let records: Vec<Value> = sf
            .query_stream("SELECT Id FROM Account")
            .map(|r| r.unwrap())
            .collect()
            .await;
        assert_eq!(records.len(), 6);
        assert_eq!(records[0]["Id"], "001a");
        assert_eq!(records[5]["Id"], "001f");
    }

    /// Mid-stream error. The stream should yield page 1's records,
    /// then yield the error from page 2, then yield None (no further
    /// retries).
    #[tokio::test]
    async fn stream_surfaces_mid_iteration_error_then_terminates() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/query"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "totalSize": 2500,
                "done": false,
                "nextRecordsUrl": "/services/data/v66.0/query/01gAA-2",
                "records": [
                    {"attributes": {"type": "Account"}, "Id": "001a"}
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/query/01gAA-2"))
            .respond_with(ResponseTemplate::new(503).set_body_json(json!([{
                "errorCode": "SERVER_UNAVAILABLE",
                "message": "Service Unavailable"
            }])))
            // The stream yields the error once and stops; subsequent
            // polls return None without re-querying. Hence 1 attempt.
            .expect(1)
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let mut stream = sf.query_stream("SELECT Id FROM Account");

        // Page 1 record
        let first = stream.next().await.unwrap().unwrap();
        assert_eq!(first["Id"], "001a");

        // Page 2 error
        let err = stream.next().await.unwrap().unwrap_err();
        assert!(matches!(err, crate::CirrusError::Api { status: 503, .. }));

        // Stream terminates — no further fetches.
        assert!(stream.next().await.is_none());
    }

    /// Dropping the stream after the first record should NOT trigger
    /// the follow-up nextRecordsUrl request. wiremock's `.expect(0)`
    /// makes this assertion testable.
    #[tokio::test]
    async fn dropping_stream_early_does_not_fetch_unconsumed_pages() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/query"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "totalSize": 100,
                "done": false,
                "nextRecordsUrl": "/services/data/v66.0/query/01gAA-2",
                "records": [
                    {"attributes": {"type": "Account"}, "Id": "001a"},
                    {"attributes": {"type": "Account"}, "Id": "001b"}
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;

        // Page 2 must NOT be requested when we drop after consuming
        // both records on page 1 (since neither buffer-empty nor
        // explicit poll-for-next has happened yet).
        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/query/01gAA-2"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let mut stream = sf.query_stream("SELECT Id FROM Account");
        let first = stream.next().await.unwrap().unwrap();
        let second = stream.next().await.unwrap().unwrap();
        assert_eq!(first["Id"], "001a");
        assert_eq!(second["Id"], "001b");
        // Drop the stream here. Since we never asked for a 3rd record,
        // the page-2 fetch must not have fired. wiremock's expect(0)
        // verifies this on server drop.
        drop(stream);
    }

    /// Typed deserialization through the stream.
    #[tokio::test]
    async fn stream_deserializes_into_caller_type() {
        #[derive(serde::Deserialize, Debug)]
        struct Acct {
            #[serde(rename = "Name")]
            name: String,
        }

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/query"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "totalSize": 2,
                "done": true,
                "records": [
                    {"attributes": {"type": "Account"}, "Name": "Acme"},
                    {"attributes": {"type": "Account"}, "Name": "Globex"}
                ]
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let names: Vec<String> = sf
            .query_stream_as::<Acct>("SELECT Name FROM Account")
            .map(|r| r.unwrap().name)
            .collect()
            .await;
        assert_eq!(names, vec!["Acme", "Globex"]);
    }

    /// `query_all_stream` hits `/queryAll` instead of `/query`.
    #[tokio::test]
    async fn query_all_stream_targets_queryall_endpoint() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/queryAll"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "totalSize": 1,
                "done": true,
                "records": [
                    {"attributes": {"type": "Account"}, "Id": "001x", "IsDeleted": true}
                ]
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let records: Vec<Value> = sf
            .query_all_stream("SELECT Id, IsDeleted FROM Account")
            .map(|r| r.unwrap())
            .collect()
            .await;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["IsDeleted"], true);
    }

    /// Tooling streaming — same envelope, different path prefix.
    /// Verifies `tooling/query` is the initial endpoint and that a
    /// Tooling-issued `nextRecordsUrl` (which embeds `tooling/`) is
    /// followed correctly.
    #[tokio::test]
    async fn tooling_query_stream_walks_tooling_prefixed_locators() {
        let server = MockServer::start().await;

        // Initial Tooling page.
        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/tooling/query"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "totalSize": 4,
                "done": false,
                "nextRecordsUrl": "/services/data/v66.0/tooling/query/01gAA-2",
                "records": [
                    {"attributes": {"type": "ApexClass"}, "Id": "01p1"},
                    {"attributes": {"type": "ApexClass"}, "Id": "01p2"}
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;

        // Tooling-prefixed nextRecordsUrl follow-up.
        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/tooling/query/01gAA-2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "totalSize": 4,
                "done": true,
                "records": [
                    {"attributes": {"type": "ApexClass"}, "Id": "01p3"},
                    {"attributes": {"type": "ApexClass"}, "Id": "01p4"}
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let records: Vec<Value> = sf
            .tooling()
            .query_stream("SELECT Id FROM ApexClass")
            .map(|r| r.unwrap())
            .collect()
            .await;
        assert_eq!(records.len(), 4);
        assert_eq!(records[0]["Id"], "01p1");
        assert_eq!(records[3]["Id"], "01p4");
    }

    /// Smoke test that polling order respects buffer-then-fetch
    /// semantics — record 1 yields *before* the second-page fetch is
    /// initiated. Uses a counter to verify the sequencing.
    #[tokio::test]
    async fn stream_yields_buffered_records_before_fetching_next_page() {
        let server = MockServer::start().await;
        let fetch_count = Arc::new(AtomicUsize::new(0));
        let counter = fetch_count.clone();

        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/query"))
            .respond_with(move |_req: &Request| {
                counter.fetch_add(1, Ordering::SeqCst);
                ResponseTemplate::new(200).set_body_json(json!({
                    "totalSize": 4,
                    "done": false,
                    "nextRecordsUrl": "/services/data/v66.0/query/01gAA-2",
                    "records": [
                        {"attributes": {"type": "Account"}, "Id": "001a"},
                        {"attributes": {"type": "Account"}, "Id": "001b"}
                    ]
                }))
            })
            .mount(&server)
            .await;

        let counter2 = fetch_count.clone();
        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/query/01gAA-2"))
            .respond_with(move |_req: &Request| {
                counter2.fetch_add(1, Ordering::SeqCst);
                ResponseTemplate::new(200).set_body_json(json!({
                    "totalSize": 4,
                    "done": true,
                    "records": [
                        {"attributes": {"type": "Account"}, "Id": "001c"},
                        {"attributes": {"type": "Account"}, "Id": "001d"}
                    ]
                }))
            })
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let mut stream = sf.query_stream("SELECT Id FROM Account");

        // First two records are served from the initial page's buffer.
        let _r0 = stream.next().await.unwrap().unwrap();
        assert_eq!(fetch_count.load(Ordering::SeqCst), 1);
        let _r1 = stream.next().await.unwrap().unwrap();
        assert_eq!(fetch_count.load(Ordering::SeqCst), 1);

        // Asking for record #3 triggers the page-2 fetch.
        let _r2 = stream.next().await.unwrap().unwrap();
        assert_eq!(fetch_count.load(Ordering::SeqCst), 2);
        let _r3 = stream.next().await.unwrap().unwrap();
        assert_eq!(fetch_count.load(Ordering::SeqCst), 2);

        assert!(stream.next().await.is_none());
    }
}
