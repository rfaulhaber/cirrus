//! Lazy pagination over Salesforce query results.
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
//! # Runtime
//!
//! [`Records<R>`] implements [`futures::stream::Stream`] and nothing
//! runtime-specific, so any combinator crate drives it. The pages it
//! fetches go through the client's [`reqwest`] transport, whose read
//! timeout, like the retry policy's backoff, is a Tokio timer, so the
//! stream has to be polled from inside a Tokio runtime with its time
//! driver enabled (`#[tokio::main]` and `#[tokio::test]` both enable
//! it). Polled from another executor's thread, the first page fetch
//! panics inside `reqwest` with "there is no reactor running".
//!
//! # Cancellation and back-pressure
//!
//! The stream is naturally cancellable — drop the stream and no further
//! HTTP requests fire. There's no pre-fetching: each page fetch is
//! initiated only when the previous page's records are exhausted, so a
//! consumer that breaks early after the first page issues exactly one
//! HTTP request total.
//!
//! # Resuming
//!
//! The first failed page fetch ends the stream once the error has been
//! yielded, because a query timeout or a malformed locator does not clear
//! up on its own. The locator of the page that failed stays reachable
//! through [`Records::pending_locator`], and Salesforce keeps a cursor
//! and its results for two days, so a consumer that wants to go on from
//! there — after a transient 503, or after a record it could not
//! deserialize — hands the locator to [`Records::from_locator`] instead
//! of re-running the query:
//!
//! ```ignore
//! use futures::StreamExt;
//!
//! let mut records = sf.query_stream_as::<Acct>("SELECT Id, Name FROM Account");
//! while let Some(rec) = records.next().await {
//!     if let Err(e) = rec {
//!         if let Some(locator) = records.pending_locator() {
//!             // The fetch of `locator` failed. Keep it and resume later with
//!             // `Records::<Acct>::from_locator(sf.clone(), locator)`.
//!         }
//!         return Err(e.into());
//!     }
//! }
//! ```
//!
//! [`Records::from_page`] starts a stream from a page fetched some other
//! way — a first page sent with `Sforce-Call-Options` through
//! [`Cirrus::send_with_headers`], say — and [`Records::total_size`]
//! reports the query's total once the first page is in. The page size
//! needs no detour: [`Cirrus::query_stream_with_options`] sends
//! `Sforce-Query-Options` on every page.
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
//! [`Cirrus::send_with_headers`]: crate::Cirrus::send_with_headers

use crate::Cirrus;
use crate::error::CirrusResult;
use crate::handlers::query::QueryOptions;
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
/// terminates the stream after surfacing it once, with the locator of
/// the page that failed left on [`pending_locator`](Self::pending_locator)
/// for [`from_locator`](Self::from_locator) to resume from. Construct
/// via [`Cirrus::query_stream`] / [`Cirrus::query_stream_as`] /
/// [`Cirrus::query_all_stream`] / [`Cirrus::query_all_stream_as`], the
/// equivalent methods on [`crate::handlers::tooling::ToolingHandler`],
/// or from a saved locator or an already-fetched page with
/// [`from_locator`](Self::from_locator) and [`from_page`](Self::from_page).
///
/// [`Cirrus::query_stream`]: crate::Cirrus::query_stream
/// [`Cirrus::query_stream_as`]: crate::Cirrus::query_stream_as
/// [`Cirrus::query_all_stream`]: crate::Cirrus::query_all_stream
/// [`Cirrus::query_all_stream_as`]: crate::Cirrus::query_all_stream_as
#[must_use = "Records is a lazy Stream: no request is issued until it is polled"]
pub struct Records<R> {
    client: Cirrus,
    state: State<R>,
    /// `totalSize` of the first page seen, which Salesforce repeats on
    /// every page of the same query.
    total_size: Option<i64>,
    /// Sent with every follow-up page the stream fetches.
    options: QueryOptions,
}

impl<R> std::fmt::Debug for Records<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Don't expose the BoxFuture or buffered records — the former
        // has no useful Debug; the latter is large and may carry PII.
        let (state, buffered) = match &self.state {
            State::Fetching { .. } => ("Fetching", 0),
            State::Buffered { records, .. } => ("Buffered", records.len()),
            State::Done { .. } => ("Done", 0),
        };
        f.debug_struct("Records")
            .field("state", &state)
            .field("buffered_records", &buffered)
            .field("has_pending_locator", &self.pending_locator().is_some())
            .field("total_size", &self.total_size)
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

enum State<R> {
    /// A page fetch is in flight. `locator` is the `nextRecordsUrl` being
    /// fetched, `None` when the page is the query itself.
    Fetching {
        fut: PageFuture<R>,
        locator: Option<String>,
    },
    /// We have a page; serve from `records` until empty, then either
    /// fetch the next page (via `next`) or transition to [`State::Done`].
    Buffered {
        records: VecDeque<R>,
        next: Option<String>,
    },
    /// Stream is fully drained or surfaced an error. Subsequent polls
    /// return `None`. `unfetched` is the locator whose fetch failed, kept
    /// so the consumer can resume from it.
    Done { unfetched: Option<String> },
}

impl<R: DeserializeOwned + Send + Unpin + 'static> Records<R> {
    /// Constructs a `Records` stream from a future yielding the first
    /// page. Internal — call sites supply the appropriate initial-page
    /// future (a `query_as`, `query_all_as`, or
    /// `tooling().query_as` call, all of which return
    /// `QueryResult<R>`) and the options every follow-up page is
    /// fetched with.
    pub(crate) fn new(client: Cirrus, initial: PageFuture<R>, options: QueryOptions) -> Self {
        Self {
            client,
            state: State::Fetching {
                fut: initial,
                locator: None,
            },
            total_size: None,
            options,
        }
    }

    /// Starts a stream at a saved `nextRecordsUrl` locator: one taken
    /// from [`QueryResult::next_records_url`], or left on
    /// [`pending_locator`](Self::pending_locator) by a stream that
    /// failed.
    ///
    /// The first poll fetches that page through
    /// [`Cirrus::query_more_as`](crate::Cirrus::query_more_as), so the
    /// locator is confined the same way: one naming another host or
    /// resource is yielded as [`CirrusError::InvalidInput`] without a
    /// request. Salesforce keeps a cursor and its results for two days.
    ///
    /// [`CirrusError::InvalidInput`]: crate::CirrusError::InvalidInput
    pub fn from_locator(client: Cirrus, next_records_url: impl Into<String>) -> Self {
        let options = QueryOptions::default();
        let state = fetch_more(&client, next_records_url.into(), &options);
        Self {
            client,
            state,
            total_size: None,
            options,
        }
    }

    /// Starts a stream at a page already fetched, serving its records
    /// first and then walking its `nextRecordsUrl` like any other page.
    ///
    /// This is how a first page sent with request headers the typed
    /// query methods do not take (`Sforce-Call-Options`, say) becomes a
    /// stream: fetch it with
    /// [`Cirrus::send_with_headers`](crate::Cirrus::send_with_headers)
    /// and hand it over here. The follow-up pages are fetched without
    /// those headers. For the page size, the
    /// [`query_stream_with_options`](crate::Cirrus::query_stream_with_options)
    /// family sends `Sforce-Query-Options` on every page.
    pub fn from_page(client: Cirrus, page: QueryResult<R>) -> Self {
        Self {
            client,
            state: State::Buffered {
                records: page.records.into(),
                next: page.next_records_url,
            },
            total_size: Some(page.total_size),
            options: QueryOptions::default(),
        }
    }
}

impl<R> Records<R> {
    /// The locator of the next page the stream has not received.
    ///
    /// While a page fetch is in flight, this is the locator being
    /// fetched; after a fetch failed, the locator that failed, which
    /// [`from_locator`](Self::from_locator) resumes from. While records
    /// are buffered, it is the locator of the page after them, so a
    /// consumer that stops early and resumes from it skips the records
    /// still buffered. `None` before the first page, when the buffered
    /// page is the last one, and after a clean drain.
    pub fn pending_locator(&self) -> Option<&str> {
        match &self.state {
            State::Fetching { locator, .. } => locator.as_deref(),
            State::Buffered { next, .. } => next.as_deref(),
            State::Done { unfetched } => unfetched.as_deref(),
        }
    }

    /// The query's `totalSize`, known once the first page has arrived
    /// (immediately for [`from_page`](Self::from_page)).
    pub fn total_size(&self) -> Option<i64> {
        self.total_size
    }
}

/// The state for fetching the page `locator` names.
fn fetch_more<R: DeserializeOwned + Send + Unpin + 'static>(
    client: &Cirrus,
    locator: String,
    options: &QueryOptions,
) -> State<R> {
    let client = client.clone();
    let url = locator.clone();
    let options = options.clone();
    let fut: PageFuture<R> =
        Box::pin(async move { client.query_more_with_options_as::<R>(&url, &options).await });
    State::Fetching {
        fut,
        locator: Some(locator),
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
                State::Fetching { fut, locator } => match fut.as_mut().poll(cx) {
                    Poll::Ready(Ok(qr)) => {
                        this.total_size = Some(qr.total_size);
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
                        // requests. The locator stays on the stream for
                        // a consumer that wants to resume.
                        let unfetched = locator.take();
                        this.state = State::Done { unfetched };
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
                        this.state = fetch_more(&this.client, next_url, &this.options);
                    } else {
                        this.state = State::Done { unfetched: None };
                        return Poll::Ready(None);
                    }
                }
                State::Done { .. } => return Poll::Ready(None),
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::Records;
    use crate::Cirrus;
    use crate::auth::StaticTokenAuth;
    use futures::StreamExt;
    use serde_json::{Value, json};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wiremock::matchers::{header, method, path, query_param};
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

    /// A failed page fetch leaves its locator on the stream, and a
    /// stream started from that locator picks up where the first one
    /// stopped instead of re-running the query.
    #[tokio::test]
    async fn a_failed_page_leaves_its_locator_pending_and_from_locator_resumes_it() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/query"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "totalSize": 3,
                "done": false,
                "nextRecordsUrl": "/services/data/v66.0/query/01gAA-2",
                "records": [{"attributes": {"type": "Account"}, "Id": "001a"}]
            })))
            .expect(1)
            .mount(&server)
            .await;

        // The first fetch of page 2 fails; the resumed one succeeds.
        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/query/01gAA-2"))
            .respond_with(ResponseTemplate::new(503).set_body_json(json!([{
                "errorCode": "SERVER_UNAVAILABLE",
                "message": "Service Unavailable"
            }])))
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/query/01gAA-2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "totalSize": 3,
                "done": true,
                "records": [
                    {"attributes": {"type": "Account"}, "Id": "001b"},
                    {"attributes": {"type": "Account"}, "Id": "001c"}
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let mut stream = sf.query_stream("SELECT Id FROM Account");
        assert_eq!(stream.pending_locator(), None, "nothing fetched yet");
        assert_eq!(stream.total_size(), None);

        let first = stream.next().await.unwrap().unwrap();
        assert_eq!(first["Id"], "001a");
        assert_eq!(stream.total_size(), Some(3));
        assert_eq!(
            stream.pending_locator(),
            Some("/services/data/v66.0/query/01gAA-2"),
            "while a page is buffered, the pending locator names the page after it"
        );

        let err = stream.next().await.unwrap().unwrap_err();
        assert!(matches!(err, crate::CirrusError::Api { status: 503, .. }));
        assert!(
            stream.next().await.is_none(),
            "the stream ends after the error"
        );
        let locator = stream
            .pending_locator()
            .expect("the failed page's locator survives the error")
            .to_owned();
        assert_eq!(locator, "/services/data/v66.0/query/01gAA-2");
        let debug = format!("{stream:?}");
        assert!(debug.contains("has_pending_locator: true"), "{debug}");
        assert!(!debug.contains("01gAA-2"), "{debug}");

        let resumed: Vec<Value> = Records::<Value>::from_locator(sf.clone(), locator)
            .map(|r| r.unwrap())
            .collect()
            .await;
        assert_eq!(resumed.len(), 2);
        assert_eq!(resumed[0]["Id"], "001b");
        assert_eq!(resumed[1]["Id"], "001c");
    }

    #[tokio::test]
    async fn a_clean_drain_leaves_no_locator_pending() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/query"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "totalSize": 1,
                "done": true,
                "records": [{"attributes": {"type": "Account"}, "Id": "001a"}]
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let mut stream = sf.query_stream("SELECT Id FROM Account");
        assert!(stream.next().await.unwrap().is_ok());
        assert_eq!(
            stream.pending_locator(),
            None,
            "the last page has no locator"
        );
        assert!(stream.next().await.is_none());
        assert_eq!(stream.pending_locator(), None);
        assert_eq!(stream.total_size(), Some(1));
    }

    /// The initial query is not a locator, so its failure leaves nothing
    /// to resume from: the consumer re-runs the query.
    #[tokio::test]
    async fn a_failed_initial_query_leaves_nothing_pending() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/query"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!([{
                "message": "unexpected token: SELECTT",
                "errorCode": "MALFORMED_QUERY"
            }])))
            .expect(1)
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let mut stream = sf.query_stream("SELECTT Id FROM Account");
        let err = stream.next().await.unwrap().unwrap_err();
        assert!(matches!(err, crate::CirrusError::Api { status: 400, .. }));
        assert_eq!(stream.pending_locator(), None);
        assert_eq!(stream.total_size(), None);
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn query_stream_with_options_sends_the_header_on_every_page() {
        // SOURCE: https://developer.salesforce.com/docs/platform/api-rest/guide/headers-queryoptions.html
        // "Sforce-Query-Options: batchSize=1000". The page is documented
        // for the Query resource; the follow-up carries the same header
        // so a cursor that honors it keeps the page size.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/query"))
            .and(query_param("q", "SELECT Id FROM Account"))
            .and(header("Sforce-Query-Options", "batchSize=200"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "totalSize": 2,
                "done": false,
                "nextRecordsUrl": "/services/data/v66.0/query/01gAA-200",
                "records": [{"attributes": {"type": "Account"}, "Id": "001a"}]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/query/01gAA-200"))
            .and(header("Sforce-Query-Options", "batchSize=200"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "totalSize": 2,
                "done": true,
                "records": [{"attributes": {"type": "Account"}, "Id": "001b"}]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let options = crate::QueryOptions::new().batch_size(200);
        let ids: Vec<Value> = sf
            .query_stream_with_options("SELECT Id FROM Account", &options)
            .map(|r| r.unwrap())
            .collect()
            .await;
        assert_eq!(ids.len(), 2);
        assert_eq!(ids[0]["Id"], "001a");
        assert_eq!(ids[1]["Id"], "001b");
    }

    /// A first page fetched by the caller — here with a request header
    /// the typed query methods do not take — becomes a stream that
    /// serves it and then walks its locator.
    #[tokio::test]
    async fn from_page_serves_the_given_page_then_walks_its_locator() {
        // SOURCE: https://developer.salesforce.com/docs/platform/api-rest/guide/headers-calloptions.html
        // "Sforce-Call-Options: client=caseSensitiveToken;
        // defaultNamespace=battle" — "can be used with ... Query".
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/query"))
            .and(query_param("q", "SELECT Id FROM Account"))
            .and(header("Sforce-Call-Options", "defaultNamespace=battle"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "totalSize": 2,
                "done": false,
                "nextRecordsUrl": "/services/data/v66.0/query/01gAA-2",
                "records": [{"attributes": {"type": "Account"}, "Id": "001a"}]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/query/01gAA-2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "totalSize": 2,
                "done": true,
                "records": [{"attributes": {"type": "Account"}, "Id": "001b"}]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let page: crate::QueryResult<Value> = sf
            .send_with_headers(
                reqwest::Method::GET,
                "query",
                Some(&[("q", "SELECT Id FROM Account")]),
                &[("Sforce-Call-Options", "defaultNamespace=battle")],
            )
            .await
            .unwrap();
        let mut stream = Records::from_page(sf, page);
        assert_eq!(stream.total_size(), Some(2), "known before the first poll");
        assert_eq!(
            stream.pending_locator(),
            Some("/services/data/v66.0/query/01gAA-2")
        );

        let ids: Vec<Value> = (&mut stream).map(|r| r.unwrap()).collect().await;
        assert_eq!(ids.len(), 2);
        assert_eq!(ids[0]["Id"], "001a");
        assert_eq!(ids[1]["Id"], "001b");
        assert_eq!(stream.pending_locator(), None);
    }

    /// A locator is followed as issued, whatever version the client was
    /// built for: the cursor belongs to the version of the query that
    /// opened it, and rebuilding it from the client's version would hit
    /// a resource that does not exist.
    #[tokio::test]
    async fn locators_are_followed_verbatim_across_client_versions() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/services/data/v61.0/query"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "totalSize": 2,
                "done": false,
                "nextRecordsUrl": "/services/data/v66.0/query/01gAA-2",
                "records": [{"attributes": {"type": "Account"}, "Id": "001a"}]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/query/01gAA-2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "totalSize": 2,
                "done": true,
                "records": [{"attributes": {"type": "Account"}, "Id": "001b"}]
            })))
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/services/data/v61.0/query/01gAA-2"))
            .respond_with(ResponseTemplate::new(404))
            .expect(0)
            .mount(&server)
            .await;

        let auth = Arc::new(StaticTokenAuth::new("tok", server.uri()));
        let sf = Cirrus::builder()
            .auth(auth)
            .api_version("v61.0")
            .retry_policy(crate::RetryPolicy::none())
            .build()
            .unwrap();

        let ids: Vec<Value> = sf
            .query_stream("SELECT Id FROM Account")
            .map(|r| r.unwrap())
            .collect()
            .await;
        assert_eq!(ids.len(), 2);
        assert_eq!(ids[1]["Id"], "001b");

        let resumed: Vec<Value> =
            Records::<Value>::from_locator(sf, "/services/data/v66.0/query/01gAA-2")
                .map(|r| r.unwrap())
                .collect()
                .await;
        assert_eq!(resumed.len(), 1);
    }

    /// `from_locator` confines the locator like `query_more` does: a
    /// value naming another host is an error on the first poll, with no
    /// request sent and nothing left to resume.
    #[tokio::test]
    async fn from_locator_refuses_a_foreign_locator_on_its_first_poll() {
        let server = MockServer::start().await;
        let sf = fixture(server.uri());

        let mut stream = Records::<Value>::from_locator(
            sf,
            "https://other.my.salesforce.com/services/data/v66.0/query/01gXXX-2000",
        );
        let err = stream.next().await.unwrap().unwrap_err();
        assert!(
            matches!(
                err,
                crate::CirrusError::InvalidInput {
                    field: "next_records_url",
                    ..
                }
            ),
            "{err:?}"
        );
        assert!(stream.next().await.is_none());
        assert!(server.received_requests().await.unwrap().is_empty());
    }
}
