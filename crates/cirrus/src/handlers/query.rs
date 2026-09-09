//! SOQL execution: `/query`, `/queryAll`, and the `nextRecordsUrl`
//! pagination follow-up.
//!
//! - [`query`] runs a SOQL statement and returns active records.
//! - [`query_all`] runs the same shape but also includes soft-deleted
//!   (Recycle Bin) and archived records — useful for replication or audit
//!   workflows. Salesforce ties both to the same response envelope
//!   ([`QueryResult`]).
//! - [`query_more`] follows a [`QueryResult::next_records_url`] locator to
//!   fetch the next batch. The locator carries the API version of the
//!   *initial* request — using a client configured for a different version
//!   doesn't change which version the locator hits, which is the documented
//!   behavior.
//!
//! Each method returns [`QueryResult<Value>`] by default; the `_as::<T>()`
//! variants deserialize records into a caller-supplied type.
//!
//! # Streaming variants
//!
//! [`query_stream`], [`query_stream_as`], [`query_all_stream`], and
//! [`query_all_stream_as`] return a [`Records<R>`](crate::Records) — a
//! [`futures::Stream`] that walks subsequent pages lazily, fetching the
//! next batch only when the current one is drained. See the
//! [`pagination`](crate::pagination) module docs for the full
//! contract.
//!
//! [`query`]: Cirrus::query
//! [`query_all`]: Cirrus::query_all
//! [`query_more`]: Cirrus::query_more
//! [`query_stream`]: Cirrus::query_stream
//! [`query_stream_as`]: Cirrus::query_stream_as
//! [`query_all_stream`]: Cirrus::query_all_stream
//! [`query_all_stream_as`]: Cirrus::query_all_stream_as
//! [`futures::Stream`]: futures::stream::Stream

use crate::Cirrus;
use crate::error::CirrusResult;
use crate::pagination::Records;
use crate::response::QueryResult;
use serde::de::DeserializeOwned;
use serde_json::Value;

impl Cirrus {
    /// Runs a SOQL query and returns the first batch of active records.
    ///
    /// Calls `GET /services/data/{api_version}/query?q={soql}`. The query
    /// string is URL-encoded automatically — pass plain SOQL.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use cirrus::{Cirrus, auth::StaticTokenAuth};
    /// # use std::sync::Arc;
    /// # async fn example() -> Result<(), cirrus::CirrusError> {
    /// # let auth = Arc::new(StaticTokenAuth::new("tok", "https://x.my.salesforce.com"));
    /// # let sf = Cirrus::builder().auth(auth).build()?;
    /// let result = sf.query("SELECT Id, Name FROM Account LIMIT 10").await?;
    /// for record in &result.records {
    ///     println!("{}", record["Name"]);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn query(&self, soql: &str) -> CirrusResult<QueryResult<Value>> {
        self.query_as(soql).await
    }

    /// Typed variant of [`query`](Self::query) — records deserialize as `R`.
    pub async fn query_as<R: DeserializeOwned>(&self, soql: &str) -> CirrusResult<QueryResult<R>> {
        let query = [("q", soql)];
        self.get_with_query("query", &query).await
    }

    /// Like [`query`](Self::query), but also returns soft-deleted and
    /// archived records. The returned envelope still uses
    /// [`QueryResult`] — soft-deleted rows are surfaced via the
    /// `IsDeleted` field on each record (when included in the SELECT).
    pub async fn query_all(&self, soql: &str) -> CirrusResult<QueryResult<Value>> {
        self.query_all_as(soql).await
    }

    /// Typed variant of [`query_all`](Self::query_all).
    pub async fn query_all_as<R: DeserializeOwned>(
        &self,
        soql: &str,
    ) -> CirrusResult<QueryResult<R>> {
        let query = [("q", soql)];
        self.get_with_query("queryAll", &query).await
    }

    /// Fetches the next batch of records using a
    /// [`QueryResult::next_records_url`] locator returned by a prior
    /// [`query`](Self::query) or [`query_all`](Self::query_all) call.
    ///
    /// The locator is an instance-relative path (e.g.
    /// `/services/data/v66.0/query/01g…-2000`). Pass it through verbatim;
    /// the leading `/` is optional.
    pub async fn query_more(&self, next_records_url: &str) -> CirrusResult<QueryResult<Value>> {
        self.query_more_as(next_records_url).await
    }

    /// Typed variant of [`query_more`](Self::query_more).
    pub async fn query_more_as<R: DeserializeOwned>(
        &self,
        next_records_url: &str,
    ) -> CirrusResult<QueryResult<R>> {
        // The locator may arrive without a leading '/' (callers
        // assembling fragments). Normalize so resolve_url's three-mode
        // dispatch always treats it as instance-rooted.
        let path = if next_records_url.starts_with('/') {
            next_records_url.to_string()
        } else {
            format!("/{next_records_url}")
        };
        self.get(&path).await
    }

    /// Streams query records lazily, walking `nextRecordsUrl` locators
    /// across pages. Yields one record at a time; subsequent pages are
    /// fetched on demand as the consumer drains the buffer.
    ///
    /// See [`pagination`](crate::pagination) for the full contract.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use cirrus::{Cirrus, auth::StaticTokenAuth};
    /// # use std::sync::Arc;
    /// use futures::StreamExt;
    /// # async fn example() -> Result<(), cirrus::CirrusError> {
    /// # let auth = Arc::new(StaticTokenAuth::new("tok", "https://x.my.salesforce.com"));
    /// # let sf = Cirrus::builder().auth(auth).build()?;
    /// let mut stream = sf.query_stream("SELECT Id FROM Account");
    /// while let Some(item) = stream.next().await {
    ///     let record = item?;
    ///     // process record
    ///     # let _ = record;
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn query_stream(&self, soql: &str) -> Records<Value> {
        self.query_stream_as(soql)
    }

    /// Typed variant of [`query_stream`](Self::query_stream).
    pub fn query_stream_as<R: DeserializeOwned + Send + Unpin + 'static>(
        &self,
        soql: &str,
    ) -> Records<R> {
        let client = self.clone();
        let soql = soql.to_string();
        let initial = Box::pin(async move { client.query_as::<R>(&soql).await });
        Records::new(self.clone(), initial)
    }

    /// Like [`query_stream`](Self::query_stream), but also includes
    /// soft-deleted and archived records (`/queryAll`).
    pub fn query_all_stream(&self, soql: &str) -> Records<Value> {
        self.query_all_stream_as(soql)
    }

    /// Typed variant of [`query_all_stream`](Self::query_all_stream).
    pub fn query_all_stream_as<R: DeserializeOwned + Send + Unpin + 'static>(
        &self,
        soql: &str,
    ) -> Records<R> {
        let client = self.clone();
        let soql = soql.to_string();
        let initial = Box::pin(async move { client.query_all_as::<R>(&soql).await });
        Records::new(self.clone(), initial)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use crate::Cirrus;
    use crate::auth::StaticTokenAuth;
    use serde_json::json;
    use std::sync::Arc;
    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn fixture(uri: String) -> Cirrus {
        let auth = Arc::new(StaticTokenAuth::new("tok", uri));
        Cirrus::builder().auth(auth).build().unwrap()
    }

    #[tokio::test]
    async fn stream_constructors_issue_no_request_until_polled() {
        // The reason the constructors are marked #[must_use]: discarding
        // the stream is silent, and no HTTP request is ever made.
        let server = MockServer::start().await;
        let sf = fixture(server.uri());

        drop(sf.query_stream("SELECT Id FROM Account"));
        drop(sf.query_all_stream("SELECT Id FROM Account"));

        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn query_passes_soql_in_q_param() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/query"))
            .and(query_param("q", "SELECT Id, Name FROM Account LIMIT 1"))
            .and(header("authorization", "Bearer tok"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "totalSize": 1,
                "done": true,
                "records": [
                    {"attributes": {"type": "Account"}, "Id": "001xx", "Name": "Acme"}
                ]
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let qr = sf
            .query("SELECT Id, Name FROM Account LIMIT 1")
            .await
            .unwrap();
        assert_eq!(qr.total_size, 1);
        assert!(qr.done);
        assert_eq!(qr.records.len(), 1);
        assert_eq!(qr.records[0]["Name"], "Acme");
        assert!(qr.next_records_url.is_none());
    }

    #[tokio::test]
    async fn query_paginated_response_exposes_next_locator() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/query"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "totalSize": 2500,
                "done": false,
                "nextRecordsUrl": "/services/data/v66.0/query/01gD0000002HU6KIAW-2000",
                "records": []
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let qr = sf.query("SELECT Id FROM Account").await.unwrap();
        assert!(!qr.done);
        assert_eq!(qr.total_size, 2500);
        assert_eq!(
            qr.next_records_url.as_deref(),
            Some("/services/data/v66.0/query/01gD0000002HU6KIAW-2000")
        );
    }

    #[tokio::test]
    async fn query_all_hits_queryall_endpoint() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/queryAll"))
            .and(query_param(
                "q",
                "SELECT Id, IsDeleted FROM Account WHERE IsDeleted = TRUE",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "totalSize": 1,
                "done": true,
                "records": [
                    {"attributes": {"type": "Account"}, "Id": "001xx", "IsDeleted": true}
                ]
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let qr = sf
            .query_all("SELECT Id, IsDeleted FROM Account WHERE IsDeleted = TRUE")
            .await
            .unwrap();
        assert_eq!(qr.records.len(), 1);
        assert_eq!(qr.records[0]["IsDeleted"], true);
    }

    #[tokio::test]
    async fn query_more_follows_locator() {
        let server = MockServer::start().await;

        // Locator carries v66.0 — this is what `nextRecordsUrl` returns
        // after a v66.0 query, regardless of the client's configured version.
        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/query/01gD0000002HU6KIAW-2000"))
            .and(header("authorization", "Bearer tok"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "totalSize": 2500,
                "done": true,
                "records": [
                    {"attributes": {"type": "Account"}, "Id": "001yy"}
                ]
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let qr = sf
            .query_more("/services/data/v66.0/query/01gD0000002HU6KIAW-2000")
            .await
            .unwrap();
        assert!(qr.done);
        assert_eq!(qr.records.len(), 1);
    }

    #[tokio::test]
    async fn query_more_accepts_locator_without_leading_slash() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/query/01gXXX-2000"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "totalSize": 0,
                "done": true,
                "records": []
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let qr = sf
            .query_more("services/data/v66.0/query/01gXXX-2000")
            .await
            .unwrap();
        assert!(qr.done);
    }

    #[tokio::test]
    async fn query_typed_records() {
        #[derive(serde::Deserialize)]
        struct Acct {
            #[serde(rename = "Name")]
            name: String,
        }

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/query"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "totalSize": 1,
                "done": true,
                "records": [
                    {"attributes": {"type": "Account"}, "Name": "Acme"}
                ]
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let qr = sf
            .query_as::<Acct>("SELECT Name FROM Account LIMIT 1")
            .await
            .unwrap();
        assert_eq!(qr.records.len(), 1);
        assert_eq!(qr.records[0].name, "Acme");
    }

    #[tokio::test]
    async fn query_surfaces_malformed_query_error() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/query"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!([{
                "message": "unexpected token: SELECTT",
                "errorCode": "MALFORMED_QUERY"
            }])))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let err = sf.query("SELECTT Id FROM Account").await.unwrap_err();
        match err {
            crate::CirrusError::Api { status, errors, .. } => {
                assert_eq!(status, 400);
                assert_eq!(errors[0].error_code, "MALFORMED_QUERY");
            }
            other => panic!("expected Api error, got {other:?}"),
        }
    }
}
