//! Event Monitoring — `EventLogFile` retrieve + binary log download.
//!
//! Salesforce's Event Monitoring product stores audit events (API calls,
//! logins, Apex executions, page views, etc.) as `EventLogFile` sObject
//! records. Each record carries metadata (event type, date, size) and a
//! `LogFile` URL pointing at a CSV payload of the actual events.
//!
//! There's no dedicated REST API for event monitoring — it's two
//! existing primitives stitched together:
//!
//! 1. **Discovery** — issue a SOQL query against `EventLogFile` via
//!    [`Cirrus::query`]/[`Cirrus::query_as`]. Use
//!    [`EventLogFileRecord`] as the typed envelope.
//! 2. **Download** — for each record, GET the CSV payload at the URL
//!    in `LogFile`. This handler exposes
//!    [`download`](EventMonitoringHandler::download) (by record ID) and
//!    [`download_url`](EventMonitoringHandler::download_url) (by the
//!    `LogFile` field's instance-relative URL — typically what you have
//!    in hand from the query).
//!
//! Both download methods reuse the [`Cirrus::fetch_raw`] transport
//! shared with Bulk 2.0 — the response comes back as `bytes::Bytes`,
//! and non-2xx still surfaces as the standard
//! [`crate::CirrusError::Api`].
//!
//! # Wire shape
//!
//! Per the [Query Event Monitoring Data] doc:
//!
//! ```text
//! GET /services/data/{v}/query?q=SELECT+Id,EventType,LogFile,LogDate,LogFileLength+FROM+EventLogFile
//! → JSON: standard QueryResult envelope, records have shape:
//!   { Id, EventType, LogFile, LogDate, LogFileLength, [Interval, Sequence, CreatedDate] }
//!
//! GET /services/data/{v}/sobjects/EventLogFile/{id}/LogFile
//! → CSV bytes
//! ```
//!
//! [Query Event Monitoring Data]: https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/dome_event_log_file_query.htm
//!
//! # Hourly vs 24-hour files
//!
//! Orgs with hourly Event Monitoring enabled produce both daily and
//! hourly log files. Filter via the `Interval` field:
//!
//! ```ignore
//! sf.query_as::<EventLogFileRecord>(
//!     "SELECT Id, EventType, LogFile, LogDate, Interval, Sequence \
//!      FROM EventLogFile WHERE Interval = 'Hourly' AND CreatedDate > 2024-01-01T00:00:00Z"
//! ).await?;
//! ```
//!
//! Per Salesforce's incremental-ingestion guidance, drive subsequent
//! pulls off `CreatedDate` (when the file became downloadable), not
//! `LogDate` (when the events occurred).
//!
//! # Decoding the CSV
//!
//! The CSV columns vary by `EventType` — the `LogFileFieldNames` and
//! `LogFileFieldTypes` fields on `EventLogFile`'s describe metadata
//! enumerate them per type. This handler intentionally does not decode
//! the CSV: column sets are large, evolve across releases, and most
//! callers want to ferry the raw bytes into a downstream analytics
//! pipeline (Splunk, Snowflake, etc.) anyway. The `csv` crate or a
//! tabular DataFrame library is the right next step on the caller side.
//!
//! [`Cirrus::query`]: crate::Cirrus::query
//! [`Cirrus::query_as`]: crate::Cirrus::query_as
//! [`Cirrus::fetch_raw`]: crate::Cirrus
//! [`EventLogFileRecord`]: crate::EventLogFileRecord

use crate::Cirrus;
use crate::error::{CirrusError, CirrusResult};

const CSV_ACCEPT: &str = "text/csv";

impl Cirrus {
    /// Returns a handler for Event Monitoring (`EventLogFile`) log-file
    /// downloads.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use cirrus::{Cirrus, auth::StaticTokenAuth};
    /// # use std::sync::Arc;
    /// use cirrus::EventLogFileRecord;
    /// # async fn example() -> Result<(), cirrus::CirrusError> {
    /// # let auth = Arc::new(StaticTokenAuth::new("tok", "https://x.my.salesforce.com"));
    /// # let sf = Cirrus::builder().auth(auth).build()?;
    /// // Discover via SOQL, download via the handler.
    /// let result = sf.query_as::<EventLogFileRecord>(
    ///     "SELECT Id, EventType, LogFile, LogDate, LogFileLength \
    ///      FROM EventLogFile WHERE EventType = 'API' ORDER BY LogDate DESC LIMIT 1"
    /// ).await?;
    /// if let Some(record) = result.records.first() {
    ///     let csv_bytes = sf.event_monitoring().download(&record.id).await?;
    ///     println!("downloaded {} bytes", csv_bytes.len());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn event_monitoring(&self) -> EventMonitoringHandler<'_> {
        EventMonitoringHandler { client: self }
    }
}

/// Handler for Event Monitoring binary downloads.
///
/// Discovery (querying the `EventLogFile` sObject) goes through the
/// regular [`Cirrus::query`] / [`Cirrus::query_as`] methods —
/// this handler only exposes the binary CSV fetch.
#[derive(Debug)]
pub struct EventMonitoringHandler<'a> {
    client: &'a Cirrus,
}

impl EventMonitoringHandler<'_> {
    /// Downloads the CSV log for a given `EventLogFile` record ID.
    ///
    /// Calls
    /// `GET /services/data/{api_version}/sobjects/EventLogFile/{id}/LogFile`
    /// with `Accept: text/csv`. Returns the raw bytes — decoding the
    /// CSV is left to the caller (column sets are EventType-dependent;
    /// see the module-level docs).
    pub async fn download(&self, log_file_id: &str) -> CirrusResult<bytes::Bytes> {
        // Percent-encode the record ID as its own path segment. `fetch_raw`
        // resolves the resulting fully-qualified URL through passthrough
        // mode, so the encoding is preserved.
        let url = self.client.versioned_segments(&[
            "sobjects",
            "EventLogFile",
            log_file_id,
            "LogFile",
        ])?;
        let (_headers, bytes) = self
            .client
            .fetch_raw(reqwest::Method::GET, &url, CSV_ACCEPT, None)
            .await?;
        Ok(bytes)
    }

    /// Downloads the CSV log given a `LogFile` URL — typically the
    /// `LogFile` field on a queried [`EventLogFileRecord`].
    ///
    /// The URL Salesforce returns is instance-relative (e.g.
    /// `/services/data/v66.0/sobjects/EventLogFile/0AT.../LogFile`),
    /// so it carries the API version of the originating query — same
    /// pattern as `nextRecordsUrl` on [`crate::QueryResult`]. Pass it
    /// through verbatim; the leading `/` is normalized into an
    /// instance-rooted resolution.
    ///
    /// # Errors
    ///
    /// A fully-qualified URL is accepted only when its origin matches
    /// the session's instance URL. Anything else returns
    /// [`CirrusError::InvalidResponse`] without issuing a request:
    /// downloads are bearer-authenticated, and `log_file_url` is a
    /// server-supplied value, so following it to another host would
    /// hand the org's access token to that host.
    ///
    /// [`EventLogFileRecord`]: crate::EventLogFileRecord
    /// [`CirrusError::InvalidResponse`]: crate::CirrusError::InvalidResponse
    pub async fn download_url(&self, log_file_url: &str) -> CirrusResult<bytes::Bytes> {
        let path = self.instance_rooted(log_file_url)?;
        let (_headers, bytes) = self
            .client
            .fetch_raw(reqwest::Method::GET, &path, CSV_ACCEPT, None)
            .await?;
        Ok(bytes)
    }

    /// Normalizes a `LogFile` value into something that resolves against
    /// this session's instance, rejecting any absolute URL that points
    /// somewhere else.
    fn instance_rooted(&self, log_file_url: &str) -> CirrusResult<String> {
        if !(log_file_url.starts_with("http://") || log_file_url.starts_with("https://")) {
            // Bare paths are normalized the way query_more does, so
            // callers can pass the LogFile field straight through
            // whether or not it has a leading slash.
            return Ok(if log_file_url.starts_with('/') {
                log_file_url.to_string()
            } else {
                format!("/{log_file_url}")
            });
        }

        let candidate = url::Url::parse(log_file_url)?;
        let instance = url::Url::parse(self.client.auth().instance_url())?;
        if candidate.origin() == instance.origin() {
            Ok(log_file_url.to_string())
        } else {
            Err(CirrusError::InvalidResponse(format!(
                "EventLogFile LogFile URL points at {}, not the org instance {}",
                candidate.origin().ascii_serialization(),
                instance.origin().ascii_serialization(),
            )))
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::auth::StaticTokenAuth;
    use std::sync::Arc;
    use wiremock::matchers::{header, method, path, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn fixture(uri: String) -> Cirrus {
        let auth = Arc::new(StaticTokenAuth::new("tok", uri));
        Cirrus::builder().auth(auth).build().unwrap()
    }

    #[tokio::test]
    async fn download_targets_logfile_endpoint_and_returns_csv_bytes() {
        let server = MockServer::start().await;

        let csv = "TIMESTAMP,EVENT_TYPE,USER_ID\n2024-01-01T00:00:00.000Z,API,005xx\n";
        Mock::given(method("GET"))
            .and(path(
                "/services/data/v66.0/sobjects/EventLogFile/0ATD000000001bROAQ/LogFile",
            ))
            .and(header("authorization", "Bearer tok"))
            .and(header("accept", "text/csv"))
            .respond_with(ResponseTemplate::new(200).set_body_string(csv))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let bytes = sf
            .event_monitoring()
            .download("0ATD000000001bROAQ")
            .await
            .unwrap();
        assert_eq!(&bytes[..], csv.as_bytes());
    }

    #[tokio::test]
    async fn download_percent_encodes_record_id() {
        // A reserved character in the record ID must be percent-encoded into
        // a single path segment rather than altering the path structure.
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(
                r"^/services/data/v66\.0/sobjects/EventLogFile/.+/LogFile$",
            ))
            .and(header("accept", "text/csv"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let bytes = sf
            .event_monitoring()
            .download("0AT/weird id")
            .await
            .unwrap();
        assert_eq!(&bytes[..], b"ok");
    }

    #[tokio::test]
    async fn download_url_accepts_instance_relative_path_from_query() {
        // Mirrors the LogFile field shape from dome_event_log_file_query
        // doc: a /services/data/v66.0/... path that may carry a
        // different API version than the client's configured one.
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path(
                "/services/data/v66.0/sobjects/EventLogFile/0ATD000000001bROAQ/LogFile",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_string("X,Y\n1,2\n"))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let bytes = sf
            .event_monitoring()
            .download_url("/services/data/v66.0/sobjects/EventLogFile/0ATD000000001bROAQ/LogFile")
            .await
            .unwrap();
        assert_eq!(&bytes[..], b"X,Y\n1,2\n");
    }

    #[tokio::test]
    async fn download_url_normalizes_path_without_leading_slash() {
        // Edge case: caller stripped the leading slash from the LogFile
        // field. Should still resolve correctly.
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path(
                "/services/data/v66.0/sobjects/EventLogFile/0ATD000000001bROAQ/LogFile",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok\n"))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let bytes = sf
            .event_monitoring()
            .download_url("services/data/v66.0/sobjects/EventLogFile/0ATD000000001bROAQ/LogFile")
            .await
            .unwrap();
        assert_eq!(&bytes[..], b"ok\n");
    }

    #[tokio::test]
    async fn download_url_accepts_absolute_url_on_the_instance_host() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path(
                "/services/data/v66.0/sobjects/EventLogFile/0ATD000000001bROAQ/LogFile",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok\n"))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let absolute = format!(
            "{}/services/data/v66.0/sobjects/EventLogFile/0ATD000000001bROAQ/LogFile",
            server.uri()
        );
        let bytes = sf.event_monitoring().download_url(&absolute).await.unwrap();
        assert_eq!(&bytes[..], b"ok\n");
    }

    #[tokio::test]
    async fn download_url_refuses_a_foreign_host() {
        // SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/dome_event_log_file_query.htm
        // Every documented LogFile value is an instance-relative path.
        // Downloads are bearer-authenticated, so a value naming another
        // host must never be followed — that would hand the org access
        // token to that host.
        let server = MockServer::start().await;
        let sf = fixture(server.uri());

        let err = sf
            .event_monitoring()
            .download_url("https://collector.attacker.example/x")
            .await
            .unwrap_err();
        assert!(matches!(err, CirrusError::InvalidResponse(_)), "{err:?}");
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn download_surfaces_404_as_api_error() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path(
                "/services/data/v66.0/sobjects/EventLogFile/0ATmissing/LogFile",
            ))
            .respond_with(
                ResponseTemplate::new(404).set_body_json(serde_json::json!([{
                    "errorCode": "NOT_FOUND",
                    "message": "The requested resource does not exist"
                }])),
            )
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let err = sf
            .event_monitoring()
            .download("0ATmissing")
            .await
            .unwrap_err();
        match err {
            crate::CirrusError::Api { status, errors, .. } => {
                assert_eq!(status, 404);
                assert_eq!(errors[0].error_code, "NOT_FOUND");
            }
            other => panic!("expected Api error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn query_via_existing_method_deserializes_into_event_log_file_record() {
        // Confirms the typed EventLogFileRecord envelope works against
        // the documented response shape from dome_event_log_file_query.
        // No new transport — just a typed query via the existing
        // Cirrus::query_as.
        use crate::EventLogFileRecord;
        use crate::QueryResult;
        use wiremock::matchers::query_param;

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/query"))
            .and(query_param(
                "q",
                "SELECT Id, EventType, LogFile, LogDate, LogFileLength FROM EventLogFile",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "totalSize": 1,
                "done": true,
                "records": [{
                    "attributes": {
                        "type": "EventLogFile",
                        "url": "/services/data/v66.0/sobjects/EventLogFile/0ATD000000001bROAQ"
                    },
                    "Id": "0ATD000000001bROAQ",
                    "EventType": "API",
                    "LogFile": "/services/data/v66.0/sobjects/EventLogFile/0ATD000000001bROAQ/LogFile",
                    "LogDate": "2014-03-14T00:00:00.000+0000",
                    "LogFileLength": 2692.0
                }]
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let result: QueryResult<EventLogFileRecord> = sf
            .query_as("SELECT Id, EventType, LogFile, LogDate, LogFileLength FROM EventLogFile")
            .await
            .unwrap();
        let rec = &result.records[0];
        assert_eq!(rec.id, "0ATD000000001bROAQ");
        assert_eq!(rec.event_type, "API");
        assert_eq!(
            rec.log_file,
            "/services/data/v66.0/sobjects/EventLogFile/0ATD000000001bROAQ/LogFile"
        );
        assert_eq!(rec.log_file_length, Some(2692.0));
        // Hourly fields not selected → None.
        assert!(rec.interval.is_none());
        assert!(rec.sequence.is_none());
    }

    #[tokio::test]
    async fn query_with_hourly_fields_populates_interval_and_sequence() {
        use crate::EventLogFileRecord;
        use crate::QueryResult;

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/query"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "totalSize": 1,
                "done": true,
                "records": [{
                    "attributes": {"type": "EventLogFile"},
                    "Id": "0ATxx",
                    "EventType": "URI",
                    "LogFile": "/services/data/v66.0/sobjects/EventLogFile/0ATxx/LogFile",
                    "LogDate": "2024-03-14T00:00:00.000+0000",
                    "Interval": "Hourly",
                    "Sequence": 3,
                    "CreatedDate": "2024-03-14T03:30:00.000+0000"
                }]
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let result: QueryResult<EventLogFileRecord> = sf
            .query_as(
                "SELECT Id, EventType, LogFile, LogDate, Interval, Sequence, CreatedDate \
                 FROM EventLogFile WHERE Interval = 'Hourly'",
            )
            .await
            .unwrap();
        let rec = &result.records[0];
        assert_eq!(rec.interval.as_deref(), Some("Hourly"));
        assert_eq!(rec.sequence, Some(3));
        assert!(rec.created_date.is_some());
    }
}
