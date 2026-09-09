//! Bulk API 2.0 — async, CSV-driven ingest and query operations.
//!
//! Two flavors live under `/services/data/{version}/jobs/`:
//!
//! - **Ingest** (`/jobs/ingest`) — create / update / upsert / delete /
//!   hardDelete records from CSV uploads. Salesforce base64-encodes an
//!   upload and caps the encoded form at 150 MB; because that
//!   conversion adds roughly 50%, keep each upload's raw CSV under
//!   100 MB. The caller drives the job through `Open` →
//!   `UploadComplete` → `InProgress` → `JobComplete` / `Failed` /
//!   `Aborted`. Reach via [`BulkHandler::ingest`].
//! - **Query** (`/jobs/query`) — async SOQL execution that streams
//!   results as CSV with cursor-based pagination. Reach via
//!   [`BulkHandler::query`].
//!
//! # CSV transport
//!
//! Bulk 2.0 is the only Salesforce REST surface that uses `text/csv`
//! bodies (not JSON). Upload and result-fetch methods take/return
//! [`bytes::Bytes`] rather than typed bodies so callers can stream large
//! payloads without forcing buffer copies. CSV parsing/encoding is the
//! caller's responsibility — pick whichever crate fits the use case
//! (`csv`, `polars`, etc.).
//!
//! # Polling is on the caller
//!
//! The SDK exposes the building blocks (create, upload, close, get,
//! results, delete) but does *not* automate polling. Salesforce ingest
//! jobs can take seconds (small batches) or hours (millions of records);
//! the right poll cadence depends entirely on payload size and the
//! caller's latency vs. quota trade-offs. Build a polling loop with the
//! interval that fits the workload.

use crate::Cirrus;
use crate::error::CirrusResult;
use crate::response::{
    BulkIngestJob, BulkJobStateChange, BulkOperation, BulkQueryJob, BulkQueryResults,
};
use serde::Serialize;

const CSV_CONTENT_TYPE: &str = "text/csv";
const CSV_ACCEPT: &str = "text/csv";
const SFORCE_LOCATOR: &str = "Sforce-Locator";
const SFORCE_NUM_RECORDS: &str = "Sforce-NumberOfRecords";

impl Cirrus {
    /// Returns a handler for Bulk API 2.0 (`/services/data/{api_version}/jobs/...`).
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use cirrus::{Cirrus, auth::StaticTokenAuth};
    /// # use std::sync::Arc;
    /// use cirrus::{BulkIngestSpec, BulkOperation};
    /// # async fn example() -> Result<(), cirrus::CirrusError> {
    /// # let auth = Arc::new(StaticTokenAuth::new("tok", "https://x.my.salesforce.com"));
    /// # let sf = Cirrus::builder().auth(auth).build()?;
    /// let bulk = sf.bulk();
    /// let ingest = bulk.ingest();
    /// let spec = BulkIngestSpec {
    ///     object: "Account".into(),
    ///     operation: BulkOperation::Insert,
    ///     external_id_field_name: None,
    ///     line_ending: None,
    ///     column_delimiter: None,
    ///     assignment_rule_id: None,
    /// };
    /// let job = ingest.create(&spec).await?;
    /// ingest.upload(&job.id, cirrus::Bytes::from("Name\nAcme\n")).await?;
    /// ingest.close(&job.id).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn bulk(&self) -> BulkHandler<'_> {
        BulkHandler { client: self }
    }
}

/// Top-level Bulk API 2.0 handler. Returned by [`Cirrus::bulk`].
#[derive(Debug)]
pub struct BulkHandler<'a> {
    client: &'a Cirrus,
}

impl BulkHandler<'_> {
    /// Returns a sub-handler for ingest (CRUD-style) bulk jobs under
    /// `/jobs/ingest`.
    pub fn ingest(&self) -> BulkIngestHandler<'_> {
        BulkIngestHandler {
            client: self.client,
        }
    }

    /// Returns a sub-handler for SOQL query bulk jobs under `/jobs/query`.
    pub fn query(&self) -> BulkQueryHandler<'_> {
        BulkQueryHandler {
            client: self.client,
        }
    }
}

/// Handler for Bulk 2.0 ingest jobs (`/jobs/ingest`).
///
/// Typical lifecycle for a single job:
///
/// 1. [`create`](Self::create) — `POST /jobs/ingest` with an operation
///    and target sObject; Salesforce returns a job in `Open` state.
/// 2. [`upload`](Self::upload) — `PUT /jobs/ingest/{id}/batches` with
///    CSV bytes. Salesforce returns 201 with no body.
/// 3. [`close`](Self::close) — `PATCH /jobs/ingest/{id}` with
///    `{"state": "UploadComplete"}`. Tells Salesforce to start
///    processing; cannot upload more data after this.
/// 4. Poll [`get`](Self::get) until `state` is `JobComplete`, `Failed`,
///    or `Aborted`.
/// 5. Fetch results: [`successful_results`](Self::successful_results) /
///    [`failed_results`](Self::failed_results) /
///    [`unprocessed_records`](Self::unprocessed_records). Each returns
///    raw CSV bytes.
/// 6. [`delete`](Self::delete) — `DELETE /jobs/ingest/{id}` once
///    you've consumed the results.
///
/// [`abort`](Self::abort) cancels a job mid-flight if needed.
#[derive(Debug)]
pub struct BulkIngestHandler<'a> {
    client: &'a Cirrus,
}

impl BulkIngestHandler<'_> {
    /// Creates a new ingest job. Salesforce returns the job in `Open`
    /// state with a `content_url` indicating where to upload data.
    ///
    /// Calls `POST /services/data/{api_version}/jobs/ingest`.
    pub async fn create(&self, spec: &BulkIngestSpec) -> CirrusResult<BulkIngestJob> {
        self.client.post("jobs/ingest", spec).await
    }

    /// Uploads CSV record data for a job. The job must be in `Open` state.
    /// Salesforce returns 201 with no body on success.
    ///
    /// Keep `csv` under 100 MB: Salesforce converts the body to base64
    /// before applying its 150 MB ceiling, and that conversion inflates
    /// the data by roughly 50%. Split larger data across uploads.
    ///
    /// A lost response is never retried automatically. Salesforce
    /// documents this `PUT` as uploading job data, not as replacing
    /// data the job already holds, so a replay risks loading the same
    /// rows twice. After a transient failure, check the job with
    /// [`get`](Self::get) before deciding whether to upload again.
    ///
    /// Calls `PUT /services/data/{api_version}/jobs/ingest/{job_id}/batches`
    /// with `Content-Type: text/csv`.
    pub async fn upload(&self, job_id: &str, csv: bytes::Bytes) -> CirrusResult<()> {
        let path = self
            .client
            .versioned_segments(&["jobs", "ingest", job_id, "batches"])?;
        self.client
            .send_with_body(
                reqwest::Method::PUT,
                &path,
                csv,
                CSV_CONTENT_TYPE,
                crate::retry::Replay::Never,
            )
            .await
    }

    /// Marks a job as ready for processing by transitioning its state to
    /// `UploadComplete`. Returns the partial job view Salesforce sends
    /// for state changes — poll [`get`](Self::get) for full metadata.
    ///
    /// Calls `PATCH /services/data/{api_version}/jobs/ingest/{job_id}`
    /// with `{"state": "UploadComplete"}`.
    pub async fn close(&self, job_id: &str) -> CirrusResult<BulkJobStateChange> {
        self.patch_state(job_id, "UploadComplete").await
    }

    /// Aborts a job. Records already processed remain committed —
    /// Salesforce does *not* roll back. Returns the partial job view
    /// Salesforce sends for state changes.
    ///
    /// Calls `PATCH /services/data/{api_version}/jobs/ingest/{job_id}`
    /// with `{"state": "Aborted"}`.
    pub async fn abort(&self, job_id: &str) -> CirrusResult<BulkJobStateChange> {
        self.patch_state(job_id, "Aborted").await
    }

    /// Fetches the current state and metadata for a job.
    ///
    /// Calls `GET /services/data/{api_version}/jobs/ingest/{job_id}`.
    pub async fn get(&self, job_id: &str) -> CirrusResult<BulkIngestJob> {
        let path = self
            .client
            .versioned_segments(&["jobs", "ingest", job_id])?;
        self.client
            .send_at::<_, (), ()>(reqwest::Method::GET, &path, None, None)
            .await
    }

    /// Deletes a job. Only valid when the job is in `UploadComplete`,
    /// `JobComplete`, `Aborted`, or `Failed` state — an ingest job that
    /// has been closed can be discarded without aborting it first.
    /// Returns 204 on success.
    ///
    /// Calls `DELETE /services/data/{api_version}/jobs/ingest/{job_id}`.
    pub async fn delete(&self, job_id: &str) -> CirrusResult<()> {
        let path = self
            .client
            .versioned_segments(&["jobs", "ingest", job_id])?;
        self.client
            .send_at::<(), (), ()>(reqwest::Method::DELETE, &path, None, None)
            .await
    }

    /// Returns CSV bytes for records that succeeded. Each row carries
    /// the original input fields plus `sf__Id` (Salesforce ID of the
    /// affected record) and `sf__Created` (`true` if the record was
    /// created as part of this upsert/insert).
    ///
    /// Calls
    /// `GET /services/data/{api_version}/jobs/ingest/{job_id}/successfulResults/`.
    pub async fn successful_results(&self, job_id: &str) -> CirrusResult<bytes::Bytes> {
        self.fetch_csv_results(job_id, "successfulResults").await
    }

    /// Returns CSV bytes for records that failed validation/save. Each
    /// row carries the original input fields plus `sf__Error` (the
    /// human-readable error) and `sf__Id` (empty for failed creates).
    ///
    /// Calls
    /// `GET /services/data/{api_version}/jobs/ingest/{job_id}/failedResults/`.
    pub async fn failed_results(&self, job_id: &str) -> CirrusResult<bytes::Bytes> {
        self.fetch_csv_results(job_id, "failedResults").await
    }

    /// Returns CSV bytes for records that were never attempted (e.g.
    /// the job was aborted before reaching them).
    ///
    /// Calls
    /// `GET /services/data/{api_version}/jobs/ingest/{job_id}/unprocessedrecords/`.
    pub async fn unprocessed_records(&self, job_id: &str) -> CirrusResult<bytes::Bytes> {
        self.fetch_csv_results(job_id, "unprocessedrecords").await
    }

    async fn patch_state(&self, job_id: &str, new_state: &str) -> CirrusResult<BulkJobStateChange> {
        let path = self
            .client
            .versioned_segments(&["jobs", "ingest", job_id])?;
        let body = StatePatch { state: new_state };
        self.client
            .send_at::<_, (), _>(reqwest::Method::PATCH, &path, None, Some(&body))
            .await
    }

    async fn fetch_csv_results(&self, job_id: &str, kind: &str) -> CirrusResult<bytes::Bytes> {
        let path = self
            .client
            .versioned_segments(&["jobs", "ingest", job_id, kind])?;
        let (_, bytes) = self
            .client
            .fetch_raw(reqwest::Method::GET, &path, CSV_ACCEPT, None)
            .await?;
        Ok(bytes)
    }
}

/// Handler for Bulk 2.0 query jobs (`/jobs/query`).
///
/// Lifecycle for a single query job:
///
/// 1. [`create`](Self::create) — `POST /jobs/query` with a SOQL string
///    and operation (`Query` or `QueryAll`); Salesforce returns a job
///    that progresses straight to `UploadComplete` (no upload step).
/// 2. Poll [`get`](Self::get) until `state` is `JobComplete`,
///    `Failed`, or `Aborted`.
/// 3. Drain results via [`results`](Self::results), passing
///    [`BulkQueryResults::locator`] back as the cursor on subsequent
///    calls until it returns `None`.
/// 4. [`delete`](Self::delete) when done.
#[derive(Debug)]
pub struct BulkQueryHandler<'a> {
    client: &'a Cirrus,
}

impl BulkQueryHandler<'_> {
    /// Creates a new query job.
    ///
    /// Calls `POST /services/data/{api_version}/jobs/query`.
    pub async fn create(&self, spec: &BulkQuerySpec) -> CirrusResult<BulkQueryJob> {
        self.client.post("jobs/query", spec).await
    }

    /// Fetches the current state and metadata for a query job.
    ///
    /// Calls `GET /services/data/{api_version}/jobs/query/{job_id}`.
    pub async fn get(&self, job_id: &str) -> CirrusResult<BulkQueryJob> {
        let path = self.client.versioned_segments(&["jobs", "query", job_id])?;
        self.client
            .send_at::<_, (), ()>(reqwest::Method::GET, &path, None, None)
            .await
    }

    /// Aborts a running query job. Returns the partial job view
    /// Salesforce sends for state changes — see [`get`](Self::get) for
    /// full metadata.
    ///
    /// Calls `PATCH /services/data/{api_version}/jobs/query/{job_id}`
    /// with `{"state": "Aborted"}`.
    pub async fn abort(&self, job_id: &str) -> CirrusResult<BulkJobStateChange> {
        let path = self.client.versioned_segments(&["jobs", "query", job_id])?;
        let body = StatePatch { state: "Aborted" };
        self.client
            .send_at::<_, (), _>(reqwest::Method::PATCH, &path, None, Some(&body))
            .await
    }

    /// Fetches one page of query results as CSV plus the cursor for
    /// the next page.
    ///
    /// `locator` is the cursor returned by a previous
    /// [`BulkQueryResults::locator`]. Pass `None` for the first page.
    ///
    /// `max_records` is an upper bound on the rows in this page, not a
    /// guarantee: the response is still subject to Salesforce's size
    /// limits, so a page can come back shorter than requested. Omit it
    /// to let Salesforce pick. A short page therefore says nothing
    /// about the end of the result set — keep draining until
    /// [`BulkQueryResults::locator`] returns `None`.
    ///
    /// Calls
    /// `GET /services/data/{api_version}/jobs/query/{job_id}/results`
    /// with optional `?locator=&maxRecords=` query parameters.
    pub async fn results(
        &self,
        job_id: &str,
        locator: Option<&str>,
        max_records: Option<u32>,
    ) -> CirrusResult<BulkQueryResults> {
        let path = self
            .client
            .versioned_segments(&["jobs", "query", job_id, "results"])?;
        let max_records_str = max_records.map(|n| n.to_string());
        let mut query: Vec<(&str, &str)> = Vec::with_capacity(2);
        if let Some(loc) = locator {
            query.push(("locator", loc));
        }
        if let Some(ref n) = max_records_str {
            query.push(("maxRecords", n.as_str()));
        }
        let query_slice = if query.is_empty() {
            None
        } else {
            Some(query.as_slice())
        };
        let (headers, csv) = self
            .client
            .fetch_raw(reqwest::Method::GET, &path, CSV_ACCEPT, query_slice)
            .await?;
        Ok(BulkQueryResults {
            csv,
            locator: header_string(&headers, SFORCE_LOCATOR).filter(|s| s != "null"),
            number_of_records: header_string(&headers, SFORCE_NUM_RECORDS)
                .and_then(|s| s.parse().ok()),
        })
    }

    /// Deletes a query job. Only valid when the job is in `JobComplete`,
    /// `Aborted`, or `Failed` state.
    ///
    /// Calls `DELETE /services/data/{api_version}/jobs/query/{job_id}`.
    pub async fn delete(&self, job_id: &str) -> CirrusResult<()> {
        let path = self.client.versioned_segments(&["jobs", "query", job_id])?;
        self.client
            .send_at::<(), (), ()>(reqwest::Method::DELETE, &path, None, None)
            .await
    }
}

/// Request body for [`BulkIngestHandler::create`].
///
/// `content_type` is fixed to `"CSV"` server-side (the only supported
/// value) and is not exposed here. Salesforce defaults `column_delimiter`
/// to `Comma` and `line_ending` to `LF` when omitted.
#[derive(Debug, Clone, Serialize)]
pub struct BulkIngestSpec {
    /// API name of the target sObject (e.g. `"Account"`).
    pub object: String,
    /// Operation kind — must be one of the ingest values: `Insert`,
    /// `Update`, `Upsert`, `Delete`, `HardDelete`. Query/QueryAll on a
    /// `BulkIngestSpec` will produce a server-side error.
    pub operation: BulkOperation,
    /// External ID field name. Required when `operation` is `Upsert`,
    /// must be `None` for the other operations.
    #[serde(
        rename = "externalIdFieldName",
        skip_serializing_if = "Option::is_none"
    )]
    pub external_id_field_name: Option<String>,
    /// CSV line ending. Defaults server-side to `LF` when `None`.
    #[serde(rename = "lineEnding", skip_serializing_if = "Option::is_none")]
    pub line_ending: Option<crate::response::BulkLineEnding>,
    /// CSV column delimiter. Defaults server-side to `Comma` when `None`.
    #[serde(rename = "columnDelimiter", skip_serializing_if = "Option::is_none")]
    pub column_delimiter: Option<crate::response::BulkColumnDelimiter>,
    /// Optional assignment-rule ID (Lead/Case routing).
    #[serde(rename = "assignmentRuleId", skip_serializing_if = "Option::is_none")]
    pub assignment_rule_id: Option<String>,
}

/// Request body for [`BulkQueryHandler::create`].
///
/// Note that Salesforce caps a single bulk query at 60 minutes of
/// processing — for larger result sets, partition the SOQL with `WHERE`
/// clauses and run multiple jobs.
#[derive(Debug, Clone, Serialize)]
pub struct BulkQuerySpec {
    /// SOQL to execute.
    pub query: String,
    /// `Query` for active records only, `QueryAll` to include
    /// soft-deleted and archived records.
    pub operation: BulkOperation,
    /// CSV line ending. Defaults server-side to `LF` when `None`.
    #[serde(rename = "lineEnding", skip_serializing_if = "Option::is_none")]
    pub line_ending: Option<crate::response::BulkLineEnding>,
    /// CSV column delimiter. Defaults server-side to `Comma` when `None`.
    #[serde(rename = "columnDelimiter", skip_serializing_if = "Option::is_none")]
    pub column_delimiter: Option<crate::response::BulkColumnDelimiter>,
}

#[derive(Serialize)]
struct StatePatch<'a> {
    state: &'a str,
}

fn header_string(headers: &reqwest::header::HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::auth::StaticTokenAuth;
    use crate::response::{BulkColumnDelimiter, BulkJobState, BulkLineEnding};
    use serde_json::json;
    use std::sync::Arc;
    use wiremock::matchers::{body_json, header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn fixture(uri: String) -> Cirrus {
        let auth = Arc::new(StaticTokenAuth::new("tok", uri));
        Cirrus::builder().auth(auth).build().unwrap()
    }

    fn state_change_response(id: &str, operation: &str, state: &str) -> serde_json::Value {
        // Mirrors the documented state-transition PATCH response — see
        // api_asynch query_abort_job (the ingest close_job/abort_job
        // pages reuse the generic field table, but the wire matches
        // this shape). No `jobType`, `lineEnding`, or `columnDelimiter`.
        json!({
            "id": id,
            "operation": operation,
            "object": "Account",
            "createdById": "005xx",
            "createdDate": "2024-01-01T00:00:00.000+0000",
            "systemModstamp": "2024-01-01T00:00:00.000+0000",
            "state": state,
            "concurrencyMode": "Parallel",
            "contentType": "CSV",
            "apiVersion": 60.0
        })
    }

    fn ingest_job_response(id: &str, state: &str) -> serde_json::Value {
        json!({
            "id": id,
            "operation": "insert",
            "object": "Account",
            "createdById": "005xx",
            "createdDate": "2024-01-01T00:00:00.000+0000",
            "systemModstamp": "2024-01-01T00:00:00.000+0000",
            "state": state,
            "concurrencyMode": "Parallel",
            "contentType": "CSV",
            "apiVersion": 60.0,
            "lineEnding": "LF",
            "columnDelimiter": "COMMA",
            "jobType": "V2Ingest"
        })
    }

    #[tokio::test]
    async fn ingest_create_posts_spec_and_parses_open_job() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/services/data/v66.0/jobs/ingest"))
            .and(header("authorization", "Bearer tok"))
            .and(body_json(json!({
                "object": "Account",
                "operation": "insert"
            })))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(ingest_job_response("750xx", "Open")),
            )
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let job = sf
            .bulk()
            .ingest()
            .create(&BulkIngestSpec {
                object: "Account".into(),
                operation: BulkOperation::Insert,
                external_id_field_name: None,
                line_ending: None,
                column_delimiter: None,
                assignment_rule_id: None,
            })
            .await
            .unwrap();
        assert_eq!(job.id, "750xx");
        assert_eq!(job.state, BulkJobState::Open);
    }

    #[tokio::test]
    async fn ingest_create_serializes_upsert_with_external_id() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/services/data/v66.0/jobs/ingest"))
            .and(body_json(json!({
                "object": "Account",
                "operation": "upsert",
                "externalIdFieldName": "External_Id__c",
                "lineEnding": "CRLF",
                "columnDelimiter": "TAB"
            })))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(ingest_job_response("750xx", "Open")),
            )
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        sf.bulk()
            .ingest()
            .create(&BulkIngestSpec {
                object: "Account".into(),
                operation: BulkOperation::Upsert,
                external_id_field_name: Some("External_Id__c".into()),
                line_ending: Some(BulkLineEnding::CRLF),
                column_delimiter: Some(BulkColumnDelimiter::Tab),
                assignment_rule_id: None,
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn ingest_upload_sends_csv_body_with_text_csv_content_type() {
        let server = MockServer::start().await;

        Mock::given(method("PUT"))
            .and(path("/services/data/v66.0/jobs/ingest/750xx/batches"))
            .and(header("content-type", "text/csv"))
            .and(header("authorization", "Bearer tok"))
            .respond_with(ResponseTemplate::new(201))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let csv = bytes::Bytes::from_static(b"Name\nAcme\nGlobex\n");
        sf.bulk().ingest().upload("750xx", csv).await.unwrap();
    }

    #[tokio::test]
    async fn ingest_upload_is_not_replayed_after_a_transient_5xx() {
        // SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_asynch.meta/api_asynch/upload_job_data.htm
        // "Uploads data for a job using CSV data you provide." Nothing
        // documents a repeat PUT as replacing the data it already
        // received, so a replay would load the rows a second time —
        // even though PUT is otherwise a replay-safe method.
        let server = MockServer::start().await;

        Mock::given(method("PUT"))
            .and(path("/services/data/v66.0/jobs/ingest/750xx/batches"))
            .respond_with(ResponseTemplate::new(503))
            .expect(1)
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let csv = bytes::Bytes::from_static(b"Name\nAcme\n");
        let err = sf.bulk().ingest().upload("750xx", csv).await.unwrap_err();
        assert!(matches!(err, crate::CirrusError::Api { status: 503, .. }));
    }

    #[tokio::test]
    async fn ingest_close_patches_state_to_upload_complete() {
        let server = MockServer::start().await;

        Mock::given(method("PATCH"))
            .and(path("/services/data/v66.0/jobs/ingest/750xx"))
            .and(body_json(json!({"state": "UploadComplete"})))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(state_change_response(
                    "750xx",
                    "update",
                    "UploadComplete",
                )),
            )
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let job = sf.bulk().ingest().close("750xx").await.unwrap();
        assert_eq!(job.id, "750xx");
        assert_eq!(job.operation, BulkOperation::Update);
        assert_eq!(job.state, BulkJobState::UploadComplete);
        assert!(job.external_id_field_name.is_none());
    }

    #[tokio::test]
    async fn ingest_abort_patches_state_to_aborted() {
        let server = MockServer::start().await;

        Mock::given(method("PATCH"))
            .and(path("/services/data/v66.0/jobs/ingest/750xx"))
            .and(body_json(json!({"state": "Aborted"})))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(state_change_response("750xx", "insert", "Aborted")),
            )
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let job = sf.bulk().ingest().abort("750xx").await.unwrap();
        assert_eq!(job.state, BulkJobState::Aborted);
    }

    #[tokio::test]
    async fn ingest_get_returns_completed_job_with_metrics() {
        let server = MockServer::start().await;

        let mut completed = ingest_job_response("750xx", "JobComplete");
        completed["numberRecordsProcessed"] = json!(100);
        completed["numberRecordsFailed"] = json!(2);
        completed["totalProcessingTime"] = json!(2349);

        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/jobs/ingest/750xx"))
            .respond_with(ResponseTemplate::new(200).set_body_json(completed))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let job = sf.bulk().ingest().get("750xx").await.unwrap();
        assert_eq!(job.state, BulkJobState::JobComplete);
        assert_eq!(job.number_records_processed, Some(100));
        assert_eq!(job.number_records_failed, Some(2));
    }

    #[tokio::test]
    async fn ingest_delete_returns_204() {
        let server = MockServer::start().await;

        Mock::given(method("DELETE"))
            .and(path("/services/data/v66.0/jobs/ingest/750xx"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        sf.bulk().ingest().delete("750xx").await.unwrap();
    }

    #[tokio::test]
    async fn ingest_successful_results_returns_csv_bytes() {
        let server = MockServer::start().await;

        let csv = "sf__Id,sf__Created,Name\n001xx,true,Acme\n";
        Mock::given(method("GET"))
            .and(path(
                "/services/data/v66.0/jobs/ingest/750xx/successfulResults",
            ))
            .and(header("accept", "text/csv"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(csv)
                    .insert_header("content-type", "text/csv"),
            )
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let bytes = sf
            .bulk()
            .ingest()
            .successful_results("750xx")
            .await
            .unwrap();
        assert_eq!(&bytes[..], csv.as_bytes());
    }

    #[tokio::test]
    async fn ingest_failed_results_surfaces_csv_error_rows() {
        let server = MockServer::start().await;

        let csv = "sf__Id,sf__Error,Name\n,REQUIRED_FIELD_MISSING:Name,\n";
        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/jobs/ingest/750xx/failedResults"))
            .respond_with(ResponseTemplate::new(200).set_body_string(csv))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let bytes = sf.bulk().ingest().failed_results("750xx").await.unwrap();
        assert!(bytes.starts_with(b"sf__Id,sf__Error"));
    }

    #[tokio::test]
    async fn ingest_unprocessed_records_uses_the_all_lowercase_path() {
        // SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_asynch.meta/api_asynch/get_job_unprocessed_results.htm
        // "URI: /services/data/vXX.X/jobs/ingest/jobID/unprocessedrecords/"
        // — all lowercase, unlike the successfulResults and
        // failedResults siblings. This mock pins that spelling: a
        // "consistency" edit to unprocessedRecords 404s against an org.
        let server = MockServer::start().await;

        let csv = "Name\nInitech\n";
        Mock::given(method("GET"))
            .and(path(
                "/services/data/v66.0/jobs/ingest/750xx/unprocessedrecords",
            ))
            .and(header("accept", "text/csv"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(csv)
                    .insert_header("content-type", "text/csv"),
            )
            .expect(1)
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let bytes = sf
            .bulk()
            .ingest()
            .unprocessed_records("750xx")
            .await
            .unwrap();
        assert_eq!(&bytes[..], csv.as_bytes());
    }

    #[tokio::test]
    async fn ingest_results_path_404_surfaces_as_api_error() {
        // Wrong job id: Salesforce returns 400 with the standard error array.
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path(
                "/services/data/v66.0/jobs/ingest/missing/successfulResults",
            ))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!([{
                "message": "InvalidJob: Bulk API job missing not found",
                "errorCode": "INVALIDJOBSTATE"
            }])))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let err = sf
            .bulk()
            .ingest()
            .successful_results("missing")
            .await
            .unwrap_err();
        match err {
            crate::CirrusError::Api { status, errors, .. } => {
                assert_eq!(status, 400);
                assert_eq!(errors[0].error_code, "INVALIDJOBSTATE");
            }
            other => panic!("expected Api error, got {other:?}"),
        }
    }

    fn query_job_response(id: &str, state: &str) -> serde_json::Value {
        // Mirrors the documented query-job CREATE response — see
        // api_asynch query_create_job. Salesforce parses the SOQL,
        // surfaces `object`, and never echoes the original `query`
        // string. `jobType` is absent until the GET endpoint, so we
        // omit it here too — tests for GET shape live in response.rs.
        json!({
            "id": id,
            "operation": "query",
            "state": state,
            "object": "Account",
            "createdById": "005xx",
            "createdDate": "2024-01-01T00:00:00.000+0000",
            "systemModstamp": "2024-01-01T00:00:00.000+0000",
            "concurrencyMode": "Parallel",
            "contentType": "CSV",
            "apiVersion": 60.0,
            "lineEnding": "LF",
            "columnDelimiter": "COMMA"
        })
    }

    #[tokio::test]
    async fn query_create_posts_soql() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/services/data/v66.0/jobs/query"))
            .and(body_json(json!({
                "query": "SELECT Id, Name FROM Account",
                "operation": "query"
            })))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(query_job_response("750xx", "UploadComplete")),
            )
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let job = sf
            .bulk()
            .query()
            .create(&BulkQuerySpec {
                query: "SELECT Id, Name FROM Account".into(),
                operation: BulkOperation::Query,
                line_ending: None,
                column_delimiter: None,
            })
            .await
            .unwrap();
        assert_eq!(job.state, BulkJobState::UploadComplete);
    }

    #[tokio::test]
    async fn query_results_returns_csv_with_locator_header() {
        let server = MockServer::start().await;

        let csv = "Id,Name\n001xx,Acme\n";
        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/jobs/query/750xx/results"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(csv)
                    .insert_header("Sforce-Locator", "MTAwMA")
                    .insert_header("Sforce-NumberOfRecords", "1"),
            )
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let result = sf
            .bulk()
            .query()
            .results("750xx", None, None)
            .await
            .unwrap();
        assert_eq!(&result.csv[..], csv.as_bytes());
        assert_eq!(result.locator.as_deref(), Some("MTAwMA"));
        assert_eq!(result.number_of_records, Some(1));
    }

    #[tokio::test]
    async fn query_results_treats_null_locator_as_done() {
        // When the result set is fully drained Salesforce sends
        // Sforce-Locator: null (literal string, not absent header).
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/jobs/query/750xx/results"))
            .and(query_param("locator", "MTAwMA"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("")
                    .insert_header("Sforce-Locator", "null")
                    .insert_header("Sforce-NumberOfRecords", "0"),
            )
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let result = sf
            .bulk()
            .query()
            .results("750xx", Some("MTAwMA"), None)
            .await
            .unwrap();
        assert!(result.locator.is_none());
        assert_eq!(result.number_of_records, Some(0));
    }

    #[tokio::test]
    async fn query_results_serializes_max_records() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/jobs/query/750xx/results"))
            .and(query_param("maxRecords", "10000"))
            .respond_with(ResponseTemplate::new(200).set_body_string("Id\n"))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        sf.bulk()
            .query()
            .results("750xx", None, Some(10000))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn query_abort_patches_state() {
        let server = MockServer::start().await;

        Mock::given(method("PATCH"))
            .and(path("/services/data/v66.0/jobs/query/750xx"))
            .and(body_json(json!({"state": "Aborted"})))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(state_change_response("750xx", "query", "Aborted")),
            )
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let job = sf.bulk().query().abort("750xx").await.unwrap();
        assert_eq!(job.operation, BulkOperation::Query);
        assert_eq!(job.state, BulkJobState::Aborted);
    }
}
