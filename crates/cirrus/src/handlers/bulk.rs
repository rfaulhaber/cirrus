//! Bulk API 2.0 — async, CSV-driven ingest and query operations.
//!
//! Two flavors live under `/services/data/{version}/jobs/`:
//!
//! - **Ingest** (`/jobs/ingest`) — create / update / upsert / delete /
//!   hardDelete records from CSV uploads. A job holds at most 150 MB
//!   of data after base64 encoding, roughly 100 MB of raw CSV, and
//!   that ceiling is per job rather than per upload: larger data sets
//!   need additional jobs. The caller drives the job through `Open` →
//!   `UploadComplete` → `InProgress` → `JobComplete` / `Failed` /
//!   `Aborted`, or collapses create, upload and close into one
//!   multipart request for a small data set. Reach via
//!   [`BulkHandler::ingest`].
//! - **Query** (`/jobs/query`) — async SOQL execution that streams
//!   results as CSV with cursor-based pagination. Reach via
//!   [`BulkHandler::query`].
//!
//! # CSV transport
//!
//! Bulk 2.0 is the only Salesforce REST surface that uses `text/csv`
//! bodies (not JSON). Upload and result-fetch methods take and return
//! [`bytes::Bytes`] rather than typed bodies. `Bytes` avoids copies but
//! does not stream: an upload is sent from one in-memory buffer, and
//! every result page or download is read completely into memory before
//! it is returned. Bound query pages with the `max_records` argument to
//! [`BulkQueryHandler::results`]. For true streaming, build the request
//! with [`Cirrus::request_builder`] and read the body with reqwest's
//! chunked API, which bypasses retry, 401 refresh, and limit-info
//! capture. CSV parsing/encoding is the caller's responsibility — pick
//! whichever crate fits the use case (`csv`, `polars`, etc.).
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
use crate::error::{CirrusError, CirrusResult};
use crate::response::{
    BulkIngestJob, BulkJobList, BulkJobStateChange, BulkJobType, BulkOperation, BulkQueryJob,
    BulkQueryResults, BulkResultPages,
};
use serde::Serialize;

const CSV_CONTENT_TYPE: &str = "text/csv";
const CSV_ACCEPT: &str = "text/csv";

/// The most job data a single multipart create-job request may carry,
/// in characters. Salesforce documents the one-request path of
/// [`BulkIngestHandler::create_with_data`] for "small amounts of job
/// data (100,000 characters or less)"; larger data goes through
/// [`BulkIngestHandler::create`] and [`BulkIngestHandler::upload`].
///
/// [Create a Job](https://developer.salesforce.com/docs/platform/api-asynch/guide/create-job.html)
pub const MAX_MULTIPART_JOB_DATA_CHARS: usize = 100_000;
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
    /// let spec = BulkIngestSpec::new("Account", BulkOperation::Insert);
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
///
/// The sub-handlers borrow the [`Cirrus`] client, not this value, so
/// they can be bound straight off a temporary and kept:
///
/// ```no_run
/// # use cirrus::{Cirrus, auth::StaticTokenAuth};
/// # use std::sync::Arc;
/// # async fn example() -> Result<(), cirrus::CirrusError> {
/// # let auth = Arc::new(StaticTokenAuth::new("tok", "https://x.my.salesforce.com"));
/// # let sf = Cirrus::builder().auth(auth).build()?;
/// let ingest = sf.bulk().ingest();
/// let first = ingest.get("7503gEXAMPLEaaaAAA").await?;
/// let second = ingest.get("7503gEXAMPLEbbbAAA").await?;
/// # let _ = (first, second);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Copy)]
pub struct BulkHandler<'a> {
    client: &'a Cirrus,
}

// The sub-handlers carry the client borrow (`'a`), not a borrow of this
// parent, so `sf.bulk().ingest()` outlives the temporary `BulkHandler`.
impl<'a> BulkHandler<'a> {
    /// Returns a sub-handler for ingest (CRUD-style) bulk jobs under
    /// `/jobs/ingest`.
    pub fn ingest(&self) -> BulkIngestHandler<'a> {
        BulkIngestHandler {
            client: self.client,
        }
    }

    /// Returns a sub-handler for SOQL query bulk jobs under `/jobs/query`.
    pub fn query(&self) -> BulkQueryHandler<'a> {
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
/// For job data of at most [`MAX_MULTIPART_JOB_DATA_CHARS`] characters,
/// [`create_with_data`](Self::create_with_data) does steps 1 to 3 in
/// one multipart request and returns the job already in
/// `UploadComplete`.
///
/// [`abort`](Self::abort) cancels a job mid-flight if needed.
#[derive(Debug, Clone, Copy)]
pub struct BulkIngestHandler<'a> {
    client: &'a Cirrus,
}

impl BulkIngestHandler<'_> {
    /// Creates a new ingest job. Salesforce returns the job in `Open`
    /// state with a `content_url` indicating where to upload data.
    ///
    /// Rejects `spec` with [`CirrusError::InvalidInput`] before issuing
    /// a request if `operation` is not one the ingest endpoint takes
    /// ([`BulkOperation::is_ingest`]), or if `object` is set for a
    /// [`ConsentImport`](BulkOperation::ConsentImport) operation or
    /// unset for any other — see [`BulkIngestSpec::object`].
    ///
    /// Calls `POST /services/data/{api_version}/jobs/ingest`.
    ///
    /// [Create a Job](https://developer.salesforce.com/docs/atlas.en-us.api_asynch.meta/api_asynch/create_job.htm)
    pub async fn create(&self, spec: &BulkIngestSpec) -> CirrusResult<BulkIngestJob> {
        check_ingest_spec(spec)?;
        self.client.post("jobs/ingest", spec).await
    }

    /// Creates an ingest job and uploads its CSV in the same request.
    ///
    /// Sends the multipart form the [Create a Job] page documents: a
    /// `job` part carrying `spec` as JSON and a `content` part carrying
    /// `csv` as `text/csv`. Salesforce completes the upload itself, so
    /// the job comes back in `UploadComplete`: do not pass it to
    /// [`close`](Self::close), poll [`get`](Self::get) until
    /// [`BulkJobState::is_terminal`](crate::BulkJobState::is_terminal)
    /// instead. The [multipart walkthrough] puts it as "You don't need
    /// to manually set the job state to UploadComplete for a multipart
    /// job".
    ///
    /// The single-request path is documented for job data of
    /// [`MAX_MULTIPART_JOB_DATA_CHARS`] characters or less. A larger
    /// `csv` is refused with [`CirrusError::InvalidInput`] before any
    /// request and belongs in [`create`](Self::create) plus
    /// [`upload`](Self::upload). `spec` passes the same checks as
    /// `create`.
    ///
    /// A lost response or a 5xx is never replayed: a second attempt
    /// would create a second job holding the same rows. After an
    /// ambiguous failure, [`list`](Self::list) the org's jobs before
    /// resubmitting the data; a job this request did create is already
    /// processing.
    ///
    /// Calls `POST /services/data/{api_version}/jobs/ingest` with
    /// `Content-Type: multipart/form-data`.
    ///
    /// [Create a Job]: https://developer.salesforce.com/docs/platform/api-asynch/guide/create-job.html
    /// [multipart walkthrough]: https://developer.salesforce.com/docs/platform/api-asynch/guide/walkthrough-upload-multipart-data.html
    pub async fn create_with_data(
        &self,
        spec: &BulkIngestSpec,
        csv: bytes::Bytes,
    ) -> CirrusResult<BulkIngestJob> {
        check_ingest_spec(spec)?;
        // The documented cap is in characters. Job data is UTF-8 text;
        // bytes stand in only for data that isn't, where the byte count
        // bounds the character count from above.
        let chars = std::str::from_utf8(&csv).map_or(csv.len(), |text| text.chars().count());
        if chars > MAX_MULTIPART_JOB_DATA_CHARS {
            return Err(CirrusError::InvalidInput {
                field: "csv",
                message: format!(
                    "{chars} characters of job data; a multipart create-job request carries \
                     at most {MAX_MULTIPART_JOB_DATA_CHARS}, so larger data goes through \
                     create and upload"
                ),
            });
        }
        let job = serde_json::to_vec(spec).map_err(CirrusError::Serialization)?;
        self.client
            .send_multipart(
                reqwest::Method::POST,
                "jobs/ingest",
                "job",
                job,
                "content",
                "content",
                CSV_CONTENT_TYPE,
                csv,
            )
            .await
    }

    /// Uploads CSV record data for a job. The job must be in `Open` state.
    /// Salesforce returns 201 with no body on success.
    ///
    /// A job accepts at most 150 MB of data after base64 encoding, and
    /// that conversion inflates the data by roughly 50%, so keep a job's
    /// total CSV under 100 MB. The ceiling is per job, not per upload:
    /// data beyond it belongs in a separate ingest job. See
    /// [Step 3: Bulk Insert] and the [Bulk API limits] cheatsheet.
    ///
    /// An upload that size needs a read timeout to match, because the
    /// deadline covers pushing the body as well as waiting for the
    /// answer — see [`CirrusBuilder::read_timeout`](crate::CirrusBuilder::read_timeout).
    ///
    /// A lost response is never retried automatically. Salesforce
    /// documents this `PUT` as uploading job data, not as replacing
    /// data the job already holds, so a replay risks loading the same
    /// rows twice. Job info cannot settle the question either: nothing
    /// in an `Open` job's state or counters changes when data arrives.
    /// After an ambiguous failure, [`abort`](Self::abort) the job and
    /// create a new one with the same data — an `Open` job has
    /// processed nothing, so aborting it commits nothing.
    ///
    /// Calls `PUT /services/data/{api_version}/jobs/ingest/{job_id}/batches`
    /// with `Content-Type: text/csv`.
    ///
    /// [Step 3: Bulk Insert]: https://developer.salesforce.com/docs/atlas.en-us.api_asynch.meta/api_asynch/walkthrough_upload_data.htm
    /// [Bulk API limits]: https://developer.salesforce.com/docs/atlas.en-us.salesforce_app_limits_cheatsheet.meta/salesforce_app_limits_cheatsheet/salesforce_app_limits_platform_bulkapi.htm
    pub async fn upload(&self, job_id: &str, csv: bytes::Bytes) -> CirrusResult<()> {
        let path = self
            .client
            .versioned_url(&["jobs", "ingest", job_id, "batches"])?;
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
        let path = self.client.versioned_url(&["jobs", "ingest", job_id])?;
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
    ///
    /// A DELETE is replayed after a transient failure (a 5xx from an
    /// intermediary, a lost response), so when the first attempt had
    /// already removed the job the replay returns a 404
    /// [`crate::CirrusError::Api`] for a delete that succeeded.
    pub async fn delete(&self, job_id: &str) -> CirrusResult<()> {
        let path = self.client.versioned_url(&["jobs", "ingest", job_id])?;
        self.client
            .send_at::<(), (), ()>(reqwest::Method::DELETE, &path, None, None)
            .await
    }

    /// Lists the org's ingest jobs, one page of up to 1,000 at a time.
    ///
    /// The listing covers every Bulk API ingest job, not only this
    /// client's: a loader that crashed between [`create`](Self::create)
    /// and [`close`](Self::close) can find its `Open` jobs here and
    /// [`abort`](Self::abort) or [`delete`](Self::delete) them instead
    /// of leaving them to Salesforce's seven-day cleanup. Narrow it with
    /// [`BulkJobListOptions::job_type`], and page with
    /// [`BulkJobList::next_locator`] until
    /// [`BulkJobList::done`].
    ///
    /// Calls `GET /services/data/{api_version}/jobs/ingest` with the
    /// optional `jobType`, `isPkChunkingEnabled` and `queryLocator`
    /// parameters.
    ///
    /// [Get Information About All Ingest Jobs](https://developer.salesforce.com/docs/platform/api-asynch/guide/get-all-jobs.html)
    pub async fn list(&self, options: &BulkJobListOptions) -> CirrusResult<BulkJobList> {
        list_jobs(self.client, "jobs/ingest", options).await
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
        let path = self.client.versioned_url(&["jobs", "ingest", job_id])?;
        let body = StatePatch { state: new_state };
        self.client
            .send_at::<_, (), _>(reqwest::Method::PATCH, &path, None, Some(&body))
            .await
    }

    async fn fetch_csv_results(&self, job_id: &str, kind: &str) -> CirrusResult<bytes::Bytes> {
        let path = self
            .client
            .versioned_url(&["jobs", "ingest", job_id, kind])?;
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
///    calls until it returns `None`; or, on API 58.0 and later, take
///    the cursors from [`result_pages`](Self::result_pages) and fetch
///    several pages at once. Fetch them through a client on the same
///    API version that created the job; Salesforce answers 409
///    otherwise.
/// 4. [`delete`](Self::delete) when done.
///
/// [`list`](Self::list) finds the org's existing query jobs.
#[derive(Debug, Clone, Copy)]
pub struct BulkQueryHandler<'a> {
    client: &'a Cirrus,
}

impl BulkQueryHandler<'_> {
    /// Creates a new query job.
    ///
    /// Rejects `spec` with [`CirrusError::InvalidInput`] before issuing
    /// a request if `operation` is not [`Query`](BulkOperation::Query)
    /// or [`QueryAll`](BulkOperation::QueryAll)
    /// ([`BulkOperation::is_query`]).
    ///
    /// Calls `POST /services/data/{api_version}/jobs/query`.
    pub async fn create(&self, spec: &BulkQuerySpec) -> CirrusResult<BulkQueryJob> {
        if !spec.operation.is_query() {
            return Err(CirrusError::InvalidInput {
                field: "operation",
                message: "a query job runs `query` or `queryAll`; ingest operations go \
                          through BulkIngestHandler"
                    .into(),
            });
        }
        self.client.post("jobs/query", spec).await
    }

    /// Fetches the current state and metadata for a query job.
    ///
    /// Calls `GET /services/data/{api_version}/jobs/query/{job_id}`.
    pub async fn get(&self, job_id: &str) -> CirrusResult<BulkQueryJob> {
        let path = self.client.versioned_url(&["jobs", "query", job_id])?;
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
        let path = self.client.versioned_url(&["jobs", "query", job_id])?;
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
    /// The request goes out at this client's API version, which must be
    /// the version the job was created with — Salesforce returns a 409
    /// error for any other ([`BulkQueryJob::api_version`] records the
    /// job's). See [Get Results for a Query Job].
    ///
    /// Calls
    /// `GET /services/data/{api_version}/jobs/query/{job_id}/results`
    /// with optional `?locator=&maxRecords=` query parameters.
    ///
    /// # Errors
    ///
    /// Salesforce marks the last page with the literal `Sforce-Locator:
    /// null`, and that literal is the only thing read as the end of the
    /// results. A 2xx page with no `Sforce-Locator` header, or one whose
    /// value is empty or not text, is [`CirrusError::InvalidResponse`]:
    /// it is the shape an intermediary produces when it strips or
    /// rewrites headers, and treating it as the last page would end a
    /// drain loop early with the export reported as complete.
    ///
    /// [Get Results for a Query Job]: https://developer.salesforce.com/docs/atlas.en-us.api_asynch.meta/api_asynch/query_get_job_results.htm
    pub async fn results(
        &self,
        job_id: &str,
        locator: Option<&str>,
        max_records: Option<u32>,
    ) -> CirrusResult<BulkQueryResults> {
        let path = self
            .client
            .versioned_url(&["jobs", "query", job_id, "results"])?;
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
        let locator = next_locator(&headers, csv.len())?;
        Ok(BulkQueryResults {
            csv,
            locator,
            number_of_records: header_string(&headers, SFORCE_NUM_RECORDS)
                .and_then(|s| s.parse().ok()),
        })
    }

    /// Deletes a query job. Only valid when the job is in `JobComplete`,
    /// `Aborted`, or `Failed` state.
    ///
    /// Calls `DELETE /services/data/{api_version}/jobs/query/{job_id}`.
    ///
    /// A DELETE is replayed after a transient failure (a 5xx from an
    /// intermediary, a lost response), so when the first attempt had
    /// already removed the job the replay returns a 404
    /// [`crate::CirrusError::Api`] for a delete that succeeded.
    pub async fn delete(&self, job_id: &str) -> CirrusResult<()> {
        let path = self.client.versioned_url(&["jobs", "query", job_id])?;
        self.client
            .send_at::<(), (), ()>(reqwest::Method::DELETE, &path, None, None)
            .await
    }

    /// Lists the org's query jobs, one page of up to 1,000 at a time.
    ///
    /// The listing covers every Bulk API job, Bulk API 1.0 included, so
    /// narrow it with [`BulkJobListOptions::job_type`] when only 2.0
    /// query jobs matter. Page with [`BulkJobList::next_locator`] until
    /// [`BulkJobList::done`].
    ///
    /// Calls `GET /services/data/{api_version}/jobs/query` with the
    /// optional `jobType`, `isPkChunkingEnabled` and `queryLocator`
    /// parameters. Available in API version 47.0 and later.
    ///
    /// [Get Information About All Query Jobs](https://developer.salesforce.com/docs/platform/api-asynch/guide/query-get-all-jobs.html)
    pub async fn list(&self, options: &BulkJobListOptions) -> CirrusResult<BulkJobList> {
        list_jobs(self.client, "jobs/query", options).await
    }

    /// Returns up to five result links for a `JobComplete` query job,
    /// each a cursor that [`results`](Self::results) can fetch, so the
    /// pages can be downloaded concurrently instead of one locator at a
    /// time.
    ///
    /// `locator` is the cursor from a previous
    /// [`BulkResultPages::next_locator`]; pass `None` for the first set
    /// and keep going until [`BulkResultPages::done`]. Like
    /// [`results`](Self::results), the request has to go out at the API
    /// version the job was created with, or Salesforce answers 409.
    ///
    /// Calls `GET /services/data/{api_version}/jobs/query/{job_id}/resultPages`
    /// with an optional `locator` parameter. Available in API version
    /// 58.0 and later.
    ///
    /// [Get Parallel Results for a Query Job](https://developer.salesforce.com/docs/platform/api-asynch/guide/query-get-parallel-job-results.html)
    pub async fn result_pages(
        &self,
        job_id: &str,
        locator: Option<&str>,
    ) -> CirrusResult<BulkResultPages> {
        let path = self
            .client
            .versioned_url(&["jobs", "query", job_id, "resultPages"])?;
        let query: Vec<(&str, &str)> = locator.map(|l| vec![("locator", l)]).unwrap_or_default();
        let pages: BulkResultPages = self.client.get_with_query(&path, &query).await?;
        if pages
            .result_pages
            .iter()
            .any(|page| page.locator().is_none())
        {
            return Err(CirrusError::InvalidResponse(
                "a resultPages entry carries no `locator` in its resultUrl, so its page \
                 cannot be fetched"
                    .into(),
            ));
        }
        if !pages.done && pages.next_locator().is_none() {
            return Err(CirrusError::InvalidResponse(
                "resultPages reports more sets of links (done is false) but carries no \
                 nextRecordsUrl with a `locator` to fetch them"
                    .into(),
            ));
        }
        Ok(pages)
    }
}

/// Request body for [`BulkIngestHandler::create`].
///
/// Build one with [`new`](Self::new) (or
/// [`consent_import`](Self::consent_import)) and the setters; the
/// struct is `#[non_exhaustive]` so a field Salesforce adds to the
/// create-job request later stays an additive change. The fields are
/// public for reading and for in-place edits.
///
/// `content_type` is fixed to `"CSV"` server-side (the only supported
/// value) and is not exposed here. Salesforce defaults `column_delimiter`
/// to `Comma` and `line_ending` to `LF` when omitted.
///
/// ```
/// use cirrus::{BulkColumnDelimiter, BulkIngestSpec, BulkOperation};
///
/// let spec = BulkIngestSpec::new("Account", BulkOperation::Upsert)
///     .external_id_field_name("External_Id__c")
///     .column_delimiter(BulkColumnDelimiter::Tab);
/// assert_eq!(spec.object.as_deref(), Some("Account"));
/// ```
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct BulkIngestSpec {
    /// API name of the object the data belongs to — for a marketing
    /// object, its API name. Required for every operation except
    /// [`ConsentImport`](BulkOperation::ConsentImport), and must be
    /// `None` there — consent ingest isn't backed by an object type,
    /// and Salesforce rejects a create-job request that names one.
    /// [`BulkIngestHandler::create`](crate::handlers::bulk::BulkIngestHandler::create)
    /// checks both directions before issuing a request.
    ///
    /// [Create a Job](https://developer.salesforce.com/docs/atlas.en-us.api_asynch.meta/api_asynch/create_job.htm)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object: Option<String>,
    /// Processing operation for the job. The ingest endpoint takes
    /// [`Insert`](BulkOperation::Insert),
    /// [`Delete`](BulkOperation::Delete),
    /// [`HardDelete`](BulkOperation::HardDelete),
    /// [`Update`](BulkOperation::Update),
    /// [`Upsert`](BulkOperation::Upsert),
    /// [`Refresh`](BulkOperation::Refresh) and
    /// [`ConsentImport`](BulkOperation::ConsentImport); which of them
    /// applies depends on the target. Standard objects support
    /// `insert`, `delete`, `hardDelete`, `update` and `upsert`;
    /// marketing objects support `insert`, `upsert` and `refresh`;
    /// consent ingest uses `consentImport`.
    pub operation: BulkOperation,
    /// External ID field in the object being updated. Required for an
    /// upsert, whose CSV job data must carry values for it too. Not
    /// supported for a marketing-object upsert — that matches on the
    /// record's primary key — nor for
    /// [`ConsentImport`](BulkOperation::ConsentImport).
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
    /// ID of an assignment rule to run for a Case or a Lead; the rule
    /// may be active or inactive. Available in API version 49.0 and
    /// later, and not supported for
    /// [`Refresh`](BulkOperation::Refresh) or
    /// [`ConsentImport`](BulkOperation::ConsentImport).
    #[serde(rename = "assignmentRuleId", skip_serializing_if = "Option::is_none")]
    pub assignment_rule_id: Option<String>,
}

impl BulkIngestSpec {
    /// A job running `operation` against `object`, with every optional
    /// field unset so Salesforce applies its defaults. For
    /// [`ConsentImport`](BulkOperation::ConsentImport), which takes no
    /// object, use [`consent_import`](Self::consent_import).
    pub fn new(object: impl Into<String>, operation: BulkOperation) -> Self {
        Self {
            object: Some(object.into()),
            operation,
            external_id_field_name: None,
            line_ending: None,
            column_delimiter: None,
            assignment_rule_id: None,
        }
    }

    /// A consent ingest job. The create-job request carries no `object`,
    /// as the [Create a Job] page requires for this operation.
    ///
    /// [Create a Job]: https://developer.salesforce.com/docs/platform/api-asynch/guide/create-job.html
    pub fn consent_import() -> Self {
        Self {
            object: None,
            operation: BulkOperation::ConsentImport,
            external_id_field_name: None,
            line_ending: None,
            column_delimiter: None,
            assignment_rule_id: None,
        }
    }

    /// Sets the external ID field an upsert matches on — see
    /// [`external_id_field_name`](Self::external_id_field_name).
    pub fn external_id_field_name(mut self, field: impl Into<String>) -> Self {
        self.external_id_field_name = Some(field.into());
        self
    }

    /// Sets the CSV line ending — see [`line_ending`](Self::line_ending).
    pub fn line_ending(mut self, line_ending: crate::response::BulkLineEnding) -> Self {
        self.line_ending = Some(line_ending);
        self
    }

    /// Sets the CSV column delimiter — see
    /// [`column_delimiter`](Self::column_delimiter).
    pub fn column_delimiter(mut self, delimiter: crate::response::BulkColumnDelimiter) -> Self {
        self.column_delimiter = Some(delimiter);
        self
    }

    /// Sets the Case or Lead assignment rule to run — see
    /// [`assignment_rule_id`](Self::assignment_rule_id).
    pub fn assignment_rule_id(mut self, rule_id: impl Into<String>) -> Self {
        self.assignment_rule_id = Some(rule_id.into());
        self
    }
}

/// Request body for [`BulkQueryHandler::create`].
///
/// Salesforce retries a query job's processing automatically; a job
/// that reports more than 15 retries needs narrower filter criteria, so
/// partition the SOQL with `WHERE` clauses and run several jobs.
/// `ORDER BY` and `LIMIT` disable PK chunking and make timeouts more
/// likely, so drop them before troubleshooting further. Retrieving
/// results times out after 20 minutes. See
/// [Understanding Bulk API 2.0 Query] and the [Bulk API limits]
/// cheatsheet.
///
/// Build one with [`new`](Self::new) and the setters; the struct is
/// `#[non_exhaustive]` so a field Salesforce adds to the create-job
/// request later stays an additive change. The fields are public for
/// reading and for in-place edits.
///
/// [Understanding Bulk API 2.0 Query]: https://developer.salesforce.com/docs/atlas.en-us.api_asynch.meta/api_asynch/queries.htm
/// [Bulk API limits]: https://developer.salesforce.com/docs/atlas.en-us.salesforce_app_limits_cheatsheet.meta/salesforce_app_limits_cheatsheet/salesforce_app_limits_platform_bulkapi.htm
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
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

impl BulkQuerySpec {
    /// A job running `query` under `operation`
    /// ([`Query`](BulkOperation::Query) or
    /// [`QueryAll`](BulkOperation::QueryAll)), with the CSV formatting
    /// fields unset so Salesforce applies its defaults.
    pub fn new(query: impl Into<String>, operation: BulkOperation) -> Self {
        Self {
            query: query.into(),
            operation,
            line_ending: None,
            column_delimiter: None,
        }
    }

    /// Sets the CSV line ending — see [`line_ending`](Self::line_ending).
    pub fn line_ending(mut self, line_ending: crate::response::BulkLineEnding) -> Self {
        self.line_ending = Some(line_ending);
        self
    }

    /// Sets the CSV column delimiter — see
    /// [`column_delimiter`](Self::column_delimiter).
    pub fn column_delimiter(mut self, delimiter: crate::response::BulkColumnDelimiter) -> Self {
        self.column_delimiter = Some(delimiter);
        self
    }
}

/// The pre-flight checks a create-job request has to pass. Each failure
/// is a 400 from Salesforce otherwise, and a job is never created, so
/// refusing locally costs nothing but saves the round trip.
fn check_ingest_spec(spec: &BulkIngestSpec) -> CirrusResult<()> {
    if !spec.operation.is_ingest() {
        return Err(CirrusError::InvalidInput {
            field: "operation",
            message: "an ingest job runs insert, update, upsert, delete, hardDelete, refresh \
                      or consentImport; query operations go through BulkQueryHandler"
                .into(),
        });
    }
    match (spec.operation, spec.object.is_some()) {
        (BulkOperation::ConsentImport, true) => Err(CirrusError::InvalidInput {
            field: "object",
            message: "must be omitted for consentImport: consent ingest isn't backed \
                      by an object type, and Salesforce rejects a create-job request \
                      that names one"
                .into(),
        }),
        (op, false) if op != BulkOperation::ConsentImport => Err(CirrusError::InvalidInput {
            field: "object",
            message: "required for every ingest operation except consentImport".into(),
        }),
        _ => Ok(()),
    }
}

/// Filters for [`BulkIngestHandler::list`] and [`BulkQueryHandler::list`].
///
/// The struct is `#[non_exhaustive]` so a filter Salesforce adds later
/// stays an additive change; build it with [`new`](Self::new) and the
/// setters. An empty set of options lists every job.
///
/// ```
/// use cirrus::{BulkJobListOptions, BulkJobType};
///
/// let only_v2_ingest = BulkJobListOptions::new().job_type(BulkJobType::V2Ingest);
/// assert_eq!(only_v2_ingest.job_type, Some(BulkJobType::V2Ingest));
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct BulkJobListOptions {
    /// Only jobs of this kind (`jobType`). The ingest listing documents
    /// `BigObjectIngest`, `Classic` and `V2Ingest`; the query listing
    /// `Classic`, `V2Query` and `V2Ingest`.
    /// [`Unknown`](BulkJobType::Unknown) is refused before any request.
    pub job_type: Option<BulkJobType>,
    /// Only jobs with PK chunking enabled (`isPkChunkingEnabled`), which
    /// applies to Bulk API 1.0 jobs.
    pub pk_chunking_enabled: Option<bool>,
    /// Continue a listing from this page (`queryLocator`). Use the value
    /// of [`BulkJobList::next_locator`] from the previous page; Salesforce
    /// documents it as opaque.
    pub query_locator: Option<String>,
}

impl BulkJobListOptions {
    /// No filters: every job, from the first page.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the job kind filter — see [`job_type`](Self::job_type).
    pub fn job_type(mut self, job_type: BulkJobType) -> Self {
        self.job_type = Some(job_type);
        self
    }

    /// Sets the PK chunking filter — see
    /// [`pk_chunking_enabled`](Self::pk_chunking_enabled).
    pub fn pk_chunking_enabled(mut self, enabled: bool) -> Self {
        self.pk_chunking_enabled = Some(enabled);
        self
    }

    /// Continues the listing from a page — see
    /// [`query_locator`](Self::query_locator).
    pub fn query_locator(mut self, locator: impl Into<String>) -> Self {
        self.query_locator = Some(locator.into());
        self
    }
}

/// The two job listings share one request shape and one envelope; only
/// the path differs. A page that says more follow but offers no locator
/// to fetch them is an error rather than a quiet end, since the caller's
/// loop would otherwise finish believing it saw every job.
async fn list_jobs(
    client: &Cirrus,
    path: &str,
    options: &BulkJobListOptions,
) -> CirrusResult<BulkJobList> {
    if options.job_type == Some(BulkJobType::Unknown) {
        return Err(CirrusError::InvalidInput {
            field: "job_type",
            message: "`Unknown` stands for a job type this SDK doesn't name and is not a \
                      filter value; the documented filters are BigObjectIngest, Classic, \
                      V2Ingest and V2Query"
                .into(),
        });
    }
    let mut query: Vec<(&str, String)> = Vec::with_capacity(3);
    if let Some(job_type) = options.job_type {
        query.push(("jobType", job_type.as_str().to_owned()));
    }
    if let Some(enabled) = options.pk_chunking_enabled {
        query.push(("isPkChunkingEnabled", enabled.to_string()));
    }
    if let Some(locator) = &options.query_locator {
        query.push(("queryLocator", locator.clone()));
    }
    let page: BulkJobList = client.get_with_query(path, &query).await?;
    if !page.done && page.next_locator().is_none() {
        return Err(CirrusError::InvalidResponse(
            "the job listing reports more pages (done is false) but carries no \
             nextRecordsUrl with a `queryLocator` to fetch them"
                .into(),
        ));
    }
    Ok(page)
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

/// Reads the cursor for the next results page off a 2xx response.
///
/// Only the documented end marker, the literal string `null`, becomes
/// `None`. An absent, empty or unreadable header is refused: it would otherwise
/// be indistinguishable from the last page, and a drain loop would stop
/// with the export incomplete. The message names the response's content
/// type and size rather than quoting the body, which is the caller's
/// exported data when the header was merely stripped in transit.
fn next_locator(
    headers: &reqwest::header::HeaderMap,
    body_len: usize,
) -> CirrusResult<Option<String>> {
    let describe = || {
        let content_type = header_string(headers, reqwest::header::CONTENT_TYPE.as_str())
            .unwrap_or_else(|| "none".to_owned());
        format!("(content type {content_type}, {body_len} bytes)")
    };
    match headers.get(SFORCE_LOCATOR) {
        None => Err(CirrusError::InvalidResponse(format!(
            "Bulk query results page carries no {SFORCE_LOCATOR} header {}; Salesforce \
             marks the last page with the literal value `null`",
            describe()
        ))),
        Some(value) => match value.to_str() {
            Ok("null") => Ok(None),
            Ok("") => Err(CirrusError::InvalidResponse(format!(
                "Bulk query results page carries an empty {SFORCE_LOCATOR} header {}; Salesforce \
                 marks the last page with the literal value `null`",
                describe()
            ))),
            Ok(locator) => Ok(Some(locator.to_owned())),
            Err(_) => Err(CirrusError::InvalidResponse(format!(
                "Bulk query results page carries a {SFORCE_LOCATOR} header that is not text {}",
                describe()
            ))),
        },
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::auth::StaticTokenAuth;
    use crate::response::{BulkColumnDelimiter, BulkJobState, BulkJobType, BulkLineEnding};
    use serde_json::json;
    use std::sync::Arc;
    use wiremock::matchers::{
        body_bytes, body_json, header, method, path, query_param, query_param_is_missing,
    };
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

    fn ingest_create_response(id: &str) -> serde_json::Value {
        // SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_asynch.meta/api_asynch/walkthrough_upload_data.htm
        // Step 3's create-job "Example response body": the job is `Open`
        // with a `contentUrl`, and `jobType` is absent until GET.
        json!({
            "id": id,
            "operation": "insert",
            "object": "Account",
            "createdById": "0055fEXAMPLEtG4AAM",
            "createdDate": "2022-01-02T21:33:43.000+0000",
            "systemModstamp": "2022-01-02T21:33:43.000+0000",
            "state": "Open",
            "concurrencyMode": "Parallel",
            "contentType": "CSV",
            "apiVersion": 67.0,
            "contentUrl": format!("services/data/v67.0/jobs/ingest/{id}/batches"),
            "lineEnding": "LF",
            "columnDelimiter": "COMMA"
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
            .respond_with(ResponseTemplate::new(200).set_body_json(ingest_create_response("750xx")))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let job = sf
            .bulk()
            .ingest()
            .create(&BulkIngestSpec {
                object: Some("Account".into()),
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
        assert_eq!(
            job.content_url.as_deref(),
            Some("services/data/v67.0/jobs/ingest/750xx/batches")
        );
        assert!(job.job_type.is_none());
    }

    #[tokio::test]
    async fn ingest_create_omits_object_for_consent_import() {
        // SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_asynch.meta/api_asynch/create_job.htm
        // Request body, `object`: "Omit this property for the
        // consentImport operation. Consent ingest isn't backed by an
        // object type. Including object with consentImport returns an
        // error." Response body, `object`: "The object type for the
        // data being processed. Empty for jobs created with the
        // consentImport operation." Response body, `contentUrl`: "The
        // URL to use for Upload Job Data requests for this job. Only
        // valid if the job is in Open state."
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/services/data/v66.0/jobs/ingest"))
            .and(body_json(json!({ "operation": "consentImport" })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "750xx",
                "operation": "consentImport",
                "object": "",
                "createdById": "005xx",
                "createdDate": "2024-01-01T00:00:00.000+0000",
                "systemModstamp": "2024-01-01T00:00:00.000+0000",
                "state": "Open",
                "concurrencyMode": "Parallel",
                "contentType": "CSV",
                "apiVersion": 60.0,
                "contentUrl": "services/data/v66.0/jobs/ingest/750xx/batches",
                "lineEnding": "LF",
                "columnDelimiter": "COMMA"
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let job = sf
            .bulk()
            .ingest()
            .create(&BulkIngestSpec {
                object: None,
                operation: BulkOperation::ConsentImport,
                external_id_field_name: None,
                line_ending: None,
                column_delimiter: None,
                assignment_rule_id: None,
            })
            .await
            .unwrap();
        assert_eq!(job.operation, BulkOperation::ConsentImport);
        assert_eq!(job.object, "");
        assert_eq!(
            job.content_url.as_deref(),
            Some("services/data/v66.0/jobs/ingest/750xx/batches")
        );
    }

    #[tokio::test]
    async fn ingest_create_rejects_object_with_consent_import() {
        // SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_asynch.meta/api_asynch/create_job.htm
        // "Omit this property for the consentImport operation... Including
        // object with consentImport returns an error." Caught before the
        // request goes out rather than round-tripped to the server.
        let server = MockServer::start().await;

        let sf = fixture(server.uri());
        let err = sf
            .bulk()
            .ingest()
            .create(&BulkIngestSpec {
                object: Some("Account".into()),
                operation: BulkOperation::ConsentImport,
                external_id_field_name: None,
                line_ending: None,
                column_delimiter: None,
                assignment_rule_id: None,
            })
            .await
            .unwrap_err();
        match err {
            crate::CirrusError::InvalidInput { field, .. } => assert_eq!(field, "object"),
            other => panic!("expected InvalidInput, got {other:?}"),
        }
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn ingest_create_rejects_missing_object_outside_consent_import() {
        // SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_asynch.meta/api_asynch/create_job.htm
        // `object` is "Required" for every operation except consentImport.
        let server = MockServer::start().await;

        let sf = fixture(server.uri());
        let err = sf
            .bulk()
            .ingest()
            .create(&BulkIngestSpec {
                object: None,
                operation: BulkOperation::Insert,
                external_id_field_name: None,
                line_ending: None,
                column_delimiter: None,
                assignment_rule_id: None,
            })
            .await
            .unwrap_err();
        match err {
            crate::CirrusError::InvalidInput { field, .. } => assert_eq!(field, "object"),
            other => panic!("expected InvalidInput, got {other:?}"),
        }
        assert!(server.received_requests().await.unwrap().is_empty());
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
            .respond_with(ResponseTemplate::new(200).set_body_json(ingest_create_response("750xx")))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        sf.bulk()
            .ingest()
            .create(&BulkIngestSpec {
                object: Some("Account".into()),
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
            .and(body_bytes(b"Name\nAcme\nGlobex\n".to_vec()))
            .respond_with(ResponseTemplate::new(201))
            .expect(1)
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
    async fn query_get_parses_documented_job_info() {
        // SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_asynch.meta/api_asynch/query_get_one_job.htm
        // "Response Body" example, verbatim.
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/jobs/query/750R0000000zlh9IAA"))
            .and(header("authorization", "Bearer tok"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "750R0000000zlh9IAA",
                "operation": "query",
                "object": "Account",
                "createdById": "005R0000000GiwjIAC",
                "createdDate": "2018-12-10T17:50:19.000+0000",
                "systemModstamp": "2018-12-10T17:51:27.000+0000",
                "state": "JobComplete",
                "concurrencyMode": "Parallel",
                "contentType": "CSV",
                "apiVersion": 46.0,
                "jobType": "V2Query",
                "lineEnding": "LF",
                "columnDelimiter": "COMMA",
                "numberRecordsProcessed": 500,
                "retries": 0,
                "totalProcessingTime": 334,
                "isPkChunkingSupported": true
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let job = sf.bulk().query().get("750R0000000zlh9IAA").await.unwrap();
        assert_eq!(job.id, "750R0000000zlh9IAA");
        assert_eq!(job.state, BulkJobState::JobComplete);
        assert_eq!(job.job_type.as_deref(), Some("V2Query"));
        assert_eq!(job.number_records_processed, Some(500));
        assert_eq!(job.is_pk_chunking_supported, Some(true));
    }

    #[tokio::test]
    async fn query_delete_returns_unit_on_204() {
        // SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_asynch.meta/api_asynch/query_delete_job.htm
        // "If the method is successful, the status code is 204 (No
        // Content) and there is no response body."
        let server = MockServer::start().await;

        Mock::given(method("DELETE"))
            .and(path("/services/data/v66.0/jobs/query/750R0000000zxnaIAA"))
            .and(header("authorization", "Bearer tok"))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        sf.bulk()
            .query()
            .delete("750R0000000zxnaIAA")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn query_delete_surfaces_documented_400_error_array() {
        // SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_asynch.meta/api_asynch/query_delete_job.htm
        // "Response Body - For an Unsuccessful Request", verbatim: a job
        // that has not terminated cannot be deleted.
        let server = MockServer::start().await;

        Mock::given(method("DELETE"))
            .and(path("/services/data/v66.0/jobs/query/750xx"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!([{
                "errorCode": "API_ERROR",
                "message": "Error encountered when deleting the job because the job is not terminated"
            }])))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let err = sf.bulk().query().delete("750xx").await.unwrap_err();
        match err {
            crate::CirrusError::Api { status, errors, .. } => {
                assert_eq!(status, 400);
                assert_eq!(errors[0].error_code, "API_ERROR");
            }
            other => panic!("expected Api error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn query_results_returns_csv_with_locator_header() {
        let server = MockServer::start().await;

        // SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_asynch.meta/api_asynch/query_get_job_results.htm
        // "The Accept header must match what was specified when the job
        // was created. Currently, only text/csv is supported."
        let csv = "Id,Name\n001xx,Acme\n";
        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/jobs/query/750xx/results"))
            .and(header("accept", "text/csv"))
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
    async fn query_results_rejects_a_page_without_a_locator_header() {
        // SOURCE: https://developer.salesforce.com/docs/platform/api-asynch/guide/query-get-job-results.html
        // "If there are no more sets of query results, this value is the
        // string 'null'." The literal is the only documented end marker,
        // so a 200 with no Sforce-Locator at all is not a last page: an
        // intermediary that strips the header must not end a drain loop
        // early with a partial export reported as complete.
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/jobs/query/750xx/results"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("Id,Name\n001xx,Acme\n")
                    .insert_header("Sforce-NumberOfRecords", "1"),
            )
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let err = sf
            .bulk()
            .query()
            .results("750xx", None, None)
            .await
            .unwrap_err();
        match err {
            CirrusError::InvalidResponse(message) => {
                assert!(message.contains("Sforce-Locator"), "{message}");
                assert!(
                    !message.contains("Acme"),
                    "the CSV body must stay out of the error: {message}"
                );
            }
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn query_results_rejects_a_locator_header_that_is_not_text() {
        // A locator the client cannot read back is as unusable as a
        // missing one; it must not pass as the end of the results.
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/jobs/query/750xx/results"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("Id\n")
                    .insert_header(
                        "Sforce-Locator",
                        reqwest::header::HeaderValue::from_bytes(b"MTAw\xffMA").unwrap(),
                    ),
            )
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let err = sf
            .bulk()
            .query()
            .results("750xx", None, None)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, CirrusError::InvalidResponse(m) if m.contains("Sforce-Locator")),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn query_results_rejects_an_empty_locator_header() {
        // An empty value is neither the documented end marker nor a
        // cursor that can be sent back; passing it on as `Some("")`
        // would request `?locator=` and the first page over again.
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/jobs/query/750xx/results"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("Id\n")
                    .insert_header("Sforce-Locator", ""),
            )
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let err = sf
            .bulk()
            .query()
            .results("750xx", None, None)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, CirrusError::InvalidResponse(m) if m.contains("empty Sforce-Locator")),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn query_results_serializes_max_records() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/jobs/query/750xx/results"))
            .and(query_param("maxRecords", "10000"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("Id\n")
                    .insert_header("Sforce-Locator", "null"),
            )
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

    #[tokio::test]
    async fn ingest_create_rejects_a_query_or_unknown_operation_without_a_request() {
        // SOURCE: https://developer.salesforce.com/docs/platform/api-asynch/guide/create-job.html
        // `operation` "Valid values are: insert, delete, hardDelete, update,
        // upsert, refresh, consentImport". `query` / `queryAll` belong to
        // `/jobs/query`, and `Unknown` names nothing, so each is refused
        // locally rather than round-tripped for a 400.
        let server = MockServer::start().await;
        let sf = fixture(server.uri());

        for operation in [
            BulkOperation::Query,
            BulkOperation::QueryAll,
            BulkOperation::Unknown,
        ] {
            let err = sf
                .bulk()
                .ingest()
                .create(&BulkIngestSpec::new("Account", operation))
                .await
                .unwrap_err();
            match err {
                crate::CirrusError::InvalidInput { field, .. } => assert_eq!(field, "operation"),
                other => panic!("expected InvalidInput, got {other:?}"),
            }
        }
        // The operation is checked before the object pairing, so a query
        // operation with no object is reported as the wrong operation,
        // not as a missing object.
        let mut spec = BulkIngestSpec::new("Account", BulkOperation::Query);
        spec.object = None;
        match sf.bulk().ingest().create(&spec).await.unwrap_err() {
            crate::CirrusError::InvalidInput { field, .. } => assert_eq!(field, "operation"),
            other => panic!("expected InvalidInput, got {other:?}"),
        }
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn query_create_rejects_an_ingest_or_unknown_operation_without_a_request() {
        // SOURCE: https://developer.salesforce.com/docs/platform/api-asynch/guide/query-create-job.html
        // `operation` "Possible values are: query, queryAll".
        let server = MockServer::start().await;
        let sf = fixture(server.uri());

        for operation in [
            BulkOperation::Insert,
            BulkOperation::Update,
            BulkOperation::Upsert,
            BulkOperation::Delete,
            BulkOperation::HardDelete,
            BulkOperation::Refresh,
            BulkOperation::ConsentImport,
            BulkOperation::Unknown,
        ] {
            let err = sf
                .bulk()
                .query()
                .create(&BulkQuerySpec::new("SELECT Id FROM Account", operation))
                .await
                .unwrap_err();
            match err {
                crate::CirrusError::InvalidInput { field, .. } => assert_eq!(field, "operation"),
                other => panic!("expected InvalidInput, got {other:?}"),
            }
        }
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[test]
    fn ingest_spec_constructor_serializes_only_object_and_operation() {
        let spec = BulkIngestSpec::new("Account", BulkOperation::Insert);
        assert_eq!(
            serde_json::to_value(&spec).unwrap(),
            json!({"object": "Account", "operation": "insert"})
        );
    }

    #[test]
    fn ingest_spec_consent_import_constructor_omits_object() {
        // SOURCE: https://developer.salesforce.com/docs/platform/api-asynch/guide/create-job.html
        // "Omit this property for the consentImport operation."
        let spec = BulkIngestSpec::consent_import();
        assert_eq!(
            serde_json::to_value(&spec).unwrap(),
            json!({"operation": "consentImport"})
        );
    }

    #[test]
    fn ingest_spec_setters_serialize_under_the_documented_keys() {
        // SOURCE: https://developer.salesforce.com/docs/platform/api-asynch/guide/create-job.html
        // Request-body parameter names.
        let spec = BulkIngestSpec::new("Account", BulkOperation::Upsert)
            .external_id_field_name("External_Id__c")
            .line_ending(BulkLineEnding::CRLF)
            .column_delimiter(BulkColumnDelimiter::Tab)
            .assignment_rule_id("01Q000000000001AAA");
        assert_eq!(
            serde_json::to_value(&spec).unwrap(),
            json!({
                "object": "Account",
                "operation": "upsert",
                "externalIdFieldName": "External_Id__c",
                "lineEnding": "CRLF",
                "columnDelimiter": "TAB",
                "assignmentRuleId": "01Q000000000001AAA"
            })
        );
    }

    #[test]
    fn query_spec_constructor_and_setters_serialize_under_the_documented_keys() {
        // SOURCE: https://developer.salesforce.com/docs/platform/api-asynch/guide/query-create-job.html
        assert_eq!(
            serde_json::to_value(BulkQuerySpec::new(
                "SELECT Id FROM Account",
                BulkOperation::Query
            ))
            .unwrap(),
            json!({"query": "SELECT Id FROM Account", "operation": "query"})
        );
        let spec = BulkQuerySpec::new("SELECT Id FROM Account", BulkOperation::QueryAll)
            .line_ending(BulkLineEnding::CRLF)
            .column_delimiter(BulkColumnDelimiter::Pipe);
        assert_eq!(
            serde_json::to_value(&spec).unwrap(),
            json!({
                "query": "SELECT Id FROM Account",
                "operation": "queryAll",
                "lineEnding": "CRLF",
                "columnDelimiter": "PIPE"
            })
        );
    }

    /// Splits a `multipart/form-data` request into `(part headers, part
    /// body)` pairs using the boundary its `Content-Type` declares.
    fn multipart_parts(request: &wiremock::Request) -> Vec<(String, Vec<u8>)> {
        let content_type = request.headers["content-type"].to_str().unwrap().to_owned();
        let boundary = content_type
            .split_once("boundary=")
            .map(|(_, b)| b.trim_matches('"').to_owned())
            .expect("multipart content type with a boundary");
        let delimiter = format!("--{boundary}");
        let body = String::from_utf8_lossy(&request.body).into_owned();
        body.split(&delimiter)
            .filter(|chunk| !chunk.trim().is_empty() && !chunk.starts_with("--"))
            .map(|chunk| {
                let chunk = chunk.strip_prefix("\r\n").unwrap_or(chunk);
                let (headers, body) = chunk.split_once("\r\n\r\n").expect("part header block");
                let body = body.strip_suffix("\r\n").unwrap_or(body);
                (headers.to_owned(), body.as_bytes().to_vec())
            })
            .collect()
    }

    #[tokio::test]
    async fn ingest_create_with_data_sends_the_documented_job_and_content_parts() {
        // SOURCE: https://developer.salesforce.com/docs/platform/api-asynch/guide/create-job.html
        // "Usage Notes": a `job` part typed application/json and a
        // `content` part typed text/csv with filename "content". The
        // response is the multipart walkthrough's: the job is already
        // `UploadComplete`, with no `contentUrl` and no `jobType`.
        // https://developer.salesforce.com/docs/platform/api-asynch/guide/walkthrough-upload-multipart-data.html
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/services/data/v66.0/jobs/ingest"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "7303gEXAMPLE4X2QAN",
                "operation": "insert",
                "object": "Contact",
                "createdById": "0055fEXAMPLEtG4AAM",
                "createdDate": "2022-01-02T19:26:52.000+0000",
                "systemModstamp": "2022-01-02T19:26:52.000+0000",
                "state": "UploadComplete",
                "concurrencyMode": "Parallel",
                "contentType": "CSV",
                "apiVersion": 68.0,
                "lineEnding": "LF",
                "columnDelimiter": "COMMA"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let csv = "FirstName,LastName\nAstro,Nomical\n";
        let job = sf
            .bulk()
            .ingest()
            .create_with_data(
                &BulkIngestSpec::new("Contact", BulkOperation::Insert)
                    .line_ending(BulkLineEnding::LF),
                bytes::Bytes::from(csv),
            )
            .await
            .unwrap();
        assert_eq!(job.id, "7303gEXAMPLE4X2QAN");
        assert_eq!(job.state, BulkJobState::UploadComplete);
        assert_eq!(job.content_url, None);
        assert_eq!(job.job_type, None);

        let requests = server.received_requests().await.unwrap();
        let request = &requests[0];
        assert!(
            request.headers["content-type"]
                .to_str()
                .unwrap()
                .starts_with("multipart/form-data; boundary="),
            "{:?}",
            request.headers["content-type"]
        );
        let parts = multipart_parts(request);
        assert_eq!(parts.len(), 2, "{parts:?}");

        let (job_headers, job_body) = &parts[0];
        assert!(
            job_headers.contains("Content-Disposition: form-data; name=\"job\""),
            "{job_headers}"
        );
        assert!(
            job_headers.contains("Content-Type: application/json"),
            "{job_headers}"
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(job_body).unwrap(),
            json!({"object": "Contact", "operation": "insert", "lineEnding": "LF"})
        );

        let (content_headers, content_body) = &parts[1];
        assert!(
            content_headers
                .contains("Content-Disposition: form-data; name=\"content\"; filename=\"content\""),
            "{content_headers}"
        );
        assert!(
            content_headers.contains("Content-Type: text/csv"),
            "{content_headers}"
        );
        assert_eq!(content_body, csv.as_bytes());
    }

    #[tokio::test]
    async fn ingest_create_with_data_refuses_more_than_the_documented_character_cap() {
        // SOURCE: https://developer.salesforce.com/docs/platform/api-asynch/guide/create-job.html
        // "For small amounts of job data (100,000 characters or less), you
        // can create a job and upload all the data for a job using a
        // multipart request." The cap counts characters, not bytes.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/services/data/v66.0/jobs/ingest"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(ingest_job_response("750xx", "UploadComplete")),
            )
            .expect(2)
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let ingest = sf.bulk().ingest();
        let spec = BulkIngestSpec::new("Account", BulkOperation::Insert);

        let over = bytes::Bytes::from("a".repeat(MAX_MULTIPART_JOB_DATA_CHARS + 1));
        match ingest.create_with_data(&spec, over).await.unwrap_err() {
            crate::CirrusError::InvalidInput { field, .. } => assert_eq!(field, "csv"),
            other => panic!("expected InvalidInput, got {other:?}"),
        }
        assert!(server.received_requests().await.unwrap().is_empty());

        let at_cap = bytes::Bytes::from("a".repeat(MAX_MULTIPART_JOB_DATA_CHARS));
        ingest.create_with_data(&spec, at_cap).await.unwrap();
        // Two-byte characters: at the cap by character count, twice it
        // by byte count.
        let multibyte = bytes::Bytes::from("é".repeat(MAX_MULTIPART_JOB_DATA_CHARS));
        assert_eq!(multibyte.len(), 2 * MAX_MULTIPART_JOB_DATA_CHARS);
        ingest.create_with_data(&spec, multibyte).await.unwrap();
    }

    #[tokio::test]
    async fn ingest_create_with_data_runs_the_create_job_checks_first() {
        let server = MockServer::start().await;
        let sf = fixture(server.uri());
        let csv = bytes::Bytes::from("Name\nAcme\n");

        let mut consent = BulkIngestSpec::consent_import();
        consent.object = Some("Account".into());
        match sf
            .bulk()
            .ingest()
            .create_with_data(&consent, csv.clone())
            .await
            .unwrap_err()
        {
            crate::CirrusError::InvalidInput { field, .. } => assert_eq!(field, "object"),
            other => panic!("expected InvalidInput, got {other:?}"),
        }
        match sf
            .bulk()
            .ingest()
            .create_with_data(&BulkIngestSpec::new("Account", BulkOperation::Query), csv)
            .await
            .unwrap_err()
        {
            crate::CirrusError::InvalidInput { field, .. } => assert_eq!(field, "operation"),
            other => panic!("expected InvalidInput, got {other:?}"),
        }
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn ingest_create_with_data_is_not_replayed_after_a_transient_5xx() {
        // A replayed multipart create would make a second job holding
        // the same rows, so a 502 surfaces as the error it is after one
        // attempt.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/services/data/v66.0/jobs/ingest"))
            .respond_with(ResponseTemplate::new(502))
            .expect(1)
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let err = sf
            .bulk()
            .ingest()
            .create_with_data(
                &BulkIngestSpec::new("Account", BulkOperation::Insert),
                bytes::Bytes::from("Name\nAcme\n"),
            )
            .await
            .unwrap_err();
        match err {
            crate::CirrusError::Api { status, .. } => assert_eq!(status, 502),
            other => panic!("expected Api 502, got {other:?}"),
        }
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    fn query_job_listing_page() -> serde_json::Value {
        // SOURCE: https://developer.salesforce.com/docs/platform/api-asynch/guide/query-get-all-jobs.html
        // "Response Body" example, verbatim apart from the elided third
        // record. Note the `nextRecordsUrl` names `/jobs/ingest` even on
        // the query listing; only its `queryLocator` is trusted.
        json!({
            "done": false,
            "records": [
                {
                    "id": "750R0000000zhfdIAA",
                    "operation": "query",
                    "object": "Account",
                    "createdById": "005R0000000GiwjIAC",
                    "createdDate": "2018-12-07T19:58:09.000+0000",
                    "systemModstamp": "2018-12-07T19:59:14.000+0000",
                    "state": "JobComplete",
                    "concurrencyMode": "Parallel",
                    "contentType": "CSV",
                    "apiVersion": 68.0,
                    "jobType": "V2Query",
                    "lineEnding": "LF",
                    "columnDelimiter": "COMMA"
                },
                {
                    "id": "750R0000000zhjzIAA",
                    "operation": "query",
                    "object": "Account",
                    "createdById": "005R0000000GiwjIAC",
                    "createdDate": "2018-12-07T20:52:28.000+0000",
                    "systemModstamp": "2018-12-07T20:53:15.000+0000",
                    "state": "JobComplete",
                    "concurrencyMode": "Parallel",
                    "contentType": "CSV",
                    "apiVersion": 68.0,
                    "jobType": "V2Query",
                    "lineEnding": "LF",
                    "columnDelimiter": "COMMA"
                }
            ],
            "nextRecordsUrl": "/services/data/v68.0/jobs/ingest?queryLocator=01gR0000000opRTIAY-2000"
        })
    }

    #[tokio::test]
    async fn ingest_list_sends_no_filters_by_default_and_parses_the_documented_envelope() {
        // SOURCE: https://developer.salesforce.com/docs/platform/api-asynch/guide/get-all-jobs.html
        // `GET /jobs/ingest` answers `{done, records: JobInfo[], nextRecordsUrl}`;
        // a JobInfo in `Open` state carries `contentUrl`.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/jobs/ingest"))
            .and(query_param_is_missing("jobType"))
            .and(query_param_is_missing("isPkChunkingEnabled"))
            .and(query_param_is_missing("queryLocator"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "done": true,
                "records": [{
                    "id": "750xx",
                    "operation": "insert",
                    "object": "Account",
                    "createdById": "005xx",
                    "createdDate": "2024-01-01T00:00:00.000+0000",
                    "systemModstamp": "2024-01-01T00:00:00.000+0000",
                    "state": "Open",
                    "concurrencyMode": "Parallel",
                    "contentType": "CSV",
                    "apiVersion": 66.0,
                    "jobType": "V2Ingest",
                    "contentUrl": "services/data/v66.0/jobs/ingest/750xx/batches",
                    "lineEnding": "LF",
                    "columnDelimiter": "COMMA"
                }]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let page = sf
            .bulk()
            .ingest()
            .list(&BulkJobListOptions::new())
            .await
            .unwrap();
        assert!(page.done);
        assert_eq!(page.next_records_url, None);
        assert_eq!(page.next_locator(), None);
        assert_eq!(page.records.len(), 1);
        let job = &page.records[0];
        assert_eq!(job.id, "750xx");
        assert_eq!(job.operation, BulkOperation::Insert);
        assert_eq!(job.object, "Account");
        assert_eq!(job.state, BulkJobState::Open);
        assert_eq!(job.job_type, Some(BulkJobType::V2Ingest));
        assert_eq!(job.api_version, 66.0);
        assert_eq!(
            job.content_url.as_deref(),
            Some("services/data/v66.0/jobs/ingest/750xx/batches")
        );
        assert_eq!(job.line_ending, Some(BulkLineEnding::LF));
        assert_eq!(job.column_delimiter, Some(BulkColumnDelimiter::Comma));
    }

    #[tokio::test]
    async fn ingest_list_sends_the_documented_filters() {
        // SOURCE: https://developer.salesforce.com/docs/platform/api-asynch/guide/get-all-jobs.html
        // Parameters `isPkChunkingEnabled`, `jobType` and `queryLocator`.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/jobs/ingest"))
            .and(query_param("jobType", "V2Ingest"))
            .and(query_param("isPkChunkingEnabled", "true"))
            .and(query_param("queryLocator", "01gR0000000opRTIAY-2000"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"done": true, "records": []})),
            )
            .expect(1)
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let options = BulkJobListOptions::new()
            .job_type(BulkJobType::V2Ingest)
            .pk_chunking_enabled(true)
            .query_locator("01gR0000000opRTIAY-2000");
        let page = sf.bulk().ingest().list(&options).await.unwrap();
        assert!(page.done);
        assert!(page.records.is_empty());
    }

    #[tokio::test]
    async fn query_list_parses_the_documented_page_and_exposes_the_next_locator() {
        // SOURCE: https://developer.salesforce.com/docs/platform/api-asynch/guide/query-get-all-jobs.html
        // The example's `nextRecordsUrl` points at `/jobs/ingest`, while
        // the page's own follow-up request goes to
        // `/jobs/query?queryLocator=...`: the locator is what carries
        // over, never the path.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/jobs/query"))
            .and(query_param_is_missing("queryLocator"))
            .respond_with(ResponseTemplate::new(200).set_body_json(query_job_listing_page()))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/jobs/query"))
            .and(query_param("queryLocator", "01gR0000000opRTIAY-2000"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"done": true, "records": []})),
            )
            .expect(1)
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let first = sf
            .bulk()
            .query()
            .list(&BulkJobListOptions::new())
            .await
            .unwrap();
        assert!(!first.done);
        assert_eq!(first.records.len(), 2);
        assert_eq!(first.records[0].id, "750R0000000zhfdIAA");
        assert_eq!(first.records[0].operation, BulkOperation::Query);
        assert_eq!(first.records[0].job_type, Some(BulkJobType::V2Query));
        assert_eq!(first.records[0].state, BulkJobState::JobComplete);
        assert_eq!(
            first.next_records_url.as_deref(),
            Some("/services/data/v68.0/jobs/ingest?queryLocator=01gR0000000opRTIAY-2000")
        );
        let locator = first.next_locator().unwrap();
        assert_eq!(locator, "01gR0000000opRTIAY-2000");

        let last = sf
            .bulk()
            .query()
            .list(&BulkJobListOptions::new().query_locator(locator))
            .await
            .unwrap();
        assert!(last.done);
    }

    #[tokio::test]
    async fn list_keeps_classic_jobs_readable() {
        // SOURCE: https://developer.salesforce.com/docs/platform/api-asynch/guide/query-get-all-jobs.html
        // "The information includes Bulk API 2.0 query jobs and all Bulk
        // API jobs." A Bulk API 1.0 job carries values outside the 2.0
        // enums: state `Closed` and content type `ZIP_CSV` per
        // https://developer.salesforce.com/docs/platform/api-asynch/guide/asynch-api-reference-jobinfo.html,
        // where `apiVersion` is typed as a string, and no CSV formatting
        // fields. One such job must not fail the whole listing.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/jobs/query"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "done": true,
                "records": [{
                    "id": "750xx",
                    "operation": "query",
                    "object": "Account",
                    "createdById": "005xx",
                    "createdDate": "2024-01-01T00:00:00.000+0000",
                    "systemModstamp": "2024-01-01T00:00:00.000+0000",
                    "state": "Closed",
                    "concurrencyMode": "Parallel",
                    "contentType": "ZIP_CSV",
                    "apiVersion": "66.0",
                    "jobType": "Classic"
                }]
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let page = sf
            .bulk()
            .query()
            .list(&BulkJobListOptions::new())
            .await
            .unwrap();
        let job = &page.records[0];
        assert_eq!(job.state, BulkJobState::Unknown);
        assert!(!job.state.is_terminal());
        assert_eq!(job.job_type, Some(BulkJobType::Classic));
        assert_eq!(job.content_type, "ZIP_CSV");
        assert_eq!(job.api_version, 66.0);
        assert_eq!(job.line_ending, None);
        assert_eq!(job.column_delimiter, None);
    }

    #[tokio::test]
    async fn list_with_more_pages_but_no_usable_locator_is_an_invalid_response() {
        // SOURCE: https://developer.salesforce.com/docs/platform/api-asynch/guide/get-all-jobs.html
        // `done` false means "use the nextRecordsUrl value to retrieve
        // the next group of jobs". Without a locator to do that, the
        // listing would end silently short, so it is an error instead.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/jobs/ingest"))
            .and(query_param("jobType", "V2Ingest"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"done": false, "records": []})),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/jobs/ingest"))
            .and(query_param("jobType", "Classic"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "done": false,
                "records": [],
                "nextRecordsUrl": "/services/data/v66.0/jobs/ingest?page=2"
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        for job_type in [BulkJobType::V2Ingest, BulkJobType::Classic] {
            let err = sf
                .bulk()
                .ingest()
                .list(&BulkJobListOptions::new().job_type(job_type))
                .await
                .unwrap_err();
            assert!(
                matches!(err, crate::CirrusError::InvalidResponse(_)),
                "{job_type:?}: {err:?}"
            );
        }
    }

    #[tokio::test]
    async fn list_rejects_the_unknown_job_type_filter_without_a_request() {
        let server = MockServer::start().await;
        let sf = fixture(server.uri());
        let options = BulkJobListOptions::new().job_type(BulkJobType::Unknown);
        for result in [
            sf.bulk().ingest().list(&options).await,
            sf.bulk().query().list(&options).await,
        ] {
            match result.unwrap_err() {
                crate::CirrusError::InvalidInput { field, .. } => assert_eq!(field, "job_type"),
                other => panic!("expected InvalidInput, got {other:?}"),
            }
        }
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn query_result_pages_parses_the_documented_response_and_follows_its_locator() {
        // SOURCE: https://developer.salesforce.com/docs/platform/api-asynch/guide/query-get-parallel-job-results.html
        // "Example Response Body", verbatim. The follow-up goes to the
        // same resource with the `locator` the response's
        // `nextRecordsUrl` carries.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/services/data/v66.0/jobs/query/750R0000000zxr8IAA/resultPages",
            ))
            .and(query_param_is_missing("locator"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "resultPages": [
                    {"resultUrl": "/services/data/vXX.X/jobs/query/750R0000000zxr8IAA/results?locator=aBcDeFg4N"},
                    {"resultUrl": "/services/data/vXX.X/jobs/query/750R0000000zxr8IAA/results?locator=HiJkLmN4N"},
                    {"resultUrl": "/services/data/vXX.X/jobs/query/750R0000000zxr8IAA/results?locator=oPQrStU4N"},
                    {"resultUrl": "/services/data/vXX.X/jobs/query/750R0000000zxr8IAA/results?locator=vWxYzz4N"},
                    {"resultUrl": "/services/data/vXX.X/jobs/query/750R0000000zxr8IAA/results?locator=NiKmABC4N"}
                ],
                "nextRecordsUrl": "/services/data/vXX.X/jobs/query/750R0000000zxr8IAA/resultpages?locator=YcApWm4N",
                "done": false
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/services/data/v66.0/jobs/query/750R0000000zxr8IAA/resultPages",
            ))
            .and(query_param("locator", "YcApWm4N"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "resultPages": [
                    {"resultUrl": "/services/data/vXX.X/jobs/query/750R0000000zxr8IAA/results?locator=LaStPaGe"}
                ],
                "done": true
            })))
            .expect(1)
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let first = sf
            .bulk()
            .query()
            .result_pages("750R0000000zxr8IAA", None)
            .await
            .unwrap();
        assert!(!first.done);
        assert_eq!(first.result_pages.len(), 5);
        assert_eq!(
            first.result_pages[0].result_url,
            "/services/data/vXX.X/jobs/query/750R0000000zxr8IAA/results?locator=aBcDeFg4N"
        );
        let locators: Vec<String> = first
            .result_pages
            .iter()
            .map(|page| page.locator().unwrap())
            .collect();
        assert_eq!(
            locators,
            [
                "aBcDeFg4N",
                "HiJkLmN4N",
                "oPQrStU4N",
                "vWxYzz4N",
                "NiKmABC4N"
            ]
        );
        let next = first.next_locator().unwrap();
        assert_eq!(next, "YcApWm4N");

        let last = sf
            .bulk()
            .query()
            .result_pages("750R0000000zxr8IAA", Some(&next))
            .await
            .unwrap();
        assert!(last.done);
        assert_eq!(last.next_records_url, None);
        assert_eq!(last.next_locator(), None);
        assert_eq!(last.result_pages[0].locator().unwrap(), "LaStPaGe");
    }

    #[tokio::test]
    async fn query_result_pages_accepts_the_table_spelling_of_the_next_url() {
        // SOURCE: https://developer.salesforce.com/docs/platform/api-asynch/guide/query-get-parallel-job-results.html
        // The element table spells it `nextRecordUrl`; the example
        // response spells it `nextRecordsUrl`. Both are read.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/jobs/query/750xx/resultPages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "resultPages": [
                    {"resultUrl": "/services/data/v66.0/jobs/query/750xx/results?locator=aBcDeFg4N"}
                ],
                "nextRecordUrl": "/services/data/v66.0/jobs/query/750xx/resultpages?locator=YcApWm4N",
                "done": false
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let pages = sf.bulk().query().result_pages("750xx", None).await.unwrap();
        assert_eq!(pages.next_locator().as_deref(), Some("YcApWm4N"));
    }

    #[tokio::test]
    async fn query_result_pages_without_usable_locators_is_an_invalid_response() {
        // A page URL without a `locator` cannot be fetched, and a
        // `done: false` response without a next locator would end the
        // listing short, so both are errors rather than silent gaps.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/jobs/query/no-next/resultPages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "resultPages": [
                    {"resultUrl": "/services/data/v66.0/jobs/query/no-next/results?locator=aBcDeFg4N"}
                ],
                "done": false
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/jobs/query/no-page/resultPages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "resultPages": [
                    {"resultUrl": "/services/data/v66.0/jobs/query/no-page/results"}
                ],
                "done": true
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        for job_id in ["no-next", "no-page"] {
            let err = sf
                .bulk()
                .query()
                .result_pages(job_id, None)
                .await
                .unwrap_err();
            assert!(
                matches!(err, crate::CirrusError::InvalidResponse(_)),
                "{job_id}: {err:?}"
            );
        }
    }
}
