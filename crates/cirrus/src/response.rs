//! Response parsing and well-known platform types.
//!
//! Salesforce REST returns a small set of envelope shapes that are
//! schema-independent — they describe the platform's behavior, not any
//! org-specific data. Those are hard-coded here. Anything that would carry
//! user-defined fields (records, sObjects, custom payloads) is left generic
//! over a caller-supplied type parameter.
//!
//! ## The success-vs-error split
//!
//! Every REST endpoint returns the same error shape on non-2xx — a JSON array
//! of `{message, errorCode, fields}`. That lets [`parse_response_bytes`] check
//! the status code first and only attempt to deserialize into the caller's `R`
//! on success. Callers never need to model error shapes in their response
//! types.

use crate::error::{CirrusError, CirrusResult, SalesforceError};
use reqwest::header::HeaderMap;
use serde::Deserialize;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::collections::HashMap;

/// Envelope returned by SOQL queries (`/query`, `/queryAll`, `/query/{locator}`).
///
/// Generic over the record type `R` — the SDK never assumes a record shape.
/// Use `serde_json::Value` for ad-hoc, or supply a typed struct.
#[derive(Debug, Clone, Deserialize)]
pub struct QueryResult<R> {
    /// Total number of records matched by the query (across all pages).
    #[serde(rename = "totalSize")]
    pub total_size: i64,
    /// `true` if all records have been returned; `false` if more pages exist.
    pub done: bool,
    /// Locator URL for the next batch of records, when `done` is `false`.
    #[serde(rename = "nextRecordsUrl", default)]
    pub next_records_url: Option<String>,
    /// Records returned in this batch.
    #[serde(default = "Vec::new")]
    pub records: Vec<R>,
}

/// Envelope returned by SOSL search endpoints (`/search`,
/// `/parameterizedSearch`).
///
/// Generic over the record type `R`. Every record carries a Salesforce
/// `attributes` object identifying the object type and self-URL — surface
/// it on your `R` if you need it (e.g. `#[serde(flatten)] attributes:
/// HashMap<String, Value>`).
///
/// `metadata` is populated only when the caller explicitly requests it
/// (`metadata=LABELS` on the search call). Surfaced as raw JSON because
/// its shape varies across versions.
#[derive(Debug, Clone, Deserialize)]
pub struct SearchResult<R> {
    /// Hit records, in Salesforce-defined relevance order.
    #[serde(rename = "searchRecords", default = "Vec::new")]
    pub search_records: Vec<R>,
    /// Field-label metadata, present only when the request asked for it.
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

/// Result of a single-record create/upsert via REST sObjects endpoints.
#[derive(Debug, Clone, Deserialize)]
pub struct SObjectCreateResult {
    /// ID of the created (or upserted) record.
    pub id: String,
    /// Whether the operation succeeded. Salesforce always sets this to `true`
    /// on a 2xx response — included for completeness with the documented shape.
    pub success: bool,
    /// Error array. Always empty on success, but Salesforce includes the field.
    #[serde(default)]
    pub errors: Vec<SalesforceError>,
    /// `true` if an upsert created a new record, `false` if it updated an
    /// existing one. Absent on plain creates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<bool>,
}

/// One limit entry from `GET /services/data/vXX.X/limits`.
///
/// Most limits are flat `{Max, Remaining}` pairs. A few (notably
/// `PermissionSets`) embed sub-limits with the same shape — those are
/// captured in [`Limit::nested`].
#[derive(Debug, Clone, Deserialize)]
pub struct Limit {
    /// Maximum allocation for the org.
    #[serde(rename = "Max")]
    pub max: i64,
    /// Remaining allocation, accurate to within five minutes per the docs.
    #[serde(rename = "Remaining")]
    pub remaining: i64,
    /// Sub-limits keyed by name. Empty for flat limits; populated for
    /// composite ones such as `PermissionSets.CreateCustom`.
    #[serde(flatten)]
    pub nested: HashMap<String, Limit>,
}

/// Top-level response from `GET /limits` — keys are limit names.
pub type OrgLimits = HashMap<String, Limit>;

/// Snapshot of the `Sforce-Limit-Info` response header, parsed.
///
/// Salesforce returns this header on every REST API request except calls
/// to the Versions URI, to surface the org's near-real-time API usage. The
/// value is a list of `key=used/allowed` directives:
///
/// ```text
/// Sforce-Limit-Info: api-usage=10018/100000; api-bursts=1/750
/// Sforce-Limit-Info: api-usage=10018/100000
/// ```
///
/// Populated automatically on every successful round-trip; the most
/// recent value is reachable via [`crate::Cirrus::last_limit_info`].
///
/// See [REST API Headers — Limit Info Header] for the upstream
/// documentation.
///
/// [REST API Headers — Limit Info Header]: https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/headers_api_usage.htm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LimitInfo {
    /// API calls used by this org in the current 24-hour rolling
    /// window (the first number of the `api-usage` directive).
    pub used: u32,
    /// Daily API call allocation for this org (the second number of
    /// the `api-usage` directive).
    pub allowed: u32,
    /// `(used, allowed)` from the `api-bursts` directive, which the
    /// header reference shows in its example but does not describe.
    /// `None` when the header carried no such directive.
    pub bursts: Option<(u32, u32)>,
}

impl LimitInfo {
    /// Parses a raw `Sforce-Limit-Info` header value, e.g.
    /// `"api-usage=10018/100000; api-bursts=1/750"`.
    ///
    /// Directives are separated by `;` (or `,`, when an intermediary
    /// folds repeated headers into one value) and unrecognized keys are
    /// ignored, so a value carrying directives this SDK doesn't model
    /// still yields the `api-usage` counts. Returns `None` when no
    /// well-formed `api-usage` directive is present.
    pub fn parse(header_value: &str) -> Option<Self> {
        let mut usage = None;
        let mut bursts = None;
        for directive in header_value.split([';', ',']) {
            let Some((key, value)) = directive.split_once('=') else {
                continue;
            };
            match key.trim() {
                "api-usage" => usage = Self::parse_pair(value),
                "api-bursts" => bursts = Self::parse_pair(value),
                _ => {}
            }
        }
        let (used, allowed) = usage?;
        Some(Self {
            used,
            allowed,
            bursts,
        })
    }

    /// Parses the `used/allowed` half of a single directive.
    fn parse_pair(value: &str) -> Option<(u32, u32)> {
        let (used, allowed) = value.split_once('/')?;
        Some((
            used.trim().parse::<u32>().ok()?,
            allowed.trim().parse::<u32>().ok()?,
        ))
    }

    /// Convenience: API calls remaining (`allowed - used`, saturating).
    pub fn remaining(&self) -> u32 {
        self.allowed.saturating_sub(self.used)
    }
}

/// Response from `GET /sobjects` (describe global). Schema-independent
/// platform metadata — concrete because every org returns the same shape.
#[derive(Debug, Clone, Deserialize)]
pub struct DescribeGlobal {
    /// Org's character encoding (typically `"UTF-8"`).
    pub encoding: String,
    /// Maximum batch size permitted in queries against this org.
    #[serde(rename = "maxBatchSize")]
    pub max_batch_size: i32,
    /// One entry per object visible to the authenticated user.
    pub sobjects: Vec<SObjectMetadata>,
}

/// Per-object metadata returned in [`DescribeGlobal::sobjects`]. Mirrors the
/// flags Salesforce documents for the describe-global response.
#[derive(Debug, Clone, Deserialize)]
pub struct SObjectMetadata {
    pub activateable: bool,
    pub createable: bool,
    pub custom: bool,
    #[serde(rename = "customSetting")]
    pub custom_setting: bool,
    pub deletable: bool,
    #[serde(rename = "deprecatedAndHidden")]
    pub deprecated_and_hidden: bool,
    #[serde(rename = "feedEnabled")]
    pub feed_enabled: bool,
    /// Three-character record-ID prefix (e.g. `"001"` for Account). `None`
    /// for objects without a stable prefix.
    #[serde(rename = "keyPrefix", default)]
    pub key_prefix: Option<String>,
    pub label: String,
    #[serde(rename = "labelPlural")]
    pub label_plural: String,
    pub layoutable: bool,
    pub mergeable: bool,
    #[serde(rename = "mruEnabled")]
    pub mru_enabled: bool,
    /// API name of the object, e.g. `"Account"`, `"My_Object__c"`.
    pub name: String,
    pub queryable: bool,
    pub replicateable: bool,
    pub retrieveable: bool,
    pub searchable: bool,
    pub triggerable: bool,
    pub undeletable: bool,
    pub updateable: bool,
    /// Map of related URL slugs (`sobject`, `describe`, `rowTemplate`,
    /// plus per-feature URLs that vary by object). Kept as a generic map
    /// because Salesforce adds keys here across API versions.
    #[serde(default)]
    pub urls: HashMap<String, String>,
}

/// Bulk API 2.0 operation kind, shared between ingest and query jobs.
///
/// Ingest jobs (`/jobs/ingest`) take `insert`, `delete`, `hardDelete`,
/// `update`, `upsert`, `refresh` or `consentImport`; which of those a job
/// may use depends on its target — standard objects support everything but
/// `refresh` and `consentImport`, Marketing objects support `insert`,
/// `upsert` and `refresh`, and consent ingest uses `consentImport`. Query
/// jobs (`/jobs/query`) take `query` or `queryAll`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BulkOperation {
    #[serde(rename = "insert")]
    Insert,
    #[serde(rename = "update")]
    Update,
    #[serde(rename = "upsert")]
    Upsert,
    #[serde(rename = "delete")]
    Delete,
    /// Permanent delete (skips Recycle Bin). Requires "Bulk API Hard
    /// Delete" permission, which is disabled by default.
    #[serde(rename = "hardDelete")]
    HardDelete,
    /// Marketing Object ingest only.
    #[serde(rename = "refresh")]
    Refresh,
    /// Consent ingest. Consent ingest isn't backed by an object type, so
    /// Salesforce rejects a create-job request that also sends `object`.
    #[serde(rename = "consentImport")]
    ConsentImport,
    #[serde(rename = "query")]
    Query,
    #[serde(rename = "queryAll")]
    QueryAll,
    /// An operation Salesforce returned that this SDK doesn't name, so a
    /// job created out-of-band still deserializes and its `state` and
    /// record counts stay readable. Serializing it sends the literal
    /// string `"Unknown"`, which no endpoint accepts — never use it in a
    /// request.
    #[serde(other)]
    Unknown,
}

/// State of a Bulk API 2.0 job.
///
/// Ingest job lifecycle: `Open` → `UploadComplete` → `InProgress` →
/// `JobComplete` / `Failed` / `Aborted`.
///
/// Query job lifecycle: `UploadComplete` → `InProgress` → `JobComplete` /
/// `Failed` / `Aborted` (query jobs skip `Open` since the SOQL is
/// supplied at create time — there's no separate upload step).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BulkJobState {
    /// Ingest job: created, accepting CSV uploads. Not used by query jobs.
    Open,
    /// Upload finished (ingest) or job created (query); Salesforce will
    /// pick it up for processing.
    UploadComplete,
    /// Job is being processed.
    InProgress,
    /// Job is fully processed. Inspect record-level results for
    /// per-row outcomes.
    JobComplete,
    /// Job was aborted by the caller or an admin.
    Aborted,
    /// Job failed at the platform level. For ingest jobs, see
    /// [`BulkIngestJob::error_message`] for the reason.
    Failed,
}

/// CSV line ending used in Bulk 2.0 job payloads and result downloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum BulkLineEnding {
    /// `\n` only.
    #[default]
    LF,
    /// `\r\n`.
    CRLF,
}

/// CSV column delimiter used in Bulk 2.0 job payloads and result
/// downloads. Salesforce supports a fixed set of single-character
/// delimiters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum BulkColumnDelimiter {
    Backquote,
    Caret,
    #[default]
    Comma,
    Pipe,
    Semicolon,
    Tab,
}

/// Response from `POST /jobs/ingest` and `GET /jobs/ingest/{jobId}`.
///
/// Field availability varies by job state — `number_records_processed`,
/// `number_records_failed`, and timing fields are populated only after
/// the job reaches `JobComplete` or `Failed`. `content_url` is populated
/// only while the job is in `Open` state.
#[derive(Debug, Clone, Deserialize)]
pub struct BulkIngestJob {
    pub id: String,
    pub operation: BulkOperation,
    pub object: String,
    pub state: BulkJobState,
    #[serde(rename = "externalIdFieldName", default)]
    pub external_id_field_name: Option<String>,
    #[serde(rename = "lineEnding")]
    pub line_ending: BulkLineEnding,
    #[serde(rename = "columnDelimiter")]
    pub column_delimiter: BulkColumnDelimiter,
    #[serde(rename = "contentType")]
    pub content_type: String,
    #[serde(rename = "contentUrl", default)]
    pub content_url: Option<String>,
    /// The wire sends a JSON number (e.g. `60.0`), so this is a float
    /// rather than the `String` used by [`ApiVersion::version`].
    #[serde(rename = "apiVersion")]
    pub api_version: f64,
    #[serde(rename = "jobType")]
    pub job_type: String,
    #[serde(rename = "concurrencyMode")]
    pub concurrency_mode: String,
    #[serde(rename = "createdById")]
    pub created_by_id: String,
    #[serde(rename = "createdDate")]
    pub created_date: String,
    #[serde(rename = "systemModstamp")]
    pub system_modstamp: String,
    #[serde(rename = "assignmentRuleId", default)]
    pub assignment_rule_id: Option<String>,
    #[serde(rename = "numberRecordsProcessed", default)]
    pub number_records_processed: Option<i64>,
    #[serde(rename = "numberRecordsFailed", default)]
    pub number_records_failed: Option<i64>,
    #[serde(default)]
    pub retries: Option<i32>,
    #[serde(rename = "totalProcessingTime", default)]
    pub total_processing_time: Option<i64>,
    #[serde(rename = "apiActiveProcessingTime", default)]
    pub api_active_processing_time: Option<i64>,
    #[serde(rename = "apexProcessingTime", default)]
    pub apex_processing_time: Option<i64>,
    /// Error message for jobs in `Failed` state. `None` for healthy
    /// jobs. Per the Get Job Info doc — see `errorMessage` field.
    #[serde(rename = "errorMessage", default)]
    pub error_message: Option<String>,
}

/// Response from the state-transition PATCH endpoints:
/// `PATCH /jobs/ingest/{jobId}` (close or abort an ingest job) and
/// `PATCH /jobs/query/{jobId}` (abort a query job).
///
/// This is a partial view of the job, not the full [`BulkIngestJob`] /
/// [`BulkQueryJob`]: Salesforce omits `jobType`, `lineEnding`, and
/// `columnDelimiter` from PATCH responses. To read the full job
/// metadata after a state change, follow up with a GET
/// ([`BulkIngestHandler::get`] / [`BulkQueryHandler::get`]).
///
/// [`BulkIngestHandler::get`]: crate::handlers::bulk::BulkIngestHandler::get
/// [`BulkQueryHandler::get`]: crate::handlers::bulk::BulkQueryHandler::get
//
// Wire-shape provenance (api_asynch doc page IDs):
// - `query_abort_job` documents this exact shape, with an example
//   response containing only the ten always-present fields below.
// - The ingest pages (`close_job`, `abort_job`) reuse the generic
//   job-info field table (which lists `jobType`/`lineEnding`/
//   `columnDelimiter`), but live API v66.0 PATCH responses match the
//   query example: the formatting fields and `jobType` are absent.
// - `externalIdFieldName` and `assignmentRuleId` are listed as
//   conditionally present on the ingest pages; they never apply to
//   query jobs.
#[derive(Debug, Clone, Deserialize)]
pub struct BulkJobStateChange {
    pub id: String,
    pub operation: BulkOperation,
    pub object: String,
    pub state: BulkJobState,
    /// The wire sends a JSON number (e.g. `60.0`), so this is a float
    /// rather than the `String` used by [`ApiVersion::version`].
    #[serde(rename = "apiVersion")]
    pub api_version: f64,
    #[serde(rename = "concurrencyMode")]
    pub concurrency_mode: String,
    #[serde(rename = "contentType")]
    pub content_type: String,
    #[serde(rename = "createdById")]
    pub created_by_id: String,
    #[serde(rename = "createdDate")]
    pub created_date: String,
    #[serde(rename = "systemModstamp")]
    pub system_modstamp: String,
    /// External ID field of an ingest upsert job. `None` for the other
    /// ingest operations and for query jobs.
    #[serde(rename = "externalIdFieldName", default)]
    pub external_id_field_name: Option<String>,
    /// Assignment rule, present only when one was specified at job
    /// creation (ingest jobs only).
    #[serde(rename = "assignmentRuleId", default)]
    pub assignment_rule_id: Option<String>,
}

/// Response from `POST /jobs/query` and `GET /jobs/query/{jobId}`.
///
/// Field availability varies by job state and request kind:
///
/// - The CREATE response (POST) includes the core identification fields
///   (`id`, `operation`, `object`, timestamps, `state`, formatting flags)
///   but **omits** `job_type`, `number_records_processed`, `retries`,
///   `total_processing_time`, `is_pk_chunking_supported`.
/// - The GET response includes the post-execution fields once the job
///   reaches `JobComplete`.
///
/// Salesforce **never echoes the original SOQL `query` string** back in
/// either response — it's intentionally write-only at this tier. If you
/// need to recover the SOQL, hold onto your [`BulkQuerySpec`] before
/// calling [`crate::handlers::bulk::BulkQueryHandler::create`].
///
/// [`BulkQuerySpec`]: crate::handlers::bulk::BulkQuerySpec
#[derive(Debug, Clone, Deserialize)]
pub struct BulkQueryJob {
    pub id: String,
    pub operation: BulkOperation,
    pub state: BulkJobState,
    /// Object the SOQL targets (parsed and surfaced by Salesforce —
    /// not the original SOQL).
    pub object: String,
    #[serde(rename = "lineEnding")]
    pub line_ending: BulkLineEnding,
    #[serde(rename = "columnDelimiter")]
    pub column_delimiter: BulkColumnDelimiter,
    #[serde(rename = "contentType")]
    pub content_type: String,
    /// The wire sends a JSON number (e.g. `60.0`), so this is a float
    /// rather than the `String` used by [`ApiVersion::version`].
    #[serde(rename = "apiVersion")]
    pub api_version: f64,
    /// `"V2Query"` once the job reaches the GET endpoint. **Not** echoed
    /// in CREATE responses; expect `None` until GET.
    #[serde(rename = "jobType", default)]
    pub job_type: Option<String>,
    #[serde(rename = "concurrencyMode")]
    pub concurrency_mode: String,
    #[serde(rename = "createdById")]
    pub created_by_id: String,
    #[serde(rename = "createdDate")]
    pub created_date: String,
    #[serde(rename = "systemModstamp")]
    pub system_modstamp: String,
    #[serde(rename = "numberRecordsProcessed", default)]
    pub number_records_processed: Option<i64>,
    #[serde(default)]
    pub retries: Option<i32>,
    #[serde(rename = "totalProcessingTime", default)]
    pub total_processing_time: Option<i64>,
    /// Whether PK chunking is supported for the queried object.
    /// Populated on GET responses only (not CREATE).
    #[serde(rename = "isPkChunkingSupported", default)]
    pub is_pk_chunking_supported: Option<bool>,
    /// Error message accompanying a `Failed` job, when the response
    /// carries one. `None` otherwise — including on healthy jobs.
    //
    // Wire-shape provenance (api_asynch doc page IDs): unlike the ingest
    // side, `query_get_one_job` lists no `errorMessage` in its response
    // parameters and neither of its example bodies contains one. The
    // field is modelled as always-optional so a query job that does
    // carry it stays readable; callers must not treat its absence as
    // meaningful.
    #[serde(rename = "errorMessage", default)]
    pub error_message: Option<String>,
}

/// Result of `GET /jobs/query/{jobId}/results`.
///
/// Carries the CSV body alongside the cursor headers Salesforce uses for
/// pagination. `locator` is `None` when the result set is fully drained;
/// pass it back to [`crate::handlers::bulk::BulkQueryHandler::results`]
/// in subsequent calls to fetch the next page.
///
/// The [`Debug`] rendering reports the CSV length in place of the body:
/// one page holds up to tens of thousands of exported records, and the
/// cursor fields are the reason to debug-format this type.
#[derive(Clone)]
pub struct BulkQueryResults {
    /// CSV body of this result page.
    pub csv: bytes::Bytes,
    /// Pagination cursor (`Sforce-Locator` response header). `None` when
    /// the job has emitted all rows.
    pub locator: Option<String>,
    /// Number of records included in this page (`Sforce-NumberOfRecords`
    /// response header).
    pub number_of_records: Option<i64>,
}

impl std::fmt::Debug for BulkQueryResults {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BulkQueryResults")
            .field("csv_len", &self.csv.len())
            .field("locator", &self.locator)
            .field("number_of_records", &self.number_of_records)
            .finish()
    }
}

/// One `EventLogFile` sObject record returned by querying
/// `SELECT ... FROM EventLogFile`.
///
/// Schema-stable platform fields are typed here; the underlying log
/// payload (CSV bytes) is fetched separately via
/// [`crate::handlers::event_monitoring::EventMonitoringHandler::download`].
///
/// # Field availability
///
/// - `Id`, `EventType`, `LogFile`, `LogDate`, `LogFileLength` are
///   present whenever you `SELECT` them.
/// - `Interval` is `"Hourly"` for hourly files and `"Daily"` for
///   24-hour files. `Sequence` is `0` for daily files and starts at 1
///   for hourly files, incrementing per file within the same hour.
///   Filter on `Interval = 'Hourly'` (or `Sequence != 0`) to read only
///   hourly files.
/// - `CreatedDate` is the timestamp the log file became downloadable —
///   not the same as `LogDate` (when the events occurred). Use
///   `CreatedDate > <last-fetch>` to drive incremental ingestion (per
///   Salesforce's documented best practice).
///
/// All Optional fields are `None` when the SELECT clause didn't ask
/// for them; serde's `default` attribute keeps deserialization robust
/// against partial column sets.
#[derive(Debug, Clone, Deserialize)]
pub struct EventLogFileRecord {
    #[serde(rename = "Id")]
    pub id: String,
    /// Event category — `"API"`, `"Login"`, `"URI"`, `"Apex"`, etc.
    /// The set of EventTypes is large and grows across releases.
    #[serde(rename = "EventType")]
    pub event_type: String,
    /// Instance-relative URL of the CSV log payload, e.g.
    /// `/services/data/v66.0/sobjects/EventLogFile/0AT.../LogFile`.
    /// Pass to [`crate::handlers::event_monitoring::EventMonitoringHandler::download_url`]
    /// directly.
    #[serde(rename = "LogFile")]
    pub log_file: String,
    /// Date the events occurred (UTC). Distinct from `CreatedDate`
    /// (when the file became downloadable).
    #[serde(rename = "LogDate")]
    pub log_date: String,
    /// Size of the CSV payload in bytes. Returned as a JSON number
    /// (often a float in older API versions, integer in newer); we
    /// store as `f64` to absorb both.
    #[serde(rename = "LogFileLength", default)]
    pub log_file_length: Option<f64>,
    /// `"Hourly"` for hourly log files, `"Daily"` for 24-hour log
    /// files. `None` only when the SELECT clause didn't ask for the
    /// field. Match on the value when you want just the hourly stream.
    #[serde(rename = "Interval", default)]
    pub interval: Option<String>,
    /// Increment ordinal per hour bucket — `0` for daily files; `>= 1`
    /// for hourly files within the same hour.
    #[serde(rename = "Sequence", default)]
    pub sequence: Option<i32>,
    /// Timestamp the file became downloadable (drives incremental
    /// ingestion). UTC, ISO-8601.
    #[serde(rename = "CreatedDate", default)]
    pub created_date: Option<String>,
}

/// One entry from `GET /services/data` — a Salesforce REST API version.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiVersion {
    /// Human-readable label, e.g. `"Winter '24"`.
    pub label: String,
    /// URL prefix for endpoints in this version, e.g. `"/services/data/v66.0"`.
    pub url: String,
    /// Numeric version string, e.g. `"60.0"`.
    pub version: String,
}

impl ApiVersion {
    /// Parses [`version`](Self::version) into a numeric `(major, minor)`
    /// tuple suitable for ordering. Returns `None` if the string is
    /// malformed.
    ///
    /// Lexical comparison of the raw string is **wrong** for version
    /// ordering: `"9.0"` sorts greater than `"60.0"` lexically. Use
    /// this for any sorting/comparison.
    pub fn version_number(&self) -> Option<(u32, u32)> {
        let (major, minor) = self.version.split_once('.')?;
        Some((major.parse().ok()?, minor.parse().ok()?))
    }

    /// Returns the highest-numbered [`ApiVersion`] in `versions`,
    /// comparing by `(major, minor)` rather than lexically.
    ///
    /// Entries whose [`version`](Self::version) isn't a `major.minor`
    /// pair are ignored, so the returned entry always carries a version
    /// string usable as a `vXX.X` path segment. Returns `None` when the
    /// slice is empty or holds nothing parseable.
    pub fn latest(versions: &[Self]) -> Option<&Self> {
        versions
            .iter()
            .filter(|v| v.version_number().is_some())
            .max_by_key(|v| v.version_number())
    }
}

/// Top-level response from `POST /composite/batch`.
///
/// Salesforce always returns HTTP 200 for a well-formed batch even when
/// individual sub-requests fail — per-subrequest failures are surfaced via
/// [`has_errors`](Self::has_errors) and the `statusCode` on each
/// [`BatchSubresult`]. Translating sub-failures into transport errors would
/// drop the partial successes in the same response, so callers inspect
/// results directly.
#[derive(Debug, Clone, Deserialize)]
pub struct BatchResponse {
    /// `true` when at least one sub-request returned a 4xx/5xx status.
    #[serde(rename = "hasErrors")]
    pub has_errors: bool,
    /// One entry per sub-request, in the order submitted.
    #[serde(default = "Vec::new")]
    pub results: Vec<BatchSubresult>,
}

/// One sub-request result inside [`BatchResponse::results`].
///
/// `result` is the body returned by the sub-request — a record on success,
/// `null` for a 204 No Content (e.g. PATCH/DELETE), or a Salesforce error
/// array on failure. Its shape is intentionally untyped because batch
/// sub-requests are heterogeneous.
#[derive(Debug, Clone, Deserialize)]
pub struct BatchSubresult {
    /// HTTP status code returned by this sub-request.
    #[serde(rename = "statusCode")]
    pub status_code: u16,
    /// Sub-request response body, or `Value::Null` for 204 responses.
    #[serde(default)]
    pub result: serde_json::Value,
}

impl BatchSubresult {
    /// `true` if this sub-request succeeded (`status_code` in 200..300).
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status_code)
    }
}

/// Top-level response from `POST /composite/tree/{SObject}`.
///
/// **All-or-nothing semantics.** Unlike [`BatchResponse`], a tree request
/// with any failing record rolls back *every* record in the request — no
/// partial commits. If [`has_errors`](Self::has_errors) is `true`, none of
/// the records in `results` were created; fix the listed errors and resend
/// the entire tree.
///
/// The `results` collection therefore behaves differently in the two cases:
/// on success it contains every record's `referenceId` → `id` mapping; on
/// failure it contains *only* the records whose validation/save errored.
#[derive(Debug, Clone, Deserialize)]
pub struct CompositeTreeResponse {
    /// `true` when the request rolled back due to one or more record errors.
    #[serde(rename = "hasErrors")]
    pub has_errors: bool,
    /// On success: one entry per record with [`CompositeTreeResult::id`]
    /// populated. On failure: only entries for the records that failed,
    /// with [`CompositeTreeResult::errors`] populated instead.
    #[serde(default = "Vec::new")]
    pub results: Vec<CompositeTreeResult>,
}

/// One per-record entry in [`CompositeTreeResponse::results`].
///
/// `id` and `errors` form a soft union — exactly one is populated:
/// - `Some(id)` / `None` on a successful create
/// - `None` / `Some(errors)` on a failure
///
/// Modeled as two `Option`s rather than a tagged enum because the wire
/// shape doesn't carry a discriminator and callers usually inspect by
/// field presence rather than matching variants.
#[derive(Debug, Clone, Deserialize)]
pub struct CompositeTreeResult {
    /// Caller-supplied reference ID echoed back from the request.
    #[serde(rename = "referenceId")]
    pub reference_id: String,
    /// Salesforce ID of the created record. Populated only on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Validation/save errors for this record. Populated only when this
    /// record's create failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<CompositeError>>,
}

impl CompositeTreeResult {
    /// `true` if this record was created (`id` is set, `errors` is not).
    pub fn is_success(&self) -> bool {
        self.id.is_some() && self.errors.is_none()
    }
}

/// Per-record error entry returned inside composite endpoint results
/// ([`CompositeTreeResult::errors`], [`SObjectCollectionResult::errors`]).
///
/// Salesforce uses a **different shape** here from the standard REST error
/// array surfaced as [`crate::SalesforceError`]: the field is `statusCode`
/// (a string enum like `"INVALID_EMAIL_ADDRESS"` or `"DUPLICATE_VALUE"`,
/// not an HTTP code) rather than `errorCode`. Don't try to deserialize
/// this from the standard error array shape and vice versa.
#[derive(Debug, Clone, Deserialize)]
pub struct CompositeError {
    /// String enum identifying the error (e.g. `"INVALID_EMAIL_ADDRESS"`).
    #[serde(rename = "statusCode")]
    pub status_code: String,
    /// Human-readable explanation.
    pub message: String,
    /// Field API names contributing to the error, when applicable.
    #[serde(default)]
    pub fields: Vec<String>,
}

/// Top-level response from `POST /composite`.
///
/// Generic composite returns `compositeResponse` — a vector of per-subrequest
/// results in submission order (or an order determined by `collateSubrequests`
/// when collation is enabled). Each entry is a [`CompositeSubresponse`]
/// carrying that subrequest's HTTP status, headers, body, and the caller's
/// `referenceId` for matching.
///
/// Unlike [`BatchResponse`] / [`CompositeTreeResponse`], there is *no*
/// top-level `hasErrors` flag — callers iterate
/// [`composite_response`](Self::composite_response) and check each
/// subresponse's [`http_status_code`](CompositeSubresponse::http_status_code)
/// (or use [`CompositeSubresponse::is_success`]). The transactional
/// rollback flag is on the *request* side (`allOrNone`).
#[derive(Debug, Clone, Deserialize)]
pub struct CompositeResponse {
    /// One entry per sub-request, ordered by submission unless
    /// `collateSubrequests` reordered them server-side.
    #[serde(rename = "compositeResponse", default = "Vec::new")]
    pub composite_response: Vec<CompositeSubresponse>,
}

/// One sub-request entry inside [`CompositeResponse::composite_response`].
///
/// Carries the caller's `referenceId` echoed back, the HTTP status and
/// headers the sub-request returned, and its body (record / error array /
/// `null`). The `http_headers` field is the place to look for `Location`
/// after a create or `Sforce-Limit-Info` for rate-limit tracking.
///
/// Headers are surfaced as a [`HeaderMap`] so lookups are case-insensitive
/// — `headers.get("location")` and `headers.get("Location")` reach the
/// same value, regardless of how Salesforce cased it on the wire.
#[derive(Debug, Clone, Deserialize)]
pub struct CompositeSubresponse {
    /// Sub-request response body — record on success, error array on
    /// failure, `Value::Null` for 204 No Content.
    #[serde(default)]
    pub body: serde_json::Value,
    /// HTTP headers returned by the sub-request.
    #[serde(rename = "httpHeaders", default, with = "http_serde::header_map")]
    pub http_headers: HeaderMap,
    /// HTTP status code of the sub-request.
    #[serde(rename = "httpStatusCode")]
    pub http_status_code: u16,
    /// Caller-supplied `referenceId` from the matching request entry.
    /// Use this to correlate when `collateSubrequests` reorders results.
    #[serde(rename = "referenceId")]
    pub reference_id: String,
}

impl CompositeSubresponse {
    /// `true` if this sub-request succeeded (`http_status_code` in 200..300).
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.http_status_code)
    }
}

/// One per-record entry in the array returned by `/composite/sobjects`
/// (create / update / upsert / delete).
///
/// Unlike [`CompositeTreeResponse`], this endpoint does *not* roll back
/// on partial failure when `allOrNone: false` (the default). Each record
/// gets its own success/error result and a successful record's `id` is
/// populated even when sibling records in the same call failed.
///
/// `created` is populated only by the upsert endpoint — `Some(true)`
/// when an upsert inserted a new record, `Some(false)` when it updated
/// an existing one. Absent on plain create/update/delete.
#[derive(Debug, Clone, Deserialize)]
pub struct SObjectCollectionResult {
    /// Salesforce ID of the affected record. `None` when this entry
    /// represents a failure (no record was created/updated).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// `true` when the per-record operation succeeded.
    pub success: bool,
    /// Errors for this record. Populated only when `success` is `false`;
    /// uses the diverged composite error shape ([`CompositeError`]).
    #[serde(default)]
    pub errors: Vec<CompositeError>,
    /// `true` if an upsert inserted a new record, `false` if it updated
    /// an existing one. Always `None` for non-upsert calls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<bool>,
}

/// Result envelope from `GET /tooling/executeAnonymous?anonymousBody=...`.
///
/// Reports whether the supplied Apex source code compiled and executed
/// successfully. The shape encodes three outcomes:
///
/// - **Success.** `compiled = true`, `success = true`,
///   `compile_problem`/`exception_message` are `None`,
///   `line`/`column` are `-1`.
/// - **Compile error.** `compiled = false`, `success = false`,
///   `compile_problem` is `Some(...)`, `line`/`column` point at the
///   offending source location.
/// - **Runtime error.** `compiled = true`, `success = false`,
///   `exception_message`/`exception_stack_trace` are `Some(...)`. The
///   `line`/`column` typically reflect where the exception was thrown.
///
/// `line` and `column` use `-1` as the "no error" sentinel. Callers
/// should branch on [`success`](Self::success) rather than checking
/// these for `>= 0`.
//
// Wire-shape provenance (api_tooling doc page IDs): `intro_rest_resources`
// documents only the request for `/executeAnonymous` — no response body is
// published for the REST resource. The field set below comes from
// `tooling_api_objects_apexresult`, which enumerates the seven
// `ExecuteAnonymousResult` fields (`column`, `compileProblem`, `compiled`,
// `exceptionMessage`, `exceptionStackTrace`, `line`, `success`) for the
// ApexExecutionOverlayResult surface. The JSON casing and the `-1` "no
// error" sentinel on `line`/`column` are not published anywhere fetchable;
// they come from live API observation, which is why those two fields are
// non-`Option` `i32`.
#[derive(Debug, Clone, Deserialize)]
pub struct ExecuteAnonymousResult {
    /// `true` if the Apex source compiled. `false` indicates a syntax
    /// or symbol-resolution failure — see
    /// [`compile_problem`](Self::compile_problem).
    pub compiled: bool,
    /// Compiler diagnostic text when [`compiled`](Self::compiled) is
    /// `false`. `None` on successful compile.
    #[serde(rename = "compileProblem", default)]
    pub compile_problem: Option<String>,
    /// `true` if the code both compiled *and* ran without throwing.
    pub success: bool,
    /// Source line of the error (1-based), or `-1` if no error.
    pub line: i32,
    /// Source column of the error (1-based), or `-1` if no error.
    pub column: i32,
    /// Runtime-exception text when an unhandled exception was thrown.
    /// `None` when the code ran cleanly or failed to compile.
    #[serde(rename = "exceptionMessage", default)]
    pub exception_message: Option<String>,
    /// Apex stack trace accompanying [`exception_message`](Self::exception_message).
    #[serde(rename = "exceptionStackTrace", default)]
    pub exception_stack_trace: Option<String>,
}

/// Parses a Salesforce response body, branching on the HTTP status.
///
/// On 2xx, the body is deserialized into `R` (use `serde_json::Value` for an
/// untyped response). On 4xx/5xx, the body is parsed as a Salesforce error
/// array; if that fails the raw body is preserved in
/// [`CirrusError::Api::raw`] for debugging.
pub(crate) fn parse_response_bytes<R: DeserializeOwned>(
    status: u16,
    bytes: &[u8],
) -> CirrusResult<R> {
    if (200..300).contains(&status) {
        if bytes.is_empty() {
            // Some endpoints return 204 No Content. Deserialize JSON null —
            // works for `()` and for `Option<T>`. For any other `R`, name
            // the real problem (empty body) instead of surfacing serde's
            // opaque "invalid type: null" message.
            return serde_json::from_slice(b"null").map_err(|_| {
                CirrusError::InvalidResponse(format!(
                    "endpoint returned {status} with an empty body; deserialize into `()` or \
                     `Option<T>` instead of a non-nullable type"
                ))
            });
        }
        return serde_json::from_slice(bytes).map_err(CirrusError::Serialization);
    }
    Err(parse_error_response(status, bytes))
}

/// Ceiling on how much of an unparseable error body is preserved in
/// [`CirrusError::Api::raw`]. Bodies that don't match the Salesforce
/// error shape come from proxies and gateways, which can echo request
/// data — capping what we retain bounds what can end up in the
/// caller's logs via `Display`/`Debug`, and keeps a pathological body
/// from ballooning the error value. 2 KiB comfortably fits real proxy
/// error pages' useful prefix.
const RAW_ERROR_BODY_CAP: usize = 2048;

/// Parses a non-2xx response body into a [`CirrusError::Api`].
///
/// Tries the standard Salesforce error-array shape first; falls back to
/// preserving the raw body (capped at [`RAW_ERROR_BODY_CAP`] bytes) for
/// debugging when the array doesn't parse. Used both by
/// [`parse_response_bytes`] (JSON success path) and the raw-body
/// transport path that bypasses JSON deserialization on success
/// (Bulk API CSV downloads).
pub(crate) fn parse_error_response(status: u16, bytes: &[u8]) -> CirrusError {
    let errors = serde_json::from_slice::<Vec<SalesforceError>>(bytes).unwrap_or_default();
    let raw = if errors.is_empty() {
        Some(capped_body(bytes))
    } else {
        None
    };
    CirrusError::Api {
        status,
        errors,
        raw,
    }
}

/// Decodes a body for inclusion in an error, bounded by
/// [`RAW_ERROR_BODY_CAP`] and marked when anything was dropped.
///
/// Only the capped byte prefix is decoded, so a multi-megabyte body never
/// gets a full owned copy. Lossy decoding expands each invalid byte to a
/// three-byte U+FFFD, which can push even that prefix past the cap, so the
/// decoded string is trimmed again at a char boundary.
fn capped_body(bytes: &[u8]) -> String {
    let mut truncated = bytes.len() > RAW_ERROR_BODY_CAP;
    let head = &bytes[..bytes.len().min(RAW_ERROR_BODY_CAP)];
    let mut body = String::from_utf8_lossy(head).into_owned();
    if body.len() > RAW_ERROR_BODY_CAP {
        let mut end = RAW_ERROR_BODY_CAP;
        while !body.is_char_boundary(end) {
            end -= 1;
        }
        body.truncate(end);
        truncated = true;
    }
    if truncated {
        body.push_str("… <truncated>");
    }
    body
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::Value;
    use serde_json::json;

    #[test]
    fn non_utf8_error_body_is_capped_after_lossy_decoding() {
        // Each invalid byte becomes a three-byte U+FFFD, so a byte-prefix
        // cap alone would still leave ~3x the cap in the error value.
        let body = vec![0xffu8; RAW_ERROR_BODY_CAP * 4];
        let err = parse_error_response(502, &body);
        match err {
            CirrusError::Api { raw: Some(raw), .. } => {
                assert!(raw.ends_with("… <truncated>"), "missing marker");
                assert!(
                    raw.len() < RAW_ERROR_BODY_CAP + 32,
                    "raw not capped: {} bytes",
                    raw.len()
                );
            }
            other => panic!("expected Api with raw body, got {other:?}"),
        }
    }

    #[test]
    fn short_error_body_is_preserved_verbatim() {
        let err = parse_error_response(502, b"<html>bad gateway</html>");
        match err {
            CirrusError::Api { raw: Some(raw), .. } => {
                assert_eq!(raw, "<html>bad gateway</html>");
            }
            other => panic!("expected Api with raw body, got {other:?}"),
        }
    }

    #[test]
    fn unparseable_error_body_is_capped() {
        let body = "x".repeat(RAW_ERROR_BODY_CAP * 3);
        let err = parse_error_response(502, body.as_bytes());
        match err {
            CirrusError::Api { raw: Some(raw), .. } => {
                assert!(
                    raw.ends_with("… <truncated>"),
                    "missing marker: …{}",
                    &raw[raw.len() - 20..]
                );
                assert!(
                    raw.len() < RAW_ERROR_BODY_CAP + 32,
                    "raw not capped: {} bytes",
                    raw.len()
                );
            }
            other => panic!("expected Api with raw body, got {other:?}"),
        }
    }

    #[test]
    fn parses_success_into_value() {
        let body = json!({"Id": "001xx", "Name": "Acme"}).to_string();
        let parsed: Value = parse_response_bytes(200, body.as_bytes()).unwrap();
        assert_eq!(parsed["Id"], "001xx");
    }

    #[test]
    fn parses_query_result() {
        let body = json!({
            "totalSize": 2,
            "done": true,
            "records": [
                {"Id": "1", "Name": "A"},
                {"Id": "2", "Name": "B"}
            ]
        })
        .to_string();
        let qr: QueryResult<Value> = parse_response_bytes(200, body.as_bytes()).unwrap();
        assert_eq!(qr.total_size, 2);
        assert!(qr.done);
        assert_eq!(qr.records.len(), 2);
        assert!(qr.next_records_url.is_none());
    }

    #[test]
    fn parses_paginated_query_result() {
        let body = json!({
            "totalSize": 1500,
            "done": false,
            "nextRecordsUrl": "/services/data/v66.0/query/01g...-2000",
            "records": []
        })
        .to_string();
        let qr: QueryResult<Value> = parse_response_bytes(200, body.as_bytes()).unwrap();
        assert!(!qr.done);
        assert_eq!(
            qr.next_records_url.as_deref(),
            Some("/services/data/v66.0/query/01g...-2000")
        );
    }

    #[test]
    fn parses_error_array_into_api_error() {
        let body = r#"[{"message":"No such column","errorCode":"INVALID_FIELD","fields":["Foo"]}]"#;
        let err = parse_response_bytes::<Value>(400, body.as_bytes()).unwrap_err();
        match err {
            CirrusError::Api {
                status,
                errors,
                raw,
            } => {
                assert_eq!(status, 400);
                assert_eq!(errors.len(), 1);
                assert_eq!(errors[0].error_code, "INVALID_FIELD");
                assert!(raw.is_none());
            }
            other => panic!("expected Api error, got {other:?}"),
        }
    }

    #[test]
    fn falls_back_to_raw_when_error_body_is_unparseable() {
        let body = "<html>Internal Server Error</html>";
        let err = parse_response_bytes::<Value>(500, body.as_bytes()).unwrap_err();
        match err {
            CirrusError::Api {
                status,
                errors,
                raw,
            } => {
                assert_eq!(status, 500);
                assert!(errors.is_empty());
                assert_eq!(raw.as_deref(), Some(body));
            }
            other => panic!("expected Api error, got {other:?}"),
        }
    }

    #[test]
    fn empty_2xx_body_is_treated_as_null() {
        let parsed: Option<Value> = parse_response_bytes(204, b"").unwrap();
        assert!(parsed.is_none());
    }

    #[test]
    fn empty_2xx_body_into_non_nullable_type_names_the_problem() {
        let err = parse_response_bytes::<Limit>(204, b"").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("204"), "got: {msg}");
        assert!(msg.contains("empty body"), "got: {msg}");
    }

    #[test]
    fn parses_flat_limit() {
        let body = r#"{"Max": 5000, "Remaining": 4937}"#;
        let limit: Limit = parse_response_bytes(200, body.as_bytes()).unwrap();
        assert_eq!(limit.max, 5000);
        assert_eq!(limit.remaining, 4937);
        assert!(limit.nested.is_empty());
    }

    #[test]
    fn parses_nested_limit() {
        // PermissionSets is the canonical nested case from the docs.
        let body = r#"{
            "Max": 1500,
            "Remaining": 1499,
            "CreateCustom": {"Max": 1000, "Remaining": 999}
        }"#;
        let limit: Limit = parse_response_bytes(200, body.as_bytes()).unwrap();
        assert_eq!(limit.max, 1500);
        assert_eq!(limit.remaining, 1499);
        assert_eq!(limit.nested.len(), 1);
        let nested = limit.nested.get("CreateCustom").unwrap();
        assert_eq!(nested.max, 1000);
        assert_eq!(nested.remaining, 999);
        assert!(nested.nested.is_empty());
    }

    #[test]
    fn parses_org_limits_envelope() {
        let body = json!({
            "DailyApiRequests": {"Max": 5000, "Remaining": 4937},
            "PermissionSets": {
                "Max": 1500,
                "Remaining": 1499,
                "CreateCustom": {"Max": 1000, "Remaining": 999}
            }
        })
        .to_string();
        let limits: OrgLimits = parse_response_bytes(200, body.as_bytes()).unwrap();
        assert_eq!(limits.len(), 2);
        assert_eq!(limits.get("DailyApiRequests").unwrap().remaining, 4937);
        assert_eq!(
            limits
                .get("PermissionSets")
                .unwrap()
                .nested
                .get("CreateCustom")
                .unwrap()
                .max,
            1000
        );
    }

    #[test]
    fn parses_describe_global() {
        let body = json!({
            "encoding": "UTF-8",
            "maxBatchSize": 200,
            "sobjects": [{
                "activateable": false,
                "custom": false,
                "customSetting": false,
                "createable": true,
                "deletable": true,
                "deprecatedAndHidden": false,
                "feedEnabled": true,
                "keyPrefix": "001",
                "label": "Account",
                "labelPlural": "Accounts",
                "layoutable": true,
                "mergeable": true,
                "mruEnabled": true,
                "name": "Account",
                "queryable": true,
                "replicateable": true,
                "retrieveable": true,
                "searchable": true,
                "triggerable": true,
                "undeletable": true,
                "updateable": true,
                "urls": {
                    "sobject": "/services/data/v66.0/sobjects/Account",
                    "describe": "/services/data/v66.0/sobjects/Account/describe",
                    "rowTemplate": "/services/data/v66.0/sobjects/Account/{ID}"
                }
            }]
        })
        .to_string();
        let dg: DescribeGlobal = parse_response_bytes(200, body.as_bytes()).unwrap();
        assert_eq!(dg.encoding, "UTF-8");
        assert_eq!(dg.max_batch_size, 200);
        assert_eq!(dg.sobjects.len(), 1);
        assert_eq!(dg.sobjects[0].name, "Account");
        assert_eq!(dg.sobjects[0].key_prefix.as_deref(), Some("001"));
        assert_eq!(
            dg.sobjects[0].urls.get("describe").map(String::as_str),
            Some("/services/data/v66.0/sobjects/Account/describe")
        );
    }

    #[test]
    fn describe_global_handles_missing_key_prefix() {
        // Some objects (junction objects, certain settings) have no key prefix.
        let body = json!({
            "encoding": "UTF-8",
            "maxBatchSize": 200,
            "sobjects": [{
                "activateable": false, "custom": false, "customSetting": false,
                "createable": false, "deletable": false, "deprecatedAndHidden": false,
                "feedEnabled": false, "label": "Foo", "labelPlural": "Foos",
                "layoutable": false, "mergeable": false, "mruEnabled": false,
                "name": "FooSetting", "queryable": false, "replicateable": false,
                "retrieveable": false, "searchable": false, "triggerable": false,
                "undeletable": false, "updateable": false, "urls": {}
            }]
        })
        .to_string();
        let dg: DescribeGlobal = parse_response_bytes(200, body.as_bytes()).unwrap();
        assert!(dg.sobjects[0].key_prefix.is_none());
    }

    #[test]
    fn parses_search_result() {
        let body = json!({
            "searchRecords": [
                {
                    "attributes": {
                        "type": "Account",
                        "url": "/services/data/v66.0/sobjects/Account/001xx"
                    },
                    "Id": "001xx"
                },
                {
                    "attributes": {
                        "type": "Contact",
                        "url": "/services/data/v66.0/sobjects/Contact/003yy"
                    },
                    "Id": "003yy"
                }
            ]
        })
        .to_string();
        let sr: SearchResult<Value> = parse_response_bytes(200, body.as_bytes()).unwrap();
        assert_eq!(sr.search_records.len(), 2);
        assert_eq!(sr.search_records[0]["attributes"]["type"], "Account");
        assert_eq!(sr.search_records[1]["Id"], "003yy");
        assert!(sr.metadata.is_none());
    }

    #[test]
    fn parses_search_result_with_metadata() {
        let body = json!({
            "searchRecords": [],
            "metadata": {
                "entityMetadata": [
                    {"entityName": "Account", "fieldMetadata": [
                        {"name": "Name", "label": "Account Name"}
                    ]}
                ]
            }
        })
        .to_string();
        let sr: SearchResult<Value> = parse_response_bytes(200, body.as_bytes()).unwrap();
        assert!(sr.search_records.is_empty());
        let md = sr.metadata.expect("metadata present");
        assert!(md["entityMetadata"].is_array());
    }

    #[test]
    fn parses_empty_search_result() {
        // No hits at all — searchRecords absent or empty.
        let body = r#"{"searchRecords": []}"#;
        let sr: SearchResult<Value> = parse_response_bytes(200, body.as_bytes()).unwrap();
        assert!(sr.search_records.is_empty());
    }

    #[test]
    fn parses_batch_response_with_mixed_subresults() {
        // Mirrors the documented example: one PATCH (204 → null result)
        // followed by one GET (200 → record body).
        let body = json!({
            "hasErrors": false,
            "results": [
                {"statusCode": 204, "result": null},
                {"statusCode": 200, "result": {
                    "attributes": {"type": "Account"},
                    "Id": "001D000000K0fXOIAZ",
                    "Name": "NewName"
                }}
            ]
        })
        .to_string();
        let resp: BatchResponse = parse_response_bytes(200, body.as_bytes()).unwrap();
        assert!(!resp.has_errors);
        assert_eq!(resp.results.len(), 2);
        assert!(resp.results[0].is_success());
        assert_eq!(resp.results[0].status_code, 204);
        assert!(resp.results[0].result.is_null());
        assert!(resp.results[1].is_success());
        assert_eq!(resp.results[1].result["Name"], "NewName");
    }

    #[test]
    fn parses_batch_response_with_subrequest_failure() {
        // hasErrors=true and one of the results carries a Salesforce error
        // array as its body. The transport call still returns 200 — only
        // by inspecting the subresult does the caller learn it failed.
        let body = json!({
            "hasErrors": true,
            "results": [
                {"statusCode": 200, "result": {"Id": "001"}},
                {"statusCode": 404, "result": [
                    {"message": "Provided external ID field does not exist or is not accessible: bogus__c",
                     "errorCode": "NOT_FOUND"}
                ]}
            ]
        })
        .to_string();
        let resp: BatchResponse = parse_response_bytes(200, body.as_bytes()).unwrap();
        assert!(resp.has_errors);
        assert!(resp.results[0].is_success());
        assert!(!resp.results[1].is_success());
        assert_eq!(resp.results[1].status_code, 404);
        assert_eq!(resp.results[1].result[0]["errorCode"], "NOT_FOUND");
    }

    #[test]
    fn parses_batch_response_with_default_results_when_absent() {
        // Defensive: schema always returns `results`, but our default keeps
        // us from panicking if a future version omits it.
        let body = r#"{"hasErrors": false}"#;
        let resp: BatchResponse = parse_response_bytes(200, body.as_bytes()).unwrap();
        assert!(resp.results.is_empty());
    }

    #[test]
    fn parses_bulk_ingest_job_response() {
        // Mirrors the documented create-job response.
        let body = json!({
            "id": "750xx0000004C92AAE",
            "operation": "insert",
            "object": "Account",
            "createdById": "005xx000001IECDAA4",
            "createdDate": "2018-12-10T17:50:19.000+0000",
            "systemModstamp": "2018-12-10T17:51:27.000+0000",
            "state": "Open",
            "concurrencyMode": "Parallel",
            "contentType": "CSV",
            "apiVersion": 60.0,
            "contentUrl": "/services/data/v66.0/jobs/ingest/750xx0000004C92AAE/batches",
            "lineEnding": "LF",
            "columnDelimiter": "COMMA",
            "jobType": "V2Ingest"
        })
        .to_string();
        let job: BulkIngestJob = parse_response_bytes(200, body.as_bytes()).unwrap();
        assert_eq!(job.id, "750xx0000004C92AAE");
        assert_eq!(job.operation, BulkOperation::Insert);
        assert_eq!(job.state, BulkJobState::Open);
        assert_eq!(job.line_ending, BulkLineEnding::LF);
        assert_eq!(job.column_delimiter, BulkColumnDelimiter::Comma);
        assert!(job.number_records_processed.is_none());
    }

    #[test]
    fn parses_bulk_ingest_job_with_consent_import_operation() {
        // SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_asynch.meta/api_asynch/create_job.htm
        // operation/OperationEnum lists `consentImport` ("Consent ingest.
        // Doesn't require the object property."), and the same page's
        // `object` row says consent ingest isn't backed by an object type.
        // Field set otherwise mirrors the Get Job Info example.
        let body = json!({
            "id": "7506g00000DhRA2AAN",
            "operation": "consentImport",
            "object": "",
            "createdById": "0056g000005HQPyAAO",
            "createdDate": "2018-12-18T22:51:36.000+0000",
            "systemModstamp": "2018-12-18T22:51:58.000+0000",
            "state": "Open",
            "concurrencyMode": "Parallel",
            "contentType": "CSV",
            "apiVersion": 67.0,
            "jobType": "V2Ingest",
            "contentUrl": "services/data/v67.0/jobs/ingest/7506g00000DhRA2AAN/batches",
            "lineEnding": "LF",
            "columnDelimiter": "COMMA"
        })
        .to_string();
        let job: BulkIngestJob = parse_response_bytes(200, body.as_bytes()).unwrap();
        assert_eq!(job.operation, BulkOperation::ConsentImport);
        assert_eq!(job.object, "");
    }

    #[test]
    fn parses_bulk_job_state_change_with_refresh_operation() {
        // SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_asynch.meta/api_asynch/create_job.htm
        // operation/OperationEnum lists `refresh` ("Marketing Object ingest
        // only."). Envelope mirrors the documented state-change shape.
        let body = json!({
            "id": "750R0000000zxwzIAA",
            "operation": "refresh",
            "object": "MarketingObject__dlm",
            "createdById": "005R0000000GiwjIAC",
            "createdDate": "2018-12-10T17:50:19.000+0000",
            "systemModstamp": "2018-12-10T17:51:27.000+0000",
            "state": "UploadComplete",
            "concurrencyMode": "Parallel",
            "contentType": "CSV",
            "apiVersion": 46.0
        })
        .to_string();
        let job: BulkJobStateChange = parse_response_bytes(200, body.as_bytes()).unwrap();
        assert_eq!(job.operation, BulkOperation::Refresh);
        assert_eq!(job.state, BulkJobState::UploadComplete);
    }

    #[test]
    fn unnamed_bulk_operation_deserializes_without_sinking_the_envelope() {
        // An operation Salesforce adds later must not cost the caller the
        // rest of the job envelope.
        let body = json!({
            "id": "750R0000000zxwzIAA",
            "operation": "someFutureOperation",
            "object": "Account",
            "createdById": "005R0000000GiwjIAC",
            "createdDate": "2018-12-10T17:50:19.000+0000",
            "systemModstamp": "2018-12-10T17:51:27.000+0000",
            "state": "JobComplete",
            "concurrencyMode": "Parallel",
            "contentType": "CSV",
            "apiVersion": 46.0
        })
        .to_string();
        let job: BulkJobStateChange = parse_response_bytes(200, body.as_bytes()).unwrap();
        assert_eq!(job.operation, BulkOperation::Unknown);
        assert_eq!(job.state, BulkJobState::JobComplete);
    }

    #[test]
    fn bulk_operation_serializes_to_the_documented_wire_names() {
        // SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_asynch.meta/api_asynch/create_job.htm
        for (op, wire) in [
            (BulkOperation::Insert, "insert"),
            (BulkOperation::Delete, "delete"),
            (BulkOperation::HardDelete, "hardDelete"),
            (BulkOperation::Update, "update"),
            (BulkOperation::Upsert, "upsert"),
            (BulkOperation::Refresh, "refresh"),
            (BulkOperation::ConsentImport, "consentImport"),
        ] {
            assert_eq!(serde_json::to_value(op).unwrap(), json!(wire));
        }
    }

    #[test]
    fn parses_bulk_ingest_job_complete_with_metrics() {
        // After processing, Salesforce populates the timing/count fields.
        let body = json!({
            "id": "750xx",
            "operation": "upsert",
            "object": "Account",
            "externalIdFieldName": "External_Id__c",
            "createdById": "005xx",
            "createdDate": "2024-01-01T00:00:00.000+0000",
            "systemModstamp": "2024-01-01T00:00:01.000+0000",
            "state": "JobComplete",
            "concurrencyMode": "Parallel",
            "contentType": "CSV",
            "apiVersion": 60.0,
            "lineEnding": "CRLF",
            "columnDelimiter": "TAB",
            "jobType": "V2Ingest",
            "numberRecordsProcessed": 1000,
            "numberRecordsFailed": 5,
            "retries": 0,
            "totalProcessingTime": 2349,
            "apiActiveProcessingTime": 1500,
            "apexProcessingTime": 0
        })
        .to_string();
        let job: BulkIngestJob = parse_response_bytes(200, body.as_bytes()).unwrap();
        assert_eq!(job.operation, BulkOperation::Upsert);
        assert_eq!(job.state, BulkJobState::JobComplete);
        assert_eq!(job.line_ending, BulkLineEnding::CRLF);
        assert_eq!(job.column_delimiter, BulkColumnDelimiter::Tab);
        assert_eq!(
            job.external_id_field_name.as_deref(),
            Some("External_Id__c")
        );
        assert_eq!(job.number_records_processed, Some(1000));
        assert_eq!(job.number_records_failed, Some(5));
        assert!(job.error_message.is_none());
    }

    #[test]
    fn parses_bulk_ingest_job_failed_with_error_message() {
        // Verifies the errorMessage field documented in the Get Ingest
        // Job page surfaces correctly. Failed ingest jobs carry an
        // operator-readable explanation here.
        let body = json!({
            "id": "750xx",
            "operation": "insert",
            "object": "Account",
            "createdById": "005xx",
            "createdDate": "2024-01-01T00:00:00.000+0000",
            "systemModstamp": "2024-01-01T00:00:01.000+0000",
            "state": "Failed",
            "concurrencyMode": "Parallel",
            "contentType": "CSV",
            "apiVersion": 60.0,
            "lineEnding": "LF",
            "columnDelimiter": "COMMA",
            "jobType": "V2Ingest",
            "errorMessage": "InvalidJobState : Aborted by user"
        })
        .to_string();
        let job: BulkIngestJob = parse_response_bytes(200, body.as_bytes()).unwrap();
        assert_eq!(job.state, BulkJobState::Failed);
        assert_eq!(
            job.error_message.as_deref(),
            Some("InvalidJobState : Aborted by user")
        );
    }

    #[test]
    fn parses_bulk_job_state_change_from_documented_query_abort_example() {
        // Verbatim example response from the api_asynch query_abort_job
        // doc. State-transition PATCH responses omit `jobType`,
        // `lineEnding`, and `columnDelimiter`.
        let body = json!({
            "id": "750R000000146UvIAI",
            "operation": "query",
            "object": "Account",
            "createdById": "005R0000000GiwjIAC",
            "createdDate": "2018-12-18T20:51:39.000+0000",
            "systemModstamp": "2018-12-18T20:51:41.000+0000",
            "state": "Aborted",
            "concurrencyMode": "Parallel",
            "contentType": "CSV",
            "apiVersion": 46.0
        })
        .to_string();
        let job: BulkJobStateChange = parse_response_bytes(200, body.as_bytes()).unwrap();
        assert_eq!(job.id, "750R000000146UvIAI");
        assert_eq!(job.operation, BulkOperation::Query);
        assert_eq!(job.state, BulkJobState::Aborted);
        assert_eq!(job.content_type, "CSV");
        assert!(job.external_id_field_name.is_none());
        assert!(job.assignment_rule_id.is_none());
    }

    #[test]
    fn parses_bulk_job_state_change_from_live_ingest_close() {
        // Captured from a live PATCH /jobs/ingest/{id} close response
        // (API v66.0). Same partial shape as the query abort example —
        // the ingest close_job/abort_job doc pages reuse the generic
        // job-info field table, but the wire omits the formatting
        // fields and `jobType`.
        let body = json!({
            "id": "7509H000003sGVwQAM",
            "object": "Account",
            "operation": "update",
            "state": "UploadComplete",
            "apiVersion": 66.0,
            "concurrencyMode": "Parallel",
            "contentType": "CSV",
            "createdById": "0059H000009Bzb6QAC",
            "createdDate": "2026-06-06T18:14:41.000+0000",
            "systemModstamp": "2026-06-06T18:14:41.000+0000"
        })
        .to_string();
        let job: BulkJobStateChange = parse_response_bytes(200, body.as_bytes()).unwrap();
        assert_eq!(job.id, "7509H000003sGVwQAM");
        assert_eq!(job.operation, BulkOperation::Update);
        assert_eq!(job.state, BulkJobState::UploadComplete);
    }

    #[test]
    fn parses_bulk_query_job_response() {
        // Mirrors the GET-job example from the api_asynch
        // query_get_one_job doc: post-execution fields populated, no
        // `query` field (Salesforce never echoes the SOQL back).
        let body = json!({
            "id": "750xx",
            "operation": "queryAll",
            "state": "JobComplete",
            "object": "Account",
            "createdById": "005xx",
            "createdDate": "2024-01-01T00:00:00.000+0000",
            "systemModstamp": "2024-01-01T00:00:01.000+0000",
            "concurrencyMode": "Parallel",
            "contentType": "CSV",
            "apiVersion": 60.0,
            "lineEnding": "LF",
            "columnDelimiter": "COMMA",
            "jobType": "V2Query",
            "numberRecordsProcessed": 5000,
            "retries": 0,
            "totalProcessingTime": 8000,
            "isPkChunkingSupported": true
        })
        .to_string();
        let job: BulkQueryJob = parse_response_bytes(200, body.as_bytes()).unwrap();
        assert_eq!(job.operation, BulkOperation::QueryAll);
        assert_eq!(job.state, BulkJobState::JobComplete);
        assert_eq!(job.object, "Account");
        assert_eq!(job.job_type.as_deref(), Some("V2Query"));
        assert_eq!(job.is_pk_chunking_supported, Some(true));
        assert!(job.error_message.is_none());
    }

    #[test]
    fn parses_bulk_query_job_create_response_without_jobtype() {
        // Mirrors the CREATE-job example from query_create_job doc:
        // `jobType`, `numberRecordsProcessed`, `retries`, etc. are all
        // absent until the GET endpoint. Critical regression test —
        // our previous struct required `jobType` and would have failed
        // here.
        let body = json!({
            "id": "750xx",
            "operation": "query",
            "object": "Account",
            "createdById": "005xx",
            "createdDate": "2024-01-01T00:00:00.000+0000",
            "systemModstamp": "2024-01-01T00:00:00.000+0000",
            "state": "UploadComplete",
            "concurrencyMode": "Parallel",
            "contentType": "CSV",
            "apiVersion": 60.0,
            "lineEnding": "LF",
            "columnDelimiter": "COMMA"
        })
        .to_string();
        let job: BulkQueryJob = parse_response_bytes(200, body.as_bytes()).unwrap();
        assert_eq!(job.state, BulkJobState::UploadComplete);
        assert!(job.job_type.is_none());
        assert!(job.number_records_processed.is_none());
        assert!(job.is_pk_chunking_supported.is_none());
    }

    #[test]
    fn parses_bulk_query_job_failed_with_error_message() {
        // Envelope fields mirror the GET-job example at
        // SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_asynch.meta/api_asynch/query_get_one_job.htm
        // `errorMessage` is NOT in that page's response parameters or its
        // examples — see the provenance note on the field. This pins the
        // optionality, not a documented shape.
        let body = json!({
            "id": "750xx",
            "operation": "query",
            "state": "Failed",
            "object": "Account",
            "createdById": "005xx",
            "createdDate": "2024-01-01T00:00:00.000+0000",
            "systemModstamp": "2024-01-01T00:00:01.000+0000",
            "concurrencyMode": "Parallel",
            "contentType": "CSV",
            "apiVersion": 60.0,
            "lineEnding": "LF",
            "columnDelimiter": "COMMA",
            "jobType": "V2Query",
            "errorMessage": "MALFORMED_QUERY: unexpected token"
        })
        .to_string();
        let job: BulkQueryJob = parse_response_bytes(200, body.as_bytes()).unwrap();
        assert_eq!(job.state, BulkJobState::Failed);
        assert_eq!(
            job.error_message.as_deref(),
            Some("MALFORMED_QUERY: unexpected token")
        );
    }

    #[test]
    fn bulk_query_job_without_error_message_deserializes() {
        // SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_asynch.meta/api_asynch/query_get_one_job.htm
        // The documented example response carries no `errorMessage`.
        let body = json!({
            "id": "750R0000000zxikIAA",
            "operation": "query",
            "object": "Account",
            "createdById": "005R0000000GiwjIAC",
            "createdDate": "2018-12-18T22:51:36.000+0000",
            "systemModstamp": "2018-12-18T22:51:58.000+0000",
            "state": "JobComplete",
            "concurrencyMode": "Parallel",
            "contentType": "CSV",
            "apiVersion": 46.0,
            "jobType": "V2Query",
            "lineEnding": "LF",
            "columnDelimiter": "COMMA",
            "numberRecordsProcessed": 740003,
            "retries": 0,
            "totalProcessingTime": 21046,
            "isPkChunkingSupported": true
        })
        .to_string();
        let job: BulkQueryJob = parse_response_bytes(200, body.as_bytes()).unwrap();
        assert!(job.error_message.is_none());
    }

    #[test]
    fn parses_composite_response_with_per_subrequest_results() {
        // Documented chain: POST account, then GET it back, then PATCH a
        // related record using @{ref.id} binding. Each subresponse echoes
        // its referenceId and carries headers/status from the inner call.
        let body = json!({
            "compositeResponse": [
                {
                    "body": {"id": "001RM000003oCprYAE", "success": true, "errors": []},
                    "httpHeaders": {"Location": "/services/data/v66.0/sobjects/Account/001RM000003oCprYAE"},
                    "httpStatusCode": 201,
                    "referenceId": "NewAccount"
                },
                {
                    "body": {"attributes": {"type": "Account"}, "Id": "001RM000003oCprYAE", "Name": "Acme"},
                    "httpHeaders": {},
                    "httpStatusCode": 200,
                    "referenceId": "AccountInfo"
                },
                {
                    "body": null,
                    "httpHeaders": {},
                    "httpStatusCode": 204,
                    "referenceId": "ContactPatch"
                }
            ]
        })
        .to_string();
        let resp: CompositeResponse = parse_response_bytes(200, body.as_bytes()).unwrap();
        assert_eq!(resp.composite_response.len(), 3);
        assert!(resp.composite_response.iter().all(|r| r.is_success()));
        assert_eq!(resp.composite_response[0].reference_id, "NewAccount");
        assert_eq!(
            resp.composite_response[0]
                .http_headers
                .get("Location")
                .and_then(|v| v.to_str().ok()),
            Some("/services/data/v66.0/sobjects/Account/001RM000003oCprYAE")
        );
        assert_eq!(resp.composite_response[1].body["Name"], "Acme");
        assert!(resp.composite_response[2].body.is_null());
    }

    #[test]
    fn composite_subresponse_header_lookup_is_case_insensitive() {
        // The wire shape uses "Location" (mixed case). HeaderMap's
        // case-insensitive lookup means callers don't have to match
        // Salesforce's casing exactly.
        let body = json!({
            "compositeResponse": [{
                "body": {"id": "001xx", "success": true, "errors": []},
                "httpHeaders": {"Location": "/services/data/v66.0/sobjects/Account/001xx"},
                "httpStatusCode": 201,
                "referenceId": "x"
            }]
        })
        .to_string();
        let resp: CompositeResponse = parse_response_bytes(200, body.as_bytes()).unwrap();
        let headers = &resp.composite_response[0].http_headers;
        // All three casings reach the same header value.
        assert!(headers.get("Location").is_some());
        assert!(headers.get("location").is_some());
        assert!(headers.get("LOCATION").is_some());
        assert_eq!(
            headers.get("location").and_then(|v| v.to_str().ok()),
            Some("/services/data/v66.0/sobjects/Account/001xx")
        );
    }

    #[test]
    fn parses_composite_subresponse_failure_body() {
        // Sub-request failure surfaces via httpStatusCode + an error array
        // body — same as composite/batch's per-subrequest failure path.
        let body = json!({
            "compositeResponse": [{
                "body": [{
                    "message": "The requested resource does not exist",
                    "errorCode": "NOT_FOUND"
                }],
                "httpHeaders": {},
                "httpStatusCode": 404,
                "referenceId": "Lookup"
            }]
        })
        .to_string();
        let resp: CompositeResponse = parse_response_bytes(200, body.as_bytes()).unwrap();
        let sub = &resp.composite_response[0];
        assert!(!sub.is_success());
        assert_eq!(sub.http_status_code, 404);
        assert_eq!(sub.body[0]["errorCode"], "NOT_FOUND");
    }

    #[test]
    fn parses_composite_response_with_default_empty_when_absent() {
        // Defensive: schema always includes compositeResponse, but empty
        // default keeps us from panicking on a hypothetical malformed
        // response. Mirrors BatchResponse / CompositeTreeResponse handling.
        let body = r#"{}"#;
        let resp: CompositeResponse = parse_response_bytes(200, body.as_bytes()).unwrap();
        assert!(resp.composite_response.is_empty());
    }

    #[test]
    fn parses_composite_tree_success_response() {
        // From the documented success example.
        let body = json!({
            "hasErrors": false,
            "results": [
                {"referenceId": "ref1", "id": "001D000000K0fXOIAZ"},
                {"referenceId": "ref4", "id": "001D000000K0fXPIAZ"},
                {"referenceId": "ref2", "id": "003D000000QV9n2IAD"},
                {"referenceId": "ref3", "id": "003D000000QV9n3IAD"}
            ]
        })
        .to_string();
        let resp: CompositeTreeResponse = parse_response_bytes(200, body.as_bytes()).unwrap();
        assert!(!resp.has_errors);
        assert_eq!(resp.results.len(), 4);
        assert!(resp.results.iter().all(CompositeTreeResult::is_success));
        assert_eq!(resp.results[0].reference_id, "ref1");
        assert_eq!(resp.results[0].id.as_deref(), Some("001D000000K0fXOIAZ"));
        assert!(resp.results[0].errors.is_none());
    }

    #[test]
    fn parses_composite_tree_failure_response() {
        // From the documented failure example: only the failing referenceId
        // appears, with `errors` populated and `id` absent.
        let body = json!({
            "hasErrors": true,
            "results": [{
                "referenceId": "ref2",
                "errors": [{
                    "statusCode": "INVALID_EMAIL_ADDRESS",
                    "message": "Email: invalid email address: 123",
                    "fields": ["Email"]
                }]
            }]
        })
        .to_string();
        let resp: CompositeTreeResponse = parse_response_bytes(200, body.as_bytes()).unwrap();
        assert!(resp.has_errors);
        assert_eq!(resp.results.len(), 1);
        let result = &resp.results[0];
        assert!(!result.is_success());
        assert_eq!(result.reference_id, "ref2");
        assert!(result.id.is_none());
        let errors = result.errors.as_ref().unwrap();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].status_code, "INVALID_EMAIL_ADDRESS");
        assert_eq!(errors[0].fields, vec!["Email".to_string()]);
    }

    #[test]
    fn parses_composite_tree_error_without_fields() {
        // Some statusCodes (e.g. row-lock contention) carry no `fields` key.
        // Default-empty Vec lets us deserialize either shape.
        let body = json!({
            "hasErrors": true,
            "results": [{
                "referenceId": "ref1",
                "errors": [{
                    "statusCode": "UNABLE_TO_LOCK_ROW",
                    "message": "unable to obtain exclusive access"
                }]
            }]
        })
        .to_string();
        let resp: CompositeTreeResponse = parse_response_bytes(200, body.as_bytes()).unwrap();
        let errors = resp.results[0].errors.as_ref().unwrap();
        assert!(errors[0].fields.is_empty());
    }

    #[test]
    fn parses_sobject_create_result() {
        let body = r#"{"id":"001xx0000000001","success":true,"errors":[]}"#;
        let parsed: SObjectCreateResult = parse_response_bytes(201, body.as_bytes()).unwrap();
        assert_eq!(parsed.id, "001xx0000000001");
        assert!(parsed.success);
        assert!(parsed.errors.is_empty());
        assert!(parsed.created.is_none());
    }

    #[test]
    fn bulk_query_results_debug_elides_the_csv_body() {
        let results = BulkQueryResults {
            csv: bytes::Bytes::from_static(b"Id,Name\n001xx,Acme Corp\n"),
            locator: Some("MTAwMDA".into()),
            number_of_records: Some(1),
        };
        let rendered = format!("{results:?}");
        assert!(!rendered.contains("Acme Corp"), "leaked body: {rendered}");
        assert!(rendered.contains("csv_len: 24"), "got {rendered}");
        assert!(rendered.contains("MTAwMDA"), "got {rendered}");
    }

    #[test]
    fn limit_info_parses_well_formed_header() {
        let info = LimitInfo::parse("api-usage=42/15000").unwrap();
        assert_eq!(info.used, 42);
        assert_eq!(info.allowed, 15000);
        assert_eq!(info.remaining(), 14958);
        assert_eq!(info.bursts, None);
    }

    #[test]
    fn limit_info_parses_documented_multi_directive_header() {
        // SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/headers_api_usage.htm
        // Example: Sforce-Limit-Info: api-usage=10018/100000; api-bursts=1/750
        let info = LimitInfo::parse("api-usage=10018/100000; api-bursts=1/750").unwrap();
        assert_eq!(info.used, 10018);
        assert_eq!(info.allowed, 100000);
        assert_eq!(info.bursts, Some((1, 750)));

        // The same page's second example carries only the api-usage
        // directive.
        let info = LimitInfo::parse("api-usage=10018/100000").unwrap();
        assert_eq!(info.used, 10018);
        assert_eq!(info.allowed, 100000);
        assert_eq!(info.bursts, None);
    }

    #[test]
    fn limit_info_ignores_unknown_directives_and_directive_order() {
        let info = LimitInfo::parse("api-bursts=1/750; api-usage=10018/100000").unwrap();
        assert_eq!(info.used, 10018);
        assert_eq!(info.bursts, Some((1, 750)));

        // A directive this SDK doesn't model must not sink the parse.
        let info = LimitInfo::parse("some-future-key=1/2; api-usage=7/100").unwrap();
        assert_eq!(info.used, 7);
        assert_eq!(info.allowed, 100);
        assert_eq!(info.bursts, None);
    }

    #[test]
    fn limit_info_parses_comma_folded_directives() {
        // Repeated headers folded into one value by an intermediary.
        let info = LimitInfo::parse("api-usage=10018/100000, api-bursts=1/750").unwrap();
        assert_eq!(info.used, 10018);
        assert_eq!(info.bursts, Some((1, 750)));
    }

    #[test]
    fn limit_info_tolerates_whitespace_around_value() {
        let info = LimitInfo::parse("api-usage= 42 / 15000 ").unwrap();
        assert_eq!(info.used, 42);
        assert_eq!(info.allowed, 15000);
    }

    #[test]
    fn limit_info_returns_none_on_malformed_input() {
        // Wrong key.
        assert_eq!(LimitInfo::parse("foo=1/2"), None);
        // Missing slash separator.
        assert_eq!(LimitInfo::parse("api-usage=10"), None);
        // Non-numeric values.
        assert_eq!(LimitInfo::parse("api-usage=ten/fifteen"), None);
        // Empty.
        assert_eq!(LimitInfo::parse(""), None);
        // Negative — not parseable as u32.
        assert_eq!(LimitInfo::parse("api-usage=-5/100"), None);
        // A well-formed burst directive alone carries no usage counts.
        assert_eq!(LimitInfo::parse("api-bursts=1/750"), None);
    }

    #[test]
    fn limit_info_remaining_saturates() {
        // If somehow `used > allowed`, `remaining()` saturates rather
        // than overflowing (u32 underflow).
        let info = LimitInfo {
            used: 100,
            allowed: 50,
            bursts: None,
        };
        assert_eq!(info.remaining(), 0);
    }
}

/// Property tests for the response parser. The load-bearing invariant
/// is that `parse_response_bytes` never panics on arbitrary inputs —
/// pairs naturally with the crate-wide `unwrap_used = "deny"` lint.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::Value;

    proptest! {
        /// For any (status, bytes) pair, parsing as `Value` returns a
        /// `Result` — it never panics, no matter how malformed the
        /// body or how unexpected the status code.
        #[test]
        fn parse_response_bytes_never_panics_for_value(
            status in 100u16..600,
            bytes in proptest::collection::vec(any::<u8>(), 0..256),
        ) {
            // Drive the parser. The result variant doesn't matter; the
            // property is that *some* result is produced rather than a
            // panic.
            let _: Result<Value, _> = parse_response_bytes(status, &bytes);
        }

        /// Status codes outside 2xx always produce `Err(Api{..})` (or
        /// `Err` of some sort) — never a successful deserialization,
        /// regardless of body content. This is what callers rely on
        /// to know "I got an error" from the Result discriminant alone.
        #[test]
        fn non_2xx_status_always_returns_err(
            status in (100u16..200).prop_union(300u16..600),
            bytes in proptest::collection::vec(any::<u8>(), 0..256),
        ) {
            let result: Result<Value, _> = parse_response_bytes(status, &bytes);
            prop_assert!(result.is_err(), "status {status} must yield Err");
        }
    }
}
