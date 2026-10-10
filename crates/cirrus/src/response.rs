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
//! Salesforce documents one error shape for every REST endpoint on non-2xx:
//! a JSON array of `{message, errorCode, fields}` ([Status Codes and Error
//! Responses]). A few per-operation pages (Upsert's "incorrect external ID
//! field", the sObject blob insert's "example error response") print the
//! same object without the array around it, so the parser also accepts a
//! bare object as a one-entry array. Either way [`parse_response_bytes`]
//! checks the status code first and only attempts to deserialize into the
//! caller's `R` on success. Callers never need to model error shapes in
//! their response types.
//!
//! [Status Codes and Error Responses]: https://developer.salesforce.com/docs/platform/api-rest/guide/errorcodes.html

use crate::error::{CirrusError, CirrusResult, SalesforceError};
use bytes::Bytes;
use reqwest::header::HeaderMap;
use serde::Deserialize;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::collections::HashMap;

/// Envelope returned by SOQL queries (`/query`, `/queryAll`, `/query/{locator}`).
///
/// Generic over the record type `R` — the SDK never assumes a record shape.
/// Use `serde_json::Value` for ad-hoc, or supply a typed struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
/// `attributes` object with the record's sObject `type` and self `url`,
/// which is how hits from a multi-object `RETURNING` clause are told
/// apart. Model it as its own field — `attributes: serde_json::Value`, or
/// a small struct with `type` (renamed, since it is a keyword) and `url`
/// — rather than through `#[serde(flatten)]`: a flattened map collects
/// every key the struct does not name, so the type would land at
/// `attributes["attributes"]["type"]`. Keep `#[serde(flatten)] rest:
/// HashMap<String, Value>` for a catch-all of the other fields.
///
/// ```
/// use serde::Deserialize;
///
/// #[derive(Deserialize)]
/// struct Attributes {
///     #[serde(rename = "type")]
///     sobject_type: String,
///     url: String,
/// }
///
/// #[derive(Deserialize)]
/// struct Hit {
///     attributes: Attributes,
///     #[serde(rename = "Id")]
///     id: String,
/// }
///
/// let hit: Hit = serde_json::from_value(serde_json::json!({
///     "attributes": {"type": "Account", "url": "/services/data/v66.0/sobjects/Account/001xx"},
///     "Id": "001xx"
/// })).unwrap();
/// assert_eq!(hit.attributes.sobject_type, "Account");
/// ```
///
/// `metadata` is populated only when the request asks for field labels:
/// `WITH METADATA='LABELS'` at the end of the SOSL passed to
/// [`Cirrus::search`](crate::Cirrus::search), or `"metadata": "LABELS"`
/// in the body of
/// [`Cirrus::parameterized_search`](crate::Cirrus::parameterized_search).
/// It is surfaced as raw JSON because its shape varies across versions.
///
/// The `searchRecords` object is the shape Salesforce has documented
/// since API 37.0; 31.0 through 36.0 answered a bare array of hits, a
/// version range [`CirrusBuilder::build`](crate::CirrusBuilder::build)
/// refuses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult<R> {
    /// Hit records, in Salesforce-defined relevance order.
    #[serde(rename = "searchRecords", default = "Vec::new")]
    pub search_records: Vec<R>,
    /// Field-label metadata, present only when the request asked for it.
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

/// Result of a single-record create/upsert via REST sObjects endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// existing one. Absent on plain creates. Salesforce added the field
    /// in API 46.0, the oldest version
    /// [`SObjectHandler::upsert`](crate::handlers::sobjects::SObjectHandler::upsert)
    /// runs on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<bool>,
}

/// One limit entry from `GET /services/data/vXX.X/limits`.
///
/// Most limits are flat `{Max, Remaining}` pairs. A few (notably
/// `PermissionSets`) embed sub-limits with the same shape — those are
/// captured in [`Limit::nested`].
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
//
// Wire-shape provenance: the REST Describe Global page (`dome_describeGlobal`)
// shows these keys in its example response but defines none of them. The
// flag descriptions follow the SOAP API DescribeGlobalSObjectResult table,
// which words each one in terms of the SOAP call it gates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SObjectMetadata {
    /// Reserved for future use.
    pub activateable: bool,
    /// Whether records of the object can be created.
    pub createable: bool,
    /// Whether the object is a custom object.
    pub custom: bool,
    /// Whether the object is a custom setting object.
    #[serde(rename = "customSetting")]
    pub custom_setting: bool,
    /// Whether records of the object can be deleted.
    pub deletable: bool,
    /// Reserved for future use.
    #[serde(rename = "deprecatedAndHidden")]
    pub deprecated_and_hidden: bool,
    /// Whether Chatter feeds are enabled for the object.
    #[serde(rename = "feedEnabled")]
    pub feed_enabled: bool,
    /// Three-character record-ID prefix (e.g. `"001"` for Account). `None`
    /// for objects without a stable prefix.
    #[serde(rename = "keyPrefix", default)]
    pub key_prefix: Option<String>,
    /// Label of the object: the text of a tab or field renamed in the
    /// user interface, if applicable, or the object name if not.
    pub label: String,
    /// Plural form of the label, for example `Accounts`.
    #[serde(rename = "labelPlural")]
    pub label_plural: String,
    /// Whether the object supports describing its layouts
    /// (`describeLayout()` in the SOAP API).
    pub layoutable: bool,
    /// Whether records of the object can be merged with other records
    /// of its type. `true` for leads, contacts and accounts.
    pub mergeable: bool,
    /// Whether Most Recently Used (MRU) list functionality is enabled
    /// for the object.
    #[serde(rename = "mruEnabled")]
    pub mru_enabled: bool,
    /// API name of the object, e.g. `"Account"`, `"My_Object__c"`.
    pub name: String,
    /// Whether the object can be queried.
    pub queryable: bool,
    /// Whether the object can be replicated through the `getUpdated()`
    /// and `getDeleted()` calls.
    pub replicateable: bool,
    /// Whether records of the object can be retrieved.
    pub retrieveable: bool,
    /// Whether the object can be searched.
    pub searchable: bool,
    /// Whether the object supports Apex triggers.
    pub triggerable: bool,
    /// Whether records of the object can be undeleted.
    pub undeletable: bool,
    /// Whether records of the object can be updated.
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
///
/// The enum is `#[non_exhaustive]`: it keeps an
/// [`Unknown`](Self::Unknown) fallback because Salesforce adds
/// operations between releases, and a literal promoted from `Unknown`
/// to a named variant has to stay an additive change. Match with a `_`
/// arm:
///
/// ```
/// use cirrus::BulkOperation;
///
/// fn is_query(op: BulkOperation) -> bool {
///     match op {
///         BulkOperation::Query | BulkOperation::QueryAll => true,
///         _ => false,
///     }
/// }
/// assert!(is_query(BulkOperation::QueryAll));
/// ```
///
/// Naming every variant, `Unknown` included, does not compile outside
/// this crate:
///
/// ```compile_fail
/// use cirrus::BulkOperation;
///
/// fn is_query(op: BulkOperation) -> bool {
///     match op {
///         BulkOperation::Query | BulkOperation::QueryAll => true,
///         BulkOperation::Insert
///         | BulkOperation::Update
///         | BulkOperation::Upsert
///         | BulkOperation::Delete
///         | BulkOperation::HardDelete
///         | BulkOperation::Refresh
///         | BulkOperation::ConsentImport
///         | BulkOperation::Unknown => false,
///     }
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum BulkOperation {
    /// Insert new records.
    #[serde(rename = "insert")]
    Insert,
    /// Update existing records.
    #[serde(rename = "update")]
    Update,
    /// Update existing records and insert the rest. Matches on the
    /// job's external ID field, or on the primary key for Marketing
    /// objects.
    #[serde(rename = "upsert")]
    Upsert,
    /// Delete records.
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
    /// Query job: returns data that hasn't been deleted or archived.
    #[serde(rename = "query")]
    Query,
    /// Query job: also returns records deleted by a merge or delete,
    /// and information about archived Task and Event records.
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

impl BulkOperation {
    /// `true` for an operation the ingest endpoint (`/jobs/ingest`)
    /// accepts: `insert`, `update`, `upsert`, `delete`, `hardDelete`,
    /// `refresh` and `consentImport`. [`Unknown`](Self::Unknown) is
    /// neither an ingest nor a query operation.
    ///
    /// [Create a Job](https://developer.salesforce.com/docs/platform/api-asynch/guide/create-job.html)
    pub fn is_ingest(self) -> bool {
        matches!(
            self,
            Self::Insert
                | Self::Update
                | Self::Upsert
                | Self::Delete
                | Self::HardDelete
                | Self::Refresh
                | Self::ConsentImport
        )
    }

    /// `true` for an operation the query endpoint (`/jobs/query`)
    /// accepts: `query` and `queryAll`.
    ///
    /// [Create a Query Job](https://developer.salesforce.com/docs/platform/api-asynch/guide/query-create-job.html)
    pub fn is_query(self) -> bool {
        matches!(self, Self::Query | Self::QueryAll)
    }
}

/// State of a Bulk API 2.0 job.
///
/// Ingest job lifecycle: `Open` → `UploadComplete` → `InProgress` →
/// `JobComplete` / `Failed` / `Aborted`.
///
/// Query job lifecycle: `UploadComplete` → `InProgress` → `JobComplete` /
/// `Failed` / `Aborted` (query jobs skip `Open` since the SOQL is
/// supplied at create time — there's no separate upload step).
///
/// The enum is `#[non_exhaustive]` with an [`Unknown`](Self::Unknown)
/// fallback: a job listing covers every Bulk API job in the org,
/// including Bulk API 1.0 jobs whose states (`Closed`) are not 2.0
/// literals, and a literal promoted from `Unknown` to a named variant
/// has to stay an additive change. Match with a `_` arm, or use
/// [`is_terminal`](Self::is_terminal):
///
/// ```
/// use cirrus::BulkJobState;
///
/// fn still_running(state: BulkJobState) -> bool {
///     match state {
///         BulkJobState::Open | BulkJobState::UploadComplete | BulkJobState::InProgress => true,
///         _ => false,
///     }
/// }
/// assert!(still_running(BulkJobState::InProgress));
/// ```
///
/// Naming every variant, `Unknown` included, does not compile outside
/// this crate:
///
/// ```compile_fail
/// use cirrus::BulkJobState;
///
/// fn still_running(state: BulkJobState) -> bool {
///     match state {
///         BulkJobState::Open | BulkJobState::UploadComplete | BulkJobState::InProgress => true,
///         BulkJobState::JobComplete
///         | BulkJobState::Aborted
///         | BulkJobState::Failed
///         | BulkJobState::Unknown => false,
///     }
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
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
    /// Job failed. For an ingest job this means some records failed,
    /// and rows that were processed successfully stay committed —
    /// Salesforce does not roll them back. Read
    /// [`successful_results`], [`failed_results`], and
    /// [`unprocessed_records`] before resubmitting the same data;
    /// [`BulkIngestJob::error_message`] carries a job-level reason when
    /// there is one. See [Get Job Info].
    ///
    /// [`successful_results`]: crate::handlers::bulk::BulkIngestHandler::successful_results
    /// [`failed_results`]: crate::handlers::bulk::BulkIngestHandler::failed_results
    /// [`unprocessed_records`]: crate::handlers::bulk::BulkIngestHandler::unprocessed_records
    /// [Get Job Info]: https://developer.salesforce.com/docs/atlas.en-us.api_asynch.meta/api_asynch/get_job_info.htm
    Failed,
    /// A state literal this SDK doesn't name: a Bulk API 1.0 job's
    /// `Closed` in a listing, or a state Salesforce adds later. Reading
    /// it as a value keeps the rest of the job, and the rest of a
    /// listing, usable.
    #[serde(other)]
    Unknown,
}

impl BulkJobState {
    /// `true` once Salesforce has stopped processing the job, for any
    /// reason: `JobComplete`, `Failed` or `Aborted`. A poll loop over
    /// [`BulkIngestHandler::get`] or [`BulkQueryHandler::get`] can stop
    /// once this returns `true`.
    ///
    /// [`Unknown`](Self::Unknown) reports `false`: an unrecognized state
    /// can't be assumed finished, so a poller should keep going, bounded
    /// by its own timeout, rather than stop early.
    ///
    /// [`BulkIngestHandler::get`]: crate::handlers::bulk::BulkIngestHandler::get
    /// [`BulkQueryHandler::get`]: crate::handlers::bulk::BulkQueryHandler::get
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::JobComplete | Self::Failed | Self::Aborted)
    }
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
    /// Backquote character (`` ` ``).
    Backquote,
    /// Caret character (`^`).
    Caret,
    /// Comma character (`,`), Salesforce's default delimiter.
    #[default]
    Comma,
    /// Pipe character (`|`).
    Pipe,
    /// Semicolon character (`;`).
    Semicolon,
    /// Tab character.
    Tab,
}

/// Response from `POST /jobs/ingest` and `GET /jobs/ingest/{jobId}`.
///
/// Field availability varies by job state and request kind —
/// `number_records_processed`, `number_records_failed`, and timing
/// fields are populated only after the job reaches `JobComplete` or
/// `Failed`; `content_url` is populated only while the job is in `Open`
/// state; and the create response (`POST`) omits `job_type`, which only
/// the `GET` response carries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkIngestJob {
    /// Unique ID of the job.
    pub id: String,
    /// Processing operation the job runs.
    pub operation: BulkOperation,
    /// Object type the job's data belongs to. Absent for jobs created
    /// with the `consentImport` operation — consent ingest isn't
    /// backed by an object type — and deserializes as an empty string
    /// there rather than failing the envelope. See [Create a Job].
    ///
    /// [Create a Job]: https://developer.salesforce.com/docs/atlas.en-us.api_asynch.meta/api_asynch/create_job.htm
    #[serde(default)]
    pub object: String,
    /// Current state of processing for the job.
    pub state: BulkJobState,
    /// External ID field an upsert job matches on. `None` for the other
    /// operations.
    #[serde(rename = "externalIdFieldName", default)]
    pub external_id_field_name: Option<String>,
    /// Line ending used for the job's CSV data.
    #[serde(rename = "lineEnding")]
    pub line_ending: BulkLineEnding,
    /// Column delimiter used for the job's CSV data.
    #[serde(rename = "columnDelimiter")]
    pub column_delimiter: BulkColumnDelimiter,
    /// Format of the data being processed. Salesforce supports only
    /// `CSV`.
    #[serde(rename = "contentType")]
    pub content_type: String,
    /// Where to PUT the job's CSV, populated while the job is `Open`.
    ///
    /// Salesforce sends this instance-relative and **without** a leading
    /// slash (`services/data/vXX.X/jobs/ingest/{id}/batches`), which the
    /// verb methods on [`crate::Cirrus`] would resolve as a versioned
    /// path and so double the `/services/data/{version}` prefix. Prefer
    /// [`BulkIngestHandler::upload`], which builds the path itself; if
    /// you must use this value directly, prefix it with `/`.
    ///
    /// [`BulkIngestHandler::upload`]: crate::handlers::bulk::BulkIngestHandler::upload
    #[serde(rename = "contentUrl", default)]
    pub content_url: Option<String>,
    /// The wire sends a JSON number (e.g. `60.0`), so this is a float
    /// rather than the `String` used by [`ApiVersion::version`].
    #[serde(rename = "apiVersion")]
    pub api_version: f64,
    /// `"V2Ingest"` on `GET` responses. The create-job response omits
    /// it, so expect `None` from [`BulkIngestHandler::create`] until a
    /// [`get`](crate::handlers::bulk::BulkIngestHandler::get).
    ///
    /// [`BulkIngestHandler::create`]: crate::handlers::bulk::BulkIngestHandler::create
    #[serde(rename = "jobType", default)]
    pub job_type: Option<String>,
    /// For future use: how the job was processed. Salesforce currently
    /// supports only parallel mode.
    #[serde(rename = "concurrencyMode")]
    pub concurrency_mode: String,
    /// ID of the user who created the job.
    #[serde(rename = "createdById")]
    pub created_by_id: String,
    /// When the job was created, as a UTC `dateTime` string.
    #[serde(rename = "createdDate")]
    pub created_date: String,
    /// Date and time in UTC that the Get Job Info reference describes
    /// as when the job finished. Its example nonetheless shows a value
    /// on a job that is still `Open`.
    #[serde(rename = "systemModstamp")]
    pub system_modstamp: String,
    /// ID of the assignment rule to run for a Case or a Lead. Present
    /// only when one was specified at job creation.
    #[serde(rename = "assignmentRuleId", default)]
    pub assignment_rule_id: Option<String>,
    /// Number of records already processed.
    #[serde(rename = "numberRecordsProcessed", default)]
    pub number_records_processed: Option<i64>,
    /// Number of records that were not processed successfully in this
    /// job.
    #[serde(rename = "numberRecordsFailed", default)]
    pub number_records_failed: Option<i64>,
    /// Number of times Salesforce attempted to save the results of an
    /// operation. Repeated attempts indicate a problem such as lock
    /// contention.
    #[serde(default)]
    pub retries: Option<i32>,
    /// Time taken to process the job, in milliseconds.
    #[serde(rename = "totalProcessingTime", default)]
    pub total_processing_time: Option<i64>,
    /// Time taken to actively process the job, in milliseconds.
    /// Includes [`apex_processing_time`](Self::apex_processing_time)
    /// but not the time the job waited to be processed.
    #[serde(rename = "apiActiveProcessingTime", default)]
    pub api_active_processing_time: Option<i64>,
    /// Time taken to process triggers and other processes related to
    /// the job data, in milliseconds. Excludes asynchronous and batch
    /// Apex. `0` when there are no triggers.
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkJobStateChange {
    /// Unique ID of the job.
    pub id: String,
    /// Processing operation the job runs.
    pub operation: BulkOperation,
    /// Object type of the job's data; for a query job, the object being
    /// queried.
    pub object: String,
    /// Current state of processing for the job.
    pub state: BulkJobState,
    /// The wire sends a JSON number (e.g. `60.0`), so this is a float
    /// rather than the `String` used by [`ApiVersion::version`].
    #[serde(rename = "apiVersion")]
    pub api_version: f64,
    /// For future use: how the job is processed. Salesforce currently
    /// supports only parallel mode.
    #[serde(rename = "concurrencyMode")]
    pub concurrency_mode: String,
    /// Format of the job's data. Salesforce supports only `CSV`.
    #[serde(rename = "contentType")]
    pub content_type: String,
    /// ID of the user who created the job.
    #[serde(rename = "createdById")]
    pub created_by_id: String,
    /// When the job was created, as a UTC `dateTime` string.
    #[serde(rename = "createdDate")]
    pub created_date: String,
    /// When the API last updated the job information, as a UTC
    /// `dateTime` string.
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkQueryJob {
    /// Unique ID of the job.
    pub id: String,
    /// The type of query: `query` or `queryAll`.
    pub operation: BulkOperation,
    /// Current state of processing for the job.
    pub state: BulkJobState,
    /// Object the SOQL targets (parsed and surfaced by Salesforce —
    /// not the original SOQL).
    pub object: String,
    /// Line ending used for the job's CSV data, marking the end of a
    /// data row.
    #[serde(rename = "lineEnding")]
    pub line_ending: BulkLineEnding,
    /// Column delimiter used for the job's CSV data.
    #[serde(rename = "columnDelimiter")]
    pub column_delimiter: BulkColumnDelimiter,
    /// Format used for the results. Salesforce currently supports only
    /// `CSV`.
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
    /// Reserved for future use: how the job is processed. Salesforce
    /// currently supports only parallel mode.
    #[serde(rename = "concurrencyMode")]
    pub concurrency_mode: String,
    /// ID of the user who created the job.
    #[serde(rename = "createdById")]
    pub created_by_id: String,
    /// When the job was created, as a UTC `dateTime` string.
    #[serde(rename = "createdDate")]
    pub created_date: String,
    /// When the API last updated the job information, as a UTC
    /// `dateTime` string.
    #[serde(rename = "systemModstamp")]
    pub system_modstamp: String,
    /// Number of records processed in this job. `None` in the CREATE
    /// response.
    #[serde(rename = "numberRecordsProcessed", default)]
    pub number_records_processed: Option<i64>,
    /// Number of times Salesforce attempted to save the results of an
    /// operation. Repeated attempts indicate a problem such as lock
    /// contention.
    #[serde(default)]
    pub retries: Option<i32>,
    /// Time taken to process the job, in milliseconds. `None` in the
    /// CREATE response.
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
/// in subsequent calls to fetch the next page. A page that arrives
/// without the `Sforce-Locator` header never becomes a value of this
/// type; `results` refuses it, so `None` here always means Salesforce
/// sent its documented end marker.
///
/// The [`Debug`] rendering reports the CSV length in place of the body:
/// one page holds up to tens of thousands of exported records, and the
/// cursor fields are the reason to debug-format this type.
#[derive(Clone)]
pub struct BulkQueryResults {
    /// CSV body of this result page.
    pub csv: bytes::Bytes,
    /// Pagination cursor (`Sforce-Locator` response header). `None` when
    /// the job has emitted all rows, which Salesforce signals with the
    /// literal header value `null`.
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

/// Kind of a Bulk job, as a job listing reports it and as the
/// `jobType` filter of [`BulkJobListOptions`] names it.
///
/// The enum is `#[non_exhaustive]` with an [`Unknown`](Self::Unknown)
/// fallback so a kind Salesforce adds later still deserializes; match
/// with a `_` arm.
///
/// [`BulkJobListOptions`]: crate::handlers::bulk::BulkJobListOptions
//
// Wire-shape provenance: get-all-jobs.html lists `BigObjectIngest`,
// `Classic` and `V2Ingest` for the ingest listing; query-get-all-jobs.html
// lists `Classic`, `V2Query` and `V2Ingest` for the query listing. The
// serialized form is the variant name as written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum BulkJobType {
    /// A BigObjects ingest job.
    BigObjectIngest,
    /// A Bulk API 1.0 job, query or ingest.
    Classic,
    /// A Bulk API 2.0 ingest job.
    V2Ingest,
    /// A Bulk API 2.0 query job.
    V2Query,
    /// A job type this SDK doesn't name. Not a filter value: the
    /// listing methods refuse it before any request.
    #[serde(other)]
    Unknown,
}

impl BulkJobType {
    /// The wire literal, as the listing filter sends it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BigObjectIngest => "BigObjectIngest",
            Self::Classic => "Classic",
            Self::V2Ingest => "V2Ingest",
            Self::V2Query => "V2Query",
            Self::Unknown => "Unknown",
        }
    }
}

/// One page of a Bulk job listing, from `GET /jobs/ingest` or
/// `GET /jobs/query`.
///
/// A page holds up to 1,000 jobs. When `done` is `false`, pass
/// [`next_locator`](Self::next_locator) to the next
/// [`list`](crate::handlers::bulk::BulkIngestHandler::list) call; the
/// listing methods guarantee it is present in that case.
///
/// [Get Information About All Ingest Jobs](https://developer.salesforce.com/docs/platform/api-asynch/guide/get-all-jobs.html)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkJobList {
    /// `false` while more pages remain.
    pub done: bool,
    /// The jobs on this page, in no particular order.
    pub records: Vec<BulkJobSummary>,
    /// The URL Salesforce suggests for the next page, carrying its
    /// `queryLocator`. Only the locator is reused: the documented query
    /// listing example names `/jobs/ingest` here, so the path is not
    /// trusted to say which listing it continues.
    #[serde(rename = "nextRecordsUrl", default)]
    pub next_records_url: Option<String>,
}

impl BulkJobList {
    /// The `queryLocator` carried by [`next_records_url`](Self::next_records_url),
    /// for [`BulkJobListOptions::query_locator`]; `None` on the last
    /// page.
    ///
    /// [`BulkJobListOptions::query_locator`]: crate::handlers::bulk::BulkJobListOptions::query_locator
    pub fn next_locator(&self) -> Option<String> {
        self.next_records_url
            .as_deref()
            .and_then(|url| query_value(url, "queryLocator"))
    }
}

/// One job as a listing reports it.
///
/// A listing covers every Bulk API job in the org, so the record is
/// looser than [`BulkIngestJob`] / [`BulkQueryJob`]: a Bulk API 1.0 job
/// has no CSV formatting fields, a content type outside `CSV`, and a
/// [`state`](Self::state) the 2.0 enum reads as
/// [`Unknown`](BulkJobState::Unknown). Fetch a 2.0 job's full record
/// through the handler's `get`.
//
// Wire-shape provenance: the JobInfo table on get-all-jobs.html, and the
// query-get-all-jobs.html example. Both type `apiVersion` as a string
// while the example prints `68.0`, and asynch-api-reference-jobinfo.html
// (the Bulk API 1.0 JobInfo a listing can include) types it as a string
// too, so either form is read.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkJobSummary {
    /// Unique ID of the job.
    pub id: String,
    /// Processing operation the job runs.
    pub operation: BulkOperation,
    /// Object type of the job's data. Empty for a `consentImport` job.
    #[serde(default)]
    pub object: String,
    /// Current state of processing for the job.
    pub state: BulkJobState,
    /// The job's type, including the Bulk API 1.0 and BigObjects kinds
    /// a listing can carry; see [`BulkJobType`]. `None` when the record
    /// omits it.
    #[serde(rename = "jobType", default)]
    pub job_type: Option<BulkJobType>,
    /// API version the job was created in.
    #[serde(rename = "apiVersion", deserialize_with = "api_version_number")]
    pub api_version: f64,
    /// For future use: how the job is processed. Salesforce currently
    /// supports only parallel mode.
    #[serde(rename = "concurrencyMode")]
    pub concurrency_mode: String,
    /// `CSV` for a Bulk API 2.0 job; a Bulk API 1.0 job can report
    /// another format.
    #[serde(rename = "contentType")]
    pub content_type: String,
    /// Where an `Open` ingest job's CSV is uploaded; see
    /// [`BulkIngestJob::content_url`] for its unusual form.
    #[serde(rename = "contentUrl", default)]
    pub content_url: Option<String>,
    /// ID of the user who created the job.
    #[serde(rename = "createdById")]
    pub created_by_id: String,
    /// When the job was created, as a UTC `dateTime` string.
    #[serde(rename = "createdDate")]
    pub created_date: String,
    /// UTC `dateTime` string. The ingest listing describes it as when
    /// the job finished, the query listing as when the API last updated
    /// the job information.
    #[serde(rename = "systemModstamp")]
    pub system_modstamp: String,
    /// Line ending used for the job's CSV data. `None` for a Bulk API
    /// 1.0 job, which has no CSV formatting fields.
    #[serde(rename = "lineEnding", default)]
    pub line_ending: Option<BulkLineEnding>,
    /// Column delimiter used for the job's CSV data. `None` for a Bulk
    /// API 1.0 job, which has no CSV formatting fields.
    #[serde(rename = "columnDelimiter", default)]
    pub column_delimiter: Option<BulkColumnDelimiter>,
}

/// Reads `apiVersion` as the JSON number the examples print or the
/// string the field tables declare.
///
/// Serialization needs no counterpart: the `f64` is written as a JSON
/// number, one of the two forms this reads.
fn api_version_number<'de, D>(deserializer: D) -> Result<f64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Raw {
        Number(f64),
        Text(String),
    }
    match Raw::deserialize(deserializer)? {
        Raw::Number(version) => Ok(version),
        Raw::Text(text) => text.trim().parse().map_err(serde::de::Error::custom),
    }
}

/// One set of parallel result links for a query job, from
/// `GET /jobs/query/{jobId}/resultPages` (API 58.0 and later).
///
/// Each [`BulkResultPage::locator`] is a cursor for
/// [`BulkQueryHandler::results`], and the pages can be fetched
/// concurrently. When `done` is `false`, pass
/// [`next_locator`](Self::next_locator) to the next
/// [`BulkQueryHandler::result_pages`] call; the handler guarantees it is
/// present in that case.
///
/// [`BulkQueryHandler::results`]: crate::handlers::bulk::BulkQueryHandler::results
/// [`BulkQueryHandler::result_pages`]: crate::handlers::bulk::BulkQueryHandler::result_pages
/// [Get Parallel Results for a Query Job](https://developer.salesforce.com/docs/platform/api-asynch/guide/query-get-parallel-job-results.html)
//
// Wire-shape provenance: query-get-parallel-job-results.html. Its
// element table spells the continuation `nextRecordUrl` while its example
// response spells it `nextRecordsUrl`, so both are read.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkResultPages {
    /// Up to five result links.
    #[serde(rename = "resultPages", default)]
    pub result_pages: Vec<BulkResultPage>,
    /// The URL Salesforce suggests for the next set of links, carrying
    /// its `locator`.
    #[serde(rename = "nextRecordsUrl", alias = "nextRecordUrl", default)]
    pub next_records_url: Option<String>,
    /// `false` while more sets of links remain.
    pub done: bool,
}

impl BulkResultPages {
    /// The `locator` carried by [`next_records_url`](Self::next_records_url);
    /// `None` on the last set.
    pub fn next_locator(&self) -> Option<String> {
        self.next_records_url
            .as_deref()
            .and_then(|url| query_value(url, "locator"))
    }
}

/// One result link from [`BulkResultPages`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkResultPage {
    /// The results URL as Salesforce wrote it, with its `locator`.
    #[serde(rename = "resultUrl")]
    pub result_url: String,
}

impl BulkResultPage {
    /// The `locator` carried by [`result_url`](Self::result_url), to pass
    /// to [`BulkQueryHandler::results`].
    ///
    /// [`BulkQueryHandler::results`]: crate::handlers::bulk::BulkQueryHandler::results
    pub fn locator(&self) -> Option<String> {
        query_value(&self.result_url, "locator")
    }
}

/// The decoded, non-empty value of `name` in `url`'s query string.
fn query_value(url: &str, name: &str) -> Option<String> {
    let (_, query) = url.split_once('?')?;
    let query = query.split_once('#').map_or(query, |(query, _)| query);
    url::form_urlencoded::parse(query.as_bytes())
        .find(|(key, value)| key == name && !value.is_empty())
        .map(|(_, value)| value.into_owned())
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventLogFileRecord {
    /// ID of the `EventLogFile` record, the `0AT...` segment of
    /// [`log_file`](Self::log_file).
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
        // `u32::from_str` tolerates a leading `+`, which is not a path
        // segment character the builder accepts; both halves must be
        // bare digits so the two checks agree.
        let digits = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
        if !(digits(major) && digits(minor)) {
            return None;
        }
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
/// subresponse's [`http_status_code`](CompositeSubresponse::http_status_code),
/// or use [`CompositeSubresponse::is_success`] and
/// [`CompositeSubresponse::is_error`]. A conditional request's 304 is a
/// success and a 300 is neither; see those methods. The transactional
/// rollback flag is on the *request* side (`allOrNone`).
///
/// # Rollback under `allOrNone`
///
/// When the request sets `allOrNone: true` and any subrequest fails,
/// Salesforce rolls the whole composite back, so none of it was
/// committed, whatever the other subresponses show. A subresponse for an
/// sObject Collections call can still answer 200 with rows that read
/// `success: true`. Salesforce's [`allOrNone` Parameters in Composite and
/// Collections Requests][allornone] page, on a response of that shape,
/// says: "Even though the response body for sObject Collections request
/// shows `"success" : true` for the creation of the first Account, the
/// fact that the Composite request is rolled back means that the Account
/// creation is rolled back."
///
/// With an outer `allOrNone: true`, then, any
/// [`is_error`](CompositeSubresponse::is_error) subresponse means nothing
/// in the composite was committed. Decide that from the whole response,
/// not entry by entry.
///
/// [allornone]: https://developer.salesforce.com/docs/platform/api-rest/guide/resources-composite-allornone.html
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// `true` when the sub-request did what it was asked: a 2xx, or a 304
    /// Not Modified answering a conditional request. Salesforce's own
    /// composite example sends `If-Modified-Since` on a describe and lists
    /// the resulting 304 in a response it calls successful. A 300 Multiple
    /// Choices — several records matched an external ID — is neither a
    /// success nor an [`error`](Self::is_error); inspect `body`.
    ///
    /// This describes the subrequest alone. When the composite request set
    /// `allOrNone: true`, a successful subresponse was still rolled back if
    /// any other subresponse is an error; see
    /// [`CompositeResponse`](CompositeResponse#rollback-under-allornone).
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.http_status_code) || self.http_status_code == 304
    }

    /// `true` when the sub-request failed: a 4xx or 5xx, which is how
    /// Salesforce defines an erroring subrequest ("an HTTP status code in
    /// the 400 or 500 range").
    pub fn is_error(&self) -> bool {
        (400..600).contains(&self.http_status_code)
    }
}

/// Top-level response from `POST /composite/graph`.
///
/// One [`CompositeGraphResult`] per graph in the request, each carrying
/// the graph's `graphId`, the per-node results in the same
/// [`CompositeResponse`] shape the generic composite call returns, and
/// the `isSuccessful` verdict for the graph as a whole. There is no
/// top-level success flag: the outer call succeeded once this type
/// parses, and each graph reports its own outcome.
///
/// [`CompositeGraphResult::is_successful`] is the one place to look. A
/// graph is atomic, so when it is `false` nothing in that graph was
/// committed, whatever its individual nodes show; its error nodes say
/// why, and its other nodes carry the rollback status, as they do for a
/// generic composite request under `allOrNone`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompositeGraphResponse {
    /// One entry per graph in the request. A 2xx body without the
    /// documented `graphs` array does not parse, so an empty list here
    /// means the request carried no graphs, never that the verdicts
    /// went missing.
    pub graphs: Vec<CompositeGraphResult>,
}

/// One graph's outcome inside [`CompositeGraphResponse::graphs`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompositeGraphResult {
    /// The caller's `graphId` for this graph.
    #[serde(rename = "graphId")]
    pub graph_id: String,
    /// The per-node results, in the generic composite response shape.
    /// Reads as empty when a graph's response omits it.
    #[serde(rename = "graphResponse", default)]
    pub graph_response: CompositeResponse,
    /// Whether the whole graph was processed successfully. `false` means
    /// nothing in the graph was committed, whether it was rolled back or
    /// never ran because processing had halted.
    #[serde(rename = "isSuccessful")]
    pub is_successful: bool,
}

/// One per-record entry in the array returned by `/composite/sobjects`
/// (create / update / upsert / delete).
///
/// `success` is the only signal that a write happened. With `allOrNone:
/// false` (the default) each record stands alone: a successful record's
/// `id` is populated even when siblings in the same call failed. With
/// `allOrNone: true` one failure rolls every record back, and the
/// rolled-back entries carry `success: false` with an
/// `ALL_OR_NONE_OPERATION_ROLLED_BACK` error — and, on update, upsert and
/// delete, still carry their `id`.
///
/// When these entries are the body of a subresponse in a composite
/// request with `allOrNone: true`, a failure elsewhere in that composite
/// rolls the whole call back, and a `success: true` entry here did not
/// stick. See
/// [`CompositeResponse`](CompositeResponse#rollback-under-allornone).
///
/// `created` is reported only by the upsert endpoint, and not on every
/// entry: `Some(true)` when the upsert inserted a record, `Some(false)`
/// when it updated one, and absent on some successful entries in the
/// documented responses as well as on failures and on create, update and
/// delete.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SObjectCollectionResult {
    /// Salesforce ID of the record. Absent when no record could be
    /// identified — a failed create, a malformed ID — but present on a
    /// rolled-back update, upsert or delete even though `success` is
    /// `false`, so it does not by itself mean a write stuck.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// `true` when the per-record operation succeeded and was not rolled
    /// back.
    pub success: bool,
    /// Errors for this record. Populated only when `success` is `false`;
    /// uses the diverged composite error shape ([`CompositeError`]).
    #[serde(default)]
    pub errors: Vec<CompositeError>,
    /// `true` if an upsert inserted a new record, `false` if it updated
    /// an existing one. `None` on every non-upsert call and on some
    /// successful upsert entries, so `None` means unknown, not "updated".
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
/// untyped response); a body that doesn't fit `R` becomes a
/// [`CirrusError::InvalidResponse`] carrying a short excerpt of what
/// arrived. Any other status goes to [`parse_error_response`]: a 300 whose
/// body is a JSON array becomes [`CirrusError::MultipleMatches`], and any
/// other body is parsed as a Salesforce error array, falling back to the
/// raw body in [`CirrusError::Api::raw`] for debugging.
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
        // A 2xx that doesn't fit `R` is usually an off-contract body from an
        // interposed hop, or a truncated one — serde's message alone names
        // neither, so lead the excerpt with enough to tell those apart.
        return serde_json::from_slice(bytes).map_err(|err| {
            CirrusError::InvalidResponse(format!(
                "endpoint returned {status} but the body did not deserialize into the requested \
                 type: {}; body starts: {}",
                capped_serde_message(&err),
                capped_body(bytes, SUCCESS_BODY_EXCERPT_CAP)
            ))
        });
    }
    Err(parse_error_response(status, bytes))
}

/// Ceiling on how much of an unparseable error body is retained in
/// [`CirrusError::Api::raw`]. A body that doesn't match the Salesforce
/// error shape comes from a proxy or gateway, which can echo request
/// data — capping what we retain bounds what can end up in the
/// caller's logs via `Display`/`Debug`, and keeps a pathological body
/// from ballooning the error value. 2 KiB comfortably fits real proxy
/// error pages' useful prefix.
const RAW_ERROR_BODY_CAP: usize = 2048;

/// Ceiling on the excerpt carried by the [`CirrusError::InvalidResponse`]
/// raised when a 2xx body doesn't fit `R`.
///
/// Much tighter than [`RAW_ERROR_BODY_CAP`], because a successful body is
/// normally the org's own record data rather than a gateway's page. The
/// excerpt only has to be wide enough to recognize an off-contract body —
/// an HTML login page, a truncated stream — at a glance; serde's own
/// message, which names the expected type and the position, is held to
/// [`SERDE_MESSAGE_CAP`].
const SUCCESS_BODY_EXCERPT_CAP: usize = 256;

/// Ceiling on the part of a serde_json message that precedes its
/// position. serde quotes the offending value (`invalid type: string
/// "…"`, ``unknown variant `…` ``), and a record field can hold 131,072
/// characters, so the message is as unbounded as the data. The expected
/// type and the position, which are what locate the mismatch, are short
/// and survive the cut.
const SERDE_MESSAGE_CAP: usize = 256;

/// Renders a serde_json error with the quoted value cut at
/// [`SERDE_MESSAGE_CAP`] bytes, marked when anything was dropped.
///
/// serde_json appends ` at line {l} column {c}` to every error that
/// has a position; that suffix is split off before the cut and put back
/// after it, so the position is never lost to a long value.
fn capped_serde_message(err: &serde_json::Error) -> String {
    let message = err.to_string();
    let position = format!(" at line {} column {}", err.line(), err.column());
    let (code, suffix) = match message.strip_suffix(&position) {
        Some(code) if err.line() != 0 => (code, position.as_str()),
        _ => (message.as_str(), ""),
    };
    if code.len() <= SERDE_MESSAGE_CAP {
        return message;
    }
    let mut end = SERDE_MESSAGE_CAP;
    while !code.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}… <truncated>{suffix}", &code[..end])
}

/// Parses a non-2xx response body into a [`CirrusError::Api`], or into
/// [`CirrusError::MultipleMatches`] for the 300 an upsert by external ID
/// answers with when the value matches several records.
///
/// A 300 whose body is a JSON array is that list of matching records and
/// is kept whole, uncapped (the transport already bounds a non-2xx body).
/// Any other body is tried as the documented Salesforce error array
/// first, then a bare error object, which some per-operation pages print
/// in place of the array. When neither parses, the body is preserved in
/// `raw` (capped at [`RAW_ERROR_BODY_CAP`] bytes) for debugging — unless
/// it was empty, in which case `raw` stays `None` and the error reads as
/// having no body. Used both by [`parse_response_bytes`] (JSON success
/// path) and the raw-body transport path that bypasses JSON
/// deserialization on success (Bulk API CSV downloads).
pub(crate) fn parse_error_response(status: u16, bytes: &[u8]) -> CirrusError {
    if status == 300
        && let Ok(records) = serde_json::from_slice::<Vec<serde_json::Value>>(bytes)
    {
        return CirrusError::MultipleMatches { records };
    }
    let errors = serde_json::from_slice::<Vec<SalesforceError>>(bytes)
        .or_else(|_| serde_json::from_slice::<SalesforceError>(bytes).map(|e| vec![e]))
        .unwrap_or_default();
    let raw = if errors.is_empty() && !bytes.is_empty() {
        Some(capped_body(bytes, RAW_ERROR_BODY_CAP))
    } else {
        None
    };
    CirrusError::Api {
        status,
        errors,
        raw,
        retry_after: None,
    }
}

/// Decodes a body for inclusion in an error, bounded by `cap` bytes and
/// marked when anything was dropped.
///
/// Only the capped byte prefix is decoded, so a multi-megabyte body never
/// gets a full owned copy. Lossy decoding expands each invalid byte to a
/// three-byte U+FFFD, which can push even that prefix past the cap, so the
/// decoded string is trimmed again at a char boundary.
fn capped_body(bytes: &[u8], cap: usize) -> String {
    let mut truncated = bytes.len() > cap;
    let head = &bytes[..bytes.len().min(cap)];
    let mut body = String::from_utf8_lossy(head).into_owned();
    if body.len() > cap {
        let mut end = cap;
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

/// A request body sent as given: the bytes and their `Content-Type`.
///
/// What [`Cirrus::send_raw`](crate::Cirrus::send_raw) and
/// [`ApexHandler::send_raw`](crate::handlers::apex::ApexHandler::send_raw)
/// take for a body that is not JSON, or that is already serialized.
#[derive(Clone)]
pub struct RawBody {
    bytes: Bytes,
    content_type: String,
}

impl RawBody {
    /// A body of `bytes` sent with `content_type` as the request's
    /// `Content-Type`. `bytes` is anything that converts into
    /// [`Bytes`]: a `Vec<u8>`, a `String`, a `&'static str` or `&'static
    /// [u8]`, or a [`Bytes`] shared with the caller.
    pub fn new(bytes: impl Into<Bytes>, content_type: impl Into<String>) -> Self {
        Self {
            bytes: bytes.into(),
            content_type: content_type.into(),
        }
    }

    /// The bytes the request sends.
    pub fn bytes(&self) -> &Bytes {
        &self.bytes
    }

    /// The `Content-Type` the request sends.
    pub fn content_type(&self) -> &str {
        &self.content_type
    }
}

impl std::fmt::Debug for RawBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The bytes are the caller's data, and can be large.
        f.debug_struct("RawBody")
            .field("content_type", &self.content_type)
            .field("len", &self.bytes.len())
            .finish()
    }
}

/// A response as it arrived: the status, the headers and the body
/// bytes, with nothing parsed.
///
/// What [`Cirrus::send_raw`](crate::Cirrus::send_raw) and
/// [`ApexHandler::send_raw`](crate::handlers::apex::ApexHandler::send_raw)
/// return, for every status the request loop lets through, so a
/// non-2xx answer is read from [`status`](Self::status) rather than
/// matched as an error. The struct is `#[non_exhaustive]`: read its
/// fields, and destructure it with `..`.
#[derive(Clone)]
#[non_exhaustive]
pub struct RawResponse {
    /// The HTTP status code.
    pub status: u16,
    /// The response headers, as received.
    pub headers: HeaderMap,
    /// The body. A 2xx body is as the server sent it. A non-2xx body
    /// has the session token, and any `Bearer` credential run, replaced
    /// with `[redacted]`, as [`CirrusError::Api`]'s `raw` has: such a
    /// body is often an intermediary's page that echoes the request.
    /// Either is decoded of its content encoding (the client the builder
    /// creates asks for gzip and inflates it, so `Content-Encoding` and
    /// `Content-Length` are then absent from [`headers`](Self::headers))
    /// and buffered only within the client's response size limits.
    pub body: Bytes,
}

impl RawResponse {
    /// Whether the status is 2xx.
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

impl std::fmt::Debug for RawResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The body is record data, or an error page that may echo the
        // request; its size is what a log line needs.
        f.debug_struct("RawResponse")
            .field("status", &self.status)
            .field("headers", &self.headers)
            .field("body_len", &self.body.len())
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::Value;
    use serde_json::json;

    /// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/dome_describeGlobal.htm
    /// "Example response body": the envelope with its first `sobjects` entry.
    fn describe_global_example() -> Value {
        json!({
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
    }

    /// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/dome_composite_record_manipulation.htm
    /// "Response body after successfully executing the composite
    /// request", verbatim apart from the prose placeholder the page uses
    /// for the account body. The last subrequest sent `If-Modified-Since`
    /// and came back 304 Not Modified with a null body.
    fn composite_response_example() -> Value {
        json!({
            "compositeResponse": [{
                "body": {"id": "001R00000033JNuIAM", "success": true, "errors": []},
                "httpHeaders": {"Location": "/services/data/v67.0/sobjects/Account/001R00000033JNuIAM"},
                "httpStatusCode": 201,
                "referenceId": "NewAccount"
            }, {
                "body": {"attributes": {"type": "Account"}, "Id": "001R00000033JNuIAM", "Name": "Acme"},
                "httpHeaders": {
                    "ETag": "\"Jbjuzw7dbhaEG3fd90kJbx6A0ow=\"",
                    "Last-Modified": "Fri, 22 Jul 2016 20:19:37 GMT"
                },
                "httpStatusCode": 200,
                "referenceId": "NewAccountInfo"
            }, {
                "body": {"id": "003R00000025REHIA2", "success": true, "errors": []},
                "httpHeaders": {"Location": "/services/data/v67.0/sobjects/Contact/003R00000025REHIA2"},
                "httpStatusCode": 201,
                "referenceId": "NewContact"
            }, {
                "body": {
                    "attributes": {"type": "User", "url": "/services/data/v67.0/sobjects/User/005R0000000I90CIAS"},
                    "Name": "Jane Doe",
                    "CompanyName": "Salesforce",
                    "Title": "Director",
                    "City": "San Francisco",
                    "State": "CA",
                    "Id": "005R0000000I90CIAS"
                },
                "httpHeaders": {},
                "httpStatusCode": 200,
                "referenceId": "NewAccountOwner"
            }, {
                "body": null,
                "httpHeaders": {
                    "ETag": "\"f2293620\"",
                    "Last-Modified": "Fri, 22 Jul 2016 18:45:56 GMT"
                },
                "httpStatusCode": 304,
                "referenceId": "AccountMetadata"
            }]
        })
    }

    /// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_asynch.meta/api_asynch/get_job_info.htm
    /// Example response for an Open ingest job, verbatim, including the
    /// slash-less, instance-relative `contentUrl`.
    fn bulk_ingest_open_job_example() -> Value {
        json!({
            "id": "7506g00000DhRA2AAN",
            "operation": "insert",
            "object": "Account",
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
            "columnDelimiter": "COMMA",
            "retries": 0,
            "totalProcessingTime": 0,
            "apiActiveProcessingTime": 0,
            "apexProcessingTime": 0
        })
    }

    /// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/resources_composite_sobjects_collections_update.htm
    /// "Example Response Body (Some Items Failed and allOrNone is true)",
    /// verbatim. The delete and upsert pages show the same shape: the
    /// rolled-back record keeps its id, so only `success` says whether the
    /// write stuck.
    fn collections_rollback_example() -> Value {
        json!([{
            "id": "001RM000003oCprYAE",
            "success": false,
            "errors": [{
                "statusCode": "ALL_OR_NONE_OPERATION_ROLLED_BACK",
                "message": "Record rolled back because not all records were valid and the request was using AllOrNone header",
                "fields": []
            }]
        }, {
            "success": false,
            "errors": [{
                "statusCode": "MALFORMED_ID",
                "message": "Contact ID: id value of incorrect type: 001xx000003DGb2999",
                "fields": ["Id"]
            }]
        }])
    }

    /// SOURCE: https://developer.salesforce.com/docs/platform/api-rest/guide/resources-composite-allornone.html
    /// "Case 4: `outerFlag` = `true`, `innerFlag` = `false`", the response
    /// body verbatim. The page's request names the sObject Collections
    /// subrequest `newAccounts` while this response prints its
    /// `referenceId` as `collection1`; the response is kept as printed.
    fn composite_all_or_none_case_4_example() -> Value {
        json!({
            "compositeResponse": [{
                "body": [{
                    "id": "001R00000066cndIAA",
                    "success": true,
                    "errors": []
                }, {
                    "success": false,
                    "errors": [{
                        "statusCode": "DUPLICATES_DETECTED",
                        "message": "Use one of these records?",
                        "fields": []
                    }]
                }],
                "httpHeaders": {},
                "httpStatusCode": 200,
                "referenceId": "collection1"
            }, {
                "body": [{
                    "errorCode": "PROCESSING_HALTED",
                    "message": "The transaction was rolled back since another operation in the same transaction failed."
                }],
                "httpHeaders": {},
                "httpStatusCode": 400,
                "referenceId": "newContact"
            }]
        })
    }

    /// A query response with more pages to fetch: `done` is `false` and
    /// `nextRecordsUrl` carries the locator.
    fn paginated_query_example() -> Value {
        json!({
            "totalSize": 1500,
            "done": false,
            "nextRecordsUrl": "/services/data/v66.0/query/01g...-2000",
            "records": []
        })
    }

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

    // Wire-shape provenance: the Upsert page (https://developer.salesforce.com/docs/platform/api-rest/guide/dome-upsert.html)
    // says a non-unique external ID answers 300 "plus a list of the
    // records that matched the query" and prints no example body, so the
    // entries below are invented. The fixture pins only that an array
    // longer than the raw-body cap passes through whole.
    #[test]
    fn a_300_with_an_array_body_keeps_every_matching_record() {
        let matches: Vec<Value> = (0..100)
            .map(|i| json!({"Id": format!("001xx000003DGb{i:03}"), "Name": format!("Company {i:03}")}))
            .collect();
        let body = serde_json::to_vec(&matches).unwrap();
        assert!(body.len() > RAW_ERROR_BODY_CAP);

        match parse_error_response(300, &body) {
            CirrusError::MultipleMatches { records, .. } => {
                assert_eq!(records.len(), 100);
                assert_eq!(records[99], matches[99]);
            }
            other => panic!("expected MultipleMatches, got {other:?}"),
        }
    }

    #[test]
    fn a_300_with_a_non_array_body_stays_an_api_error() {
        match parse_error_response(300, b"<html>") {
            CirrusError::Api {
                status: 300,
                raw: Some(raw),
                ..
            } => assert_eq!(raw, "<html>"),
            other => panic!("expected Api with a raw body, got {other:?}"),
        }
    }

    #[test]
    fn undeserializable_2xx_body_keeps_an_excerpt() {
        let err = parse_response_bytes::<QueryResult<Value>>(
            200,
            b"<html><body>Gateway timeout</body></html>",
        )
        .unwrap_err();
        match err {
            CirrusError::InvalidResponse(msg) => {
                assert!(msg.contains("200"), "status missing: {msg}");
                assert!(msg.contains("Gateway timeout"), "body missing: {msg}");
            }
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }

    #[test]
    fn undeserializable_2xx_body_excerpt_is_capped() {
        // A successful body is the org's own data, so the excerpt is
        // held to a far tighter cap than an error page's.
        let body = format!("{{\"junk\": \"{}\"}}", "x".repeat(RAW_ERROR_BODY_CAP * 3));
        let err = parse_response_bytes::<QueryResult<Value>>(200, body.as_bytes()).unwrap_err();
        match err {
            CirrusError::InvalidResponse(msg) => {
                assert!(msg.contains("… <truncated>"), "missing marker");
                assert!(
                    msg.len() < SUCCESS_BODY_EXCERPT_CAP + 256,
                    "excerpt not capped: {} bytes",
                    msg.len()
                );
            }
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }

    /// Deserialization target with a numeric field, so a string in it is
    /// the wrong-typed value serde quotes in full.
    #[derive(Debug, Deserialize)]
    #[allow(dead_code)]
    struct Numeric {
        v: f64,
    }

    /// Deserialization target with a closed set of variants.
    #[derive(Debug, Deserialize)]
    #[allow(dead_code)]
    enum Closed {
        A,
        B,
    }

    fn invalid_response_message<R: DeserializeOwned + std::fmt::Debug>(body: &str) -> String {
        match parse_response_bytes::<R>(200, body.as_bytes()).unwrap_err() {
            CirrusError::InvalidResponse(msg) => msg,
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }

    #[test]
    fn a_wrong_typed_value_is_not_quoted_in_full() {
        // The offending value can be a 131,072-character Long Text Area;
        // serde puts it into its message, ahead of the position.
        let body = format!("{{\"v\":\"{}\"}}", "x".repeat(100_000));
        let direct = serde_json::from_str::<Numeric>(&body).unwrap_err();
        let msg = invalid_response_message::<Numeric>(&body);
        assert!(msg.len() < 1024, "message not capped: {} bytes", msg.len());
        assert!(
            msg.contains(&format!(
                "… <truncated> at line {} column {}; body starts:",
                direct.line(),
                direct.column()
            )),
            "{msg}"
        );
    }

    #[test]
    fn an_unknown_variant_is_not_quoted_in_full() {
        let body = format!("\"{}\"", "v".repeat(10_000));
        let direct = serde_json::from_str::<Closed>(&body).unwrap_err();
        let msg = invalid_response_message::<Closed>(&body);
        assert!(msg.len() < 1024, "message not capped: {} bytes", msg.len());
        assert!(
            msg.contains(&format!(
                "… <truncated> at line {} column {}; body starts:",
                direct.line(),
                direct.column()
            )),
            "{msg}"
        );
    }

    #[test]
    fn a_short_serde_message_is_unchanged() {
        let body = "{\"v\":\"abc\"}";
        let direct = serde_json::from_str::<Numeric>(body).unwrap_err();
        let msg = invalid_response_message::<Numeric>(body);
        assert!(msg.contains(&direct.to_string()), "{msg}");
        assert_eq!(capped_serde_message(&direct), direct.to_string());
    }

    #[test]
    fn a_serde_message_without_a_position_is_capped_whole() {
        // `from_value` errors carry no line, so the message has no
        // position suffix to preserve.
        let long = "é".repeat(SERDE_MESSAGE_CAP);
        let err = serde_json::from_value::<Numeric>(json!({ "v": long })).unwrap_err();
        assert_eq!(err.line(), 0);
        let msg = capped_serde_message(&err);
        assert!(msg.ends_with("… <truncated>"), "{msg}");
        assert!(msg.len() < SERDE_MESSAGE_CAP + 32, "{} bytes", msg.len());
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
        let body = paginated_query_example().to_string();
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
                ..
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
    fn bare_object_error_body_parses_as_one_entry() {
        // SOURCE: https://developer.salesforce.com/docs/platform/api-rest/guide/dome-upsert.html
        // "Incorrect external ID field" prints the error without the
        // array that the Status Codes and Error Responses page wraps it
        // in. Verbatim, spacing included.
        let body =
            r#"{ "message" : "The requested resource does not exist", "errorCode" : "NOT_FOUND" }"#;
        let err = parse_response_bytes::<Value>(404, body.as_bytes()).unwrap_err();
        match err {
            CirrusError::Api {
                status,
                errors,
                raw,
                ..
            } => {
                assert_eq!(status, 404);
                assert_eq!(errors.len(), 1);
                assert_eq!(errors[0].error_code, "NOT_FOUND");
                assert_eq!(errors[0].message, "The requested resource does not exist");
                assert!(errors[0].fields.is_empty());
                assert!(raw.is_none(), "a parsed body is not kept raw: {raw:?}");
            }
            other => panic!("expected Api error, got {other:?}"),
        }
    }

    #[test]
    fn empty_error_body_leaves_raw_absent() {
        // An edge or load balancer answering 503 with no body: there is
        // nothing to preserve, and the error says so instead of printing
        // an empty excerpt that reads like a parsing problem.
        let err = parse_error_response(503, b"");
        match &err {
            CirrusError::Api {
                status,
                errors,
                raw,
                ..
            } => {
                assert_eq!(*status, 503);
                assert!(errors.is_empty());
                assert!(raw.is_none(), "{raw:?}");
            }
            other => panic!("expected Api error, got {other:?}"),
        }
        assert!(err.to_string().contains("<no body>"), "{err}");
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
                ..
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
        let body = describe_global_example().to_string();
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
        let body = bulk_ingest_open_job_example().to_string();
        let job: BulkIngestJob = parse_response_bytes(200, body.as_bytes()).unwrap();
        assert_eq!(job.id, "7506g00000DhRA2AAN");
        assert_eq!(job.operation, BulkOperation::Insert);
        assert_eq!(job.state, BulkJobState::Open);
        assert_eq!(job.line_ending, BulkLineEnding::LF);
        assert_eq!(job.column_delimiter, BulkColumnDelimiter::Comma);
        assert_eq!(
            job.content_url.as_deref(),
            Some("services/data/v67.0/jobs/ingest/7506g00000DhRA2AAN/batches")
        );
        assert_eq!(job.job_type.as_deref(), Some("V2Ingest"));
        assert!(job.number_records_processed.is_none());
    }

    #[test]
    fn parses_bulk_ingest_job_create_response_without_jobtype() {
        // SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_asynch.meta/api_asynch/walkthrough_upload_data.htm
        // Step 3's "Example response body" for `POST /jobs/ingest`,
        // verbatim. The create response carries no `jobType`; only the
        // later GET example on the same page does. The example's
        // `contentUrl` also lacks the `v` in its version segment (the
        // Get Job Info example has it) and is kept as published.
        let body = json!({
            "id": "7505fEXAMPLE4C2AAM",
            "operation": "insert",
            "object": "Account",
            "createdById": "0055fEXAMPLEtG4AAM",
            "createdDate": "2022-01-02T21:33:43.000+0000",
            "systemModstamp": "2022-01-02T21:33:43.000+0000",
            "state": "Open",
            "concurrencyMode": "Parallel",
            "contentType": "CSV",
            "apiVersion": 67.0,
            "contentUrl": "services/data/67.0/jobs/ingest/7505fEXAMPLE4C2AAM/batches",
            "lineEnding": "LF",
            "columnDelimiter": "COMMA"
        })
        .to_string();
        let job: BulkIngestJob = parse_response_bytes(200, body.as_bytes()).unwrap();
        assert_eq!(job.id, "7505fEXAMPLE4C2AAM");
        assert_eq!(job.state, BulkJobState::Open);
        assert_eq!(
            job.content_url.as_deref(),
            Some("services/data/67.0/jobs/ingest/7505fEXAMPLE4C2AAM/batches")
        );
        assert!(job.job_type.is_none());
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
    fn parses_bulk_ingest_job_with_object_absent() {
        // SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_asynch.meta/api_asynch/create_job.htm
        // The response table treats `object` as conditional on the
        // operation rather than always present; `#[serde(default)]`
        // keeps a body that omits it from failing the whole envelope.
        let body = json!({
            "id": "7506g00000DhRA2AAN",
            "operation": "consentImport",
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
    fn unnamed_bulk_operation_writes_its_own_literal_and_reads_back_as_unknown() {
        // The literal Salesforce sent is not kept: `Unknown` serializes as
        // its own name, which no endpoint accepts, and parses as itself.
        let op: BulkOperation = serde_json::from_value(json!("someFutureOperation")).unwrap();
        assert_eq!(op, BulkOperation::Unknown);
        let written = serde_json::to_value(op).unwrap();
        assert_eq!(written, json!("Unknown"));
        assert_eq!(
            serde_json::from_value::<BulkOperation>(written).unwrap(),
            BulkOperation::Unknown
        );
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
    fn bulk_operation_knows_which_endpoint_takes_it() {
        // SOURCE: https://developer.salesforce.com/docs/platform/api-asynch/guide/create-job.html
        // and query-create-job.html: the ingest endpoint lists insert,
        // delete, hardDelete, update, upsert, refresh and consentImport;
        // the query endpoint lists query and queryAll.
        for op in [
            BulkOperation::Insert,
            BulkOperation::Update,
            BulkOperation::Upsert,
            BulkOperation::Delete,
            BulkOperation::HardDelete,
            BulkOperation::Refresh,
            BulkOperation::ConsentImport,
        ] {
            assert!(op.is_ingest(), "{op:?}");
            assert!(!op.is_query(), "{op:?}");
        }
        for op in [BulkOperation::Query, BulkOperation::QueryAll] {
            assert!(op.is_query(), "{op:?}");
            assert!(!op.is_ingest(), "{op:?}");
        }
        assert!(!BulkOperation::Unknown.is_ingest());
        assert!(!BulkOperation::Unknown.is_query());
    }

    #[test]
    fn bulk_job_type_round_trips_the_documented_wire_names() {
        // SOURCE: https://developer.salesforce.com/docs/platform/api-asynch/guide/get-all-jobs.html
        // (`BigObjectIngest`, `Classic`, `V2Ingest`) and
        // query-get-all-jobs.html (`Classic`, `V2Query`, `V2Ingest`).
        for (job_type, wire) in [
            (BulkJobType::BigObjectIngest, "BigObjectIngest"),
            (BulkJobType::Classic, "Classic"),
            (BulkJobType::V2Ingest, "V2Ingest"),
            (BulkJobType::V2Query, "V2Query"),
        ] {
            assert_eq!(serde_json::to_value(job_type).unwrap(), json!(wire));
            assert_eq!(
                serde_json::from_value::<BulkJobType>(json!(wire)).unwrap(),
                job_type
            );
            assert_eq!(job_type.as_str(), wire);
        }
        assert_eq!(
            serde_json::from_value::<BulkJobType>(json!("V3Ingest")).unwrap(),
            BulkJobType::Unknown
        );
    }

    #[test]
    fn bulk_job_state_reads_an_unnamed_literal_as_unknown_and_never_terminal() {
        // A job listing can carry Bulk API 1.0 jobs, whose `Closed`
        // state is not a 2.0 literal.
        let state: BulkJobState = serde_json::from_value(json!("Closed")).unwrap();
        assert_eq!(state, BulkJobState::Unknown);
        assert!(!state.is_terminal());
    }

    #[test]
    fn bulk_job_state_is_terminal_once_processing_has_ended() {
        // SOURCE: https://developer.salesforce.com/docs/platform/api-asynch/guide/get-job-info.html
        // `state`: JobComplete, Failed and Aborted end a job; Open,
        // UploadComplete and InProgress precede processing or are it.
        for state in [
            BulkJobState::JobComplete,
            BulkJobState::Failed,
            BulkJobState::Aborted,
        ] {
            assert!(state.is_terminal(), "{state:?}");
        }
        for state in [
            BulkJobState::Open,
            BulkJobState::UploadComplete,
            BulkJobState::InProgress,
        ] {
            assert!(!state.is_terminal(), "{state:?}");
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
    fn parses_the_documented_composite_response_including_its_304_entry() {
        let body = composite_response_example().to_string();
        let resp: CompositeResponse = parse_response_bytes(200, body.as_bytes()).unwrap();
        assert_eq!(resp.composite_response.len(), 5);
        assert_eq!(resp.composite_response[0].reference_id, "NewAccount");
        assert_eq!(
            resp.composite_response[0]
                .http_headers
                .get("Location")
                .and_then(|v| v.to_str().ok()),
            Some("/services/data/v67.0/sobjects/Account/001R00000033JNuIAM")
        );
        assert_eq!(resp.composite_response[1].body["Name"], "Acme");
        let cached = &resp.composite_response[4];
        assert_eq!(cached.http_status_code, 304);
        assert!(cached.body.is_null());
        assert!(
            resp.composite_response.iter().all(|r| r.is_success()),
            "a 304 on a conditional subrequest is not a failure"
        );
    }

    #[test]
    fn composite_subresponse_classifies_304_as_success_and_300_as_neither() {
        fn sub(code: u16) -> CompositeSubresponse {
            CompositeSubresponse {
                body: serde_json::Value::Null,
                http_headers: HeaderMap::new(),
                http_status_code: code,
                reference_id: "r".into(),
            }
        }
        assert!(sub(201).is_success() && !sub(201).is_error());
        assert!(sub(304).is_success() && !sub(304).is_error());
        assert!(!sub(300).is_success() && !sub(300).is_error());
        assert!(!sub(400).is_success() && sub(400).is_error());
        assert!(!sub(500).is_success() && sub(500).is_error());
    }

    #[test]
    fn parses_the_all_or_none_case_4_response() {
        let body = composite_all_or_none_case_4_example().to_string();
        let resp: CompositeResponse = parse_response_bytes(200, body.as_bytes()).unwrap();
        assert_eq!(resp.composite_response.len(), 2);

        // The collections subrequest answers 200 and its first row says
        // `success: true`, yet the outer `allOrNone: true` rolled it back
        // along with the failed Contact create.
        let collections = &resp.composite_response[0];
        assert_eq!(collections.http_status_code, 200);
        assert!(collections.is_success());
        let rows: Vec<SObjectCollectionResult> =
            serde_json::from_value(collections.body.clone()).unwrap();
        assert!(rows[0].success);
        assert_eq!(rows[1].errors[0].status_code, "DUPLICATES_DETECTED");

        let halted = &resp.composite_response[1];
        assert_eq!(halted.http_status_code, 400);
        assert!(halted.is_error());
        let errors: Vec<SalesforceError> = serde_json::from_value(halted.body.clone()).unwrap();
        assert_eq!(errors[0].error_code, "PROCESSING_HALTED");
    }

    #[test]
    fn parses_collections_rollback_entries_that_keep_their_ids() {
        let body = collections_rollback_example().to_string();
        let results: Vec<SObjectCollectionResult> =
            parse_response_bytes(200, body.as_bytes()).unwrap();
        assert_eq!(results[0].id.as_deref(), Some("001RM000003oCprYAE"));
        assert!(!results[0].success);
        assert_eq!(
            results[0].errors[0].status_code,
            "ALL_OR_NONE_OPERATION_ROLLED_BACK"
        );
        assert!(results[1].id.is_none());
        assert!(!results[1].success);
        assert_eq!(results[1].errors[0].fields, vec!["Id".to_string()]);
    }

    #[test]
    fn parses_an_upsert_success_without_a_created_flag() {
        // SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/resources_composite_sobjects_collections_upsert.htm
        // "Example Response Body (Some Items Failed and allOrNone is false)",
        // verbatim: the successful entry carries no `created`.
        let body = json!([{
            "id": "001xx0000004GxDAAU",
            "success": true,
            "errors": []
        }, {
            "success": false,
            "errors": [{
                "statusCode": "MALFORMED_ID",
                "message": "Contact ID: id value of incorrect type: 001xx0000004GxEAAU",
                "fields": ["Id"]
            }]
        }])
        .to_string();
        let results: Vec<SObjectCollectionResult> =
            parse_response_bytes(200, body.as_bytes()).unwrap();
        assert!(results[0].success);
        assert_eq!(results[0].id.as_deref(), Some("001xx0000004GxDAAU"));
        assert!(results[0].created.is_none());
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

    // Every envelope serializes under the wire names it deserializes from,
    // so a parsed response can be persisted and read back.

    fn assert_serialize<T: Serialize>() {}

    #[test]
    fn every_response_envelope_is_serialize() {
        assert_serialize::<QueryResult<Value>>();
        assert_serialize::<SearchResult<Value>>();
        assert_serialize::<SObjectCreateResult>();
        assert_serialize::<Limit>();
        assert_serialize::<DescribeGlobal>();
        assert_serialize::<SObjectMetadata>();
        assert_serialize::<BulkIngestJob>();
        assert_serialize::<BulkJobStateChange>();
        assert_serialize::<BulkQueryJob>();
        assert_serialize::<BulkJobList>();
        assert_serialize::<BulkJobSummary>();
        assert_serialize::<BulkResultPages>();
        assert_serialize::<BulkResultPage>();
        assert_serialize::<EventLogFileRecord>();
        assert_serialize::<ApiVersion>();
        assert_serialize::<BatchResponse>();
        assert_serialize::<BatchSubresult>();
        assert_serialize::<CompositeTreeResponse>();
        assert_serialize::<CompositeTreeResult>();
        assert_serialize::<CompositeError>();
        assert_serialize::<CompositeResponse>();
        assert_serialize::<CompositeSubresponse>();
        assert_serialize::<CompositeGraphResponse>();
        assert_serialize::<CompositeGraphResult>();
        assert_serialize::<SObjectCollectionResult>();
        assert_serialize::<ExecuteAnonymousResult>();
    }

    #[test]
    fn describe_global_serializes_under_its_wire_names_and_reads_back() {
        let fixture = describe_global_example();
        let parsed: DescribeGlobal = serde_json::from_value(fixture.clone()).unwrap();

        let written = serde_json::to_value(&parsed).unwrap();
        assert_eq!(written["maxBatchSize"], 200);
        let object = &written["sobjects"][0];
        for key in [
            "customSetting",
            "deprecatedAndHidden",
            "feedEnabled",
            "keyPrefix",
            "labelPlural",
            "mruEnabled",
        ] {
            assert!(object.get(key).is_some(), "{key} missing from {object}");
        }
        assert!(written.get("max_batch_size").is_none());
        assert_eq!(written, fixture);

        let back: DescribeGlobal = serde_json::from_value(written).unwrap();
        assert_eq!(back.max_batch_size, 200);
        assert_eq!(back.sobjects[0].key_prefix.as_deref(), Some("001"));
        assert_eq!(back.sobjects[0].urls, parsed.sobjects[0].urls);
    }

    #[test]
    fn query_result_serializes_its_pagination_members_and_reads_back() {
        let mut fixture = paginated_query_example();
        fixture["records"] = json!([{"Id": "001xx", "Name": "Acme"}]);
        let parsed: QueryResult<Value> = serde_json::from_value(fixture.clone()).unwrap();

        let written = serde_json::to_value(&parsed).unwrap();
        assert_eq!(written["totalSize"], 1500);
        assert_eq!(
            written["nextRecordsUrl"],
            "/services/data/v66.0/query/01g...-2000"
        );
        assert_eq!(written, fixture);

        let back: QueryResult<Value> = serde_json::from_value(written).unwrap();
        assert_eq!(back.total_size, 1500);
        assert!(!back.done);
        assert_eq!(back.next_records_url, parsed.next_records_url);
        assert_eq!(back.records[0]["Name"], "Acme");
    }

    /// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/dome_search.htm
    /// The `searchRecords` entry follows that page's "Example response body".
    /// The `metadata` member is struct-derived (the struct has the field);
    /// its value here is not a documented example.
    #[test]
    fn search_result_serializes_the_current_object_form() {
        let fixture = json!({
            "searchRecords": [{
                "attributes": {
                    "type": "Account",
                    "url": "/services/data/v66.0/sobjects/Account/001xx"
                },
                "Id": "001xx"
            }],
            "metadata": {"entityMetadata": []}
        });
        let parsed: SearchResult<Value> = serde_json::from_value(fixture.clone()).unwrap();

        let written = serde_json::to_value(&parsed).unwrap();
        assert_eq!(written, fixture);
        let back: SearchResult<Value> = serde_json::from_value(written).unwrap();
        assert_eq!(back.search_records[0]["attributes"]["type"], "Account");
    }

    /// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/dome_versions.htm
    /// "Example JSON response body": one entry of the array.
    #[test]
    fn api_version_serializes_and_reads_back() {
        let fixture = json!({
            "label": "Summer '14",
            "url": "/services/data/v31.0",
            "version": "31.0"
        });
        let parsed: ApiVersion = serde_json::from_value(fixture.clone()).unwrap();

        let written = serde_json::to_value(&parsed).unwrap();
        assert_eq!(written, fixture);
        let back: ApiVersion = serde_json::from_value(written).unwrap();
        assert_eq!(back.version_number(), Some((31, 0)));
    }

    #[test]
    fn collection_results_omit_an_absent_id_and_created_flag() {
        let fixture = collections_rollback_example();
        let parsed: Vec<SObjectCollectionResult> = serde_json::from_value(fixture.clone()).unwrap();

        let written = serde_json::to_value(&parsed).unwrap();
        assert_eq!(
            written[0]["errors"][0]["statusCode"],
            "ALL_OR_NONE_OPERATION_ROLLED_BACK"
        );
        assert_eq!(written[0]["id"], "001RM000003oCprYAE");
        assert!(written[0].get("created").is_none());
        assert!(written[1].get("id").is_none());
        assert!(written[1].get("created").is_none());
        assert_eq!(written, fixture);

        let back: Vec<SObjectCollectionResult> = serde_json::from_value(written).unwrap();
        assert_eq!(back[0].id.as_deref(), Some("001RM000003oCprYAE"));
        assert!(back[1].id.is_none());
        assert_eq!(back[1].errors[0].fields, vec!["Id".to_string()]);
    }

    /// SOURCE: https://developer.salesforce.com/docs/platform/api-rest/guide/resources-composite-sobjects-collections-upsert.html
    /// The first body is an entry of its "Example Response Body" (every item
    /// succeeded). The second has the shape of the single-record reply on
    /// https://developer.salesforce.com/docs/platform/api-rest/guide/dome-upsert.html
    /// (API 46.0 and later), with the first entry's ID substituted.
    #[test]
    fn created_flag_is_written_when_present() {
        let parsed: SObjectCollectionResult = serde_json::from_value(
            json!({"id": "001xx0000004GxDAAU", "success": true, "errors": [], "created": true}),
        )
        .unwrap();
        let written = serde_json::to_value(&parsed).unwrap();
        assert_eq!(written["created"], true);

        let parsed: SObjectCreateResult = serde_json::from_value(
            json!({"id": "001xx0000004GxDAAU", "success": true, "errors": [], "created": false}),
        )
        .unwrap();
        let written = serde_json::to_value(&parsed).unwrap();
        assert_eq!(written["created"], false);
    }

    /// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/responses_composite_sobject_tree.htm
    /// "JSON example upon success" (its first result) and "JSON example upon
    /// failure".
    #[test]
    fn composite_tree_results_write_only_the_member_they_carry() {
        let success: CompositeTreeResponse = serde_json::from_value(json!({
            "hasErrors": false,
            "results": [{"referenceId": "ref1", "id": "001D000000K0fXOIAZ"}]
        }))
        .unwrap();
        let written = serde_json::to_value(&success).unwrap();
        assert_eq!(written["hasErrors"], false);
        assert_eq!(written["results"][0]["referenceId"], "ref1");
        assert_eq!(written["results"][0]["id"], "001D000000K0fXOIAZ");
        assert!(written["results"][0].get("errors").is_none());

        let failure: CompositeTreeResponse = serde_json::from_value(json!({
            "hasErrors": true,
            "results": [{
                "referenceId": "ref2",
                "errors": [{
                    "statusCode": "INVALID_EMAIL_ADDRESS",
                    "message": "Email: invalid email address: 123",
                    "fields": ["Email"]
                }]
            }]
        }))
        .unwrap();
        let written = serde_json::to_value(&failure).unwrap();
        assert!(written["results"][0].get("id").is_none());
        let back: CompositeTreeResponse = serde_json::from_value(written).unwrap();
        assert!(back.has_errors);
        assert_eq!(
            back.results[0].errors.as_ref().unwrap()[0].status_code,
            "INVALID_EMAIL_ADDRESS"
        );
    }

    #[test]
    fn composite_response_serializes_its_wire_names_and_reads_back() {
        let parsed: CompositeResponse =
            serde_json::from_value(composite_response_example()).unwrap();

        let written = serde_json::to_value(&parsed).unwrap();
        let first = &written["compositeResponse"][0];
        assert_eq!(first["httpStatusCode"], 201);
        assert_eq!(first["referenceId"], "NewAccount");
        assert_eq!(first["body"]["id"], "001R00000033JNuIAM");
        assert!(first["httpHeaders"].is_object());
        assert!(first.get("http_status_code").is_none());

        let back: CompositeResponse = serde_json::from_value(written).unwrap();
        assert_eq!(back.composite_response.len(), 5);
        for (before, after) in parsed
            .composite_response
            .iter()
            .zip(&back.composite_response)
        {
            assert_eq!(after.reference_id, before.reference_id);
            assert_eq!(after.http_status_code, before.http_status_code);
            assert_eq!(after.body, before.body);
            assert_eq!(after.http_headers, before.http_headers);
        }
        let cached = &back.composite_response[4];
        assert!(cached.is_success());
        assert_eq!(
            cached
                .http_headers
                .get("ETag")
                .and_then(|v| v.to_str().ok()),
            Some("\"f2293620\"")
        );
    }

    #[test]
    fn bulk_ingest_job_serializes_its_wire_names_and_reads_back() {
        let fixture = bulk_ingest_open_job_example();
        let parsed: BulkIngestJob = serde_json::from_value(fixture.clone()).unwrap();

        let written = serde_json::to_value(&parsed).unwrap();
        for (key, value) in fixture.as_object().unwrap() {
            assert_eq!(&written[key], value, "{key}");
        }
        assert_eq!(written["columnDelimiter"], "COMMA");
        assert!(written.get("created_by_id").is_none());

        let back: BulkIngestJob = serde_json::from_value(written).unwrap();
        assert_eq!(back.id, parsed.id);
        assert_eq!(back.operation, BulkOperation::Insert);
        assert_eq!(back.state, BulkJobState::Open);
        assert_eq!(back.column_delimiter, BulkColumnDelimiter::Comma);
        assert_eq!(back.api_version, 67.0);
        assert_eq!(back.content_url, parsed.content_url);
    }

    /// SOURCE: https://developer.salesforce.com/docs/platform/api-asynch/guide/query-get-all-jobs.html
    /// A Bulk API 1.0 job in a listing types `apiVersion` as a string
    /// (https://developer.salesforce.com/docs/platform/api-asynch/guide/asynch-api-reference-jobinfo.html),
    /// which a summary reads as a number and writes as one.
    #[test]
    fn bulk_job_summary_writes_api_version_as_a_number_it_reads_back() {
        let list: BulkJobList = serde_json::from_value(json!({
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
        }))
        .unwrap();

        let written = serde_json::to_value(&list).unwrap();
        let record = &written["records"][0];
        assert_eq!(record["apiVersion"], 66.0);
        assert_eq!(record["jobType"], "Classic");
        assert_eq!(record["concurrencyMode"], "Parallel");

        let back: BulkJobList = serde_json::from_value(written).unwrap();
        assert_eq!(back.records[0].api_version, 66.0);
        assert_eq!(back.records[0].job_type, Some(BulkJobType::Classic));
        assert!(back.done);
    }

    /// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/dome_limits.htm
    /// The `PermissionSets` entry of its "Example response body".
    #[test]
    fn nested_limits_serialize_their_sub_limits_at_the_top_level() {
        let fixture = json!({
            "Max": 1500,
            "Remaining": 1499,
            "CreateCustom": {"Max": 1000, "Remaining": 999}
        });
        let parsed: Limit = serde_json::from_value(fixture.clone()).unwrap();

        let written = serde_json::to_value(&parsed).unwrap();
        assert_eq!(written, fixture);
        let back: Limit = serde_json::from_value(written).unwrap();
        assert_eq!(back.nested["CreateCustom"].remaining, 999);
    }

    /// Wire-shape provenance: see the comment above `ExecuteAnonymousResult`.
    #[test]
    fn execute_anonymous_result_serializes_its_wire_names() {
        let fixture = json!({
            "compiled": true,
            "compileProblem": null,
            "success": true,
            "line": -1,
            "column": -1,
            "exceptionMessage": null,
            "exceptionStackTrace": null
        });
        let parsed: ExecuteAnonymousResult = serde_json::from_value(fixture.clone()).unwrap();

        let written = serde_json::to_value(&parsed).unwrap();
        assert_eq!(written, fixture);
        let back: ExecuteAnonymousResult = serde_json::from_value(written).unwrap();
        assert_eq!(back.line, -1);
        assert!(back.exception_message.is_none());
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
