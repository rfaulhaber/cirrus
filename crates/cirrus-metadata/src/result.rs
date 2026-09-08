//! Typed wire envelopes for the file-based Metadata API operations.
//!
//! Every struct here is a platform contract — its shape is defined by
//! the Salesforce Metadata API and shipped per the field tables in the
//! [Metadata API Developer Guide]. Caller-controlled metadata
//! components (CustomObject XML, ApexClass source, etc.) are *not*
//! modeled — they belong in opaque zip payloads on deploy and arrive
//! as base64-encoded zip bytes on retrieve.
//!
//! ## Forward compatibility
//!
//! Salesforce adds fields to these envelopes every release. We
//! deliberately:
//!
//! - use `#[serde(default)]` on every optional / list field, and
//! - omit `#[serde(deny_unknown_fields)]`,
//!
//! so a response carrying new fields deserializes cleanly into the old
//! struct rather than failing the call. The cost is that genuinely
//! malformed responses degrade silently; the trade-off is worth it for
//! a long-running SDK.
//!
//! [Metadata API Developer Guide]: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/

use serde::Deserialize;

/// Adapter that maps blank strings to `None`.
///
/// Salesforce encodes a null `Option<String>` as either an empty
/// `<field></field>` element or a self-closing `<field xsi:nil="true"/>`,
/// and both reach serde as `Some("")`. quick-xml does honor `xsi:nil`,
/// but only where the `xsi` prefix is declared in scope — and the
/// prefix is declared on the SOAP envelope, which sits outside the
/// response element the transport hands to the deserializer. Without
/// this adapter, code branching on `.is_none()` would see `Some("")`
/// for unnamespaced components, types with no file suffix, and the
/// other common absent-value cases.
///
/// Whitespace counts as blank. Character data reaches the deserializer
/// verbatim — the envelope reader deliberately leaves it untrimmed, so
/// that entity references and stored leading whitespace survive — which
/// means a pretty-printed `<field>\n  </field>` from an intermediary
/// arrives as whitespace rather than as the empty string.
///
/// Apply via `#[serde(default, deserialize_with = "deserialize_nil_string")]`
/// on every `Option<String>` field Salesforce can render blank.
fn deserialize_nil_string<'de, D>(d: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt: Option<String> = Option::deserialize(d)?;
    Ok(opt.filter(|s| !s.trim().is_empty()))
}

// -- Async kickoff envelopes -------------------------------------------------

/// Returned by `deploy()` and `retrieve()` to identify the async job.
///
/// Most fields beyond `id` are deprecated as of API v31; we keep them
/// optional for future-proofing but in practice only `id` is reliably
/// populated.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AsyncResult {
    /// ID of the deployment or retrieval job. Pass this to
    /// `check_deploy_status` / `check_retrieve_status`.
    pub id: String,
    /// Whether the job has completed. Deprecated in newer API versions
    /// (use `check_*_status` instead), kept for compatibility.
    #[serde(default)]
    pub done: bool,
    /// Job state. Deprecated in newer API versions.
    #[serde(default)]
    pub state: Option<AsyncRequestState>,
    /// Status code on error. Deprecated.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub status_code: Option<String>,
    /// Error message corresponding to `status_code`. Deprecated.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub message: Option<String>,
}

/// Lifecycle state of an async metadata call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum AsyncRequestState {
    Queued,
    InProgress,
    Completed,
    Error,
    /// A state literal this SDK version doesn't know — kept from
    /// turning the whole response into a deserialization error.
    #[serde(other)]
    Unknown,
}

// -- Deploy ------------------------------------------------------------------

/// Options for a `deploy()` call.
///
/// All fields are optional — omitted fields are not sent and Salesforce
/// applies its defaults. Pass `Default::default()` to use Salesforce's
/// defaults for everything.
///
/// See the [DeployOptions docs] for field semantics and production-deploy
/// requirements (e.g. `rollback_on_error` must be `true` for prod).
///
/// [DeployOptions docs]: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_deploy.htm
#[derive(Debug, Clone, Default)]
pub struct DeployOptions {
    /// If `true`, the deployment proceeds even if files listed in
    /// `package.xml` are missing from the zip. **Don't set on
    /// production deploys.**
    pub allow_missing_files: Option<bool>,
    /// Whether a file that's in the zip but not listed in
    /// `package.xml` is automatically added to the package. A
    /// `retrieve()` is issued with the updated `package.xml` that
    /// includes the file. **Don't set on production deploys.**
    pub auto_update_package: Option<bool>,
    /// If `true`, performs a test deployment (validation) without
    /// actually committing the components. Pair with
    /// `test_level: RunLocalTests` to qualify the result for
    /// `deploy_recent_validation`.
    pub check_only: Option<bool>,
    /// Continue on warnings.
    pub ignore_warnings: Option<bool>,
    /// Whether a `retrieve()` runs immediately after the deployment.
    /// Set `true` to retrieve whatever was deployed; its outcome
    /// arrives in [`DeployDetails::retrieve_result`], which
    /// `check_deploy_status` populates only when called with
    /// `include_details: true`.
    pub perform_retrieve: Option<bool>,
    /// In dev/sandbox orgs only: skip the Recycle Bin when deleting
    /// components listed in `destructiveChanges.xml`.
    pub purge_on_delete: Option<bool>,
    /// Required `true` for production deployments — roll back the
    /// whole job on any failure.
    pub rollback_on_error: Option<bool>,
    /// Specific Apex test class names to run. Only meaningful when
    /// `test_level` is `RunSpecifiedTests`.
    pub run_tests: Vec<String>,
    /// `true` if the zip is a single package; `false` for a set.
    pub single_package: Option<bool>,
    /// How aggressively to run tests during deployment.
    pub test_level: Option<TestLevel>,
}

/// How much of the org's Apex test suite to run during a deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestLevel {
    /// No tests. Sandbox/dev only.
    NoTestRun,
    /// Only the classes listed in [`DeployOptions::run_tests`].
    RunSpecifiedTests,
    /// (Beta) Salesforce-selected relevant tests.
    RunRelevantTests,
    /// All non-managed-package tests in the org. Default for prod
    /// deploys that contain Apex.
    RunLocalTests,
    /// Every test in the org including managed-package ones.
    RunAllTestsInOrg,
}

impl TestLevel {
    pub(crate) fn as_wire(&self) -> &'static str {
        match self {
            Self::NoTestRun => "NoTestRun",
            Self::RunSpecifiedTests => "RunSpecifiedTests",
            Self::RunRelevantTests => "RunRelevantTests",
            Self::RunLocalTests => "RunLocalTests",
            Self::RunAllTestsInOrg => "RunAllTestsInOrg",
        }
    }
}

/// Returned by `check_deploy_status`. The headline summary of a
/// deployment.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeployResult {
    pub id: String,
    /// Whether the server is done processing the job. Poll until this
    /// is `true`.
    #[serde(default)]
    pub done: bool,
    /// Overall success/failure. Only meaningful once `done == true`.
    #[serde(default)]
    pub success: bool,
    #[serde(default)]
    pub status: Option<DeployStatus>,
    #[serde(default)]
    pub check_only: bool,
    #[serde(default)]
    pub ignore_warnings: bool,
    #[serde(default)]
    pub rollback_on_error: bool,
    /// Whether Apex tests were exercised.
    #[serde(default)]
    pub run_tests_enabled: bool,

    #[serde(default)]
    pub number_components_deployed: i32,
    #[serde(default)]
    pub number_components_total: i32,
    #[serde(default)]
    pub number_component_errors: i32,
    #[serde(default)]
    pub number_tests_completed: i32,
    #[serde(default)]
    pub number_tests_total: i32,
    #[serde(default)]
    pub number_test_errors: i32,

    /// Total number of files included in this deployment. Available
    /// in API version 64.0 and later; `0` on older versions.
    #[serde(default)]
    pub num_files: i32,
    /// Size of the unzipped deployment folder, in bytes. Available in
    /// API version 64.0 and later; `0` on older versions.
    #[serde(default)]
    pub zip_size: i64,

    /// Free-form description of the in-progress component or test
    /// class.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub state_detail: Option<String>,

    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub error_status_code: Option<String>,
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub error_message: Option<String>,

    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub created_by: Option<String>,
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub created_by_name: Option<String>,
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub created_date: Option<String>,
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub start_date: Option<String>,
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub last_modified_date: Option<String>,
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub completed_date: Option<String>,
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub canceled_by: Option<String>,
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub canceled_by_name: Option<String>,

    /// Per-component success/failure entries. Only populated when
    /// `check_deploy_status` was called with `include_details: true`.
    #[serde(default)]
    pub details: Option<DeployDetails>,
}

/// State of a deployment job. See [`DeployResult::status`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum DeployStatus {
    Pending,
    InProgress,
    Succeeded,
    SucceededPartial,
    Failed,
    Canceling,
    Canceled,
    /// Newer status, post-commit phase that can't be canceled in
    /// API 65.0+.
    FinalizingDeploy,
    FinalizingDeployFailed,
    /// A status literal this SDK version doesn't know. Salesforce has
    /// extended the set before (`FinalizingDeploy` arrived in API
    /// 65.0), and a new literal must not turn every status poll into
    /// a deserialization error. Terminal-state detection is unaffected:
    /// [`wait_for_deploy`] keys off the `done` flag, not the status.
    ///
    /// [`wait_for_deploy`]: crate::MetadataClient::wait_for_deploy
    #[serde(other)]
    Unknown,
}

impl DeployStatus {
    /// True when the deploy job is finished, regardless of success.
    ///
    /// [`Unknown`](Self::Unknown) reports `false` — an unrecognized
    /// status can't be assumed finished.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded
                | Self::SucceededPartial
                | Self::Failed
                | Self::Canceled
                | Self::FinalizingDeployFailed
        )
    }
}

/// Per-component results bundled into a [`DeployResult`].
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeployDetails {
    #[serde(default, rename = "componentFailures")]
    pub component_failures: Vec<DeployMessage>,
    #[serde(default, rename = "componentSuccesses")]
    pub component_successes: Vec<DeployMessage>,
    /// Apex test results.
    #[serde(default)]
    pub run_test_result: Option<RunTestsResult>,
    /// Outcome of the `retrieve()` Salesforce runs after the deploy
    /// when [`DeployOptions::perform_retrieve`] was set. `None`
    /// otherwise.
    #[serde(default)]
    pub retrieve_result: Option<RetrieveResult>,
}

/// Per-component status entry inside [`DeployDetails`].
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeployMessage {
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub id: Option<String>,
    /// Metadata type, e.g. `ApexClass`.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub component_type: Option<String>,
    /// Component identifier (e.g. `MyClass`).
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub full_name: Option<String>,
    /// File path inside the deployed zip.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub file_name: Option<String>,
    #[serde(default)]
    pub success: bool,
    #[serde(default)]
    pub changed: bool,
    #[serde(default)]
    pub created: bool,
    #[serde(default)]
    pub deleted: bool,
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub created_date: Option<String>,
    /// Error or warning message text when `success == false` or
    /// `problem_type == Warning`.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub problem: Option<String>,
    /// Distinguishes errors from warnings.
    #[serde(default)]
    pub problem_type: Option<DeployProblemType>,
    /// Line number in a source file where the problem occurred, when
    /// applicable (Apex class compile errors, etc.).
    #[serde(default)]
    pub line_number: Option<i32>,
    /// Column number, paired with `line_number`.
    #[serde(default)]
    pub column_number: Option<i32>,
}

/// Whether a [`DeployMessage`] reports an error or a warning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum DeployProblemType {
    Warning,
    Error,
    /// A problem-type literal this SDK version doesn't know. This enum
    /// rides inside every [`DeployMessage`], so without a fallback a
    /// single new literal would fail deserialization of an entire
    /// `check_deploy_status(id, true)` response — every component
    /// success and failure with it.
    #[serde(other)]
    Unknown,
}

/// Apex test results inside [`DeployDetails`].
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunTestsResult {
    #[serde(default)]
    pub num_tests_run: i32,
    #[serde(default)]
    pub num_failures: i32,
    #[serde(default)]
    pub total_time: f64,
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub apex_log_id: Option<String>,
    #[serde(default)]
    pub successes: Vec<RunTestSuccess>,
    #[serde(default)]
    pub failures: Vec<RunTestFailure>,
    #[serde(default)]
    pub code_coverage: Vec<CodeCoverageResult>,
    #[serde(default)]
    pub code_coverage_warnings: Vec<CodeCoverageWarning>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunTestSuccess {
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub id: Option<String>,
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub name: Option<String>,
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub method_name: Option<String>,
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub namespace: Option<String>,
    #[serde(default)]
    pub time: f64,
    #[serde(default)]
    pub see_all_data: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunTestFailure {
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub id: Option<String>,
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub name: Option<String>,
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub method_name: Option<String>,
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub namespace: Option<String>,
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub message: Option<String>,
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub stack_trace: Option<String>,
    #[serde(default)]
    pub time: f64,
    #[serde(default)]
    pub see_all_data: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeCoverageResult {
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub id: Option<String>,
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub name: Option<String>,
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub namespace: Option<String>,
    #[serde(default)]
    pub num_locations: i32,
    #[serde(default)]
    pub num_locations_not_covered: i32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeCoverageWarning {
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub id: Option<String>,
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub name: Option<String>,
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub namespace: Option<String>,
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub message: Option<String>,
}

// -- Cancel ------------------------------------------------------------------

/// Returned by `cancel_deploy()`. `done == false` means the cancellation
/// is in progress; `done == true` means it landed (the deployment was
/// either still queued or cancelled successfully).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CancelDeployResult {
    pub id: String,
    #[serde(default)]
    pub done: bool,
}

// -- Retrieve ----------------------------------------------------------------

/// Input for a `retrieve()` call.
///
/// At least one of [`package_names`](Self::package_names),
/// [`specific_files`](Self::specific_files), or
/// [`unpackaged`](Self::unpackaged) should be set — otherwise there's
/// nothing to retrieve.
#[derive(Debug, Clone, Default)]
pub struct RetrieveRequest {
    /// API version for the retrieve. The version inside `package.xml`
    /// takes precedence in API v31+.
    pub api_version: String,
    /// Packaged components to retrieve by managed-package name.
    pub package_names: Vec<String>,
    /// Component types to pull dependencies for. `"Bot"` is the only
    /// value Salesforce currently allows; set it when the request
    /// includes Bot components. Available in API version 64.0 and
    /// later, and metered separately — 25 retrieves per day using this
    /// field, each covering up to 100 components.
    pub root_types_with_dependencies: Vec<String>,
    /// `true` if the result is one package (vs. a set). Required
    /// `true` when `specific_files` is non-empty.
    pub single_package: bool,
    /// Specific file paths to retrieve, e.g.
    /// `["unpackaged/classes/MyClass.cls"]`. When set, `package_names`
    /// must be empty and `single_package` must be `true` —
    /// [`retrieve`] rejects any other combination with
    /// [`MetadataError::InvalidArgument`] rather than sending it.
    ///
    /// [`retrieve`]: crate::MetadataClient::retrieve
    /// [`MetadataError::InvalidArgument`]: crate::MetadataError::InvalidArgument
    pub specific_files: Vec<String>,
    /// Unpackaged components to retrieve, expressed as a
    /// [`PackageManifest`]. Built with the same fluent API used for
    /// generating `package.xml` files — see the manifest module
    /// docs.
    ///
    /// [`PackageManifest`]: crate::PackageManifest
    pub unpackaged: Option<crate::PackageManifest>,
}

/// Returned by `check_retrieve_status`. Once `done == true` and
/// `success == true`, `zip_file` contains the retrieved zip bytes.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RetrieveResult {
    /// ID of the retrieve request. `done` is the only field Salesforce
    /// documents as required on this object, so an omitted `id` reads
    /// back as an empty string rather than failing the call —
    /// including when this result arrives nested in
    /// [`DeployDetails::retrieve_result`].
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub done: bool,
    #[serde(default)]
    pub success: bool,
    #[serde(default)]
    pub status: Option<RetrieveStatus>,
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub error_status_code: Option<String>,
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub error_message: Option<String>,
    /// Per-file properties for everything in the retrieved zip,
    /// including the manifest.
    #[serde(default)]
    pub file_properties: Vec<FileProperties>,
    /// Errors and warnings encountered during the retrieve.
    #[serde(default)]
    pub messages: Vec<RetrieveMessage>,
    /// Base64-encoded zip bytes. Use [`Self::zip_bytes`] to decode.
    /// Only populated when `done == true` and `success == true`,
    /// and only when `check_retrieve_status` was called with
    /// `include_zip == true`.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub zip_file: Option<String>,
}

impl RetrieveResult {
    /// Decode the `zip_file` field from base64 into raw zip bytes.
    /// Returns `Ok(None)` if no zip is present in the result.
    pub fn zip_bytes(&self) -> Result<Option<bytes::Bytes>, base64::DecodeError> {
        use base64::Engine;
        match &self.zip_file {
            None => Ok(None),
            Some(b64) => base64::engine::general_purpose::STANDARD
                .decode(b64)
                .map(|v| Some(bytes::Bytes::from(v))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum RetrieveStatus {
    Pending,
    InProgress,
    Succeeded,
    Failed,
    /// A status literal this SDK version doesn't know — kept from
    /// turning the whole response into a deserialization error.
    /// Terminal-state detection is unaffected: [`wait_for_retrieve`]
    /// keys off the `done` flag, not the status.
    ///
    /// [`wait_for_retrieve`]: crate::MetadataClient::wait_for_retrieve
    #[serde(other)]
    Unknown,
}

impl RetrieveStatus {
    /// True when the retrieve job is finished, regardless of success.
    ///
    /// [`Unknown`](Self::Unknown) reports `false` — an unrecognized
    /// status can't be assumed finished.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed)
    }
}

/// Properties of one file inside a retrieve result.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileProperties {
    pub file_name: String,
    pub full_name: String,
    /// Metadata type name, e.g. `"ApexClass"`.
    #[serde(default, rename = "type", deserialize_with = "deserialize_nil_string")]
    pub type_name: Option<String>,
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub id: Option<String>,
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub created_by_id: Option<String>,
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub created_by_name: Option<String>,
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub created_date: Option<String>,
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub last_modified_by_id: Option<String>,
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub last_modified_by_name: Option<String>,
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub last_modified_date: Option<String>,
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub namespace_prefix: Option<String>,
    #[serde(default)]
    pub manageable_state: Option<ManageableState>,
}

/// Distribution / lifecycle state of a packaged component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ManageableState {
    Beta,
    Deleted,
    Deprecated,
    DeprecatedEditable,
    Installed,
    InstalledEditable,
    Released,
    Unmanaged,
    /// A state literal this SDK version doesn't know. This enum rides
    /// inside every [`FileProperties`], so without a fallback a single
    /// new literal would fail deserialization of an entire
    /// `listMetadata` / retrieve response.
    #[serde(other)]
    Unknown,
}

/// Error / warning surfaced in a [`RetrieveResult`].
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RetrieveMessage {
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub file_name: Option<String>,
    pub problem: String,
}

// -- Utility ops -------------------------------------------------------------

/// One query inside a `list_metadata` call.
///
/// At most three queries may be batched per call (Salesforce server
/// limit). `type_name` is required; `folder` is needed for components
/// that live under a folder (Dashboard, Document, EmailTemplate,
/// Report).
#[derive(Debug, Clone)]
pub struct ListMetadataQuery {
    /// Metadata type, e.g. `"ApexClass"`, `"CustomObject"`.
    pub type_name: String,
    /// Folder name when querying a folder-based type. Set to `None`
    /// for top-level types.
    pub folder: Option<String>,
}

/// Returned by `describe_metadata`. Catalogs the metadata types
/// available in the target org plus a few org-wide flags useful for
/// deciding deploy behavior.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeMetadataResult {
    /// Per-type descriptors — directory name, file suffix, child types,
    /// etc. One entry per metadata type the org supports.
    #[serde(default)]
    pub metadata_objects: Vec<DescribeMetadataObject>,
    /// Namespace prefix for managed packages in this org. `None` for
    /// orgs with no namespace — Salesforce sends a blank element,
    /// which this field normalizes to `None`.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub organization_namespace: Option<String>,
    /// Whether the org allows partial deployments (`rollbackOnError`
    /// can be `false`). In practice this is the inverse of
    /// [`Self::test_required`] — production-like orgs require tests
    /// and disallow partial saves — but both fields come from the
    /// server, so trust the wire over the invariant.
    #[serde(default)]
    pub partial_save_allowed: bool,
    /// Whether Apex tests are required on deploy. See
    /// [`Self::partial_save_allowed`] for the usual relationship.
    #[serde(default)]
    pub test_required: bool,
}

/// Descriptor for one metadata type, returned inside
/// [`DescribeMetadataResult::metadata_objects`].
///
/// This is the source of truth for `package.xml` `<types><name>` values
/// and for zip directory layout — `xml_name` is what goes in the
/// manifest, `directory_name` is what the zip folder is called.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeMetadataObject {
    /// Component name as it appears in `package.xml` (and in
    /// `<types><name>`).
    pub xml_name: String,
    /// Top-level directory inside the deploy zip for components of
    /// this type.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub directory_name: Option<String>,
    /// File extension (without the leading dot) for component files.
    /// `None` for types whose components live entirely inside a
    /// `-meta.xml` file with no companion data file.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub suffix: Option<String>,
    /// Whether components of this type live in a folder
    /// (Dashboard / Document / EmailTemplate / Report).
    #[serde(default)]
    pub in_folder: bool,
    /// Whether components of this type require a companion
    /// `-meta.xml` file alongside the source file (ApexClass,
    /// Document, etc.).
    #[serde(default)]
    pub meta_file: bool,
    /// Names of child sub-component types (e.g. `CustomField` is a
    /// child of `CustomObject`). Useful for crawling a metadata graph.
    #[serde(default)]
    pub child_xml_names: Vec<String>,
}

/// Returned by `describe_value_type`. Schema-level information about
/// one specific metadata type — what fields it has, whether it supports
/// CRUD operations, etc.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeValueTypeResult {
    /// `true` if components of this type can be created via
    /// `create_metadata`.
    #[serde(default)]
    pub api_creatable: bool,
    /// `true` if components of this type can be deleted via
    /// `delete_metadata`.
    #[serde(default)]
    pub api_deletable: bool,
    /// `true` if components of this type can be read via
    /// `read_metadata`.
    #[serde(default)]
    pub api_readable: bool,
    /// `true` if components of this type can be updated via
    /// `update_metadata`.
    #[serde(default)]
    pub api_updatable: bool,
    /// Information about the parent field for types whose `fullName`
    /// embeds a parent identifier (e.g. `Account.MyField__c` for
    /// `CustomField`). `None` for types with no parent.
    #[serde(default)]
    pub parent_field: Option<ValueTypeField>,
    /// Fields of this metadata type.
    #[serde(default)]
    pub value_type_fields: Vec<ValueTypeField>,
}

/// Describes one field of a metadata type, returned inside
/// [`DescribeValueTypeResult::value_type_fields`].
///
/// Self-referential — complex fields can carry nested
/// [`fields`](Self::fields) describing their own structure (e.g. a
/// `CustomField` value type field on `CustomObject` itself has a
/// nested schema). Use [`Self::fields`] to walk the tree.
//
// Wire-shape provenance (api_meta doc page IDs):
// - `meta_describeValueTypeResult` types `foreignKeyDomain` as a
//   singular `string` in its property table, but
//   `meta_describeValueType` contradicts it twice over: the Java
//   sample iterates `field.getForeignKeyDomain()` as a collection, and
//   its printed output for `CustomObject` prints two domains
//   (`ApexPage`, `Scontrol`) for the one `customHelp` field. The
//   repeating form is modelled here because binding a repeated
//   element to a scalar fails the whole response, not just the field.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValueTypeField {
    /// Field name. `None` for the placeholder root in `parent_field`.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub name: Option<String>,
    /// XML Schema simple type name (e.g. `"boolean"`, `"double"`,
    /// `"string"`).
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub soap_type: Option<String>,
    /// `1` if the field is required, `0` otherwise. (The wire uses an
    /// XSD-style cardinality bound.)
    #[serde(default)]
    pub min_occurs: i32,
    /// Whether the field must have a non-null value.
    #[serde(default)]
    pub value_required: bool,
    /// Whether this field is the type's `fullName`.
    #[serde(default)]
    pub is_name_field: bool,
    /// Whether this field is a foreign key to another component.
    #[serde(default)]
    pub is_foreign_key: bool,
    /// Target object types when [`is_foreign_key`](Self::is_foreign_key)
    /// is true (e.g. `"Account"`, `"Opportunity"`). A single field can
    /// point at more than one type — `CustomObject.customHelp` names
    /// both `ApexPage` and `Scontrol` — so the wire emits one
    /// `<foreignKeyDomain>` element per target. Empty for fields that
    /// aren't foreign keys.
    #[serde(default)]
    pub foreign_key_domain: Vec<String>,
    /// Picklist options when this field is a picklist. Empty for
    /// non-picklist fields.
    #[serde(default)]
    pub picklist_values: Vec<PicklistEntry>,
    /// Nested fields for complex / structured value types. The wire
    /// emits multiple `<fields>` siblings, each carrying its own
    /// `ValueTypeField`.
    #[serde(default)]
    pub fields: Vec<ValueTypeField>,
}

/// One picklist option inside a [`ValueTypeField`].
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PicklistEntry {
    /// Wire value of the option.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub value: Option<String>,
    /// Display label.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub label: Option<String>,
    /// Whether this option is the default selection.
    #[serde(default)]
    pub default_value: bool,
    /// Whether the option is currently active.
    #[serde(default)]
    pub active: bool,
    /// Encoded `validFor` bitmap for dependent picklists. Salesforce
    /// emits this as base64; we surface the raw string.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub valid_for: Option<String>,
}

// -- CRUD ops ----------------------------------------------------------------

/// Per-component result for `createMetadata`, `updateMetadata`, and
/// `renameMetadata`.
///
/// `success == true` means the component was applied; `errors` is the
/// failure detail otherwise. A single call can have a mix of
/// per-component successes and failures — Salesforce's default in
/// API v34+ allows partial success.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SaveResult {
    /// `fullName` of the component that was processed.
    #[serde(default)]
    pub full_name: String,
    #[serde(default)]
    pub success: bool,
    /// Per-component errors when `success == false`.
    #[serde(default)]
    pub errors: Vec<MetadataApiError>,
}

/// Per-component result for `upsertMetadata`. Same shape as
/// [`SaveResult`] plus a `created` flag that distinguishes
/// newly-inserted components from those that were updated.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpsertResult {
    #[serde(default)]
    pub full_name: String,
    #[serde(default)]
    pub success: bool,
    /// `true` if the upsert resulted in a newly-created component;
    /// `false` if an existing component was updated. Only meaningful
    /// when `success == true`.
    #[serde(default)]
    pub created: bool,
    #[serde(default)]
    pub errors: Vec<MetadataApiError>,
}

/// Per-component result for `deleteMetadata`. Same shape as
/// [`SaveResult`] in API v30+.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteResult {
    #[serde(default)]
    pub full_name: String,
    #[serde(default)]
    pub success: bool,
    #[serde(default)]
    pub errors: Vec<MetadataApiError>,
}

/// One error entry inside a CRUD result.
///
/// Distinct from [`MetadataError`](crate::MetadataError) — that's the
/// transport-level enum; this is the per-component validation /
/// permission failure Salesforce attaches to a SaveResult /
/// UpsertResult / DeleteResult.
///
/// `status_code` is left as a `String` rather than an enum because
/// Salesforce ships hundreds of status codes across the platform and
/// adds new ones each release.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MetadataApiError {
    /// Salesforce status code identifier (e.g. `"DUPLICATE_VALUE"`,
    /// `"INVALID_FIELD"`). String-typed because the closed enum
    /// would lag behind Salesforce releases.
    #[serde(default)]
    pub status_code: String,
    /// Human-readable error message.
    #[serde(default)]
    pub message: String,
    /// Field names involved in the error, when applicable.
    #[serde(default)]
    pub fields: Vec<String>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn deploy_status_is_terminal_matches_completed_states() {
        assert!(DeployStatus::Succeeded.is_terminal());
        assert!(DeployStatus::SucceededPartial.is_terminal());
        assert!(DeployStatus::Failed.is_terminal());
        assert!(DeployStatus::Canceled.is_terminal());
        assert!(!DeployStatus::Pending.is_terminal());
        assert!(!DeployStatus::InProgress.is_terminal());
        assert!(!DeployStatus::Canceling.is_terminal());
        assert!(!DeployStatus::FinalizingDeploy.is_terminal());
    }

    #[test]
    fn retrieve_status_is_terminal_matches_succeeded_or_failed() {
        assert!(RetrieveStatus::Succeeded.is_terminal());
        assert!(RetrieveStatus::Failed.is_terminal());
        assert!(!RetrieveStatus::Pending.is_terminal());
        assert!(!RetrieveStatus::InProgress.is_terminal());
    }

    #[test]
    fn unknown_status_literals_deserialize_to_unknown_not_error() {
        // Salesforce extends these enums across API versions
        // (FinalizingDeploy arrived in 65.0); an unrecognized literal
        // must degrade to Unknown, not fail the whole response.
        #[derive(Deserialize)]
        struct Wire {
            deploy: DeployStatus,
            retrieve: RetrieveStatus,
            state: AsyncRequestState,
            manageable: ManageableState,
            problem: DeployProblemType,
        }
        let parsed: Wire = quick_xml::de::from_str(
            "<Wire>\
               <deploy>BrandNewPhase</deploy>\
               <retrieve>BrandNewPhase</retrieve>\
               <state>BrandNewPhase</state>\
               <manageable>brandNewState</manageable>\
               <problem>Info</problem>\
             </Wire>",
        )
        .unwrap();
        assert_eq!(parsed.deploy, DeployStatus::Unknown);
        assert!(!parsed.deploy.is_terminal());
        assert_eq!(parsed.retrieve, RetrieveStatus::Unknown);
        assert!(!parsed.retrieve.is_terminal());
        assert_eq!(parsed.state, AsyncRequestState::Unknown);
        assert_eq!(parsed.manageable, ManageableState::Unknown);
        assert_eq!(parsed.problem, DeployProblemType::Unknown);
    }

    /// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_deployresult.htm
    /// DeployResult.status is a "DeployStatus (enumeration of type
    /// string)" whose valid values are Pending, InProgress,
    /// FinalizingDeploy, FinalizingDeployFailed, Succeeded,
    /// SucceededPartial, Failed, Canceling, and Canceled. With
    /// `#[serde(other)]` in place a misspelled variant identifier
    /// would deserialize to `Unknown` instead of failing, so every
    /// documented literal is pinned here.
    #[test]
    fn deploy_status_literals_match_the_documented_set() {
        #[derive(Deserialize)]
        struct Wire {
            status: DeployStatus,
        }
        fn parse(literal: &str) -> DeployStatus {
            let wire: Wire =
                quick_xml::de::from_str(&format!("<Wire><status>{literal}</status></Wire>"))
                    .unwrap();
            wire.status
        }

        for (literal, expected) in [
            ("Pending", DeployStatus::Pending),
            ("InProgress", DeployStatus::InProgress),
            ("FinalizingDeploy", DeployStatus::FinalizingDeploy),
            (
                "FinalizingDeployFailed",
                DeployStatus::FinalizingDeployFailed,
            ),
            ("Succeeded", DeployStatus::Succeeded),
            ("SucceededPartial", DeployStatus::SucceededPartial),
            ("Failed", DeployStatus::Failed),
            ("Canceling", DeployStatus::Canceling),
            ("Canceled", DeployStatus::Canceled),
        ] {
            assert_eq!(parse(literal), expected, "literal {literal}");
        }
    }

    /// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_retrieveresult.htm
    /// RetrieveResult.status is a "RetrieveStatus (enumeration of type
    /// string)" whose valid values are Pending, InProgress, Succeeded,
    /// and Failed.
    #[test]
    fn retrieve_status_literals_match_the_documented_set() {
        #[derive(Deserialize)]
        struct Wire {
            status: RetrieveStatus,
        }
        fn parse(literal: &str) -> RetrieveStatus {
            let wire: Wire =
                quick_xml::de::from_str(&format!("<Wire><status>{literal}</status></Wire>"))
                    .unwrap();
            wire.status
        }

        for (literal, expected) in [
            ("Pending", RetrieveStatus::Pending),
            ("InProgress", RetrieveStatus::InProgress),
            ("Succeeded", RetrieveStatus::Succeeded),
            ("Failed", RetrieveStatus::Failed),
        ] {
            assert_eq!(parse(literal), expected, "literal {literal}");
        }
    }

    #[test]
    fn test_level_as_wire_matches_doc_strings() {
        assert_eq!(TestLevel::NoTestRun.as_wire(), "NoTestRun");
        assert_eq!(TestLevel::RunSpecifiedTests.as_wire(), "RunSpecifiedTests");
        assert_eq!(TestLevel::RunLocalTests.as_wire(), "RunLocalTests");
        assert_eq!(TestLevel::RunAllTestsInOrg.as_wire(), "RunAllTestsInOrg");
        assert_eq!(TestLevel::RunRelevantTests.as_wire(), "RunRelevantTests");
    }

    #[test]
    fn retrieve_result_decodes_zip_bytes_from_base64() {
        let r = RetrieveResult {
            id: "x".into(),
            done: true,
            success: true,
            status: Some(RetrieveStatus::Succeeded),
            error_status_code: None,
            error_message: None,
            file_properties: vec![],
            messages: vec![],
            zip_file: Some("aGVsbG8=".into()), // base64 of "hello"
        };
        let bytes = r.zip_bytes().unwrap().unwrap();
        assert_eq!(&bytes[..], b"hello");
    }

    #[test]
    fn retrieve_result_zip_bytes_returns_none_when_absent() {
        let r = RetrieveResult {
            id: "x".into(),
            done: false,
            success: false,
            status: None,
            error_status_code: None,
            error_message: None,
            file_properties: vec![],
            messages: vec![],
            zip_file: None,
        };
        assert!(r.zip_bytes().unwrap().is_none());
    }
}
