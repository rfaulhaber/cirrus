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

use crate::error::{MetadataError, MetadataResult};
use serde::{Deserialize, Serialize};

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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
///
/// `#[non_exhaustive]`, like [`DeployStatus`]: match with a `_` arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AsyncRequestState {
    /// The call has not started; it is waiting in a queue.
    Queued,
    /// The call has started but has not completed.
    InProgress,
    /// The call has completed.
    Completed,
    /// An error occurred; [`AsyncResult::status_code`] and
    /// [`AsyncResult::message`] describe it.
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
/// Serializes and deserializes under the camelCase names of the
/// Metadata API's `DeployOptions` (`checkOnly`, `runTests`,
/// `testLevel`, …), the same keys the REST `DeployOptions` in `cirrus`
/// uses, so one configuration struct can feed either client. Absent
/// keys take the field defaults.
///
/// [DeployOptions docs]: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_deploy.htm
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DeployOptions {
    /// If `true`, the deployment proceeds even if files listed in
    /// `package.xml` are missing from the zip. **Don't set on
    /// production deploys.**
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_missing_files: Option<bool>,
    /// Whether a file that's in the zip but not listed in
    /// `package.xml` is automatically added to the package. A
    /// `retrieve()` is issued with the updated `package.xml` that
    /// includes the file. **Don't set on production deploys.**
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_update_package: Option<bool>,
    /// If `true`, performs a test deployment (validation) without
    /// actually committing the components. Pair with
    /// `test_level: RunLocalTests` to qualify the result for
    /// `deploy_recent_validation`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub check_only: Option<bool>,
    /// Continue on warnings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ignore_warnings: Option<bool>,
    /// Whether a `retrieve()` runs immediately after the deployment.
    /// Set `true` to retrieve whatever was deployed; its outcome
    /// arrives in [`DeployDetails::retrieve_result`], which
    /// `check_deploy_status` populates only when called with
    /// `include_details: true`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub perform_retrieve: Option<bool>,
    /// In dev/sandbox orgs only: skip the Recycle Bin when deleting
    /// components listed in `destructiveChanges.xml`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purge_on_delete: Option<bool>,
    /// Required `true` for production deployments — roll back the
    /// whole job on any failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rollback_on_error: Option<bool>,
    /// Specific Apex test class names to run, one per entry; a name may
    /// carry a namespace with dot notation. Requires
    /// `test_level: Some(TestLevel::RunSpecifiedTests)`: Salesforce
    /// rejects the deploy under any other level, so [`deploy`] refuses a
    /// non-empty list paired with another level with
    /// [`MetadataError::InvalidArgument`] before uploading the zip.
    ///
    /// [`deploy`]: crate::MetadataClient::deploy
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub run_tests: Vec<String>,
    /// `true` if the zip is a single package; `false` for a set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub single_package: Option<bool>,
    /// How aggressively to run tests during deployment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_level: Option<TestLevel>,
}

/// How much of the org's Apex test suite to run during a deployment.
///
/// Each variant is named after its wire literal: [`as_str`](Self::as_str)
/// and `Display` give the literal, `FromStr` parses one (case-sensitive,
/// as the API is) and the serde derives use it, so a value read from a
/// configuration file or a command line needs no hand-written mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TestLevel {
    /// No tests. Sandbox/dev only.
    NoTestRun,
    /// Only the classes listed in [`DeployOptions::run_tests`].
    RunSpecifiedTests,
    /// (Beta) Salesforce-selected relevant tests.
    RunRelevantTests,
    /// All tests in the org except those from installed managed and
    /// unlocked packages. Default for production deploys that include
    /// Apex classes or triggers.
    RunLocalTests,
    /// Every test in the org including managed-package ones.
    RunAllTestsInOrg,
}

impl TestLevel {
    /// Every level, in the order the deploy() documentation lists them,
    /// for `FromStr` and its error message.
    const ALL: [TestLevel; 5] = [
        Self::NoTestRun,
        Self::RunSpecifiedTests,
        Self::RunLocalTests,
        Self::RunAllTestsInOrg,
        Self::RunRelevantTests,
    ];

    /// The wire literal Salesforce uses for this level, e.g.
    /// `"RunLocalTests"`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NoTestRun => "NoTestRun",
            Self::RunSpecifiedTests => "RunSpecifiedTests",
            Self::RunRelevantTests => "RunRelevantTests",
            Self::RunLocalTests => "RunLocalTests",
            Self::RunAllTestsInOrg => "RunAllTestsInOrg",
        }
    }
}

impl std::fmt::Display for TestLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for TestLevel {
    type Err = MetadataError;

    /// Parses a wire literal such as `"RunLocalTests"`. Anything else is
    /// [`MetadataError::InvalidArgument`] naming the accepted literals.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|level| level.as_str() == s)
            .ok_or_else(|| {
                let valid: Vec<&str> = Self::ALL.iter().map(TestLevel::as_str).collect();
                MetadataError::InvalidArgument(format!(
                    "unknown test level {s:?}; expected one of {}",
                    valid.join(", ")
                ))
            })
    }
}

/// Returned by `check_deploy_status`. The headline summary of a
/// deployment.
///
/// A finished deployment is returned as a value whatever its outcome;
/// [`Self::into_result`] converts one that did not succeed into
/// [`MetadataError::DeployFailed`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeployResult {
    /// ID of the deployment job, the value `deploy()` returned in
    /// [`AsyncResult::id`].
    pub id: String,
    /// Whether the server is done processing the job. Poll until this
    /// is `true`.
    #[serde(default)]
    pub done: bool,
    /// Overall success/failure. Only meaningful once `done == true`.
    #[serde(default)]
    pub success: bool,
    /// Current state of the deployment. `None` when the response omits
    /// it.
    #[serde(default)]
    pub status: Option<DeployStatus>,
    /// Whether the deployment only checks the validity of the files
    /// without changing the org (`true`). A check-only deployment
    /// deploys no components.
    #[serde(default)]
    pub check_only: bool,
    /// Whether the deployment continues even if it generates warnings.
    /// Salesforce advises against `true` for deployments to production
    /// orgs.
    #[serde(default)]
    pub ignore_warnings: bool,
    /// Whether any failure rolls the whole deployment back (`true`).
    /// When `false`, whatever can be done without errors is performed
    /// and errors are returned for the rest. Must be `true` for a
    /// production org.
    #[serde(default)]
    pub rollback_on_error: bool,
    /// Whether Apex tests were exercised.
    #[serde(default)]
    pub run_tests_enabled: bool,

    /// Number of components deployed so far. Together with
    /// [`number_components_total`](Self::number_components_total) it
    /// estimates the deployment's progress.
    #[serde(default)]
    pub number_components_deployed: i32,
    /// Total number of components in the deployment. Together with
    /// [`number_components_deployed`](Self::number_components_deployed)
    /// it estimates the deployment's progress.
    #[serde(default)]
    pub number_components_total: i32,
    /// Number of components that generated errors during this
    /// deployment.
    #[serde(default)]
    pub number_component_errors: i32,
    /// Number of Apex tests completed so far. Together with
    /// [`number_tests_total`](Self::number_tests_total) it estimates
    /// the deployment's test progress.
    #[serde(default)]
    pub number_tests_completed: i32,
    /// Total number of Apex tests for this deployment. Not accurate
    /// until the deployment has started running tests.
    #[serde(default)]
    pub number_tests_total: i32,
    /// Number of Apex tests that generated errors during this
    /// deployment.
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

    /// Status code of the error, if one occurred during the deployment.
    /// [`error_message`](Self::error_message) carries the matching
    /// message. The values are the platform `StatusCode` literals the
    /// SOAP API Developer Guide lists.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub error_status_code: Option<String>,
    /// Message corresponding to
    /// [`error_status_code`](Self::error_status_code), if any.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub error_message: Option<String>,

    /// ID of the user who created the deployment. Available in API
    /// version 30.0 and later.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub created_by: Option<String>,
    /// Full name of the user who created the deployment. Available in
    /// API version 30.0 and later.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub created_by_name: Option<String>,
    /// When the `deploy()` call was received, as the ISO 8601
    /// `dateTime` string Salesforce sends.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub created_date: Option<String>,
    /// When the deployment process began, as an ISO 8601 `dateTime`
    /// string.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub start_date: Option<String>,
    /// When the deployment process was last updated, as an ISO 8601
    /// `dateTime` string.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub last_modified_date: Option<String>,
    /// When the deployment process ended, as an ISO 8601 `dateTime`
    /// string.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub completed_date: Option<String>,
    /// ID of the user who canceled the deployment. Available in API
    /// version 30.0 and later.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub canceled_by: Option<String>,
    /// Full name of the user who canceled the deployment. Available in
    /// API version 30.0 and later.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub canceled_by_name: Option<String>,

    /// Per-component success/failure entries. Only populated when
    /// `check_deploy_status` was called with `include_details: true`.
    #[serde(default)]
    pub details: Option<DeployDetails>,
}

impl DeployResult {
    /// Converts a finished deployment into a `Result`.
    ///
    /// Returns `Ok(self)` when [`success`](Self::success) is `true`,
    /// and otherwise [`MetadataError::DeployFailed`] carrying the whole
    /// result, so a `?` after
    /// [`wait_for_deploy`](crate::MetadataClient::wait_for_deploy)
    /// fails the caller on a `Failed`, `Canceled` or
    /// `FinalizingDeployFailed` deployment while
    /// [`details`](Self::details) stays reachable through the error.
    ///
    /// Salesforce sets `success` only once a deployment has finished
    /// successfully, so a result that is still in progress is returned
    /// as `Err` too: call this on a terminal result. Whether a
    /// `SucceededPartial` deployment counts as a success is decided by
    /// the flag Salesforce sets; match on [`status`](Self::status) to
    /// treat it differently.
    ///
    /// The error's `Display` names the status, the component and test
    /// error counts, `error_status_code` / `error_message`, and the
    /// first few component failures, test failures and coverage
    /// warnings from `details`.
    pub fn into_result(self) -> MetadataResult<Self> {
        if self.success {
            Ok(self)
        } else {
            Err(MetadataError::DeployFailed(Box::new(self)))
        }
    }

    /// One-line account of why the deployment is not a success, for
    /// the `Display` of [`MetadataError::DeployFailed`].
    pub(crate) fn failure_summary(&self) -> String {
        let mut summary = format!(
            "{} {}: status {}; {} component error(s), {} test error(s)",
            job_label("deployment", &self.id),
            outcome_phrase(self.done),
            status_label(self.status.as_ref()),
            self.number_component_errors,
            self.number_test_errors,
        );
        push_error_fields(
            &mut summary,
            self.error_status_code.as_deref(),
            self.error_message.as_deref(),
        );
        if let Some(details) = &self.details {
            let tests = details.run_test_result.as_ref();
            let problems = details
                .component_failures
                .iter()
                .map(component_failure_line)
                .chain(
                    tests
                        .into_iter()
                        .flat_map(|t| t.failures.iter().map(test_failure_line)),
                )
                .chain(
                    tests
                        .into_iter()
                        .flat_map(|t| t.code_coverage_warnings.iter().map(coverage_warning_line)),
                )
                .chain(tests.into_iter().flat_map(|t| {
                    t.flow_coverage_warnings
                        .iter()
                        .map(flow_coverage_warning_line)
                }));
            push_problems(&mut summary, problems);
        }
        summary
    }
}

/// Upper bound on the individual problems a failure summary lists. The
/// boxed result inside the error carries every one of them; the message
/// only has to say what went wrong.
const FAILURE_SUMMARY_PROBLEM_CAP: usize = 5;

fn job_label(kind: &str, id: &str) -> String {
    if id.is_empty() {
        kind.to_string()
    } else {
        format!("{kind} {id}")
    }
}

fn outcome_phrase(done: bool) -> &'static str {
    if done {
        "did not succeed"
    } else {
        "has not finished"
    }
}

fn status_label<S: std::fmt::Debug>(status: Option<&S>) -> String {
    status.map_or_else(|| "not reported".to_string(), |s| format!("{s:?}"))
}

fn push_error_fields(summary: &mut String, code: Option<&str>, message: Option<&str>) {
    match (code, message) {
        (Some(code), Some(message)) => summary.push_str(&format!("; {code}: {message}")),
        (Some(text), None) | (None, Some(text)) => summary.push_str(&format!("; {text}")),
        (None, None) => {}
    }
}

fn push_problems(summary: &mut String, problems: impl Iterator<Item = String>) {
    let mut seen = 0usize;
    for problem in problems {
        seen += 1;
        if seen <= FAILURE_SUMMARY_PROBLEM_CAP {
            summary.push_str("; ");
            summary.push_str(&problem);
        }
    }
    if seen > FAILURE_SUMMARY_PROBLEM_CAP {
        summary.push_str(&format!(
            "; and {} more",
            seen - FAILURE_SUMMARY_PROBLEM_CAP
        ));
    }
}

fn component_failure_line(message: &DeployMessage) -> String {
    let name = message
        .full_name
        .as_deref()
        .or(message.file_name.as_deref())
        .unwrap_or("(unnamed component)");
    let problem = message.problem.as_deref().unwrap_or("(no problem text)");
    match message.component_type.as_deref() {
        Some(kind) => format!("{kind} {name}: {problem}"),
        None => format!("{name}: {problem}"),
    }
}

fn test_failure_line(failure: &RunTestFailure) -> String {
    let class = failure.name.as_deref().unwrap_or("(unnamed test)");
    let message = failure.message.as_deref().unwrap_or("(no message)");
    match failure.method_name.as_deref() {
        Some(method) => format!("test {class}.{method}: {message}"),
        None => format!("test {class}: {message}"),
    }
}

fn coverage_warning_line(warning: &CodeCoverageWarning) -> String {
    let message = warning.message.as_deref().unwrap_or("(no message)");
    match warning.name.as_deref() {
        Some(name) => format!("coverage {name}: {message}"),
        None => format!("coverage: {message}"),
    }
}

fn flow_coverage_warning_line(warning: &FlowCoverageWarning) -> String {
    let message = warning.message.as_deref().unwrap_or("(no message)");
    match warning.flow_name.as_deref() {
        Some(name) => format!("flow coverage {name}: {message}"),
        None => format!("flow coverage: {message}"),
    }
}

fn retrieve_message_line(message: &RetrieveMessage) -> String {
    match message.file_name.as_deref() {
        Some(file) => format!("{file}: {}", message.problem),
        None => message.problem.clone(),
    }
}

/// State of a deployment job. See [`DeployResult::status`].
///
/// The enum is `#[non_exhaustive]`, like every wire enum here that
/// keeps an [`Unknown`](Self::Unknown) fallback: Salesforce extends
/// these sets between releases, and a literal promoted from `Unknown`
/// to a named variant has to stay an additive change. Match with a `_`
/// arm:
///
/// ```
/// use cirrus_metadata::DeployStatus;
///
/// fn label(status: DeployStatus) -> &'static str {
///     match status {
///         DeployStatus::Succeeded | DeployStatus::SucceededPartial => "ok",
///         DeployStatus::Failed
///         | DeployStatus::FinalizingDeployFailed
///         | DeployStatus::Canceled => "failed",
///         _ => "running or unrecognized",
///     }
/// }
/// assert_eq!(label(DeployStatus::Succeeded), "ok");
/// ```
///
/// Naming every variant, `Unknown` included, does not compile outside
/// this crate:
///
/// ```compile_fail
/// use cirrus_metadata::DeployStatus;
///
/// fn label(status: DeployStatus) -> &'static str {
///     match status {
///         DeployStatus::Pending
///         | DeployStatus::InProgress
///         | DeployStatus::FinalizingDeploy
///         | DeployStatus::Canceling => "running",
///         DeployStatus::Succeeded | DeployStatus::SucceededPartial => "ok",
///         DeployStatus::Failed
///         | DeployStatus::FinalizingDeployFailed
///         | DeployStatus::Canceled => "failed",
///         DeployStatus::Unknown => "unrecognized",
///     }
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum DeployStatus {
    /// The deployment is queued and has not started.
    Pending,
    /// The deployment has started and is in progress.
    InProgress,
    /// The deployment succeeded.
    Succeeded,
    /// The deployment succeeded, but some components might not have
    /// been deployed successfully. Check [`DeployResult::details`] for
    /// more.
    SucceededPartial,
    /// The deployment failed.
    Failed,
    /// The deployment is being canceled. Poll again until the status is
    /// `Canceled`.
    Canceling,
    /// The deployment was canceled.
    Canceled,
    /// The deployment has started and is in the finalizing state. A
    /// deployment in this state can't be canceled (API version 65.0 and
    /// later).
    FinalizingDeploy,
    /// The deployment failed during the finalizing state.
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
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeployDetails {
    /// Deployment errors, one entry per failed component. Filled in
    /// while the deployment is still running; the other fields fill in
    /// once it finishes.
    #[serde(default, rename = "componentFailures")]
    pub component_failures: Vec<DeployMessage>,
    /// Successful deployment details, one entry per component.
    /// Populated after the deployment finishes.
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
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeployMessage {
    /// ID of the component this entry reports on.
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
    /// Whether the component was deployed successfully.
    #[serde(default)]
    pub success: bool,
    /// Whether the deployment changed the component (`true`). `false`
    /// means the deployed component matched the one already in the org.
    #[serde(default)]
    pub changed: bool,
    /// Whether the deployment created the component (`true`). `false`
    /// means it was deleted or modified.
    #[serde(default)]
    pub created: bool,
    /// Whether the deployment deleted the component (`true`). `false`
    /// means it was new or modified.
    #[serde(default)]
    pub deleted: bool,
    /// When the deployment created the component, as an ISO 8601
    /// `dateTime` string. Available in API version 30.0 and later.
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
///
/// `#[non_exhaustive]`, like [`DeployStatus`]: match with a `_` arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum DeployProblemType {
    /// The problem is a warning. [`DeployOptions::ignore_warnings`]
    /// decides whether the deployment continues past one.
    Warning,
    /// The problem is an error.
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
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunTestsResult {
    /// Number of unit tests that were run.
    #[serde(default)]
    pub num_tests_run: i32,
    /// Number of unit tests that failed.
    #[serde(default)]
    pub num_failures: i32,
    /// Total cumulative time spent running tests, in milliseconds.
    #[serde(default)]
    pub total_time: f64,
    /// ID of the `ApexLog` created at the end of the test run.
    /// Salesforce creates it only when a trace flag is active on the
    /// user running the test or on a class or trigger being executed.
    /// Available in API version 35.0 and later.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub apex_log_id: Option<String>,
    /// One entry per test that passed.
    #[serde(default)]
    pub successes: Vec<RunTestSuccess>,
    /// One entry per test that failed.
    #[serde(default)]
    pub failures: Vec<RunTestFailure>,
    /// Code coverage of each class or trigger the tests exercised.
    #[serde(default)]
    pub code_coverage: Vec<CodeCoverageResult>,
    /// Code coverage warnings for the test run. An entry whose `name`
    /// is `None` applies to the overall code coverage rather than to
    /// one class.
    #[serde(default)]
    pub code_coverage_warnings: Vec<CodeCoverageWarning>,
    /// Coverage of each flow version the test run executed. Available
    /// in API version 44.0 and later; empty before that and when no
    /// test ran a flow.
    #[serde(default)]
    pub flow_coverage: Vec<FlowCoverageResult>,
    /// Flow coverage warnings — one per flow that fell short, plus
    /// org-wide warnings that name no flow. Available in API version
    /// 44.0 and later.
    #[serde(default)]
    pub flow_coverage_warnings: Vec<FlowCoverageWarning>,
}

/// One Apex test that passed, inside [`RunTestsResult::successes`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunTestSuccess {
    /// ID of the class that generated the success.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub id: Option<String>,
    /// Name of the class that succeeded.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub name: Option<String>,
    /// Name of the test method that succeeded.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub method_name: Option<String>,
    /// Namespace that contained the unit tests, if one is specified.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub namespace: Option<String>,
    /// Time spent running this test. Presumably milliseconds like
    /// [`RunTestsResult::total_time`] and [`RunTestFailure::time`], but
    /// the Metadata API reference gives this field no unit.
    #[serde(default)]
    pub time: f64,
    /// Whether the test method has access to organization data
    /// (`true`). Available in API version 33.0 and later.
    #[serde(default)]
    pub see_all_data: bool,
}

/// One Apex test that failed, inside [`RunTestsResult::failures`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunTestFailure {
    /// ID of the class that generated the failure.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub id: Option<String>,
    /// Name of the class that failed.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub name: Option<String>,
    /// Name of the test method that failed.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub method_name: Option<String>,
    /// Namespace that contained the class, if one was specified.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub namespace: Option<String>,
    /// The failure message.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub message: Option<String>,
    /// Stack trace for the failure.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub stack_trace: Option<String>,
    /// Time spent running tests for this failed operation, in
    /// milliseconds.
    #[serde(default)]
    pub time: f64,
    /// Whether the test method has access to organization data
    /// (`true`). Available in API version 33.0 and later.
    #[serde(default)]
    pub see_all_data: bool,
}

/// Code coverage of one Apex class or trigger, inside
/// [`RunTestsResult::code_coverage`].
///
/// The counts say how much was covered; the `CodeLocation` arrays say
/// where. `locations_not_covered` is what a CI job needs to annotate
/// the lines a failed 75% check left uncovered.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeCoverageResult {
    /// ID Salesforce gives this coverage entry, unique within the org.
    /// The reference describes it only as "the ID of the CodeLocation".
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub id: Option<String>,
    /// Name of the class or trigger covered.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub name: Option<String>,
    /// Namespace that contained the unit tests, if one is specified.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub namespace: Option<String>,
    /// Total number of code locations.
    #[serde(default)]
    pub num_locations: i32,
    /// Number of code locations no test executed.
    #[serde(default)]
    pub num_locations_not_covered: i32,
    /// Line and column of each location no test executed.
    #[serde(default)]
    pub locations_not_covered: Vec<CodeLocation>,
    /// Line and column of each location a test executed, with the
    /// execution count. Available in API version 68.0 and later.
    #[serde(default)]
    pub locations_covered: Vec<CodeLocation>,
    /// DML statement locations, with execution counts and cumulative
    /// time.
    #[serde(default)]
    pub dml_info: Vec<CodeLocation>,
    /// Method invocation locations, with execution counts and
    /// cumulative time.
    #[serde(default)]
    pub method_info: Vec<CodeLocation>,
    /// SOQL statement locations, with execution counts and cumulative
    /// time.
    #[serde(default)]
    pub soql_info: Vec<CodeLocation>,
}

/// One position in Apex source, inside the arrays of
/// [`CodeCoverageResult`].
// Wire-shape provenance: the CodeLocation table on `meta_deployresult`
// lists `column`, `line` and `numExecutions` as int and `time` as
// double. The documented "Do not use" `type` field of CodeCoverageResult
// and RunTestFailure is left out. `time` is typed like
// `RunTestSuccess::time`; whether Salesforce ever sends it blank is not
// documented.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeLocation {
    /// Column location of the Apex tested.
    #[serde(default)]
    pub column: i32,
    /// Line location of the Apex tested.
    #[serde(default)]
    pub line: i32,
    /// How many times the test run executed this location. `0` for an
    /// entry in [`CodeCoverageResult::locations_not_covered`].
    #[serde(default)]
    pub num_executions: i32,
    /// Cumulative time spent at this location, in milliseconds.
    #[serde(default)]
    pub time: f64,
}

/// Coverage of one flow version, inside
/// [`RunTestsResult::flow_coverage`]. Available in API version 44.0
/// and later.
// Wire-shape provenance: the FlowCoverageResult table on
// `meta_deployresult` types `elementsNotCovered` as `string` but
// describes it as a "List of elements", so it is modeled as a repeated
// element. `processType` is a "FlowProcessType (enumeration of type
// string)" whose set grows with the platform; the literal is kept
// rather than mapped onto a closed enum.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowCoverageResult {
    /// API names of the flow elements the test run did not execute.
    #[serde(default)]
    pub elements_not_covered: Vec<String>,
    /// ID of the flow version.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub flow_id: Option<String>,
    /// API name of the flow.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub flow_name: Option<String>,
    /// Namespace that contains the flow, if one is specified.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub flow_namespace: Option<String>,
    /// Total number of elements in the flow version.
    #[serde(default)]
    pub num_elements: i32,
    /// Number of elements the test run did not execute.
    #[serde(default)]
    pub num_elements_not_covered: i32,
    /// The flow version's process type, as Salesforce names it (for
    /// example `AutoLaunchedFlow` or `Flow`).
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub process_type: Option<String>,
}

/// A warning about flow coverage, inside
/// [`RunTestsResult::flow_coverage_warnings`]. Available in API
/// version 44.0 and later.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowCoverageWarning {
    /// ID of the flow version that generated the warning. `None` for a
    /// warning about the org's overall flow coverage.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub flow_id: Option<String>,
    /// API name of the flow that generated the warning. `None` for a
    /// warning about the org's overall flow coverage.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub flow_name: Option<String>,
    /// Namespace that contains the flow, if one was specified.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub flow_namespace: Option<String>,
    /// The message of the warning Salesforce generated.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub message: Option<String>,
}

/// A code coverage warning, inside
/// [`RunTestsResult::code_coverage_warnings`]. Describes the Apex class
/// that generated it.
// Wire-shape provenance: the `meta_deployresult` CodeCoverageWarning
// table describes `name` with the `namespace` text and `id` as "the ID
// of the CodeLocation". The field descriptions follow the SOAP API
// RunTestsResult page, whose CodeCoverageWarning table describes `id`
// and `name` as the class and states that a null `name` marks a warning
// about the overall code coverage.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeCoverageWarning {
    /// ID of the class that generated the warning.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub id: Option<String>,
    /// Name of the class that generated the warning. `None` when the
    /// warning applies to the overall code coverage.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub name: Option<String>,
    /// Namespace that contains the class, if one was specified.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub namespace: Option<String>,
    /// The message of the warning generated.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub message: Option<String>,
}

// -- Cancel ------------------------------------------------------------------

/// Returned by `cancel_deploy()`. `done == false` means the cancellation
/// is in progress; `done == true` means it landed (the deployment was
/// either still queued or cancelled successfully).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CancelDeployResult {
    /// ID of the deployment being canceled.
    pub id: String,
    /// Whether the cancellation has completed (`true`). A deployment
    /// still in the queue is canceled immediately and reports `true`;
    /// one that has started is sometimes canceled later, in which case
    /// this is `false` and `check_deploy_status` reports `Canceling`
    /// until the server transitions it to `Canceled`.
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
///
/// A finished retrieve is returned as a value whatever its outcome;
/// [`Self::into_result`] converts one that did not succeed into
/// [`MetadataError::RetrieveFailed`].
///
/// Serializing writes `zip_file` in full, where the `Debug` output
/// prints only its length, so a persisted result still decodes with
/// [`Self::zip_bytes`].
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RetrieveResult {
    /// ID of the retrieve request. `done` is the only field Salesforce
    /// documents as required on this object, so an omitted `id` reads
    /// back as an empty string rather than failing the call —
    /// including when this result arrives nested in
    /// [`DeployDetails::retrieve_result`].
    #[serde(default)]
    pub id: String,
    /// Whether the retrieve has completed. Poll until this is `true`.
    #[serde(default)]
    pub done: bool,
    /// Whether the retrieve succeeded.
    #[serde(default)]
    pub success: bool,
    /// State of the retrieve. `None` when the response omits it.
    #[serde(default)]
    pub status: Option<RetrieveStatus>,
    /// Status code of the error, if one occurred during the retrieve.
    /// [`error_message`](Self::error_message) carries the matching
    /// message.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub error_status_code: Option<String>,
    /// Descriptive message about the error, if one occurred during the
    /// retrieve.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub error_message: Option<String>,
    /// One entry per retrieved component, plus `package.xml`. The
    /// companion `-meta.xml` files are not listed: the RetrieveResult
    /// page says the array "doesn't contain information about any
    /// associated metadata files in the .zip file, only the component
    /// files and manifest file". Enumerate the decoded zip
    /// ([`zip_bytes`](Self::zip_bytes)) to get the full file set.
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

// Hand-written so `{:?}` prints the size of `zip_file` rather than its
// content: the field holds a whole base64 archive, up to tens of
// megabytes, and a log line must not carry it.
impl std::fmt::Debug for RetrieveResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetrieveResult")
            .field("id", &self.id)
            .field("done", &self.done)
            .field("success", &self.success)
            .field("status", &self.status)
            .field("error_status_code", &self.error_status_code)
            .field("error_message", &self.error_message)
            .field("file_properties", &self.file_properties)
            .field("messages", &self.messages)
            .field("zip_file_len", &self.zip_file.as_ref().map(String::len))
            .finish()
    }
}

impl RetrieveResult {
    /// Decode the `zip_file` field from base64 into raw zip bytes.
    /// Returns `Ok(None)` if no zip is present in the result, and
    /// [`MetadataError::ZipDecode`] if the payload is not valid base64.
    pub fn zip_bytes(&self) -> MetadataResult<Option<bytes::Bytes>> {
        use base64::Engine;
        match &self.zip_file {
            None => Ok(None),
            Some(b64) => Ok(Some(bytes::Bytes::from(
                base64::engine::general_purpose::STANDARD.decode(b64)?,
            ))),
        }
    }

    /// Converts a finished retrieve into a `Result`.
    ///
    /// Returns `Ok(self)` when [`success`](Self::success) is `true`,
    /// and otherwise [`MetadataError::RetrieveFailed`] carrying the
    /// whole result, so a `?` after
    /// [`wait_for_retrieve`](crate::MetadataClient::wait_for_retrieve)
    /// fails the caller on a `Failed` retrieve while
    /// [`error_status_code`](Self::error_status_code),
    /// [`error_message`](Self::error_message) and
    /// [`messages`](Self::messages) stay reachable through the error.
    /// A result that is still in progress has `success == false` as
    /// well and is returned as `Err`: call this on a terminal result.
    ///
    /// The error's `Display` names the status, `error_status_code` /
    /// `error_message`, and the first few per-file problems.
    pub fn into_result(self) -> MetadataResult<Self> {
        if self.success {
            Ok(self)
        } else {
            Err(MetadataError::RetrieveFailed(Box::new(self)))
        }
    }

    /// One-line account of why the retrieve is not a success, for the
    /// `Display` of [`MetadataError::RetrieveFailed`].
    pub(crate) fn failure_summary(&self) -> String {
        let mut summary = format!(
            "{} {}: status {}",
            job_label("retrieve", &self.id),
            outcome_phrase(self.done),
            status_label(self.status.as_ref()),
        );
        push_error_fields(
            &mut summary,
            self.error_status_code.as_deref(),
            self.error_message.as_deref(),
        );
        push_problems(
            &mut summary,
            self.messages.iter().map(retrieve_message_line),
        );
        summary
    }
}

/// State of a retrieve job. See [`RetrieveResult::status`].
///
/// `#[non_exhaustive]`, like [`DeployStatus`]: match with a `_` arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum RetrieveStatus {
    /// The retrieve has not started.
    Pending,
    /// The retrieve has started and has not finished.
    InProgress,
    /// The retrieve finished successfully.
    Succeeded,
    /// The retrieve finished with an error.
    /// [`RetrieveResult::error_message`] and
    /// [`RetrieveResult::messages`] describe it.
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
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileProperties {
    /// Name of the file this entry describes.
    /// [`full_name`](Self::full_name) is derived from it.
    pub file_name: String,
    /// The component's developer name, its unique identifier for API
    /// access. The FileProperties page describes it as based on
    /// `file_name` and limited to a letter followed by alphanumerics and
    /// single underscores, but that is the rule for a bare developer
    /// name only: namespaced (`acme__Baz`), custom (`My_Object__c`) and
    /// child-component (`Account.Industry`) names all carry other
    /// characters, so do not validate against it.
    pub full_name: String,
    /// Metadata type name, e.g. `"ApexClass"`.
    #[serde(default, rename = "type", deserialize_with = "deserialize_nil_string")]
    pub type_name: Option<String>,
    /// ID of the file.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub id: Option<String>,
    /// ID of the user who created the file.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub created_by_id: Option<String>,
    /// Name of the user who created the file.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub created_by_name: Option<String>,
    /// When the file was created, as an ISO 8601 `dateTime` string.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub created_date: Option<String>,
    /// ID of the user who last modified the file.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub last_modified_by_id: Option<String>,
    /// Name of the user who last modified the file.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub last_modified_by_name: Option<String>,
    /// When the file was last modified, as an ISO 8601 `dateTime`
    /// string.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub last_modified_date: Option<String>,
    /// Namespace prefix of the component, if any.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub namespace_prefix: Option<String>,
    /// Manageable state of the component, when it is contained in a
    /// package.
    #[serde(default)]
    pub manageable_state: Option<ManageableState>,
}

/// Distribution / lifecycle state of a packaged component.
///
/// Salesforce's `FileProperties` reference lists these literals without
/// describing them one by one, so each variant names only the literal it
/// deserializes from.
///
/// `#[non_exhaustive]`, like [`DeployStatus`]: match with a `_` arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum ManageableState {
    /// Wire literal `beta`.
    Beta,
    /// Wire literal `deleted`.
    Deleted,
    /// Wire literal `deprecated`.
    Deprecated,
    /// Wire literal `deprecatedEditable`.
    DeprecatedEditable,
    /// Wire literal `installed`.
    Installed,
    /// Wire literal `installedEditable`.
    InstalledEditable,
    /// Wire literal `released`.
    Released,
    /// Wire literal `unmanaged`.
    Unmanaged,
    /// A state literal this SDK version doesn't know. This enum rides
    /// inside every [`FileProperties`], so without a fallback a single
    /// new literal would fail deserialization of an entire
    /// `listMetadata` / retrieve response.
    #[serde(other)]
    Unknown,
}

/// Error / warning surfaced in a [`RetrieveResult`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RetrieveMessage {
    /// Name of the file in the retrieved zip where the problem
    /// occurred.
    #[serde(default, deserialize_with = "deserialize_nil_string")]
    pub file_name: Option<String>,
    /// Description of the problem that occurred.
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SaveResult {
    /// `fullName` of the component that was processed.
    #[serde(default)]
    pub full_name: String,
    /// Whether the operation succeeded for this component.
    #[serde(default)]
    pub success: bool,
    /// Per-component errors when `success == false`.
    #[serde(default)]
    pub errors: Vec<MetadataApiError>,
}

/// Per-component result for `upsertMetadata`. Same shape as
/// [`SaveResult`] plus a `created` flag that distinguishes
/// newly-inserted components from those that were updated.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpsertResult {
    /// `fullName` of the component that was created or updated, when
    /// the operation succeeded.
    #[serde(default)]
    pub full_name: String,
    /// Whether the operation succeeded for this component.
    #[serde(default)]
    pub success: bool,
    /// `true` if the upsert resulted in a newly-created component;
    /// `false` if an existing component was updated. Only meaningful
    /// when `success == true`.
    #[serde(default)]
    pub created: bool,
    /// Per-component errors when `success == false`.
    #[serde(default)]
    pub errors: Vec<MetadataApiError>,
}

/// Per-component result for `deleteMetadata`. Same shape as
/// [`SaveResult`] in API v30+.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteResult {
    /// `fullName` of the deleted component.
    #[serde(default)]
    pub full_name: String,
    /// Whether the deletion succeeded.
    #[serde(default)]
    pub success: bool,
    /// Per-component errors when `success == false`.
    #[serde(default)]
    pub errors: Vec<MetadataApiError>,
}

/// One error entry inside a CRUD result.
///
/// Distinct from [`MetadataError`] — that's the
/// transport-level enum; this is the per-component validation /
/// permission failure Salesforce attaches to a SaveResult /
/// UpsertResult / DeleteResult.
///
/// `status_code` is left as a `String` rather than an enum because
/// Salesforce ships hundreds of status codes across the platform and
/// adds new ones each release.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

    #[test]
    fn unnamed_manageable_state_writes_its_own_literal_and_reads_back_as_unknown() {
        // The literal Salesforce sent is not kept: `Unknown` serializes as
        // its own name, camelCased like the enum's other variants, and
        // parses as itself.
        let state: ManageableState = serde_json::from_str("\"brandNewState\"").unwrap();
        assert_eq!(state, ManageableState::Unknown);
        let written = serde_json::to_string(&state).unwrap();
        assert_eq!(written, "\"unknown\"");
        assert_eq!(
            serde_json::from_str::<ManageableState>(&written).unwrap(),
            ManageableState::Unknown
        );
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

    /// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_retrieveresult.htm
    /// FileProperties.manageableState is a "ManageableState (enumeration
    /// of type string)" that "Indicates the manageable state of the
    /// specified component if it's contained in a package": beta,
    /// deleted, deprecated, deprecatedEditable, installed,
    /// installedEditable, released, and unmanaged. The `Unknown`
    /// fallback would absorb a literal the enum's casing failed to
    /// match, so every documented literal is pinned here.
    #[test]
    fn manageable_state_literals_match_the_documented_set() {
        #[derive(Deserialize)]
        struct Wire {
            state: ManageableState,
        }
        fn parse(literal: &str) -> ManageableState {
            let wire: Wire =
                quick_xml::de::from_str(&format!("<Wire><state>{literal}</state></Wire>")).unwrap();
            wire.state
        }

        for (literal, expected) in [
            ("beta", ManageableState::Beta),
            ("deleted", ManageableState::Deleted),
            ("deprecated", ManageableState::Deprecated),
            ("deprecatedEditable", ManageableState::DeprecatedEditable),
            ("installed", ManageableState::Installed),
            ("installedEditable", ManageableState::InstalledEditable),
            ("released", ManageableState::Released),
            ("unmanaged", ManageableState::Unmanaged),
        ] {
            assert_eq!(parse(literal), expected, "literal {literal}");
        }
    }

    const EVERY_TEST_LEVEL: [TestLevel; 5] = [
        TestLevel::NoTestRun,
        TestLevel::RunSpecifiedTests,
        TestLevel::RunRelevantTests,
        TestLevel::RunLocalTests,
        TestLevel::RunAllTestsInOrg,
    ];

    /// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_deploy.htm
    /// DeployOptions.testLevel is a "TestLevel (enumeration of type
    /// string)" with the values NoTestRun, RunSpecifiedTests,
    /// RunLocalTests, RunAllTestsInOrg and (beta) RunRelevantTests.
    #[test]
    fn test_level_as_str_matches_doc_strings() {
        assert_eq!(TestLevel::NoTestRun.as_str(), "NoTestRun");
        assert_eq!(TestLevel::RunSpecifiedTests.as_str(), "RunSpecifiedTests");
        assert_eq!(TestLevel::RunLocalTests.as_str(), "RunLocalTests");
        assert_eq!(TestLevel::RunAllTestsInOrg.as_str(), "RunAllTestsInOrg");
        assert_eq!(TestLevel::RunRelevantTests.as_str(), "RunRelevantTests");
    }

    #[test]
    fn test_level_round_trips_through_display_and_from_str() {
        for level in EVERY_TEST_LEVEL {
            assert_eq!(level.to_string(), level.as_str());
            assert_eq!(level.as_str().parse::<TestLevel>().unwrap(), level);
        }
    }

    #[test]
    fn test_level_from_str_names_the_valid_literals_on_a_miss() {
        let err = "RunSomeTests".parse::<TestLevel>().unwrap_err();
        assert!(matches!(err, MetadataError::InvalidArgument(_)), "{err:?}");
        let msg = err.to_string();
        assert!(msg.contains("RunSomeTests"), "{msg}");
        for level in EVERY_TEST_LEVEL {
            assert!(msg.contains(level.as_str()), "{msg}");
        }
        // The literals are case-sensitive on the wire.
        assert!("runlocaltests".parse::<TestLevel>().is_err());
    }

    #[test]
    fn test_level_serializes_as_its_wire_literal() {
        #[derive(serde::Serialize, Deserialize)]
        struct Wire {
            level: TestLevel,
        }
        for level in EVERY_TEST_LEVEL {
            let xml = quick_xml::se::to_string(&Wire { level }).unwrap();
            assert!(
                xml.contains(&format!("<level>{}</level>", level.as_str())),
                "{xml}"
            );
            let back: Wire = quick_xml::de::from_str(&xml).unwrap();
            assert_eq!(back.level, level);
        }
    }

    /// `DeployOptions` reads from the same camelCase keys the REST
    /// `DeployOptions` in `cirrus` serializes, so one config struct can
    /// drive either client; absent keys take the type's defaults.
    #[test]
    fn deploy_options_deserialize_from_camel_case_keys_with_defaults() {
        let opts: DeployOptions = quick_xml::de::from_str(
            "<DeployOptions>\
               <checkOnly>true</checkOnly>\
               <runTests>AccountTest</runTests>\
               <runTests>ns.ContactTest</runTests>\
               <testLevel>RunSpecifiedTests</testLevel>\
             </DeployOptions>",
        )
        .unwrap();
        assert_eq!(opts.check_only, Some(true));
        assert_eq!(opts.rollback_on_error, None);
        assert_eq!(opts.run_tests, ["AccountTest", "ns.ContactTest"]);
        assert_eq!(opts.test_level, Some(TestLevel::RunSpecifiedTests));

        let empty: DeployOptions = quick_xml::de::from_str("<DeployOptions/>").unwrap();
        assert!(empty.run_tests.is_empty());
        assert_eq!(empty.test_level, None);

        let xml = quick_xml::se::to_string(&opts).unwrap();
        assert!(xml.contains("<checkOnly>true</checkOnly>"), "{xml}");
        assert!(
            xml.contains("<testLevel>RunSpecifiedTests</testLevel>"),
            "{xml}"
        );
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
    fn retrieve_result_debug_does_not_carry_the_zip() {
        let with_zip = |zip: String| RetrieveResult {
            id: "09S000000000001".into(),
            done: true,
            success: true,
            status: Some(RetrieveStatus::Succeeded),
            error_status_code: None,
            error_message: None,
            file_properties: vec![],
            messages: vec![],
            zip_file: Some(zip),
        };
        let small = format!("{:?}", with_zip("A".repeat(16)));
        let large = format!("{:?}", with_zip("A".repeat(4 << 20)));
        // Only the digits of the length differ.
        assert_eq!(large.len() - small.len(), "4194304".len() - "16".len());
        assert!(large.contains("zip_file_len: Some(4194304)"), "{large}");
        assert!(large.len() < 1024, "{} bytes", large.len());
        assert!(
            format!(
                "{:?}",
                MetadataError::RetrieveFailed(Box::new(with_zip("A".repeat(4 << 20))))
            )
            .len()
                < 1024
        );
    }

    #[test]
    fn retrieve_result_zip_bytes_reports_invalid_base64_as_zip_decode() {
        use std::error::Error as _;
        let r = RetrieveResult {
            id: "x".into(),
            done: true,
            success: true,
            status: Some(RetrieveStatus::Succeeded),
            error_status_code: None,
            error_message: None,
            file_properties: vec![],
            messages: vec![],
            zip_file: Some("not base64!".into()),
        };
        let err = r.zip_bytes().unwrap_err();
        assert!(matches!(err, MetadataError::ZipDecode(_)), "{err:?}");
        let source = err.source().expect("ZipDecode carries the base64 error");
        assert!(source.is::<base64::DecodeError>());
        assert_eq!(err.to_string(), "retrieved zip is not valid base64");
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

    fn deploy_result(xml: &str) -> DeployResult {
        quick_xml::de::from_str(xml).unwrap()
    }

    fn retrieve_result(xml: &str) -> RetrieveResult {
        quick_xml::de::from_str(xml).unwrap()
    }

    #[test]
    fn into_result_passes_a_successful_deploy_through() {
        let r = deploy_result(
            "<result><id>0Af1</id><done>true</done><success>true</success>\
             <status>Succeeded</status></result>",
        );
        assert_eq!(r.into_result().unwrap().id, "0Af1");
    }

    #[test]
    fn into_result_defers_to_the_success_flag_for_a_partial_deploy() {
        // Salesforce decides whether a partial deploy counts as success;
        // the method reads the flag, not the status.
        let flagged = deploy_result(
            "<result><id>0Af1</id><done>true</done><success>true</success>\
             <status>SucceededPartial</status></result>",
        );
        assert!(flagged.into_result().is_ok());
        let unflagged = deploy_result(
            "<result><id>0Af1</id><done>true</done><success>false</success>\
             <status>SucceededPartial</status></result>",
        );
        assert!(matches!(
            unflagged.into_result(),
            Err(MetadataError::DeployFailed(_))
        ));
    }

    #[test]
    fn into_result_treats_an_unfinished_deploy_as_not_succeeded() {
        let r = deploy_result(
            "<result><id>0Af1</id><done>false</done><success>false</success>\
             <status>InProgress</status></result>",
        );
        let err = r.into_result().unwrap_err();
        assert!(matches!(err, MetadataError::DeployFailed(_)));
        assert_eq!(
            err.to_string(),
            "deployment 0Af1 has not finished: status InProgress; \
             0 component error(s), 0 test error(s)"
        );
    }

    #[test]
    fn deploy_failure_summary_reports_the_error_fields_and_an_unreported_status() {
        let r = deploy_result(
            "<result><id>0Af1</id><done>true</done><success>false</success>\
             <errorStatusCode>UNKNOWN_EXCEPTION</errorStatusCode>\
             <errorMessage>An unexpected error occurred.</errorMessage></result>",
        );
        assert_eq!(
            r.into_result().unwrap_err().to_string(),
            "deployment 0Af1 did not succeed: status not reported; \
             0 component error(s), 0 test error(s); \
             UNKNOWN_EXCEPTION: An unexpected error occurred."
        );
    }

    #[test]
    fn deploy_failure_summary_lists_component_test_and_coverage_problems() {
        let r = deploy_result(
            "<result><id>0Af1</id><done>true</done><success>false</success>\
             <status>Failed</status>\
             <numberComponentErrors>1</numberComponentErrors>\
             <numberTestErrors>1</numberTestErrors>\
             <details>\
               <componentFailures>\
                 <componentType>ApexClass</componentType>\
                 <fullName>Broken</fullName>\
                 <problem>Unexpected token.</problem>\
                 <success>false</success>\
               </componentFailures>\
               <componentFailures>\
                 <fileName>objects/Thing__c.object</fileName>\
                 <problem>Invalid field.</problem>\
                 <success>false</success>\
               </componentFailures>\
               <componentSuccesses>\
                 <componentType>ApexClass</componentType>\
                 <fullName>Fine</fullName>\
                 <success>true</success>\
               </componentSuccesses>\
               <runTestResult>\
                 <numTestsRun>2</numTestsRun>\
                 <numFailures>1</numFailures>\
                 <failures>\
                   <name>BrokenTest</name>\
                   <methodName>testIt</methodName>\
                   <message>Assertion Failed</message>\
                 </failures>\
                 <codeCoverageWarnings>\
                   <message>Average test coverage is 61%, at least 75% is required.</message>\
                 </codeCoverageWarnings>\
                 <flowCoverageWarnings>\
                   <flowId>301xx00000000AB</flowId>\
                   <flowName>Lead_Routing</flowName>\
                   <message>Flow coverage is 60%, at least 75% is required.</message>\
                 </flowCoverageWarnings>\
               </runTestResult>\
             </details></result>",
        );
        assert_eq!(
            r.into_result().unwrap_err().to_string(),
            "deployment 0Af1 did not succeed: status Failed; \
             1 component error(s), 1 test error(s); \
             ApexClass Broken: Unexpected token.; \
             objects/Thing__c.object: Invalid field.; \
             test BrokenTest.testIt: Assertion Failed; \
             coverage: Average test coverage is 61%, at least 75% is required.; \
             flow coverage Lead_Routing: Flow coverage is 60%, at least 75% is required."
        );
    }

    #[test]
    fn deploy_failure_summary_caps_the_listed_problems() {
        let failures: String = (1..=7)
            .map(|n| {
                format!(
                    "<componentFailures><componentType>ApexClass</componentType>\
                     <fullName>C{n}</fullName><problem>p{n}</problem>\
                     <success>false</success></componentFailures>"
                )
            })
            .collect();
        let r = deploy_result(&format!(
            "<result><id>0Af1</id><done>true</done><success>false</success>\
             <status>Failed</status><numberComponentErrors>7</numberComponentErrors>\
             <details>{failures}</details></result>"
        ));
        let msg = r.into_result().unwrap_err().to_string();
        assert!(msg.contains("ApexClass C5: p5"), "{msg}");
        assert!(!msg.contains("C6"), "{msg}");
        assert!(msg.ends_with("; and 2 more"), "{msg}");
    }

    #[test]
    fn into_result_passes_a_successful_retrieve_through() {
        let r = retrieve_result(
            "<result><id>09S1</id><done>true</done><success>true</success>\
             <status>Succeeded</status><zipFile>aGVsbG8=</zipFile></result>",
        );
        let r = r.into_result().unwrap();
        assert_eq!(&r.zip_bytes().unwrap().unwrap()[..], b"hello");
    }

    #[test]
    fn retrieve_failure_summary_reports_the_error_fields_and_problems() {
        let r = retrieve_result(
            "<result><id>09S1</id><done>true</done><success>false</success>\
             <status>Failed</status>\
             <errorStatusCode>INVALID_CROSS_REFERENCE_KEY</errorStatusCode>\
             <errorMessage>An error occurred during the retrieve.</errorMessage>\
             <messages><fileName>unpackaged/package.xml</fileName>\
               <problem>No package.xml found</problem></messages>\
             <messages><problem>Something unlocated</problem></messages>\
             </result>",
        );
        let err = r.into_result().unwrap_err();
        assert!(matches!(err, MetadataError::RetrieveFailed(_)));
        assert_eq!(
            err.to_string(),
            "retrieve 09S1 did not succeed: status Failed; \
             INVALID_CROSS_REFERENCE_KEY: An error occurred during the retrieve.; \
             unpackaged/package.xml: No package.xml found; \
             Something unlocated"
        );
    }

    #[test]
    fn retrieve_failure_summary_copes_with_a_result_that_carries_no_id() {
        // `done` is the only field Salesforce documents as required.
        let r = retrieve_result("<result><done>true</done><success>false</success></result>");
        assert_eq!(
            r.into_result().unwrap_err().to_string(),
            "retrieve did not succeed: status not reported"
        );
    }

    /// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_deployresult.htm
    /// RunTestsResult carries `flowCoverage` ("FlowCoverageResult[]",
    /// API 44.0+) and `flowCoverageWarnings` ("FlowCoverageWarning[]");
    /// each CodeCoverageResult carries `locationsNotCovered`,
    /// `locationsCovered` (API 68.0+), `dmlInfo`, `methodInfo` and
    /// `soqlInfo`, all "CodeLocation[]" with `column`, `line`,
    /// `numExecutions` (int) and `time` (double). FlowCoverageResult
    /// lists `elementsNotCovered` ("List of elements ... that weren't
    /// executed"), `flowId`, `flowName`, `flowNamespace`, `numElements`,
    /// `numElementsNotCovered` and `processType`; FlowCoverageWarning
    /// lists `flowId`, `flowName` ("If the warning applies to the overall
    /// test coverage of flows within your org, this value is null"),
    /// `flowNamespace` and `message`. The page publishes no XML sample
    /// for these, so the fixture is built from the field tables.
    #[test]
    fn run_tests_result_reads_code_locations_and_flow_coverage() {
        let parsed: RunTestsResult = quick_xml::de::from_str(
            "<runTestResult>\
               <numTestsRun>1</numTestsRun>\
               <codeCoverage>\
                 <id>01pxx0000000001</id>\
                 <name>AccountService</name>\
                 <numLocations>10</numLocations>\
                 <numLocationsNotCovered>2</numLocationsNotCovered>\
                 <locationsNotCovered><column>5</column><line>12</line>\
                   <numExecutions>0</numExecutions><time>0.0</time></locationsNotCovered>\
                 <locationsNotCovered><column>9</column><line>31</line>\
                   <numExecutions>0</numExecutions><time>0.0</time></locationsNotCovered>\
                 <locationsCovered><column>1</column><line>3</line>\
                   <numExecutions>4</numExecutions><time>1.5</time></locationsCovered>\
                 <dmlInfo><column>9</column><line>20</line>\
                   <numExecutions>2</numExecutions><time>12.25</time></dmlInfo>\
                 <methodInfo><column>17</column><line>8</line>\
                   <numExecutions>4</numExecutions><time>3.0</time></methodInfo>\
                 <soqlInfo><column>21</column><line>14</line>\
                   <numExecutions>1</numExecutions><time>7.75</time></soqlInfo>\
               </codeCoverage>\
               <flowCoverage>\
                 <elementsNotCovered>Decision_1</elementsNotCovered>\
                 <elementsNotCovered>Assignment_2</elementsNotCovered>\
                 <flowId>301xx00000000AB</flowId>\
                 <flowName>Lead_Routing</flowName>\
                 <flowNamespace></flowNamespace>\
                 <numElements>6</numElements>\
                 <numElementsNotCovered>2</numElementsNotCovered>\
                 <processType>AutoLaunchedFlow</processType>\
               </flowCoverage>\
               <flowCoverageWarnings>\
                 <flowId></flowId>\
                 <flowName></flowName>\
                 <message>Flow coverage is 60%, at least 75% is required.</message>\
               </flowCoverageWarnings>\
             </runTestResult>",
        )
        .unwrap();

        let coverage = &parsed.code_coverage[0];
        assert_eq!(coverage.num_locations_not_covered, 2);
        assert_eq!(
            coverage
                .locations_not_covered
                .iter()
                .map(|l| (l.line, l.column, l.num_executions))
                .collect::<Vec<_>>(),
            vec![(12, 5, 0), (31, 9, 0)]
        );
        assert_eq!(coverage.locations_covered.len(), 1);
        assert_eq!(coverage.locations_covered[0].time, 1.5);
        assert_eq!(coverage.dml_info[0].time, 12.25);
        assert_eq!(coverage.method_info[0].num_executions, 4);
        assert_eq!(coverage.soql_info[0].line, 14);

        let flow = &parsed.flow_coverage[0];
        assert_eq!(flow.flow_id.as_deref(), Some("301xx00000000AB"));
        assert_eq!(flow.flow_name.as_deref(), Some("Lead_Routing"));
        assert_eq!(flow.flow_namespace, None);
        assert_eq!(flow.num_elements, 6);
        assert_eq!(flow.num_elements_not_covered, 2);
        assert_eq!(flow.elements_not_covered, ["Decision_1", "Assignment_2"]);
        assert_eq!(flow.process_type.as_deref(), Some("AutoLaunchedFlow"));

        let warning = &parsed.flow_coverage_warnings[0];
        assert_eq!(warning.flow_id, None);
        assert_eq!(warning.flow_name, None, "an org-wide warning names no flow");
        assert_eq!(
            warning.message.as_deref(),
            Some("Flow coverage is 60%, at least 75% is required.")
        );
    }

    #[test]
    fn run_tests_result_defaults_the_coverage_arrays_when_absent() {
        // Pre-44.0 orgs and Apex-only deploys send none of these.
        let parsed: RunTestsResult = quick_xml::de::from_str(
            "<runTestResult><numTestsRun>0</numTestsRun>\
             <codeCoverage><name>Foo</name></codeCoverage></runTestResult>",
        )
        .unwrap();
        assert!(parsed.flow_coverage.is_empty());
        assert!(parsed.flow_coverage_warnings.is_empty());
        let coverage = &parsed.code_coverage[0];
        assert!(coverage.locations_not_covered.is_empty());
        assert!(coverage.locations_covered.is_empty());
        assert!(coverage.dml_info.is_empty());
        assert!(coverage.method_info.is_empty());
        assert!(coverage.soql_info.is_empty());
    }

    /// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_deployresult.htm
    /// Elements are the "API version 29.0 and later" DeployResult table
    /// plus the DeployDetails, DeployMessage and RunTestsResult tables
    /// on the same page, with one failed component carrying a problem
    /// and its location.
    const DEPLOY_RESULT_XML: &str = "<result>\
        <id>0Af00000abcDEF</id>\
        <done>true</done>\
        <success>false</success>\
        <status>Failed</status>\
        <checkOnly>false</checkOnly>\
        <ignoreWarnings>false</ignoreWarnings>\
        <rollbackOnError>true</rollbackOnError>\
        <runTestsEnabled>true</runTestsEnabled>\
        <numberComponentsDeployed>9</numberComponentsDeployed>\
        <numberComponentsTotal>10</numberComponentsTotal>\
        <numberComponentErrors>1</numberComponentErrors>\
        <numberTestsCompleted>5</numberTestsCompleted>\
        <numberTestsTotal>5</numberTestsTotal>\
        <numberTestErrors>0</numberTestErrors>\
        <numFiles>12</numFiles>\
        <zipSize>18342211</zipSize>\
        <createdBy>005xx00000abcde</createdBy>\
        <createdByName>Stephanie</createdByName>\
        <createdDate>2026-05-28T10:00:00.000Z</createdDate>\
        <completedDate>2026-05-28T10:01:00.000Z</completedDate>\
        <details>\
          <componentFailures>\
            <componentType>ApexClass</componentType>\
            <fullName>Bar</fullName>\
            <fileName>classes/Bar.cls</fileName>\
            <success>false</success>\
            <changed>false</changed>\
            <created>false</created>\
            <deleted>false</deleted>\
            <problem>Unexpected token</problem>\
            <problemType>Error</problemType>\
            <lineNumber>4</lineNumber>\
            <columnNumber>9</columnNumber>\
          </componentFailures>\
          <componentSuccesses>\
            <componentType>ApexClass</componentType>\
            <fullName>Foo</fullName>\
            <fileName>classes/Foo.cls</fileName>\
            <success>true</success>\
            <changed>false</changed>\
            <created>true</created>\
            <deleted>false</deleted>\
          </componentSuccesses>\
          <runTestResult>\
            <numTestsRun>5</numTestsRun>\
            <numFailures>0</numFailures>\
            <totalTime>1234.5</totalTime>\
            <codeCoverage>\
              <name>Foo</name>\
              <numLocations>10</numLocations>\
              <numLocationsNotCovered>1</numLocationsNotCovered>\
              <locationsNotCovered><column>5</column><line>12</line>\
                <numExecutions>0</numExecutions><time>0.0</time></locationsNotCovered>\
            </codeCoverage>\
          </runTestResult>\
        </details>\
      </result>";

    /// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_retrieveresult.htm
    /// RetrieveResult: `fileProperties` ("information about the
    /// properties of each component in the .zip file"), `messages`, and
    /// `zipFile` ("base64Binary ... client applications must decode the
    /// base64 data to binary"). The base64 text decodes to "PKfakezipbytes".
    const RETRIEVE_RESULT_XML: &str = "<result>\
        <id>09S00000retrId</id>\
        <done>true</done>\
        <success>true</success>\
        <status>Succeeded</status>\
        <fileProperties>\
          <createdById>005xx0000</createdById>\
          <createdByName>Stephanie</createdByName>\
          <createdDate>2026-05-28T10:00:00.000Z</createdDate>\
          <fileName>unpackaged/classes/MyClass.cls</fileName>\
          <fullName>MyClass</fullName>\
          <id>01p00000abc</id>\
          <lastModifiedById>005xx0000</lastModifiedById>\
          <lastModifiedByName>Stephanie</lastModifiedByName>\
          <lastModifiedDate>2026-05-28T10:00:00.000Z</lastModifiedDate>\
          <manageableState>unmanaged</manageableState>\
          <type>ApexClass</type>\
        </fileProperties>\
        <messages>\
          <fileName>unpackaged/package.xml</fileName>\
          <problem>Entity of type 'ApexClass' named 'Gone' cannot be found</problem>\
        </messages>\
        <zipFile>UEtmYWtlemlwYnl0ZXM=</zipFile>\
      </result>";

    fn assert_serialize<T: Serialize>() {}

    #[test]
    fn every_result_struct_is_serialize() {
        assert_serialize::<AsyncResult>();
        assert_serialize::<AsyncRequestState>();
        assert_serialize::<DeployResult>();
        assert_serialize::<DeployStatus>();
        assert_serialize::<DeployDetails>();
        assert_serialize::<DeployMessage>();
        assert_serialize::<DeployProblemType>();
        assert_serialize::<RunTestsResult>();
        assert_serialize::<RunTestSuccess>();
        assert_serialize::<RunTestFailure>();
        assert_serialize::<CodeCoverageResult>();
        assert_serialize::<CodeLocation>();
        assert_serialize::<FlowCoverageResult>();
        assert_serialize::<FlowCoverageWarning>();
        assert_serialize::<CodeCoverageWarning>();
        assert_serialize::<CancelDeployResult>();
        assert_serialize::<RetrieveResult>();
        assert_serialize::<RetrieveStatus>();
        assert_serialize::<FileProperties>();
        assert_serialize::<ManageableState>();
        assert_serialize::<RetrieveMessage>();
        assert_serialize::<DescribeMetadataResult>();
        assert_serialize::<DescribeMetadataObject>();
        assert_serialize::<DescribeValueTypeResult>();
        assert_serialize::<ValueTypeField>();
        assert_serialize::<PicklistEntry>();
        assert_serialize::<SaveResult>();
        assert_serialize::<UpsertResult>();
        assert_serialize::<DeleteResult>();
        assert_serialize::<MetadataApiError>();
    }

    #[test]
    fn deploy_result_serializes_its_wire_names_and_reads_back() {
        let parsed = deploy_result(DEPLOY_RESULT_XML);

        let written = serde_json::to_value(&parsed).unwrap();
        assert_eq!(written["id"], "0Af00000abcDEF");
        assert_eq!(written["status"], "Failed");
        assert_eq!(written["numberComponentsDeployed"], 9);
        assert_eq!(written["rollbackOnError"], true);
        assert_eq!(written["zipSize"], 18_342_211);
        assert_eq!(written["createdByName"], "Stephanie");
        assert!(written.get("number_components_deployed").is_none());
        // A member the response left out is written as null, which
        // reads back as absent.
        assert!(written["stateDetail"].is_null());
        let details = &written["details"];
        assert_eq!(details["componentFailures"][0]["problemType"], "Error");
        assert_eq!(details["componentFailures"][0]["lineNumber"], 4);
        assert_eq!(details["runTestResult"]["numTestsRun"], 5);
        assert_eq!(
            details["runTestResult"]["codeCoverage"][0]["locationsNotCovered"][0]["line"],
            12
        );

        let back: DeployResult = serde_json::from_value(written).unwrap();
        assert_eq!(back.id, parsed.id);
        assert!(back.done);
        assert!(!back.success);
        assert_eq!(back.status, Some(DeployStatus::Failed));
        assert_eq!(back.num_files, 12);
        assert_eq!(back.zip_size, 18_342_211);
        assert_eq!(back.state_detail, None);
        assert_eq!(back.created_by_name.as_deref(), Some("Stephanie"));
        let back_details = back.details.unwrap();
        assert_eq!(back_details.component_successes.len(), 1);
        let failure = &back_details.component_failures[0];
        assert_eq!(failure.problem_type, Some(DeployProblemType::Error));
        assert_eq!(failure.line_number, Some(4));
        let tests = back_details.run_test_result.unwrap();
        assert_eq!(tests.num_tests_run, 5);
        assert_eq!(tests.code_coverage[0].locations_not_covered[0].column, 5);
    }

    #[test]
    fn retrieve_result_serializes_the_zip_with_its_wire_names_and_reads_back() {
        let parsed = retrieve_result(RETRIEVE_RESULT_XML);

        let written = serde_json::to_value(&parsed).unwrap();
        assert_eq!(written["zipFile"], "UEtmYWtlemlwYnl0ZXM=");
        assert_eq!(written["status"], "Succeeded");
        let file = &written["fileProperties"][0];
        assert_eq!(file["type"], "ApexClass");
        assert_eq!(file["fullName"], "MyClass");
        assert_eq!(file["manageableState"], "unmanaged");
        assert!(file.get("type_name").is_none());
        assert_eq!(written["messages"][0]["fileName"], "unpackaged/package.xml");

        let back: RetrieveResult = serde_json::from_value(written).unwrap();
        assert_eq!(back.id, "09S00000retrId");
        assert_eq!(back.status, Some(RetrieveStatus::Succeeded));
        assert_eq!(
            back.file_properties[0].type_name.as_deref(),
            Some("ApexClass")
        );
        assert_eq!(
            back.file_properties[0].manageable_state,
            Some(ManageableState::Unmanaged)
        );
        assert_eq!(back.messages.len(), 1);
        assert_eq!(&back.zip_bytes().unwrap().unwrap()[..], b"PKfakezipbytes");
    }
}
