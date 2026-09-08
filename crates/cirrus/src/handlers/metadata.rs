//! Metadata REST API — the four `deployRequest` endpoints.
//!
//! Salesforce exposes a small REST slice of the Metadata API covering
//! deploy initiation, status polling, cancellation, and quick-deploy
//! of a previously validated component set. Everything else
//! (`retrieve`, `listMetadata`, `describeMetadata`, the CRUD-based
//! calls) is SOAP-only — for that, use the sibling `cirrus-metadata`
//! crate.
//!
//! All four endpoints sit under
//! `/services/data/{api_version}/metadata/deployRequest`.
//!
//! ## Wire-shape provenance
//!
//! The typed response envelopes here are modeled from the official
//! Metadata REST docs, page IDs:
//!
//! - `meta_rest_deploy` — POST initiate deploy (multipart).
//! - `meta_rest_deploy_checkstatus` — GET status (with optional
//!   `includeDetails=true`).
//! - `meta_rest_deploy_cancel` — PATCH to cancel.
//! - `meta_rest_deploy_recentvalidation` — POST quick deploy.
//!
//! The SOAP and REST shapes diverge in a few names: e.g., SOAP's
//! `DeployDetails.runTestResult` is `runTestResults` (plural) on
//! REST. We model the REST shape here, not the SOAP one.
//!
//! The `deployResult` object is not uniform across the four pages:
//! `meta_rest_deploy` shows an inner `id`, `success` and `done`, while
//! `meta_rest_deploy_checkstatus` and `meta_rest_deploy_cancel` show
//! neither an inner `id` nor those flags. Every field on
//! [`DeployResultDetails`] is therefore optional or defaulted, and the
//! deploy id is read from [`DeployRequest::id`], which all pages show.

use crate::Cirrus;
use crate::error::CirrusResult;
use serde::{Deserialize, Serialize};

impl Cirrus {
    /// Returns a handler for the Metadata REST API
    /// (`/services/data/{api_version}/metadata/...`).
    ///
    /// Only the four `deployRequest` endpoints are exposed —
    /// everything else in the Metadata API is SOAP-only and lives in
    /// the `cirrus-metadata` sibling crate.
    pub fn metadata(&self) -> MetadataHandler<'_> {
        MetadataHandler { client: self }
    }
}

/// Handler for the Metadata REST API. Returned by [`Cirrus::metadata`].
#[derive(Debug)]
pub struct MetadataHandler<'a> {
    client: &'a Cirrus,
}

impl MetadataHandler<'_> {
    /// Initiates a deployment.
    ///
    /// Calls `POST /services/data/{api_version}/metadata/deployRequest`
    /// with a `multipart/form-data` body: a `json` part carrying the
    /// `deployOptions` and a `file` part carrying the zip.
    ///
    /// Returns the new deploy request, including the `id` to use with
    /// [`check_deploy_status`](Self::check_deploy_status) and
    /// [`cancel_deploy`](Self::cancel_deploy). Salesforce responds
    /// with HTTP 201 on success.
    ///
    /// # Limits
    ///
    /// Per the Metadata API docs: up to 10,000 files per deployment;
    /// max zip size 39 MB compressed (600 MB uncompressed).
    pub async fn deploy(
        &self,
        options: &DeployOptions,
        zip: bytes::Bytes,
    ) -> CirrusResult<DeployRequest> {
        let payload = DeployRequestBody {
            deploy_options: options,
        };
        let json_bytes =
            serde_json::to_vec(&payload).map_err(crate::error::CirrusError::Serialization)?;
        self.client
            .send_multipart(
                reqwest::Method::POST,
                "metadata/deployRequest",
                "json",
                json_bytes,
                "file",
                "deploy.zip",
                "application/zip",
                zip,
            )
            .await
    }

    /// Fetches the status of a deployment.
    ///
    /// Calls `GET /services/data/{api_version}/metadata/deployRequest/{id}`.
    /// Pass `include_details = true` to populate
    /// [`DeployResultDetails::details`] with per-component results and
    /// Apex test outcomes — at the cost of a larger response body.
    pub async fn check_deploy_status(
        &self,
        deploy_id: &str,
        include_details: bool,
    ) -> CirrusResult<DeployRequest> {
        let url = self
            .client
            .versioned_segments(&["metadata", "deployRequest", deploy_id])?;
        if include_details {
            self.client
                .send_at::<_, _, ()>(
                    reqwest::Method::GET,
                    &url,
                    Some(&[("includeDetails", "true")]),
                    None,
                )
                .await
        } else {
            self.client
                .send_at(reqwest::Method::GET, &url, None::<&()>, None::<&()>)
                .await
        }
    }

    /// Requests cancellation of an in-progress deployment.
    ///
    /// Calls `PATCH /services/data/{api_version}/metadata/deployRequest/{id}`
    /// with body `{"deployResult": {"status": "Canceling"}}`. Salesforce
    /// responds with HTTP 202 (Accepted) and a status of either
    /// `Canceling` (still in flight) or `Canceled` (already landed).
    ///
    /// In API v65.0+, a deployment in `FinalizingDeploy` status cannot
    /// be canceled. In earlier versions, cancellation may race with the
    /// commit phase and partially-apply.
    pub async fn cancel_deploy(&self, deploy_id: &str) -> CirrusResult<DeployRequest> {
        let url = self
            .client
            .versioned_segments(&["metadata", "deployRequest", deploy_id])?;
        let body = CancelBody {
            deploy_result: CancelStatus {
                status: "Canceling",
            },
        };
        self.client
            .send_at(reqwest::Method::PATCH, &url, None::<&()>, Some(&body))
            .await
    }

    /// Deploys a component set that was previously validated, skipping
    /// Apex test re-execution.
    ///
    /// Calls `POST /services/data/{api_version}/metadata/deployRequest/{validatedId}`
    /// with body `{"validatedDeployRequestId": "{validatedId}"}`.
    ///
    /// **Note:** the HTTP method is `POST` — `PATCH` would create a
    /// new deployment.
    ///
    /// Salesforce responds with HTTP 201 (Created) and a *new*
    /// `id` that's distinct from `validated_deploy_request_id`.
    /// Returns 404 if no matching validation exists or if the
    /// 10-day eligibility window has expired.
    pub async fn deploy_recent_validation(
        &self,
        validated_deploy_request_id: &str,
    ) -> CirrusResult<DeployRequest> {
        let url = self.client.versioned_segments(&[
            "metadata",
            "deployRequest",
            validated_deploy_request_id,
        ])?;
        let body = RecentValidationBody {
            validated_deploy_request_id,
        };
        self.client
            .send_at(reqwest::Method::POST, &url, None::<&()>, Some(&body))
            .await
    }
}

// ---- Private request bodies ----------------------------------------------

#[derive(Serialize)]
struct DeployRequestBody<'a> {
    #[serde(rename = "deployOptions")]
    deploy_options: &'a DeployOptions,
}

#[derive(Serialize)]
struct CancelBody {
    #[serde(rename = "deployResult")]
    deploy_result: CancelStatus,
}

#[derive(Serialize)]
struct CancelStatus {
    status: &'static str,
}

#[derive(Serialize)]
struct RecentValidationBody<'a> {
    #[serde(rename = "validatedDeployRequestId")]
    validated_deploy_request_id: &'a str,
}

// ---- Public request types ------------------------------------------------

/// Options controlling a deployment.
///
/// Every field is optional; omitted fields are not sent over the wire
/// and Salesforce applies its defaults. Pass `DeployOptions::default()`
/// to take Salesforce's defaults for everything.
///
/// For production deployments, `rollback_on_error` must be `true` and
/// `allow_missing_files` should not be set — see the
/// [REST deploy docs](https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_rest_deploy.htm)
/// for the full set of constraints.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeployOptions {
    /// If `true`, the deploy continues when files listed in
    /// `package.xml` are absent from the zip. Don't set on production.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_missing_files: Option<bool>,

    /// Reserved for future use.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_update_package: Option<bool>,

    /// If `true`, validates without committing changes. Pair with a
    /// thorough `test_level` to qualify for a later quick-deploy via
    /// [`MetadataHandler::deploy_recent_validation`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub check_only: Option<bool>,

    /// If `true`, warnings don't fail the deploy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ignore_warnings: Option<bool>,

    /// Reserved for future use.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub perform_retrieve: Option<bool>,

    /// In dev/sandbox orgs only: skip the Recycle Bin when deleting
    /// components listed in `destructiveChanges.xml`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purge_on_delete: Option<bool>,

    /// Required `true` for production deployments — roll back the
    /// entire job on any failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rollback_on_error: Option<bool>,

    /// Specific Apex test class names to run. Only meaningful when
    /// `test_level` is [`TestLevel::RunSpecifiedTests`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_tests: Option<Vec<String>>,

    /// `true` if the zip is a single package; `false` for a set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub single_package: Option<bool>,

    /// How aggressively to run Apex tests during deployment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_level: Option<TestLevel>,
}

/// How much of the org's Apex test suite to run during a deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TestLevel {
    /// No tests. Sandbox/dev orgs only.
    NoTestRun,
    /// Only the classes listed in [`DeployOptions::run_tests`].
    RunSpecifiedTests,
    /// (Beta) Salesforce-selected relevant tests.
    RunRelevantTests,
    /// All non-managed-package tests in the org. Default for prod
    /// deploys that include Apex.
    RunLocalTests,
    /// Every test in the org, including managed-package tests.
    RunAllTestsInOrg,
}

// ---- Public response types -----------------------------------------------

/// The top-level shape returned by all four `deployRequest` endpoints.
///
/// The same envelope wraps both kickoff responses (where `deploy_result`
/// holds the initial status) and status-check responses (where
/// `deploy_result` carries the full progress snapshot, optionally with
/// per-component `details`).
///
/// Quick-deploy responses
/// ([`MetadataHandler::deploy_recent_validation`]) populate
/// [`validated_deploy_request_id`](Self::validated_deploy_request_id)
/// with the original validation's id and a fresh `id` for the new
/// deployment.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeployRequest {
    /// Unique id for *this* deployment. Pass it to
    /// [`MetadataHandler::check_deploy_status`] /
    /// [`MetadataHandler::cancel_deploy`].
    pub id: String,

    /// Canonical URL for this deploy request. Present on most
    /// responses; absent on the initial kickoff response.
    #[serde(default)]
    pub url: Option<String>,

    /// Present only on quick-deploy responses
    /// ([`MetadataHandler::deploy_recent_validation`]). Holds the id
    /// of the original validation that this deploy is reusing.
    #[serde(default)]
    pub validated_deploy_request_id: Option<String>,

    /// Echoes back the effective deploy options. Useful for confirming
    /// what Salesforce actually applied (defaults plus the caller's
    /// overrides). Modeled loosely as
    /// `serde_json::Value` — the response shape includes
    /// undocumented fields like `runAllTests` that drift across
    /// releases.
    #[serde(default)]
    pub deploy_options: Option<serde_json::Value>,

    /// The deployment's current state. Absent on the immediate
    /// response to a quick-deploy POST (which only echoes options +
    /// new id); populated otherwise.
    #[serde(default)]
    pub deploy_result: Option<DeployResultDetails>,
}

/// In-progress or terminal state of a deployment.
///
/// Populated inside [`DeployRequest::deploy_result`]. Status fields
/// (`number_*`) are only meaningful once the deployment has begun;
/// per-component results live in
/// [`details`](Self::details) and are only populated when the request
/// was made with `include_details: true`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeployResultDetails {
    /// Mirrors [`DeployRequest::id`] when present.
    ///
    /// The kickoff response repeats the deploy id here; the status-check
    /// and cancellation examples omit it, so treat
    /// [`DeployRequest::id`] as the authoritative source and this as a
    /// convenience echo.
    #[serde(default)]
    pub id: Option<String>,

    /// `true` once Salesforce has finished processing.
    #[serde(default)]
    pub done: bool,

    /// `true` when the deployment finished successfully. Only
    /// meaningful when `done == true`.
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

    /// Whether Apex tests were exercised. The doc has inconsistent
    /// casing across pages — the kickoff response uses
    /// `runTestsEnabled` (boolean); the checkstatus example shows
    /// `isRunTestsEnabled` (sometimes literal `null` before the
    /// deployment has started running tests). Modeled as
    /// `Option<bool>` to capture both the rename and the explicit
    /// null. We accept either field name via `serde(alias)`.
    #[serde(default, alias = "isRunTestsEnabled")]
    pub run_tests_enabled: Option<bool>,

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

    /// Free-form description of the currently-processing component
    /// or test class.
    #[serde(default)]
    pub state_detail: Option<String>,

    #[serde(default)]
    pub error_status_code: Option<String>,

    #[serde(default)]
    pub error_message: Option<String>,

    #[serde(default)]
    pub created_by: Option<String>,

    #[serde(default)]
    pub created_by_name: Option<String>,

    #[serde(default)]
    pub created_date: Option<String>,

    #[serde(default)]
    pub start_date: Option<String>,

    #[serde(default)]
    pub last_modified_date: Option<String>,

    #[serde(default)]
    pub completed_date: Option<String>,

    #[serde(default)]
    pub canceled_by: Option<String>,

    #[serde(default)]
    pub canceled_by_name: Option<String>,

    /// Per-component results. Only populated when `check_deploy_status`
    /// was called with `include_details: true`.
    #[serde(default)]
    pub details: Option<DeployResultInnerDetails>,
}

/// Per-component success/failure and test results inside a
/// [`DeployResultDetails`].
///
/// The component list is split into `component_failures` and
/// `component_successes`; runs of the deployment's Apex test suite
/// appear under `run_test_results`. Note the field name: the REST
/// surface uses `runTestResults` (plural), while the SOAP surface
/// uses `runTestResult` (singular).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeployResultInnerDetails {
    #[serde(default)]
    pub component_failures: Vec<DeployMessage>,

    #[serde(default)]
    pub component_successes: Vec<DeployMessage>,

    /// Reserved for `performRetrieve` workflows. Modeled as
    /// `serde_json::Value` since the field is documented as
    /// "Reserved for future use" on the request side and the wire
    /// shape isn't pinned.
    #[serde(default)]
    pub retrieve_result: Option<serde_json::Value>,

    #[serde(default)]
    pub run_test_results: Option<RunTestResults>,
}

/// Per-component message in a deployment's `componentFailures` or
/// `componentSuccesses` list.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeployMessage {
    #[serde(default)]
    pub id: Option<String>,

    /// Metadata type — e.g. `ApexClass`, `CustomObject`.
    #[serde(default)]
    pub component_type: Option<String>,

    /// Component identifier inside its type.
    #[serde(default)]
    pub full_name: Option<String>,

    /// Path inside the deployed zip.
    #[serde(default)]
    pub file_name: Option<String>,

    #[serde(default)]
    pub success: bool,

    #[serde(default)]
    pub changed: bool,

    #[serde(default)]
    pub created: bool,

    #[serde(default)]
    pub deleted: bool,

    #[serde(default)]
    pub created_date: Option<String>,

    /// Error or warning message text.
    #[serde(default)]
    pub problem: Option<String>,

    /// Distinguishes errors from warnings. Modeled as
    /// `String` (open enum) because Salesforce ships new
    /// problem-type codes between releases.
    #[serde(default)]
    pub problem_type: Option<String>,

    #[serde(default)]
    pub line_number: Option<i32>,

    #[serde(default)]
    pub column_number: Option<i32>,
}

/// Apex test results bundled into [`DeployResultInnerDetails`].
///
/// Individual `successes` / `failures` entries are left as
/// `serde_json::Value` — the per-test schema isn't fully pinned in
/// the REST docs, and the SOAP-side modeling in `cirrus-metadata`
/// diverges from what the REST endpoint actually returns. Callers
/// that need typed access can deserialize the value themselves.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunTestResults {
    #[serde(default)]
    pub num_run: i32,

    #[serde(default)]
    pub num_failures: i32,

    #[serde(default)]
    pub total_time: f64,

    #[serde(default)]
    pub successes: Vec<serde_json::Value>,

    #[serde(default)]
    pub failures: Vec<serde_json::Value>,
}

/// Lifecycle state of a deployment.
///
/// `FinalizingDeploy` / `FinalizingDeployFailed` were added in API
/// 65.0 — earlier API versions go straight from `InProgress` to
/// `Succeeded` / `Failed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum DeployStatus {
    Pending,
    InProgress,
    FinalizingDeploy,
    FinalizingDeployFailed,
    Succeeded,
    SucceededPartial,
    Failed,
    Canceling,
    Canceled,
    /// A status literal this SDK version doesn't know. Salesforce has
    /// extended the set before (`FinalizingDeploy` arrived in API
    /// 65.0), and a new literal must not turn every status poll into
    /// a deserialization error.
    #[serde(other)]
    Unknown,
}

impl DeployStatus {
    /// `true` once the deployment has finished — for any reason,
    /// success or failure. Callers polling
    /// [`MetadataHandler::check_deploy_status`] can stop once this
    /// returns `true`.
    ///
    /// [`Unknown`](Self::Unknown) reports `false` — an unrecognized
    /// status can't be assumed finished, so pollers should keep going
    /// (bounded by their own timeout) rather than stop early.
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::Cirrus;
    use crate::auth::StaticTokenAuth;
    use serde_json::json;
    use std::sync::Arc;
    use wiremock::matchers::{body_json, header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn fixture(uri: String) -> Cirrus {
        let auth = Arc::new(StaticTokenAuth::new("tok", uri));
        Cirrus::builder().auth(auth).build().unwrap()
    }

    #[test]
    fn unknown_deploy_status_deserializes_to_unknown_not_error() {
        // Salesforce extends the status set across API versions
        // (FinalizingDeploy arrived in 65.0); an unrecognized literal
        // must degrade to Unknown, not fail every status poll.
        let status: DeployStatus = serde_json::from_value(json!("BrandNewPhase")).unwrap();
        assert_eq!(status, DeployStatus::Unknown);
        assert!(!status.is_terminal());
    }

    /// Wire shape per the `meta_rest_deploy` example response body.
    ///
    /// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_rest_deploy.htm
    #[tokio::test]
    async fn deploy_initiates_with_multipart_and_returns_request() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/services/data/v66.0/metadata/deployRequest"))
            .and(header("authorization", "Bearer tok"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "id": "0Afxx00000001VPCAY",
                "deployOptions": {
                    "checkOnly": false,
                    "singlePackage": false,
                    "allowMissingFiles": false,
                    "performRetrieve": false,
                    "autoUpdatePackage": false,
                    "rollbackOnError": true,
                    "ignoreWarnings": false,
                    "purgeOnDelete": false,
                    "runAllTests": false
                },
                "deployResult": {
                    "id": "0Afxx00000001VPCAY",
                    "success": false,
                    "checkOnly": false,
                    "ignoreWarnings": false,
                    "rollbackOnError": true,
                    "status": "Pending",
                    "runTestsEnabled": false,
                    "done": false
                }
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let zip: bytes::Bytes = b"PK\x03\x04fake-zip-bytes".to_vec().into();
        let options = DeployOptions {
            check_only: Some(true),
            rollback_on_error: Some(true),
            test_level: Some(TestLevel::RunLocalTests),
            ..Default::default()
        };

        let req = sf.metadata().deploy(&options, zip).await.unwrap();
        assert_eq!(req.id, "0Afxx00000001VPCAY");
        let result = req.deploy_result.expect("deploy_result populated");
        // The kickoff page is the one example that echoes the id inside
        // deployResult.
        assert_eq!(result.id.as_deref(), Some("0Afxx00000001VPCAY"));
        assert_eq!(result.status, Some(DeployStatus::Pending));
        assert!(!result.done);
        // runAllTests field in deploy_options is informational; ensure
        // it's preserved untyped.
        let opts = req.deploy_options.expect("echoed options");
        assert_eq!(opts["runAllTests"], json!(false));
    }

    /// DeployOptions skips None fields and serializes camelCase per
    /// the doc's request body example.
    #[tokio::test]
    async fn deploy_options_serializes_only_set_fields() {
        let options = DeployOptions {
            check_only: Some(true),
            test_level: Some(TestLevel::RunSpecifiedTests),
            run_tests: Some(vec!["MyTestClass".into()]),
            ..Default::default()
        };
        let body = DeployRequestBody {
            deploy_options: &options,
        };
        let v = serde_json::to_value(&body).unwrap();
        let opts = &v["deployOptions"];
        assert_eq!(opts["checkOnly"], json!(true));
        assert_eq!(opts["testLevel"], json!("RunSpecifiedTests"));
        assert_eq!(opts["runTests"], json!(["MyTestClass"]));
        // Untouched fields are absent (not null).
        assert!(opts.get("allowMissingFiles").is_none());
        assert!(opts.get("rollbackOnError").is_none());
        assert!(opts.get("singlePackage").is_none());
    }

    /// Wire shape per the `meta_rest_deploy_checkstatus` example
    /// response body, with `?includeDetails=true`. The example's
    /// `deployResult` carries no inner `id`.
    ///
    /// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_rest_deploy_checkstatus.htm
    #[tokio::test]
    async fn check_deploy_status_with_details_parses_full_envelope() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/metadata/deployRequest/0Afxx00000000lWCAQ"))
            .and(query_param("includeDetails", "true"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "0Afxx00000000lWCAQ",
                "url": "https://host/services/data/v66.0/metadata/deployRequest/0Afxx00000000lWCAQ?includeDetails=true",
                "deployResult": {
                    "checkOnly": false,
                    "ignoreWarnings": false,
                    "rollbackOnError": false,
                    "status": "InProgress",
                    "numberComponentsDeployed": 10,
                    "numberComponentsTotal": 1032,
                    "numberComponentErrors": 0,
                    "numberTestsCompleted": 45,
                    "numberTestsTotal": 135,
                    "numberTestErrors": 0,
                    "details": {
                        "componentFailures": [],
                        "componentSuccesses": [],
                        "retrieveResult": null,
                        "runTestResults": {
                            "numRun": 0,
                            "successes": [],
                            "failures": []
                        }
                    },
                    "createdDate": "2017-10-10T08:22Z",
                    "startDate": "2017-10-10T08:22Z",
                    "lastModifiedDate": "2017-10-10T08:44Z",
                    "completedDate": "2017-10-10T08:44Z",
                    "errorStatusCode": null,
                    "errorMessage": null,
                    "stateDetail": "Processing Type: Apex Component",
                    "createdBy": "005xx0000001Sv1m",
                    "createdByName": "stephanie stevens",
                    "canceledBy": null,
                    "canceledByName": null,
                    "isRunTestsEnabled": false
                },
                "deployOptions": {
                    "allowMissingFiles": false,
                    "autoUpdatePackage": false,
                    "checkOnly": true,
                    "ignoreWarnings": false,
                    "performRetrieve": false,
                    "purgeOnDelete": false,
                    "rollbackOnError": false,
                    "runTests": null,
                    "singlePackage": true,
                    "testLevel": "RunAllTestsInOrg"
                }
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let req = sf
            .metadata()
            .check_deploy_status("0Afxx00000000lWCAQ", true)
            .await
            .unwrap();
        assert_eq!(req.id, "0Afxx00000000lWCAQ");
        let r = req.deploy_result.unwrap();
        assert!(r.id.is_none());
        assert_eq!(r.status, Some(DeployStatus::InProgress));
        assert_eq!(r.number_components_total, 1032);
        assert_eq!(
            r.state_detail.as_deref(),
            Some("Processing Type: Apex Component")
        );
        let details = r.details.expect("details populated");
        assert!(details.component_failures.is_empty());
        let tests = details.run_test_results.unwrap();
        assert_eq!(tests.num_run, 0);
    }

    /// Without `include_details`, the query string is omitted so
    /// Salesforce returns the lean envelope.
    #[tokio::test]
    async fn check_deploy_status_without_details_omits_query() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/services/data/v66.0/metadata/deployRequest/0Afxx00000000lWCAQ",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "0Afxx00000000lWCAQ",
                "deployResult": {
                    "status": "Succeeded",
                    "done": true,
                    "success": true
                }
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let req = sf
            .metadata()
            .check_deploy_status("0Afxx00000000lWCAQ", false)
            .await
            .unwrap();
        let r = req.deploy_result.unwrap();
        assert!(r.id.is_none());
        assert_eq!(r.status, Some(DeployStatus::Succeeded));
        assert!(r.done);
        assert!(r.success);
        assert!(r.details.is_none());
    }

    /// Wire shape per the `meta_rest_deploy_cancel` example. PATCH body
    /// is `{"deployResult": {"status": "Canceling"}}`; response is
    /// 202 Accepted with the full deploy snapshot, whose `deployResult`
    /// carries no inner `id`.
    ///
    /// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_rest_deploy_cancel.htm
    #[tokio::test]
    async fn cancel_deploy_patches_status_and_returns_snapshot() {
        let server = MockServer::start().await;

        Mock::given(method("PATCH"))
            .and(path(
                "/services/data/v66.0/metadata/deployRequest/0Afxx00000000lWCAQ",
            ))
            .and(body_json(json!({
                "deployResult": { "status": "Canceling" }
            })))
            .respond_with(ResponseTemplate::new(202).set_body_json(json!({
                "id": "0Afxx00000000lWCAQ",
                "url": "https://host/services/data/v66.0/metadata/deployRequest/0Afxx00000000lWCAQ",
                "deployResult": {
                    "checkOnly": false,
                    "ignoreWarnings": false,
                    "rollbackOnError": false,
                    "status": "Canceling",
                    "numberComponentsDeployed": 10,
                    "numberComponentsTotal": 1032,
                    "numberComponentErrors": 0,
                    "numberTestsCompleted": 45,
                    "numberTestsTotal": 135,
                    "numberTestErrors": 0,
                    "details": {
                        "componentFailures": [],
                        "componentSuccesses": [],
                        "retrieveResult": null,
                        "runTestResults": {
                            "numRun": 0,
                            "successes": [],
                            "failures": []
                        }
                    },
                    "createdDate": "2017-10-10T08:22Z",
                    "startDate": "2017-10-10T08:22Z",
                    "lastModifiedDate": "2017-10-10T08:44Z",
                    "completedDate": "2017-10-10T08:44Z",
                    "errorStatusCode": null,
                    "errorMessage": null,
                    "stateDetail": "Processing Type: Apex Component",
                    "createdBy": "005xx0000001Sv1m",
                    "createdByName": "steve stevens",
                    "canceledBy": null,
                    "canceledByName": null,
                    "isRunTestsEnabled": null
                }
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let req = sf
            .metadata()
            .cancel_deploy("0Afxx00000000lWCAQ")
            .await
            .unwrap();
        let r = req.deploy_result.unwrap();
        assert!(r.id.is_none());
        assert_eq!(r.status, Some(DeployStatus::Canceling));
    }

    /// Wire shape per the `meta_rest_deploy_recentvalidation` example.
    /// Body echoes the validated id; response includes a *new* id plus
    /// the original `validatedDeployRequestId`.
    ///
    /// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_rest_deploy_recentvalidation.htm
    #[tokio::test]
    async fn deploy_recent_validation_posts_validated_id() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path(
                "/services/data/v66.0/metadata/deployRequest/0Afxx00000000lWCAQ",
            ))
            .and(body_json(json!({
                "validatedDeployRequestId": "0Afxx00000000lWCAQ"
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "validatedDeployRequestId": "0Afxx00000000lWCAQ",
                "id": "0Afxx00000000lWMEM",
                "url": "https://host/services/data/v66.0/metadata/deployRequest/0Afxx00000000lWMEM",
                "deployOptions": {
                    "allowMissingFiles": false,
                    "autoUpdatePackage": false,
                    "checkOnly": true,
                    "ignoreWarnings": false,
                    "performRetrieve": false,
                    "purgeOnDelete": false,
                    "rollbackOnError": false,
                    "runTests": null,
                    "singlePackage": true,
                    "testLevel": "RunAllTestsInOrg"
                }
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let req = sf
            .metadata()
            .deploy_recent_validation("0Afxx00000000lWCAQ")
            .await
            .unwrap();
        // The new deploy id is distinct from the validated id.
        assert_eq!(req.id, "0Afxx00000000lWMEM");
        assert_eq!(
            req.validated_deploy_request_id.as_deref(),
            Some("0Afxx00000000lWCAQ")
        );
        // No deploy_result yet — the quick-deploy POST response only
        // includes options.
        assert!(req.deploy_result.is_none());
    }

    /// Per the doc, 404 means no matching validation (or it expired).
    #[tokio::test]
    async fn deploy_recent_validation_surfaces_404_no_match() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(
                "/services/data/v66.0/metadata/deployRequest/0Afxx99999999999",
            ))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!([{
                "errorCode": "NOT_FOUND",
                "message": "No matching deployment validation found"
            }])))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let err = sf
            .metadata()
            .deploy_recent_validation("0Afxx99999999999")
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

    /// Deploy errors come back as the standard Salesforce error array.
    #[tokio::test]
    async fn deploy_surfaces_salesforce_error_array() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/services/data/v66.0/metadata/deployRequest"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!([{
                "errorCode": "INVALID_DEPLOY_OPTIONS",
                "message": "rollbackOnError must be true for production"
            }])))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let err = sf
            .metadata()
            .deploy(&DeployOptions::default(), bytes::Bytes::from_static(b"zip"))
            .await
            .unwrap_err();
        match err {
            crate::CirrusError::Api { status, errors, .. } => {
                assert_eq!(status, 400);
                assert_eq!(errors[0].error_code, "INVALID_DEPLOY_OPTIONS");
            }
            other => panic!("expected Api error, got {other:?}"),
        }
    }

    #[test]
    fn deploy_status_is_terminal_matches_finished_states() {
        assert!(DeployStatus::Succeeded.is_terminal());
        assert!(DeployStatus::SucceededPartial.is_terminal());
        assert!(DeployStatus::Failed.is_terminal());
        assert!(DeployStatus::Canceled.is_terminal());
        assert!(DeployStatus::FinalizingDeployFailed.is_terminal());

        assert!(!DeployStatus::Pending.is_terminal());
        assert!(!DeployStatus::InProgress.is_terminal());
        assert!(!DeployStatus::FinalizingDeploy.is_terminal());
        assert!(!DeployStatus::Canceling.is_terminal());
    }
}
