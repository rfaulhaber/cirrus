//! File-based deploy / retrieve handlers.
//!
//! Each operation is a small [`SoapOperation`] implementation that
//! renders its body XML and names the response wrapper. Public methods
//! on [`MetadataClient`] wrap them with the user-facing arguments.
//!
//! ## Body XML rendering
//!
//! We hand-render bodies as strings rather than going through
//! `quick-xml`'s serde serializer. Two reasons:
//!
//! 1. The metadata namespace prefix `met:` must appear on every
//!    element inside `<met:{op}>` for Salesforce's parser. Driving that
//!    through serde rename attributes is brittle.
//! 2. We need explicit control over which fields are emitted — the
//!    server treats "absent" and "present-but-empty" differently for
//!    some fields, and serde's `skip_serializing_if` doesn't compose
//!    cleanly with quick-xml.
//!
//! The bodies are short and structurally regular, so the hand-rolled
//! code stays under a few dozen lines per operation.

use crate::envelope::xml_escape;
use crate::error::{MetadataError, MetadataResult};
use crate::result::{
    AsyncResult, CancelDeployResult, DeployOptions, DeployResult, RetrieveRequest, RetrieveResult,
};
use crate::transport::SoapOperation;
use crate::{MetadataClient, PackageManifest};
use base64::Engine;
use bytes::Bytes;
use serde::Deserialize;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

struct DeployOp {
    zip: Bytes,
    options: DeployOptions,
}

#[derive(Deserialize)]
struct DeployResponseWire {
    result: AsyncResult,
}

impl SoapOperation for DeployOp {
    const NAME: &'static str = "deploy";
    type Response = DeployResponseWire;

    fn render_body(&self) -> MetadataResult<String> {
        // The options are rendered first so their exact length is known
        // before the buffer is sized. Everything after the encoded zip
        // has to fit in the initial allocation: a reallocation here
        // would copy a buffer already holding the base64 form of a
        // documented-maximum 39 MB zip.
        let mut opts = String::new();
        render_deploy_options(&self.options, &mut opts);

        // Base64 expands to four characters per three input bytes,
        // rounded up to a whole quantum. Sizing the buffer for that up
        // front and encoding straight into it keeps the zip from being
        // materialized a second time as a standalone encoded string.
        let encoded_len = self.zip.len().div_ceil(3) * 4;
        let mut out = String::with_capacity(encoded_len + opts.len() + 128);
        out.push_str("<met:ZipFile>");
        base64::engine::general_purpose::STANDARD.encode_string(&self.zip, &mut out);
        out.push_str("</met:ZipFile><met:DeployOptions>");
        out.push_str(&opts);
        out.push_str("</met:DeployOptions>");
        Ok(out)
    }
}

struct CheckDeployStatusOp {
    async_process_id: String,
    include_details: bool,
}

#[derive(Deserialize)]
struct CheckDeployStatusResponseWire {
    result: DeployResult,
}

impl SoapOperation for CheckDeployStatusOp {
    const NAME: &'static str = "checkDeployStatus";
    // Read-only status poll: safe to replay. Keeping this retryable
    // matters — wait_for_deploy polls through it, and a transient 503
    // mid-wait would otherwise abort a long-running deploy watch.
    const IDEMPOTENT: bool = true;
    type Response = CheckDeployStatusResponseWire;

    fn render_body(&self) -> MetadataResult<String> {
        Ok(format!(
            "<met:asyncProcessId>{}</met:asyncProcessId>\
             <met:includeDetails>{}</met:includeDetails>",
            xml_escape(&self.async_process_id),
            self.include_details,
        ))
    }
}

// Wire-shape provenance (api_meta doc page IDs):
// - `meta_canceldeploy` names this argument `id` ("CancelDeployResult
//   = metadatabinding.cancelDeploy(string id)"), but that table prints
//   the Java parameter name rather than the wire element name:
//   `meta_checkdeploystatus` likewise prints `id` for the argument
//   this crate sends -- and Salesforce accepts -- as
//   `<asyncProcessId>`. The guide publishes no request envelope for
//   any call, so the element name below is carried over from the two
//   status calls rather than read off a page. Anything asserting the
//   name (the fixture in tests/file_based.rs included) is pinning that
//   inference, not a documented shape.
struct CancelDeployOp {
    async_process_id: String,
}

#[derive(Deserialize)]
struct CancelDeployResponseWire {
    result: CancelDeployResult,
}

impl SoapOperation for CancelDeployOp {
    const NAME: &'static str = "cancelDeploy";
    type Response = CancelDeployResponseWire;

    fn render_body(&self) -> MetadataResult<String> {
        Ok(format!(
            "<met:asyncProcessId>{}</met:asyncProcessId>",
            xml_escape(&self.async_process_id),
        ))
    }
}

struct DeployRecentValidationOp {
    validation_id: String,
}

#[derive(Deserialize)]
struct DeployRecentValidationResponseWire {
    /// The wire is `<result>0Aff00...</result>` — just the new deploy id.
    result: String,
}

impl SoapOperation for DeployRecentValidationOp {
    const NAME: &'static str = "deployRecentValidation";
    type Response = DeployRecentValidationResponseWire;

    fn render_body(&self) -> MetadataResult<String> {
        Ok(format!(
            "<met:validationId>{}</met:validationId>",
            xml_escape(&self.validation_id),
        ))
    }
}

struct RetrieveOp {
    request: RetrieveRequest,
}

#[derive(Deserialize)]
struct RetrieveResponseWire {
    result: AsyncResult,
}

impl SoapOperation for RetrieveOp {
    const NAME: &'static str = "retrieve";
    type Response = RetrieveResponseWire;

    fn render_body(&self) -> MetadataResult<String> {
        // RetrieveRequest derives Default, which produces an empty
        // apiVersion. The server rejects that with an opaque fault; fail
        // fast with a useful message instead.
        if self.request.api_version.is_empty() {
            return Err(MetadataError::InvalidArgument(
                "RetrieveRequest.api_version is required (e.g. \"66.0\")".into(),
            ));
        }
        // specificFiles is documented as usable only on its own: it
        // requires singlePackage true and no packageNames. Default
        // gives single_package false, so the natural
        // `..Default::default()` construction would otherwise render
        // an invalid combination.
        if !self.request.specific_files.is_empty() {
            if !self.request.single_package {
                return Err(MetadataError::InvalidArgument(
                    "RetrieveRequest.specific_files requires single_package == true".into(),
                ));
            }
            if !self.request.package_names.is_empty() {
                return Err(MetadataError::InvalidArgument(
                    "RetrieveRequest.specific_files requires an empty package_names".into(),
                ));
            }
        }
        let mut out = String::with_capacity(256);
        out.push_str("<met:RetrieveRequest>");
        out.push_str("<met:apiVersion>");
        out.push_str(&xml_escape(&self.request.api_version));
        out.push_str("</met:apiVersion>");
        for pkg in &self.request.package_names {
            out.push_str("<met:packageNames>");
            out.push_str(&xml_escape(pkg));
            out.push_str("</met:packageNames>");
        }
        write_bool(&mut out, "singlePackage", self.request.single_package);
        for f in &self.request.specific_files {
            out.push_str("<met:specificFiles>");
            out.push_str(&xml_escape(f));
            out.push_str("</met:specificFiles>");
        }
        if let Some(pkg) = &self.request.unpackaged {
            render_unpackaged(pkg, &mut out);
        }
        out.push_str("</met:RetrieveRequest>");
        Ok(out)
    }
}

struct CheckRetrieveStatusOp {
    async_process_id: String,
    include_zip: bool,
}

#[derive(Deserialize)]
struct CheckRetrieveStatusResponseWire {
    result: RetrieveResult,
}

impl SoapOperation for CheckRetrieveStatusOp {
    const NAME: &'static str = "checkRetrieveStatus";
    type Response = CheckRetrieveStatusResponseWire;

    // Replay safety depends on the argument, not the operation. With
    // includeZip false this is a status read like checkDeployStatus.
    // With it true the server serves the zip and then deletes it, so a
    // replay after the origin already answered comes back without a
    // zipFile and the retrieved payload is gone for good.
    fn idempotent(&self) -> bool {
        !self.include_zip
    }

    fn render_body(&self) -> MetadataResult<String> {
        Ok(format!(
            "<met:asyncProcessId>{}</met:asyncProcessId>\
             <met:includeZip>{}</met:includeZip>",
            xml_escape(&self.async_process_id),
            self.include_zip,
        ))
    }
}

// ---------------------------------------------------------------------------
// Render helpers
// ---------------------------------------------------------------------------

fn write_bool(out: &mut String, name: &str, value: bool) {
    out.push_str("<met:");
    out.push_str(name);
    out.push('>');
    out.push_str(if value { "true" } else { "false" });
    out.push_str("</met:");
    out.push_str(name);
    out.push('>');
}

fn write_opt_bool(out: &mut String, name: &str, value: Option<bool>) {
    if let Some(v) = value {
        write_bool(out, name, v);
    }
}

fn render_deploy_options(opts: &DeployOptions, out: &mut String) {
    // Emit in the order shown in the Metadata API Developer Guide
    // table — Salesforce's parser tolerates other orders, but emitting
    // in doc order keeps wire diffs against the published examples
    // minimal and makes the rendered XML easy to eyeball-diff.
    write_opt_bool(out, "allowMissingFiles", opts.allow_missing_files);
    write_opt_bool(out, "autoUpdatePackage", opts.auto_update_package);
    write_opt_bool(out, "checkOnly", opts.check_only);
    write_opt_bool(out, "ignoreWarnings", opts.ignore_warnings);
    write_opt_bool(out, "performRetrieve", opts.perform_retrieve);
    write_opt_bool(out, "purgeOnDelete", opts.purge_on_delete);
    write_opt_bool(out, "rollbackOnError", opts.rollback_on_error);
    for test in &opts.run_tests {
        out.push_str("<met:runTests>");
        out.push_str(&xml_escape(test));
        out.push_str("</met:runTests>");
    }
    write_opt_bool(out, "singlePackage", opts.single_package);
    if let Some(level) = opts.test_level {
        out.push_str("<met:testLevel>");
        out.push_str(level.as_wire());
        out.push_str("</met:testLevel>");
    }
}

fn render_unpackaged(pkg: &PackageManifest, out: &mut String) {
    out.push_str("<met:unpackaged>");
    out.push_str(&pkg.render_soap_inner());
    out.push_str("</met:unpackaged>");
}

// ---------------------------------------------------------------------------
// Polling
// ---------------------------------------------------------------------------

/// Configuration for [`MetadataClient::wait_for_deploy_with`] and
/// [`MetadataClient::wait_for_retrieve_with`].
///
/// Polling uses exponential backoff starting at `initial_delay`,
/// doubling each round, capped at `max_delay`. Calls don't have a
/// per-request timeout — the dispatcher's own [`RetryPolicy`] handles
/// transient failures.
///
/// [`RetryPolicy`]: crate::RetryPolicy
#[derive(Debug, Clone)]
pub struct WaitConfig {
    /// Delay between the first and second poll; the first poll is
    /// issued immediately. Doubles each round up to
    /// [`max_delay`](Self::max_delay). Default 2 s.
    pub initial_delay: Duration,
    /// Cap on the backoff delay. Default 30 s.
    pub max_delay: Duration,
    /// Total wall-clock budget. `None` = wait indefinitely. Default
    /// `None` — deploys can legitimately run for hours.
    ///
    /// Backoff sleeps are clamped to what's left of the budget, so the
    /// timeout fires within one in-flight status call of it rather
    /// than a whole backoff round past it.
    pub total_timeout: Option<Duration>,
}

impl Default for WaitConfig {
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_secs(2),
            max_delay: Duration::from_secs(30),
            total_timeout: None,
        }
    }
}

impl WaitConfig {
    /// Builder-style setter for a wall-clock timeout. Useful when you
    /// want a CI job to fail fast rather than wait hours on a stuck
    /// deploy.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.total_timeout = Some(timeout);
        self
    }
}

// ---------------------------------------------------------------------------
// Public API on MetadataClient
// ---------------------------------------------------------------------------

impl MetadataClient {
    /// Starts a metadata deployment.
    ///
    /// `zip` is the raw bytes of the deployment zip (containing
    /// `package.xml` plus the component files). The SDK base64-encodes
    /// it on the wire — pass the unencoded bytes.
    ///
    /// Returns an [`AsyncResult`] whose `id` is the deployment job ID;
    /// use [`Self::check_deploy_status`] or [`Self::wait_for_deploy`]
    /// to follow its progress.
    pub async fn deploy(&self, zip: Bytes, options: DeployOptions) -> MetadataResult<AsyncResult> {
        let op = DeployOp { zip, options };
        let resp = self.call(&op).await?;
        Ok(resp.result)
    }

    /// Fetches the current status of a deployment.
    ///
    /// `include_details` controls whether the response includes
    /// per-component success/failure entries and Apex test results.
    /// Costs extra bandwidth, but is required for any meaningful
    /// post-mortem on a failed deploy.
    pub async fn check_deploy_status(
        &self,
        deploy_id: &str,
        include_details: bool,
    ) -> MetadataResult<DeployResult> {
        let op = CheckDeployStatusOp {
            async_process_id: deploy_id.to_string(),
            include_details,
        };
        let resp = self.call(&op).await?;
        Ok(resp.result)
    }

    /// Requests cancellation of an in-progress deployment.
    ///
    /// Returns immediately. If the deployment was still queued, it's
    /// canceled synchronously (`done == true` in the result). If it
    /// had started, the cancellation is processed asynchronously —
    /// check_deploy_status continues to return `Canceling` until the
    /// server transitions it to `Canceled`.
    ///
    /// In API v65+, deployments that have entered `FinalizingDeploy`
    /// can't be canceled.
    pub async fn cancel_deploy(&self, deploy_id: &str) -> MetadataResult<CancelDeployResult> {
        let op = CancelDeployOp {
            async_process_id: deploy_id.to_string(),
        };
        let resp = self.call(&op).await?;
        Ok(resp.result)
    }

    /// Quick-deploys a recently-validated deployment without re-running
    /// tests.
    ///
    /// `validation_id` is the deploy ID returned by an earlier
    /// `deploy()` call that was run with
    /// [`DeployOptions::check_only`] set to `true` and finished
    /// successfully within the last 10 days.
    ///
    /// Returns the *new* deployment job ID — use
    /// [`Self::check_deploy_status`] or [`Self::wait_for_deploy`] to
    /// follow it.
    pub async fn deploy_recent_validation(&self, validation_id: &str) -> MetadataResult<String> {
        let op = DeployRecentValidationOp {
            validation_id: validation_id.to_string(),
        };
        let resp = self.call(&op).await?;
        Ok(resp.result)
    }

    /// Starts a metadata retrieval.
    ///
    /// Returns an [`AsyncResult`] whose `id` is the retrieve job ID;
    /// use [`Self::check_retrieve_status`] or
    /// [`Self::wait_for_retrieve`] to follow it. The retrieved zip
    /// bytes are returned as part of the [`RetrieveResult`].
    pub async fn retrieve(&self, request: RetrieveRequest) -> MetadataResult<AsyncResult> {
        let op = RetrieveOp { request };
        let resp = self.call(&op).await?;
        Ok(resp.result)
    }

    /// Fetches the current status of a retrieval.
    ///
    /// `include_zip` controls whether the response embeds the
    /// base64-encoded zip bytes. The server populates that field only
    /// when the retrieve has succeeded; intermediate polls return
    /// `zip_file: None` regardless of this flag.
    ///
    /// **The zip is served once.** Salesforce deletes it from the server
    /// as soon as a call with `include_zip == true` returns it, and later
    /// calls for the same retrieve ID can't get it back. Poll with
    /// `include_zip == false` until `done`, then make a single call with
    /// `include_zip == true` — which is what [`Self::wait_for_retrieve`]
    /// does. Because that call can't be repeated, the SDK never replays
    /// it, even when the retry policy would otherwise allow it.
    pub async fn check_retrieve_status(
        &self,
        retrieve_id: &str,
        include_zip: bool,
    ) -> MetadataResult<RetrieveResult> {
        let op = CheckRetrieveStatusOp {
            async_process_id: retrieve_id.to_string(),
            include_zip,
        };
        let resp = self.call(&op).await?;
        Ok(resp.result)
    }

    /// Polls [`Self::check_deploy_status`] until `done == true` or
    /// the configured timeout fires.
    ///
    /// Uses [`WaitConfig::default()`] — 2 s initial backoff doubling
    /// to a 30 s cap, no timeout. For CI-friendly timeouts, use
    /// [`Self::wait_for_deploy_with`] with
    /// [`WaitConfig::with_timeout`].
    ///
    /// [`DeployResult::details`] is populated best-effort: it comes
    /// from one final `include_details: true` fetch after the deploy
    /// reaches a terminal state, and if that follow-up call fails the
    /// terminal result is returned with `details: None` rather than
    /// discarding a completed deploy's outcome behind an error.
    pub async fn wait_for_deploy(&self, deploy_id: &str) -> MetadataResult<DeployResult> {
        self.wait_for_deploy_with(deploy_id, WaitConfig::default())
            .await
    }

    /// Polling form with a configurable [`WaitConfig`].
    pub async fn wait_for_deploy_with(
        &self,
        deploy_id: &str,
        config: WaitConfig,
    ) -> MetadataResult<DeployResult> {
        let start = tokio::time::Instant::now();
        let mut delay = config.initial_delay;
        loop {
            // Intermediate polls skip details — they grow with every
            // processed component and can balloon into megabytes for
            // large deploys. We fetch the full DeployDetails once after
            // the deploy reaches a terminal state.
            let result = self.check_deploy_status(deploy_id, false).await?;
            if result.done {
                // The terminal result is already in hand; the details
                // fetch only enriches it. If the follow-up fails (after
                // its own retries), return what we have — an error here
                // would discard a completed deploy's outcome.
                return match self.check_deploy_status(deploy_id, true).await {
                    Ok(with_details) => Ok(with_details),
                    Err(e) => {
                        tracing::warn!(
                            target: "cirrus_metadata::poll",
                            deploy_id,
                            error = %e,
                            "deploy reached a terminal state but the details fetch failed; \
                             returning the result without details",
                        );
                        Ok(result)
                    }
                };
            }
            if let Some(timeout) = config.total_timeout {
                // Clamping the sleep to what's left of the budget is
                // what keeps the deadline honest: an unclamped sleep
                // would carry the next check up to `max_delay` past
                // the budget before it could fire.
                let remaining = timeout.saturating_sub(start.elapsed());
                if remaining.is_zero() {
                    return Err(MetadataError::PollTimeout(format!(
                        "wait_for_deploy timed out after {timeout:?} (deploy still in progress)"
                    )));
                }
                tokio::time::sleep(delay.min(remaining)).await;
            } else {
                tokio::time::sleep(delay).await;
            }
            delay = delay.saturating_mul(2).min(config.max_delay);
        }
    }

    /// Polls [`Self::check_retrieve_status`] until `done == true` or
    /// the configured timeout fires. The returned [`RetrieveResult`]
    /// has the zip bytes populated when the retrieve succeeded.
    ///
    /// Polling never asks for the zip; it is fetched by one final call
    /// once the retrieve has succeeded, because the server deletes it
    /// as soon as it has been served.
    pub async fn wait_for_retrieve(&self, retrieve_id: &str) -> MetadataResult<RetrieveResult> {
        self.wait_for_retrieve_with(retrieve_id, WaitConfig::default())
            .await
    }

    /// Polling form with a configurable [`WaitConfig`].
    pub async fn wait_for_retrieve_with(
        &self,
        retrieve_id: &str,
        config: WaitConfig,
    ) -> MetadataResult<RetrieveResult> {
        let start = tokio::time::Instant::now();
        let mut delay = config.initial_delay;
        loop {
            // Poll without the zip so each tick stays a replayable
            // status read, then fetch the payload once the retrieve has
            // succeeded — the fetch deletes it server-side, so it gets
            // exactly one chance to happen.
            let result = self.check_retrieve_status(retrieve_id, false).await?;
            if result.done {
                if !result.success {
                    // A failed retrieve has no zip to collect; the
                    // status result already carries the error fields.
                    return Ok(result);
                }
                return self.check_retrieve_status(retrieve_id, true).await;
            }
            if let Some(timeout) = config.total_timeout {
                // Clamping the sleep to what's left of the budget is
                // what keeps the deadline honest: an unclamped sleep
                // would carry the next check up to `max_delay` past
                // the budget before it could fire.
                let remaining = timeout.saturating_sub(start.elapsed());
                if remaining.is_zero() {
                    return Err(MetadataError::PollTimeout(format!(
                        "wait_for_retrieve timed out after {timeout:?} (retrieve still in progress)"
                    )));
                }
                tokio::time::sleep(delay.min(remaining)).await;
            } else {
                tokio::time::sleep(delay).await;
            }
            delay = delay.saturating_mul(2).min(config.max_delay);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::MetadataType;
    use crate::result::TestLevel;

    fn deploy_op(zip: &'static [u8], options: DeployOptions) -> DeployOp {
        DeployOp {
            zip: Bytes::from_static(zip),
            options,
        }
    }

    #[test]
    fn deploy_op_emits_zipfile_and_deployoptions() {
        let op = deploy_op(b"PK\x03\x04hello", DeployOptions::default());
        let body = op.render_body().unwrap();
        assert!(body.contains("<met:ZipFile>"));
        assert!(body.contains("</met:ZipFile>"));
        assert!(body.contains("<met:DeployOptions>"));
        assert!(body.contains("</met:DeployOptions>"));
        // Base64 of "PK\x03\x04hello"
        assert!(body.contains("UEsDBGhlbGxv"));
    }

    #[test]
    fn deploy_op_emits_options_in_doc_order() {
        let opts = DeployOptions {
            check_only: Some(true),
            rollback_on_error: Some(true),
            test_level: Some(TestLevel::RunLocalTests),
            run_tests: vec!["MyTest".into()],
            ..Default::default()
        };
        let op = deploy_op(b"", opts);
        let body = op.render_body().unwrap();
        // checkOnly comes before rollbackOnError comes before
        // runTests comes before testLevel.
        let i_check = body.find("checkOnly").unwrap();
        let i_rollback = body.find("rollbackOnError").unwrap();
        let i_runtests = body.find("runTests").unwrap();
        let i_testlevel = body.find("testLevel").unwrap();
        assert!(i_check < i_rollback);
        assert!(i_rollback < i_runtests);
        assert!(i_runtests < i_testlevel);
        assert!(body.contains("<met:runTests>MyTest</met:runTests>"));
        assert!(body.contains("<met:testLevel>RunLocalTests</met:testLevel>"));
    }

    #[test]
    fn deploy_op_body_fits_its_initial_allocation() {
        // A populated option set renders far longer than the tags that
        // surround the encoded zip, so the buffer is sized from the
        // rendered options rather than a fixed headroom. Growing it
        // after the zip has been encoded into it would copy the whole
        // base64 payload.
        let opts = DeployOptions {
            allow_missing_files: Some(true),
            auto_update_package: Some(true),
            check_only: Some(true),
            ignore_warnings: Some(false),
            perform_retrieve: Some(false),
            purge_on_delete: Some(false),
            rollback_on_error: Some(true),
            run_tests: vec![
                "AccountTriggerTest".into(),
                "ContactTriggerTest".into(),
                "OpportunityServiceTest".into(),
            ],
            single_package: Some(true),
            test_level: Some(TestLevel::RunSpecifiedTests),
        };

        let mut rendered_opts = String::new();
        render_deploy_options(&opts, &mut rendered_opts);
        assert!(
            rendered_opts.len() > 256,
            "option set should be large enough to exercise the sizing"
        );

        let zip = vec![0x5a_u8; 4096];
        let encoded_len = zip.len().div_ceil(3) * 4;
        let op = DeployOp {
            zip: Bytes::from(zip),
            options: opts,
        };
        let body = op.render_body().unwrap();

        // An untouched `String::with_capacity` reservation proves the
        // buffer was never grown while it held the encoded zip.
        assert_eq!(body.capacity(), encoded_len + rendered_opts.len() + 128);
        assert!(body.contains(&rendered_opts));
    }

    #[test]
    fn deploy_op_skips_none_options() {
        let op = deploy_op(b"", DeployOptions::default());
        let body = op.render_body().unwrap();
        // Nothing optional is set — DeployOptions body should be empty.
        assert!(body.contains("<met:DeployOptions></met:DeployOptions>"));
    }

    #[test]
    fn check_deploy_status_body_round_trip() {
        let op = CheckDeployStatusOp {
            async_process_id: "0Aff00000abc".into(),
            include_details: true,
        };
        let body = op.render_body().unwrap();
        assert_eq!(
            body,
            "<met:asyncProcessId>0Aff00000abc</met:asyncProcessId>\
             <met:includeDetails>true</met:includeDetails>"
        );
    }

    #[test]
    fn retrieve_op_emits_unpackaged_manifest() {
        let req = RetrieveRequest {
            api_version: "66.0".into(),
            single_package: true,
            unpackaged: Some(
                PackageManifest::new("66.0")
                    .add(MetadataType::APEX_CLASS, ["MyClass", "OtherClass"]),
            ),
            ..Default::default()
        };
        let op = RetrieveOp { request: req };
        let body = op.render_body().unwrap();
        assert!(body.contains("<met:RetrieveRequest>"));
        assert!(body.contains("<met:apiVersion>66.0</met:apiVersion>"));
        assert!(body.contains("<met:singlePackage>true</met:singlePackage>"));
        assert!(body.contains("<met:unpackaged>"));
        assert!(body.contains("<met:types>"));
        assert!(body.contains("<met:members>MyClass</met:members>"));
        assert!(body.contains("<met:members>OtherClass</met:members>"));
        assert!(body.contains("<met:name>ApexClass</met:name>"));
        assert!(body.contains("<met:version>66.0</met:version>"));
    }

    #[test]
    fn retrieve_op_escapes_specific_files() {
        let req = RetrieveRequest {
            api_version: "66.0".into(),
            single_package: true,
            specific_files: vec!["a<b>c".into()],
            ..Default::default()
        };
        let op = RetrieveOp { request: req };
        let body = op.render_body().unwrap();
        assert!(body.contains("<met:specificFiles>a&lt;b&gt;c</met:specificFiles>"));
    }

    /// meta_retrieve_request, specificFiles row: "If a value is
    /// specified for this property, packageNames must be set to null
    /// and singlePackage must be set to true."
    #[test]
    fn retrieve_op_rejects_specific_files_without_single_package() {
        // The Default-derived single_package is false, so this is the
        // shape `..Default::default()` produces.
        let req = RetrieveRequest {
            api_version: "66.0".into(),
            specific_files: vec!["unpackaged/classes/MyClass.cls".into()],
            ..Default::default()
        };
        let op = RetrieveOp { request: req };
        let err = op.render_body().unwrap_err();
        assert!(matches!(err, MetadataError::InvalidArgument(_)));
        let msg = err.to_string();
        assert!(msg.contains("specific_files"), "{msg}");
        assert!(msg.contains("single_package"), "{msg}");
    }

    #[test]
    fn retrieve_op_rejects_specific_files_alongside_package_names() {
        let req = RetrieveRequest {
            api_version: "66.0".into(),
            single_package: true,
            package_names: vec!["MyManagedPackage".into()],
            specific_files: vec!["unpackaged/classes/MyClass.cls".into()],
            ..Default::default()
        };
        let op = RetrieveOp { request: req };
        let err = op.render_body().unwrap_err();
        assert!(matches!(err, MetadataError::InvalidArgument(_)));
        assert!(err.to_string().contains("package_names"));
    }

    #[test]
    fn retrieve_op_allows_package_names_without_specific_files() {
        // The coupling is one-directional: packageNames on its own is
        // the ordinary packaged-retrieve shape.
        let req = RetrieveRequest {
            api_version: "66.0".into(),
            package_names: vec!["MyManagedPackage".into()],
            ..Default::default()
        };
        let op = RetrieveOp { request: req };
        let body = op.render_body().unwrap();
        assert!(body.contains("<met:packageNames>MyManagedPackage</met:packageNames>"));
    }

    #[test]
    fn retrieve_op_rejects_empty_api_version() {
        let req = RetrieveRequest::default();
        let op = RetrieveOp { request: req };
        let err = op.render_body().unwrap_err();
        assert!(matches!(err, MetadataError::InvalidArgument(_)));
        assert!(err.to_string().contains("api_version"));
    }

    #[test]
    fn check_retrieve_status_emits_include_zip_flag() {
        let op = CheckRetrieveStatusOp {
            async_process_id: "0Aff00000abc".into(),
            include_zip: false,
        };
        let body = op.render_body().unwrap();
        assert!(body.contains("<met:includeZip>false</met:includeZip>"));
    }
}
