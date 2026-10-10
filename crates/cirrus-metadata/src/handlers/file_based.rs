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
use crate::headers::{DebuggingHeader, DebuggingInfo, render_debugging_header};
use crate::result::{
    AsyncResult, CancelDeployResult, DeployOptions, DeployResult, RetrieveRequest, RetrieveResult,
    TestLevel,
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
    debugging: Option<DebuggingHeader>,
}

#[derive(Deserialize)]
struct DeployResponseWire {
    result: AsyncResult,
}

impl DeployOp {
    /// The rendered `<met:DeployOptions>` children.
    fn rendered_options(&self) -> String {
        let mut opts = String::new();
        render_deploy_options(&self.options, &mut opts);
        opts
    }
}

impl SoapOperation for DeployOp {
    const NAME: &'static str = "deploy";
    type Response = DeployResponseWire;

    fn render_body(&self) -> MetadataResult<String> {
        let mut out = String::with_capacity(self.body_size_hint());
        self.render_body_into(&mut out)?;
        Ok(out)
    }

    /// The base64 zip is encoded straight into the envelope buffer, so
    /// the only copy of it while the request is in flight is the
    /// envelope's; the buffer was sized from [`Self::body_size_hint`]
    /// and nothing appended after the zip reallocates it.
    fn render_body_into(&self, out: &mut String) -> MetadataResult<()> {
        // Salesforce accepts runTests only under RunSpecifiedTests and
        // faults on any other pairing. Checking here, before the zip is
        // encoded, spares a documented-maximum upload that could only
        // come back INVALID_OPERATION.
        if !self.options.run_tests.is_empty()
            && self.options.test_level != Some(TestLevel::RunSpecifiedTests)
        {
            return Err(MetadataError::InvalidArgument(
                "DeployOptions.run_tests requires test_level == Some(TestLevel::RunSpecifiedTests)"
                    .into(),
            ));
        }
        out.push_str("<met:ZipFile>");
        base64::engine::general_purpose::STANDARD.encode_string(&self.zip, out);
        out.push_str("</met:ZipFile><met:DeployOptions>");
        out.push_str(&self.rendered_options());
        out.push_str("</met:DeployOptions>");
        Ok(())
    }

    /// Base64 expands to four characters per three input bytes, rounded
    /// up to a whole quantum, plus the options and the fixed tags. The
    /// options are rendered here so the hint is exact: a buffer that
    /// came up short would reallocate while holding the encoded form of
    /// a documented-maximum zip.
    fn body_size_hint(&self) -> usize {
        self.zip.len().div_ceil(3) * 4 + self.rendered_options().len() + 128
    }

    fn render_headers(&self) -> MetadataResult<String> {
        Ok(render_debugging_headers(self.debugging.as_ref()))
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
    debugging: Option<DebuggingHeader>,
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

    fn render_headers(&self) -> MetadataResult<String> {
        Ok(render_debugging_headers(self.debugging.as_ref()))
    }
}

/// The `DebuggingHeader` of a deploy call, or nothing when the caller
/// didn't ask for a debug log.
fn render_debugging_headers(debugging: Option<&DebuggingHeader>) -> String {
    let mut out = String::new();
    if let Some(header) = debugging {
        render_debugging_header(header, &mut out);
    }
    out
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
        for ty in &self.request.root_types_with_dependencies {
            out.push_str("<met:rootTypesWithDependencies>");
            out.push_str(&xml_escape(ty));
            out.push_str("</met:rootTypesWithDependencies>");
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
        out.push_str(level.as_str());
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
        let op = DeployOp {
            zip,
            options,
            debugging: None,
        };
        let resp = self.call(&op).await?;
        Ok(resp.result)
    }

    /// [`Self::deploy`] that also sends a [`DebuggingHeader`], asking
    /// Salesforce to record an Apex debug log for the deployment.
    ///
    /// Once the deployment has finished and ran tests, the log is in the
    /// `DebuggingInfo` header of the status check — read it with
    /// [`Self::check_deploy_status_with_debugging`] or
    /// [`Self::wait_for_deploy_with_debugging`].
    pub async fn deploy_with_debugging(
        &self,
        zip: Bytes,
        options: DeployOptions,
        debugging: DebuggingHeader,
    ) -> MetadataResult<AsyncResult> {
        let op = DeployOp {
            zip,
            options,
            debugging: Some(debugging),
        };
        let resp = self.call(&op).await?;
        Ok(resp.result)
    }

    /// Fetches the current status of a deployment.
    ///
    /// `include_details` controls whether the response includes
    /// per-component success/failure entries and Apex test results.
    /// Costs extra bandwidth, but is required for any meaningful
    /// post-mortem on a failed deploy.
    ///
    /// The response's `DebuggingInfo` header is left unread;
    /// [`Self::check_deploy_status_with_debugging`] returns it.
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

    /// [`Self::check_deploy_status`] that also returns the
    /// [`DebuggingInfo`] output header.
    ///
    /// The Apex debug log is present once the deployment has finished
    /// and ran tests, and only for a deploy that was sent with a
    /// [`DebuggingHeader`] (see [`Self::deploy_with_debugging`]);
    /// otherwise the second element is `None`.
    pub async fn check_deploy_status_with_debugging(
        &self,
        deploy_id: &str,
        include_details: bool,
    ) -> MetadataResult<(DeployResult, Option<DebuggingInfo>)> {
        let op = CheckDeployStatusOp {
            async_process_id: deploy_id.to_string(),
            include_details,
        };
        let (resp, headers) = self.call_with_response_headers(&op).await?;
        Ok((resp.result, headers.debugging_info))
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
            debugging: None,
        };
        let resp = self.call(&op).await?;
        Ok(resp.result)
    }

    /// [`Self::deploy_recent_validation`] that also sends a
    /// [`DebuggingHeader`]; read the log back with
    /// [`Self::wait_for_deploy_with_debugging`] on the returned id.
    pub async fn deploy_recent_validation_with_debugging(
        &self,
        validation_id: &str,
        debugging: DebuggingHeader,
    ) -> MetadataResult<String> {
        let op = DeployRecentValidationOp {
            validation_id: validation_id.to_string(),
            debugging: Some(debugging),
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
    /// it, even when the retry policy would otherwise allow it, and the
    /// future of an `include_zip == true` call must be left to resolve:
    /// dropping it mid-flight loses a zip the server may already have
    /// served and deleted.
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
    /// # Outcome
    ///
    /// Every terminal state is returned as `Ok`, exactly as
    /// `checkDeployStatus` reports it: `Succeeded`, `SucceededPartial`,
    /// `Failed`, `Canceled` and `FinalizingDeployFailed` alike, with
    /// the outcome in [`DeployResult::success`] and
    /// [`DeployResult::status`]. Chain [`DeployResult::into_result`]
    /// to turn a deployment that did not succeed into
    /// [`MetadataError::DeployFailed`], whose message names the
    /// component and test failures:
    ///
    /// ```no_run
    /// # async fn example(md: cirrus_metadata::MetadataClient, id: &str) -> Result<(), cirrus_metadata::MetadataError> {
    /// let result = md.wait_for_deploy(id).await?.into_result()?;
    /// # let _ = result;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// `Err` means the wait itself failed: a poll returned an error, or
    /// [`MetadataError::PollTimeout`] fired.
    ///
    /// [`DeployResult::details`] is populated best-effort: it comes
    /// from one final `include_details: true` fetch after the deploy
    /// reaches a terminal state, and if that follow-up call fails the
    /// terminal result is returned with `details: None` rather than
    /// discarding a completed deploy's outcome behind an error.
    ///
    /// The response's `DebuggingInfo` header is left unread;
    /// [`Self::wait_for_deploy_with_debugging`] returns it.
    pub async fn wait_for_deploy(&self, deploy_id: &str) -> MetadataResult<DeployResult> {
        self.wait_for_deploy_with(deploy_id, WaitConfig::default())
            .await
    }

    /// Polling form of [`Self::wait_for_deploy`] with a configurable
    /// [`WaitConfig`]; the outcome contract is the same, and the
    /// response's `DebuggingInfo` header is likewise left unread.
    pub async fn wait_for_deploy_with(
        &self,
        deploy_id: &str,
        config: WaitConfig,
    ) -> MetadataResult<DeployResult> {
        self.poll_deploy_until_done(deploy_id, config, false)
            .await
            .map(|(result, _)| result)
    }

    /// [`Self::wait_for_deploy_with`] that also returns the
    /// [`DebuggingInfo`] of the deployment; the outcome contract is the
    /// same.
    ///
    /// The log comes from the final `include_details: true` fetch, or
    /// from the terminal poll when that fetch fails. It is `None`
    /// unless the deploy was sent with a [`DebuggingHeader`] and ran
    /// tests.
    pub async fn wait_for_deploy_with_debugging(
        &self,
        deploy_id: &str,
        config: WaitConfig,
    ) -> MetadataResult<(DeployResult, Option<DebuggingInfo>)> {
        self.poll_deploy_until_done(deploy_id, config, true).await
    }

    /// One status read of the deploy poll loop. Only a caller that asked
    /// for the debug log reads the `DebuggingInfo` header, so a header
    /// the caller never requested cannot fail its status check.
    async fn deploy_status(
        &self,
        deploy_id: &str,
        include_details: bool,
        with_debugging: bool,
    ) -> MetadataResult<(DeployResult, Option<DebuggingInfo>)> {
        if with_debugging {
            self.check_deploy_status_with_debugging(deploy_id, include_details)
                .await
        } else {
            self.check_deploy_status(deploy_id, include_details)
                .await
                .map(|result| (result, None))
        }
    }

    /// The poll loop behind [`Self::wait_for_deploy_with`] and
    /// [`Self::wait_for_deploy_with_debugging`].
    async fn poll_deploy_until_done(
        &self,
        deploy_id: &str,
        config: WaitConfig,
        with_debugging: bool,
    ) -> MetadataResult<(DeployResult, Option<DebuggingInfo>)> {
        let start = tokio::time::Instant::now();
        let mut delay = config.initial_delay;
        loop {
            // Intermediate polls skip details — they grow with every
            // processed component and can balloon into megabytes for
            // large deploys. We fetch the full DeployDetails once after
            // the deploy reaches a terminal state.
            let (result, info) = self.deploy_status(deploy_id, false, with_debugging).await?;
            if result.done {
                // The terminal result is already in hand; the details
                // fetch only enriches it. If the follow-up fails (after
                // its own retries), return what we have — an error here
                // would discard a completed deploy's outcome.
                return match self.deploy_status(deploy_id, true, with_debugging).await {
                    Ok(with_details) => Ok(with_details),
                    Err(e) => {
                        tracing::warn!(
                            target: "cirrus_metadata::poll",
                            deploy_id,
                            error = %e,
                            "deploy reached a terminal state but the details fetch failed; \
                             returning the result without details",
                        );
                        Ok((result, info))
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
                        "deploy {deploy_id} still in progress after {timeout:?}"
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
    /// the configured timeout fires, then collects the zip with one
    /// final `include_zip == true` call once the retrieve has
    /// succeeded. The returned [`RetrieveResult`] has the zip bytes
    /// populated in that case.
    ///
    /// Polling never asks for the zip, because the server deletes it
    /// as soon as it has been served; the single fetch at the end is
    /// the one chance to collect it.
    ///
    /// Uses [`WaitConfig::default()`] — 2 s initial backoff doubling
    /// to a 30 s cap, no timeout; [`Self::wait_for_retrieve_with`]
    /// takes a configuration.
    ///
    /// # Outcome
    ///
    /// A retrieve that ended `Failed` is returned as `Ok`, exactly as
    /// `checkRetrieveStatus` reports it: `success == false`, no zip,
    /// and the cause in [`RetrieveResult::error_status_code`],
    /// [`error_message`](RetrieveResult::error_message) and
    /// [`messages`](RetrieveResult::messages). Chain
    /// [`RetrieveResult::into_result`] to turn it into
    /// [`MetadataError::RetrieveFailed`]:
    ///
    /// ```no_run
    /// # async fn example(md: cirrus_metadata::MetadataClient, id: &str) -> Result<(), cirrus_metadata::MetadataError> {
    /// let result = md.wait_for_retrieve(id).await?.into_result()?;
    /// # let _ = result;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// `Err` means the wait itself failed: a poll or the zip fetch
    /// returned an error, or [`MetadataError::PollTimeout`] fired.
    ///
    /// # Cancellation
    ///
    /// Dropping this future while the final `include_zip == true` call
    /// is in flight — through an outer `tokio::time::timeout`, a losing
    /// `select!` branch or a shutdown signal — loses the zip: the
    /// server may already have served and deleted it, a later call
    /// comes back without one, and the retrieve has to be started over.
    /// Bound the wait with [`WaitConfig::total_timeout`] instead, which
    /// is checked only between polls and so never interrupts the
    /// fetch. Alternatively poll with [`Self::wait_for_retrieve_done`]
    /// under any cancellation mechanism and make the one-shot
    /// [`Self::check_retrieve_status`] call yourself once it reports
    /// success.
    pub async fn wait_for_retrieve(&self, retrieve_id: &str) -> MetadataResult<RetrieveResult> {
        self.wait_for_retrieve_with(retrieve_id, WaitConfig::default())
            .await
    }

    /// Polling form of [`Self::wait_for_retrieve`] with a configurable
    /// [`WaitConfig`]; the outcome and cancellation contracts are the
    /// same.
    pub async fn wait_for_retrieve_with(
        &self,
        retrieve_id: &str,
        config: WaitConfig,
    ) -> MetadataResult<RetrieveResult> {
        let result = self
            .wait_for_retrieve_done_with(retrieve_id, config)
            .await?;
        if !result.success {
            // A failed retrieve has no zip to collect; the status result
            // already carries the error fields.
            return Ok(result);
        }
        // The fetch deletes the zip server-side, so it gets exactly one
        // chance to happen.
        self.check_retrieve_status(retrieve_id, true).await
    }

    /// Polls [`Self::check_retrieve_status`] with `include_zip == false`
    /// until `done == true` or the configured timeout fires, and
    /// returns the terminal status without the zip.
    ///
    /// Every call this makes is a replayable status read, so the future
    /// can be dropped at any point — under a `tokio::time::timeout`, in
    /// a `select!` — without losing anything, which
    /// [`Self::wait_for_retrieve`] cannot offer for its final fetch.
    /// Once the result reports `success == true`, collect the zip with
    /// one `check_retrieve_status(id, true)` call and let that call run
    /// to completion.
    ///
    /// The outcome contract is that of [`Self::wait_for_retrieve`]: a
    /// `Failed` retrieve is `Ok` with `success == false`, and
    /// [`RetrieveResult::into_result`] turns it into an error.
    ///
    /// Uses [`WaitConfig::default()`];
    /// [`Self::wait_for_retrieve_done_with`] takes a configuration.
    pub async fn wait_for_retrieve_done(
        &self,
        retrieve_id: &str,
    ) -> MetadataResult<RetrieveResult> {
        self.wait_for_retrieve_done_with(retrieve_id, WaitConfig::default())
            .await
    }

    /// Polling form of [`Self::wait_for_retrieve_done`] with a
    /// configurable [`WaitConfig`].
    pub async fn wait_for_retrieve_done_with(
        &self,
        retrieve_id: &str,
        config: WaitConfig,
    ) -> MetadataResult<RetrieveResult> {
        let start = tokio::time::Instant::now();
        let mut delay = config.initial_delay;
        loop {
            // Each tick is a status read without the zip, so it stays
            // replayable and the future stays safe to drop.
            let result = self.check_retrieve_status(retrieve_id, false).await?;
            if result.done {
                return Ok(result);
            }
            if let Some(timeout) = config.total_timeout {
                // Clamping the sleep to what's left of the budget is
                // what keeps the deadline honest: an unclamped sleep
                // would carry the next check up to `max_delay` past
                // the budget before it could fire.
                let remaining = timeout.saturating_sub(start.elapsed());
                if remaining.is_zero() {
                    return Err(MetadataError::PollTimeout(format!(
                        "retrieve {retrieve_id} still in progress after {timeout:?}"
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

    fn deploy_op(zip: &'static [u8], options: DeployOptions) -> DeployOp {
        DeployOp {
            zip: Bytes::from_static(zip),
            options,
            debugging: None,
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

    /// `render_body_into` appends to the buffer it is given and
    /// `body_size_hint` covers what it appends, so the envelope builder
    /// can size its buffer once and the base64 zip is never held in a
    /// second string on its way into the envelope.
    #[test]
    fn deploy_op_renders_into_a_sized_buffer_without_a_second_copy() {
        let op = deploy_op(
            b"PK\x03\x04hello world, hello world",
            DeployOptions::default(),
        );
        let mut out = String::from("<prefix>");
        out.reserve(op.body_size_hint());
        let capacity = out.capacity();
        op.render_body_into(&mut out).unwrap();
        assert_eq!(out.capacity(), capacity, "the hint must cover the body");
        assert!(out.starts_with("<prefix><met:ZipFile>"));
        assert_eq!(&out["<prefix>".len()..], op.render_body().unwrap());
        assert!(out.len() - "<prefix>".len() <= op.body_size_hint());
    }

    #[test]
    fn deploy_op_emits_options_in_doc_order() {
        let opts = DeployOptions {
            check_only: Some(true),
            rollback_on_error: Some(true),
            test_level: Some(TestLevel::RunSpecifiedTests),
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
        assert!(body.contains("<met:testLevel>RunSpecifiedTests</met:testLevel>"));
    }

    /// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_deploy.htm
    /// DeployOptions.runTests: "To use this option, set testLevel to
    /// RunSpecifiedTests." The server rejects any other pairing, so the
    /// client refuses it before encoding and uploading the zip.
    #[test]
    fn deploy_op_rejects_run_tests_unless_the_level_is_run_specified_tests() {
        for level in [
            None,
            Some(TestLevel::NoTestRun),
            Some(TestLevel::RunLocalTests),
            Some(TestLevel::RunAllTestsInOrg),
            Some(TestLevel::RunRelevantTests),
        ] {
            let op = deploy_op(
                b"PK",
                DeployOptions {
                    run_tests: vec!["MyTest".into()],
                    test_level: level,
                    ..Default::default()
                },
            );
            let err = op.render_body().unwrap_err();
            assert!(
                matches!(err, MetadataError::InvalidArgument(_)),
                "{level:?}: {err:?}"
            );
            let msg = err.to_string();
            assert!(msg.contains("run_tests"), "{msg}");
            assert!(msg.contains("RunSpecifiedTests"), "{msg}");
        }
    }

    #[test]
    fn deploy_op_allows_an_empty_run_tests_at_any_level() {
        for level in [None, Some(TestLevel::RunLocalTests)] {
            let op = deploy_op(
                b"PK",
                DeployOptions {
                    test_level: level,
                    ..Default::default()
                },
            );
            assert!(op.render_body().is_ok(), "{level:?}");
        }
    }

    #[test]
    fn deploy_op_body_fits_the_capacity_it_reserves() {
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
        let reserved = encoded_len + rendered_opts.len() + 128;
        let op = DeployOp {
            zip: Bytes::from(zip),
            options: opts,
            debugging: None,
        };
        let body = op.render_body().unwrap();

        // Everything appended after the encoded zip has to fit in what
        // `render_body` reserved up front; the moment it doesn't, the
        // push that overflows copies the whole base64 payload. Asserting
        // the fit rather than the final capacity keeps the test about
        // that, since `String::with_capacity` and base64's own sink are
        // both free to reserve more than they were asked for.
        assert!(
            body.len() <= reserved,
            "body outgrew its reservation: {} > {reserved}",
            body.len()
        );
        assert!(body.capacity() >= reserved);
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
    fn deploy_ops_render_the_debugging_header_only_when_set() {
        use crate::headers::{LogCategory, LogCategoryLevel, LogInfo};

        let header = DebuggingHeader {
            categories: vec![LogInfo {
                category: LogCategory::ApexCode,
                level: LogCategoryLevel::Fine,
            }],
        };
        let mut deploy = deploy_op(b"", DeployOptions::default());
        assert_eq!(deploy.render_headers().unwrap(), "");
        deploy.debugging = Some(header.clone());
        let rendered = deploy.render_headers().unwrap();
        assert!(rendered.starts_with("<met:DebuggingHeader>"), "{rendered}");

        let mut recent = DeployRecentValidationOp {
            validation_id: "0Af".into(),
            debugging: None,
        };
        assert_eq!(recent.render_headers().unwrap(), "");
        recent.debugging = Some(header);
        assert_eq!(recent.render_headers().unwrap(), rendered);
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
