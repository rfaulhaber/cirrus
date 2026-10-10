//! File-based Metadata API tests: `deploy` + polling, `retrieve` +
//! polling.
//!
//! ## Deploy
//!
//! Builds a minimal CustomLabels deploy zip in-memory and runs it
//! with `checkOnly = true` so the deploy *validates* against the org
//! but doesn't actually create any state. This still exercises:
//!
//! - The SOAP `deploy` op (zip → base64 → `<ZipFile>` envelope).
//! - `wait_for_deploy` polling against a real progress curve.
//! - The new lightweight-poll-plus-detail-fetch optimisation.
//! - Terminal-state semantics (`done == true`, `success == true`).
//!
//! `checkOnly=true` is the polite default for CI: no org-state
//! mutation, no concurrent-deploy contention.
//!
//! ## Retrieve
//!
//! Retrieves the `CustomLabels` component, which is universal on
//! every edition (returns an empty-ish file on orgs with no labels).
//! Verifies `wait_for_retrieve` polls until `done == true` and the
//! base64 zip decodes to a valid ZIP archive.

use crate::common::try_init_client;
use bytes::Bytes;
use cirrus_metadata::{
    DeployOptions, MetadataClient, MetadataError, MetadataType, PackageManifest, RetrieveRequest,
    RetrieveStatus, SoapFault, WaitConfig,
};
use std::io::Write;
use std::time::Duration;

/// Builds an in-memory ZIP archive containing the given files. Used
/// to construct the minimal deploy package.
fn build_zip(files: &[(&str, &[u8])]) -> Bytes {
    let mut buf = Vec::new();
    {
        let mut zw = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
        let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for (name, bytes) in files {
            zw.start_file(*name, opts)
                .expect("start_file should not fail on in-memory writer");
            zw.write_all(bytes)
                .expect("write_all should not fail on in-memory writer");
        }
        zw.finish()
            .expect("finish should not fail on in-memory writer");
    }
    Bytes::from(buf)
}

/// Strips the optional `v` prefix from a REST-style API version
/// (`"v66.0"` → `"66.0"`). The SOAP Metadata API and `package.xml`
/// both use the bare numeric form.
fn pkg_version(md: &MetadataClient) -> String {
    md.api_version().trim_start_matches('v').to_string()
}

/// True when a fault is about the id argument: the `INVALID_ID_FIELD`
/// code, or a message that mentions the id and calls something
/// invalid, unknown, missing or not found. A test that passes an id the
/// org just issued reads such a fault as a request element the server
/// did not bind to the id.
fn faults_the_id(fault: &SoapFault) -> bool {
    let message = fault.faultstring.to_ascii_lowercase();
    let names_an_id = message
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|word| word == "id");
    fault.code() == "INVALID_ID_FIELD"
        || (names_an_id
            && ["invalid", "unknown", "missing", "not found"]
                .iter()
                .any(|flaw| message.contains(flaw)))
}

/// In-memory deploy zip containing a single empty `<CustomLabels/>`
/// document plus its `package.xml`. The smallest deploy payload
/// Salesforce will accept for the CustomLabels metadata type — used
/// as a no-op checkOnly fixture across multiple tests.
fn minimal_labels_zip(pkg_version: &str) -> Bytes {
    let labels_xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<CustomLabels xmlns="http://soap.sforce.com/2006/04/metadata">
</CustomLabels>"#;
    let manifest_xml = PackageManifest::new(pkg_version)
        .all(MetadataType::CUSTOM_LABELS)
        .to_xml();
    build_zip(&[
        ("package.xml", manifest_xml.as_bytes()),
        ("labels/CustomLabels.labels", labels_xml),
    ])
}

/// Default `DeployOptions` for checkOnly tests: validation-only, safe
/// rollback semantics, single-package mode (matches what's inside the
/// zip).
fn check_only_options() -> DeployOptions {
    DeployOptions {
        check_only: Some(true),
        rollback_on_error: Some(true),
        single_package: Some(true),
        ..Default::default()
    }
}

fn deploy_timeout() -> Duration {
    // Generous; the real risk for a CustomLabels checkOnly is
    // platform queue latency, not the deploy work itself.
    Duration::from_secs(120)
}

fn retrieve_timeout() -> Duration {
    Duration::from_secs(120)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn deploy_check_only_minimal_custom_labels_succeeds() {
    let Some(md) = try_init_client().await else {
        return;
    };
    let zip_bytes = minimal_labels_zip(&pkg_version(&md));

    let async_result = md
        .deploy(zip_bytes, check_only_options())
        .await
        .expect("deploy should return an AsyncResult");
    assert!(
        !async_result.id.is_empty(),
        "AsyncResult should carry a non-empty deploy id",
    );

    let result = md
        .wait_for_deploy_with(
            &async_result.id,
            WaitConfig::default().with_timeout(deploy_timeout()),
        )
        .await
        .expect("wait_for_deploy should complete before the timeout");

    assert!(result.done, "deploy result should be terminal");
    assert!(
        result.success,
        "checkOnly deploy of empty CustomLabels should succeed; \
         got status={:?}, error={:?}",
        result.status, result.error_message,
    );
    // checkOnly preserves the validation; the result should reflect
    // that. The fields populate inconsistently across edition/version,
    // but on a successful deploy `number_components_total` is non-zero.
    assert!(
        result.check_only,
        "result.check_only should mirror the option we sent",
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn retrieve_custom_labels_returns_a_zip() {
    let Some(md) = try_init_client().await else {
        return;
    };
    let api_version = md.api_version().to_string();
    let pkg_version = api_version.trim_start_matches('v').to_string();

    let manifest = PackageManifest::new(&pkg_version).all(MetadataType::CUSTOM_LABELS);
    let req = RetrieveRequest {
        api_version: pkg_version.clone(),
        single_package: true,
        unpackaged: Some(manifest),
        ..Default::default()
    };

    let async_result = md
        .retrieve(req)
        .await
        .expect("retrieve should return an AsyncResult");

    let config = WaitConfig::default().with_timeout(retrieve_timeout());
    let result = md
        .wait_for_retrieve_with(&async_result.id, config)
        .await
        .expect("wait_for_retrieve should complete before the timeout");

    assert!(result.done, "retrieve result should be terminal");
    assert_eq!(
        result.status,
        Some(RetrieveStatus::Succeeded),
        "expected Succeeded; got {:?} with error={:?}",
        result.status,
        result.error_message,
    );
    assert!(
        result.success,
        "retrieve should report success on a CustomLabels-only manifest",
    );

    let zip = result
        .zip_bytes()
        .expect("zip_file should decode as valid base64")
        .expect("zip should be present once retrieve completed successfully");
    assert!(
        zip.len() >= 22,
        "retrieved zip should be at least the size of an empty ZIP \
         End-Of-Central-Directory record (22 bytes); got {} bytes",
        zip.len(),
    );
    // ZIP local file headers start with the magic bytes 'P' 'K' \x03 \x04.
    assert_eq!(
        &zip[..4],
        b"PK\x03\x04",
        "retrieved bytes should start with the ZIP local-file header magic",
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn check_deploy_status_returns_terminal_state_after_completion() {
    // Companion to `deploy_check_only_minimal_custom_labels_succeeds`
    // but uses the lower-level `check_deploy_status` instead of the
    // polling helper. Verifies the include_details=true path returns
    // the populated DeployDetails envelope.
    let Some(md) = try_init_client().await else {
        return;
    };
    let zip_bytes = minimal_labels_zip(&pkg_version(&md));
    let async_result = md.deploy(zip_bytes, check_only_options()).await.unwrap();

    // Drive the loop manually so we exercise check_deploy_status
    // directly, not through wait_for_deploy.
    let deadline = std::time::Instant::now() + deploy_timeout();
    let result = loop {
        let r = md
            .check_deploy_status(&async_result.id, false)
            .await
            .expect("check_deploy_status should not fail");
        if r.done {
            // Final detailed fetch — exercises the include_details=true
            // branch.
            break md
                .check_deploy_status(&async_result.id, true)
                .await
                .unwrap();
        }
        assert!(
            std::time::Instant::now() < deadline,
            "deploy did not reach terminal state within {:?}",
            deploy_timeout(),
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    };

    assert!(result.done && result.success);
    // include_details=true should populate at least one of the detail
    // collections. Empty CustomLabels has no components — so
    // `details.component_successes` may be empty; just verify the
    // `details` envelope itself parsed.
    assert!(
        result.details.is_some(),
        "include_details=true should produce a populated details envelope",
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn deploy_recent_validation_quick_deploys_or_surfaces_typed_error() {
    // Two-phase test of the deployRecentValidation wire path.
    //
    // Phase 1: deploy(checkOnly=true) the minimal CustomLabels zip,
    // wait for it to reach a terminal state. This produces a
    // validation that's *theoretically* eligible for quick-deploy.
    //
    // Phase 2: call deploy_recent_validation with that id.
    //
    // The success criteria are deliberately tolerant: a real org may
    // refuse quick-deploy of an empty validation (no Apex tests ran,
    // no code coverage validated, no components to deploy). What
    // we're exercising is the wire path — the request body, the
    // response shape, the error parsing. *Either* a success
    // (AsyncResult-with-new-id) or a typed fault about the validation's
    // eligibility is a valid outcome; a fault about the id or the
    // request's shape, a hard panic or a malformed response shape fails
    // the test.
    let Some(md) = try_init_client().await else {
        return;
    };
    let zip_bytes = minimal_labels_zip(&pkg_version(&md));

    let async_result = md.deploy(zip_bytes, check_only_options()).await.unwrap();
    let validation = md
        .wait_for_deploy_with(
            &async_result.id,
            WaitConfig::default().with_timeout(deploy_timeout()),
        )
        .await
        .expect("validation phase should complete");
    assert!(
        validation.success,
        "phase-1 validation must succeed before quick-deploy: status={:?}, error={:?}",
        validation.status, validation.error_message,
    );

    // Phase 2 — fire the quick-deploy.
    match md.deploy_recent_validation(&validation.id).await {
        Ok(new_deploy_id) => {
            // Quick-deploy succeeded — the server accepted the
            // validation as eligible and returned a new job id
            // distinct from the validation id.
            assert!(
                !new_deploy_id.is_empty(),
                "quick-deploy response should carry a non-empty new job id",
            );
            assert_ne!(
                new_deploy_id, validation.id,
                "quick-deploy should produce a *new* deploy id (the docs are explicit on this)",
            );
        }
        Err(MetadataError::Soap { fault, .. }) => {
            // SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_deployRecentValidation.htm
            // The page lists no faults. It states what a quick deploy
            // needs: "The components have been validated successfully
            // for the target environment within the last 10 days.",
            // "As part of the validation, Apex tests in the target org
            // have passed." and "Code coverage requirements are met."
            // The empty validation phase 1 produced ran no tests, so a
            // refusal over those requirements is expected on
            // dev/sandbox orgs. The id, though, is the one deploy()
            // just returned: a fault calling it invalid, unknown or
            // missing means the `validationId` element is not the
            // argument the server reads.
            //
            // Wire-shape provenance: unverified. No documentation page
            // says what a mis-bound element yields. The expectation is
            // a SOAP-level fault coded `soapenv:Client` (`Client` here)
            // with a message such as "Element {...}x invalid at this
            // location" that never says "id", because Salesforce
            // reports its own application faults under an `sf:` code
            // and a malformed envelope under the SOAP one.
            if faults_the_id(&fault) || fault.code() == "Client" {
                panic!(
                    "quick-deploy faulted as if the request did not carry the id \
                     deploy() just returned; the `validationId` element may not be \
                     the argument the server reads: {} / {}",
                    fault.faultcode, fault.faultstring,
                );
            }
            assert!(
                !fault.code().is_empty(),
                "SOAP fault on quick-deploy refusal should carry a faultcode",
            );
            assert!(
                !fault.faultstring.is_empty(),
                "SOAP fault on quick-deploy refusal should carry a non-empty faultstring",
            );
        }
        Err(e) => {
            panic!(
                "unexpected error variant from deploy_recent_validation; \
                 expected Ok or MetadataError::Soap, got {e:?}",
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn failing_apex_deploy_populates_component_failures() {
    // checkOnly deploy of a syntactically broken Apex class.
    // Exercises:
    //   1. The deploy state machine when `success == false`.
    //   2. The `DeployDetails.component_failures` parser path.
    //   3. The `DeployMessage` Option<String> fields that show up
    //      filled (problem, line_number, column_number) versus empty
    //      on the success path.
    let Some(md) = try_init_client().await else {
        return;
    };
    let pkg_version = pkg_version(&md);

    // Intentionally broken: `intentionally broken` is not valid Apex.
    let broken_apex = b"public class CirrusItBroken { intentionally broken syntax }";
    let meta_xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<ApexClass xmlns="http://soap.sforce.com/2006/04/metadata">
    <apiVersion>{pkg_version}</apiVersion>
    <status>Active</status>
</ApexClass>"#,
    );
    let manifest_xml = PackageManifest::new(&pkg_version)
        .add(MetadataType::APEX_CLASS, ["CirrusItBroken"])
        .to_xml();

    let zip_bytes = build_zip(&[
        ("package.xml", manifest_xml.as_bytes()),
        ("classes/CirrusItBroken.cls", broken_apex),
        ("classes/CirrusItBroken.cls-meta.xml", meta_xml.as_bytes()),
    ]);

    let async_result = md.deploy(zip_bytes, check_only_options()).await.unwrap();
    let result = md
        .wait_for_deploy_with(
            &async_result.id,
            WaitConfig::default().with_timeout(deploy_timeout()),
        )
        .await
        .expect("wait_for_deploy should resolve even when the deploy fails");

    assert!(
        result.done,
        "failing deploy should still reach terminal state"
    );
    assert!(
        !result.success,
        "broken Apex deploy must report success=false; got status={:?}",
        result.status,
    );

    let details = result
        .details
        .expect("wait_for_deploy issues a final include_details=true fetch on terminal state");
    assert!(
        !details.component_failures.is_empty(),
        "broken Apex deploy should populate component_failures; \
         got {} successes, {} failures",
        details.component_successes.len(),
        details.component_failures.len(),
    );

    // The broken class should be the cited component, with a
    // non-empty problem description.
    let broken = details
        .component_failures
        .iter()
        .find(|m| {
            m.full_name
                .as_deref()
                .is_some_and(|n| n.contains("CirrusItBroken"))
        })
        .expect("component_failures should mention CirrusItBroken by fullName");
    assert!(
        broken.problem.as_deref().is_some_and(|p| !p.is_empty()),
        "failed component should carry a non-empty `problem` description",
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn cancel_deploy_lands_or_surfaces_a_documented_refusal() {
    // Race-tolerant test of the cancel wire path. Start a deploy and
    // immediately call cancel_deploy. The empty CustomLabels checkOnly
    // completes in ~2 seconds on a free Dev Edition org, so the
    // cancel may land in any of three states:
    //
    //   1. Deploy still queued or in progress — cancel succeeds, server
    //      returns CancelDeployResult { done: true|false }.
    //   2. Deploy already completed — INVALID_ID_FIELD with the message
    //      `Deployment already completed`.
    //   3. Deploy in Finalizing Deploy (API 65.0+) — INVALID_ID_FIELD
    //      with the message `You cannot cancel the deployment while
    //      finalizing is in progress`.
    //
    // SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_canceldeploy.htm
    // Those are two of the three faults the page lists. The third,
    // `Invalid deploy ID` ("The specified ID argument doesn't
    // correspond to a valid deployment."), fails the test: the id came
    // straight from deploy(), so it means the `asyncProcessId` request
    // element, which the page does not spell out, is not the one the
    // server reads. Any other fault fails the test too.
    let Some(md) = try_init_client().await else {
        return;
    };
    let zip_bytes = minimal_labels_zip(&pkg_version(&md));
    let async_result = md.deploy(zip_bytes, check_only_options()).await.unwrap();

    match md.cancel_deploy(&async_result.id).await {
        Ok(cancel) => {
            assert_eq!(
                cancel.id, async_result.id,
                "cancel_deploy result.id should echo the input deploy id",
            );
            // `done` may be true (cancel landed synchronously, deploy
            // was still queued) or false (cancel in progress, deploy
            // moving toward `Canceling`). Either is valid; the
            // important thing is the response parsed.
            //
            // Drain to a terminal state so we don't leave a Canceling
            // job hanging on the org. Tolerate failure here — the
            // deploy may already be in a terminal state by the time
            // we follow up.
            let _ = md
                .wait_for_deploy_with(
                    &async_result.id,
                    WaitConfig::default().with_timeout(deploy_timeout()),
                )
                .await;
        }
        Err(MetadataError::Soap { fault, .. }) => {
            let documented_race = fault.code() == "INVALID_ID_FIELD"
                && [
                    "Deployment already completed",
                    "You cannot cancel the deployment while finalizing is in progress",
                ]
                .iter()
                .any(|message| fault.faultstring.contains(message));
            if !documented_race {
                panic!(
                    "cancel_deploy faulted with something other than a documented \
                     already-completed or finalizing refusal: {} / {}",
                    fault.faultcode, fault.faultstring,
                );
            }
        }
        Err(e) => {
            panic!(
                "unexpected error variant from cancel_deploy; \
                 expected Ok or MetadataError::Soap, got {e:?}",
            );
        }
    }
}
