//! Wiremock-backed tests for the file-based deploy/retrieve handlers.
//!
//! Each test pins down one operation's wire shape:
//!
//! - the SOAP request body Salesforce should see, and
//! - the response envelope shape we parse into typed results.
//!
//! Response fixtures are modeled after the documented examples in the
//! Metadata API Developer Guide; field coverage is deliberately
//! generous so we exercise as much of the typed envelope surface as
//! possible.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bytes::Bytes;
use cirrus_metadata::auth::StaticTokenAuth;
use cirrus_metadata::{
    DeployOptions, DeployStatus, MetadataClient, MetadataError, MetadataType, PackageManifest,
    RetrieveRequest, RetrieveStatus, RetryPolicy, TestLevel, WaitConfig,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// -- Helpers -----------------------------------------------------------------

fn xml_response(body: &str) -> ResponseTemplate {
    ResponseTemplate::new(200)
        .insert_header("content-type", "text/xml; charset=UTF-8")
        .set_body_string(body.to_string())
}

fn client_against(server: &MockServer) -> MetadataClient {
    let auth = Arc::new(StaticTokenAuth::new("tok", server.uri()));
    MetadataClient::builder()
        .auth(auth)
        .retry_policy(RetryPolicy {
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(5),
            jitter: false,
            ..RetryPolicy::default()
        })
        .build()
        .unwrap()
}

// -- deploy ------------------------------------------------------------------

#[tokio::test]
async fn deploy_sends_zip_base64_and_returns_async_result() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/services/Soap/m/66.0"))
        // Base64 of "PKzip" is "UEt6aXA=" — assert the bytes were
        // base64-encoded before going on the wire.
        .and(body_string_contains("<met:ZipFile>UEt6aXA="))
        .and(body_string_contains("<met:checkOnly>true</met:checkOnly>"))
        .and(body_string_contains(
            "<met:testLevel>RunLocalTests</met:testLevel>",
        ))
        .respond_with(xml_response(
            r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <deployResponse xmlns="http://soap.sforce.com/2006/04/metadata">
      <result>
        <done>false</done>
        <id>0Af00000abcDEF</id>
        <state>Queued</state>
      </result>
    </deployResponse>
  </soapenv:Body>
</soapenv:Envelope>"#,
        ))
        .mount(&server)
        .await;

    let md = client_against(&server);
    let opts = DeployOptions {
        check_only: Some(true),
        test_level: Some(TestLevel::RunLocalTests),
        ..Default::default()
    };
    let result = md.deploy(Bytes::from_static(b"PKzip"), opts).await.unwrap();
    assert_eq!(result.id, "0Af00000abcDEF");
    assert!(!result.done);
}

// -- check_deploy_status -----------------------------------------------------

#[tokio::test]
async fn check_deploy_status_parses_full_deploy_result() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(body_string_contains("<met:checkDeployStatus>"))
        .and(body_string_contains(
            "<met:asyncProcessId>0Af00000abcDEF</met:asyncProcessId>",
        ))
        .and(body_string_contains(
            "<met:includeDetails>true</met:includeDetails>",
        ))
        .respond_with(xml_response(
            r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <checkDeployStatusResponse xmlns="http://soap.sforce.com/2006/04/metadata">
      <result>
        <id>0Af00000abcDEF</id>
        <done>true</done>
        <success>true</success>
        <status>Succeeded</status>
        <checkOnly>false</checkOnly>
        <ignoreWarnings>false</ignoreWarnings>
        <rollbackOnError>true</rollbackOnError>
        <runTestsEnabled>true</runTestsEnabled>
        <numberComponentsDeployed>10</numberComponentsDeployed>
        <numberComponentsTotal>10</numberComponentsTotal>
        <numberComponentErrors>0</numberComponentErrors>
        <numberTestsCompleted>5</numberTestsCompleted>
        <numberTestsTotal>5</numberTestsTotal>
        <numberTestErrors>0</numberTestErrors>
        <createdBy>005xx00000abcde</createdBy>
        <createdByName>Stephanie</createdByName>
        <createdDate>2026-05-28T10:00:00.000Z</createdDate>
        <startDate>2026-05-28T10:00:05.000Z</startDate>
        <completedDate>2026-05-28T10:01:00.000Z</completedDate>
        <details>
          <componentSuccesses>
            <componentType>ApexClass</componentType>
            <fullName>Foo</fullName>
            <fileName>classes/Foo.cls</fileName>
            <success>true</success>
            <changed>false</changed>
            <created>true</created>
            <deleted>false</deleted>
          </componentSuccesses>
          <runTestResult>
            <numTestsRun>5</numTestsRun>
            <numFailures>0</numFailures>
            <totalTime>1234.5</totalTime>
          </runTestResult>
        </details>
      </result>
    </checkDeployStatusResponse>
  </soapenv:Body>
</soapenv:Envelope>"#,
        ))
        .mount(&server)
        .await;

    let md = client_against(&server);
    let result = md
        .check_deploy_status("0Af00000abcDEF", true)
        .await
        .unwrap();
    assert!(result.done);
    assert!(result.success);
    assert_eq!(result.status, Some(DeployStatus::Succeeded));
    assert_eq!(result.number_components_deployed, 10);
    let details = result.details.unwrap();
    assert_eq!(details.component_successes.len(), 1);
    assert_eq!(details.component_successes[0].full_name, Some("Foo".into()));
    let test_result = details.run_test_result.unwrap();
    assert_eq!(test_result.num_tests_run, 5);
    assert_eq!(test_result.total_time, 1234.5);
}

#[tokio::test]
async fn check_deploy_status_parses_failure_details() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .respond_with(xml_response(
            r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <checkDeployStatusResponse xmlns="http://soap.sforce.com/2006/04/metadata">
      <result>
        <id>0Af00000bad</id>
        <done>true</done>
        <success>false</success>
        <status>Failed</status>
        <numberComponentErrors>2</numberComponentErrors>
        <details>
          <componentFailures>
            <componentType>ApexClass</componentType>
            <fullName>BrokenClass</fullName>
            <fileName>classes/BrokenClass.cls</fileName>
            <success>false</success>
            <problem>Unexpected token 'foo'</problem>
            <problemType>Error</problemType>
            <lineNumber>42</lineNumber>
            <columnNumber>13</columnNumber>
          </componentFailures>
          <componentFailures>
            <componentType>ApexClass</componentType>
            <fullName>BrokenTwo</fullName>
            <fileName>classes/BrokenTwo.cls</fileName>
            <success>false</success>
            <problem>Method does not exist</problem>
            <problemType>Error</problemType>
          </componentFailures>
        </details>
      </result>
    </checkDeployStatusResponse>
  </soapenv:Body>
</soapenv:Envelope>"#,
        ))
        .mount(&server)
        .await;

    let md = client_against(&server);
    let result = md.check_deploy_status("0Af00000bad", true).await.unwrap();
    assert!(!result.success);
    assert_eq!(result.status, Some(DeployStatus::Failed));
    let details = result.details.unwrap();
    assert_eq!(details.component_failures.len(), 2);
    let first = &details.component_failures[0];
    assert_eq!(first.full_name, Some("BrokenClass".into()));
    assert_eq!(first.problem, Some("Unexpected token 'foo'".into()));
    assert_eq!(first.line_number, Some(42));
    assert_eq!(first.column_number, Some(13));
}

// -- cancel_deploy -----------------------------------------------------------

#[tokio::test]
async fn cancel_deploy_round_trip() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(body_string_contains("<met:cancelDeploy>"))
        .and(body_string_contains(
            "<met:asyncProcessId>0Af00000abc</met:asyncProcessId>",
        ))
        .respond_with(xml_response(
            r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <cancelDeployResponse xmlns="http://soap.sforce.com/2006/04/metadata">
      <result>
        <id>0Af00000abc</id>
        <done>true</done>
      </result>
    </cancelDeployResponse>
  </soapenv:Body>
</soapenv:Envelope>"#,
        ))
        .mount(&server)
        .await;

    let md = client_against(&server);
    let result = md.cancel_deploy("0Af00000abc").await.unwrap();
    assert_eq!(result.id, "0Af00000abc");
    assert!(result.done);
}

// -- deploy_recent_validation ------------------------------------------------

#[tokio::test]
async fn deploy_recent_validation_returns_new_deploy_id() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(body_string_contains("<met:deployRecentValidation>"))
        .and(body_string_contains(
            "<met:validationId>0Af00000valid</met:validationId>",
        ))
        .respond_with(xml_response(
            r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <deployRecentValidationResponse xmlns="http://soap.sforce.com/2006/04/metadata">
      <result>0Af00000NEWdep</result>
    </deployRecentValidationResponse>
  </soapenv:Body>
</soapenv:Envelope>"#,
        ))
        .mount(&server)
        .await;

    let md = client_against(&server);
    let new_id = md.deploy_recent_validation("0Af00000valid").await.unwrap();
    assert_eq!(new_id, "0Af00000NEWdep");
}

// -- retrieve ----------------------------------------------------------------

#[tokio::test]
async fn retrieve_sends_unpackaged_manifest_and_returns_async_result() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(body_string_contains("<met:retrieve>"))
        .and(body_string_contains("<met:RetrieveRequest>"))
        .and(body_string_contains(
            "<met:apiVersion>66.0</met:apiVersion>",
        ))
        .and(body_string_contains("<met:members>MyClass</met:members>"))
        .and(body_string_contains("<met:name>ApexClass</met:name>"))
        .respond_with(xml_response(
            r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <retrieveResponse xmlns="http://soap.sforce.com/2006/04/metadata">
      <result>
        <done>false</done>
        <id>09S00000retrId</id>
        <state>Queued</state>
      </result>
    </retrieveResponse>
  </soapenv:Body>
</soapenv:Envelope>"#,
        ))
        .mount(&server)
        .await;

    let md = client_against(&server);
    let req = RetrieveRequest {
        api_version: "66.0".into(),
        single_package: true,
        unpackaged: Some(PackageManifest::new("66.0").add(MetadataType::APEX_CLASS, ["MyClass"])),
        ..Default::default()
    };
    let result = md.retrieve(req).await.unwrap();
    assert_eq!(result.id, "09S00000retrId");
}

// -- check_retrieve_status ---------------------------------------------------

#[tokio::test]
async fn check_retrieve_status_decodes_zip_bytes() {
    let server = MockServer::start().await;

    // Base64 of "PKfakezipbytes" — stand-in for an actual zip.
    let zip_b64 = "UEtmYWtlemlwYnl0ZXM=";

    Mock::given(method("POST"))
        .and(body_string_contains("<met:checkRetrieveStatus>"))
        .and(body_string_contains(
            "<met:includeZip>true</met:includeZip>",
        ))
        .respond_with(xml_response(&format!(
            r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <checkRetrieveStatusResponse xmlns="http://soap.sforce.com/2006/04/metadata">
      <result>
        <id>09S00000retrId</id>
        <done>true</done>
        <success>true</success>
        <status>Succeeded</status>
        <fileProperties>
          <createdById>005xx0000</createdById>
          <createdByName>Stephanie</createdByName>
          <createdDate>2026-05-28T10:00:00.000Z</createdDate>
          <fileName>unpackaged/classes/MyClass.cls</fileName>
          <fullName>MyClass</fullName>
          <id>01p00000abc</id>
          <lastModifiedById>005xx0000</lastModifiedById>
          <lastModifiedByName>Stephanie</lastModifiedByName>
          <lastModifiedDate>2026-05-28T10:00:00.000Z</lastModifiedDate>
          <type>ApexClass</type>
        </fileProperties>
        <zipFile>{zip_b64}</zipFile>
      </result>
    </checkRetrieveStatusResponse>
  </soapenv:Body>
</soapenv:Envelope>"#
        )))
        .mount(&server)
        .await;

    let md = client_against(&server);
    let result = md
        .check_retrieve_status("09S00000retrId", true)
        .await
        .unwrap();
    assert!(result.done);
    assert!(result.success);
    assert_eq!(result.status, Some(RetrieveStatus::Succeeded));
    assert_eq!(result.file_properties.len(), 1);
    assert_eq!(result.file_properties[0].full_name, "MyClass");
    assert_eq!(
        result.file_properties[0].type_name,
        Some("ApexClass".into())
    );
    let zip = result.zip_bytes().unwrap().unwrap();
    assert_eq!(&zip[..], b"PKfakezipbytes");
}

// -- wait_for_deploy ---------------------------------------------------------

#[tokio::test]
async fn wait_for_deploy_polls_until_done() {
    let server = MockServer::start().await;

    // Hand-rolled call counter so the first two polls return InProgress
    // and the third returns Succeeded. wiremock's `up_to_n_times`
    // composes awkwardly with two paired Mocks; an AtomicUsize-keyed
    // matcher keeps the test readable.
    let counter = Arc::new(AtomicUsize::new(0));

    Mock::given(method("POST"))
        .and(body_string_contains("<met:checkDeployStatus>"))
        .respond_with({
            let counter = counter.clone();
            move |_: &wiremock::Request| {
                let n = counter.fetch_add(1, Ordering::SeqCst);
                let (done, status) = if n < 2 {
                    ("false", "InProgress")
                } else {
                    ("true", "Succeeded")
                };
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/xml; charset=UTF-8")
                    .set_body_string(format!(
                        r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <checkDeployStatusResponse xmlns="http://soap.sforce.com/2006/04/metadata">
      <result>
        <id>0Af00000poll</id>
        <done>{done}</done>
        <success>true</success>
        <status>{status}</status>
      </result>
    </checkDeployStatusResponse>
  </soapenv:Body>
</soapenv:Envelope>"#
                    ))
            }
        })
        .mount(&server)
        .await;

    let md = client_against(&server);
    let result = md
        .wait_for_deploy_with(
            "0Af00000poll",
            WaitConfig {
                // Keep tests fast; the helper still exercises the
                // backoff doubling and clamping.
                initial_delay: Duration::from_millis(1),
                max_delay: Duration::from_millis(5),
                total_timeout: None,
            },
        )
        .await
        .unwrap();

    assert_eq!(result.status, Some(DeployStatus::Succeeded));
    // 3 intermediate polls (InProgress, InProgress, Succeeded) plus 1
    // final include_details=true fetch once the deploy reached a
    // terminal state — the polling loop deliberately skips details on
    // intermediate iterations because the response grows with every
    // processed component on large deploys.
    assert_eq!(counter.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn wait_for_deploy_returns_terminal_result_when_details_fetch_fails() {
    let server = MockServer::start().await;

    // First poll: done. Second call (the include_details=true follow-up):
    // server error. The helper must surface the terminal result it
    // already holds instead of discarding it behind the follow-up error.
    let counter = Arc::new(AtomicUsize::new(0));

    Mock::given(method("POST"))
        .and(body_string_contains("<met:checkDeployStatus>"))
        .respond_with({
            let counter = counter.clone();
            move |_: &wiremock::Request| {
                let n = counter.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    ResponseTemplate::new(200)
                        .insert_header("content-type", "text/xml; charset=UTF-8")
                        .set_body_string(
                            r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <checkDeployStatusResponse xmlns="http://soap.sforce.com/2006/04/metadata">
      <result>
        <id>0Af00000nodet</id>
        <done>true</done>
        <success>true</success>
        <status>Succeeded</status>
      </result>
    </checkDeployStatusResponse>
  </soapenv:Body>
</soapenv:Envelope>"#,
                        )
                } else {
                    ResponseTemplate::new(500)
                }
            }
        })
        .mount(&server)
        .await;

    let md = client_against(&server);
    let result = md
        .wait_for_deploy_with(
            "0Af00000nodet",
            WaitConfig {
                initial_delay: Duration::from_millis(1),
                max_delay: Duration::from_millis(5),
                total_timeout: None,
            },
        )
        .await
        .unwrap();

    assert_eq!(result.status, Some(DeployStatus::Succeeded));
    assert!(result.details.is_none());
    // One terminal poll plus the failed details fetch. checkDeployStatus
    // is a read-only (idempotent) operation, so the 500 on the details
    // fetch is retried per the default policy: 1 + (1 + 3 retries) = 5.
    assert_eq!(counter.load(Ordering::SeqCst), 5);
}

#[tokio::test]
async fn wait_for_deploy_times_out_when_never_done() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(body_string_contains("<met:checkDeployStatus>"))
        .respond_with(xml_response(
            r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <checkDeployStatusResponse xmlns="http://soap.sforce.com/2006/04/metadata">
      <result>
        <id>0Af00000slow</id>
        <done>false</done>
        <status>InProgress</status>
      </result>
    </checkDeployStatusResponse>
  </soapenv:Body>
</soapenv:Envelope>"#,
        ))
        .mount(&server)
        .await;

    let md = client_against(&server);
    let err = md
        .wait_for_deploy_with(
            "0Af00000slow",
            WaitConfig {
                initial_delay: Duration::from_millis(1),
                max_delay: Duration::from_millis(2),
                total_timeout: Some(Duration::from_millis(10)),
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(err, MetadataError::PollTimeout(_)));
    assert!(err.to_string().contains("timed out"));
}

// -- wait_for_retrieve -------------------------------------------------------
//
// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_checkretrievestatus.htm
// "By default, checkRetrieveStatus() returns the zip file on the last
// call to this operation when the retrieval is completed
// (RetrieveResult.isDone() == true) and then deletes the zip file from
// the server. Subsequent calls to checkRetrieveStatus() for the same
// retrieve operation can't retrieve the zip file after it has been
// deleted." The documented pattern polls with includeZip false and
// fetches the zip with one final includeZip-true call.

fn retrieve_status_body(done: bool, success: bool, zip: Option<&str>) -> String {
    let status = if !done {
        "InProgress"
    } else if success {
        "Succeeded"
    } else {
        "Failed"
    };
    let zip_element = zip
        .map(|z| format!("<zipFile>{z}</zipFile>"))
        .unwrap_or_default();
    format!(
        r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <checkRetrieveStatusResponse xmlns="http://soap.sforce.com/2006/04/metadata">
      <result>
        <id>09S00000poll</id>
        <done>{done}</done>
        <success>{success}</success>
        <status>{status}</status>
        {zip_element}
      </result>
    </checkRetrieveStatusResponse>
  </soapenv:Body>
</soapenv:Envelope>"#
    )
}

fn fast_wait() -> WaitConfig {
    WaitConfig {
        initial_delay: Duration::from_millis(1),
        max_delay: Duration::from_millis(5),
        total_timeout: None,
    }
}

#[tokio::test]
async fn wait_for_retrieve_polls_without_zip_then_fetches_it_once() {
    let server = MockServer::start().await;
    let polls = Arc::new(AtomicUsize::new(0));

    // Status polls: the first is still running, the second is done.
    // Neither asks for the zip.
    Mock::given(method("POST"))
        .and(body_string_contains(
            "<met:includeZip>false</met:includeZip>",
        ))
        .respond_with({
            let polls = polls.clone();
            move |_: &wiremock::Request| {
                let n = polls.fetch_add(1, Ordering::SeqCst);
                let body = retrieve_status_body(n > 0, n > 0, None);
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/xml; charset=UTF-8")
                    .set_body_string(body)
            }
        })
        .mount(&server)
        .await;

    // The zip is served exactly once, by the single includeZip-true call.
    Mock::given(method("POST"))
        .and(body_string_contains(
            "<met:includeZip>true</met:includeZip>",
        ))
        .respond_with(xml_response(&retrieve_status_body(
            true,
            true,
            Some("UEt6aXA="),
        )))
        .expect(1)
        .mount(&server)
        .await;

    let md = client_against(&server);
    let result = md
        .wait_for_retrieve_with("09S00000poll", fast_wait())
        .await
        .unwrap();
    assert!(result.done);
    let zip = result.zip_bytes().unwrap().unwrap();
    assert_eq!(&zip[..], b"PKzip");
    assert_eq!(polls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn wait_for_retrieve_skips_the_zip_fetch_when_the_retrieve_failed() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(body_string_contains(
            "<met:includeZip>false</met:includeZip>",
        ))
        .respond_with(xml_response(&retrieve_status_body(true, false, None)))
        .expect(1)
        .mount(&server)
        .await;

    // A failed retrieve produced no zip; asking for one would spend an
    // API call for nothing.
    Mock::given(method("POST"))
        .and(body_string_contains(
            "<met:includeZip>true</met:includeZip>",
        ))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let md = client_against(&server);
    let result = md
        .wait_for_retrieve_with("09S00000poll", fast_wait())
        .await
        .unwrap();
    assert!(result.done);
    assert!(!result.success);
    assert_eq!(result.status, Some(RetrieveStatus::Failed));
}

#[tokio::test]
async fn check_retrieve_status_with_zip_is_never_replayed() {
    let server = MockServer::start().await;

    // 503 from an intermediary after the origin already served — and
    // deleted — the zip. Replaying can only lose the payload, so the
    // status is surfaced on the first attempt.
    Mock::given(method("POST"))
        .and(body_string_contains(
            "<met:includeZip>true</met:includeZip>",
        ))
        .respond_with(ResponseTemplate::new(503))
        .expect(1)
        .mount(&server)
        .await;

    let md = client_against(&server);
    let err = md
        .check_retrieve_status("09S00000poll", true)
        .await
        .unwrap_err();
    match err {
        MetadataError::Http4xx5xx { status, .. } => assert_eq!(status, 503),
        other => panic!("expected Http4xx5xx, got {other:?}"),
    }
}

#[tokio::test]
async fn check_retrieve_status_without_zip_is_retried() {
    let server = MockServer::start().await;

    // The status-only poll carries no payload, so a 503 replays like
    // any other read.
    Mock::given(method("POST"))
        .and(body_string_contains(
            "<met:includeZip>false</met:includeZip>",
        ))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(body_string_contains(
            "<met:includeZip>false</met:includeZip>",
        ))
        .respond_with(xml_response(&retrieve_status_body(false, false, None)))
        .mount(&server)
        .await;

    let md = client_against(&server);
    let result = md
        .check_retrieve_status("09S00000poll", false)
        .await
        .unwrap();
    assert!(!result.done);
}
