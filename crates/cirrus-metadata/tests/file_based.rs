//! Wiremock-backed tests for the file-based deploy/retrieve handlers.
//!
//! Each test pins down one operation's wire shape:
//!
//! - the SOAP request body Salesforce should see, and
//! - the response envelope shape we parse into typed results.
//!
//! ## Fixture provenance
//!
//! Every fixture's element names and values come from a property table
//! or Java sample in the Metadata API Developer Guide; each test names
//! the page it was built from. Field coverage is deliberately generous
//! so the fixtures exercise as much of the typed envelope surface as
//! possible.
//!
//! The guide publishes no SOAP envelope example for any call, so the
//! `<soapenv:Envelope><soapenv:Body><xxxResponse><result>` framing
//! around every fixture below follows the WSDL's document-literal
//! binding rather than a published sample. Only what sits *inside*
//! `<result>` is doc-cited.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bytes::Bytes;
use cirrus_metadata::auth::StaticTokenAuth;
use cirrus_metadata::{
    DeployOptions, DeployProblemType, DeployStatus, MetadataClient, MetadataError, MetadataType,
    PackageManifest, RetrieveRequest, RetrieveStatus, RetryPolicy, TestLevel, WaitConfig,
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

/// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_deploy.htm
/// deploy() takes "base64Binary ZipFile" plus DeployOptions, whose
/// table defines `checkOnly` and `testLevel`.
/// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_asyncresult.htm
/// The response is an AsyncResult: "id | ID | Required. The ID of the
/// component that's being deployed or retrieved."
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

/// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_deployresult.htm
/// Elements below are the "API version 29.0 and later" DeployResult
/// table plus the DeployDetails, DeployMessage and RunTestsResult
/// tables on the same page.
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
        <numFiles>12</numFiles>
        <zipSize>18342211</zipSize>
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
    // meta_deployresult.htm: "numFiles | int | The total number of
    // files included in this deployment." and "zipSize | long | The
    // size of the unzipped deployment folder in bytes." Both are
    // available in API version 64.0 and later, so both are live at the
    // 66.0 default this client targets.
    assert_eq!(result.num_files, 12);
    assert_eq!(result.zip_size, 18_342_211);
    let details = result.details.unwrap();
    assert_eq!(details.component_successes.len(), 1);
    assert_eq!(details.component_successes[0].full_name, Some("Foo".into()));
    let test_result = details.run_test_result.unwrap();
    assert_eq!(test_result.num_tests_run, 5);
    assert_eq!(test_result.total_time, 1234.5);
}

/// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_deployresult.htm
/// DeployMessage table: `problem` is "a description of the problem
/// that caused the compile to fail", `problemType` is Warning or
/// Error, and `lineNumber`/`columnNumber` locate it in the source.
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
    assert_eq!(first.problem_type, Some(DeployProblemType::Error));
    assert_eq!(first.line_number, Some(42));
    assert_eq!(first.column_number, Some(13));
}

/// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_deployresult.htm
/// DeployResult.status valid values include `SucceededPartial`;
/// `errorStatusCode` carries "a status code … the message
/// corresponding to the status code is returned in the errorMessage
/// field", which meta_deploy.htm's sample reads as
/// `getErrorStatusCode()` / `getErrorMessage()`. DeployMessage's
/// `problemType` is one of Warning or Error.
///
/// `success` is deliberately absent: the guide doesn't say what value
/// accompanies a partial deploy, so the fixture doesn't invent one.
#[tokio::test]
async fn check_deploy_status_parses_partial_success_and_error_fields() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .respond_with(xml_response(
            r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <checkDeployStatusResponse xmlns="http://soap.sforce.com/2006/04/metadata">
      <result>
        <id>0Af00000partial</id>
        <done>true</done>
        <status>SucceededPartial</status>
        <numberComponentsDeployed>8</numberComponentsDeployed>
        <numberComponentsTotal>10</numberComponentsTotal>
        <numberComponentErrors>2</numberComponentErrors>
        <errorStatusCode>INVALID_CROSS_REFERENCE_KEY</errorStatusCode>
        <errorMessage>Some components were not deployed.</errorMessage>
        <details>
          <componentFailures>
            <componentType>ApexClass</componentType>
            <fullName>OldStyle</fullName>
            <fileName>classes/OldStyle.cls</fileName>
            <success>false</success>
            <problem>Deprecated method used</problem>
            <problemType>Warning</problemType>
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
    let result = md
        .check_deploy_status("0Af00000partial", true)
        .await
        .unwrap();
    assert_eq!(result.status, Some(DeployStatus::SucceededPartial));
    assert!(result.status.unwrap().is_terminal());
    assert_eq!(
        result.error_status_code,
        Some("INVALID_CROSS_REFERENCE_KEY".into())
    );
    assert_eq!(
        result.error_message,
        Some("Some components were not deployed.".into())
    );
    assert_eq!(result.number_component_errors, 2);
    let failure = &result.details.unwrap().component_failures[0];
    assert_eq!(failure.problem_type, Some(DeployProblemType::Warning));
}

/// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_canceldeploy.htm
/// "In the returned DeployResult object, check the status field. If
/// the status is Canceling, the cancellation is still in progress …
/// Otherwise, if the status is Canceled, the deployment has been
/// canceled and you're done."
#[tokio::test]
async fn check_deploy_status_parses_the_cancellation_states() {
    let server = MockServer::start().await;
    let counter = Arc::new(AtomicUsize::new(0));

    Mock::given(method("POST"))
        .and(body_string_contains("<met:checkDeployStatus>"))
        .respond_with({
            let counter = counter.clone();
            move |_: &wiremock::Request| {
                let n = counter.fetch_add(1, Ordering::SeqCst);
                let (done, status) = if n == 0 {
                    ("false", "Canceling")
                } else {
                    ("true", "Canceled")
                };
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/xml; charset=UTF-8")
                    .set_body_string(format!(
                        r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <checkDeployStatusResponse xmlns="http://soap.sforce.com/2006/04/metadata">
      <result>
        <id>0Af00000cancel</id>
        <done>{done}</done>
        <success>false</success>
        <status>{status}</status>
        <canceledBy>005xx00000abcde</canceledBy>
        <canceledByName>Stephanie</canceledByName>
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
    let in_progress = md
        .check_deploy_status("0Af00000cancel", false)
        .await
        .unwrap();
    assert_eq!(in_progress.status, Some(DeployStatus::Canceling));
    assert!(
        !in_progress.status.unwrap().is_terminal(),
        "a cancellation in progress is not a finished deploy"
    );
    assert_eq!(in_progress.canceled_by_name, Some("Stephanie".into()));

    let settled = md
        .check_deploy_status("0Af00000cancel", false)
        .await
        .unwrap();
    assert_eq!(settled.status, Some(DeployStatus::Canceled));
    assert!(settled.status.unwrap().is_terminal());
}

/// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_deploy.htm
/// DeployOptions: "performRetrieve | boolean | Indicates whether a
/// retrieve() call is performed immediately after the deployment
/// (true) or not (false)."
///
/// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_deployresult.htm
/// DeployDetails: "retrieveResult | RetrieveResult | If the
/// performRetrieve parameter was specified for the deploy() call, a
/// retrieve() call is performed immediately after the deploy() process
/// completes." The nested shape is the RetrieveResult table on
/// meta_retrieveresult.htm.
#[tokio::test]
async fn check_deploy_status_surfaces_the_post_deploy_retrieve_result() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(body_string_contains("<met:checkDeployStatus>"))
        .respond_with(xml_response(
            r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <checkDeployStatusResponse xmlns="http://soap.sforce.com/2006/04/metadata">
      <result>
        <id>0Af00000retr</id>
        <done>true</done>
        <success>true</success>
        <status>Succeeded</status>
        <details>
          <componentSuccesses>
            <componentType>ApexClass</componentType>
            <fullName>Foo</fullName>
            <fileName>classes/Foo.cls</fileName>
            <success>true</success>
          </componentSuccesses>
          <retrieveResult>
            <done>true</done>
            <id>09S00000postdep</id>
            <status>Succeeded</status>
            <success>true</success>
            <fileProperties>
              <createdById>005xx0000abc</createdById>
              <createdByName>Stephanie</createdByName>
              <createdDate>2026-05-28T10:00:00.000Z</createdDate>
              <fileName>unpackaged/classes/Foo.cls</fileName>
              <fullName>Foo</fullName>
              <id>01p00000abc</id>
              <lastModifiedById>005xx0000abc</lastModifiedById>
              <lastModifiedByName>Stephanie</lastModifiedByName>
              <lastModifiedDate>2026-05-28T10:00:00.000Z</lastModifiedDate>
              <type>ApexClass</type>
            </fileProperties>
            <zipFile>UEt6aXA=</zipFile>
          </retrieveResult>
        </details>
      </result>
    </checkDeployStatusResponse>
  </soapenv:Body>
</soapenv:Envelope>"#,
        ))
        .mount(&server)
        .await;

    let md = client_against(&server);
    let result = md.check_deploy_status("0Af00000retr", true).await.unwrap();
    let details = result.details.unwrap();
    let retrieved = details.retrieve_result.unwrap();
    assert_eq!(retrieved.id, "09S00000postdep");
    assert_eq!(retrieved.status, Some(RetrieveStatus::Succeeded));
    assert_eq!(retrieved.file_properties.len(), 1);
    assert_eq!(&retrieved.zip_bytes().unwrap().unwrap()[..], b"PKzip");
}

/// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_deploy.htm
/// DeployOptions defines both `performRetrieve` and
/// `autoUpdatePackage`; neither is reserved on the SOAP endpoint.
#[tokio::test]
async fn deploy_emits_the_retrieve_side_options() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(body_string_contains(
            "<met:autoUpdatePackage>true</met:autoUpdatePackage>",
        ))
        .and(body_string_contains(
            "<met:performRetrieve>true</met:performRetrieve>",
        ))
        .respond_with(xml_response(
            r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <deployResponse xmlns="http://soap.sforce.com/2006/04/metadata">
      <result>
        <done>false</done>
        <id>0Af00000withretr</id>
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
        auto_update_package: Some(true),
        perform_retrieve: Some(true),
        ..Default::default()
    };
    let result = md.deploy(Bytes::from_static(b"PKzip"), opts).await.unwrap();
    assert_eq!(result.id, "0Af00000withretr");
}

// -- cancel_deploy -----------------------------------------------------------

/// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_canceldeploy.htm
/// CancelDeployResult carries `id` and `done`; "If the done field
/// value is true, the deployment has been canceled".
///
/// The request's element name is not documented — see the wire-shape
/// provenance note on `CancelDeployOp`. The assertion below pins the
/// name the crate sends so a change to it is deliberate, not a claim
/// that a page specifies it.
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

/// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_deployRecentValidation.htm
/// "string = metadatabinding.deployRecentValidation(ID validationID)"
/// — the call takes a validation id and returns the new deployment's
/// id, so `<result>` here holds a bare string rather than a struct.
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

/// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_retrieve_request.htm
/// RetrieveRequest: `apiVersion` (required), `singlePackage`, and
/// `unpackaged` ("A list of components to retrieve that aren't in a
/// package"), which carries a Package manifest.
/// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_asyncresult.htm
/// retrieve() answers with an AsyncResult, same as deploy().
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

/// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_retrieve_request.htm
/// rootTypesWithDependencies row: "A list of component types to
/// retrieve dependencies for. Currently, the only allowed value for
/// this parameter is Bot. … This field is available in API version
/// 64.0 and later."
#[tokio::test]
async fn retrieve_sends_root_types_with_dependencies() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(body_string_contains(
            "<met:rootTypesWithDependencies>Bot</met:rootTypesWithDependencies>",
        ))
        .respond_with(xml_response(
            r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <retrieveResponse xmlns="http://soap.sforce.com/2006/04/metadata">
      <result>
        <done>false</done>
        <id>09S00000botdeps</id>
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
        root_types_with_dependencies: vec!["Bot".into()],
        unpackaged: Some(PackageManifest::new("66.0").add(MetadataType::new("Bot"), ["MyBot"])),
        ..Default::default()
    };
    let result = md.retrieve(req).await.unwrap();
    assert_eq!(result.id, "09S00000botdeps");
}

// -- check_retrieve_status ---------------------------------------------------

/// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_retrieveresult.htm
/// RetrieveResult: `fileProperties` ("information about the properties
/// of each component in the .zip file"), and `zipFile` — "base64Binary
/// … client applications must decode the base64 data to binary". The
/// FileProperties table on the same page names the child elements.
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

/// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_retrieveresult.htm
/// RetrieveResult carries `errorStatusCode` ("If an error occurs
/// during the retrieve() call, this field contains the status code for
/// this error"), the matching `errorMessage`, and `messages`
/// (RetrieveMessage[]) — "information about the success or failure of
/// the retrieve() call". A RetrieveMessage is a `fileName` plus a
/// required `problem`.
#[tokio::test]
async fn check_retrieve_status_parses_failure_messages() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(body_string_contains("<met:checkRetrieveStatus>"))
        .respond_with(xml_response(
            r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <checkRetrieveStatusResponse xmlns="http://soap.sforce.com/2006/04/metadata">
      <result>
        <id>09S00000failed</id>
        <done>true</done>
        <success>false</success>
        <status>Failed</status>
        <errorStatusCode>INVALID_CROSS_REFERENCE_KEY</errorStatusCode>
        <errorMessage>An error occurred during the retrieve.</errorMessage>
        <messages>
          <fileName>unpackaged/classes/Missing.cls</fileName>
          <problem>Entity of type 'ApexClass' named 'Missing' cannot be found</problem>
        </messages>
        <messages>
          <fileName>unpackaged/package.xml</fileName>
          <problem>No package.xml found</problem>
        </messages>
      </result>
    </checkRetrieveStatusResponse>
  </soapenv:Body>
</soapenv:Envelope>"#,
        ))
        .mount(&server)
        .await;

    let md = client_against(&server);
    let result = md
        .check_retrieve_status("09S00000failed", false)
        .await
        .unwrap();
    assert!(result.done);
    assert!(!result.success);
    assert_eq!(result.status, Some(RetrieveStatus::Failed));
    assert!(result.status.unwrap().is_terminal());
    assert_eq!(
        result.error_status_code,
        Some("INVALID_CROSS_REFERENCE_KEY".into())
    );
    assert_eq!(
        result.error_message,
        Some("An error occurred during the retrieve.".into())
    );
    assert_eq!(result.messages.len(), 2);
    assert_eq!(
        result.messages[0].file_name,
        Some("unpackaged/classes/Missing.cls".into())
    );
    assert_eq!(
        result.messages[1].problem,
        "No package.xml found".to_string()
    );
    assert!(result.zip_file.is_none());
}

// -- wait_for_deploy ---------------------------------------------------------

/// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_checkdeploystatus.htm
/// checkDeployStatus() takes an id and an `includeDetails` flag, and
/// the same page prescribes issuing it "in a loop until the done field
/// of the returned DeployResult contains true".
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

/// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_checkdeploystatus.htm
/// `includeDetails` "Sets the DeployResult object to include
/// DeployDetails information", so the details fetch is a second call
/// that can fail on its own.
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

/// A deploy that never reports `done`. The timeout is the SDK's own
/// contract — the guide prescribes no bound on how long a deployment
/// may run.
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

/// The backoff schedule is deliberately built so an unclamped sleep
/// would overshoot: with a 40 ms initial delay and a 2 s cap, the poll
/// at t≈120 ms is followed by a 160 ms sleep, which would push the
/// deadline check for a 140 ms budget out to t≈280 ms — twice the
/// budget the caller asked for.
#[tokio::test]
async fn wait_for_deploy_timeout_fires_within_its_budget() {
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
    let budget = Duration::from_millis(140);
    let started = std::time::Instant::now();
    let err = md
        .wait_for_deploy_with(
            "0Af00000slow",
            WaitConfig {
                initial_delay: Duration::from_millis(40),
                max_delay: Duration::from_secs(2),
                total_timeout: Some(budget),
            },
        )
        .await
        .unwrap_err();
    let elapsed = started.elapsed();

    assert!(matches!(err, MetadataError::PollTimeout(_)));
    assert!(elapsed >= budget, "returned early at {elapsed:?}");
    // Generous headroom for the in-flight poll the budget can't
    // interrupt; the unclamped schedule would land near 280 ms.
    assert!(
        elapsed < budget * 2,
        "timeout overshot its budget: {elapsed:?}"
    );
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

/// Same schedule as the deploy case: an unclamped 160 ms sleep after
/// the t≈120 ms poll would carry a 140 ms budget out to t≈280 ms.
#[tokio::test]
async fn wait_for_retrieve_timeout_fires_within_its_budget() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(body_string_contains(
            "<met:includeZip>false</met:includeZip>",
        ))
        .respond_with(xml_response(&retrieve_status_body(false, false, None)))
        .mount(&server)
        .await;

    let md = client_against(&server);
    let budget = Duration::from_millis(140);
    let started = std::time::Instant::now();
    let err = md
        .wait_for_retrieve_with(
            "09S00000poll",
            WaitConfig {
                initial_delay: Duration::from_millis(40),
                max_delay: Duration::from_secs(2),
                total_timeout: Some(budget),
            },
        )
        .await
        .unwrap_err();
    let elapsed = started.elapsed();

    assert!(matches!(err, MetadataError::PollTimeout(_)));
    assert!(elapsed >= budget, "returned early at {elapsed:?}");
    assert!(
        elapsed < budget * 2,
        "timeout overshot its budget: {elapsed:?}"
    );
}
