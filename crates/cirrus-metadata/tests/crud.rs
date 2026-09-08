//! Wiremock-backed tests for the CRUD-based handlers.
//!
//! Covers `create_metadata`, `update_metadata`, `upsert_metadata`,
//! `delete_metadata`, `read_metadata`, and `rename_metadata`. The
//! happy-path fixtures exercise the SOAP wire shapes; the
//! partial-success and 11-cap tests cover the realistic failure
//! modes.
//!
//! ## Fixture provenance
//!
//! Every fixture's elements come from a property table or Java sample
//! in the Metadata API Developer Guide; each test names the page. The
//! guide publishes no SOAP envelope example, so the
//! `<soapenv:Envelope><soapenv:Body><xxxResponse>` framing follows the
//! WSDL's document-literal binding rather than a published sample —
//! only what sits inside `<result>` is doc-cited.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use cirrus_metadata::auth::StaticTokenAuth;
use cirrus_metadata::{MetadataClient, MetadataError, RetryPolicy};
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

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

// -- create_metadata ---------------------------------------------------------

/// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_createMetadata.htm
/// "SaveResult[] = metadataConnection.createMetadata(Metadata[]
/// metadata)"; the call "can save a partial set of records for records
/// with no errors" by default in API 34.0 and later, which is the
/// mixed result below.
/// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_saveResult.htm
/// SaveResult: `fullName`, `success`, and `errors` ("An array of
/// errors returned if the operation wasn't successful") whose entries
/// carry `statusCode`, `message` and `fields`.
#[tokio::test]
async fn create_metadata_returns_save_results_per_component() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/services/Soap/m/66.0"))
        .and(body_string_contains("<met:createMetadata>"))
        .and(body_string_contains(
            r#"<met:metadata xsi:type="met:ApexClass""#,
        ))
        // The wrapper declares the metadata namespace as default so
        // children without prefix end up in the metadata namespace.
        .and(body_string_contains(
            r#"xmlns="http://soap.sforce.com/2006/04/metadata""#,
        ))
        .and(body_string_contains("<fullName>Foo</fullName>"))
        .and(body_string_contains("<fullName>Bar</fullName>"))
        .respond_with(xml_response(
            r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <createMetadataResponse xmlns="http://soap.sforce.com/2006/04/metadata">
      <result>
        <fullName>Foo</fullName>
        <success>true</success>
      </result>
      <result>
        <fullName>Bar</fullName>
        <success>false</success>
        <errors>
          <statusCode>DUPLICATE_VALUE</statusCode>
          <message>An object with that name already exists.</message>
          <fields>fullName</fields>
        </errors>
      </result>
    </createMetadataResponse>
  </soapenv:Body>
</soapenv:Envelope>"#,
        ))
        .mount(&server)
        .await;

    let md = client_against(&server);
    let class_a = "<fullName>Foo</fullName><apiVersion>66.0</apiVersion>";
    let class_b = "<fullName>Bar</fullName><apiVersion>66.0</apiVersion>";
    let results = md
        .create_metadata("ApexClass", &[class_a, class_b])
        .await
        .unwrap();

    assert_eq!(results.len(), 2);
    assert_eq!(results[0].full_name, "Foo");
    assert!(results[0].success);
    assert!(results[0].errors.is_empty());

    assert_eq!(results[1].full_name, "Bar");
    assert!(!results[1].success);
    assert_eq!(results[1].errors.len(), 1);
    assert_eq!(results[1].errors[0].status_code, "DUPLICATE_VALUE");
    assert_eq!(results[1].errors[0].fields, vec!["fullName".to_string()]);
}

/// An empty component array has nothing to save, so it is rejected
/// before an envelope is built rather than spending a round trip.
#[tokio::test]
async fn create_metadata_rejects_empty_input_before_sending() {
    // No mock — the rejection happens client-side.
    let auth = Arc::new(StaticTokenAuth::new("tok", "https://x.example.com"));
    let md = MetadataClient::builder().auth(auth).build().unwrap();

    let err = md
        .create_metadata::<&str>("ApexClass", &[])
        .await
        .unwrap_err();
    match err {
        MetadataError::InvalidArgument(msg) => assert!(msg.contains("at least one")),
        other => panic!("expected InvalidArgument, got {other:?}"),
    }
}

/// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_createMetadata.htm
/// Arguments table, `metadata Metadata[]`: "Limit: 10. (For
/// CustomMetadata and CustomApplication only, the limit is 200.)"
#[tokio::test]
async fn create_metadata_rejects_more_than_ten_components() {
    let auth = Arc::new(StaticTokenAuth::new("tok", "https://x.example.com"));
    let md = MetadataClient::builder().auth(auth).build().unwrap();

    let xml: Vec<String> = (0..11)
        .map(|i| format!("<fullName>X{i}</fullName>"))
        .collect();
    let err = md.create_metadata("ApexClass", &xml).await.unwrap_err();
    match err {
        MetadataError::InvalidArgument(msg) => {
            assert!(msg.contains("10"));
            assert!(msg.contains("11"));
        }
        other => panic!("expected InvalidArgument, got {other:?}"),
    }
}

// -- update_metadata ---------------------------------------------------------

/// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_updateMetadata.htm
/// updateMetadata() returns SaveResult[], the same shape
/// createMetadata() does.
#[tokio::test]
async fn update_metadata_returns_save_results() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(body_string_contains("<met:updateMetadata>"))
        .respond_with(xml_response(
            r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <updateMetadataResponse xmlns="http://soap.sforce.com/2006/04/metadata">
      <result>
        <fullName>MyClass</fullName>
        <success>true</success>
      </result>
    </updateMetadataResponse>
  </soapenv:Body>
</soapenv:Envelope>"#,
        ))
        .mount(&server)
        .await;

    let md = client_against(&server);
    let results = md
        .update_metadata(
            "ApexClass",
            &["<fullName>MyClass</fullName><apiVersion>66.0</apiVersion>"],
        )
        .await
        .unwrap();
    assert_eq!(results.len(), 1);
    assert!(results[0].success);
}

// -- upsert_metadata ---------------------------------------------------------

/// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_upsertMetadata.htm
/// The Arguments table reads "Limit: 10." for `metadata Metadata[]`,
/// with none of the "(For CustomMetadata and CustomApplication only,
/// the limit is 200.)" clause the other four component-array calls
/// carry. The client-side guard has to hold upsert to 10 even for the
/// two types those calls exempt, or an over-limit envelope reaches the
/// wire.
#[tokio::test]
async fn upsert_metadata_caps_large_types_at_ten_like_every_other_type() {
    let auth = Arc::new(StaticTokenAuth::new("tok", "https://x.example.com"));
    let md = MetadataClient::builder().auth(auth).build().unwrap();

    let xml: Vec<String> = (0..11)
        .map(|i| format!("<fullName>Rec.X{i}</fullName>"))
        .collect();
    let err = md
        .upsert_metadata("CustomMetadata", &xml)
        .await
        .unwrap_err();
    match err {
        MetadataError::InvalidArgument(msg) => {
            assert!(msg.contains("upsert_metadata"), "{msg}");
            assert!(msg.contains("10"), "{msg}");
            assert!(msg.contains("11"), "{msg}");
        }
        other => panic!("expected InvalidArgument, got {other:?}"),
    }
}

/// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_upsertResult.htm
/// UpsertResult adds `created` to the SaveResult shape: "Indicates
/// whether the upsert operation resulted in the creation of the
/// component (true) or not (false). If false and the upsert operation
/// was successful, the component was updated."
#[tokio::test]
async fn upsert_metadata_returns_created_flag_per_component() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(body_string_contains("<met:upsertMetadata>"))
        .respond_with(xml_response(
            r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <upsertMetadataResponse xmlns="http://soap.sforce.com/2006/04/metadata">
      <result>
        <fullName>Foo</fullName>
        <success>true</success>
        <created>true</created>
      </result>
      <result>
        <fullName>Bar</fullName>
        <success>true</success>
        <created>false</created>
      </result>
    </upsertMetadataResponse>
  </soapenv:Body>
</soapenv:Envelope>"#,
        ))
        .mount(&server)
        .await;

    let md = client_against(&server);
    let results = md
        .upsert_metadata(
            "ApexClass",
            &["<fullName>Foo</fullName>", "<fullName>Bar</fullName>"],
        )
        .await
        .unwrap();
    assert_eq!(results.len(), 2);
    assert!(results[0].success);
    assert!(results[0].created);
    assert!(results[1].success);
    assert!(!results[1].created);
}

// -- delete_metadata ---------------------------------------------------------

/// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_deleteResult.htm
/// DeleteResult: `fullName` ("The full name of the deleted
/// component"), `success`, and `errors`.
#[tokio::test]
async fn delete_metadata_returns_one_result_per_full_name() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(body_string_contains("<met:deleteMetadata>"))
        .and(body_string_contains("<met:type>ApexClass</met:type>"))
        .and(body_string_contains("<met:fullNames>Foo</met:fullNames>"))
        .and(body_string_contains("<met:fullNames>Bar</met:fullNames>"))
        .respond_with(xml_response(
            r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <deleteMetadataResponse xmlns="http://soap.sforce.com/2006/04/metadata">
      <result>
        <fullName>Foo</fullName>
        <success>true</success>
      </result>
      <result>
        <fullName>Bar</fullName>
        <success>false</success>
        <errors>
          <statusCode>INVALID_TYPE</statusCode>
          <message>Component does not exist</message>
        </errors>
      </result>
    </deleteMetadataResponse>
  </soapenv:Body>
</soapenv:Envelope>"#,
        ))
        .mount(&server)
        .await;

    let md = client_against(&server);
    let results = md
        .delete_metadata("ApexClass", &["Foo", "Bar"])
        .await
        .unwrap();
    assert_eq!(results.len(), 2);
    assert!(results[0].success);
    assert!(!results[1].success);
    assert_eq!(results[1].errors[0].status_code, "INVALID_TYPE");
}

// -- read_metadata -----------------------------------------------------------

/// Caller shape for `readMetadata`-of-ApexClass.
///
/// Every field is optional, including `fullName`: a requested name the
/// org doesn't have comes back as a content-free placeholder record,
/// and one required field would fail the whole document.
#[derive(Deserialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
struct ApexClassRecord {
    #[serde(default)]
    full_name: Option<String>,
    #[serde(default)]
    api_version: Option<String>,
    #[serde(default)]
    status: Option<String>,
}

/// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_readResult.htm
/// ReadResult: "records | Metadata[] | An array of metadata components
/// returned from readMetadata()." The children of each `<records>`
/// element are the caller's own metadata type — here an ApexClass.
#[tokio::test]
async fn read_metadata_deserializes_records_into_caller_type() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(body_string_contains("<met:readMetadata>"))
        .and(body_string_contains("<met:type>ApexClass</met:type>"))
        .respond_with(xml_response(
            r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <readMetadataResponse xmlns="http://soap.sforce.com/2006/04/metadata">
      <result>
        <records>
          <fullName>Foo</fullName>
          <apiVersion>66.0</apiVersion>
          <status>Active</status>
        </records>
        <records>
          <fullName>Bar</fullName>
          <apiVersion>65.0</apiVersion>
          <status>Deleted</status>
        </records>
      </result>
    </readMetadataResponse>
  </soapenv:Body>
</soapenv:Envelope>"#,
        ))
        .mount(&server)
        .await;

    let md = client_against(&server);
    let records: Vec<ApexClassRecord> = md
        .read_metadata("ApexClass", &["Foo", "Bar"])
        .await
        .unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].full_name, Some("Foo".into()));
    assert_eq!(records[0].api_version, Some("66.0".into()));
    assert_eq!(records[0].status, Some("Active".into()));
    assert_eq!(records[1].full_name, Some("Bar".into()));
    assert_eq!(records[1].status, Some("Deleted".into()));
}

/// A ReadResult whose `records` array is empty; the handler must
/// answer with an empty `Vec` rather than a deserialization error.
#[tokio::test]
async fn read_metadata_empty_result_yields_empty_vec() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .respond_with(xml_response(
            r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <readMetadataResponse xmlns="http://soap.sforce.com/2006/04/metadata">
      <result></result>
    </readMetadataResponse>
  </soapenv:Body>
</soapenv:Envelope>"#,
        ))
        .mount(&server)
        .await;

    let md = client_against(&server);
    let records: Vec<ApexClassRecord> = md.read_metadata("ApexClass", &["NotFound"]).await.unwrap();
    assert!(records.is_empty());
}

/// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_readMetadata.htm
/// The guide's Java sample walks `readResult.getRecords()` and guards
/// each entry — `if (md != null) { … } else { "Empty metadata." }` —
/// so a records entry can carry no component. The guide publishes no
/// response envelope; the `xsi:nil` spelling below is the form live
/// orgs send (see `tests/integration/crud.rs`).
///
/// The placeholder must not cost the caller the names that resolved,
/// which is why the whole records array has to survive it.
#[tokio::test]
async fn read_metadata_tolerates_the_placeholder_for_a_missing_full_name() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(body_string_contains("<met:fullNames>Foo</met:fullNames>"))
        .and(body_string_contains(
            "<met:fullNames>DoesNotExist</met:fullNames>",
        ))
        .respond_with(xml_response(
            r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <soapenv:Body>
    <readMetadataResponse xmlns="http://soap.sforce.com/2006/04/metadata">
      <result>
        <records>
          <fullName>Foo</fullName>
          <apiVersion>66.0</apiVersion>
          <status>Active</status>
        </records>
        <records xsi:nil="true"/>
      </result>
    </readMetadataResponse>
  </soapenv:Body>
</soapenv:Envelope>"#,
        ))
        .mount(&server)
        .await;

    let md = client_against(&server);
    let records: Vec<ApexClassRecord> = md
        .read_metadata("ApexClass", &["Foo", "DoesNotExist"])
        .await
        .unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].full_name, Some("Foo".into()));
    // Every field absent is the "no such component" signal.
    assert_eq!(records[1].full_name, None);
    assert_eq!(records[1].api_version, None);
    assert_eq!(records[1].status, None);
}

// -- rename_metadata ---------------------------------------------------------

/// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_renameMetadata.htm
/// "SaveResult = metadataConnection.renameMetadata(string
/// metadataType, String oldFullname, String newFullname)" — one
/// component per call, so `<result>` holds a single SaveResult.
#[tokio::test]
async fn rename_metadata_returns_single_save_result() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(body_string_contains("<met:renameMetadata>"))
        .and(body_string_contains("<met:type>ApexClass</met:type>"))
        .and(body_string_contains(
            "<met:oldFullName>OldName</met:oldFullName>",
        ))
        .and(body_string_contains(
            "<met:newFullName>NewName</met:newFullName>",
        ))
        .respond_with(xml_response(
            r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <renameMetadataResponse xmlns="http://soap.sforce.com/2006/04/metadata">
      <result>
        <fullName>NewName</fullName>
        <success>true</success>
      </result>
    </renameMetadataResponse>
  </soapenv:Body>
</soapenv:Envelope>"#,
        ))
        .mount(&server)
        .await;

    let md = client_against(&server);
    let result = md
        .rename_metadata("ApexClass", "OldName", "NewName")
        .await
        .unwrap();
    assert!(result.success);
    assert_eq!(result.full_name, "NewName");
}

/// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_saveResult.htm
/// A rename that fails reports it in the SaveResult's `errors` array,
/// not as a SOAP fault.
#[tokio::test]
async fn rename_metadata_propagates_error_in_save_result() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .respond_with(xml_response(
            r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <renameMetadataResponse xmlns="http://soap.sforce.com/2006/04/metadata">
      <result>
        <fullName>OldName</fullName>
        <success>false</success>
        <errors>
          <statusCode>INVALID_TYPE</statusCode>
          <message>No such component</message>
        </errors>
      </result>
    </renameMetadataResponse>
  </soapenv:Body>
</soapenv:Envelope>"#,
        ))
        .mount(&server)
        .await;

    let md = client_against(&server);
    let result = md
        .rename_metadata("ApexClass", "OldName", "NewName")
        .await
        .unwrap();
    assert!(!result.success);
    assert_eq!(result.errors.len(), 1);
    assert_eq!(result.errors[0].status_code, "INVALID_TYPE");
    assert_eq!(result.errors[0].message, "No such component");
}
