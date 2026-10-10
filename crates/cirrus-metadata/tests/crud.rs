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
//! only what sits inside `<result>` is doc-cited. The fixtures use
//! `CustomObject`, the type in the guide's own Java sample on every
//! CRUD page; `ApexClass` is documented as supporting every Metadata
//! API call except the CRUD-based ones.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use cirrus_metadata::auth::StaticTokenAuth;
use cirrus_metadata::{CrudOptions, MetadataClient, MetadataError, MetadataType, RetryPolicy};
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
/// errors returned if the operation wasn't successful").
/// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_error.htm
/// Error, the element type of that array: `fields` ("An array
/// containing names of fields that affected the error condition"),
/// `message` ("The error message text") and `statusCode` ("A status
/// code corresponding to the error").
#[tokio::test]
async fn create_metadata_returns_save_results_per_component() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/services/Soap/m/66.0"))
        .and(body_string_contains("<met:createMetadata>"))
        .and(body_string_contains(
            r#"<met:metadata xsi:type="met:CustomObject""#,
        ))
        // The wrapper declares the metadata namespace as default so
        // children without prefix end up in the metadata namespace.
        .and(body_string_contains(
            r#"xmlns="http://soap.sforce.com/2006/04/metadata""#,
        ))
        .and(body_string_contains(
            "<fullName>MyCustomObject1__c</fullName>",
        ))
        .and(body_string_contains(
            "<fullName>MyCustomObject2__c</fullName>",
        ))
        .respond_with(xml_response(
            r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <createMetadataResponse xmlns="http://soap.sforce.com/2006/04/metadata">
      <result>
        <fullName>MyCustomObject1__c</fullName>
        <success>true</success>
      </result>
      <result>
        <fullName>MyCustomObject2__c</fullName>
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
    let object_a = "<fullName>MyCustomObject1__c</fullName><label>MyCustomObject1 Object</label>";
    let object_b = "<fullName>MyCustomObject2__c</fullName><label>MyCustomObject2 Object</label>";
    let results = md
        .create_metadata("CustomObject", &[object_a, object_b])
        .await
        .unwrap();

    assert_eq!(results.len(), 2);
    assert_eq!(results[0].full_name, "MyCustomObject1__c");
    assert!(results[0].success);
    assert!(results[0].errors.is_empty());

    assert_eq!(results[1].full_name, "MyCustomObject2__c");
    assert!(!results[1].success);
    assert_eq!(results[1].errors.len(), 1);
    assert_eq!(results[1].errors[0].status_code, "DUPLICATE_VALUE");
    assert_eq!(results[1].errors[0].fields, vec!["fullName".to_string()]);
}

/// The type name is anything `AsRef<str>`, so the `MetadataType`
/// constants that build manifests name CRUD types too, by value or by
/// reference, alongside plain strings.
/// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_custommetadata.htm
/// CustomMetadata supports the CRUD-based calls; its `fullName` is
/// `TypeName.RecordName` and it carries a `label`.
#[tokio::test]
async fn crud_calls_take_a_metadata_type_for_the_type_name() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(body_string_contains("<met:createMetadata>"))
        .and(body_string_contains(
            r#"<met:metadata xsi:type="met:CustomMetadata""#,
        ))
        .respond_with(xml_response(
            r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <createMetadataResponse xmlns="http://soap.sforce.com/2006/04/metadata">
      <result>
        <fullName>Settings.Default</fullName>
        <success>true</success>
      </result>
    </createMetadataResponse>
  </soapenv:Body>
</soapenv:Envelope>"#,
        ))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(body_string_contains("<met:readMetadata>"))
        .and(body_string_contains("<met:type>CustomMetadata</met:type>"))
        .respond_with(xml_response(
            r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <readMetadataResponse xmlns="http://soap.sforce.com/2006/04/metadata">
      <result>
        <records>
          <fullName>Settings.Default</fullName>
          <label>Default</label>
        </records>
      </result>
    </readMetadataResponse>
  </soapenv:Body>
</soapenv:Envelope>"#,
        ))
        .mount(&server)
        .await;

    let md = client_against(&server);
    let results = md
        .create_metadata(
            MetadataType::CUSTOM_METADATA,
            &["<fullName>Settings.Default</fullName><label>Default</label>"],
        )
        .await
        .unwrap();
    assert!(results[0].success);

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Record {
        full_name: Option<String>,
        label: Option<String>,
    }
    let records: Vec<Record> = md
        .read_metadata(&MetadataType::CUSTOM_METADATA, &["Settings.Default"])
        .await
        .unwrap();
    assert_eq!(records[0].full_name.as_deref(), Some("Settings.Default"));
    assert_eq!(records[0].label.as_deref(), Some("Default"));
}

/// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_custommetadata.htm
/// Every CustomMetadata sample types its values with the `xsd` prefix,
/// `<value xsi:type="xsd:boolean">false</value>`, declaring
/// `xmlns:xsd` on the root the CRUD caller strips away. The envelope
/// binds both `xsi` and `xsd` so the pasted inner XML resolves.
#[tokio::test]
async fn create_metadata_envelope_binds_the_xsd_prefix_for_typed_values() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(body_string_contains(
            r#"xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance""#,
        ))
        .and(body_string_contains(
            r#"xmlns:xsd="http://www.w3.org/2001/XMLSchema""#,
        ))
        .and(body_string_contains(
            r#"<value xsi:type="xsd:boolean">false</value>"#,
        ))
        .respond_with(xml_response(
            r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <createMetadataResponse xmlns="http://soap.sforce.com/2006/04/metadata">
      <result>
        <fullName>Settings.Default</fullName>
        <success>true</success>
      </result>
    </createMetadataResponse>
  </soapenv:Body>
</soapenv:Envelope>"#,
        ))
        .mount(&server)
        .await;

    let md = client_against(&server);
    let record = r#"<fullName>Settings.Default</fullName><label>Default</label>
        <values><field>Enabled__c</field><value xsi:type="xsd:boolean">false</value></values>"#;
    let results = md
        .create_metadata(MetadataType::CUSTOM_METADATA, &[record])
        .await
        .unwrap();
    assert!(results[0].success);
}

/// An empty component array has nothing to save, so it is rejected
/// before an envelope is built rather than spending a round trip.
#[tokio::test]
async fn create_metadata_rejects_empty_input_before_sending() {
    // No mock — the rejection happens client-side.
    let auth = Arc::new(StaticTokenAuth::new("tok", "https://x.example.com"));
    let md = MetadataClient::builder().auth(auth).build().unwrap();

    let err = md
        .create_metadata::<&str, _>("CustomObject", &[])
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
    let err = md.create_metadata("CustomObject", &xml).await.unwrap_err();
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
        <fullName>MyCustomObject1__c</fullName>
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
            "CustomObject",
            &["<fullName>MyCustomObject1__c</fullName><label>MyCustomObject1 Object Update</label>"],
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
        <fullName>MyCustomObject1__c</fullName>
        <success>true</success>
        <created>true</created>
      </result>
      <result>
        <fullName>MyCustomObject2__c</fullName>
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
            "CustomObject",
            &[
                "<fullName>MyCustomObject1__c</fullName>",
                "<fullName>MyCustomObject2__c</fullName>",
            ],
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
/// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_error.htm
/// Error, the element type of that array: `fields`, `message` ("The
/// error message text") and `statusCode` ("A status code
/// corresponding to the error").
#[tokio::test]
async fn delete_metadata_returns_one_result_per_full_name() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(body_string_contains("<met:deleteMetadata>"))
        .and(body_string_contains("<met:type>CustomObject</met:type>"))
        .and(body_string_contains(
            "<met:fullNames>MyCustomObject1__c</met:fullNames>",
        ))
        .and(body_string_contains(
            "<met:fullNames>MyCustomObject2__c</met:fullNames>",
        ))
        .respond_with(xml_response(
            r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <deleteMetadataResponse xmlns="http://soap.sforce.com/2006/04/metadata">
      <result>
        <fullName>MyCustomObject1__c</fullName>
        <success>true</success>
      </result>
      <result>
        <fullName>MyCustomObject2__c</fullName>
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
        .delete_metadata(
            "CustomObject",
            &["MyCustomObject1__c", "MyCustomObject2__c"],
        )
        .await
        .unwrap();
    assert_eq!(results.len(), 2);
    assert!(results[0].success);
    assert!(!results[1].success);
    assert_eq!(results[1].errors[0].status_code, "INVALID_TYPE");
}

// -- read_metadata -----------------------------------------------------------

/// Caller shape for `readMetadata`-of-CustomObject, with the three
/// fields the guide's `readMetadata()` Java sample reads back.
///
/// Every field is optional, including `fullName`: a requested name the
/// org doesn't have comes back as a content-free placeholder record,
/// and one required field would fail the whole document.
#[derive(Deserialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
struct CustomObjectRecord {
    #[serde(default)]
    full_name: Option<String>,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    sharing_model: Option<String>,
}

/// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_readResult.htm
/// ReadResult: "records | Metadata[] | An array of metadata components
/// returned from readMetadata()." The children of each `<records>`
/// element are the caller's own metadata type — here a CustomObject.
#[tokio::test]
async fn read_metadata_deserializes_records_into_caller_type() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(body_string_contains("<met:readMetadata>"))
        .and(body_string_contains("<met:type>CustomObject</met:type>"))
        .respond_with(xml_response(
            r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <readMetadataResponse xmlns="http://soap.sforce.com/2006/04/metadata">
      <result>
        <records>
          <fullName>MyCustomObject1__c</fullName>
          <label>MyCustomObject1 Object</label>
          <sharingModel>ReadWrite</sharingModel>
        </records>
        <records>
          <fullName>MyCustomObject2__c</fullName>
          <label>MyCustomObject2 Object</label>
          <sharingModel>Private</sharingModel>
        </records>
      </result>
    </readMetadataResponse>
  </soapenv:Body>
</soapenv:Envelope>"#,
        ))
        .mount(&server)
        .await;

    let md = client_against(&server);
    let records: Vec<CustomObjectRecord> = md
        .read_metadata(
            "CustomObject",
            &["MyCustomObject1__c", "MyCustomObject2__c"],
        )
        .await
        .unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].full_name, Some("MyCustomObject1__c".into()));
    assert_eq!(records[0].label, Some("MyCustomObject1 Object".into()));
    assert_eq!(records[0].sharing_model, Some("ReadWrite".into()));
    assert_eq!(records[1].full_name, Some("MyCustomObject2__c".into()));
    assert_eq!(records[1].sharing_model, Some("Private".into()));
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
    let records: Vec<CustomObjectRecord> = md
        .read_metadata("CustomObject", &["NotFound"])
        .await
        .unwrap();
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
        .and(body_string_contains(
            "<met:fullNames>MyCustomObject1__c</met:fullNames>",
        ))
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
          <fullName>MyCustomObject1__c</fullName>
          <label>MyCustomObject1 Object</label>
          <sharingModel>ReadWrite</sharingModel>
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
    let records: Vec<CustomObjectRecord> = md
        .read_metadata("CustomObject", &["MyCustomObject1__c", "DoesNotExist"])
        .await
        .unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].full_name, Some("MyCustomObject1__c".into()));
    // Every field absent is the "no such component" signal.
    assert_eq!(records[1].full_name, None);
    assert_eq!(records[1].label, None);
    assert_eq!(records[1].sharing_model, None);
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
        .and(body_string_contains("<met:type>CustomObject</met:type>"))
        .and(body_string_contains(
            "<met:oldFullName>MyCustomObject1__c</met:oldFullName>",
        ))
        .and(body_string_contains(
            "<met:newFullName>MyCustomObject1New__c</met:newFullName>",
        ))
        .respond_with(xml_response(
            r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <renameMetadataResponse xmlns="http://soap.sforce.com/2006/04/metadata">
      <result>
        <fullName>MyCustomObject1New__c</fullName>
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
        .rename_metadata(
            "CustomObject",
            "MyCustomObject1__c",
            "MyCustomObject1New__c",
        )
        .await
        .unwrap();
    assert!(result.success);
    assert_eq!(result.full_name, "MyCustomObject1New__c");
}

/// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_saveResult.htm
/// A rename that fails reports it in the SaveResult's `errors` array,
/// not as a SOAP fault.
/// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_error.htm
/// Error, the element type of that array: `fields`, `message` ("The
/// error message text") and `statusCode` ("A status code
/// corresponding to the error").
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
        <fullName>MyCustomObject1__c</fullName>
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
        .rename_metadata(
            "CustomObject",
            "MyCustomObject1__c",
            "MyCustomObject1New__c",
        )
        .await
        .unwrap();
    assert!(!result.success);
    assert_eq!(result.errors.len(), 1);
    assert_eq!(result.errors[0].status_code, "INVALID_TYPE");
    assert_eq!(result.errors[0].message, "No such component");
}

// -- AllOrNoneHeader ---------------------------------------------------------

/// The header element, placed right after the SessionHeader.
const ALL_OR_NONE_AFTER_SESSION: &str = "</met:SessionHeader>\
     <met:AllOrNoneHeader><met:allOrNone>true</met:allOrNone></met:AllOrNoneHeader>\
     </soapenv:Header>";

fn save_results_response(operation: &str) -> ResponseTemplate {
    xml_response(&format!(
        r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <{operation}Response xmlns="http://soap.sforce.com/2006/04/metadata">
      <result>
        <fullName>MyCustomObject1__c</fullName>
        <success>true</success>
        <created>true</created>
      </result>
    </{operation}Response>
  </soapenv:Body>
</soapenv:Envelope>"#
    ))
}

/// Mounts a mock for `operation` that, when `with_header` is set, also
/// requires the header adjacent to the SessionHeader. Without it, a
/// mock that must never see an AllOrNoneHeader is mounted *first*:
/// wiremock hands a request to the first mock that matches, so a
/// request carrying the header would reach it and fail its
/// `expect(0)`, where a later mock would never be asked.
async fn mount_all_or_none_expectation(server: &MockServer, operation: &str, with_header: bool) {
    if !with_header {
        Mock::given(method("POST"))
            .and(body_string_contains("AllOrNoneHeader"))
            .respond_with(save_results_response(operation))
            .expect(0)
            .mount(server)
            .await;
    }
    let mut positive = Mock::given(method("POST"))
        .and(path("/services/Soap/m/66.0"))
        .and(body_string_contains(format!("<met:{operation}>")));
    if with_header {
        positive = positive.and(body_string_contains(ALL_OR_NONE_AFTER_SESSION));
    }
    positive
        .respond_with(save_results_response(operation))
        .expect(1)
        .mount(server)
        .await;
}

/// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_allornoneheader.htm
/// AllOrNoneHeader (API 34.0 and later): "allOrNone | boolean | Set to
/// true to roll back all changes if any record in the call fails";
/// absent is equivalent to false; supported on createMetadata(),
/// updateMetadata(), upsertMetadata() and deleteMetadata().
/// SOURCE: API 66.0 Metadata WSDL (sforce.660.metadata.wsdl): the
/// `AllOrNoneHeader{allOrNone: boolean}` element, bound as an input
/// header of those four operations.
#[tokio::test]
async fn create_metadata_with_all_or_none_sends_the_header_after_the_session_header() {
    let server = MockServer::start().await;
    mount_all_or_none_expectation(&server, "createMetadata", true).await;

    let md = client_against(&server);
    md.create_metadata_with(
        "CustomObject",
        &["<fullName>MyCustomObject1__c</fullName>"],
        CrudOptions { all_or_none: true },
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn create_metadata_sends_no_all_or_none_header() {
    let server = MockServer::start().await;
    mount_all_or_none_expectation(&server, "createMetadata", false).await;

    let md = client_against(&server);
    md.create_metadata("CustomObject", &["<fullName>MyCustomObject1__c</fullName>"])
        .await
        .unwrap();
}

#[tokio::test]
async fn create_metadata_with_default_options_sends_no_all_or_none_header() {
    let server = MockServer::start().await;
    mount_all_or_none_expectation(&server, "createMetadata", false).await;

    let md = client_against(&server);
    md.create_metadata_with(
        "CustomObject",
        &["<fullName>MyCustomObject1__c</fullName>"],
        CrudOptions::default(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn update_metadata_with_all_or_none_sends_the_header() {
    let server = MockServer::start().await;
    mount_all_or_none_expectation(&server, "updateMetadata", true).await;

    let md = client_against(&server);
    md.update_metadata_with(
        "CustomObject",
        &["<fullName>MyCustomObject1__c</fullName>"],
        CrudOptions { all_or_none: true },
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn update_metadata_sends_no_all_or_none_header() {
    let server = MockServer::start().await;
    mount_all_or_none_expectation(&server, "updateMetadata", false).await;

    let md = client_against(&server);
    md.update_metadata("CustomObject", &["<fullName>MyCustomObject1__c</fullName>"])
        .await
        .unwrap();
}

#[tokio::test]
async fn upsert_metadata_with_all_or_none_sends_the_header() {
    let server = MockServer::start().await;
    mount_all_or_none_expectation(&server, "upsertMetadata", true).await;

    let md = client_against(&server);
    md.upsert_metadata_with(
        "CustomObject",
        &["<fullName>MyCustomObject1__c</fullName>"],
        CrudOptions { all_or_none: true },
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn upsert_metadata_sends_no_all_or_none_header() {
    let server = MockServer::start().await;
    mount_all_or_none_expectation(&server, "upsertMetadata", false).await;

    let md = client_against(&server);
    md.upsert_metadata("CustomObject", &["<fullName>MyCustomObject1__c</fullName>"])
        .await
        .unwrap();
}

#[tokio::test]
async fn delete_metadata_with_all_or_none_sends_the_header() {
    let server = MockServer::start().await;
    mount_all_or_none_expectation(&server, "deleteMetadata", true).await;

    let md = client_against(&server);
    md.delete_metadata_with(
        "CustomObject",
        &["MyCustomObject1__c"],
        CrudOptions { all_or_none: true },
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn delete_metadata_sends_no_all_or_none_header() {
    let server = MockServer::start().await;
    mount_all_or_none_expectation(&server, "deleteMetadata", false).await;

    let md = client_against(&server);
    md.delete_metadata("CustomObject", &["MyCustomObject1__c"])
        .await
        .unwrap();
}

/// The `_with` forms keep the per-call component cap.
#[tokio::test]
async fn create_metadata_with_still_enforces_the_component_cap() {
    let auth = Arc::new(StaticTokenAuth::new("tok", "https://x.example.com"));
    let md = MetadataClient::builder().auth(auth).build().unwrap();
    let empty: [&str; 0] = [];
    let err = md
        .create_metadata_with("CustomObject", &empty, CrudOptions { all_or_none: true })
        .await
        .unwrap_err();
    assert!(matches!(err, MetadataError::InvalidArgument(_)));
}

// -- Component well-formedness -------------------------------------------

/// A component is spliced into the envelope as written, so one that is
/// not a well-formed fragment would corrupt the request or, with a
/// stray `</met:metadata>`, inject sibling components. Each shape here
/// is refused before any request is made, and the error names the call,
/// the component and the escaper.
#[tokio::test]
async fn write_calls_refuse_a_component_that_is_not_a_well_formed_fragment() {
    let server = MockServer::start().await;
    let md = client_against(&server);
    let malformed = [
        // A bare ampersand in text.
        "<fullName>R&D</fullName>",
        // Closes the wrapper and injects a second component.
        r#"<fullName>A</fullName></met:metadata><met:metadata xsi:type="met:PermissionSet"><fullName>B</fullName>"#,
        // An unclosed element.
        "<fullName>A",
        // A mismatched end tag.
        "<fullName>A</label>",
        // An entity the Metadata API's parser has no definition for.
        "<label>&nbsp;</label>",
        // A declaration cannot appear inside an envelope.
        r#"<?xml version="1.0"?><fullName>A</fullName>"#,
    ];
    for component in malformed {
        let components = ["<fullName>Fine</fullName>", component];
        let results = [
            (
                "create_metadata",
                md.create_metadata("CustomObject", &components)
                    .await
                    .map(drop),
            ),
            (
                "update_metadata",
                md.update_metadata("CustomObject", &components)
                    .await
                    .map(drop),
            ),
            (
                "upsert_metadata",
                md.upsert_metadata("CustomObject", &components)
                    .await
                    .map(drop),
            ),
        ];
        for (label, result) in results {
            let err = result.unwrap_err();
            assert!(
                matches!(err, MetadataError::InvalidArgument(_)),
                "{label} {component:?}: {err:?}"
            );
            let msg = err.to_string();
            assert!(msg.contains(label), "{msg}");
            assert!(msg.contains("component 1"), "{msg}");
            assert!(msg.contains("xml_escape"), "{msg}");
        }
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

/// A well-formed fragment goes out exactly as written: sibling elements,
/// escaped text, predefined and numeric references, CDATA, a comment, an
/// empty element and an `xsi:type` attribute all pass.
#[tokio::test]
async fn write_calls_splice_a_well_formed_fragment_as_written() {
    let server = MockServer::start().await;
    let component = "<fullName>MyCustomObject1__c</fullName>\
         <label>R&amp;D &#x26; &#38; &quot;</label>\
         <description><![CDATA[a < b]]></description>\
         <!-- a comment -->\
         <enableActivities/>\
         <nameField><type>Text</type><label>Name</label></nameField>\
         <values><value xsi:type=\"xsd:boolean\">false</value></values>";
    Mock::given(method("POST"))
        .and(body_string_contains(component))
        .respond_with(save_results_response("createMetadata"))
        .expect(1)
        .mount(&server)
        .await;
    let md = client_against(&server);
    md.create_metadata("CustomObject", &[component])
        .await
        .unwrap();
}
