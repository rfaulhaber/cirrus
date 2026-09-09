//! Wiremock-backed tests for the utility Metadata API handlers.
//!
//! Covers `list_metadata`, `describe_metadata`, and
//! `describe_value_type` happy paths plus the client-side query-cap
//! check on `list_metadata`.
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
use cirrus_metadata::{ListMetadataQuery, MetadataClient, MetadataError, RetryPolicy};
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

// -- list_metadata -----------------------------------------------------------

/// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_listmetadata.htm
/// "FileProperties[] = metadataConnection.listMetadata(ListMetadataQuery[]
/// queries, double asOfVersion)" — the response is one FileProperties
/// per matching component.
/// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_retrieveresult.htm
/// The FileProperties table (created/lastModified ids and names,
/// fileName, fullName, id, type) lives on the RetrieveResult page.
#[tokio::test]
async fn list_metadata_returns_file_properties_for_each_match() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/services/Soap/m/66.0"))
        .and(body_string_contains("<met:listMetadata>"))
        .and(body_string_contains("<met:type>ApexClass</met:type>"))
        .and(body_string_contains(
            "<met:asOfVersion>66.0</met:asOfVersion>",
        ))
        .respond_with(xml_response(
            r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <listMetadataResponse xmlns="http://soap.sforce.com/2006/04/metadata">
      <result>
        <createdById>005xx0000abc</createdById>
        <createdByName>Stephanie</createdByName>
        <createdDate>2026-01-15T08:00:00.000Z</createdDate>
        <fileName>classes/Foo.cls</fileName>
        <fullName>Foo</fullName>
        <id>01p00000abcDEF</id>
        <lastModifiedById>005xx0000abc</lastModifiedById>
        <lastModifiedByName>Stephanie</lastModifiedByName>
        <lastModifiedDate>2026-05-20T12:00:00.000Z</lastModifiedDate>
        <type>ApexClass</type>
      </result>
      <result>
        <createdById>005xx0000abc</createdById>
        <createdByName>Stephanie</createdByName>
        <createdDate>2026-02-10T08:00:00.000Z</createdDate>
        <fileName>classes/Bar.cls</fileName>
        <fullName>Bar</fullName>
        <id>01p00000xyzGHI</id>
        <lastModifiedById>005xx0000abc</lastModifiedById>
        <lastModifiedByName>Stephanie</lastModifiedByName>
        <lastModifiedDate>2026-04-01T09:30:00.000Z</lastModifiedDate>
        <type>ApexClass</type>
      </result>
    </listMetadataResponse>
  </soapenv:Body>
</soapenv:Envelope>"#,
        ))
        .mount(&server)
        .await;

    let md = client_against(&server);
    let results = md
        .list_metadata(
            vec![ListMetadataQuery {
                type_name: "ApexClass".into(),
                folder: None,
            }],
            "66.0",
        )
        .await
        .unwrap();
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].full_name, "Foo");
    assert_eq!(results[0].type_name, Some("ApexClass".into()));
    assert_eq!(results[1].full_name, "Bar");
}

/// A query that matches nothing. `listMetadata` returns an array, so
/// the wrapper arrives with no `<result>` children rather than as an
/// error.
#[tokio::test]
async fn list_metadata_empty_results_deserialize_as_empty_vec() {
    let server = MockServer::start().await;

    // Empty-response shape — Salesforce returns the wrapper with no
    // <result> children when there's nothing matching.
    Mock::given(method("POST"))
        .respond_with(xml_response(
            r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <listMetadataResponse xmlns="http://soap.sforce.com/2006/04/metadata">
    </listMetadataResponse>
  </soapenv:Body>
</soapenv:Envelope>"#,
        ))
        .mount(&server)
        .await;

    let md = client_against(&server);
    let results = md
        .list_metadata(
            vec![ListMetadataQuery {
                type_name: "CustomObject".into(),
                folder: None,
            }],
            "66.0",
        )
        .await
        .unwrap();
    assert!(results.is_empty());
}

/// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_listmetadataquery.htm
/// ListMetadataQuery: `folder` is "The folder associated with the
/// component. This field is required for components that use folders,
/// such as Dashboard, Document, EmailTemplate, or Report."
#[tokio::test]
async fn list_metadata_emits_folder_for_folder_based_types() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(body_string_contains(
            "<met:folder>SharedDashboards</met:folder>",
        ))
        .and(body_string_contains("<met:type>Dashboard</met:type>"))
        .respond_with(xml_response(
            r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <listMetadataResponse xmlns="http://soap.sforce.com/2006/04/metadata"/>
  </soapenv:Body>
</soapenv:Envelope>"#,
        ))
        .mount(&server)
        .await;

    let md = client_against(&server);
    let _ = md
        .list_metadata(
            vec![ListMetadataQuery {
                type_name: "Dashboard".into(),
                folder: Some("SharedDashboards".into()),
            }],
            "66.0",
        )
        .await
        .unwrap();
}

/// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_listmetadata.htm
/// "The queries array can contain up to three ListMetadataQuery
/// queries for each call."
#[tokio::test]
async fn list_metadata_rejects_more_than_three_queries() {
    // No mock server needed — the rejection happens client-side.
    let auth = Arc::new(StaticTokenAuth::new("tok", "https://x.example.com"));
    let md = MetadataClient::builder().auth(auth).build().unwrap();

    let queries: Vec<_> = (0..4)
        .map(|i| ListMetadataQuery {
            type_name: format!("Type{i}"),
            folder: None,
        })
        .collect();

    let err = md.list_metadata(queries, "66.0").await.unwrap_err();
    match err {
        MetadataError::InvalidArgument(msg) => {
            assert!(msg.contains("3"));
            assert!(msg.contains("4"));
        }
        other => panic!("expected InvalidArgument, got {other:?}"),
    }
}

#[tokio::test]
async fn list_metadata_rejects_empty_query_list() {
    // No mock server needed — the rejection happens client-side, before
    // a zero-query envelope can reach the server (which would answer
    // with an opaque SOAP fault).
    let auth = Arc::new(StaticTokenAuth::new("tok", "https://x.example.com"));
    let md = MetadataClient::builder().auth(auth).build().unwrap();

    let err = md.list_metadata(Vec::new(), "66.0").await.unwrap_err();
    match err {
        MetadataError::InvalidArgument(msg) => {
            assert!(msg.contains("at least one"));
        }
        other => panic!("expected InvalidArgument, got {other:?}"),
    }
}

// -- describe_metadata -------------------------------------------------------

/// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_describemeta_result.htm
/// DescribeMetadataResult: `metadataObjects`, `organizationNamespace`,
/// `partialSaveAllowed` and `testRequired`; the DescribeMetadataObject
/// table on the same page names `directoryName`, `inFolder`,
/// `metaFile`, `suffix`, `xmlName` and `childXmlNames`.
#[tokio::test]
async fn describe_metadata_parses_object_catalog() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(body_string_contains("<met:describeMetadata>"))
        .and(body_string_contains(
            "<met:asOfVersion>66.0</met:asOfVersion>",
        ))
        .respond_with(xml_response(
            r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <describeMetadataResponse xmlns="http://soap.sforce.com/2006/04/metadata">
      <result>
        <metadataObjects>
          <directoryName>classes</directoryName>
          <inFolder>false</inFolder>
          <metaFile>true</metaFile>
          <suffix>cls</suffix>
          <xmlName>ApexClass</xmlName>
        </metadataObjects>
        <metadataObjects>
          <childXmlNames>CustomField</childXmlNames>
          <childXmlNames>ValidationRule</childXmlNames>
          <directoryName>objects</directoryName>
          <inFolder>false</inFolder>
          <metaFile>false</metaFile>
          <suffix>object</suffix>
          <xmlName>CustomObject</xmlName>
        </metadataObjects>
        <metadataObjects>
          <directoryName>dashboards</directoryName>
          <inFolder>true</inFolder>
          <metaFile>false</metaFile>
          <suffix>dashboard</suffix>
          <xmlName>Dashboard</xmlName>
        </metadataObjects>
        <organizationNamespace></organizationNamespace>
        <partialSaveAllowed>true</partialSaveAllowed>
        <testRequired>false</testRequired>
      </result>
    </describeMetadataResponse>
  </soapenv:Body>
</soapenv:Envelope>"#,
        ))
        .mount(&server)
        .await;

    let md = client_against(&server);
    let result = md.describe_metadata("66.0").await.unwrap();
    assert_eq!(result.metadata_objects.len(), 3);
    assert!(result.partial_save_allowed);
    assert!(!result.test_required);

    let apex = &result.metadata_objects[0];
    assert_eq!(apex.xml_name, "ApexClass");
    assert_eq!(apex.directory_name, Some("classes".into()));
    assert_eq!(apex.suffix, Some("cls".into()));
    assert!(!apex.in_folder);
    assert!(apex.meta_file);

    let custom_obj = &result.metadata_objects[1];
    assert_eq!(custom_obj.xml_name, "CustomObject");
    assert_eq!(
        custom_obj.child_xml_names,
        vec!["CustomField".to_string(), "ValidationRule".to_string()]
    );

    let dashboard = &result.metadata_objects[2];
    assert!(dashboard.in_folder);

    // The fixture's `<organizationNamespace></organizationNamespace>`
    // is the shape an org with no namespace sends. It has to arrive as
    // None, or `if let Some(ns) = …` prefixing would build names like
    // "__MyClass".
    assert_eq!(result.organization_namespace, None);
}

/// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_retrieveresult.htm
/// FileProperties: "namespacePrefix | string | The namespace prefix of
/// the component" — present only for components that have one.
///
/// The two blank forms Salesforce sends for an absent string both have
/// to normalize to `None`: a self-closing `xsi:nil` element and an
/// empty one. The `xsi` prefix is declared on the SOAP envelope, which
/// is outside the response element the transport hands the
/// deserializer, so neither form carries nil semantics by the time it
/// is parsed.
#[tokio::test]
async fn blank_string_elements_normalize_to_none() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(body_string_contains("<met:listMetadata>"))
        .respond_with(xml_response(
            r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <soapenv:Body>
    <listMetadataResponse xmlns="http://soap.sforce.com/2006/04/metadata">
      <result>
        <createdById>005xx0000abc</createdById>
        <createdByName>Stephanie</createdByName>
        <createdDate>2026-01-15T08:00:00.000Z</createdDate>
        <fileName>classes/Foo.cls</fileName>
        <fullName>Foo</fullName>
        <id>01p00000abcDEF</id>
        <lastModifiedById>005xx0000abc</lastModifiedById>
        <lastModifiedByName>Stephanie</lastModifiedByName>
        <lastModifiedDate>2026-05-20T12:00:00.000Z</lastModifiedDate>
        <namespacePrefix xsi:nil="true"/>
        <type>ApexClass</type>
      </result>
      <result>
        <createdById>005xx0000abc</createdById>
        <createdByName>Stephanie</createdByName>
        <createdDate>2026-01-15T08:00:00.000Z</createdDate>
        <fileName>classes/Bar.cls</fileName>
        <fullName>Bar</fullName>
        <id>01p00000xyzGHI</id>
        <lastModifiedById>005xx0000abc</lastModifiedById>
        <lastModifiedByName>Stephanie</lastModifiedByName>
        <lastModifiedDate>2026-05-20T12:00:00.000Z</lastModifiedDate>
        <namespacePrefix></namespacePrefix>
        <type>ApexClass</type>
      </result>
      <result>
        <createdById>005xx0000abc</createdById>
        <createdByName>Stephanie</createdByName>
        <createdDate>2026-01-15T08:00:00.000Z</createdDate>
        <fileName>classes/Baz.cls</fileName>
        <fullName>acme__Baz</fullName>
        <id>01p00000jklMNO</id>
        <lastModifiedById>005xx0000abc</lastModifiedById>
        <lastModifiedByName>Stephanie</lastModifiedByName>
        <lastModifiedDate>2026-05-20T12:00:00.000Z</lastModifiedDate>
        <namespacePrefix>acme</namespacePrefix>
        <type>ApexClass</type>
      </result>
    </listMetadataResponse>
  </soapenv:Body>
</soapenv:Envelope>"#,
        ))
        .mount(&server)
        .await;

    let md = client_against(&server);
    let results = md
        .list_metadata(
            vec![ListMetadataQuery {
                type_name: "ApexClass".into(),
                folder: None,
            }],
            "66.0",
        )
        .await
        .unwrap();

    assert_eq!(results[0].namespace_prefix, None, "xsi:nil form");
    assert_eq!(results[1].namespace_prefix, None, "empty-element form");
    // A real namespace still comes through, so the adapter isn't just
    // discarding the field.
    assert_eq!(results[2].namespace_prefix, Some("acme".into()));
}

// -- describe_value_type -----------------------------------------------------

/// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_describeValueTypeResult.htm
/// DescribeValueTypeResult (`apiCreatable`/`apiDeletable`/
/// `apiReadable`/`apiUpdatable`, `valueTypeFields`) plus the
/// ValueTypeField and PicklistEntry tables on the same page.
#[tokio::test]
async fn describe_value_type_parses_field_schema() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(body_string_contains("<met:describeValueType>"))
        .and(body_string_contains(
            "<met:type>{http://soap.sforce.com/2006/04/metadata}ApexClass</met:type>",
        ))
        .respond_with(xml_response(
            r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <describeValueTypeResponse xmlns="http://soap.sforce.com/2006/04/metadata">
      <result>
        <apiCreatable>true</apiCreatable>
        <apiDeletable>true</apiDeletable>
        <apiReadable>true</apiReadable>
        <apiUpdatable>true</apiUpdatable>
        <valueTypeFields>
          <isForeignKey>false</isForeignKey>
          <isNameField>true</isNameField>
          <minOccurs>1</minOccurs>
          <name>fullName</name>
          <soapType>string</soapType>
          <valueRequired>true</valueRequired>
        </valueTypeFields>
        <valueTypeFields>
          <isForeignKey>false</isForeignKey>
          <isNameField>false</isNameField>
          <minOccurs>0</minOccurs>
          <name>apiVersion</name>
          <soapType>double</soapType>
          <valueRequired>false</valueRequired>
        </valueTypeFields>
        <valueTypeFields>
          <isForeignKey>false</isForeignKey>
          <isNameField>false</isNameField>
          <minOccurs>0</minOccurs>
          <name>status</name>
          <soapType>ApexCodeUnitStatus</soapType>
          <valueRequired>false</valueRequired>
          <picklistValues>
            <active>true</active>
            <defaultValue>true</defaultValue>
            <value>Active</value>
          </picklistValues>
          <picklistValues>
            <active>true</active>
            <defaultValue>false</defaultValue>
            <value>Deleted</value>
          </picklistValues>
        </valueTypeFields>
      </result>
    </describeValueTypeResponse>
  </soapenv:Body>
</soapenv:Envelope>"#,
        ))
        .mount(&server)
        .await;

    let md = client_against(&server);
    let result = md
        .describe_value_type("{http://soap.sforce.com/2006/04/metadata}ApexClass")
        .await
        .unwrap();

    assert!(result.api_creatable);
    assert!(result.api_deletable);
    assert!(result.api_readable);
    assert!(result.api_updatable);
    assert_eq!(result.value_type_fields.len(), 3);

    let full_name = &result.value_type_fields[0];
    assert_eq!(full_name.name, Some("fullName".into()));
    assert_eq!(full_name.soap_type, Some("string".into()));
    assert_eq!(full_name.min_occurs, 1);
    assert!(full_name.is_name_field);
    assert!(full_name.value_required);
    assert!(full_name.picklist_values.is_empty());

    let status = &result.value_type_fields[2];
    assert_eq!(status.name, Some("status".into()));
    assert_eq!(status.picklist_values.len(), 2);
    assert_eq!(status.picklist_values[0].value, Some("Active".into()));
    assert!(status.picklist_values[0].default_value);
    assert_eq!(status.picklist_values[1].value, Some("Deleted".into()));
}

/// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_describeValueType.htm
/// The guide's own sample output for
/// `{http://soap.sforce.com/2006/04/metadata}CustomObject` prints one
/// field carrying two foreign key domains:
///
/// ```text
/// Name: customHelp
/// SoapType: string
/// This field is a foreign key.
/// Foreign key domain: ApexPage
/// Foreign key domain: Scontrol
/// ```
///
/// and its Java sample iterates `getForeignKeyDomain()` as a
/// collection on each entry of `valueTypeFields`. That same output
/// opens CustomObject with `** Value type fields **` and no
/// `** Parent type fields **` section, so CustomObject has no parent.
/// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_describeValueTypeResult.htm
/// parentField: "If the value type has no parent, this field is null."
#[tokio::test]
async fn describe_value_type_collects_every_foreign_key_domain() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(body_string_contains(
            "<met:type>{http://soap.sforce.com/2006/04/metadata}CustomObject</met:type>",
        ))
        .respond_with(xml_response(
            r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <describeValueTypeResponse xmlns="http://soap.sforce.com/2006/04/metadata">
      <result>
        <apiCreatable>true</apiCreatable>
        <apiDeletable>true</apiDeletable>
        <apiReadable>true</apiReadable>
        <apiUpdatable>true</apiUpdatable>
        <valueTypeFields>
          <isForeignKey>false</isForeignKey>
          <isNameField>false</isNameField>
          <minOccurs>0</minOccurs>
          <name>compactLayoutAssignment</name>
          <soapType>string</soapType>
          <valueRequired>false</valueRequired>
        </valueTypeFields>
        <valueTypeFields>
          <foreignKeyDomain>ApexPage</foreignKeyDomain>
          <foreignKeyDomain>Scontrol</foreignKeyDomain>
          <isForeignKey>true</isForeignKey>
          <isNameField>false</isNameField>
          <minOccurs>0</minOccurs>
          <name>customHelp</name>
          <soapType>string</soapType>
          <valueRequired>false</valueRequired>
        </valueTypeFields>
      </result>
    </describeValueTypeResponse>
  </soapenv:Body>
</soapenv:Envelope>"#,
        ))
        .mount(&server)
        .await;

    let md = client_against(&server);
    let result = md
        .describe_value_type("{http://soap.sforce.com/2006/04/metadata}CustomObject")
        .await
        .unwrap();

    // A repeated element bound to a scalar field aborts the whole
    // document, so the two-domain field is what proves the list shape.
    let custom_help = &result.value_type_fields[1];
    assert_eq!(custom_help.name, Some("customHelp".into()));
    assert!(custom_help.is_foreign_key);
    assert_eq!(custom_help.foreign_key_domain, ["ApexPage", "Scontrol"]);

    // A non-key field carries no domain, and CustomObject has no parent.
    assert!(result.value_type_fields[0].foreign_key_domain.is_empty());
    assert!(result.parent_field.is_none());
}

/// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_describeValueType.htm
/// The sample output for
/// `{http://soap.sforce.com/2006/04/metadata}CustomField` is the one
/// that prints a parent:
///
/// ```text
/// ** Parent type fields **
/// This field is a foreign key.
/// Foreign key domain: CustomObject
/// ```
///
/// and the Java sample reads it through the same collection-valued
/// `getForeignKeyDomain()` accessor it uses on `valueTypeFields`.
/// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_describeValueTypeResult.htm
/// ValueTypeField.name: "The name is null for parent fields."
#[tokio::test]
async fn describe_value_type_reports_the_parent_field_domain() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(body_string_contains(
            "<met:type>{http://soap.sforce.com/2006/04/metadata}CustomField</met:type>",
        ))
        .respond_with(xml_response(
            r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <describeValueTypeResponse xmlns="http://soap.sforce.com/2006/04/metadata">
      <result>
        <apiCreatable>true</apiCreatable>
        <apiDeletable>true</apiDeletable>
        <apiReadable>true</apiReadable>
        <apiUpdatable>true</apiUpdatable>
        <parentField>
          <foreignKeyDomain>CustomObject</foreignKeyDomain>
          <isForeignKey>true</isForeignKey>
          <isNameField>false</isNameField>
          <minOccurs>0</minOccurs>
          <soapType>string</soapType>
          <valueRequired>false</valueRequired>
        </parentField>
        <valueTypeFields>
          <isForeignKey>false</isForeignKey>
          <isNameField>false</isNameField>
          <minOccurs>0</minOccurs>
          <name>caseSensitive</name>
          <soapType>boolean</soapType>
          <valueRequired>false</valueRequired>
        </valueTypeFields>
        <valueTypeFields>
          <isForeignKey>false</isForeignKey>
          <isNameField>false</isNameField>
          <minOccurs>0</minOccurs>
          <name>defaultValue</name>
          <soapType>string</soapType>
          <valueRequired>false</valueRequired>
        </valueTypeFields>
      </result>
    </describeValueTypeResponse>
  </soapenv:Body>
</soapenv:Envelope>"#,
        ))
        .mount(&server)
        .await;

    let md = client_against(&server);
    let result = md
        .describe_value_type("{http://soap.sforce.com/2006/04/metadata}CustomField")
        .await
        .unwrap();

    let parent = result.parent_field.as_ref().unwrap();
    assert!(parent.is_foreign_key);
    assert_eq!(parent.foreign_key_domain, ["CustomObject"]);
    assert_eq!(parent.name, None);
    assert_eq!(result.value_type_fields.len(), 2);
}
