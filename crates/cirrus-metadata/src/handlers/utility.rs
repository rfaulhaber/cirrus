//! Utility (synchronous) Metadata API handlers.
//!
//! These calls return immediately — no polling, no zip files. They're
//! the discovery layer:
//!
//! - [`MetadataClient::list_metadata`] — enumerate components of a
//!   given type, useful for building a `package.xml` for a subsequent
//!   `retrieve` call.
//! - [`MetadataClient::describe_metadata`] — catalog every metadata
//!   type the org supports plus its directory/suffix conventions.
//! - [`MetadataClient::describe_value_type`] — schema for one specific
//!   metadata type (field list, foreign keys, picklist options).

use crate::MetadataClient;
use crate::envelope::xml_escape;
use crate::error::{MetadataError, MetadataResult};
use crate::result::{
    DescribeMetadataResult, DescribeValueTypeResult, FileProperties, ListMetadataQuery,
};
use crate::transport::SoapOperation;
use serde::Deserialize;

/// Salesforce server limit — at most 3 [`ListMetadataQuery`] entries
/// per `listMetadata` call.
pub const MAX_LIST_METADATA_QUERIES_PER_CALL: usize = 3;

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

struct ListMetadataOp<'a> {
    queries: Vec<ListMetadataQuery>,
    as_of_version: &'a str,
}

/// Wire wrapper for `<listMetadataResponse>...</listMetadataResponse>`.
///
/// The response has zero or more `<result>` siblings, one per matching
/// component. `#[serde(rename = "result")]` on a `Vec` picks them all up.
#[derive(Deserialize)]
struct ListMetadataResponseWire {
    #[serde(default, rename = "result")]
    results: Vec<FileProperties>,
}

impl SoapOperation for ListMetadataOp<'_> {
    const NAME: &'static str = "listMetadata";
    // Read-only: safe to replay on ambiguous transport failures.
    const IDEMPOTENT: bool = true;
    type Response = ListMetadataResponseWire;

    fn render_body(&self) -> MetadataResult<String> {
        let mut out = String::with_capacity(64 + self.queries.len() * 64);
        for q in &self.queries {
            out.push_str("<met:queries>");
            if let Some(folder) = &q.folder {
                out.push_str("<met:folder>");
                out.push_str(&xml_escape(folder));
                out.push_str("</met:folder>");
            }
            out.push_str("<met:type>");
            out.push_str(&xml_escape(&q.type_name));
            out.push_str("</met:type>");
            out.push_str("</met:queries>");
        }
        // Salesforce parses asOfVersion as XSD double; "66.0" is the
        // canonical form. We accept any string the caller provides and
        // let the server validate.
        out.push_str("<met:asOfVersion>");
        out.push_str(&xml_escape(self.as_of_version));
        out.push_str("</met:asOfVersion>");
        Ok(out)
    }
}

struct DescribeMetadataOp<'a> {
    as_of_version: &'a str,
}

#[derive(Deserialize)]
struct DescribeMetadataResponseWire {
    result: DescribeMetadataResult,
}

impl SoapOperation for DescribeMetadataOp<'_> {
    const NAME: &'static str = "describeMetadata";
    // Read-only: safe to replay on ambiguous transport failures.
    const IDEMPOTENT: bool = true;
    type Response = DescribeMetadataResponseWire;

    fn render_body(&self) -> MetadataResult<String> {
        Ok(format!(
            "<met:asOfVersion>{}</met:asOfVersion>",
            xml_escape(self.as_of_version),
        ))
    }
}

struct DescribeValueTypeOp {
    type_name: String,
}

#[derive(Deserialize)]
struct DescribeValueTypeResponseWire {
    result: DescribeValueTypeResult,
}

impl SoapOperation for DescribeValueTypeOp {
    const NAME: &'static str = "describeValueType";
    // The Metadata WSDL (API 66.0, sforce.660.metadata.wsdl) binds
    // CallOptions on every operation except this one.
    const ACCEPTS_CALL_OPTIONS: bool = false;
    // Read-only: safe to replay on ambiguous transport failures.
    const IDEMPOTENT: bool = true;
    type Response = DescribeValueTypeResponseWire;

    fn render_body(&self) -> MetadataResult<String> {
        Ok(format!(
            "<met:type>{}</met:type>",
            xml_escape(&self.type_name),
        ))
    }
}

// ---------------------------------------------------------------------------
// Public API on MetadataClient
// ---------------------------------------------------------------------------

impl MetadataClient {
    /// Enumerate metadata components of one or more types.
    ///
    /// Each [`ListMetadataQuery`] picks one metadata type (and
    /// optionally a folder for folder-based types). The Salesforce
    /// server limits this to **3 queries per call** — pass more and
    /// we return [`MetadataError::InvalidArgument`] before hitting the
    /// wire. For broader enumeration, batch into multiple calls.
    ///
    /// `as_of_version` controls the API version used to evaluate the
    /// queries (e.g. `"66.0"`); this matters when types/fields are added
    /// or removed across releases. Pass [`Self::api_version`] to use the
    /// client's configured version.
    ///
    /// Returns `Vec<FileProperties>` — one entry per matched
    /// component. Empty when nothing matches.
    pub async fn list_metadata(
        &self,
        queries: Vec<ListMetadataQuery>,
        as_of_version: &str,
    ) -> MetadataResult<Vec<FileProperties>> {
        if queries.is_empty() {
            return Err(MetadataError::InvalidArgument(
                "listMetadata requires at least one query; got 0".to_string(),
            ));
        }
        if queries.len() > MAX_LIST_METADATA_QUERIES_PER_CALL {
            return Err(MetadataError::InvalidArgument(format!(
                "listMetadata accepts at most {MAX_LIST_METADATA_QUERIES_PER_CALL} queries per \
                 call; got {}",
                queries.len()
            )));
        }
        let op = ListMetadataOp {
            queries,
            as_of_version,
        };
        let resp = self.call(&op).await?;
        Ok(resp.results)
    }

    /// Catalog the metadata types this org supports.
    ///
    /// Returns one [`DescribeMetadataObject`] per type, with the
    /// directory name, file suffix, and child-type relationships.
    /// This is the canonical source for `package.xml` `<types><name>`
    /// values and for the zip directory layout — handlers building
    /// deploy zips should reference this rather than hard-coding the
    /// list.
    ///
    /// `as_of_version` is the API version of the catalog (e.g. `"66.0"`).
    /// Pass the version your tooling targets so newly-added types in
    /// newer versions don't surface unexpectedly.
    ///
    /// [`DescribeMetadataObject`]: crate::result::DescribeMetadataObject
    pub async fn describe_metadata(
        &self,
        as_of_version: &str,
    ) -> MetadataResult<DescribeMetadataResult> {
        let op = DescribeMetadataOp { as_of_version };
        let resp = self.call(&op).await?;
        Ok(resp.result)
    }

    /// Describe the schema of one specific metadata type.
    ///
    /// `qualified_type_name` is the type's name qualified with the
    /// Metadata API's SOAP namespace, for example
    /// `"{http://soap.sforce.com/2006/04/metadata}ApexClass"`. The
    /// Tooling API describes its own types under
    /// `{urn:metadata.tooling.soap.sforce.com}`, but Salesforce serves
    /// those through a Tooling SOAP connection, which this client does
    /// not provide; a name in that namespace is refused with
    /// [`MetadataError::InvalidArgument`] before any request is made.
    ///
    /// [`MetadataError::InvalidArgument`]: crate::MetadataError::InvalidArgument
    /// Returns field-level metadata — types, requirement flags,
    /// foreign-key relationships, picklist options. Useful for
    /// validating component XML before deploy or for generating
    /// typed bindings.
    pub async fn describe_value_type(
        &self,
        qualified_type_name: &str,
    ) -> MetadataResult<DescribeValueTypeResult> {
        const TOOLING_NAMESPACE: &str = "{urn:metadata.tooling.soap.sforce.com}";
        if qualified_type_name.starts_with(TOOLING_NAMESPACE) {
            return Err(MetadataError::InvalidArgument(format!(
                "describe_value_type: `{qualified_type_name}` is in the Tooling API's namespace, \
                 which Salesforce serves through a Tooling SOAP connection; this client posts \
                 only to the Metadata API"
            )));
        }
        let op = DescribeValueTypeOp {
            type_name: qualified_type_name.to_string(),
        };
        let resp = self.call(&op).await?;
        Ok(resp.result)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn list_metadata_op_emits_queries_and_version() {
        let op = ListMetadataOp {
            queries: vec![
                ListMetadataQuery {
                    type_name: "ApexClass".into(),
                    folder: None,
                },
                ListMetadataQuery {
                    type_name: "Dashboard".into(),
                    folder: Some("SharedDashboards".into()),
                },
            ],
            as_of_version: "66.0",
        };
        let body = op.render_body().unwrap();
        assert!(body.contains("<met:queries><met:type>ApexClass</met:type></met:queries>"));
        assert!(body.contains(
            "<met:queries><met:folder>SharedDashboards</met:folder><met:type>Dashboard</met:type></met:queries>"
        ));
        assert!(body.contains("<met:asOfVersion>66.0</met:asOfVersion>"));
    }

    #[test]
    fn list_metadata_op_escapes_folder_and_type() {
        let op = ListMetadataOp {
            queries: vec![ListMetadataQuery {
                type_name: "Type<>".into(),
                folder: Some("Folder&Co".into()),
            }],
            as_of_version: "66.0",
        };
        let body = op.render_body().unwrap();
        assert!(body.contains("<met:folder>Folder&amp;Co</met:folder>"));
        assert!(body.contains("<met:type>Type&lt;&gt;</met:type>"));
    }

    #[test]
    fn describe_metadata_op_emits_version() {
        let op = DescribeMetadataOp {
            as_of_version: "58.0",
        };
        let body = op.render_body().unwrap();
        assert_eq!(body, "<met:asOfVersion>58.0</met:asOfVersion>");
    }

    #[test]
    fn describe_value_type_emits_qualified_type() {
        let op = DescribeValueTypeOp {
            type_name: "{http://soap.sforce.com/2006/04/metadata}ApexClass".into(),
        };
        let body = op.render_body().unwrap();
        // Curly braces aren't XML-reserved, so they pass through
        // unescaped — sanity-check that.
        assert_eq!(
            body,
            "<met:type>{http://soap.sforce.com/2006/04/metadata}ApexClass</met:type>"
        );
    }
}
