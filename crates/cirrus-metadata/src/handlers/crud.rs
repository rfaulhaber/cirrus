//! Synchronous CRUD-based Metadata API handlers.
//!
//! These calls let you create / read / update / upsert / delete /
//! rename individual metadata components in a single SOAP round-trip
//! — no zip files, no async polling. They sit alongside the file-based
//! [`deploy`] / [`retrieve`] flow and cover the same lifecycle
//! operations at a finer grain.
//!
//! ## What the SDK does and doesn't model
//!
//! Salesforce defines ~200 concrete metadata types (`CustomObject`,
//! `ApexClass`, `Profile`, …). Modeling every one as a typed Rust
//! struct would be brittle (types change every release) and against
//! cirrus's "no user-facing types" principle. So:
//!
//! - For [`MetadataClient::create_metadata`] /
//!   [`MetadataClient::update_metadata`] /
//!   [`MetadataClient::upsert_metadata`] the caller supplies
//!   **pre-rendered XML inner content** per component. The SDK wraps
//!   each component in a
//!   `<metadata xsi:type="met:{TypeName}">…</metadata>` element and
//!   handles the SOAP envelope.
//! - For [`MetadataClient::read_metadata`] the caller supplies a typed
//!   `R: Deserialize` shape that maps over one `<records>` element. The
//!   SDK returns `Vec<R>`.
//!
//! Inside the `<metadata>` wrapper the metadata namespace is declared
//! as the default, so callers can write naked element names —
//! `<fullName>Foo</fullName>` rather than
//! `<met:fullName>Foo</met:fullName>`. Both forms work; the naked
//! form is more readable for hand-built XML.
//!
//! ## Per-call component cap
//!
//! All five "multi" CRUD calls cap at 10 components per call (server
//! limit), except `CustomMetadata` and `CustomApplication`, which
//! Salesforce documents at 200. The SDK enforces this client-side via
//! [`MAX_CRUD_COMPONENTS_PER_CALL`] /
//! [`MAX_CRUD_COMPONENTS_PER_CALL_LARGE`] — passing more returns
//! [`MetadataError::InvalidArgument`] before hitting the wire.
//!
//! [`deploy`]: crate::MetadataClient::deploy
//! [`retrieve`]: crate::MetadataClient::retrieve
//! [`MetadataError::InvalidArgument`]: crate::MetadataError::InvalidArgument

use crate::MetadataClient;
use crate::envelope::xml_escape;
use crate::error::{MetadataError, MetadataResult};
use crate::result::{DeleteResult, SaveResult, UpsertResult};
use crate::transport::SoapOperation;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use std::marker::PhantomData;

/// Salesforce server limit on per-call component count for
/// `createMetadata`, `updateMetadata`, `upsertMetadata`,
/// `readMetadata`, and `deleteMetadata`. `CustomMetadata` and
/// `CustomApplication` are the documented exceptions — see
/// [`MAX_CRUD_COMPONENTS_PER_CALL_LARGE`].
pub const MAX_CRUD_COMPONENTS_PER_CALL: usize = 10;

/// Raised per-call component limit for `CustomMetadata` and
/// `CustomApplication`, the two types Salesforce documents at 200
/// components per CRUD call.
pub const MAX_CRUD_COMPONENTS_PER_CALL_LARGE: usize = 200;

/// The documented per-call cap for a metadata type.
fn per_call_cap(type_name: &str) -> usize {
    match type_name {
        "CustomMetadata" | "CustomApplication" => MAX_CRUD_COMPONENTS_PER_CALL_LARGE,
        _ => MAX_CRUD_COMPONENTS_PER_CALL,
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Render `<met:metadata xsi:type="met:{TYPE}" xmlns="...">CHILDREN</met:metadata>`
/// for each caller-supplied component. The default-namespace declaration
/// on the wrapper means callers' children don't need a `met:` prefix.
fn render_metadata_components<S: AsRef<str>>(type_name: &str, components: &[S], out: &mut String) {
    for component in components {
        out.push_str(r#"<met:metadata xsi:type="met:"#);
        out.push_str(&xml_escape(type_name));
        // Declare the metadata namespace as default *within* the
        // wrapper. Caller-written children without a prefix end up
        // in the metadata namespace, which is what the server
        // expects.
        out.push_str(r#"" xmlns="http://soap.sforce.com/2006/04/metadata">"#);
        out.push_str(component.as_ref());
        out.push_str("</met:metadata>");
    }
}

/// Render `<met:type>X</met:type><met:fullNames>...</met:fullNames>...` —
/// the shared body shape for `readMetadata` and `deleteMetadata`.
fn render_type_and_full_names<S: AsRef<str>>(type_name: &str, full_names: &[S], out: &mut String) {
    out.push_str("<met:type>");
    out.push_str(&xml_escape(type_name));
    out.push_str("</met:type>");
    for name in full_names {
        out.push_str("<met:fullNames>");
        out.push_str(&xml_escape(name.as_ref()));
        out.push_str("</met:fullNames>");
    }
}

fn check_component_cap(count: usize, type_name: &str, op_label: &str) -> MetadataResult<()> {
    if count == 0 {
        return Err(MetadataError::InvalidArgument(format!(
            "{op_label} requires at least one component; got 0"
        )));
    }
    let cap = per_call_cap(type_name);
    if count > cap {
        return Err(MetadataError::InvalidArgument(format!(
            "{op_label} accepts at most {cap} {type_name} components per call; got {count}"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

struct CreateMetadataOp<'a, S: AsRef<str>> {
    type_name: &'a str,
    components: &'a [S],
}

#[derive(Deserialize)]
struct SaveResultsWire {
    #[serde(default, rename = "result")]
    results: Vec<SaveResult>,
}

impl<S: AsRef<str>> SoapOperation for CreateMetadataOp<'_, S> {
    const NAME: &'static str = "createMetadata";
    type Response = SaveResultsWire;

    fn render_body(&self) -> MetadataResult<String> {
        let mut out = String::with_capacity(self.components.len() * 256);
        render_metadata_components(self.type_name, self.components, &mut out);
        Ok(out)
    }
}

struct UpdateMetadataOp<'a, S: AsRef<str>> {
    type_name: &'a str,
    components: &'a [S],
}

impl<S: AsRef<str>> SoapOperation for UpdateMetadataOp<'_, S> {
    const NAME: &'static str = "updateMetadata";
    type Response = SaveResultsWire;

    fn render_body(&self) -> MetadataResult<String> {
        let mut out = String::with_capacity(self.components.len() * 256);
        render_metadata_components(self.type_name, self.components, &mut out);
        Ok(out)
    }
}

struct UpsertMetadataOp<'a, S: AsRef<str>> {
    type_name: &'a str,
    components: &'a [S],
}

#[derive(Deserialize)]
struct UpsertResultsWire {
    #[serde(default, rename = "result")]
    results: Vec<UpsertResult>,
}

impl<S: AsRef<str>> SoapOperation for UpsertMetadataOp<'_, S> {
    const NAME: &'static str = "upsertMetadata";
    type Response = UpsertResultsWire;

    fn render_body(&self) -> MetadataResult<String> {
        let mut out = String::with_capacity(self.components.len() * 256);
        render_metadata_components(self.type_name, self.components, &mut out);
        Ok(out)
    }
}

struct DeleteMetadataOp<'a, S: AsRef<str>> {
    type_name: &'a str,
    full_names: &'a [S],
}

#[derive(Deserialize)]
struct DeleteResultsWire {
    #[serde(default, rename = "result")]
    results: Vec<DeleteResult>,
}

impl<S: AsRef<str>> SoapOperation for DeleteMetadataOp<'_, S> {
    const NAME: &'static str = "deleteMetadata";
    type Response = DeleteResultsWire;

    fn render_body(&self) -> MetadataResult<String> {
        let mut out = String::with_capacity(64 + self.full_names.len() * 64);
        render_type_and_full_names(self.type_name, self.full_names, &mut out);
        Ok(out)
    }
}

struct ReadMetadataOp<'a, T, S: AsRef<str>> {
    type_name: &'a str,
    full_names: &'a [S],
    _marker: PhantomData<fn() -> T>,
}

#[derive(Deserialize)]
#[serde(bound(deserialize = "T: serde::de::DeserializeOwned"))]
struct ReadMetadataResponseWire<T> {
    result: ReadResultWire<T>,
}

#[derive(Deserialize)]
// Without an explicit deserialize bound, serde adds `T: Default` because
// of `#[serde(default)]` on `records`. That bound bleeds into callers
// who only need `Deserialize`. Pin the bound to just deserialization —
// `Vec<T>::default()` works for any `T` regardless.
#[serde(bound(deserialize = "T: serde::de::DeserializeOwned"))]
struct ReadResultWire<T> {
    // Wire-shape provenance (api_meta doc page IDs):
    // - `meta_readMetadata`'s Java sample guards every entry of
    //   `readResult.getRecords()` with `if (md != null) … else
    //   "Empty metadata."`, so a records entry can carry no component
    //   at all. The guide publishes no response envelope, so the
    //   placeholder's exact XML form isn't documented; live orgs send
    //   `<records xsi:nil="true"/>`.
    // - Deserializing the placeholder per element is not available:
    //   quick-xml applies `xsi:nil` to named `Option` fields, not to
    //   sequence elements, so `Vec<Option<T>>` reports it as
    //   `Some(T)` with every field absent rather than `None`. That is
    //   why the all-optional `T` requirement is on `read_metadata`
    //   instead.
    #[serde(default = "Vec::new")]
    records: Vec<T>,
}

impl<T, S> SoapOperation for ReadMetadataOp<'_, T, S>
where
    T: DeserializeOwned,
    S: AsRef<str>,
{
    const NAME: &'static str = "readMetadata";
    // Read-only: safe to replay on ambiguous transport failures.
    const IDEMPOTENT: bool = true;
    type Response = ReadMetadataResponseWire<T>;

    fn render_body(&self) -> MetadataResult<String> {
        let mut out = String::with_capacity(64 + self.full_names.len() * 64);
        render_type_and_full_names(self.type_name, self.full_names, &mut out);
        Ok(out)
    }
}

struct RenameMetadataOp<'a> {
    type_name: &'a str,
    old_full_name: &'a str,
    new_full_name: &'a str,
}

#[derive(Deserialize)]
struct RenameMetadataResponseWire {
    result: SaveResult,
}

impl SoapOperation for RenameMetadataOp<'_> {
    const NAME: &'static str = "renameMetadata";
    type Response = RenameMetadataResponseWire;

    fn render_body(&self) -> MetadataResult<String> {
        Ok(format!(
            "<met:type>{}</met:type>\
             <met:oldFullName>{}</met:oldFullName>\
             <met:newFullName>{}</met:newFullName>",
            xml_escape(self.type_name),
            xml_escape(self.old_full_name),
            xml_escape(self.new_full_name),
        ))
    }
}

// ---------------------------------------------------------------------------
// Public API on MetadataClient
// ---------------------------------------------------------------------------

impl MetadataClient {
    /// Create one or more metadata components synchronously.
    ///
    /// All components must be of the same `type_name`. Each entry in
    /// `components` is the inner XML of one `<metadata>` element — the
    /// SDK wraps each in `<metadata xsi:type="met:{type_name}">…</metadata>`
    /// and handles the SOAP envelope. Inside the wrapper, the
    /// metadata namespace is the default, so caller XML can use bare
    /// element names like `<fullName>Foo</fullName>`.
    ///
    /// ```no_run
    /// # use cirrus_metadata::{MetadataClient, SaveResult, MetadataError};
    /// # async fn example(md: &MetadataClient) -> Result<(), MetadataError> {
    /// let class = r#"
    ///     <fullName>MyClass</fullName>
    ///     <apiVersion>66.0</apiVersion>
    ///     <status>Active</status>
    ///     <content>cHVibGljIGNsYXNzIE15Q2xhc3Mge30=</content>
    /// "#;
    /// let results: Vec<SaveResult> = md.create_metadata("ApexClass", &[class]).await?;
    /// for r in &results {
    ///     assert!(r.success, "create failed: {:?}", r.errors);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Returns one [`SaveResult`] per component. Partial success is
    /// possible — inspect each entry's `success` field and per-entry
    /// `errors`.
    pub async fn create_metadata<S: AsRef<str>>(
        &self,
        type_name: &str,
        components: &[S],
    ) -> MetadataResult<Vec<SaveResult>> {
        check_component_cap(components.len(), type_name, "create_metadata")?;
        let op = CreateMetadataOp {
            type_name,
            components,
        };
        let resp = self.call(&op).await?;
        Ok(resp.results)
    }

    /// Update one or more existing metadata components.
    ///
    /// Same input shape as [`Self::create_metadata`] — each
    /// component's `<fullName>` identifies which existing component
    /// to update. Returns one [`SaveResult`] per component.
    pub async fn update_metadata<S: AsRef<str>>(
        &self,
        type_name: &str,
        components: &[S],
    ) -> MetadataResult<Vec<SaveResult>> {
        check_component_cap(components.len(), type_name, "update_metadata")?;
        let op = UpdateMetadataOp {
            type_name,
            components,
        };
        let resp = self.call(&op).await?;
        Ok(resp.results)
    }

    /// Create or update one or more metadata components.
    ///
    /// Same input shape as [`Self::create_metadata`]. The returned
    /// [`UpsertResult::created`] flag distinguishes per-component
    /// inserts (`true`) from updates (`false`). Available in
    /// API v31+.
    pub async fn upsert_metadata<S: AsRef<str>>(
        &self,
        type_name: &str,
        components: &[S],
    ) -> MetadataResult<Vec<UpsertResult>> {
        check_component_cap(components.len(), type_name, "upsert_metadata")?;
        let op = UpsertMetadataOp {
            type_name,
            components,
        };
        let resp = self.call(&op).await?;
        Ok(resp.results)
    }

    /// Delete one or more metadata components.
    ///
    /// Returns one [`DeleteResult`] per `full_names` entry. Partial
    /// success is possible — inspect each entry.
    pub async fn delete_metadata<S: AsRef<str>>(
        &self,
        type_name: &str,
        full_names: &[S],
    ) -> MetadataResult<Vec<DeleteResult>> {
        check_component_cap(full_names.len(), type_name, "delete_metadata")?;
        let op = DeleteMetadataOp {
            type_name,
            full_names,
        };
        let resp = self.call(&op).await?;
        Ok(resp.results)
    }

    /// Read one or more metadata components synchronously.
    ///
    /// The caller supplies a typed `T: Deserialize` shape that maps
    /// over one `<records>` element. Component XML uses the metadata
    /// namespace as default on the wire, so quick-xml's serde
    /// deserialize sees field names like `fullName`, `apiVersion`,
    /// `status`, etc.
    ///
    /// **Every field of `T` must be optional** — `Option<_>` or
    /// `#[serde(default)]`, including `fullName`. A `fullName` that
    /// doesn't resolve doesn't drop out of the response: Salesforce
    /// answers it with a content-free placeholder record, which
    /// deserializes into a `T` with every field absent. A `T` carrying
    /// one required field turns that placeholder into a
    /// [`MetadataError::Xml`], losing the components that *did*
    /// resolve along with it. Treat `full_name.is_some()` as the
    /// "this component exists" signal.
    ///
    /// ```no_run
    /// # use cirrus_metadata::{MetadataClient, MetadataError};
    /// # use serde::Deserialize;
    /// #[derive(Deserialize)]
    /// #[serde(rename_all = "camelCase")]
    /// struct ApexClassRecord {
    ///     #[serde(default)]
    ///     full_name: Option<String>,
    ///     #[serde(default)]
    ///     api_version: Option<String>,
    ///     #[serde(default)]
    ///     status: Option<String>,
    ///     #[serde(default)]
    ///     content: Option<String>,
    /// }
    ///
    /// # async fn example(md: &MetadataClient) -> Result<(), MetadataError> {
    /// let classes: Vec<ApexClassRecord> = md
    ///     .read_metadata::<ApexClassRecord, _>("ApexClass", &["Foo", "Bar"])
    ///     .await?;
    /// for class in &classes {
    ///     let Some(name) = &class.full_name else {
    ///         continue; // placeholder for a name the org doesn't have
    ///     };
    ///     println!("{name}");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// [`MetadataError::Xml`]: crate::MetadataError::Xml
    pub async fn read_metadata<T, S>(
        &self,
        type_name: &str,
        full_names: &[S],
    ) -> MetadataResult<Vec<T>>
    where
        T: DeserializeOwned,
        S: AsRef<str>,
    {
        check_component_cap(full_names.len(), type_name, "read_metadata")?;
        let op = ReadMetadataOp::<T, S> {
            type_name,
            full_names,
            _marker: PhantomData,
        };
        let resp = self.call(&op).await?;
        Ok(resp.result.records)
    }

    /// Rename a single metadata component.
    ///
    /// Returns a single [`SaveResult`] — unlike the array-returning
    /// CRUD calls, `renameMetadata` takes one component at a time.
    pub async fn rename_metadata(
        &self,
        type_name: &str,
        old_full_name: &str,
        new_full_name: &str,
    ) -> MetadataResult<SaveResult> {
        let op = RenameMetadataOp {
            type_name,
            old_full_name,
            new_full_name,
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
    fn create_op_wraps_components_with_xsi_type_and_default_ns() {
        let op = CreateMetadataOp {
            type_name: "ApexClass",
            components: &["<fullName>Foo</fullName>"],
        };
        let body = op.render_body().unwrap();
        assert!(body.contains(r#"<met:metadata xsi:type="met:ApexClass""#));
        assert!(body.contains(r#"xmlns="http://soap.sforce.com/2006/04/metadata""#));
        assert!(body.contains("<fullName>Foo</fullName>"));
        assert!(body.contains("</met:metadata>"));
    }

    #[test]
    fn create_op_emits_one_wrapper_per_component() {
        let op = CreateMetadataOp {
            type_name: "ApexClass",
            components: &["<fullName>A</fullName>", "<fullName>B</fullName>"],
        };
        let body = op.render_body().unwrap();
        assert_eq!(
            body.matches(r#"<met:metadata xsi:type="met:ApexClass""#)
                .count(),
            2
        );
        assert_eq!(body.matches("</met:metadata>").count(), 2);
    }

    #[test]
    fn read_op_emits_type_and_full_names() {
        // Dummy stand-in for T — only renders body XML, doesn't
        // exercise deserialization.
        #[derive(Deserialize)]
        struct Empty {}
        let op = ReadMetadataOp::<Empty, _> {
            type_name: "ApexClass",
            full_names: &["Foo", "Bar"],
            _marker: PhantomData,
        };
        let body = op.render_body().unwrap();
        assert_eq!(
            body,
            "<met:type>ApexClass</met:type>\
             <met:fullNames>Foo</met:fullNames>\
             <met:fullNames>Bar</met:fullNames>"
        );
    }

    #[test]
    fn delete_op_shares_body_shape_with_read() {
        let op = DeleteMetadataOp {
            type_name: "ApexTrigger",
            full_names: &["AccountTrigger"],
        };
        let body = op.render_body().unwrap();
        assert_eq!(
            body,
            "<met:type>ApexTrigger</met:type>\
             <met:fullNames>AccountTrigger</met:fullNames>"
        );
    }

    #[test]
    fn rename_op_emits_type_and_both_full_names() {
        let op = RenameMetadataOp {
            type_name: "ApexClass",
            old_full_name: "OldName",
            new_full_name: "NewName",
        };
        let body = op.render_body().unwrap();
        assert_eq!(
            body,
            "<met:type>ApexClass</met:type>\
             <met:oldFullName>OldName</met:oldFullName>\
             <met:newFullName>NewName</met:newFullName>"
        );
    }

    #[test]
    fn render_escapes_special_chars_in_type_and_names() {
        let op = DeleteMetadataOp {
            type_name: "Weird<>",
            full_names: &["a&b"],
        };
        let body = op.render_body().unwrap();
        assert!(body.contains("<met:type>Weird&lt;&gt;</met:type>"));
        assert!(body.contains("<met:fullNames>a&amp;b</met:fullNames>"));
    }

    #[test]
    fn check_component_cap_rejects_empty_input() {
        let err = check_component_cap(0, "ApexClass", "create_metadata").unwrap_err();
        assert!(err.to_string().contains("at least one"));
    }

    #[test]
    fn check_component_cap_rejects_more_than_ten() {
        let err = check_component_cap(11, "ApexClass", "delete_metadata").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("10"));
        assert!(msg.contains("11"));
    }

    #[test]
    fn check_component_cap_accepts_one_to_ten() {
        for n in 1..=10 {
            assert!(
                check_component_cap(n, "ApexClass", "x").is_ok(),
                "should accept {n}"
            );
        }
    }

    /// CustomMetadata / CustomApplication carry a documented 200-component
    /// cap (meta_createMetadata: "Limit: 10. (For CustomMetadata and
    /// CustomApplication only, the limit is 200.)").
    #[test]
    fn check_component_cap_allows_200_for_documented_large_types() {
        for ty in ["CustomMetadata", "CustomApplication"] {
            assert!(check_component_cap(11, ty, "x").is_ok());
            assert!(check_component_cap(200, ty, "x").is_ok());
            let err = check_component_cap(201, ty, "x").unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("200"),
                "message should cite the 200 cap: {msg}"
            );
        }
    }
}
