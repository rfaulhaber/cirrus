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
//! limit). Four of them — `createMetadata`, `updateMetadata`,
//! `readMetadata` and `deleteMetadata` — raise that to 200 for
//! `CustomMetadata` and `CustomApplication`. `upsertMetadata` is the
//! exception: its documented limit is a flat 10 for every type. The
//! SDK enforces this client-side via [`MAX_CRUD_COMPONENTS_PER_CALL`]
//! / [`MAX_CRUD_COMPONENTS_PER_CALL_LARGE`] — passing more returns
//! [`MetadataError::InvalidArgument`] before hitting the wire.
//!
//! ## Atomicity
//!
//! `createMetadata`, `updateMetadata`, `upsertMetadata` and
//! `deleteMetadata` save the components that succeed and report the
//! rest per entry. [`CrudOptions::all_or_none`], taken by the `_with`
//! variant of each call, turns that into all-or-nothing.
//!
//! [`deploy`]: crate::MetadataClient::deploy
//! [`retrieve`]: crate::MetadataClient::retrieve
//! [`MetadataError::InvalidArgument`]: crate::MetadataError::InvalidArgument

use crate::MetadataClient;
use crate::envelope::xml_escape;
use crate::error::{MetadataError, MetadataResult};
use crate::headers::render_all_or_none;
use crate::result::{DeleteResult, SaveResult, UpsertResult};
use crate::transport::SoapOperation;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use std::marker::PhantomData;

/// Salesforce server limit on per-call component count for
/// `createMetadata`, `updateMetadata`, `upsertMetadata`,
/// `readMetadata`, and `deleteMetadata`. All but `upsertMetadata`
/// document a raised cap for two types — see
/// [`MAX_CRUD_COMPONENTS_PER_CALL_LARGE`].
pub const MAX_CRUD_COMPONENTS_PER_CALL: usize = 10;

/// Raised per-call component limit for `CustomMetadata` and
/// `CustomApplication`, the two types Salesforce documents at 200
/// components per call.
///
/// Applies to `createMetadata`, `updateMetadata`, `readMetadata` and
/// `deleteMetadata`. `upsertMetadata` doesn't carry the exception: its
/// documented limit is [`MAX_CRUD_COMPONENTS_PER_CALL`] for every
/// type.
pub const MAX_CRUD_COMPONENTS_PER_CALL_LARGE: usize = 200;

/// Per-call options for the CRUD writes that accept an
/// `AllOrNoneHeader`: [`create_metadata_with`], [`update_metadata_with`],
/// [`upsert_metadata_with`] and [`delete_metadata_with`].
///
/// The header is available in API version 34.0 and later. The Metadata
/// API Developer Guide documents it on its `AllOrNoneHeader` page.
///
/// [`create_metadata_with`]: MetadataClient::create_metadata_with
/// [`update_metadata_with`]: MetadataClient::update_metadata_with
/// [`upsert_metadata_with`]: MetadataClient::upsert_metadata_with
/// [`delete_metadata_with`]: MetadataClient::delete_metadata_with
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CrudOptions {
    /// `false` (the default, and Salesforce's own default) saves the
    /// records that succeed and reports the others per entry. `true`
    /// rolls back every change in the call when any record fails.
    pub all_or_none: bool,
}

/// One of the five component-array CRUD calls, for resolving the
/// documented per-call cap and naming the call in errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CrudCall {
    Create,
    Update,
    Upsert,
    Read,
    Delete,
}

impl CrudCall {
    /// The public method name, used in `InvalidArgument` messages.
    fn label(self) -> &'static str {
        match self {
            Self::Create => "create_metadata",
            Self::Update => "update_metadata",
            Self::Upsert => "upsert_metadata",
            Self::Read => "read_metadata",
            Self::Delete => "delete_metadata",
        }
    }

    /// The documented per-call cap for this call and metadata type.
    ///
    /// `meta_upsertMetadata`'s argument table states "Limit: 10." with
    /// no type carve-out, where the other four spell out "Limit: 10.
    /// (For CustomMetadata and CustomApplication only, the limit is
    /// 200.)". A cap the docs don't grant would defeat the guard: an
    /// over-limit upsert would reach the wire unchecked.
    fn per_call_cap(self, type_name: &str) -> usize {
        match (self, type_name) {
            (Self::Upsert, _) => MAX_CRUD_COMPONENTS_PER_CALL,
            (_, "CustomMetadata" | "CustomApplication") => MAX_CRUD_COMPONENTS_PER_CALL_LARGE,
            _ => MAX_CRUD_COMPONENTS_PER_CALL,
        }
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

/// The `AllOrNoneHeader` for a write, or nothing when the call keeps
/// Salesforce's default of saving the records that succeed.
fn render_crud_headers(all_or_none: bool) -> String {
    let mut out = String::new();
    if all_or_none {
        render_all_or_none(&mut out);
    }
    out
}

fn check_component_cap(count: usize, type_name: &str, call: CrudCall) -> MetadataResult<()> {
    let op_label = call.label();
    if count == 0 {
        return Err(MetadataError::InvalidArgument(format!(
            "{op_label} requires at least one component; got 0"
        )));
    }
    let cap = call.per_call_cap(type_name);
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
    all_or_none: bool,
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

    fn render_headers(&self) -> MetadataResult<String> {
        Ok(render_crud_headers(self.all_or_none))
    }
}

struct UpdateMetadataOp<'a, S: AsRef<str>> {
    type_name: &'a str,
    components: &'a [S],
    all_or_none: bool,
}

impl<S: AsRef<str>> SoapOperation for UpdateMetadataOp<'_, S> {
    const NAME: &'static str = "updateMetadata";
    type Response = SaveResultsWire;

    fn render_body(&self) -> MetadataResult<String> {
        let mut out = String::with_capacity(self.components.len() * 256);
        render_metadata_components(self.type_name, self.components, &mut out);
        Ok(out)
    }

    fn render_headers(&self) -> MetadataResult<String> {
        Ok(render_crud_headers(self.all_or_none))
    }
}

struct UpsertMetadataOp<'a, S: AsRef<str>> {
    type_name: &'a str,
    components: &'a [S],
    all_or_none: bool,
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

    fn render_headers(&self) -> MetadataResult<String> {
        Ok(render_crud_headers(self.all_or_none))
    }
}

struct DeleteMetadataOp<'a, S: AsRef<str>> {
    type_name: &'a str,
    full_names: &'a [S],
    all_or_none: bool,
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

    fn render_headers(&self) -> MetadataResult<String> {
        Ok(render_crud_headers(self.all_or_none))
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
    /// All components must be of the same `type_name`, given as a
    /// string or a [`MetadataType`](crate::MetadataType). Each entry in
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
    /// `errors`. Use [`Self::create_metadata_with`] with
    /// [`CrudOptions::all_or_none`] to roll the whole call back instead.
    pub async fn create_metadata<S: AsRef<str>, N: AsRef<str>>(
        &self,
        type_name: N,
        components: &[S],
    ) -> MetadataResult<Vec<SaveResult>> {
        self.create_metadata_with(type_name, components, CrudOptions::default())
            .await
    }

    /// [`Self::create_metadata`] with [`CrudOptions`], such as
    /// all-or-nothing saving.
    pub async fn create_metadata_with<S: AsRef<str>, N: AsRef<str>>(
        &self,
        type_name: N,
        components: &[S],
        options: CrudOptions,
    ) -> MetadataResult<Vec<SaveResult>> {
        let type_name = type_name.as_ref();
        check_component_cap(components.len(), type_name, CrudCall::Create)?;
        let op = CreateMetadataOp {
            type_name,
            components,
            all_or_none: options.all_or_none,
        };
        let resp = self.call(&op).await?;
        Ok(resp.results)
    }

    /// Update one or more existing metadata components.
    ///
    /// Same input shape as [`Self::create_metadata`] — each
    /// component's `<fullName>` identifies which existing component
    /// to update. Returns one [`SaveResult`] per component. Partial
    /// success is possible; [`Self::update_metadata_with`] with
    /// [`CrudOptions::all_or_none`] rolls the whole call back instead.
    pub async fn update_metadata<S: AsRef<str>, N: AsRef<str>>(
        &self,
        type_name: N,
        components: &[S],
    ) -> MetadataResult<Vec<SaveResult>> {
        self.update_metadata_with(type_name, components, CrudOptions::default())
            .await
    }

    /// [`Self::update_metadata`] with [`CrudOptions`], such as
    /// all-or-nothing saving.
    pub async fn update_metadata_with<S: AsRef<str>, N: AsRef<str>>(
        &self,
        type_name: N,
        components: &[S],
        options: CrudOptions,
    ) -> MetadataResult<Vec<SaveResult>> {
        let type_name = type_name.as_ref();
        check_component_cap(components.len(), type_name, CrudCall::Update)?;
        let op = UpdateMetadataOp {
            type_name,
            components,
            all_or_none: options.all_or_none,
        };
        let resp = self.call(&op).await?;
        Ok(resp.results)
    }

    /// Create or update one or more metadata components.
    ///
    /// Same input shape as [`Self::create_metadata`]. The returned
    /// [`UpsertResult::created`] flag distinguishes per-component
    /// inserts (`true`) from updates (`false`). Available in
    /// API v31+. Partial success is possible;
    /// [`Self::upsert_metadata_with`] with [`CrudOptions::all_or_none`]
    /// rolls the whole call back instead.
    pub async fn upsert_metadata<S: AsRef<str>, N: AsRef<str>>(
        &self,
        type_name: N,
        components: &[S],
    ) -> MetadataResult<Vec<UpsertResult>> {
        self.upsert_metadata_with(type_name, components, CrudOptions::default())
            .await
    }

    /// [`Self::upsert_metadata`] with [`CrudOptions`], such as
    /// all-or-nothing saving.
    pub async fn upsert_metadata_with<S: AsRef<str>, N: AsRef<str>>(
        &self,
        type_name: N,
        components: &[S],
        options: CrudOptions,
    ) -> MetadataResult<Vec<UpsertResult>> {
        let type_name = type_name.as_ref();
        check_component_cap(components.len(), type_name, CrudCall::Upsert)?;
        let op = UpsertMetadataOp {
            type_name,
            components,
            all_or_none: options.all_or_none,
        };
        let resp = self.call(&op).await?;
        Ok(resp.results)
    }

    /// Delete one or more metadata components.
    ///
    /// Returns one [`DeleteResult`] per `full_names` entry. Partial
    /// success is possible — inspect each entry — unless
    /// [`Self::delete_metadata_with`] sets
    /// [`CrudOptions::all_or_none`].
    pub async fn delete_metadata<S: AsRef<str>, N: AsRef<str>>(
        &self,
        type_name: N,
        full_names: &[S],
    ) -> MetadataResult<Vec<DeleteResult>> {
        self.delete_metadata_with(type_name, full_names, CrudOptions::default())
            .await
    }

    /// [`Self::delete_metadata`] with [`CrudOptions`], such as
    /// all-or-nothing deletion.
    pub async fn delete_metadata_with<S: AsRef<str>, N: AsRef<str>>(
        &self,
        type_name: N,
        full_names: &[S],
        options: CrudOptions,
    ) -> MetadataResult<Vec<DeleteResult>> {
        let type_name = type_name.as_ref();
        check_component_cap(full_names.len(), type_name, CrudCall::Delete)?;
        let op = DeleteMetadataOp {
            type_name,
            full_names,
            all_or_none: options.all_or_none,
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
    ///     .read_metadata::<ApexClassRecord, _, _>("ApexClass", &["Foo", "Bar"])
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
    pub async fn read_metadata<T, S, N>(
        &self,
        type_name: N,
        full_names: &[S],
    ) -> MetadataResult<Vec<T>>
    where
        T: DeserializeOwned,
        S: AsRef<str>,
        N: AsRef<str>,
    {
        let type_name = type_name.as_ref();
        check_component_cap(full_names.len(), type_name, CrudCall::Read)?;
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
    pub async fn rename_metadata<N: AsRef<str>>(
        &self,
        type_name: N,
        old_full_name: &str,
        new_full_name: &str,
    ) -> MetadataResult<SaveResult> {
        let type_name = type_name.as_ref();
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
            all_or_none: false,
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
            all_or_none: false,
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
            all_or_none: false,
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
            all_or_none: false,
        };
        let body = op.render_body().unwrap();
        assert!(body.contains("<met:type>Weird&lt;&gt;</met:type>"));
        assert!(body.contains("<met:fullNames>a&amp;b</met:fullNames>"));
    }

    #[test]
    fn write_ops_render_the_all_or_none_header_only_when_asked() {
        let header =
            "<met:AllOrNoneHeader><met:allOrNone>true</met:allOrNone></met:AllOrNoneHeader>";
        let comps = ["<fullName>Foo</fullName>"];
        for all_or_none in [false, true] {
            let expected = if all_or_none { header } else { "" };
            let create = CreateMetadataOp {
                type_name: "ApexClass",
                components: &comps,
                all_or_none,
            };
            let update = UpdateMetadataOp {
                type_name: "ApexClass",
                components: &comps,
                all_or_none,
            };
            let upsert = UpsertMetadataOp {
                type_name: "ApexClass",
                components: &comps,
                all_or_none,
            };
            let delete = DeleteMetadataOp {
                type_name: "ApexClass",
                full_names: &["Foo"],
                all_or_none,
            };
            assert_eq!(create.render_headers().unwrap(), expected);
            assert_eq!(update.render_headers().unwrap(), expected);
            assert_eq!(upsert.render_headers().unwrap(), expected);
            assert_eq!(delete.render_headers().unwrap(), expected);
        }
    }

    #[test]
    fn read_and_rename_ops_render_no_headers() {
        #[derive(Deserialize)]
        struct Empty {}
        let read = ReadMetadataOp::<Empty, _> {
            type_name: "ApexClass",
            full_names: &["Foo"],
            _marker: PhantomData,
        };
        let rename = RenameMetadataOp {
            type_name: "ApexClass",
            old_full_name: "A",
            new_full_name: "B",
        };
        assert_eq!(read.render_headers().unwrap(), "");
        assert_eq!(rename.render_headers().unwrap(), "");
    }

    #[test]
    fn check_component_cap_rejects_empty_input() {
        let err = check_component_cap(0, "ApexClass", CrudCall::Create).unwrap_err();
        assert!(err.to_string().contains("at least one"));
        assert!(err.to_string().contains("create_metadata"));
    }

    #[test]
    fn check_component_cap_rejects_more_than_ten() {
        let err = check_component_cap(11, "ApexClass", CrudCall::Delete).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("10"));
        assert!(msg.contains("11"));
    }

    #[test]
    fn check_component_cap_accepts_one_to_ten() {
        for n in 1..=10 {
            assert!(
                check_component_cap(n, "ApexClass", CrudCall::Create).is_ok(),
                "should accept {n}"
            );
        }
    }

    /// CustomMetadata / CustomApplication carry a documented 200-component
    /// cap (meta_createMetadata: "Limit: 10. (For CustomMetadata and
    /// CustomApplication only, the limit is 200.)"), repeated verbatim on
    /// meta_updateMetadata, meta_readMetadata and meta_deleteMetadata.
    #[test]
    fn check_component_cap_allows_200_for_documented_large_types() {
        let calls = [
            CrudCall::Create,
            CrudCall::Update,
            CrudCall::Read,
            CrudCall::Delete,
        ];
        for ty in ["CustomMetadata", "CustomApplication"] {
            for call in calls {
                assert!(check_component_cap(11, ty, call).is_ok());
                assert!(check_component_cap(200, ty, call).is_ok());
                let err = check_component_cap(201, ty, call).unwrap_err();
                let msg = err.to_string();
                assert!(
                    msg.contains("200"),
                    "message should cite the 200 cap: {msg}"
                );
            }
        }
    }

    /// meta_upsertMetadata's Arguments table says "Limit: 10." with no
    /// type carve-out, so the raised cap the other four calls document
    /// must not leak into upsert.
    #[test]
    fn check_component_cap_holds_upsert_to_ten_for_every_type() {
        for ty in ["CustomMetadata", "CustomApplication", "ApexClass"] {
            assert!(check_component_cap(10, ty, CrudCall::Upsert).is_ok());
            let err = check_component_cap(11, ty, CrudCall::Upsert).unwrap_err();
            let msg = err.to_string();
            assert!(msg.contains("upsert_metadata"), "{msg}");
            assert!(
                msg.contains("10"),
                "message should cite the flat cap: {msg}"
            );
        }
    }
}
