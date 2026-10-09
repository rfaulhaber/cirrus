//! sObject resources — describe global, per-object describe, and CRUD.
//!
//! Two handler structs gate the surface:
//!
//! - [`SObjectsHandler`] (from [`Cirrus::sobjects`]): collection-level
//!   operations that don't target a specific object —
//!   [`describe_global`].
//! - [`SObjectHandler`] (from [`Cirrus::sobject`]): per-object
//!   operations — describe metadata, retrieve, create, update, delete,
//!   and retrieve, upsert and delete by external ID. Generic over
//!   caller-supplied record types: every method that
//!   produces a record returns `serde_json::Value` by default, with an
//!   `_as::<T>()` variant for typed deserialization.
//!
//! [`describe_global`]: SObjectsHandler::describe_global
//! [`Cirrus::sobjects`]: crate::Cirrus::sobjects
//! [`Cirrus::sobject`]: crate::Cirrus::sobject

use crate::Cirrus;
use crate::error::{CirrusError, CirrusResult};
use crate::locator;
use crate::response::{DescribeGlobal, SObjectCreateResult};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::time::SystemTime;

/// The first API version whose upsert-by-external-ID response carries a
/// body; through v45.0 a successful update is a bare 204.
const UPSERT_RESULT_SINCE: (u32, u32) = (46, 0);

impl Cirrus {
    /// Returns a handler for collection-level sObject operations
    /// (describe global).
    pub fn sobjects(&self) -> SObjectsHandler<'_> {
        SObjectsHandler { client: self }
    }

    /// Returns a handler scoped to a single sObject by API name (e.g.
    /// `"Account"`, `"My_Object__c"`).
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use cirrus::{Cirrus, auth::StaticTokenAuth};
    /// # use std::sync::Arc;
    /// use serde_json::json;
    /// # async fn example() -> Result<(), cirrus::CirrusError> {
    /// # let auth = Arc::new(StaticTokenAuth::new("tok", "https://x.my.salesforce.com"));
    /// # let sf = Cirrus::builder().auth(auth).build()?;
    /// let accounts = sf.sobject("Account");
    /// let created = accounts.create(&json!({ "Name": "Acme" })).await?;
    /// let record = accounts.retrieve(&created.id).await?;
    /// accounts.delete(&created.id).await?;
    /// # let _ = record;
    /// # Ok(())
    /// # }
    /// ```
    pub fn sobject<'a>(&'a self, name: &'a str) -> SObjectHandler<'a> {
        SObjectHandler { client: self, name }
    }
}

/// Collection-level sObject handler. Returned by [`Cirrus::sobjects`].
#[derive(Debug)]
pub struct SObjectsHandler<'a> {
    client: &'a Cirrus,
}

impl SObjectsHandler<'_> {
    /// Describes every object visible to the authenticated user.
    ///
    /// Calls `GET /services/data/{api_version}/sobjects/`.
    pub async fn describe_global(&self) -> CirrusResult<DescribeGlobal> {
        self.client.get("sobjects").await
    }

    /// Conditional describe-global — returns `Some(metadata)` if the
    /// describe-global response has changed since `since`, or `None`
    /// if the org returns `304 Not Modified`.
    ///
    /// Salesforce documents this header on the describe-global
    /// endpoint specifically — it tracks both per-object metadata
    /// changes *and* org-wide events (permissions, profiles, field
    /// labels). The 304 path lets you keep your cached
    /// [`DescribeGlobal`] without re-deserializing a multi-megabyte
    /// response.
    ///
    /// `since` is formatted as RFC 7231 IMF-fixdate (e.g.
    /// `"Wed, 21 Oct 2015 07:28:00 GMT"`) before being sent. A `since`
    /// before the Unix epoch, or in year 9999 or later, can't be
    /// expressed in that format and returns
    /// [`CirrusError::InvalidHeader`].
    pub async fn describe_global_if_modified_since(
        &self,
        since: SystemTime,
    ) -> CirrusResult<Option<DescribeGlobal>> {
        let date = http_date(since)?;
        self.client.get_if_modified_since("sobjects", &date).await
    }
}

/// Per-object handler. Returned by [`Cirrus::sobject`].
///
/// # External IDs
///
/// [`retrieve_by_external_id`](Self::retrieve_by_external_id),
/// [`upsert`](Self::upsert) and
/// [`delete_by_external_id`](Self::delete_by_external_id) address a
/// record through `sobjects/{name}/{external_field}/{external_value}`.
/// The value occupies exactly one path segment and is percent-encoded, so
/// `/`, `#`, `?`, `%`, `=`, spaces and the like pass safely. An empty
/// value is refused with [`CirrusError::InvalidInput`] rather than sent,
/// because the URL it would produce is a different resource.
///
/// One documented case no encoding avoids: Salesforce answers 404 for a
/// value that ends like a file extension it blocks, such as the email
/// `example@email.inc`, and that 404 reads exactly like the `NOT_FOUND`
/// for a misspelled external-ID field. The [Upsert] page lists the
/// workarounds: use a different External ID field, keep a copy of the
/// value with `_` in place of `.`, query for the record's `Id` first and
/// address it by id, or move the call to SOAP or to a custom Apex REST
/// endpoint that takes the value as a query parameter.
///
/// [Upsert]: https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/resources_sobject_upsert_patch.htm
/// [`CirrusError::InvalidInput`]: crate::CirrusError::InvalidInput
#[derive(Debug)]
pub struct SObjectHandler<'a> {
    client: &'a Cirrus,
    name: &'a str,
}

impl<'a> SObjectHandler<'a> {
    /// API name of the targeted object.
    pub fn name(&self) -> &'a str {
        self.name
    }

    /// Describes the object's metadata (fields, child relationships,
    /// record-type info, etc.). Returns the raw JSON.
    ///
    /// Calls `GET /services/data/{api_version}/sobjects/{name}/describe`.
    pub async fn describe(&self) -> CirrusResult<Value> {
        self.describe_as().await
    }

    /// Typed variant of [`describe`](Self::describe). Supply your own
    /// struct to model a subset of the (very large) describe response.
    pub async fn describe_as<R: DeserializeOwned>(&self) -> CirrusResult<R> {
        let url = self
            .client
            .versioned_url(&["sobjects", self.name, "describe"])?;
        self.client
            .send_at(reqwest::Method::GET, &url, None::<&()>, None::<&()>)
            .await
    }

    /// Conditional per-object describe — returns `Some(metadata)` if
    /// changed since `since`, or `None` on `304 Not Modified`.
    ///
    /// Same caching workflow as
    /// [`SObjectsHandler::describe_global_if_modified_since`]:
    /// pass the timestamp of your last fetch; Salesforce returns 304
    /// (and you can keep your cached metadata) when nothing has
    /// changed. A `since` that RFC 7231's IMF-fixdate format can't
    /// express returns [`CirrusError::InvalidHeader`].
    pub async fn describe_if_modified_since(
        &self,
        since: SystemTime,
    ) -> CirrusResult<Option<Value>> {
        self.describe_if_modified_since_as(since).await
    }

    /// Typed variant of
    /// [`describe_if_modified_since`](Self::describe_if_modified_since).
    pub async fn describe_if_modified_since_as<R: DeserializeOwned>(
        &self,
        since: SystemTime,
    ) -> CirrusResult<Option<R>> {
        // versioned_url produces an absolute URL, which the
        // three-mode path resolution passes through verbatim.
        let url = self
            .client
            .versioned_url(&["sobjects", self.name, "describe"])?;
        let date = http_date(since)?;
        self.client.get_if_modified_since(&url, &date).await
    }

    /// Retrieves a record by ID, returning every field. For a subset of
    /// fields use [`retrieve_with_fields`](Self::retrieve_with_fields).
    ///
    /// Calls `GET /services/data/{api_version}/sobjects/{name}/{id}`.
    pub async fn retrieve(&self, id: &str) -> CirrusResult<Value> {
        self.retrieve_as(id).await
    }

    /// Typed variant of [`retrieve`](Self::retrieve).
    pub async fn retrieve_as<R: DeserializeOwned>(&self, id: &str) -> CirrusResult<R> {
        let url = self.client.versioned_url(&["sobjects", self.name, id])?;
        self.client
            .send_at(reqwest::Method::GET, &url, None::<&()>, None::<&()>)
            .await
    }

    /// Retrieves selected fields of a record by ID.
    ///
    /// Calls `GET /sobjects/{name}/{id}?fields=Field1,Field2,...`.
    pub async fn retrieve_with_fields(&self, id: &str, fields: &[&str]) -> CirrusResult<Value> {
        self.retrieve_with_fields_as(id, fields).await
    }

    /// Typed variant of
    /// [`retrieve_with_fields`](Self::retrieve_with_fields).
    pub async fn retrieve_with_fields_as<R: DeserializeOwned>(
        &self,
        id: &str,
        fields: &[&str],
    ) -> CirrusResult<R> {
        let url = self.client.versioned_url(&["sobjects", self.name, id])?;
        let joined = fields.join(",");
        let query = [("fields", joined.as_str())];
        self.client
            .send_at(reqwest::Method::GET, &url, Some(&query), None::<&()>)
            .await
    }

    /// Creates a new record of this object.
    ///
    /// Calls `POST /services/data/{api_version}/sobjects/{name}/`. The body
    /// is serialized as JSON — any `Serialize` value works (typed structs,
    /// `serde_json::json!({...})`, `HashMap<String, Value>`).
    pub async fn create<B>(&self, body: &B) -> CirrusResult<SObjectCreateResult>
    where
        B: Serialize + ?Sized,
    {
        let url = self.client.versioned_url(&["sobjects", self.name])?;
        self.client
            .send_at(reqwest::Method::POST, &url, None::<&()>, Some(body))
            .await
    }

    /// Updates a record by ID. Field values in `body` replace the
    /// existing values; fields not present in `body` are left alone.
    ///
    /// Calls `PATCH /services/data/{api_version}/sobjects/{name}/{id}`.
    /// Salesforce returns 204 No Content on success.
    pub async fn update<B>(&self, id: &str, body: &B) -> CirrusResult<()>
    where
        B: Serialize + ?Sized,
    {
        let url = self.client.versioned_url(&["sobjects", self.name, id])?;
        self.client
            .send_at::<(), (), B>(reqwest::Method::PATCH, &url, None, Some(body))
            .await
    }

    /// Deletes a record by ID.
    ///
    /// Calls `DELETE /services/data/{api_version}/sobjects/{name}/{id}`.
    /// Salesforce returns 204 No Content on success.
    ///
    /// A DELETE is replayed after a transient failure (a 5xx from an
    /// intermediary, a lost response), so when the first attempt had
    /// already committed the replay finds the record gone and this
    /// returns a 404 [`crate::CirrusError::Api`] for a delete that
    /// succeeded. Treat that 404 as "already deleted" in cleanup code,
    /// or disable replays with [`crate::RetryPolicy`].
    pub async fn delete(&self, id: &str) -> CirrusResult<()> {
        let url = self.client.versioned_url(&["sobjects", self.name, id])?;
        self.client
            .send_at::<(), (), ()>(reqwest::Method::DELETE, &url, None, None)
            .await
    }

    /// Retrieves the record whose `external_field` equals `external_value`,
    /// returning every field.
    ///
    /// Calls
    /// `GET /services/data/{api_version}/sobjects/{name}/{external_field}/{external_value}`.
    /// A value no record carries is a 404 [`crate::CirrusError::Api`]. See
    /// [External IDs](Self#external-ids) for the encoding, and for the one
    /// documented value shape that answers 404 regardless.
    pub async fn retrieve_by_external_id(
        &self,
        external_field: &str,
        external_value: &str,
    ) -> CirrusResult<Value> {
        self.retrieve_by_external_id_as(external_field, external_value)
            .await
    }

    /// Typed variant of
    /// [`retrieve_by_external_id`](Self::retrieve_by_external_id).
    pub async fn retrieve_by_external_id_as<R: DeserializeOwned>(
        &self,
        external_field: &str,
        external_value: &str,
    ) -> CirrusResult<R> {
        let url = self.external_id_url(external_field, external_value)?;
        self.client
            .send_at(reqwest::Method::GET, &url, None::<&()>, None::<&()>)
            .await
    }

    /// Deletes the record whose `external_field` equals `external_value`.
    ///
    /// Calls
    /// `DELETE /services/data/{api_version}/sobjects/{name}/{external_field}/{external_value}`.
    /// Salesforce returns 204 No Content on success; a value no record
    /// carries is a 404 [`crate::CirrusError::Api`], which is also what
    /// a replay after a transient failure returns when the first attempt
    /// had already committed (see [`delete`](Self::delete)). See
    /// [External IDs](Self#external-ids) for the encoding.
    pub async fn delete_by_external_id(
        &self,
        external_field: &str,
        external_value: &str,
    ) -> CirrusResult<()> {
        let url = self.external_id_url(external_field, external_value)?;
        self.client
            .send_at::<(), (), ()>(reqwest::Method::DELETE, &url, None, None)
            .await
    }

    /// Upserts a record by external ID. If a record matching
    /// `external_value` exists, it's updated; otherwise a new record is
    /// created. The `created` flag on the returned
    /// [`SObjectCreateResult`] distinguishes the two outcomes.
    /// [`upsert_with`](Self::upsert_with) takes an [`UpsertOptions`] to
    /// forbid the create.
    ///
    /// Calls
    /// `PATCH /services/data/{api_version}/sobjects/{name}/{external_field}/{external_value}`.
    /// `external_value` is percent-encoded, so values containing `/`,
    /// `=`, or other reserved characters are passed safely — with the one
    /// documented exception under [External IDs](Self#external-ids).
    ///
    /// If multiple records match the external ID, Salesforce returns 300
    /// — surfaced as [`crate::CirrusError::Api`].
    ///
    /// Needs API v46.0 or later. Through v45.0 Salesforce answers a
    /// successful update with 204 and no body, which leaves nothing to
    /// return, so a client built for one of those versions is refused
    /// with [`crate::CirrusError::InvalidInput`] before any request;
    /// [`retrieve_by_external_id`](Self::retrieve_by_external_id)
    /// followed by [`update`](Self::update) or [`create`](Self::create)
    /// covers them.
    pub async fn upsert<B>(
        &self,
        external_field: &str,
        external_value: &str,
        body: &B,
    ) -> CirrusResult<SObjectCreateResult>
    where
        B: Serialize + ?Sized,
    {
        self.upsert_with(
            external_field,
            external_value,
            body,
            UpsertOptions::default(),
        )
        .await
    }

    /// [`upsert`](Self::upsert) with [`UpsertOptions`].
    ///
    /// With [`update_only`](UpsertOptions::update_only) the request carries
    /// `updateOnly=true`, which Salesforce documents as forcing "the upsert
    /// to behave like an update": a value no record carries is then a 404
    /// [`crate::CirrusError::Api`] instead of a create.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use cirrus::{Cirrus, UpsertOptions, auth::StaticTokenAuth};
    /// # use std::sync::Arc;
    /// use serde_json::json;
    /// # async fn example() -> Result<(), cirrus::CirrusError> {
    /// # let auth = Arc::new(StaticTokenAuth::new("tok", "https://x.my.salesforce.com"));
    /// # let sf = Cirrus::builder().auth(auth).build()?;
    /// // Sync existing Accounts by SKU__c without ever creating one.
    /// let result = sf
    ///     .sobject("Account")
    ///     .upsert_with(
    ///         "SKU__c",
    ///         "SKU#1",
    ///         &json!({ "Name": "Acme" }),
    ///         UpsertOptions { update_only: true },
    ///     )
    ///     .await?;
    /// assert_eq!(result.created, Some(false));
    /// # Ok(())
    /// # }
    /// ```
    pub async fn upsert_with<B>(
        &self,
        external_field: &str,
        external_value: &str,
        body: &B,
        options: UpsertOptions,
    ) -> CirrusResult<SObjectCreateResult>
    where
        B: Serialize + ?Sized,
    {
        // Through v45.0 a successful update is a 204 with no body, so
        // the write would commit and then surface as InvalidResponse.
        let version = self.client.api_version();
        if locator::api_version_number(version).is_some_and(|number| number < UPSERT_RESULT_SINCE) {
            return Err(CirrusError::InvalidInput {
                field: "api_version",
                message: format!(
                    "upsert by external ID needs API v46.0 or later: `{version}` answers an update \
                     with 204 and no body, so there is no result to return; use \
                     retrieve_by_external_id followed by update or create on this version",
                ),
            });
        }
        let url = self.external_id_url(external_field, external_value)?;
        let query = options.update_only.then_some([("updateOnly", "true")]);
        self.client
            .send_at(reqwest::Method::PATCH, &url, query.as_ref(), Some(body))
            .await
    }

    /// The sObject Rows by External ID URL, with the field and the value
    /// each as one encoded segment.
    fn external_id_url(&self, external_field: &str, external_value: &str) -> CirrusResult<String> {
        self.client
            .versioned_url(&["sobjects", self.name, external_field, external_value])
    }

    /// Inserts a new record carrying binary blob data — `ContentVersion`,
    /// `Document`, `Attachment`, or any sObject with a blob field.
    ///
    /// Sends a `multipart/form-data` request with the metadata as one
    /// part and the binary as a second part. See [`BlobUploadSpec`] for
    /// how the two parts are named: the binary part must carry the
    /// sObject's blob field API name, and the JSON part's name is
    /// caller-chosen.
    ///
    /// Calls
    /// `POST /services/data/{api_version}/sobjects/{name}` with a
    /// multipart body. Returns the standard [`SObjectCreateResult`].
    ///
    /// # File-size limits
    ///
    /// Per the [Insert or Update Blob Data] doc:
    ///
    /// - 2 GB for `ContentVersion`
    /// - 500 MB for other standard objects with blob fields
    ///
    /// Non-multipart blob inserts (base64-encoded body field) are also
    /// possible but capped at 37.5 MB and aren't worth a separate API
    /// surface — use this method for any non-trivial upload.
    ///
    /// [Insert or Update Blob Data]: https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/dome_sobject_insert_update_blob.htm
    ///
    /// # Example: ContentVersion upload
    ///
    /// ```ignore
    /// use cirrus::BlobUploadSpec;
    /// use serde_json::json;
    ///
    /// let pdf: bytes::Bytes = std::fs::read("brochure.pdf").unwrap().into();
    /// let result = sf.sobject("ContentVersion").create_with_blob(BlobUploadSpec {
    ///     json_part_name: "entity_content",
    ///     metadata: &json!({
    ///         "Title": "Q1 Brochure",
    ///         "PathOnClient": "brochure.pdf",
    ///     }),
    ///     blob_field_name: "VersionData",
    ///     filename: "brochure.pdf",
    ///     content_type: Some("application/pdf"),
    ///     blob: pdf,
    /// }).await?;
    /// println!("created ContentVersion {}", result.id);
    /// # Ok::<(), cirrus::CirrusError>(())
    /// ```
    pub async fn create_with_blob<B>(
        &self,
        spec: BlobUploadSpec<'_, B>,
    ) -> CirrusResult<SObjectCreateResult>
    where
        B: Serialize + ?Sized,
    {
        let url = self.client.versioned_url(&["sobjects", self.name])?;
        let json_bytes =
            serde_json::to_vec(spec.metadata).map_err(crate::error::CirrusError::Serialization)?;
        let content_type = spec.content_type.unwrap_or("application/octet-stream");
        self.client
            .send_multipart(
                reqwest::Method::POST,
                &url,
                spec.json_part_name,
                json_bytes,
                spec.blob_field_name,
                spec.filename,
                content_type,
                spec.blob,
            )
            .await
    }

    /// Updates a record's blob field (and optionally non-binary fields)
    /// via multipart `PATCH`.
    ///
    /// **Note:** `ContentVersion` does not support updates per the
    /// Salesforce docs — only inserts. Use [`create_with_blob`] for new
    /// versions. Other blob-field-bearing objects (Document, Attachment,
    /// Knowledge articles) do support multipart update.
    ///
    /// Calls
    /// `PATCH /services/data/{api_version}/sobjects/{name}/{id}` with
    /// a multipart body. Salesforce returns 204 No Content on success.
    ///
    /// The doc's update example names its JSON part `entity_content`
    /// where the insert example uses `entity_document`; neither name is
    /// required, so pass whichever you like — only
    /// [`BlobUploadSpec::blob_field_name`] is constrained.
    ///
    /// [`create_with_blob`]: Self::create_with_blob
    pub async fn update_with_blob<B>(
        &self,
        id: &str,
        spec: BlobUploadSpec<'_, B>,
    ) -> CirrusResult<()>
    where
        B: Serialize + ?Sized,
    {
        let url = self.client.versioned_url(&["sobjects", self.name, id])?;
        let json_bytes =
            serde_json::to_vec(spec.metadata).map_err(crate::error::CirrusError::Serialization)?;
        let content_type = spec.content_type.unwrap_or("application/octet-stream");
        self.client
            .send_multipart(
                reqwest::Method::PATCH,
                &url,
                spec.json_part_name,
                json_bytes,
                spec.blob_field_name,
                spec.filename,
                content_type,
                spec.blob,
            )
            .await
    }
}

/// Formats a [`SystemTime`] as an RFC 7231 IMF-fixdate for
/// `If-Modified-Since`.
///
/// `httpdate::fmt_http_date` is partial: it panics for times before the
/// Unix epoch and for year 9999 onwards. Both bounds are checked here so
/// a caller-supplied watermark — a stored sentinel, a clock skewed
/// backwards — surfaces as an error instead of unwinding the calling
/// task.
fn http_date(since: SystemTime) -> CirrusResult<String> {
    // httpdate's own ceiling, in seconds since the epoch: 9999-01-01.
    const YEAR_9999: u64 = 253_402_300_800;

    let secs = since
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| {
            CirrusError::InvalidHeader(
                "If-Modified-Since requires a time at or after the Unix epoch".into(),
            )
        })?
        .as_secs();
    if secs >= YEAR_9999 {
        return Err(CirrusError::InvalidHeader(
            "If-Modified-Since requires a time before year 9999".into(),
        ));
    }
    Ok(httpdate::fmt_http_date(since))
}

/// Options for [`SObjectHandler::upsert_with`].
///
/// The default is a plain upsert: a value no record carries creates one.
///
/// ```
/// use cirrus::UpsertOptions;
///
/// let never_create = UpsertOptions { update_only: true };
/// assert!(!UpsertOptions::default().update_only);
/// # let _ = never_create;
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UpsertOptions {
    /// Sends `updateOnly=true`, documented on the [Upsert] page as "an
    /// optional parameter that prevents a new record from being created.
    /// Forces the upsert to behave like an update". A value no record
    /// carries is then a 404 instead of a create.
    ///
    /// [Upsert]: https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/resources_sobject_upsert_patch.htm
    pub update_only: bool,
}

/// Specification for a multipart blob upload via
/// [`SObjectHandler::create_with_blob`] or
/// [`SObjectHandler::update_with_blob`].
///
/// # Naming the two parts
///
/// Only one of the two part names is constrained. Per the
/// [Insert or Update Blob Data] doc: "In the non-binary part of the
/// request body, use any value for the name attribute. For single
/// documents, in the binary part of the request body, use the name
/// attribute to specify the name of the blob data field for the
/// object."
///
/// So [`blob_field_name`](Self::blob_field_name) must be the sObject's
/// blob field API name, while
/// [`json_part_name`](Self::json_part_name) is yours to choose. The
/// doc's examples happen to use these:
///
/// | sObject          | Operation | Example `json_part_name` | Required `blob_field_name` |
/// |------------------|-----------|--------------------------|----------------------------|
/// | `ContentVersion` | insert    | `entity_content`         | `VersionData`              |
/// | `Document`       | insert    | `entity_document`        | `Body`                     |
/// | `Document`       | update    | `entity_content`         | `Body`                     |
///
/// The two different names for `Document` are just what the two
/// examples happen to show — either works for either operation.
///
/// For other blob-bearing objects, look up the blob field's API name on
/// the object; the JSON part name needs no lookup.
///
/// [Insert or Update Blob Data]: https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/dome_sobject_insert_update_blob.htm
pub struct BlobUploadSpec<'a, B: ?Sized> {
    /// Name of the JSON metadata part. Any value works — see the
    /// [type-level docs](BlobUploadSpec#naming-the-two-parts).
    pub json_part_name: &'a str,
    /// Non-binary record fields, serialized as JSON. Any
    /// [`Serialize`] value works — typed structs,
    /// `serde_json::json!({...})`, `HashMap<String, Value>`.
    pub metadata: &'a B,
    /// Name of the binary part. This one Salesforce does validate: it
    /// must be the sObject's blob field API name — `Body` for
    /// `Document`, `VersionData` for `ContentVersion`.
    pub blob_field_name: &'a str,
    /// Filename to declare in the binary part's `Content-Disposition`.
    /// Salesforce surfaces this as the `PathOnClient` / `Name` /
    /// `FileName` attribute on most blob objects (varies; check the
    /// object's documented field set).
    pub filename: &'a str,
    /// MIME type for the binary part. Defaults to
    /// `application/octet-stream` when `None`. Setting it correctly
    /// helps Salesforce correctly classify the upload (e.g.
    /// `application/pdf` so previews render).
    pub content_type: Option<&'a str>,
    /// Binary payload. `bytes::Bytes` is Arc-backed and zero-copy
    /// across retries.
    pub blob: bytes::Bytes,
}

impl<B: ?Sized> std::fmt::Debug for BlobUploadSpec<'_, B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Neither payload is safe to render: `blob` is the file being
        // uploaded (up to 2 GB, and `bytes::Bytes` escapes every byte),
        // and `metadata` is caller record data. Both are summarized.
        f.debug_struct("BlobUploadSpec")
            .field("json_part_name", &self.json_part_name)
            .field("blob_field_name", &self.blob_field_name)
            .field("filename", &self.filename)
            .field("content_type", &self.content_type)
            .field("blob_len", &self.blob.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use crate::auth::StaticTokenAuth;
    use crate::{Cirrus, CirrusError, UpsertOptions};
    use serde_json::json;
    use std::sync::Arc;
    use wiremock::matchers::{body_json, header, method, path, path_regex, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn fixture(uri: String) -> Cirrus {
        let auth = Arc::new(StaticTokenAuth::new("tok", uri));
        Cirrus::builder().auth(auth).build().unwrap()
    }

    #[tokio::test]
    async fn describe_global_returns_envelope() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/sobjects"))
            .and(header("authorization", "Bearer tok"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "encoding": "UTF-8",
                "maxBatchSize": 200,
                "sobjects": [{
                    "activateable": false, "custom": false, "customSetting": false,
                    "createable": true, "deletable": true, "deprecatedAndHidden": false,
                    "feedEnabled": true, "keyPrefix": "001",
                    "label": "Account", "labelPlural": "Accounts",
                    "layoutable": true, "mergeable": true, "mruEnabled": true,
                    "name": "Account", "queryable": true, "replicateable": true,
                    "retrieveable": true, "searchable": true, "triggerable": true,
                    "undeletable": true, "updateable": true,
                    "urls": {
                        "sobject": "/services/data/v66.0/sobjects/Account",
                        "describe": "/services/data/v66.0/sobjects/Account/describe",
                        "rowTemplate": "/services/data/v66.0/sobjects/Account/{ID}"
                    }
                }]
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let dg = sf.sobjects().describe_global().await.unwrap();
        assert_eq!(dg.encoding, "UTF-8");
        assert_eq!(dg.max_batch_size, 200);
        assert_eq!(dg.sobjects.len(), 1);
        assert_eq!(dg.sobjects[0].name, "Account");
    }

    #[tokio::test]
    async fn describe_returns_value() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/sobjects/Account/describe"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "name": "Account",
                "label": "Account",
                "fields": []
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let v = sf.sobject("Account").describe().await.unwrap();
        assert_eq!(v["name"], "Account");
    }

    #[tokio::test]
    async fn retrieve_full_record() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path(
                "/services/data/v66.0/sobjects/Account/001xx0000000001",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "Id": "001xx0000000001",
                "Name": "Acme",
                "Industry": "Tech"
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let v = sf
            .sobject("Account")
            .retrieve("001xx0000000001")
            .await
            .unwrap();
        assert_eq!(v["Name"], "Acme");
    }

    #[tokio::test]
    async fn retrieve_with_fields_sets_query() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path(
                "/services/data/v66.0/sobjects/Account/001xx0000000001",
            ))
            .and(query_param("fields", "Name,Industry"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "Name": "Acme",
                "Industry": "Tech"
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let v = sf
            .sobject("Account")
            .retrieve_with_fields("001xx0000000001", &["Name", "Industry"])
            .await
            .unwrap();
        assert_eq!(v["Name"], "Acme");
        assert_eq!(v["Industry"], "Tech");
    }

    #[tokio::test]
    async fn create_posts_body_and_returns_id() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/services/data/v66.0/sobjects/Account"))
            .and(body_json(json!({"Name": "Acme"})))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "id": "001xx0000000001",
                "success": true,
                "errors": []
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let result = sf
            .sobject("Account")
            .create(&json!({"Name": "Acme"}))
            .await
            .unwrap();
        assert_eq!(result.id, "001xx0000000001");
        assert!(result.success);
    }

    #[tokio::test]
    async fn update_sends_patch_and_handles_204() {
        let server = MockServer::start().await;

        Mock::given(method("PATCH"))
            .and(path(
                "/services/data/v66.0/sobjects/Account/001xx0000000001",
            ))
            .and(body_json(json!({"Industry": "Biotech"})))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        sf.sobject("Account")
            .update("001xx0000000001", &json!({"Industry": "Biotech"}))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn delete_sends_delete_and_handles_204() {
        let server = MockServer::start().await;

        Mock::given(method("DELETE"))
            .and(path(
                "/services/data/v66.0/sobjects/Account/001xx0000000001",
            ))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        sf.sobject("Account")
            .delete("001xx0000000001")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn retrieve_refuses_an_empty_id_without_a_request() {
        // SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/resources_sobject_basic_info_get.htm
        // "URI: /services/data/vXX.X/sobjects/sObject/" — the URL an
        // empty id would produce is the sObject Basic Information
        // resource, whose 200 body would be returned as the "record".
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "objectDescribe": {"name": "Account"},
                "recentItems": []
            })))
            .expect(0)
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let err = sf.sobject("Account").retrieve("").await.unwrap_err();
        assert!(
            matches!(
                err,
                CirrusError::InvalidInput {
                    field: "path segment",
                    ..
                }
            ),
            "got {err:?}"
        );
        let err = sf
            .sobject("Account")
            .retrieve_with_fields("", &["Name"])
            .await
            .unwrap_err();
        assert!(
            matches!(err, CirrusError::InvalidInput { .. }),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn upsert_refuses_a_client_built_for_a_version_that_answers_with_no_body() {
        // SOURCE: https://developer.salesforce.com/docs/platform/api-rest/guide/dome-upsert.html
        // "In API version 45.0 and earlier, the HTTP status code is 204
        // (No Content) and there isn't a response body." Refused before
        // the request, so the update is never committed and then
        // reported as an invalid response.
        let server = MockServer::start().await;
        let auth = Arc::new(StaticTokenAuth::new("tok", server.uri()));
        let sf = Cirrus::builder()
            .auth(auth)
            .api_version("v45.0")
            .build()
            .unwrap();

        let err = sf
            .sobject("Account")
            .upsert("Ext__c", "A-1", &json!({"Name": "Acme"}))
            .await
            .unwrap_err();
        match err {
            CirrusError::InvalidInput { field, message } => {
                assert_eq!(field, "api_version");
                assert!(message.contains("v46.0"), "{message}");
                assert!(message.contains("v45.0"), "{message}");
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn upsert_runs_on_the_first_version_that_answers_with_a_body() {
        // SOURCE: https://developer.salesforce.com/docs/platform/api-rest/guide/dome-upsert.html
        // "In API version 46.0 and later, the HTTP status code is 200
        // (OK)" with the documented {id, success, errors, created} body.
        let server = MockServer::start().await;
        Mock::given(method("PATCH"))
            .and(path("/services/data/v46.0/sobjects/Account/Ext__c/A-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "001xx000003DGb2AAG",
                "success": true,
                "errors": [],
                "created": false
            })))
            .expect(1)
            .mount(&server)
            .await;
        let auth = Arc::new(StaticTokenAuth::new("tok", server.uri()));
        let sf = Cirrus::builder()
            .auth(auth)
            .api_version("v46.0")
            .build()
            .unwrap();

        let result = sf
            .sobject("Account")
            .upsert("Ext__c", "A-1", &json!({"Name": "Acme"}))
            .await
            .unwrap();
        assert_eq!(result.created, Some(false));
    }

    #[tokio::test]
    async fn upsert_patches_to_external_id_path() {
        let server = MockServer::start().await;

        Mock::given(method("PATCH"))
            .and(path(
                "/services/data/v66.0/sobjects/Account/External_Id__c/EXT-1",
            ))
            .and(body_json(json!({"Name": "Acme"})))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "id": "001xx0000000001",
                "success": true,
                "errors": [],
                "created": true
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let result = sf
            .sobject("Account")
            .upsert("External_Id__c", "EXT-1", &json!({"Name": "Acme"}))
            .await
            .unwrap();
        assert_eq!(result.id, "001xx0000000001");
        assert_eq!(result.created, Some(true));
    }

    #[tokio::test]
    async fn upsert_percent_encodes_external_value() {
        // SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/resources_sobject_upsert_patch.htm
        // "URI: /services/data/vXX.X/sobjects/sObject/fieldName/fieldValue"
        // — the external-ID value occupies exactly one path segment, so a
        // '/' inside it has to arrive encoded or the request targets a
        // different resource.
        let server = MockServer::start().await;

        // wiremock matches on `Url::path()`, which is percent-encoded, so
        // both matchers below see the value as it goes over the wire. The
        // `[^/]+` anchor is what fails if the encoding regresses.
        Mock::given(method("PATCH"))
            .and(path(
                "/services/data/v66.0/sobjects/Account/External_Id__c/a%2Fb=c%20d",
            ))
            .and(path_regex(
                r"^/services/data/v66\.0/sobjects/Account/External_Id__c/[^/]+$",
            ))
            .and(body_json(json!({"Name": "Edge"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "001xx0000000002",
                "success": true,
                "errors": [],
                "created": false
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let result = sf
            .sobject("Account")
            .upsert("External_Id__c", "a/b=c d", &json!({"Name": "Edge"}))
            .await
            .unwrap();
        assert_eq!(result.created, Some(false));
    }

    #[tokio::test]
    async fn retrieve_by_external_id_gets_the_encoded_external_id_path() {
        // SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/resources_sobject_upsert_get.htm
        // "Retrieves a record based on the value of the specified external
        // ID field. URI: /services/data/vXX.X/sobjects/sObject/fieldName/fieldValue
        // HTTP Method: GET". The value is one path segment, so a `#` in it
        // has to arrive as `%23` or the request is for `.../SKU__c/SKU`.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/services/data/v66.0/sobjects/Product2/SKU__c/SKU%231",
            ))
            .and(path_regex(
                r"^/services/data/v66\.0/sobjects/Product2/SKU__c/[^/]+$",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "attributes": {
                    "type": "Product2",
                    "url": "/services/data/v66.0/sobjects/Product2/01txx0000000001"
                },
                "Id": "01txx0000000001",
                "SKU__c": "SKU#1",
                "Name": "Widget"
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let record = sf
            .sobject("Product2")
            .retrieve_by_external_id("SKU__c", "SKU#1")
            .await
            .unwrap();
        assert_eq!(record["Id"], "01txx0000000001");

        #[derive(serde::Deserialize)]
        struct Product {
            #[serde(rename = "Name")]
            name: String,
        }
        let typed: Product = sf
            .sobject("Product2")
            .retrieve_by_external_id_as("SKU__c", "SKU#1")
            .await
            .unwrap();
        assert_eq!(typed.name, "Widget");
    }

    #[tokio::test]
    async fn delete_by_external_id_deletes_the_encoded_external_id_path() {
        // SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/resources_sobject_upsert_delete.htm
        // "Deletes a record based on the value of the specified external ID
        // field. URI: /services/data/vXX.X/sobjects/sObject/fieldName/fieldValue
        // HTTP Method: DELETE". Unencoded, `SKU#1` would delete the record
        // whose SKU is `SKU`.
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path(
                "/services/data/v66.0/sobjects/Product2/SKU__c/SKU%231",
            ))
            .and(path_regex(
                r"^/services/data/v66\.0/sobjects/Product2/SKU__c/[^/]+$",
            ))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        sf.sobject("Product2")
            .delete_by_external_id("SKU__c", "SKU#1")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn by_external_id_refuses_an_empty_value_without_a_request() {
        // `sobjects/Product2/SKU__c/` is the sObject Rows resource with
        // `SKU__c` read as a record id, not a lookup by external ID.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .expect(0)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .respond_with(ResponseTemplate::new(204))
            .expect(0)
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let err = sf
            .sobject("Product2")
            .retrieve_by_external_id("SKU__c", "")
            .await
            .unwrap_err();
        assert!(
            matches!(err, CirrusError::InvalidInput { .. }),
            "got {err:?}"
        );
        let err = sf
            .sobject("Product2")
            .delete_by_external_id("SKU__c", "")
            .await
            .unwrap_err();
        assert!(
            matches!(err, CirrusError::InvalidInput { .. }),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn upsert_update_only_sends_the_query_parameter_on_the_encoded_path() {
        // SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/resources_sobject_upsert_patch.htm
        // "updateOnly: An optional parameter that prevents a new record from
        // being created. Forces the upsert to behave like an update when
        // updateOnly=true is used." The example URL on dome_upsert is
        // .../sobjects/Account/customExtIdField__c/11999?updateOnly=true.
        let server = MockServer::start().await;
        Mock::given(method("PATCH"))
            .and(path("/services/data/v66.0/sobjects/Account/Ext__c/A%231"))
            .and(query_param("updateOnly", "true"))
            .and(body_json(json!({"Name": "Acme"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "001xx0000000001",
                "success": true,
                "errors": [],
                "created": false
            })))
            .expect(1)
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let result = sf
            .sobject("Account")
            .upsert_with(
                "Ext__c",
                "A#1",
                &json!({"Name": "Acme"}),
                UpsertOptions { update_only: true },
            )
            .await
            .unwrap();
        assert_eq!(result.created, Some(false));
    }

    #[tokio::test]
    async fn upsert_without_options_sends_no_query_string() {
        // The default upsert must not carry `updateOnly=false` or any
        // other parameter the plain PATCH page doesn't show.
        let server = MockServer::start().await;
        Mock::given(method("PATCH"))
            .and(path("/services/data/v66.0/sobjects/Account/Ext__c/A-1"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "id": "001xx0000000001",
                "success": true,
                "errors": [],
                "created": true
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        sf.sobject("Account")
            .upsert("Ext__c", "A-1", &json!({"Name": "Acme"}))
            .await
            .unwrap();
        let received = server.received_requests().await.unwrap();
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].url.query(), None, "url was {}", received[0].url);
    }

    #[tokio::test]
    async fn retrieve_typed() {
        #[derive(serde::Deserialize)]
        struct Account {
            #[serde(rename = "Name")]
            name: String,
        }

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/services/data/v66.0/sobjects/Account/001xx0000000001",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"Name": "Acme"})))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let acct: Account = sf
            .sobject("Account")
            .retrieve_as("001xx0000000001")
            .await
            .unwrap();
        assert_eq!(acct.name, "Acme");
    }

    #[tokio::test]
    async fn create_surfaces_validation_errors() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/services/data/v66.0/sobjects/Account"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!([{
                "message": "Required fields are missing: [Name]",
                "errorCode": "REQUIRED_FIELD_MISSING",
                "fields": ["Name"]
            }])))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let err = sf.sobject("Account").create(&json!({})).await.unwrap_err();
        match err {
            crate::CirrusError::Api { status, errors, .. } => {
                assert_eq!(status, 400);
                assert_eq!(errors[0].error_code, "REQUIRED_FIELD_MISSING");
                assert_eq!(errors[0].fields, vec!["Name".to_string()]);
            }
            other => panic!("expected Api error, got {other:?}"),
        }
    }

    /// Multipart blob uploads. wiremock matchers can't structurally
    /// parse multipart bodies (the boundary is randomized per request),
    /// so these tests verify by header + body-substring matching:
    /// `Content-Type` starts with `multipart/form-data`, and the body
    /// contains the part-name + filename + JSON-snippet markers we
    /// expect.
    mod conditional {
        use super::super::http_date;
        use super::*;
        use std::time::{Duration, SystemTime};
        use wiremock::matchers::header_regex;

        #[tokio::test]
        async fn describe_global_if_modified_since_returns_some_on_200() {
            let server = MockServer::start().await;

            // Hits the same /sobjects path as plain describe_global,
            // but the request must carry an If-Modified-Since header
            // formatted as RFC 7231 IMF-fixdate (e.g. "Wed, 21 Oct
            // 2015 07:28:00 GMT" — the comma + space is the giveaway).
            Mock::given(method("GET"))
                .and(path("/services/data/v66.0/sobjects"))
                .and(header_regex(
                    "if-modified-since",
                    r"^[A-Z][a-z]{2}, \d{2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} GMT$",
                ))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "encoding": "UTF-8",
                    "maxBatchSize": 200,
                    "sobjects": [{
                        "activateable": false, "custom": false, "customSetting": false,
                        "createable": true, "deletable": true, "deprecatedAndHidden": false,
                        "feedEnabled": true, "keyPrefix": "001",
                        "label": "Account", "labelPlural": "Accounts",
                        "layoutable": true, "mergeable": true, "mruEnabled": true,
                        "name": "Account", "queryable": true, "replicateable": true,
                        "retrieveable": true, "searchable": true, "triggerable": true,
                        "undeletable": true, "updateable": true,
                        "urls": {}
                    }]
                })))
                .mount(&server)
                .await;

            let sf = fixture(server.uri());
            let yesterday = SystemTime::now() - Duration::from_secs(86_400);
            let result = sf
                .sobjects()
                .describe_global_if_modified_since(yesterday)
                .await
                .unwrap();
            let dg = result.expect("expected Some(DescribeGlobal) on 200");
            assert_eq!(dg.encoding, "UTF-8");
            assert_eq!(dg.sobjects[0].name, "Account");
        }

        #[tokio::test]
        async fn describe_global_if_modified_since_returns_none_on_304() {
            let server = MockServer::start().await;

            Mock::given(method("GET"))
                .and(path("/services/data/v66.0/sobjects"))
                .and(header_regex("if-modified-since", r"GMT$"))
                .respond_with(ResponseTemplate::new(304))
                .mount(&server)
                .await;

            let sf = fixture(server.uri());
            let yesterday = SystemTime::now() - Duration::from_secs(86_400);
            let result = sf
                .sobjects()
                .describe_global_if_modified_since(yesterday)
                .await
                .unwrap();
            assert!(result.is_none(), "expected None on 304");
        }

        #[tokio::test]
        async fn describe_per_object_if_modified_since_returns_typed_some() {
            #[derive(serde::Deserialize)]
            struct DescribeSubset {
                name: String,
                custom: bool,
            }

            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/services/data/v66.0/sobjects/Account/describe"))
                .and(header_regex("if-modified-since", r"GMT$"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "name": "Account",
                    "custom": false,
                    "fields": []
                })))
                .mount(&server)
                .await;

            let sf = fixture(server.uri());
            let result: Option<DescribeSubset> = sf
                .sobject("Account")
                .describe_if_modified_since_as(SystemTime::now())
                .await
                .unwrap();
            let d = result.unwrap();
            assert_eq!(d.name, "Account");
            assert!(!d.custom);
        }

        #[tokio::test]
        async fn describe_per_object_if_modified_since_none_on_304() {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/services/data/v66.0/sobjects/Account/describe"))
                .respond_with(ResponseTemplate::new(304))
                .mount(&server)
                .await;

            let sf = fixture(server.uri());
            let result = sf
                .sobject("Account")
                .describe_if_modified_since(SystemTime::now())
                .await
                .unwrap();
            assert!(result.is_none());
        }

        #[tokio::test]
        async fn conditional_describe_surfaces_other_4xx_as_error() {
            // 401/403/etc. should NOT become Ok(None) — that special
            // case is reserved for 304. Other non-2xx flow through
            // the standard error-array parsing.
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/services/data/v66.0/sobjects"))
                .respond_with(ResponseTemplate::new(403).set_body_json(json!([{
                    "errorCode": "INSUFFICIENT_ACCESS",
                    "message": "no permission"
                }])))
                .mount(&server)
                .await;

            let sf = fixture(server.uri());
            let err = sf
                .sobjects()
                .describe_global_if_modified_since(SystemTime::now())
                .await
                .unwrap_err();
            assert!(matches!(err, crate::CirrusError::Api { status: 403, .. }));
        }

        #[tokio::test]
        async fn conditional_describe_keeps_an_off_contract_2xx_body_excerpt() {
            // SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/errorcodes.htm
            // "420 Salesforce Edge doesn't have routing information
            // available for this request host." An interposed hop can
            // answer for the instance, and nothing stops it doing so
            // with a 200 and its own page. That body is the only
            // diagnostic there is, so the conditional path has to keep
            // an excerpt of it — and scrub the credential the page
            // echoed back — just like the unconditional one.
            let token = "00D5f000000ABCD!AQcAQK_session_id";
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/services/data/v66.0/sobjects"))
                .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                    "<html>GET /services/data/v66.0/sobjects\nAuthorization: Bearer {token}</html>"
                )))
                .mount(&server)
                .await;

            let auth = Arc::new(StaticTokenAuth::new(token, server.uri()));
            let sf = Cirrus::builder().auth(auth).build().unwrap();
            let err = sf
                .sobjects()
                .describe_global_if_modified_since(SystemTime::now())
                .await
                .unwrap_err();
            match err {
                crate::CirrusError::InvalidResponse(message) => {
                    assert!(message.contains("200"), "{message}");
                    assert!(message.contains("<html>"), "{message}");
                    assert!(!message.contains(token), "{message}");
                    assert!(message.contains("[redacted]"), "{message}");
                }
                other => panic!("expected InvalidResponse, got {other:?}"),
            }
        }

        #[tokio::test]
        async fn conditional_per_object_describe_keeps_an_off_contract_2xx_body_excerpt() {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/services/data/v66.0/sobjects/Account/describe"))
                .respond_with(ResponseTemplate::new(200).set_body_string("not json at all"))
                .mount(&server)
                .await;

            let sf = fixture(server.uri());
            let err = sf
                .sobject("Account")
                .describe_if_modified_since(SystemTime::now())
                .await
                .unwrap_err();
            match err {
                crate::CirrusError::InvalidResponse(message) => {
                    assert!(message.contains("200"), "{message}");
                    assert!(message.contains("not json at all"), "{message}");
                }
                other => panic!("expected InvalidResponse, got {other:?}"),
            }
        }

        #[test]
        fn http_date_formats_a_representable_time() {
            // RFC 7231 IMF-fixdate example: 1994-11-06T08:49:37Z.
            let t = SystemTime::UNIX_EPOCH + Duration::from_secs(784_111_777);
            assert_eq!(http_date(t).unwrap(), "Sun, 06 Nov 1994 08:49:37 GMT");
        }

        #[test]
        fn http_date_rejects_times_before_the_epoch() {
            let t = SystemTime::UNIX_EPOCH - Duration::from_secs(1);
            assert!(matches!(
                http_date(t),
                Err(crate::CirrusError::InvalidHeader(_))
            ));
        }

        #[test]
        fn http_date_rejects_year_9999_and_later() {
            let t = SystemTime::UNIX_EPOCH + Duration::from_secs(253_402_300_800);
            assert!(matches!(
                http_date(t),
                Err(crate::CirrusError::InvalidHeader(_))
            ));
        }

        #[tokio::test]
        async fn conditional_describe_errors_on_unrepresentable_time() {
            // A cache watermark computed defensively (a pre-epoch
            // sentinel, a clock skewed backwards) must not unwind the
            // caller's task.
            let server = MockServer::start().await;
            let sf = fixture(server.uri());
            let before_epoch = SystemTime::UNIX_EPOCH - Duration::from_secs(1);

            let err = sf
                .sobjects()
                .describe_global_if_modified_since(before_epoch)
                .await
                .unwrap_err();
            assert!(
                matches!(err, crate::CirrusError::InvalidHeader(_)),
                "{err:?}"
            );

            let err = sf
                .sobject("Account")
                .describe_if_modified_since(before_epoch)
                .await
                .unwrap_err();
            assert!(
                matches!(err, crate::CirrusError::InvalidHeader(_)),
                "{err:?}"
            );

            assert!(server.received_requests().await.unwrap().is_empty());
        }
    }

    mod blob_upload {
        use super::*;
        use crate::BlobUploadSpec;
        use wiremock::matchers::{body_string_contains, header_regex};

        #[tokio::test]
        async fn create_with_blob_posts_multipart_to_sobjects_endpoint() {
            // SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/dome_sobject_insert_update_blob.htm
            // Mirrors the documented ContentVersion insert: the example's
            // JSON part name `entity_content`, and the required binary
            // part name `VersionData`.
            let server = MockServer::start().await;

            Mock::given(method("POST"))
                .and(path("/services/data/v66.0/sobjects/ContentVersion"))
                .and(header("authorization", "Bearer tok"))
                .and(header_regex(
                    "content-type",
                    r"^multipart/form-data; boundary=",
                ))
                .and(body_string_contains(r#"name="entity_content""#))
                .and(body_string_contains(r#"name="VersionData""#))
                .and(body_string_contains(r#"filename="brochure.pdf""#))
                .and(body_string_contains(r#""PathOnClient":"brochure.pdf""#))
                .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                    "id": "068D00000000pgOIAQ",
                    "errors": [],
                    "success": true
                })))
                .mount(&server)
                .await;

            let sf = fixture(server.uri());
            let pdf = bytes::Bytes::from_static(b"%PDF-1.4 fake pdf bytes\n");
            let result = sf
                .sobject("ContentVersion")
                .create_with_blob(BlobUploadSpec {
                    json_part_name: "entity_content",
                    metadata: &json!({
                        "Title": "Q1 Brochure",
                        "PathOnClient": "brochure.pdf",
                    }),
                    blob_field_name: "VersionData",
                    filename: "brochure.pdf",
                    content_type: Some("application/pdf"),
                    blob: pdf,
                })
                .await
                .unwrap();
            assert_eq!(result.id, "068D00000000pgOIAQ");
            assert!(result.success);
        }

        #[tokio::test]
        async fn create_with_blob_defaults_content_type_to_octet_stream() {
            // When `content_type: None`, the binary part should
            // declare application/octet-stream.
            let server = MockServer::start().await;

            Mock::given(method("POST"))
                .and(path("/services/data/v66.0/sobjects/Document"))
                .and(body_string_contains("application/octet-stream"))
                .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                    "id": "015D000000000",
                    "errors": [],
                    "success": true
                })))
                .mount(&server)
                .await;

            let sf = fixture(server.uri());
            sf.sobject("Document")
                .create_with_blob(BlobUploadSpec {
                    json_part_name: "entity_document",
                    metadata: &json!({"Name": "test", "FolderId": "005xx", "Type": "pdf"}),
                    blob_field_name: "Body",
                    filename: "x.pdf",
                    content_type: None,
                    blob: bytes::Bytes::from_static(b"fake"),
                })
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn create_with_blob_surfaces_the_documented_bare_error_object() {
            // SOURCE: https://developer.salesforce.com/docs/platform/api-rest/guide/dome-sobject-insert-update-blob.html
            // "Example error response" prints the MALFORMED_ID error as a
            // single object, not inside the array the Status Codes and
            // Error Responses page documents.
            let server = MockServer::start().await;

            Mock::given(method("POST"))
                .and(path("/services/data/v66.0/sobjects/Document"))
                .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                    "fields": ["FolderId"],
                    "message": "Folder ID: id value of incorrect type",
                    "errorCode": "MALFORMED_ID"
                })))
                .mount(&server)
                .await;

            let sf = fixture(server.uri());
            let err = sf
                .sobject("Document")
                .create_with_blob(BlobUploadSpec {
                    json_part_name: "entity_document",
                    metadata: &json!({"Name": "x", "FolderId": "bad", "Type": "pdf"}),
                    blob_field_name: "Body",
                    filename: "x.pdf",
                    content_type: Some("application/pdf"),
                    blob: bytes::Bytes::from_static(b"x"),
                })
                .await
                .unwrap_err();
            match err {
                crate::CirrusError::Api {
                    status,
                    errors,
                    raw,
                    ..
                } => {
                    assert_eq!(status, 400);
                    assert_eq!(errors.len(), 1);
                    assert_eq!(errors[0].error_code, "MALFORMED_ID");
                    assert_eq!(errors[0].fields, vec!["FolderId".to_string()]);
                    assert!(raw.is_none(), "{raw:?}");
                }
                other => panic!("expected Api error, got {other:?}"),
            }
        }

        #[tokio::test]
        async fn create_with_blob_surfaces_salesforce_error_array() {
            let server = MockServer::start().await;

            Mock::given(method("POST"))
                .and(path("/services/data/v66.0/sobjects/Document"))
                .respond_with(ResponseTemplate::new(400).set_body_json(json!([{
                    "fields": ["FolderId"],
                    "message": "Folder ID: id value of incorrect type",
                    "errorCode": "MALFORMED_ID"
                }])))
                .mount(&server)
                .await;

            let sf = fixture(server.uri());
            let err = sf
                .sobject("Document")
                .create_with_blob(BlobUploadSpec {
                    json_part_name: "entity_document",
                    metadata: &json!({"Name": "x", "FolderId": "bad", "Type": "pdf"}),
                    blob_field_name: "Body",
                    filename: "x.pdf",
                    content_type: Some("application/pdf"),
                    blob: bytes::Bytes::from_static(b"x"),
                })
                .await
                .unwrap_err();
            match err {
                crate::CirrusError::Api { status, errors, .. } => {
                    assert_eq!(status, 400);
                    assert_eq!(errors[0].error_code, "MALFORMED_ID");
                    assert_eq!(errors[0].fields, vec!["FolderId".to_string()]);
                }
                other => panic!("expected Api error, got {other:?}"),
            }
        }

        #[test]
        fn blob_upload_spec_debug_summarizes_the_payload() {
            // The blob is the file being shipped to Salesforce and the
            // metadata is caller record data; neither may reach a log
            // sink through a `?spec` capture.
            let spec = BlobUploadSpec {
                json_part_name: "entity_content",
                metadata: &json!({"Title": "Signed contract", "OwnerId": "005xx"}),
                blob_field_name: "VersionData",
                filename: "contract.pdf",
                content_type: Some("application/pdf"),
                blob: bytes::Bytes::from_static(b"%PDF-1.7 secret bytes"),
            };

            let rendered = format!("{spec:?}");
            assert!(rendered.contains("blob_len: 21"), "{rendered}");
            assert!(!rendered.contains("secret"), "{rendered}");
            assert!(!rendered.contains("Signed contract"), "{rendered}");
            assert!(!rendered.contains("005xx"), "{rendered}");
        }

        #[tokio::test]
        async fn update_with_blob_uses_patch_and_targets_record_id_path() {
            let server = MockServer::start().await;

            // SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/dome_sobject_insert_update_blob.htm
            // Mirrors the doc's "Updating a Document with Blob Data"
            // example: an arbitrary JSON part name, and the binary part
            // named for Document's blob field, `Body`.
            Mock::given(method("PATCH"))
                .and(path("/services/data/v66.0/sobjects/Document/015D000000000"))
                .and(header_regex(
                    "content-type",
                    r"^multipart/form-data; boundary=",
                ))
                .and(body_string_contains(r#"name="entity_content""#))
                .and(body_string_contains(r#"name="Body""#))
                .respond_with(ResponseTemplate::new(204))
                .mount(&server)
                .await;

            let sf = fixture(server.uri());
            sf.sobject("Document")
                .update_with_blob(
                    "015D000000000",
                    BlobUploadSpec {
                        json_part_name: "entity_content",
                        metadata: &json!({"Name": "Updated"}),
                        blob_field_name: "Body",
                        filename: "updated.pdf",
                        content_type: Some("application/pdf"),
                        blob: bytes::Bytes::from_static(b"%PDF updated"),
                    },
                )
                .await
                .unwrap();
        }
    }
}
