//! Composite resources — fan-out primitives that bundle multiple REST
//! sub-requests into a single round trip.
//!
//! Salesforce groups several composite endpoints under
//! `/services/data/{version}/composite/...`. This module hosts the typed
//! handler for them, including:
//!
//! - [`CompositeHandler::batch`] — `POST /composite/batch`, up to 25
//!   sub-requests in one call. Sub-requests run serially; the outer call
//!   always returns HTTP 200 for a well-formed batch and per-subrequest
//!   failures surface via [`BatchResponse::has_errors`].
//!
//! # Sub-request URL shape
//!
//! Sub-request URLs are *not* instance-rooted and they do *not* go through
//! [`Cirrus::resolve_url`]. Salesforce dispatches them under the
//! configured `/services/data/` tree, so the expected form is
//! `vXX.X/sobjects/Account/001…` — the API version prefix is mandatory.
//! Each sub-request can target a different version, subject to the rule
//! `v34.0 ≤ subrequest_version ≤ batch_version`.
//!
//! [`Cirrus::resolve_url`]: crate::Cirrus

use crate::Cirrus;
use crate::error::CirrusResult;
use crate::response::{
    BatchResponse, CompositeResponse, CompositeTreeResponse, SObjectCollectionResult,
};
use reqwest::header::HeaderMap;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

impl Cirrus {
    /// Returns a handler for the composite REST resources.
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
    /// // Bulk-create three Accounts in one round trip.
    /// let results = sf.composite().sobjects().create(&json!({
    ///     "allOrNone": false,
    ///     "records": [
    ///         { "attributes": { "type": "Account" }, "Name": "Acme" },
    ///         { "attributes": { "type": "Account" }, "Name": "Globex" },
    ///         { "attributes": { "type": "Account" }, "Name": "Initech" },
    ///     ]
    /// })).await?;
    /// for r in &results {
    ///     println!("success={} id={:?}", r.success, r.id);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn composite(&self) -> CompositeHandler<'_> {
        CompositeHandler { client: self }
    }
}

/// Handler for `/services/data/{version}/composite/...` resources.
///
/// Returned by [`Cirrus::composite`].
#[derive(Debug)]
pub struct CompositeHandler<'a> {
    client: &'a Cirrus,
}

impl CompositeHandler<'_> {
    /// Executes up to 25 sub-requests in a single batch via
    /// `POST /services/data/{api_version}/composite/batch`.
    ///
    /// `body` is any [`Serialize`] value matching Salesforce's documented
    /// shape — typically a [`BatchRequest`] from this crate, or a hand-rolled
    /// `serde_json::json!({...})`. Sub-request URLs must include their own
    /// API version prefix (e.g. `"v66.0/sobjects/Account/001…"`).
    ///
    /// Sub-requests execute serially in submission order. A sub-request that
    /// fails does *not* roll back commits made by earlier sub-requests; the
    /// caller is responsible for compensating logic. Set
    /// [`BatchRequest::halt_on_error`] to stop processing after the first
    /// failure (Salesforce returns HTTP 412 with `BATCH_PROCESSING_HALTED`
    /// for the remaining sub-requests).
    ///
    /// ```ignore
    /// use cirrus::{BatchRequest, BatchSubrequest};
    /// use serde_json::json;
    ///
    /// let req = BatchRequest {
    ///     batch_requests: vec![
    ///         BatchSubrequest {
    ///             method: "GET".into(),
    ///             url: "v66.0/limits".into(),
    ///             rich_input: None,
    ///         },
    ///         BatchSubrequest {
    ///             method: "PATCH".into(),
    ///             url: "v66.0/sobjects/Account/001xx".into(),
    ///             rich_input: Some(json!({"Name": "Acme"})),
    ///         },
    ///     ],
    ///     halt_on_error: Some(true),
    /// };
    /// let resp = sf.composite().batch(&req).await?;
    /// if resp.has_errors {
    ///     for sub in &resp.results {
    ///         if !sub.is_success() {
    ///             eprintln!("subrequest failed: {} {}", sub.status_code, sub.result);
    ///         }
    ///     }
    /// }
    /// ```
    pub async fn batch<B>(&self, body: &B) -> CirrusResult<BatchResponse>
    where
        B: Serialize + ?Sized,
    {
        self.client.post("composite/batch", body).await
    }

    /// Creates a tree of nested records in one round trip via
    /// `POST /services/data/{api_version}/composite/tree/{sobject}`.
    ///
    /// `sobject` is the **root** record type (e.g. `"Account"`) — child
    /// types are inferred from each record's `attributes.type`. The body is
    /// any [`Serialize`] value matching the documented envelope:
    ///
    /// ```ignore
    /// use serde_json::json;
    ///
    /// let body = json!({
    ///     "records": [{
    ///         "attributes": {"type": "Account", "referenceId": "ref1"},
    ///         "Name": "Acme",
    ///         "Contacts": {
    ///             "records": [{
    ///                 "attributes": {"type": "Contact", "referenceId": "ref2"},
    ///                 "LastName": "Doe"
    ///             }]
    ///         }
    ///     }]
    /// });
    /// let resp = sf.composite().tree("Account", &body).await?;
    /// for r in &resp.results {
    ///     if let Some(id) = &r.id {
    ///         println!("{} -> {}", r.reference_id, id);
    ///     }
    /// }
    /// ```
    ///
    /// **Limits:** up to 200 records total across all trees, up to 5
    /// distinct sObject types, and up to 5 levels of nesting.
    ///
    /// **All-or-nothing:** if any record fails validation/save, the entire
    /// request rolls back and [`CompositeTreeResponse::has_errors`] is
    /// `true`. The `results` collection in that case lists only the
    /// failing records' `referenceId`s — *no* records were committed.
    pub async fn tree<B>(&self, sobject: &str, body: &B) -> CirrusResult<CompositeTreeResponse>
    where
        B: Serialize + ?Sized,
    {
        let url = self
            .client
            .versioned_segments(&["composite", "tree", sobject])?;
        self.client
            .send_at(reqwest::Method::POST, &url, None::<&()>, Some(body))
            .await
    }

    /// Returns a sub-handler for the sObject Collections endpoints
    /// (`/composite/sobjects`).
    ///
    /// Five operations live under this resource — see
    /// [`CompositeSObjectsHandler`] for create/retrieve/update/upsert/delete
    /// against up to 200 (or 800 for retrieve) records per call.
    pub fn sobjects(&self) -> CompositeSObjectsHandler<'_> {
        CompositeSObjectsHandler {
            client: self.client,
        }
    }

    /// Executes a chained series of REST sub-requests in a single call via
    /// `POST /services/data/{api_version}/composite`.
    ///
    /// Up to 25 sub-requests, with reference binding (`@{ref.field}`) so a
    /// later sub-request can consume an earlier one's output. The body is
    /// any [`Serialize`] value matching the documented envelope —
    /// typically a [`CompositeRequest`] from this crate.
    ///
    /// **Sub-request URL shape differs from [`batch`](Self::batch).** Generic
    /// composite sub-requests use full-prefix URLs starting with
    /// `/services/data/vXX.X/`, *not* the bare `vXX.X/...` form that batch
    /// uses. Wires-crossed gives a 400 from Salesforce.
    ///
    /// **Reference binding** is a server-side template Salesforce evaluates
    /// before each sub-request runs. Field names are case-sensitive: a
    /// create's response uses `id` (lowercase) but a record retrieve uses
    /// `Id` — `@{ref.id}` and `@{ref.Id}` reach different fields.
    ///
    /// ```ignore
    /// use cirrus::{CompositeRequest, CompositeSubrequest};
    /// use serde_json::json;
    ///
    /// let req = CompositeRequest {
    ///     all_or_none: Some(true),
    ///     collate_subrequests: None, // server default (true since v49.0)
    ///     composite_request: vec![
    ///         CompositeSubrequest {
    ///             method: "POST".into(),
    ///             url: "/services/data/v66.0/sobjects/Account".into(),
    ///             reference_id: "NewAccount".into(),
    ///             body: Some(json!({"Name": "Acme"})),
    ///             http_headers: None,
    ///         },
    ///         CompositeSubrequest {
    ///             method: "POST".into(),
    ///             url: "/services/data/v66.0/sobjects/Contact".into(),
    ///             reference_id: "NewContact".into(),
    ///             body: Some(json!({
    ///                 "AccountId": "@{NewAccount.id}",
    ///                 "LastName": "Doe"
    ///             })),
    ///             http_headers: None,
    ///         },
    ///     ],
    /// };
    /// let resp = sf.composite().execute(&req).await?;
    /// for sub in &resp.composite_response {
    ///     println!("{} -> {}", sub.reference_id, sub.http_status_code);
    /// }
    /// ```
    pub async fn execute<B>(&self, body: &B) -> CirrusResult<CompositeResponse>
    where
        B: Serialize + ?Sized,
    {
        self.client.post("composite", body).await
    }
}

/// Request body for [`CompositeHandler::execute`].
///
/// Equivalent to a `serde_json::json!({...})` literal of the documented
/// envelope; both flow through [`CompositeHandler::execute`]'s generic
/// `Serialize` bound.
#[derive(Debug, Clone, Default, Serialize)]
pub struct CompositeRequest {
    /// Sub-requests to execute (max 25, of which up to 5 may be sObject
    /// Collections or query/queryAll calls).
    #[serde(rename = "compositeRequest")]
    pub composite_request: Vec<CompositeSubrequest>,
    /// When `Some(true)`, any sub-request failure rolls back the whole
    /// composite request transactionally. Defaults to `false` server-side
    /// when omitted.
    #[serde(rename = "allOrNone", skip_serializing_if = "Option::is_none")]
    pub all_or_none: Option<bool>,
    /// Whether the API may collate compatible sub-requests into bulkified
    /// operations. Server default: `true` since API v49.0, `false` on
    /// v48.0. We omit the field when `None` so callers see the server
    /// default for their configured `api_version`.
    #[serde(rename = "collateSubrequests", skip_serializing_if = "Option::is_none")]
    pub collate_subrequests: Option<bool>,
}

/// One entry in [`CompositeRequest::composite_request`].
///
/// `url` *must* start with `/services/data/vXX.X/` — generic composite
/// requires the full path prefix that [`BatchSubrequest::url`] (without
/// the `/services/data/` prefix) does *not*. Don't confuse the two.
///
/// `reference_id` is required and must start with a letter/digit and
/// contain only letters/digits/underscores. Other sub-requests in the
/// same composite can reference this entry via `@{reference_id.field}`.
#[derive(Debug, Clone, Serialize)]
pub struct CompositeSubrequest {
    /// HTTP method, e.g. `"POST"`, `"PATCH"`, `"GET"`, `"DELETE"`.
    pub method: String,
    /// Resource URL — must start with `/services/data/vXX.X/`.
    pub url: String,
    /// Reference ID used both to correlate the matching subresponse and
    /// for `@{...}` binding from later sub-requests.
    #[serde(rename = "referenceId")]
    pub reference_id: String,
    /// Request body for the sub-request. `None` for verbs that don't
    /// carry a body (GET, DELETE).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<Value>,
    /// Per-sub-request HTTP headers. Salesforce rejects `Accept`,
    /// `Authorization`, and `Content-Type` here — they're inherited from
    /// the top-level request. Also: setting any header opts a sub-request
    /// out of collation.
    #[serde(
        rename = "httpHeaders",
        with = "http_serde::option::header_map",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub http_headers: Option<HeaderMap>,
}

/// Handler for `/composite/sobjects` — the SObject Collections endpoints.
///
/// Available since API version 42.0. Each method below corresponds to one
/// HTTP verb against the resource:
///
/// - [`create`](Self::create) — `POST` (up to 200 records)
/// - [`update`](Self::update) — `PATCH` on the bare collection (up to 200)
/// - [`upsert`](Self::upsert) — `PATCH` on `/{sobject}/{externalIdField}` (up to 200)
/// - [`delete`](Self::delete) — `DELETE` with `?ids=...` (up to 200)
/// - [`retrieve`](Self::retrieve) — `GET` on `/{sobject}` with `?ids=...&fields=...` (up to ~800, URL-length-bound)
/// - [`retrieve_with_body`](Self::retrieve_with_body) — `POST` on `/{sobject}` with `{ids, fields}` body (up to 2000)
///
/// All methods return record-level results and never roll back across
/// records on partial failure (when `allOrNone: false`, which is the
/// default). Set `allOrNone` on the request body (or query string for
/// delete) to enable transactional semantics.
#[derive(Debug)]
pub struct CompositeSObjectsHandler<'a> {
    client: &'a Cirrus,
}

impl CompositeSObjectsHandler<'_> {
    /// Creates up to 200 records via `POST /composite/sobjects`.
    ///
    /// The body envelope is `{"allOrNone": false, "records": [...]}`,
    /// where each record carries an `attributes.type` identifying its
    /// sObject. Records may target different sObject types in the same
    /// call.
    ///
    /// ```ignore
    /// use serde_json::json;
    ///
    /// let body = json!({
    ///     "allOrNone": false,
    ///     "records": [
    ///         {"attributes": {"type": "Account"}, "Name": "Acme"},
    ///         {"attributes": {"type": "Contact"}, "LastName": "Doe"}
    ///     ]
    /// });
    /// let results = sf.composite().sobjects().create(&body).await?;
    /// for r in &results {
    ///     if r.success {
    ///         println!("{:?}", r.id);
    ///     }
    /// }
    /// ```
    pub async fn create<B>(&self, body: &B) -> CirrusResult<Vec<SObjectCollectionResult>>
    where
        B: Serialize + ?Sized,
    {
        self.client.post("composite/sobjects", body).await
    }

    /// Updates up to 200 records via `PATCH /composite/sobjects`.
    ///
    /// Each record in the body must include its `id` alongside the
    /// `attributes.type` and the fields to update. Same envelope as
    /// [`create`](Self::create).
    pub async fn update<B>(&self, body: &B) -> CirrusResult<Vec<SObjectCollectionResult>>
    where
        B: Serialize + ?Sized,
    {
        self.client.patch("composite/sobjects", body).await
    }

    /// Upserts up to 200 records by external ID via
    /// `PATCH /composite/sobjects/{sobject}/{externalIdField}`.
    ///
    /// Each record must carry the external ID field's value as a top-level
    /// property. [`SObjectCollectionResult::created`] indicates whether
    /// each record was newly inserted (`Some(true)`) or matched an
    /// existing record (`Some(false)`).
    pub async fn upsert<B>(
        &self,
        sobject: &str,
        external_id_field: &str,
        body: &B,
    ) -> CirrusResult<Vec<SObjectCollectionResult>>
    where
        B: Serialize + ?Sized,
    {
        let url = self.client.versioned_segments(&[
            "composite",
            "sobjects",
            sobject,
            external_id_field,
        ])?;
        self.client
            .send_at(reqwest::Method::PATCH, &url, None::<&()>, Some(body))
            .await
    }

    /// Deletes up to 200 records by ID via
    /// `DELETE /composite/sobjects?ids=...&allOrNone=...`.
    ///
    /// `ids` is comma-joined into a single query parameter. `all_or_none`
    /// makes the operation transactional: when `true`, any single
    /// failure rolls back the whole batch.
    pub async fn delete(
        &self,
        ids: &[&str],
        all_or_none: bool,
    ) -> CirrusResult<Vec<SObjectCollectionResult>> {
        let joined = ids.join(",");
        let all = if all_or_none { "true" } else { "false" };
        let url = self.client.versioned_segments(&["composite", "sobjects"])?;
        self.client
            .send_at::<_, _, ()>(
                reqwest::Method::DELETE,
                &url,
                Some(&[("ids", joined.as_str()), ("allOrNone", all)]),
                None,
            )
            .await
    }

    /// Retrieves up to 800 records of a single sObject type via
    /// `GET /composite/sobjects/{sobject}?ids=...&fields=...`.
    ///
    /// Records that don't exist (or aren't visible to the caller) appear
    /// as `Value::Null` in the corresponding position of the returned
    /// slice — preserving 1:1 alignment with the input `ids`.
    ///
    /// Salesforce documents the ~800-ID ceiling as the point where the
    /// URI passes its 16,384-byte limit and the request fails with HTTP
    /// 414. Beyond that, switch to
    /// [`retrieve_with_body`](Self::retrieve_with_body), which carries
    /// the same arguments in a JSON body and allows 2000 records.
    pub async fn retrieve(
        &self,
        sobject: &str,
        ids: &[&str],
        fields: &[&str],
    ) -> CirrusResult<Vec<Value>> {
        self.retrieve_as(sobject, ids, fields).await
    }

    /// Typed variant of [`retrieve`](Self::retrieve). Records that don't
    /// exist will fail to deserialize as `R` from `null` unless `R` itself
    /// is `Option<T>` — use `Vec<Option<T>>` if missing records are
    /// possible.
    pub async fn retrieve_as<R: DeserializeOwned>(
        &self,
        sobject: &str,
        ids: &[&str],
        fields: &[&str],
    ) -> CirrusResult<Vec<R>> {
        let mut url = url::Url::parse(&self.client.versioned_segments(&[
            "composite",
            "sobjects",
            sobject,
        ])?)?;
        // The query string is set wholesale rather than handed to
        // reqwest's form encoder, which would emit each separator as
        // `%2C`. A comma is a legal sub-delim in a query, and the
        // three-byte expansion costs ~1.6 KB across the 799 separators
        // of a full 800-ID batch — enough to push a request that
        // Salesforce documents as legal past the 16,384-byte URI limit.
        url.set_query(Some(&format!(
            "ids={}&fields={}",
            ids.join(","),
            fields.join(",")
        )));
        self.client
            .send_at::<_, (), ()>(reqwest::Method::GET, url.as_str(), None, None)
            .await
    }

    /// Retrieves up to 2000 records of a single sObject type via
    /// `POST /composite/sobjects/{sobject}` with body `{ids, fields}`.
    ///
    /// Functionally equivalent to [`retrieve`](Self::retrieve) but ferries
    /// the IDs and field list in a JSON body instead of the query string.
    /// Use this when:
    ///
    /// - The number of IDs exceeds the GET form's URL-length cap
    ///   (~800 — Salesforce documents 414 URI Too Long beyond that).
    /// - The total length of `fields` (e.g. many long custom field
    ///   names) pushes a smaller batch over the URL cap.
    ///
    /// Records that don't exist or aren't visible appear as `null` in the
    /// returned array — same per-position alignment as
    /// [`retrieve`](Self::retrieve). Use [`retrieve_with_body_as`]`::<Option<T>>`
    /// for typed deserialization in the presence of nulls.
    ///
    /// [`retrieve_with_body_as`]: Self::retrieve_with_body_as
    pub async fn retrieve_with_body(
        &self,
        sobject: &str,
        ids: &[&str],
        fields: &[&str],
    ) -> CirrusResult<Vec<Value>> {
        self.retrieve_with_body_as(sobject, ids, fields).await
    }

    /// Typed variant of [`retrieve_with_body`](Self::retrieve_with_body).
    pub async fn retrieve_with_body_as<R: DeserializeOwned>(
        &self,
        sobject: &str,
        ids: &[&str],
        fields: &[&str],
    ) -> CirrusResult<Vec<R>> {
        let url = self
            .client
            .versioned_segments(&["composite", "sobjects", sobject])?;
        let body = serde_json::json!({
            "ids": ids,
            "fields": fields,
        });
        self.client
            .send_at::<_, (), _>(reqwest::Method::POST, &url, None, Some(&body))
            .await
    }
}

/// Request body for [`CompositeHandler::batch`].
///
/// Use this when you want a typed builder for the batch payload. Equivalent
/// to a `serde_json::json!({ "batchRequests": [...], "haltOnError": ... })`
/// literal — both flow through [`CompositeHandler::batch`]'s generic
/// `Serialize` bound.
#[derive(Debug, Clone, Default, Serialize)]
pub struct BatchRequest {
    /// Sub-requests to execute (max 25).
    #[serde(rename = "batchRequests")]
    pub batch_requests: Vec<BatchSubrequest>,
    /// When `Some(true)`, Salesforce halts after the first 4xx/5xx
    /// sub-response and returns 412 `BATCH_PROCESSING_HALTED` for the
    /// remainder. Defaults to `false` server-side; we omit the field
    /// entirely when `None` so the wire shape matches the documented
    /// example exactly.
    #[serde(rename = "haltOnError", skip_serializing_if = "Option::is_none")]
    pub halt_on_error: Option<bool>,
}

/// One entry in [`BatchRequest::batch_requests`].
///
/// `url` is the sub-request target as Salesforce dispatches it under
/// `/services/data/`. It must include the API version prefix
/// (e.g. `"v66.0/sobjects/Account/001…"`); sub-request URLs do *not* go
/// through the SDK's normal path resolution.
///
/// `binaryPartName` / `binaryPartNameAlias` (used for multipart blob
/// uploads) are not exposed here. To use them, drop down to a
/// `serde_json::json!({...})` body.
#[derive(Debug, Clone, Serialize)]
pub struct BatchSubrequest {
    /// HTTP method, e.g. `"GET"`, `"POST"`, `"PATCH"`, `"DELETE"`.
    pub method: String,
    /// Sub-request URL, including the API version prefix.
    pub url: String,
    /// Request body for the sub-request. `None` for verbs that don't carry
    /// a body (GET, DELETE).
    #[serde(rename = "richInput", skip_serializing_if = "Option::is_none")]
    pub rich_input: Option<serde_json::Value>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::Cirrus;
    use crate::auth::StaticTokenAuth;
    use serde_json::json;
    use std::sync::Arc;
    use wiremock::matchers::{body_json, header, method, path, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn fixture(uri: String) -> Cirrus {
        let auth = Arc::new(StaticTokenAuth::new("tok", uri));
        Cirrus::builder().auth(auth).build().unwrap()
    }

    #[tokio::test]
    async fn batch_posts_and_parses_mixed_subresults() {
        let server = MockServer::start().await;

        let request_body = json!({
            "batchRequests": [
                {
                    "method": "PATCH",
                    "url": "v66.0/sobjects/Account/001xx",
                    "richInput": {"Name": "NewName"}
                },
                {
                    "method": "GET",
                    "url": "v66.0/sobjects/Account/001xx?fields=Name"
                }
            ]
        });

        Mock::given(method("POST"))
            .and(path("/services/data/v66.0/composite/batch"))
            .and(header("authorization", "Bearer tok"))
            .and(body_json(request_body.clone()))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "hasErrors": false,
                "results": [
                    {"statusCode": 204, "result": null},
                    {"statusCode": 200, "result": {
                        "attributes": {"type": "Account"},
                        "Name": "NewName",
                        "Id": "001xx"
                    }}
                ]
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let resp = sf.composite().batch(&request_body).await.unwrap();
        assert!(!resp.has_errors);
        assert_eq!(resp.results.len(), 2);
        assert_eq!(resp.results[0].status_code, 204);
        assert!(resp.results[0].result.is_null());
        assert_eq!(resp.results[1].result["Name"], "NewName");
    }

    #[tokio::test]
    async fn batch_typed_request_matches_documented_wire_shape() {
        // Construct via the typed BatchRequest/BatchSubrequest structs and
        // assert the serialized body matches the JSON example from the
        // Salesforce Batch Request Body docs.
        let server = MockServer::start().await;

        let expected_body = json!({
            "batchRequests": [
                {
                    "method": "PATCH",
                    "url": "v66.0/sobjects/account/001D000000K0fXOIAZ",
                    "richInput": {"Name": "NewName"}
                },
                {
                    "method": "GET",
                    "url": "v66.0/sobjects/account/001D000000K0fXOIAZ?fields=Name,BillingPostalCode"
                }
            ]
        });

        Mock::given(method("POST"))
            .and(path("/services/data/v66.0/composite/batch"))
            .and(body_json(expected_body))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "hasErrors": false,
                "results": []
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let req = BatchRequest {
            batch_requests: vec![
                BatchSubrequest {
                    method: "PATCH".into(),
                    url: "v66.0/sobjects/account/001D000000K0fXOIAZ".into(),
                    rich_input: Some(json!({"Name": "NewName"})),
                },
                BatchSubrequest {
                    method: "GET".into(),
                    url: "v66.0/sobjects/account/001D000000K0fXOIAZ?fields=Name,BillingPostalCode"
                        .into(),
                    rich_input: None,
                },
            ],
            halt_on_error: None,
        };
        let resp = sf.composite().batch(&req).await.unwrap();
        assert!(!resp.has_errors);
    }

    #[tokio::test]
    async fn batch_serializes_halt_on_error_when_set() {
        let server = MockServer::start().await;

        // haltOnError is present and `true` in the body.
        Mock::given(method("POST"))
            .and(path("/services/data/v66.0/composite/batch"))
            .and(body_json(json!({
                "batchRequests": [
                    {"method": "GET", "url": "v66.0/limits"}
                ],
                "haltOnError": true
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "hasErrors": false,
                "results": [{"statusCode": 200, "result": {}}]
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let req = BatchRequest {
            batch_requests: vec![BatchSubrequest {
                method: "GET".into(),
                url: "v66.0/limits".into(),
                rich_input: None,
            }],
            halt_on_error: Some(true),
        };
        sf.composite().batch(&req).await.unwrap();
    }

    #[tokio::test]
    async fn batch_omits_halt_on_error_when_none() {
        // None must be skipped entirely — not serialized as null. Any
        // request body with a `haltOnError` key would not match.
        let server = MockServer::start().await;

        let body_without_halt = json!({
            "batchRequests": [
                {"method": "GET", "url": "v66.0/limits"}
            ]
        });

        Mock::given(method("POST"))
            .and(path("/services/data/v66.0/composite/batch"))
            .and(body_json(body_without_halt))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "hasErrors": false,
                "results": []
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let req = BatchRequest {
            batch_requests: vec![BatchSubrequest {
                method: "GET".into(),
                url: "v66.0/limits".into(),
                rich_input: None,
            }],
            halt_on_error: None,
        };
        sf.composite().batch(&req).await.unwrap();
    }

    #[tokio::test]
    async fn batch_surfaces_subrequest_errors_via_has_errors() {
        // Outer call returns 200 even though a sub-request failed —
        // hasErrors=true and the failed result carries a SF error array.
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/services/data/v66.0/composite/batch"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "hasErrors": true,
                "results": [
                    {"statusCode": 200, "result": {"Id": "001xx"}},
                    {"statusCode": 400, "result": [
                        {"message": "Required fields are missing: [Name]",
                         "errorCode": "REQUIRED_FIELD_MISSING",
                         "fields": ["Name"]}
                    ]}
                ]
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let resp = sf
            .composite()
            .batch(&json!({"batchRequests": []}))
            .await
            .unwrap();
        assert!(resp.has_errors);
        assert!(resp.results[0].is_success());
        assert!(!resp.results[1].is_success());
        assert_eq!(resp.results[1].status_code, 400);
        assert_eq!(
            resp.results[1].result[0]["errorCode"],
            "REQUIRED_FIELD_MISSING"
        );
    }

    #[tokio::test]
    async fn tree_creates_nested_records_and_returns_id_map() {
        let server = MockServer::start().await;

        let request_body = json!({
            "records": [{
                "attributes": {"type": "Account", "referenceId": "ref1"},
                "Name": "Acme",
                "Contacts": {
                    "records": [{
                        "attributes": {"type": "Contact", "referenceId": "ref2"},
                        "LastName": "Smith"
                    }, {
                        "attributes": {"type": "Contact", "referenceId": "ref3"},
                        "LastName": "Evans"
                    }]
                }
            }]
        });

        Mock::given(method("POST"))
            .and(path("/services/data/v66.0/composite/tree/Account"))
            .and(header("authorization", "Bearer tok"))
            .and(body_json(request_body.clone()))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "hasErrors": false,
                "results": [
                    {"referenceId": "ref1", "id": "001D000000K0fXOIAZ"},
                    {"referenceId": "ref2", "id": "003D000000QV9n2IAD"},
                    {"referenceId": "ref3", "id": "003D000000QV9n3IAD"}
                ]
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let resp = sf.composite().tree("Account", &request_body).await.unwrap();
        assert!(!resp.has_errors);
        assert_eq!(resp.results.len(), 3);
        assert_eq!(resp.results[0].reference_id, "ref1");
        assert_eq!(resp.results[0].id.as_deref(), Some("001D000000K0fXOIAZ"));
        assert!(resp.results.iter().all(|r| r.is_success()));
    }

    /// Wire shape per the `responses_composite_sobject_tree` "JSON
    /// example upon failure" body.
    ///
    /// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/responses_composite_sobject_tree.htm
    ///
    /// Wire-shape provenance: that page prints the rollback response
    /// body but no HTTP status line, and
    /// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/errorcodes.htm
    /// assigns 201 to "POST requests and some PATCH requests" without
    /// singling out sObject Tree. The 201 below is therefore assumed,
    /// not doc-verified — it has not been pinned against a live org.
    /// What the test does prove is the handler contract that matters:
    /// a 2xx rollback response is surfaced as
    /// [`CompositeTreeResponse`] rather than an error, so callers reach
    /// the per-record `referenceId`/`errors` payload.
    #[tokio::test]
    async fn tree_surfaces_per_record_failure() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/services/data/v66.0/composite/tree/Account"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "hasErrors": true,
                "results": [{
                    "referenceId": "ref2",
                    "errors": [{
                        "statusCode": "INVALID_EMAIL_ADDRESS",
                        "message": "Email: invalid email address: 123",
                        "fields": ["Email"]
                    }]
                }]
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let resp = sf
            .composite()
            .tree("Account", &json!({"records": []}))
            .await
            .unwrap();
        assert!(resp.has_errors);
        let result = &resp.results[0];
        assert!(!result.is_success());
        assert!(result.id.is_none());
        let errors = result.errors.as_ref().unwrap();
        assert_eq!(errors[0].status_code, "INVALID_EMAIL_ADDRESS");
        assert_eq!(errors[0].fields, vec!["Email".to_string()]);
    }

    #[tokio::test]
    async fn tree_percent_encodes_sobject_name() {
        // An sObject name carrying characters reserved in a URL path
        // segment ('/', space) must stay inside one segment, so it can't
        // inject extra segments into the composite tree URL.
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/services/data/v66.0/composite/tree/a%2Fb=c%20d"))
            .and(path_regex(r"^/services/data/v66\.0/composite/tree/[^/]+$"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "hasErrors": false,
                "results": []
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let resp = sf
            .composite()
            .tree("a/b=c d", &json!({"records": []}))
            .await
            .unwrap();
        assert!(!resp.has_errors);
    }

    #[tokio::test]
    async fn tree_top_level_400_surfaces_as_api_error() {
        // Malformed top-level body (e.g. invalid attributes) — the batch
        // endpoint itself returns 400, parsed as our standard Api error.
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/services/data/v66.0/composite/tree/Account"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!([{
                "message": "Invalid request: missing 'records'",
                "errorCode": "INVALID_REQUEST"
            }])))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let err = sf
            .composite()
            .tree("Account", &json!({}))
            .await
            .unwrap_err();
        match err {
            crate::CirrusError::Api { status, errors, .. } => {
                assert_eq!(status, 400);
                assert_eq!(errors[0].error_code, "INVALID_REQUEST");
            }
            other => panic!("expected Api error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn batch_top_level_400_surfaces_as_api_error() {
        // A top-level deserialization error (per docs: invalid method/url
        // in a sub-request) returns HTTP 400 from the batch endpoint
        // itself, *not* the per-subrequest path. Our normal Api error
        // surfacing applies.
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/services/data/v66.0/composite/batch"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!([{
                "message": "Invalid HTTP method: BOGUS",
                "errorCode": "JSON_PARSER_ERROR"
            }])))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let err = sf
            .composite()
            .batch(&json!({"batchRequests": [{"method": "BOGUS", "url": "v66.0/limits"}]}))
            .await
            .unwrap_err();
        match err {
            crate::CirrusError::Api { status, errors, .. } => {
                assert_eq!(status, 400);
                assert_eq!(errors[0].error_code, "JSON_PARSER_ERROR");
            }
            other => panic!("expected Api error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn composite_executes_chained_subrequests_and_returns_subresponses() {
        let server = MockServer::start().await;

        let request_body = json!({
            "compositeRequest": [
                {
                    "method": "POST",
                    "url": "/services/data/v66.0/sobjects/Account",
                    "referenceId": "NewAccount",
                    "body": {"Name": "Acme"}
                },
                {
                    "method": "POST",
                    "url": "/services/data/v66.0/sobjects/Contact",
                    "referenceId": "NewContact",
                    "body": {"AccountId": "@{NewAccount.id}", "LastName": "Doe"}
                }
            ]
        });

        Mock::given(method("POST"))
            .and(path("/services/data/v66.0/composite"))
            .and(header("authorization", "Bearer tok"))
            .and(body_json(request_body.clone()))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "compositeResponse": [
                    {
                        "body": {"id": "001xx", "success": true, "errors": []},
                        "httpHeaders": {"Location": "/services/data/v66.0/sobjects/Account/001xx"},
                        "httpStatusCode": 201,
                        "referenceId": "NewAccount"
                    },
                    {
                        "body": {"id": "003yy", "success": true, "errors": []},
                        "httpHeaders": {"Location": "/services/data/v66.0/sobjects/Contact/003yy"},
                        "httpStatusCode": 201,
                        "referenceId": "NewContact"
                    }
                ]
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let resp = sf.composite().execute(&request_body).await.unwrap();
        assert_eq!(resp.composite_response.len(), 2);
        assert!(resp.composite_response.iter().all(|s| s.is_success()));
        assert_eq!(resp.composite_response[0].reference_id, "NewAccount");
        assert_eq!(resp.composite_response[0].body["id"], "001xx");
        assert_eq!(
            resp.composite_response[0]
                .http_headers
                .get("Location")
                .and_then(|v| v.to_str().ok()),
            Some("/services/data/v66.0/sobjects/Account/001xx")
        );
    }

    #[tokio::test]
    async fn composite_typed_request_serializes_documented_shape() {
        // Construct via the typed CompositeRequest/CompositeSubrequest
        // structs and assert the wire body matches the documented example.
        let server = MockServer::start().await;

        let expected_body = json!({
            "compositeRequest": [{
                "method": "POST",
                "url": "/services/data/v66.0/sobjects/Account",
                "referenceId": "refAccount",
                "body": {"Name": "Sample Account"}
            }],
            "allOrNone": true
        });

        Mock::given(method("POST"))
            .and(path("/services/data/v66.0/composite"))
            .and(body_json(expected_body))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "compositeResponse": []
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let req = CompositeRequest {
            composite_request: vec![CompositeSubrequest {
                method: "POST".into(),
                url: "/services/data/v66.0/sobjects/Account".into(),
                reference_id: "refAccount".into(),
                body: Some(json!({"Name": "Sample Account"})),
                http_headers: None,
            }],
            all_or_none: Some(true),
            collate_subrequests: None,
        };
        sf.composite().execute(&req).await.unwrap();
    }

    #[tokio::test]
    async fn composite_typed_request_omits_optional_flags_when_none() {
        // None must serialize to absence — not null. Body match would fail
        // if either allOrNone or collateSubrequests appeared.
        let server = MockServer::start().await;

        let expected_body = json!({
            "compositeRequest": [{
                "method": "GET",
                "url": "/services/data/v66.0/limits",
                "referenceId": "L"
            }]
        });

        Mock::given(method("POST"))
            .and(path("/services/data/v66.0/composite"))
            .and(body_json(expected_body))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "compositeResponse": []
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let req = CompositeRequest {
            composite_request: vec![CompositeSubrequest {
                method: "GET".into(),
                url: "/services/data/v66.0/limits".into(),
                reference_id: "L".into(),
                body: None,
                http_headers: None,
            }],
            all_or_none: None,
            collate_subrequests: None,
        };
        sf.composite().execute(&req).await.unwrap();
    }

    #[tokio::test]
    async fn composite_subrequest_failure_surfaces_via_http_status_code() {
        // Sub-request failure: outer call returns 200, but a subresponse
        // carries httpStatusCode: 404 + an error array body. is_success
        // distinguishes per-subrequest outcomes.
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/services/data/v66.0/composite"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "compositeResponse": [
                    {
                        "body": {"id": "001xx", "success": true, "errors": []},
                        "httpHeaders": {},
                        "httpStatusCode": 201,
                        "referenceId": "OK"
                    },
                    {
                        "body": [{
                            "message": "The requested resource does not exist",
                            "errorCode": "NOT_FOUND"
                        }],
                        "httpHeaders": {},
                        "httpStatusCode": 404,
                        "referenceId": "Missing"
                    }
                ]
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let resp = sf
            .composite()
            .execute(&json!({"compositeRequest": []}))
            .await
            .unwrap();
        assert!(resp.composite_response[0].is_success());
        assert!(!resp.composite_response[1].is_success());
        assert_eq!(resp.composite_response[1].body[0]["errorCode"], "NOT_FOUND");
    }

    #[tokio::test]
    async fn composite_top_level_400_surfaces_as_api_error() {
        // Malformed top-level body (e.g. duplicate referenceId) — the
        // composite endpoint itself returns 400, parsed as our standard
        // Api error.
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/services/data/v66.0/composite"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!([{
                "message": "Duplicate referenceId: ref1",
                "errorCode": "INVALID_INPUT"
            }])))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let err = sf
            .composite()
            .execute(&json!({"compositeRequest": []}))
            .await
            .unwrap_err();
        match err {
            crate::CirrusError::Api { status, errors, .. } => {
                assert_eq!(status, 400);
                assert_eq!(errors[0].error_code, "INVALID_INPUT");
            }
            other => panic!("expected Api error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn sobjects_create_returns_per_record_results() {
        let server = MockServer::start().await;

        let request_body = json!({
            "allOrNone": false,
            "records": [
                {"attributes": {"type": "Account"}, "Name": "Acme"},
                {"attributes": {"type": "Contact"}, "LastName": "Doe"}
            ]
        });

        Mock::given(method("POST"))
            .and(path("/services/data/v66.0/composite/sobjects"))
            .and(header("authorization", "Bearer tok"))
            .and(body_json(request_body.clone()))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                {"id": "001xx0000000001", "success": true, "errors": []},
                {"id": "003yy0000000001", "success": true, "errors": []}
            ])))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let results = sf
            .composite()
            .sobjects()
            .create(&request_body)
            .await
            .unwrap();
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.success));
        assert_eq!(results[0].id.as_deref(), Some("001xx0000000001"));
        assert_eq!(results[1].id.as_deref(), Some("003yy0000000001"));
        assert!(results[0].created.is_none());
    }

    #[tokio::test]
    async fn sobjects_update_uses_patch_verb() {
        let server = MockServer::start().await;

        Mock::given(method("PATCH"))
            .and(path("/services/data/v66.0/composite/sobjects"))
            .and(body_json(json!({
                "allOrNone": true,
                "records": [
                    {"attributes": {"type": "Account"}, "id": "001xx", "Name": "Renamed"}
                ]
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                {"id": "001xx", "success": true, "errors": []}
            ])))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let results = sf
            .composite()
            .sobjects()
            .update(&json!({
                "allOrNone": true,
                "records": [
                    {"attributes": {"type": "Account"}, "id": "001xx", "Name": "Renamed"}
                ]
            }))
            .await
            .unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].success);
    }

    #[tokio::test]
    async fn sobjects_upsert_targets_external_id_path_and_returns_created_flag() {
        let server = MockServer::start().await;

        Mock::given(method("PATCH"))
            .and(path(
                "/services/data/v66.0/composite/sobjects/Account/External_Id__c",
            ))
            .and(body_json(json!({
                "allOrNone": false,
                "records": [
                    {"attributes": {"type": "Account"},
                     "External_Id__c": "EXT-1",
                     "Name": "Acme"},
                    {"attributes": {"type": "Account"},
                     "External_Id__c": "EXT-2",
                     "Name": "Existing"}
                ]
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                {"id": "001aa", "success": true, "errors": [], "created": true},
                {"id": "001bb", "success": true, "errors": [], "created": false}
            ])))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let results = sf
            .composite()
            .sobjects()
            .upsert(
                "Account",
                "External_Id__c",
                &json!({
                    "allOrNone": false,
                    "records": [
                        {"attributes": {"type": "Account"},
                         "External_Id__c": "EXT-1",
                         "Name": "Acme"},
                        {"attributes": {"type": "Account"},
                         "External_Id__c": "EXT-2",
                         "Name": "Existing"}
                    ]
                }),
            )
            .await
            .unwrap();
        assert_eq!(results[0].created, Some(true));
        assert_eq!(results[1].created, Some(false));
    }

    #[tokio::test]
    async fn sobjects_delete_passes_ids_and_all_or_none_query_params() {
        let server = MockServer::start().await;

        Mock::given(method("DELETE"))
            .and(path("/services/data/v66.0/composite/sobjects"))
            .and(wiremock::matchers::query_param("ids", "001xx,001yy"))
            .and(wiremock::matchers::query_param("allOrNone", "false"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                {"id": "001xx", "success": true, "errors": []},
                {"id": "001yy", "success": true, "errors": []}
            ])))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let results = sf
            .composite()
            .sobjects()
            .delete(&["001xx", "001yy"], false)
            .await
            .unwrap();
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.success));
    }

    #[tokio::test]
    async fn sobjects_retrieve_returns_record_array_aligned_with_ids() {
        let server = MockServer::start().await;

        // Salesforce surfaces missing records as `null` at the corresponding
        // index — preserving 1:1 alignment with the input ids.
        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/composite/sobjects/Account"))
            .and(wiremock::matchers::query_param(
                "ids",
                "001xx,missing,001yy",
            ))
            .and(wiremock::matchers::query_param("fields", "Id,Name"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                {"attributes": {"type": "Account"}, "Id": "001xx", "Name": "Acme"},
                null,
                {"attributes": {"type": "Account"}, "Id": "001yy", "Name": "Other"}
            ])))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let records = sf
            .composite()
            .sobjects()
            .retrieve("Account", &["001xx", "missing", "001yy"], &["Id", "Name"])
            .await
            .unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0]["Name"], "Acme");
        assert!(records[1].is_null());
        assert_eq!(records[2]["Name"], "Other");
    }

    #[tokio::test]
    async fn sobjects_retrieve_sends_literal_comma_separators() {
        // SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/resources_composite_sobjects_collections_retrieve.htm
        // The documented request separates ids and fields with literal
        // commas: `?ids=001xx000003DGb1AAG,...&fields=id,name`.
        // SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/errorcodes.htm
        // "414  The length of the URI exceeds the 16,384-byte limit." —
        // percent-encoding each separator as `%2C` triples its cost and
        // pushes a documented-size batch over that limit.
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/composite/sobjects/Account"))
            .and(|request: &wiremock::Request| {
                request.url.query()
                    == Some("ids=001xx000003DGb1AAG,001xx000003DGb0AAG&fields=id,name")
            })
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                {"attributes": {"type": "Account"}, "Id": "001xx000003DGb1AAG", "Name": "Acme"},
                {"attributes": {"type": "Account"}, "Id": "001xx000003DGb0AAG", "Name": "Global Media"}
            ])))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let records = sf
            .composite()
            .sobjects()
            .retrieve(
                "Account",
                &["001xx000003DGb1AAG", "001xx000003DGb0AAG"],
                &["id", "name"],
            )
            .await
            .unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["Name"], "Acme");
    }

    #[test]
    fn sobjects_retrieve_uri_stays_under_the_documented_800_id_ceiling() {
        // 800 18-character ids joined by literal commas is the batch size
        // Salesforce calls out as roughly the maximum; the resulting URI
        // has to fit the 16,384-byte limit that produces HTTP 414.
        let ids: Vec<String> = (0..800).map(|i| format!("001xx{i:013}")).collect();
        let query = format!("ids={}&fields=Id,Name", ids.join(","));
        assert_eq!(query.len(), 15_218);

        let percent_encoded_len = query.len() + ids.len().saturating_sub(1) * 2;
        assert!(percent_encoded_len > 16_384);
    }

    #[tokio::test]
    async fn sobjects_retrieve_typed_into_optional_records() {
        // Demonstrates the documented Vec<Option<T>> idiom for handling
        // null entries when missing records are possible.
        #[derive(serde::Deserialize)]
        struct Acct {
            #[serde(rename = "Id")]
            id: String,
        }

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/composite/sobjects/Account"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                {"attributes": {"type": "Account"}, "Id": "001xx"},
                null
            ])))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let records: Vec<Option<Acct>> = sf
            .composite()
            .sobjects()
            .retrieve_as("Account", &["001xx", "missing"], &["Id"])
            .await
            .unwrap();
        assert_eq!(records[0].as_ref().unwrap().id, "001xx");
        assert!(records[1].is_none());
    }

    #[tokio::test]
    async fn sobjects_retrieve_with_body_posts_ids_and_fields() {
        // POST /composite/sobjects/{sobject} with {ids, fields} body —
        // the high-cardinality (>800 ids) variant of retrieve.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/services/data/v66.0/composite/sobjects/Account"))
            .and(body_json(json!({
                "ids": ["001xx", "missing"],
                "fields": ["Id", "Name"]
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                {"attributes": {"type": "Account"}, "Id": "001xx", "Name": "Acme"},
                null
            ])))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let records = sf
            .composite()
            .sobjects()
            .retrieve_with_body("Account", &["001xx", "missing"], &["Id", "Name"])
            .await
            .unwrap();
        assert_eq!(records[0]["Id"], "001xx");
        assert!(records[1].is_null());
    }

    #[tokio::test]
    async fn sobjects_create_surfaces_per_record_failures_with_diverged_error_shape() {
        // The endpoint returns 200 with per-record success: false entries
        // carrying the {statusCode, message, fields} CompositeError shape.
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/services/data/v66.0/composite/sobjects"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                {"id": "001xx", "success": true, "errors": []},
                {"success": false, "errors": [{
                    "statusCode": "DUPLICATE_VALUE",
                    "message": "duplicate value found: External_Id__c duplicates value on record with id: 001aa",
                    "fields": []
                }]}
            ])))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let results = sf
            .composite()
            .sobjects()
            .create(&json!({"allOrNone": false, "records": []}))
            .await
            .unwrap();
        assert!(results[0].success);
        assert!(!results[1].success);
        assert!(results[1].id.is_none());
        assert_eq!(results[1].errors[0].status_code, "DUPLICATE_VALUE");
        assert!(results[1].errors[0].fields.is_empty());
    }
}
