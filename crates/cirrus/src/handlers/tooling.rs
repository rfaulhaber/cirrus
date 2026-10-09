//! Tooling API — `/services/data/{version}/tooling/...`.
//!
//! The Tooling API exposes Salesforce *metadata* (Apex classes, triggers,
//! custom fields, layouts, workflow rules, etc.) and developer-tooling
//! primitives (anonymous Apex execution, symbol tables, container-based
//! deployment) over the same REST shape as the regular data API. Almost
//! every resource you'd reach for in the regular REST API has a parallel
//! under `tooling/` that operates on the metadata equivalent.
//!
//! # Shape mirrors regular REST
//!
//! - [`describe_global`](ToolingHandler::describe_global) → `tooling/sobjects/`
//!   (returns the same [`DescribeGlobal`] envelope, populated with
//!   *Tooling-API* sObjects: `ApexClass`, `ApexTrigger`, `CustomField`,
//!   `MetadataContainer`, `ContainerAsyncRequest`, etc.)
//! - [`sobject(name)`](ToolingHandler::sobject) → per-Tooling-object handler
//!   with `describe`, `retrieve`, `retrieve_with_fields`, `create`,
//!   `update`, `delete`. Same envelopes ([`SObjectCreateResult`]) and same
//!   error array as regular REST.
//! - [`query`](ToolingHandler::query) → `tooling/query`. Returns the
//!   same [`QueryResult<R>`] envelope. Distinct endpoint from the
//!   regular `/query` because Tooling SOQL *only* sees Tooling-API
//!   objects — regular SOQL on the data tier doesn't surface metadata
//!   records, and vice versa. There is **no** `tooling/queryAll`; the
//!   Tooling REST resource list documents only `/query/`.
//! - [`search`](ToolingHandler::search) → `tooling/search`. Same
//!   [`SearchResult<R>`] envelope as the regular REST search.
//!   See [`reference_objects_sosl_limits`] for the per-object SOSL
//!   restrictions that apply on the Tooling tier.
//!
//! [`reference_objects_sosl_limits`]: https://developer.salesforce.com/docs/atlas.en-us.api_tooling.meta/api_tooling/reference_objects_sosl_limits.htm
//!
//! # Tooling-only: anonymous Apex execution
//!
//! [`execute_anonymous`](ToolingHandler::execute_anonymous) is the one
//! endpoint with no parallel in the regular REST API. It compiles and
//! executes an arbitrary Apex source string and returns
//! [`ExecuteAnonymousResult`] indicating whether the code compiled, ran,
//! and (on failure) where the error occurred.
//!
//! The Apex source is passed as a URL query parameter (`anonymousBody=...`)
//! on a GET request, not a JSON body on POST. This caps the practical size
//! of the supplied source — long Apex scripts may exceed URL-length limits
//! in proxies, gateways, or logging infrastructure even when the Salesforce
//! front-end accepts them. For large jobs, prefer creating an [`ApexClass`]
//! via [`sobject("ApexClass").create(...)`](ToolingSObjectHandler::create)
//! and invoking it through a runner, or use the [`MetadataContainer`] /
//! [`ContainerAsyncRequest`] flow.
//!
//! [`apex_log_body`](ToolingHandler::apex_log_body) fetches the debug log
//! of an `ApexLog` record, such as one an anonymous run produces, as raw
//! text, which a JSON verb cannot read.
//!
//! [`ApexClass`]: https://developer.salesforce.com/docs/atlas.en-us.api_tooling.meta/api_tooling/tooling_api_objects_apexclass.htm
//! [`MetadataContainer`]: https://developer.salesforce.com/docs/atlas.en-us.api_tooling.meta/api_tooling/tooling_api_objects_metadatacontainer.htm
//! [`ContainerAsyncRequest`]: https://developer.salesforce.com/docs/atlas.en-us.api_tooling.meta/api_tooling/tooling_api_objects_containerasyncrequest.htm
//!
//! # Errors
//!
//! Failures use the *standard* Salesforce error array
//! `[{message, errorCode}]` — same shape as regular REST, surfaced as
//! [`crate::CirrusError::Api`]. The Tooling API does **not** use the
//! diverged composite-error shape ([`crate::CompositeError`]).
//!
//! # What this handler doesn't expose
//!
//! - Upsert by external ID on Tooling-API metadata.
//! - `runTests` / `runTestsAsync`. Test runs go through
//!   `/services/data/{version}/tooling/runTestsAsynchronous/` and friends,
//!   reachable via the open-ended client escape hatch.

use crate::Cirrus;
use crate::error::{CirrusError, CirrusResult};
use crate::response::{
    CompositeResponse, DescribeGlobal, ExecuteAnonymousResult, QueryResult, SObjectCreateResult,
    SearchResult,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

impl Cirrus {
    /// Returns a handler for Tooling API resources rooted at
    /// `/services/data/{api_version}/tooling/`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use cirrus::{Cirrus, auth::StaticTokenAuth};
    /// # use std::sync::Arc;
    /// # async fn example() -> Result<(), cirrus::CirrusError> {
    /// # let auth = Arc::new(StaticTokenAuth::new("tok", "https://x.my.salesforce.com"));
    /// # let sf = Cirrus::builder().auth(auth).build()?;
    /// let result = sf.tooling().execute_anonymous("System.debug('hello');").await?;
    /// assert!(result.compiled && result.success);
    /// # Ok(())
    /// # }
    /// ```
    pub fn tooling(&self) -> ToolingHandler<'_> {
        ToolingHandler { client: self }
    }
}

/// Handler for Tooling API resources. Returned by [`Cirrus::tooling`].
#[derive(Debug, Clone, Copy)]
pub struct ToolingHandler<'a> {
    client: &'a Cirrus,
}

impl<'a> ToolingHandler<'a> {
    /// Describes every Tooling-API sObject visible to the authenticated
    /// user.
    ///
    /// Calls `GET /services/data/{api_version}/tooling/sobjects/`. The
    /// returned [`DescribeGlobal`] uses the same envelope as the regular
    /// REST describe-global call, but enumerates Tooling sObjects
    /// (`ApexClass`, `CustomField`, `MetadataContainer`, …) instead of
    /// data sObjects (`Account`, `Contact`, …).
    pub async fn describe_global(&self) -> CirrusResult<DescribeGlobal> {
        self.client.get("tooling/sobjects").await
    }

    /// Executes up to 25 chained Tooling subrequests in one call via
    /// `POST /services/data/{api_version}/tooling/composite`.
    ///
    /// Subrequest URLs must start with `/services/data/vXX.X/tooling`, and
    /// at most five of them may be query operations. The body is a
    /// [`CompositeRequest`](crate::CompositeRequest) or any `Serialize`
    /// value of the same shape; the response is the same
    /// [`CompositeResponse`] envelope the data-tier `/composite` returns.
    ///
    /// The data-tier endpoint documents only the sObject, Query, QueryAll
    /// and sObject Collections resources as subrequest targets, so a
    /// Tooling chain — `MetadataContainer`, `ApexClassMember`,
    /// `ContainerAsyncRequest` — belongs here, not in
    /// [`Cirrus::composite`].
    pub async fn composite<B>(&self, body: &B) -> CirrusResult<CompositeResponse>
    where
        B: Serialize + ?Sized,
    {
        self.client.post("tooling/composite", body).await
    }

    /// Returns a handler scoped to a single Tooling-API sObject by API
    /// name (e.g. `"ApexClass"`, `"CustomField"`,
    /// `"MetadataContainer"`).
    pub fn sobject(&self, name: &'a str) -> ToolingSObjectHandler<'a> {
        ToolingSObjectHandler {
            client: self.client,
            name,
        }
    }

    /// Runs a Tooling SOQL query.
    ///
    /// Calls `GET /services/data/{api_version}/tooling/query?q={soql}`.
    /// Tooling SOQL targets the metadata tier — regular sObjects
    /// (`Account`, `Contact`) are *not* visible here; reach for them via
    /// [`Cirrus::query`] instead. The escaping and request-size notes on
    /// that method apply here too: a value interpolated into the
    /// statement goes through [`soql::quote`](crate::soql::quote) first,
    /// and the encoded statement has to fit the 16,384-byte URI cap.
    pub async fn query(&self, soql: &str) -> CirrusResult<QueryResult<Value>> {
        self.query_as(soql).await
    }

    /// Typed variant of [`query`](Self::query) — records deserialize as
    /// `R`.
    pub async fn query_as<R: DeserializeOwned>(&self, soql: &str) -> CirrusResult<QueryResult<R>> {
        let query = [("q", soql)];
        self.client.get_with_query("tooling/query", &query).await
    }

    /// Streams Tooling-API query records lazily, walking
    /// `nextRecordsUrl` locators across pages.
    ///
    /// See [`pagination`](crate::pagination) for the full contract.
    /// Tooling-issued `nextRecordsUrl` locators carry the `tooling/`
    /// path prefix in their URL; the same `query_more` machinery
    /// follows them transparently.
    pub fn query_stream(&self, soql: &str) -> crate::pagination::Records<Value> {
        self.query_stream_as(soql)
    }

    /// Typed variant of [`query_stream`](Self::query_stream).
    pub fn query_stream_as<R: DeserializeOwned + Send + Unpin + 'static>(
        &self,
        soql: &str,
    ) -> crate::pagination::Records<R> {
        let client = self.client.clone();
        let soql = soql.to_string();
        let initial = Box::pin(async move {
            let query = [("q", soql.as_str())];
            client
                .get_with_query::<QueryResult<R>, _>("tooling/query", &query)
                .await
        });
        crate::pagination::Records::new(
            self.client.clone(),
            initial,
            crate::handlers::query::QueryOptions::default(),
        )
    }

    /// Runs a Tooling SOSL search.
    ///
    /// Calls `GET /services/data/{api_version}/tooling/search?q={sosl}`.
    /// Returns the same [`SearchResult<R>`] envelope as the regular
    /// REST search; per-object SOSL restrictions on the Tooling tier
    /// are listed in the [SOSL Operation Limitations] doc page. As with
    /// [`Cirrus::search`], a term from outside the program goes through
    /// [`sosl::escape_term`](crate::sosl::escape_term) first.
    ///
    /// [SOSL Operation Limitations]: https://developer.salesforce.com/docs/atlas.en-us.api_tooling.meta/api_tooling/reference_objects_sosl_limits.htm
    pub async fn search(&self, sosl: &str) -> CirrusResult<SearchResult<Value>> {
        self.search_as(sosl).await
    }

    /// Typed variant of [`search`](Self::search) — hits deserialize as
    /// `R`.
    pub async fn search_as<R: DeserializeOwned>(
        &self,
        sosl: &str,
    ) -> CirrusResult<SearchResult<R>> {
        let query = [("q", sosl)];
        self.client.get_with_query("tooling/search", &query).await
    }

    /// Compiles and executes anonymous Apex source, returning
    /// [`ExecuteAnonymousResult`].
    ///
    /// Calls
    /// `GET /services/data/{api_version}/tooling/executeAnonymous?anonymousBody={apex}`.
    /// The Apex source is percent-encoded into the query string by
    /// reqwest — see the module-level docs for the URL-length caveat
    /// that applies to long scripts.
    ///
    /// The returned envelope encodes three outcomes (success, compile
    /// error, runtime error); see [`ExecuteAnonymousResult`] for the
    /// field-by-field guide. A non-2xx response (auth, permissions,
    /// malformed request) still surfaces as
    /// [`crate::CirrusError::Api`] — `ExecuteAnonymousResult` only
    /// describes outcomes for requests that Salesforce was *able* to
    /// dispatch to the Apex runtime.
    ///
    /// The resource is a GET, but it executes the script, so a lost
    /// response is never replayed by the retry policy: the Apex may
    /// already have committed its DML, fired callouts or sent email.
    /// A transient failure surfaces to the caller, who is the only one
    /// that can tell whether re-running the script is safe.
    pub async fn execute_anonymous(&self, apex: &str) -> CirrusResult<ExecuteAnonymousResult> {
        let query = [("anonymousBody", apex)];
        self.client
            .get_with_query_no_replay("tooling/executeAnonymous", &query)
            .await
    }

    /// Fetches the raw debug log of an `ApexLog` record as text.
    ///
    /// Calls
    /// `GET /services/data/{api_version}/tooling/sobjects/ApexLog/{id}/Body`
    /// with `Accept: */*`. The [Tooling REST Resources] page lists this
    /// resource as "Retrieves a raw debug log by ID. Available in API
    /// version 28.0 and later."
    ///
    /// A typical use runs [`execute_anonymous`](Self::execute_anonymous),
    /// queries `ApexLog` for the newest record's `Id`, then fetches its
    /// body. [`sobject("ApexLog").retrieve(id)`](ToolingSObjectHandler::retrieve)
    /// returns the log's metadata record (operation, start time, length);
    /// this returns the log text itself, which a JSON verb such as
    /// [`Cirrus::get`] cannot read because the body is plain text.
    ///
    /// The request runs inside the request loop, so the retry policy, the
    /// 401 session refresh and `Sforce-Limit-Info` capture apply, and the
    /// body is bounded by
    /// [`CirrusBuilder::max_response_size`](crate::CirrusBuilder::max_response_size).
    /// A body that is not valid UTF-8 is a
    /// [`CirrusError::InvalidResponse`] that names the byte offset of the
    /// first invalid byte and quotes none of the log, since a debug log
    /// can carry record data.
    ///
    /// [Tooling REST Resources]: https://developer.salesforce.com/docs/atlas.en-us.api_tooling.meta/api_tooling/intro_rest_resources.htm
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use cirrus::{Cirrus, auth::StaticTokenAuth};
    /// # use std::sync::Arc;
    /// # async fn example() -> Result<(), cirrus::CirrusError> {
    /// # let auth = Arc::new(StaticTokenAuth::new("tok", "https://x.my.salesforce.com"));
    /// # let sf = Cirrus::builder().auth(auth).build()?;
    /// sf.tooling().execute_anonymous("System.debug('hello');").await?;
    /// let newest = sf
    ///     .tooling()
    ///     .query("SELECT Id FROM ApexLog ORDER BY StartTime DESC LIMIT 1")
    ///     .await?;
    /// if let Some(id) = newest.records.first().and_then(|log| log["Id"].as_str()) {
    ///     let log = sf.tooling().apex_log_body(id).await?;
    ///     println!("{log}");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn apex_log_body(&self, id: &str) -> CirrusResult<String> {
        // The Tooling REST Resources page prints a trailing slash on every
        // resource (`/sobjects/`, `/sobjects/{name}/describe/`,
        // `/sobjects/{name}/{id}/`) and this crate sends none for any of
        // them, so the log body follows suit.
        let url = self
            .client
            .versioned_url(&["tooling", "sobjects", "ApexLog", id, "Body"])?;
        let (_headers, bytes) = self
            .client
            .fetch_raw(reqwest::Method::GET, &url, "*/*", None)
            .await?;
        String::from_utf8(Vec::from(bytes)).map_err(|err| {
            CirrusError::InvalidResponse(format!(
                "ApexLog Body is not valid UTF-8 (valid up to byte {})",
                err.utf8_error().valid_up_to()
            ))
        })
    }
}

/// Handler scoped to a single Tooling-API sObject. Returned by
/// [`ToolingHandler::sobject`].
///
/// Mirrors the per-object methods of [`crate::handlers::sobjects::SObjectHandler`]
/// but rooted under `tooling/sobjects/` instead of `sobjects/`.
#[derive(Debug, Clone, Copy)]
pub struct ToolingSObjectHandler<'a> {
    client: &'a Cirrus,
    name: &'a str,
}

impl<'a> ToolingSObjectHandler<'a> {
    /// API name of the targeted Tooling-API sObject.
    pub fn name(&self) -> &'a str {
        self.name
    }

    /// Describes the Tooling object's metadata (fields, relationships,
    /// etc.). Returns the raw JSON.
    ///
    /// Calls
    /// `GET /services/data/{api_version}/tooling/sobjects/{name}/describe`.
    pub async fn describe(&self) -> CirrusResult<Value> {
        self.describe_as().await
    }

    /// Typed variant of [`describe`](Self::describe).
    pub async fn describe_as<R: DeserializeOwned>(&self) -> CirrusResult<R> {
        // Percent-encode each segment so a reserved character in the object
        // name can't alter the path — mirrors the regular SObjectHandler.
        let url = self
            .client
            .versioned_url(&["tooling", "sobjects", self.name, "describe"])?;
        self.client
            .send_at(reqwest::Method::GET, &url, None::<&()>, None::<&()>)
            .await
    }

    /// Retrieves a Tooling-API record by ID, returning every field.
    ///
    /// Calls
    /// `GET /services/data/{api_version}/tooling/sobjects/{name}/{id}`.
    pub async fn retrieve(&self, id: &str) -> CirrusResult<Value> {
        self.retrieve_as(id).await
    }

    /// Typed variant of [`retrieve`](Self::retrieve).
    pub async fn retrieve_as<R: DeserializeOwned>(&self, id: &str) -> CirrusResult<R> {
        let url = self
            .client
            .versioned_url(&["tooling", "sobjects", self.name, id])?;
        self.client
            .send_at(reqwest::Method::GET, &url, None::<&()>, None::<&()>)
            .await
    }

    /// Retrieves selected fields of a Tooling-API record by ID.
    ///
    /// Calls
    /// `GET /tooling/sobjects/{name}/{id}?fields=Field1,Field2,...`.
    /// `fields` accepts `&[&str]`, `&[String]` or a `&Vec<String>`.
    pub async fn retrieve_with_fields(
        &self,
        id: &str,
        fields: &[impl AsRef<str>],
    ) -> CirrusResult<Value> {
        self.retrieve_with_fields_as(id, fields).await
    }

    /// Typed variant of
    /// [`retrieve_with_fields`](Self::retrieve_with_fields); `fields`
    /// accepts the same list types.
    pub async fn retrieve_with_fields_as<R: DeserializeOwned>(
        &self,
        id: &str,
        fields: &[impl AsRef<str>],
    ) -> CirrusResult<R> {
        let url = self
            .client
            .versioned_url(&["tooling", "sobjects", self.name, id])?;
        let joined = fields
            .iter()
            .map(AsRef::as_ref)
            .collect::<Vec<&str>>()
            .join(",");
        let query = [("fields", joined.as_str())];
        self.client
            .send_at(reqwest::Method::GET, &url, Some(&query), None::<&()>)
            .await
    }

    /// Creates a new Tooling-API record.
    ///
    /// Calls
    /// `POST /services/data/{api_version}/tooling/sobjects/{name}/`.
    /// Returns the standard [`SObjectCreateResult`].
    pub async fn create<B>(&self, body: &B) -> CirrusResult<SObjectCreateResult>
    where
        B: Serialize + ?Sized,
    {
        let url = self
            .client
            .versioned_url(&["tooling", "sobjects", self.name])?;
        self.client
            .send_at(reqwest::Method::POST, &url, None::<&()>, Some(body))
            .await
    }

    /// Updates a Tooling-API record by ID.
    ///
    /// Calls
    /// `PATCH /services/data/{api_version}/tooling/sobjects/{name}/{id}`.
    /// Salesforce returns 204 No Content on success.
    pub async fn update<B>(&self, id: &str, body: &B) -> CirrusResult<()>
    where
        B: Serialize + ?Sized,
    {
        let url = self
            .client
            .versioned_url(&["tooling", "sobjects", self.name, id])?;
        self.client
            .send_at(reqwest::Method::PATCH, &url, None::<&()>, Some(body))
            .await
    }

    /// Deletes a Tooling-API record by ID.
    ///
    /// Calls
    /// `DELETE /services/data/{api_version}/tooling/sobjects/{name}/{id}`.
    /// Salesforce returns 204 No Content on success.
    ///
    /// A DELETE is replayed after a transient failure (a 5xx from an
    /// intermediary, a lost response), so when the first attempt had
    /// already committed the replay finds the record gone and this
    /// returns a 404 [`crate::CirrusError::Api`] for a delete that
    /// succeeded. Treat that 404 as "already deleted" in cleanup code,
    /// or disable replays with [`crate::RetryPolicy`].
    pub async fn delete(&self, id: &str) -> CirrusResult<()> {
        let url = self
            .client
            .versioned_url(&["tooling", "sobjects", self.name, id])?;
        self.client
            .send_at(reqwest::Method::DELETE, &url, None::<&()>, None::<&()>)
            .await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::auth::StaticTokenAuth;
    use serde_json::json;
    use std::sync::Arc;
    use wiremock::matchers::{body_json, header, method, path, path_regex, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn fixture(uri: String) -> Cirrus {
        let auth = Arc::new(StaticTokenAuth::new("tok", uri));
        Cirrus::builder().auth(auth).build().unwrap()
    }

    #[tokio::test]
    async fn composite_posts_to_the_tooling_composite_resource() {
        // SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_tooling.meta/api_tooling/tooling_responses_composite_composite.htm
        // "Composite Subrequest Result" JSON example, verbatim, as the
        // only entry of the documented `compositeResponse` envelope.
        let server = MockServer::start().await;
        let request = json!({
            "allOrNone": true,
            "compositeRequest": [{
                "method": "POST",
                "url": "/services/data/v66.0/tooling/sobjects/apexclassmember/",
                "referenceId": "apexclassmember_reference_id",
                "body": {
                    "MetadataContainerId": "1dcxx",
                    "ContentEntityId": "01pxx",
                    "Body": "public class Foo {}"
                }
            }]
        });

        Mock::given(method("POST"))
            .and(path("/services/data/v66.0/tooling/composite"))
            .and(body_json(request.clone()))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "compositeResponse": [{
                    "body": {"id": "001R00000033I6AIAU", "success": true, "errors": []},
                    "httpHeaders": {
                        "Location": "/services/data/v40.0/tooling/sobjects/apexclassmember/001R00000033I6AIAU"
                    },
                    "httpStatusCode": 201,
                    "referenceId": "apexclassmember_reference_id"
                }]
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let resp = sf.tooling().composite(&request).await.unwrap();
        assert_eq!(resp.composite_response.len(), 1);
        let created = &resp.composite_response[0];
        assert_eq!(created.http_status_code, 201);
        assert!(created.is_success());
        assert_eq!(created.reference_id, "apexclassmember_reference_id");
        assert_eq!(created.body["id"], "001R00000033I6AIAU");
    }

    #[tokio::test]
    async fn describe_global_targets_tooling_sobjects_root() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/tooling/sobjects"))
            .and(header("authorization", "Bearer tok"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "encoding": "UTF-8",
                "maxBatchSize": 200,
                "sobjects": [{
                    "activateable": false, "custom": false, "customSetting": false,
                    "createable": true, "deletable": true, "deprecatedAndHidden": false,
                    "feedEnabled": false, "keyPrefix": "01p",
                    "label": "Apex Class", "labelPlural": "Apex Classes",
                    "layoutable": false, "mergeable": false, "mruEnabled": false,
                    "name": "ApexClass", "queryable": true, "replicateable": false,
                    "retrieveable": true, "searchable": false, "triggerable": false,
                    "undeletable": false, "updateable": true,
                    "urls": {
                        "sobject": "/services/data/v66.0/tooling/sobjects/ApexClass",
                        "describe": "/services/data/v66.0/tooling/sobjects/ApexClass/describe",
                        "rowTemplate": "/services/data/v66.0/tooling/sobjects/ApexClass/{ID}"
                    }
                }]
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let dg = sf.tooling().describe_global().await.unwrap();
        assert_eq!(dg.sobjects.len(), 1);
        assert_eq!(dg.sobjects[0].name, "ApexClass");
    }

    #[tokio::test]
    async fn sobject_describe_targets_tooling_path() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path(
                "/services/data/v66.0/tooling/sobjects/ApexClass/describe",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "name": "ApexClass",
                "label": "Apex Class",
                "fields": []
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let v = sf.tooling().sobject("ApexClass").describe().await.unwrap();
        assert_eq!(v["name"], "ApexClass");
    }

    #[tokio::test]
    async fn sobject_retrieve_returns_record() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path(
                "/services/data/v66.0/tooling/sobjects/ApexClass/01p000000000001",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "Id": "01p000000000001",
                "Name": "MyClass",
                "Body": "public class MyClass {}"
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let v = sf
            .tooling()
            .sobject("ApexClass")
            .retrieve("01p000000000001")
            .await
            .unwrap();
        assert_eq!(v["Name"], "MyClass");
    }

    #[tokio::test]
    async fn sobject_retrieve_with_fields_passes_csv_query_param() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path(
                "/services/data/v66.0/tooling/sobjects/ApexClass/01p000000000001",
            ))
            .and(query_param("fields", "Id,Name,Body"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "Id": "01p000000000001",
                "Name": "MyClass",
                "Body": "public class MyClass {}"
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let v = sf
            .tooling()
            .sobject("ApexClass")
            .retrieve_with_fields("01p000000000001", &["Id", "Name", "Body"])
            .await
            .unwrap();
        assert_eq!(v["Name"], "MyClass");
    }

    #[tokio::test]
    async fn sobject_retrieve_with_fields_accepts_owned_field_lists() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path(
                "/services/data/v66.0/tooling/sobjects/ApexClass/01p000000000001",
            ))
            .and(query_param("fields", "Id,Name,Body"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "Id": "01p000000000001",
                "Name": "MyClass",
                "Body": "public class MyClass {}"
            })))
            .expect(2)
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let class = sf.tooling().sobject("ApexClass");
        let fields: Vec<String> = vec!["Id".into(), "Name".into(), "Body".into()];
        class
            .retrieve_with_fields("01p000000000001", &["Id", "Name", "Body"])
            .await
            .unwrap();
        let v = class
            .retrieve_with_fields_as::<serde_json::Value>("01p000000000001", &fields)
            .await
            .unwrap();
        assert_eq!(v["Name"], "MyClass");

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests[1].url, requests[0].url);
    }

    #[tokio::test]
    async fn sobject_create_posts_and_returns_create_result() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/services/data/v66.0/tooling/sobjects/ApexClass"))
            .and(body_json(json!({
                "Name": "Hello",
                "Body": "public class Hello {}"
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "id": "01p000000000002",
                "success": true,
                "errors": []
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let res = sf
            .tooling()
            .sobject("ApexClass")
            .create(&json!({
                "Name": "Hello",
                "Body": "public class Hello {}"
            }))
            .await
            .unwrap();
        assert!(res.success);
        assert_eq!(res.id, "01p000000000002");
    }

    #[tokio::test]
    async fn sobject_update_patches_and_returns_unit() {
        let server = MockServer::start().await;

        Mock::given(method("PATCH"))
            .and(path(
                "/services/data/v66.0/tooling/sobjects/ApexClass/01p000000000001",
            ))
            .and(body_json(
                json!({"Body": "public class MyClass { /* v2 */ }"}),
            ))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        sf.tooling()
            .sobject("ApexClass")
            .update(
                "01p000000000001",
                &json!({"Body": "public class MyClass { /* v2 */ }"}),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn sobject_delete_returns_unit_on_204() {
        let server = MockServer::start().await;

        Mock::given(method("DELETE"))
            .and(path(
                "/services/data/v66.0/tooling/sobjects/ApexClass/01p000000000001",
            ))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        sf.tooling()
            .sobject("ApexClass")
            .delete("01p000000000001")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn sobject_retrieve_percent_encodes_record_id() {
        // A record ID carrying characters reserved in a URL path segment
        // ('/', '=', space) must be percent-encoded so it can't alter the
        // path structure — same contract as the regular SObjectHandler.
        let server = MockServer::start().await;

        // wiremock matches on `Url::path()`, which is percent-encoded, so
        // the exact path pins the encoding and the `[^/]+` anchor fails if
        // the id is ever split into two segments.
        Mock::given(method("GET"))
            .and(path(
                "/services/data/v66.0/tooling/sobjects/ApexClass/a%2Fb=c%20d",
            ))
            .and(path_regex(
                r"^/services/data/v66\.0/tooling/sobjects/ApexClass/[^/]+$",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"Id": "ok"})))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let v = sf
            .tooling()
            .sobject("ApexClass")
            .retrieve("a/b=c d")
            .await
            .unwrap();
        assert_eq!(v["Id"], "ok");
    }

    #[tokio::test]
    async fn query_targets_tooling_query_endpoint() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/tooling/query"))
            .and(query_param("q", "SELECT Id, Name FROM ApexClass"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "totalSize": 1,
                "done": true,
                "records": [
                    {"attributes": {"type": "ApexClass"}, "Id": "01p000000000001", "Name": "MyClass"}
                ]
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let qr = sf
            .tooling()
            .query("SELECT Id, Name FROM ApexClass")
            .await
            .unwrap();
        assert_eq!(qr.total_size, 1);
        assert_eq!(qr.records[0]["Name"], "MyClass");
    }

    #[tokio::test]
    async fn query_typed_records_into_caller_struct() {
        #[derive(serde::Deserialize)]
        struct Cls {
            #[serde(rename = "Name")]
            name: String,
        }

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/tooling/query"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "totalSize": 1,
                "done": true,
                "records": [
                    {"attributes": {"type": "ApexClass"}, "Name": "MyClass"}
                ]
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let qr = sf
            .tooling()
            .query_as::<Cls>("SELECT Name FROM ApexClass LIMIT 1")
            .await
            .unwrap();
        assert_eq!(qr.records[0].name, "MyClass");
    }

    #[tokio::test]
    async fn search_targets_tooling_search_endpoint() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/tooling/search"))
            .and(query_param(
                "q",
                "FIND {MyClass} IN ALL FIELDS RETURNING ApexClass(Id, Name)",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "searchRecords": [
                    {"attributes": {"type": "ApexClass"}, "Id": "01p000000000001", "Name": "MyClass"}
                ]
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let sr = sf
            .tooling()
            .search("FIND {MyClass} IN ALL FIELDS RETURNING ApexClass(Id, Name)")
            .await
            .unwrap();
        assert_eq!(sr.search_records.len(), 1);
        assert_eq!(sr.search_records[0]["Name"], "MyClass");
    }

    #[tokio::test]
    async fn search_typed_records_into_caller_struct() {
        #[derive(serde::Deserialize)]
        struct ClsHit {
            #[serde(rename = "Id")]
            id: String,
        }

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/tooling/search"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "searchRecords": [
                    {"attributes": {"type": "ApexClass"}, "Id": "01p000000000001"}
                ]
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let sr = sf
            .tooling()
            .search_as::<ClsHit>("FIND {anything} RETURNING ApexClass(Id)")
            .await
            .unwrap();
        assert_eq!(sr.search_records[0].id, "01p000000000001");
    }

    #[tokio::test]
    async fn execute_anonymous_success_path() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/tooling/executeAnonymous"))
            .and(query_param("anonymousBody", "System.debug('hello world');"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "compiled": true,
                "compileProblem": null,
                "success": true,
                "line": -1,
                "column": -1,
                "exceptionMessage": null,
                "exceptionStackTrace": null
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let res = sf
            .tooling()
            .execute_anonymous("System.debug('hello world');")
            .await
            .unwrap();
        assert!(res.compiled);
        assert!(res.success);
        assert_eq!(res.line, -1);
        assert_eq!(res.column, -1);
        assert!(res.compile_problem.is_none());
        assert!(res.exception_message.is_none());
    }

    #[tokio::test]
    async fn execute_anonymous_is_not_replayed_after_a_transient_5xx() {
        // SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_tooling.meta/api_tooling/intro_rest_resources.htm
        // "/executeAnonymous/?anonymousBody= <url encoded body> —
        // Supported methods: GET — Executes Apex code anonymously."
        // The script may already have committed its DML when the 503
        // arrives, so the default policy's GET retry must not apply.
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/tooling/executeAnonymous"))
            .respond_with(ResponseTemplate::new(503))
            .expect(1)
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let err = sf
            .tooling()
            .execute_anonymous("insert new Account(Name='Acme');")
            .await
            .unwrap_err();
        assert!(matches!(err, crate::CirrusError::Api { status: 503, .. }));
    }

    #[tokio::test]
    async fn execute_anonymous_compile_error_populates_compile_problem() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/tooling/executeAnonymous"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "compiled": false,
                "compileProblem": "Variable does not exist: foo",
                "success": false,
                "line": 1,
                "column": 5,
                "exceptionMessage": null,
                "exceptionStackTrace": null
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let res = sf.tooling().execute_anonymous("foo.bar();").await.unwrap();
        assert!(!res.compiled);
        assert!(!res.success);
        assert_eq!(
            res.compile_problem.as_deref(),
            Some("Variable does not exist: foo"),
        );
        assert_eq!(res.line, 1);
        assert_eq!(res.column, 5);
    }

    #[tokio::test]
    async fn execute_anonymous_runtime_error_populates_exception_fields() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/tooling/executeAnonymous"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "compiled": true,
                "compileProblem": null,
                "success": false,
                "line": 2,
                "column": 1,
                "exceptionMessage": "System.NullPointerException: Attempt to de-reference a null object",
                "exceptionStackTrace": "AnonymousBlock: line 2, column 1"
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let res = sf
            .tooling()
            .execute_anonymous("Account a; a.Name = 'x';")
            .await
            .unwrap();
        assert!(res.compiled);
        assert!(!res.success);
        assert!(
            res.exception_message
                .as_deref()
                .unwrap_or_default()
                .contains("NullPointerException")
        );
        assert!(res.exception_stack_trace.is_some());
    }

    #[tokio::test]
    async fn errors_use_standard_salesforce_error_array() {
        // Confirm the Tooling API uses the *standard* errorCode/message
        // shape — not the diverged `statusCode` shape used by the
        // composite family.
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/tooling/query"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!([{
                "message": "unexpected token: SELECTT",
                "errorCode": "MALFORMED_QUERY"
            }])))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let err = sf
            .tooling()
            .query("SELECTT Id FROM ApexClass")
            .await
            .unwrap_err();
        match err {
            crate::CirrusError::Api { status, errors, .. } => {
                assert_eq!(status, 400);
                assert_eq!(errors[0].error_code, "MALFORMED_QUERY");
            }
            other => panic!("expected Api error, got {other:?}"),
        }
    }

    /// The Tooling query sends `q` through the same encoder as the data
    /// query: a `+`, `&`, `%` or `#` in the statement is percent-encoded
    /// rather than read as query-string syntax.
    #[tokio::test]
    async fn tooling_query_percent_encodes_reserved_characters_in_q() {
        const SOQL: &str = "SELECT Id FROM ApexClass WHERE Name = 'A&B' AND Body LIKE '%+1#%'";
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/tooling/query"))
            .and(query_param("q", SOQL))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "totalSize": 0,
                "done": true,
                "records": []
            })))
            .expect(1)
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        sf.tooling().query(SOQL).await.unwrap();

        let requests = server.received_requests().await.unwrap();
        let raw = requests[0].url.query().unwrap();
        assert!(raw.contains("A%26B"), "`&` must be encoded: {raw}");
        assert!(
            raw.contains("%25%2B1%23%25"),
            "`%`, `+` and `#` must be encoded: {raw}"
        );
    }

    #[tokio::test]
    async fn apex_log_body_returns_the_log_text() {
        // SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_tooling.meta/api_tooling/intro_rest_resources.htm
        // "/sobjects/ApexLog/id/Body/ — Supported methods: GET. Retrieves
        // a raw debug log by ID."
        //
        // Wire-shape provenance: no page publishes an example body or
        // response headers for this resource, so the `text/plain` content
        // type and the two log lines are illustrative. The page prints a
        // trailing slash on every resource, this one included; the
        // exact-path matcher pins the crate's slash-less form.
        const LOG: &str = "66.0 APEX_CODE,DEBUG\n10:15:02.1 (1234)|USER_DEBUG|[1]|DEBUG|hello\n";
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/services/data/v66.0/tooling/sobjects/ApexLog/07L5f00000ABCDEFGH/Body",
            ))
            .and(header("accept", "*/*"))
            .and(header("authorization", "Bearer tok"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/plain")
                    .set_body_string(LOG),
            )
            .expect(1)
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let log = sf
            .tooling()
            .apex_log_body("07L5f00000ABCDEFGH")
            .await
            .unwrap();
        assert_eq!(log, LOG);
    }

    #[tokio::test]
    async fn apex_log_body_reports_invalid_utf8_without_echoing_the_log() {
        // Wire-shape provenance: the page publishes no body for this
        // resource; the bytes are a deliberately malformed log. A debug
        // log can carry record data, so the error names the resource and
        // the offset of the first bad byte and quotes none of the body,
        // not even the valid prefix.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/services/data/v66.0/tooling/sobjects/ApexLog/07L5f00000ABCDEFGH/Body",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/plain")
                    .set_body_bytes(&b"SECRET\xff\xfe"[..]),
            )
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let err = sf
            .tooling()
            .apex_log_body("07L5f00000ABCDEFGH")
            .await
            .unwrap_err();
        match err {
            crate::CirrusError::InvalidResponse(message) => {
                assert!(message.contains("ApexLog"), "{message}");
                assert!(message.contains("byte 6"), "{message}");
                assert!(!message.contains("SECRET"), "{message}");
                assert!(!message.contains("255"), "{message}");
            }
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn apex_log_body_surfaces_the_error_array_on_404() {
        // SOURCE: https://developer.salesforce.com/docs/platform/api-rest/guide/errorcodes.html
        // The "Resource doesn't exist" body, `[{"message": "The requested
        // resource does not exist", "errorCode": "NOT_FOUND"}]`, under a
        // 404, which the status table describes as "The requested resource
        // couldn't be found." The endpoint's own page prints no error body.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/services/data/v66.0/tooling/sobjects/ApexLog/07L5f00000ABCDEFGH/Body",
            ))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!([{
                "message": "The requested resource does not exist",
                "errorCode": "NOT_FOUND"
            }])))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let err = sf
            .tooling()
            .apex_log_body("07L5f00000ABCDEFGH")
            .await
            .unwrap_err();
        match err {
            crate::CirrusError::Api { status, errors, .. } => {
                assert_eq!(status, 404);
                assert_eq!(errors[0].error_code, "NOT_FOUND");
            }
            other => panic!("expected Api error, got {other:?}"),
        }
    }
}
