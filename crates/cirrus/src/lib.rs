//! # Cirrus SDK
//!
//! An ergonomic Rust HTTP client for the Salesforce REST API.
//!
//! Cirrus provides a type-safe, async interface for interacting with
//! Salesforce while leaving response shapes entirely up to the caller —
//! no hard-coded sObject types like `Account` or `Contact`.
//!
//! ## Design principles
//!
//! - **No user-facing types.** The SDK never models org-specific data. Every
//!   handler that returns records is generic over a caller-supplied type, and
//!   defaults to [`serde_json::Value`] when none is specified.
//! - **Hard-coded platform types only.** Schema-independent envelopes
//!   ([`response::QueryResult`], [`response::SObjectCreateResult`],
//!   [`response::ApiVersion`], the Salesforce error array) are concrete,
//!   because their shape is part of the platform contract.
//! - **Auth is pluggable.** Any [`auth::AuthSession`] implementation works;
//!   handlers don't know which OAuth flow produced the token.
//! - **No legacy surface.** Anything Salesforce labels deprecated or legacy
//!   is intentionally not supported.
//!
//! ## Quick start
//!
//! ```no_run
//! use cirrus::{Cirrus, auth::StaticTokenAuth};
//! use std::sync::Arc;
//!
//! # async fn example() -> Result<(), cirrus::CirrusError> {
//! let auth = Arc::new(StaticTokenAuth::new(
//!     "00D...!AQ...",
//!     "https://my-org.my.salesforce.com",
//! ));
//!
//! let sf = Cirrus::builder()
//!     .auth(auth)
//!     .build()?;
//!
//! let versions = sf.versions().await?;
//! # let _ = versions;
//! # Ok(())
//! # }
//! ```

mod error;
pub mod handlers;
pub mod pagination;
mod response;
pub mod retry;

/// Re-export of the [`cirrus_auth`] crate as `cirrus::auth`.
///
/// All OAuth flow implementations live in the standalone `cirrus-auth`
/// crate so that other Cirrus subcrates (e.g. `cirrus-metadata`) can
/// depend on them without pulling in the REST client. Users of `cirrus`
/// don't need an explicit `cirrus-auth` dependency — this re-export
/// keeps `cirrus::auth::{StaticTokenAuth, JwtAuth, ...}` working
/// transparently.
pub use cirrus_auth as auth;

/// Re-export of [`reqwest`].
///
/// Several public APIs accept or return `reqwest` types
/// ([`Cirrus::request_builder`], [`Cirrus::execute`],
/// [`Cirrus::http_client`], [`CirrusBuilder::http_client`]). Using this
/// re-export instead of a separate `reqwest` dependency keeps the
/// caller's `reqwest` version aligned with the SDK's.
pub use reqwest;

pub use auth::{AuthError, AuthSession, SharedAuth};
pub use bytes::Bytes;
pub use error::{CirrusError, CirrusResult, SalesforceError};
pub use handlers::bulk::{BulkIngestSpec, BulkQuerySpec};
pub use handlers::composite::{
    BatchRequest, BatchSubrequest, CompositeRequest, CompositeSubrequest,
};
pub use handlers::metadata::{
    DeployMessage, DeployOptions, DeployRequest, DeployResultDetails, DeployResultInnerDetails,
    DeployStatus, MetadataHandler, RunTestResults, TestLevel,
};
pub use handlers::sobjects::BlobUploadSpec;
pub use pagination::Records;
pub use response::LimitInfo;
pub use response::{
    ApiVersion, BatchResponse, BatchSubresult, BulkColumnDelimiter, BulkIngestJob, BulkJobState,
    BulkJobStateChange, BulkLineEnding, BulkOperation, BulkQueryJob, BulkQueryResults,
    CompositeError, CompositeResponse, CompositeSubresponse, CompositeTreeResponse,
    CompositeTreeResult, DescribeGlobal, EventLogFileRecord, ExecuteAnonymousResult, Limit,
    OrgLimits, QueryResult, SObjectCollectionResult, SObjectCreateResult, SObjectMetadata,
    SearchResult,
};
pub use retry::RetryPolicy;

use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::sync::{Arc, RwLock};
use std::time::Duration;

/// Default Salesforce REST API version when the caller doesn't override it.
pub const DEFAULT_API_VERSION: &str = "v66.0";

/// Connect-phase timeout applied to the HTTP client the builder
/// creates. Override with [`CirrusBuilder::connect_timeout`].
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Read timeout applied to the HTTP client the builder creates.
///
/// It runs from the moment the request is dispatched until the response
/// head arrives — covering the upload of the request body and the org's
/// own processing time — and from then on bounds the gap between two
/// chunks of the response body. Only that second phase resets, so this
/// is a deadline on getting an answer at all, not merely a stall
/// detector.
///
/// Widen it with [`CirrusBuilder::read_timeout`] for a large Bulk 2.0
/// or blob upload, or for a synchronous call the org takes a long time
/// to answer; no fixed default covers a 100 MB ingest upload over an
/// arbitrary link.
pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(120);

/// Default User-Agent header value sent on every request.
pub(crate) const DEFAULT_USER_AGENT: &str = concat!(
    "cirrus/",
    env!("CARGO_PKG_VERSION"),
    " (Rust SDK for Salesforce)"
);

/// The main Salesforce client.
///
/// Holds the underlying HTTP client, an [`AuthSession`] for credentials, and
/// the API version to use. Cheap to clone.
///
/// # Path resolution
///
/// Every public verb method ([`Self::get`], [`Self::post`], etc.) and
/// [`Self::request_builder`] accepts a `path` argument resolved with
/// three-mode semantics:
///
/// - **Fully-qualified** (`http://…` or `https://…`): used as-is.
/// - **Instance-rooted** (leading `/`): resolved against the instance URL,
///   e.g. `/services/data` → `{instance}/services/data`.
/// - **Versioned** (anything else): prefixed with `/services/data/{version}/`,
///   e.g. `limits` → `{instance}/services/data/{version}/limits`.
///
/// Whichever mode applies, the resolved target has to be `https` (or a
/// loopback host) before the session token is attached — see
/// [`CirrusBuilder::allow_insecure_transport`] for the opt-out.
#[derive(Clone)]
pub struct Cirrus {
    client: reqwest::Client,
    auth: SharedAuth,
    api_version: String,
    retry_policy: RetryPolicy,
    allow_insecure_transport: bool,
    /// Most recent `Sforce-Limit-Info` header value, parsed. Wrapped
    /// in `Arc<RwLock<...>>` so updates are visible across cloned
    /// clients (clones share state).
    last_limit_info: Arc<RwLock<Option<LimitInfo>>>,
}

impl std::fmt::Debug for Cirrus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately omit `auth` — it may carry secrets — and the reqwest
        // client (no useful Debug). Show only the safe configuration knobs.
        f.debug_struct("Cirrus")
            .field("api_version", &self.api_version)
            .field("instance_url", &self.auth.instance_url())
            .field("retry_policy", &self.retry_policy)
            .field("allow_insecure_transport", &self.allow_insecure_transport)
            .finish_non_exhaustive()
    }
}

/// Outcome of the shared 401 auth-refresh decision run at the tail of
/// every send path.
enum AuthRetry {
    /// The cached token was invalidated and a genuinely new one obtained;
    /// the caller should loop and retry the request.
    Retry,
    /// Not a refreshable 401 — already retried once, the result wasn't a
    /// 401, or the auth session couldn't produce a different token (static
    /// auth, scope/permission issue). The caller should return the result
    /// as-is.
    Done,
}

impl Cirrus {
    /// Creates a new builder for constructing a [`Cirrus`] client.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use cirrus::{Cirrus, auth::StaticTokenAuth};
    /// use std::sync::Arc;
    ///
    /// # fn example() -> Result<(), cirrus::CirrusError> {
    /// let auth = Arc::new(StaticTokenAuth::new(
    ///     "00D...!AQ...",
    ///     "https://my-org.my.salesforce.com",
    /// ));
    /// let sf = Cirrus::builder().auth(auth).build()?;
    /// # let _ = sf;
    /// # Ok(())
    /// # }
    /// ```
    pub fn builder() -> CirrusBuilder {
        CirrusBuilder::default()
    }

    /// Returns the configured API version (e.g. `"v66.0"`).
    pub fn api_version(&self) -> &str {
        &self.api_version
    }

    /// Returns a reference to the underlying `reqwest` client. Useful for
    /// callers who want to compose additional requests against the same
    /// connection pool.
    pub fn http_client(&self) -> &reqwest::Client {
        &self.client
    }

    /// Returns the auth session backing this client.
    pub fn auth(&self) -> &SharedAuth {
        &self.auth
    }

    /// Returns the configured retry policy.
    pub fn retry_policy(&self) -> &RetryPolicy {
        &self.retry_policy
    }

    /// Returns the most recent [`LimitInfo`] parsed from a
    /// `Sforce-Limit-Info` response header, if one has been seen.
    ///
    /// Salesforce includes this header on most REST API responses to
    /// surface near-real-time API call usage. The SDK captures it
    /// transparently on every request — successful, retried, or
    /// errored at the HTTP layer. Returns `None` until the first
    /// response with the header lands.
    ///
    /// Cloned clients share the same underlying state, so updates
    /// from one are visible from others.
    pub fn last_limit_info(&self) -> Option<LimitInfo> {
        self.last_limit_info.read().ok().and_then(|guard| *guard)
    }

    /// Internal: parse `Sforce-Limit-Info` from a response and stash
    /// the latest value. Called from every send path on every attempt.
    fn update_limit_info(&self, headers: &reqwest::header::HeaderMap) {
        let Some(value) = headers.get("Sforce-Limit-Info") else {
            return;
        };
        let Ok(s) = value.to_str() else { return };
        let Some(info) = LimitInfo::parse(s) else {
            return;
        };
        tracing::debug!(
            target: "cirrus::limit_info",
            used = info.used,
            allowed = info.allowed,
            "captured Sforce-Limit-Info",
        );
        // Silently ignore poison — this is a best-effort stat surface,
        // not load-bearing for any operation.
        if let Ok(mut guard) = self.last_limit_info.write() {
            *guard = Some(info);
        }
    }

    /// Resolves a path to a fully-qualified URL using three-mode semantics:
    ///
    /// - Fully-qualified (`http://…` or `https://…`): used as-is.
    /// - Instance-rooted (leading `/`): resolved against the instance URL,
    ///   e.g. `/services/data` → `{instance}/services/data`.
    /// - Versioned (anything else): prefixed with `/services/data/{version}/`,
    ///   e.g. `limits` → `{instance}/services/data/{version}/limits`.
    ///
    /// This is the path-resolution contract used by every public verb method
    /// on [`Cirrus`].
    pub(crate) fn resolve_url(&self, path: &str) -> String {
        if path.starts_with("http://") || path.starts_with("https://") {
            path.to_string()
        } else if path.starts_with('/') {
            // trim_start_matches collapses runs of leading slashes —
            // `/foo` and `//foo` both mean "instance-rooted absolute
            // path." Property-tested in property_tests::
            // resolve_url_never_emits_double_slash.
            let rest = path.trim_start_matches('/');
            format!("{}/{}", self.auth.instance_url(), rest)
        } else {
            format!(
                "{}/services/data/{}/{}",
                self.auth.instance_url(),
                self.api_version,
                path
            )
        }
    }

    /// Refuses to put the session token on a target that isn't
    /// TLS-protected. See [`check_transport_security`].
    fn check_transport_security(&self, url: &str) -> CirrusResult<()> {
        check_transport_security("request URL", url, self.allow_insecure_transport)
    }

    /// Builds a versioned URL by appending percent-encoded path segments.
    ///
    /// Use this when any segment may contain reserved characters (slash,
    /// equals, percent, etc.) — e.g. an upsert external-ID value. Each
    /// element of `segments` is encoded as a single path segment.
    ///
    /// A segment of `.` or `..` is rejected: URL path resolution drops
    /// those rather than encoding them, so the request would quietly
    /// land one segment short — on a different Salesforce resource —
    /// instead of failing.
    pub(crate) fn versioned_segments(&self, segments: &[&str]) -> CirrusResult<String> {
        if let Some(dotted) = segments.iter().find(|s| matches!(**s, "." | "..")) {
            return Err(CirrusError::InvalidInput {
                field: "path segment",
                message: format!(
                    "`{dotted}` is a relative path reference, so it cannot address a resource",
                ),
            });
        }
        let base = format!(
            "{}/services/data/{}/",
            self.auth.instance_url(),
            self.api_version
        );
        let mut url = url::Url::parse(&base)?;
        // The trailing '/' on `base` leaves an empty path segment; without
        // popping it, `extend` produces `.../v66.0//sobjects/...`.
        url.path_segments_mut()
            .map_err(|()| CirrusError::InvalidResponse("instance URL is not hierarchical".into()))?
            .pop_if_empty()
            .extend(segments);
        Ok(url.to_string())
    }

    /// GET an arbitrary Salesforce path, deserializing the response into `R`.
    ///
    /// Path resolution follows [`Cirrus`]'s three-mode
    /// semantics. Use this as the open-ended client escape hatch when no
    /// typed builder exists for the resource you need.
    pub async fn get<R: DeserializeOwned>(&self, path: &str) -> CirrusResult<R> {
        let url = self.resolve_url(path);
        self.send::<R, (), ()>(reqwest::Method::GET, &url, None, None)
            .await
    }

    /// GET with query parameters. `query` is anything `Serialize` —
    /// typically `&[("k", "v")]` or a struct.
    pub async fn get_with_query<R, Q>(&self, path: &str, query: &Q) -> CirrusResult<R>
    where
        R: DeserializeOwned,
        Q: Serialize + ?Sized,
    {
        let url = self.resolve_url(path);
        self.send::<R, Q, ()>(reqwest::Method::GET, &url, Some(query), None)
            .await
    }

    /// Sends a request carrying extra request headers, deserializing
    /// the response into `R`.
    ///
    /// Salesforce defines a family of request headers that change how a
    /// call behaves — `Sforce-Auto-Assign`,
    /// `Sforce-Duplicate-Rule-Header`, `Sforce-Call-Options`,
    /// `Sforce-Query-Options`, `Sforce-Mru` — and this attaches one
    /// while keeping the retry policy, the 401 auto-refresh and the
    /// `Sforce-Limit-Info` capture that the typed verb methods provide.
    ///
    /// `query` and `body` are optional; path resolution follows
    /// [`Cirrus`]'s three-mode semantics.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use cirrus::{Cirrus, auth::StaticTokenAuth};
    /// # use std::sync::Arc;
    /// use serde_json::{Value, json};
    ///
    /// # async fn example() -> Result<(), cirrus::CirrusError> {
    /// # let auth = Arc::new(StaticTokenAuth::new("tok", "https://x.my.salesforce.com"));
    /// # let sf = Cirrus::builder().auth(auth).build()?;
    /// // Create a Lead without running the org's assignment rules.
    /// let created: Value = sf
    ///     .send_with_headers(
    ///         cirrus::reqwest::Method::POST,
    ///         "sobjects/Lead",
    ///         None,
    ///         &[("Sforce-Auto-Assign", "FALSE")],
    ///         Some(&json!({"LastName": "Chen", "Company": "Initech"})),
    ///     )
    ///     .await?;
    /// # let _ = created;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn send_with_headers<R, B>(
        &self,
        method: reqwest::Method,
        path: &str,
        query: Option<&[(&str, &str)]>,
        headers: &[(&str, &str)],
        body: Option<&B>,
    ) -> CirrusResult<R>
    where
        R: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        let url = self.resolve_url(path);
        self.send_with_replay(method, &url, query, headers, body, retry::Replay::ByMethod)
            .await
    }

    /// GET with query parameters for a resource whose GET has side
    /// effects, so a lost response must never be replayed. Same wire
    /// behavior as [`Self::get_with_query`]; only the retry
    /// classification differs.
    pub(crate) async fn get_with_query_no_replay<R, Q>(
        &self,
        path: &str,
        query: &Q,
    ) -> CirrusResult<R>
    where
        R: DeserializeOwned,
        Q: Serialize + ?Sized,
    {
        let url = self.resolve_url(path);
        self.send_with_replay::<R, Q, ()>(
            reqwest::Method::GET,
            &url,
            Some(query),
            &[],
            None,
            retry::Replay::Never,
        )
        .await
    }

    /// POST a JSON body.
    pub async fn post<R, B>(&self, path: &str, body: &B) -> CirrusResult<R>
    where
        R: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        let url = self.resolve_url(path);
        self.send::<R, (), B>(reqwest::Method::POST, &url, None, Some(body))
            .await
    }

    /// PUT a JSON body.
    ///
    /// Salesforce REST proper rarely uses PUT; provided for surfaces that
    /// do (Tooling API, Apex REST, etc.).
    pub async fn put<R, B>(&self, path: &str, body: &B) -> CirrusResult<R>
    where
        R: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        let url = self.resolve_url(path);
        self.send::<R, (), B>(reqwest::Method::PUT, &url, None, Some(body))
            .await
    }

    /// PATCH a JSON body.
    pub async fn patch<R, B>(&self, path: &str, body: &B) -> CirrusResult<R>
    where
        R: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        let url = self.resolve_url(path);
        self.send::<R, (), B>(reqwest::Method::PATCH, &url, None, Some(body))
            .await
    }

    /// DELETE a resource. Salesforce typically returns 204 No Content on
    /// success — call with `R = ()`.
    pub async fn delete<R: DeserializeOwned>(&self, path: &str) -> CirrusResult<R> {
        let url = self.resolve_url(path);
        self.send::<R, (), ()>(reqwest::Method::DELETE, &url, None, None)
            .await
    }

    /// Internal: send a request to a fully-built absolute URL. Used by
    /// handlers that need percent-encoded path segments (sObject upsert by
    /// external ID, for example) — they construct the URL via
    /// [`Self::versioned_segments`] and dispatch through this method.
    pub(crate) async fn send_at<R, Q, B>(
        &self,
        method: reqwest::Method,
        url: &str,
        query: Option<&Q>,
        body: Option<&B>,
    ) -> CirrusResult<R>
    where
        R: DeserializeOwned,
        Q: Serialize + ?Sized,
        B: Serialize + ?Sized,
    {
        self.send(method, url, query, body).await
    }

    /// Returns a pre-authenticated [`reqwest::RequestBuilder`] targeting
    /// the resolved URL. Path resolution follows
    /// [`Cirrus`]'s three-mode semantics; the bearer
    /// token is injected via [`AuthSession::access_token`]. The caller is
    /// then free to add headers, configure timeouts, set a custom body
    /// (multipart, form, raw bytes), and `.send()` the request.
    ///
    /// The request this returns leaves the SDK's request loop behind,
    /// so none of the following applies to it:
    ///
    /// - Salesforce-error-aware response parsing — the caller gets a
    ///   raw [`reqwest::Response`] to interpret.
    /// - The [`RetryPolicy`]: no backoff on a transient 5xx, no
    ///   `Retry-After` handling on a 429.
    /// - The 401 auto-refresh. The bearer token is fetched once, here;
    ///   once it expires the caller sees the 401 and has to invalidate
    ///   the session and rebuild the request.
    /// - `Sforce-Limit-Info` capture, so [`Self::last_limit_info`]
    ///   stops advancing.
    ///
    /// To add Salesforce request headers and keep all of that, use
    /// [`Self::send_with_headers`]; for a plain typed call, one of
    /// the verb methods ([`Self::get`], [`Self::post`], …).
    pub async fn request_builder(
        &self,
        method: reqwest::Method,
        path: &str,
    ) -> CirrusResult<reqwest::RequestBuilder> {
        let url = self.resolve_url(path);
        self.check_transport_security(&url)?;
        let token = self.auth.access_token().await?;
        Ok(self.client.request(method, url).bearer_auth(&*token))
    }

    /// Executes a fully-prepared [`reqwest::Request`] using the SDK's
    /// HTTP client.
    ///
    /// Hands-off passthrough — no auth injection, no URL resolution, no
    /// response parsing. Useful for unusual cases where the caller has
    /// constructed the entire request themselves and just wants to share
    /// the SDK's connection pool.
    ///
    /// The request never enters the SDK's request loop, so — as with
    /// [`Self::request_builder`] — the [`RetryPolicy`], the 401
    /// auto-refresh and `Sforce-Limit-Info` capture do not apply:
    /// a transient 5xx or a 429 comes back as-is, an expired token
    /// surfaces as a 401 the caller must handle, and
    /// [`Self::last_limit_info`] stops advancing.
    ///
    /// To get an auth token for a custom request, use
    /// `client.auth().access_token().await?`.
    pub async fn execute(&self, request: reqwest::Request) -> CirrusResult<reqwest::Response> {
        self.client.execute(request).await.map_err(Into::into)
    }

    /// Shared 401 auth-refresh tail used by every send path.
    ///
    /// On a 401 that hasn't already been retried this call, invalidate the
    /// cached token (compare-and-swap against `token`) and fetch a fresh
    /// one. Returns [`AuthRetry::Retry`] when a genuinely different token
    /// was obtained — the caller should set its own `auth_retried` latch
    /// and loop — or [`AuthRetry::Done`] otherwise. `auth_retried` short-
    /// circuits the whole check so the refresh happens at most once.
    ///
    /// Every send path reaches this through the shared [`Self::dispatch`]
    /// loop, so the refresh behavior lives in one place. This is the place
    /// to change it.
    ///
    /// `is_retryable_401` is computed by the caller from the response
    /// *before* this future is awaited — deliberately not a borrow of the
    /// `CirrusResult<T>`, so this future stays `Send` without forcing a
    /// `T: Sync` bound on the streaming send paths.
    async fn auth_retry_decision(
        &self,
        is_retryable_401: bool,
        token: &str,
        auth_retried: bool,
    ) -> CirrusResult<AuthRetry> {
        if auth_retried || !is_retryable_401 {
            return Ok(AuthRetry::Done);
        }
        tracing::warn!(
            target: "cirrus::auth",
            "received 401; invalidating cached token and retrying once",
        );
        self.auth.invalidate(token).await;
        let fresh = self.auth.access_token().await?;
        if *fresh == *token {
            tracing::warn!(
                target: "cirrus::auth",
                "auth session returned same token after invalidate; surfacing 401 (likely static auth or scope/permission issue)",
            );
            return Ok(AuthRetry::Done);
        }
        Ok(AuthRetry::Retry)
    }

    /// Shared request loop behind every send path.
    ///
    /// Two nested retry layers, each with its own budget:
    ///
    /// - **Inner loop** — the [`RetryPolicy`]-driven transient retry
    ///   (429/5xx and network errors), counted by `attempt`.
    /// - **Outer loop** — the 401 auth-refresh retry, latched to at most
    ///   two passes via [`Self::auth_retry_decision`].
    ///
    /// `attempt` resets to zero when the outer loop re-enters with a
    /// fresh token: transient flakiness and credential staleness are
    /// independent failure classes, so retries burned on throttling
    /// before a 401 must not starve the post-refresh request. The reset
    /// also restarts the backoff schedule from `base_delay`. Total work
    /// stays bounded at `2 * (max_retries + 1)` requests because the
    /// outer loop is latched.
    ///
    /// `make_request` builds a fresh request from the current bearer
    /// token, once per attempt ([`reqwest::RequestBuilder`] is consumed
    /// by `send`); an `Err` from it aborts the whole call without
    /// retrying. `parse` maps the terminal response into the caller's
    /// result shape. `Sforce-Limit-Info` capture happens here, on every
    /// response, so no send path can forget it.
    ///
    /// `replay` lets a call site whose HTTP method understates its
    /// effect (anonymous Apex, Bulk job-data upload) opt out of the
    /// method-derived idempotency assumption.
    async fn dispatch<T, MakeReq, Parse>(
        &self,
        method: &reqwest::Method,
        url: &str,
        replay: retry::Replay,
        make_request: MakeReq,
        parse: Parse,
    ) -> CirrusResult<T>
    where
        MakeReq: Fn(&str) -> CirrusResult<reqwest::RequestBuilder>,
        Parse: Fn(u16, reqwest::header::HeaderMap, bytes::Bytes) -> CirrusResult<T>,
    {
        self.check_transport_security(url)?;
        let mut auth_retried = false;
        let mut attempt: u32 = 0;
        loop {
            let token = self.auth.access_token().await?;

            let result: CirrusResult<T> = loop {
                let request = make_request(&token)?;

                // Both a request that never got a response and a
                // response whose body dies mid-stream are transport
                // failures with the same ambiguity, so they share one
                // retry decision below.
                let transport_error: CirrusError = match request.send().await {
                    Ok(response) => {
                        let status = response.status().as_u16();
                        let headers = response.headers().clone();
                        self.update_limit_info(&headers);

                        if retry::should_retry_status(
                            &self.retry_policy,
                            method,
                            replay,
                            status,
                            attempt,
                        ) {
                            // Drain the body so the connection returns
                            // to the pool clean.
                            let _ = response.bytes().await;
                            let retry_after = retry::parse_retry_after(&headers);
                            let delay =
                                retry::compute_delay(&self.retry_policy, attempt, retry_after);
                            tokio::time::sleep(delay).await;
                            attempt += 1;
                            continue;
                        }

                        match response.bytes().await {
                            Ok(bytes) => break parse(status, headers, bytes),
                            Err(e) => e.into(),
                        }
                    }
                    Err(e) => e.into(),
                };

                if retry::should_retry_network(
                    &self.retry_policy,
                    method,
                    replay,
                    &transport_error,
                    attempt,
                ) {
                    let delay = retry::compute_delay(&self.retry_policy, attempt, None);
                    tokio::time::sleep(delay).await;
                    attempt += 1;
                    continue;
                }
                break Err(transport_error);
            };

            // An unparsed error body is whatever an intermediary chose
            // to return, and those pages echo the request that provoked
            // them. Scrub the credential here, where the token for the
            // attempt is still in hand, before the error can reach a
            // log sink.
            let result = result.map_err(|e| e.redact_secrets(&token));

            // 401 → invalidate the cached token and try once more with
            // a fresh one. If the auth session can't refresh (returns
            // the same token), surface the 401 verbatim.
            let is_retryable_401 = matches!(&result, Err(CirrusError::Api { status: 401, .. }));
            match self
                .auth_retry_decision(is_retryable_401, &token, auth_retried)
                .await?
            {
                AuthRetry::Retry => {
                    auth_retried = true;
                    attempt = 0;
                    continue;
                }
                AuthRetry::Done => return result,
            }
        }
    }

    async fn send<R, Q, B>(
        &self,
        method: reqwest::Method,
        url: &str,
        query: Option<&Q>,
        body: Option<&B>,
    ) -> CirrusResult<R>
    where
        R: DeserializeOwned,
        Q: Serialize + ?Sized,
        B: Serialize + ?Sized,
    {
        self.send_with_replay(method, url, query, &[], body, retry::Replay::ByMethod)
            .await
    }

    async fn send_with_replay<R, Q, B>(
        &self,
        method: reqwest::Method,
        url: &str,
        query: Option<&Q>,
        headers: &[(&str, &str)],
        body: Option<&B>,
        replay: retry::Replay,
    ) -> CirrusResult<R>
    where
        R: DeserializeOwned,
        Q: Serialize + ?Sized,
        B: Serialize + ?Sized,
    {
        self.dispatch(
            &method,
            url,
            replay,
            |token: &str| {
                let mut request = self.client.request(method.clone(), url).bearer_auth(token);
                for (name, value) in headers {
                    request = request.header(*name, *value);
                }
                if let Some(q) = query {
                    request = request.query(q);
                }
                if let Some(b) = body {
                    request = request.json(b);
                }
                Ok(request)
            },
            |status, _headers, bytes| response::parse_response_bytes(status, &bytes),
        )
        .await
    }

    /// Sends a request with a raw body (e.g. CSV) and a custom Content-Type,
    /// parsing the response as JSON via [`response::parse_response_bytes`].
    ///
    /// Used by Bulk 2.0 ingest uploads — the request body is `text/csv`, the
    /// response is the standard JSON job envelope. Path resolution still
    /// follows [`Cirrus`]'s three-mode semantics.
    ///
    /// `replay` says whether a lost response may be re-sent; a body
    /// that submits data (rather than replacing a resource) passes
    /// [`retry::Replay::Never`] even on an idempotent method.
    pub(crate) async fn send_with_body<R>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: bytes::Bytes,
        content_type: &str,
        replay: retry::Replay,
    ) -> CirrusResult<R>
    where
        R: DeserializeOwned,
    {
        let url = self.resolve_url(path);
        self.dispatch(
            &method,
            &url,
            replay,
            |token: &str| {
                // bytes::Bytes is Arc-backed — clone is cheap.
                Ok(self
                    .client
                    .request(method.clone(), &url)
                    .bearer_auth(token)
                    .header(reqwest::header::CONTENT_TYPE, content_type)
                    .body(body.clone()))
            },
            |status, _headers, bytes| response::parse_response_bytes(status, &bytes),
        )
        .await
    }

    /// Sends a multipart/form-data request with one JSON metadata part
    /// and one binary blob part.
    ///
    /// Used by sObject blob inserts/updates (ContentVersion / Document /
    /// Attachment / any object with a blob field). Each retry iteration
    /// rebuilds the [`reqwest::multipart::Form`] from the raw parts —
    /// the form itself isn't Clone, but the underlying `Vec<u8>` JSON
    /// and `bytes::Bytes` blob are cheap to clone.
    ///
    /// Path resolution follows [`Cirrus`]'s three-mode
    /// semantics. Goes through the same retry + auth-refresh +
    /// `Sforce-Limit-Info` capture as the other send methods.
    // Internal transport helper: the public surface
    // ([`crate::handlers::sobjects::SObjectHandler::create_with_blob`])
    // groups these into a [`crate::BlobUploadSpec`] struct. Keeping
    // this fn positional avoids a second public-or-pub(crate) struct
    // just for transport.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn send_multipart<R>(
        &self,
        method: reqwest::Method,
        path: &str,
        json_part_name: &str,
        json_bytes: Vec<u8>,
        blob_part_name: &str,
        blob_filename: &str,
        blob_content_type: &str,
        blob: bytes::Bytes,
    ) -> CirrusResult<R>
    where
        R: DeserializeOwned,
    {
        let url = self.resolve_url(path);
        self.dispatch(
            &method,
            &url,
            retry::Replay::ByMethod,
            |token: &str| {
                // Build a fresh Form per attempt — Form isn't Clone.
                // The Vec<u8> JSON clone is one alloc (typically <1KB
                // metadata). The blob goes through Part::stream so that
                // its underlying Arc-backed bytes::Bytes is forwarded
                // zero-copy — Part::bytes would force a to_vec() and
                // copy up to 2GB for ContentVersion uploads on each
                // retry attempt.
                let json_part = reqwest::multipart::Part::bytes(json_bytes.clone())
                    .mime_str("application/json")
                    .map_err(|e| {
                        CirrusError::InvalidHeader(format!("invalid JSON part content-type: {e}"))
                    })?;
                let blob_part = reqwest::multipart::Part::stream(reqwest::Body::from(blob.clone()))
                    .file_name(blob_filename.to_string())
                    .mime_str(blob_content_type)
                    .map_err(|e| {
                        CirrusError::InvalidHeader(format!("invalid blob part content-type: {e}"))
                    })?;
                let form = reqwest::multipart::Form::new()
                    .part(json_part_name.to_string(), json_part)
                    .part(blob_part_name.to_string(), blob_part);

                Ok(self
                    .client
                    .request(method.clone(), &url)
                    .bearer_auth(token)
                    .multipart(form))
            },
            |status, _headers, bytes| response::parse_response_bytes(status, &bytes),
        )
        .await
    }

    /// Fetches a response as raw bytes (e.g. CSV) plus its headers, with
    /// the standard Salesforce error-array parsing on non-2xx.
    ///
    /// Used by Bulk 2.0 result downloads — the response body is `text/csv`
    /// and the caller may need response headers for cursor pagination
    /// (`Sforce-Locator`, `Sforce-NumberOfRecords`). Path resolution still
    /// follows [`Cirrus`]'s three-mode semantics.
    pub(crate) async fn fetch_raw(
        &self,
        method: reqwest::Method,
        path: &str,
        accept: &str,
        query: Option<&[(&str, &str)]>,
    ) -> CirrusResult<(reqwest::header::HeaderMap, bytes::Bytes)> {
        let url = self.resolve_url(path);
        self.dispatch(
            &method,
            &url,
            retry::Replay::ByMethod,
            |token: &str| {
                let mut request = self
                    .client
                    .request(method.clone(), &url)
                    .bearer_auth(token)
                    .header(reqwest::header::ACCEPT, accept);
                if let Some(q) = query {
                    request = request.query(q);
                }
                Ok(request)
            },
            |status, headers, bytes| {
                if (200..300).contains(&status) {
                    Ok((headers, bytes))
                } else {
                    Err(response::parse_error_response(status, &bytes))
                }
            },
        )
        .await
    }

    /// Sends a conditional GET carrying `If-Modified-Since`, returning
    /// `None` when the org answers `304 Not Modified`.
    ///
    /// `since` is an already-formatted IMF-fixdate. Goes through the
    /// same retry policy, auth-refresh, `Sforce-Limit-Info` capture and
    /// body handling as the other send paths — a 2xx that doesn't fit
    /// `R` surfaces as [`CirrusError::InvalidResponse`] with a scrubbed
    /// excerpt, exactly as it does on the unconditional path.
    pub(crate) async fn get_if_modified_since<R: DeserializeOwned>(
        &self,
        path: &str,
        since: &str,
    ) -> CirrusResult<Option<R>> {
        let method = reqwest::Method::GET;
        let url = self.resolve_url(path);
        self.dispatch(
            &method,
            &url,
            retry::Replay::ByMethod,
            |token: &str| {
                Ok(self
                    .client
                    .request(method.clone(), &url)
                    .bearer_auth(token)
                    .header(reqwest::header::IF_MODIFIED_SINCE, since))
            },
            |status, _headers, bytes| {
                // 304 is "your cache is still good", not a failure —
                // and it carries no body to deserialize.
                if status == 304 {
                    return Ok(None);
                }
                response::parse_response_bytes(status, &bytes).map(Some)
            },
        )
        .await
    }
}

/// Builder for [`Cirrus`].
///
/// Required: an [`AuthSession`] via [`auth`](Self::auth). Everything else has
/// a sensible default.
#[derive(Default)]
pub struct CirrusBuilder {
    auth: Option<SharedAuth>,
    api_version: Option<String>,
    user_agent: Option<String>,
    http_client: Option<reqwest::Client>,
    retry_policy: Option<RetryPolicy>,
    // Outer `Option` is "did the caller set this"; inner `None` is the
    // caller asking for no deadline at all.
    connect_timeout: Option<Option<Duration>>,
    read_timeout: Option<Option<Duration>>,
    allow_insecure_transport: bool,
}

impl CirrusBuilder {
    /// Sets the auth session (any [`AuthSession`] implementation wrapped in
    /// `Arc`). Required.
    pub fn auth(mut self, auth: SharedAuth) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Sets the Salesforce REST API version, e.g. `"v66.0"`. Defaults to
    /// [`DEFAULT_API_VERSION`].
    ///
    /// Salesforce writes this URI segment as `vXX.X`, or as the alias
    /// `latest` to track the org's newest release. Anything else — the
    /// bare `"66.0"` that [`ApiVersion::version`] carries, for instance
    /// — is rejected by [`build`](Self::build) rather than turning every
    /// later call into a `NOT_FOUND`.
    pub fn api_version(mut self, version: impl Into<String>) -> Self {
        self.api_version = Some(version.into());
        self
    }

    /// Overrides the default User-Agent header.
    pub fn user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = Some(ua.into());
        self
    }

    /// Supplies a pre-configured `reqwest::Client`. Useful for sharing a
    /// connection pool across multiple SDK clients or for installing custom
    /// middleware. When provided, the builder's `user_agent`,
    /// `connect_timeout` and `read_timeout` settings are ignored — the
    /// supplied client owns its own headers, timeouts, redirect policy and
    /// content-encoding support.
    pub fn http_client(mut self, client: reqwest::Client) -> Self {
        self.http_client = Some(client);
        self
    }

    /// Sets the connect-phase timeout for the HTTP client this builder
    /// creates. Defaults to [`DEFAULT_CONNECT_TIMEOUT`]; pass `None` to
    /// wait indefinitely for a connection.
    ///
    /// Ignored when [`http_client`](Self::http_client) supplies a client.
    pub fn connect_timeout(mut self, timeout: impl Into<Option<Duration>>) -> Self {
        self.connect_timeout = Some(timeout.into());
        self
    }

    /// Sets the read timeout for the HTTP client this builder creates.
    /// Defaults to [`DEFAULT_READ_TIMEOUT`]; pass `None` to wait
    /// indefinitely.
    ///
    /// The deadline covers the whole in-flight request until the
    /// response head arrives — request-body upload and org processing
    /// included — and after that the gap between two response chunks.
    /// Widen it for a large Bulk 2.0 or blob **upload**, for draining a
    /// very large result page over a slow link, and for a call the org
    /// takes a long time to answer.
    ///
    /// Ignored when [`http_client`](Self::http_client) supplies a client.
    pub fn read_timeout(mut self, timeout: impl Into<Option<Duration>>) -> Self {
        self.read_timeout = Some(timeout.into());
        self
    }

    /// Sets the [`RetryPolicy`] for transient-failure handling.
    /// Defaults to [`RetryPolicy::default`] (3 retries, exponential
    /// backoff with full jitter, 100 ms base, 30 s cap, retry on
    /// idempotent 5xx). Pass [`RetryPolicy::none`] to disable retries
    /// entirely.
    pub fn retry_policy(mut self, policy: RetryPolicy) -> Self {
        self.retry_policy = Some(policy);
        self
    }

    /// Allows requests to carry the Salesforce session token over
    /// plaintext `http://` to a non-loopback host.
    ///
    /// Off by default: the token is the org session id, and RFC 6750
    /// §5.3 requires TLS for any request that bears one. Turn this on
    /// only for a deliberate plaintext hop you control, such as a
    /// recording proxy on a trusted network.
    pub fn allow_insecure_transport(mut self, allow: bool) -> Self {
        self.allow_insecure_transport = allow;
        self
    }

    /// Finalizes the builder.
    ///
    /// Fails when no [`auth`](Self::auth) session was supplied, when
    /// [`api_version`](Self::api_version) isn't a version segment
    /// Salesforce recognizes, or when the auth session's instance URL
    /// would send the session token in the clear.
    pub fn build(self) -> CirrusResult<Cirrus> {
        let auth = self.auth.ok_or(CirrusError::MissingField("auth"))?;
        let api_version = self
            .api_version
            .unwrap_or_else(|| DEFAULT_API_VERSION.to_string());
        validate_api_version(&api_version)?;
        check_transport_security(
            "instance URL",
            auth.instance_url(),
            self.allow_insecure_transport,
        )?;

        let client = if let Some(c) = self.http_client {
            c
        } else {
            let ua = self.user_agent.as_deref().unwrap_or(DEFAULT_USER_AGENT);
            let mut headers = HeaderMap::new();
            headers.insert(
                USER_AGENT,
                HeaderValue::from_str(ua).map_err(|e| CirrusError::InvalidHeader(e.to_string()))?,
            );
            let mut builder = reqwest::Client::builder()
                .default_headers(headers)
                // Salesforce compresses a response only when the request
                // carries Accept-Encoding, which this turns on.
                .gzip(true)
                // Following a 3xx would re-send the request — bearer
                // token included — to whatever host the Location header
                // names, so a redirect is surfaced as an error for the
                // caller to inspect.
                .redirect(reqwest::redirect::Policy::none());
            if let Some(t) = self
                .connect_timeout
                .unwrap_or(Some(DEFAULT_CONNECT_TIMEOUT))
            {
                builder = builder.connect_timeout(t);
            }
            if let Some(t) = self.read_timeout.unwrap_or(Some(DEFAULT_READ_TIMEOUT)) {
                builder = builder.read_timeout(t);
            }
            builder.build().map_err(CirrusError::HttpClient)?
        };

        Ok(Cirrus {
            client,
            auth,
            api_version,
            retry_policy: self.retry_policy.unwrap_or_default(),
            allow_insecure_transport: self.allow_insecure_transport,
            last_limit_info: Arc::new(RwLock::new(None)),
        })
    }

    /// Builds a client and immediately discovers the highest API
    /// version the org supports via `GET /services/data`, replacing
    /// the configured `api_version` with the discovered value.
    ///
    /// Useful when you don't want to lock into [`DEFAULT_API_VERSION`]
    /// — newer Salesforce releases add fields and endpoints that
    /// won't be visible against an older version. Costs one extra
    /// `GET /services/data` round-trip on client construction.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use cirrus::{Cirrus, auth::StaticTokenAuth};
    /// use std::sync::Arc;
    ///
    /// # async fn example() -> Result<(), cirrus::CirrusError> {
    /// let auth = Arc::new(StaticTokenAuth::new("tok", "https://my-org.my.salesforce.com"));
    /// let sf = Cirrus::builder()
    ///     .auth(auth)
    ///     .build_with_latest_version()
    ///     .await?;
    /// // sf.api_version() now returns "v66.0" (or whatever the org's
    /// // highest is) rather than the SDK's compile-time default.
    /// # Ok(())
    /// # }
    /// ```
    pub async fn build_with_latest_version(self) -> CirrusResult<Cirrus> {
        let bootstrap = self.build()?;
        let latest = bootstrap.latest_api_version().await?;
        Ok(Cirrus {
            api_version: latest,
            ..bootstrap
        })
    }
}

/// Rejects a target that would carry the Salesforce session token in
/// the clear.
///
/// RFC 6750 §5.3 makes TLS mandatory for requests bearing an OAuth
/// bearer token, and the value here is the org session id: anything
/// on the path can replay it for the session's lifetime. Loopback
/// hosts are exempt (local mock servers and sidecar proxies never
/// leave the machine), and `allow_insecure` reflects the caller's
/// deliberate opt-out.
fn check_transport_security(
    field: &'static str,
    url: &str,
    allow_insecure: bool,
) -> CirrusResult<()> {
    if allow_insecure {
        return Ok(());
    }
    let parsed = url::Url::parse(url)?;
    if parsed.scheme() == "https" {
        return Ok(());
    }
    let loopback = match parsed.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(host)) => host == "localhost" || host.ends_with(".localhost"),
        None => false,
    };
    if loopback {
        return Ok(());
    }
    Err(CirrusError::InvalidInput {
        field,
        message: format!(
            "`{url}` is not an https target, and the Salesforce session token must not travel in the clear; \
             opt out with CirrusBuilder::allow_insecure_transport if the plaintext hop is deliberate",
        ),
    })
}

/// Accepts the two forms Salesforce documents for the version segment
/// of a REST URI: `vXX.X` and the alias `latest`.
///
/// The bare numeric form (`"66.0"`) is what `GET /services/data`
/// reports in `ApiVersion::version`, and it is the mistake worth
/// catching here: the SDK would happily build
/// `/services/data/66.0/query` and every call would come back as a
/// generic `NOT_FOUND` that never mentions the version.
fn validate_api_version(version: &str) -> CirrusResult<()> {
    let numeric = version.strip_prefix('v').and_then(|v| v.split_once('.'));
    let well_formed = match numeric {
        Some((major, minor)) => {
            !major.is_empty()
                && !minor.is_empty()
                && major.bytes().all(|b| b.is_ascii_digit())
                && minor.bytes().all(|b| b.is_ascii_digit())
        }
        None => false,
    };
    if version == "latest" || well_formed {
        return Ok(());
    }
    Err(CirrusError::InvalidInput {
        field: "api_version",
        message: format!(
            "expected `vXX.X` (for example `{DEFAULT_API_VERSION}`) or `latest`, got `{version}`",
        ),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::auth::StaticTokenAuth;
    use std::sync::Arc;

    fn fixture(instance: &str) -> Cirrus {
        let auth = Arc::new(StaticTokenAuth::new("tok", instance));
        Cirrus::builder().auth(auth).build().unwrap()
    }

    #[test]
    fn build_requires_auth() {
        let err = Cirrus::builder().build().unwrap_err();
        assert!(matches!(err, CirrusError::MissingField("auth")));
    }

    #[test]
    fn resolve_url_versioned_for_relative_path() {
        let sf = fixture("https://my.salesforce.com");
        let url = sf.resolve_url("limits");
        assert_eq!(url, "https://my.salesforce.com/services/data/v66.0/limits");
    }

    #[test]
    fn resolve_url_versioned_for_nested_relative_path() {
        let sf = fixture("https://my.salesforce.com");
        let url = sf.resolve_url("sobjects/Account/001");
        assert_eq!(
            url,
            "https://my.salesforce.com/services/data/v66.0/sobjects/Account/001"
        );
    }

    #[test]
    fn resolve_url_instance_rooted_for_leading_slash() {
        let sf = fixture("https://my.salesforce.com");
        let url = sf.resolve_url("/services/data");
        assert_eq!(url, "https://my.salesforce.com/services/data");
    }

    #[test]
    fn resolve_url_passthrough_for_https_url() {
        let sf = fixture("https://my.salesforce.com");
        let absolute = "https://other.example.com/some/path";
        assert_eq!(sf.resolve_url(absolute), absolute);
    }

    #[test]
    fn resolve_url_passthrough_for_http_url() {
        let sf = fixture("https://my.salesforce.com");
        let absolute = "http://localhost:1234/path";
        assert_eq!(sf.resolve_url(absolute), absolute);
    }

    #[test]
    fn build_rejects_a_plaintext_instance_url() {
        // RFC 6750 §5.3: "Clients MUST always use TLS [RFC5246] (https)
        // or equivalent transport security when making requests with
        // bearer tokens." An org URL that lost its `s` would otherwise
        // put the session id on the wire in the clear.
        let auth = Arc::new(StaticTokenAuth::new(
            "tok",
            "http://my-org.my.salesforce.com",
        ));
        let err = Cirrus::builder().auth(auth).build().unwrap_err();
        match err {
            CirrusError::InvalidInput { field, .. } => assert_eq!(field, "instance URL"),
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn build_accepts_a_plaintext_instance_url_when_opted_in() {
        let auth = Arc::new(StaticTokenAuth::new(
            "tok",
            "http://my-org.my.salesforce.com",
        ));
        let sf = Cirrus::builder()
            .auth(auth)
            .allow_insecure_transport(true)
            .build()
            .unwrap();
        assert_eq!(
            sf.resolve_url("limits"),
            "http://my-org.my.salesforce.com/services/data/v66.0/limits"
        );
    }

    #[tokio::test]
    async fn refuses_to_send_the_token_to_a_plaintext_absolute_url() {
        // The passthrough mode takes a fully-qualified URL, which can
        // come from data the caller doesn't control (a locator, a
        // config value). The token must not follow it onto a plaintext
        // hop — and nothing should be sent at all.
        let sf = fixture("https://my-org.my.salesforce.com");
        let err = sf
            .get::<serde_json::Value>("http://elsewhere.example.com/collect")
            .await
            .unwrap_err();
        match err {
            CirrusError::InvalidInput { field, .. } => assert_eq!(field, "request URL"),
            other => panic!("expected InvalidInput, got {other:?}"),
        }

        let err = sf
            .request_builder(reqwest::Method::GET, "http://elsewhere.example.com/collect")
            .await
            .unwrap_err();
        assert!(matches!(err, CirrusError::InvalidInput { .. }));
    }

    #[test]
    fn build_rejects_a_version_segment_salesforce_would_not_recognize() {
        // SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/resources_query.htm
        // "URI: /services/data/vXX.X/query?q=query" — the segment
        // carries the `v`. `ApiVersion::version` reports "66.0"
        // without it, which is the value callers copy by mistake.
        for bad in ["66.0", "v66", "V66.0", "vXX.X", ""] {
            let auth = Arc::new(StaticTokenAuth::new("tok", "https://my.salesforce.com"));
            let err = Cirrus::builder()
                .auth(auth)
                .api_version(bad)
                .build()
                .unwrap_err();
            match err {
                CirrusError::InvalidInput { field, message } => {
                    assert_eq!(field, "api_version");
                    assert!(message.contains("latest"), "message should name both forms");
                }
                other => panic!("expected InvalidInput for {bad:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn build_accepts_the_latest_version_alias() {
        // SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/resources_versions.htm
        // "Version alias: Instead of a numeric version (for example,
        // vXX.X), you can use latest in the URI to resolve to the most
        // recently released API version."
        let auth = Arc::new(StaticTokenAuth::new("tok", "https://my.salesforce.com"));
        let sf = Cirrus::builder()
            .auth(auth)
            .api_version("latest")
            .build()
            .unwrap();
        assert_eq!(
            sf.resolve_url("limits"),
            "https://my.salesforce.com/services/data/latest/limits"
        );
    }

    #[test]
    fn api_version_can_be_overridden() {
        let auth = Arc::new(StaticTokenAuth::new("tok", "https://my.salesforce.com"));
        let sf = Cirrus::builder()
            .auth(auth)
            .api_version("v61.0")
            .build()
            .unwrap();
        assert_eq!(sf.api_version(), "v61.0");
        assert!(sf.resolve_url("x").contains("/v61.0/"));
    }

    mod escape_hatch {
        use super::*;
        use serde_json::{Value, json};
        use wiremock::matchers::{body_json, header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        fn server_fixture(uri: String) -> Cirrus {
            let auth = Arc::new(StaticTokenAuth::new("tok", uri));
            Cirrus::builder().auth(auth).build().unwrap()
        }

        #[tokio::test]
        async fn get_resolves_relative_path_as_versioned() {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/services/data/v66.0/limits"))
                .and(header("authorization", "Bearer tok"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
                .mount(&server)
                .await;

            let sf = server_fixture(server.uri());
            let v: Value = sf.get("limits").await.unwrap();
            assert_eq!(v["ok"], true);
        }

        #[tokio::test]
        async fn get_resolves_leading_slash_as_instance_rooted() {
            let server = MockServer::start().await;
            // Note: /services/apexrest/foo lives outside the versioned tree,
            // so passing a leading-slash path is the only correct way.
            Mock::given(method("GET"))
                .and(path("/services/apexrest/foo"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({"called": "apex"})))
                .mount(&server)
                .await;

            let sf = server_fixture(server.uri());
            let v: Value = sf.get("/services/apexrest/foo").await.unwrap();
            assert_eq!(v["called"], "apex");
        }

        #[tokio::test]
        async fn get_passes_through_absolute_url() {
            // The "passthrough" mode targets a different host entirely from
            // the configured instance URL, proving resolve_url didn't try to
            // prefix it.
            let other = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/some/other/path"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({"hit": "other"})))
                .mount(&other)
                .await;

            let sf = server_fixture("https://unused.invalid".to_string());
            let target = format!("{}/some/other/path", other.uri());
            let v: Value = sf.get(&target).await.unwrap();
            assert_eq!(v["hit"], "other");
        }

        #[tokio::test]
        async fn post_sends_json_body() {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/services/data/v66.0/composite/batch"))
                .and(body_json(json!({"batchRequests": []})))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({"results": []})))
                .mount(&server)
                .await;

            let sf = server_fixture(server.uri());
            let v: Value = sf
                .post("composite/batch", &json!({"batchRequests": []}))
                .await
                .unwrap();
            assert!(v["results"].is_array());
        }

        #[tokio::test]
        async fn put_sends_json_body() {
            let server = MockServer::start().await;
            Mock::given(method("PUT"))
                .and(path("/services/data/v66.0/custom/resource"))
                .and(body_json(json!({"k": "v"})))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({"updated": true})))
                .mount(&server)
                .await;

            let sf = server_fixture(server.uri());
            let v: Value = sf.put("custom/resource", &json!({"k": "v"})).await.unwrap();
            assert_eq!(v["updated"], true);
        }

        #[tokio::test]
        async fn patch_sends_json_body() {
            let server = MockServer::start().await;
            Mock::given(method("PATCH"))
                .and(path("/services/data/v66.0/sobjects/Account/001"))
                .and(body_json(json!({"Name": "X"})))
                .respond_with(ResponseTemplate::new(204))
                .mount(&server)
                .await;

            let sf = server_fixture(server.uri());
            sf.patch::<(), _>("sobjects/Account/001", &json!({"Name": "X"}))
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn delete_handles_204() {
            let server = MockServer::start().await;
            Mock::given(method("DELETE"))
                .and(path("/services/data/v66.0/sobjects/Account/001"))
                .respond_with(ResponseTemplate::new(204))
                .mount(&server)
                .await;

            let sf = server_fixture(server.uri());
            sf.delete::<()>("sobjects/Account/001").await.unwrap();
        }

        #[tokio::test]
        async fn send_with_headers_attaches_salesforce_request_headers() {
            // SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/headers_autoassign.htm
            // "Field name: Sforce-Auto-Assign ... If the header is not
            // provided in the request, the default value is TRUE."
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/services/data/v66.0/sobjects/Lead"))
                .and(header("sforce-auto-assign", "FALSE"))
                .and(header("authorization", "Bearer tok"))
                .and(body_json(json!({"LastName": "Chen", "Company": "Initech"})))
                .respond_with(
                    ResponseTemplate::new(201).set_body_json(
                        json!({"id": "00Q000000000001", "success": true, "errors": []}),
                    ),
                )
                .mount(&server)
                .await;

            let sf = server_fixture(server.uri());
            let created: Value = sf
                .send_with_headers(
                    reqwest::Method::POST,
                    "sobjects/Lead",
                    None,
                    &[("Sforce-Auto-Assign", "FALSE")],
                    Some(&json!({"LastName": "Chen", "Company": "Initech"})),
                )
                .await
                .unwrap();
            assert_eq!(created["id"], "00Q000000000001");
        }

        #[tokio::test]
        async fn send_with_headers_keeps_the_retry_policy() {
            // The point of the method over request_builder: a
            // header-carrying call still gets retry, 401 refresh and
            // Sforce-Limit-Info capture.
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/services/data/v66.0/query"))
                .respond_with(ResponseTemplate::new(503))
                .up_to_n_times(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/services/data/v66.0/query"))
                .and(header("sforce-query-options", "batchSize=200"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(json!({"totalSize": 0, "done": true, "records": []}))
                        .insert_header("Sforce-Limit-Info", "api-usage=7/15000"),
                )
                .mount(&server)
                .await;

            let auth = Arc::new(StaticTokenAuth::new("tok", server.uri()));
            let sf = Cirrus::builder()
                .auth(auth)
                .retry_policy(RetryPolicy {
                    base_delay: std::time::Duration::ZERO,
                    max_delay: std::time::Duration::ZERO,
                    jitter: false,
                    ..RetryPolicy::default()
                })
                .build()
                .unwrap();
            let result: Value = sf
                .send_with_headers::<_, ()>(
                    reqwest::Method::GET,
                    "query",
                    Some(&[("q", "SELECT Id FROM Account")]),
                    &[("Sforce-Query-Options", "batchSize=200")],
                    None,
                )
                .await
                .unwrap();
            assert_eq!(result["done"], true);
            assert_eq!(sf.last_limit_info().unwrap().used, 7);
        }

        #[tokio::test]
        async fn request_builder_pre_injects_bearer_auth() {
            // Verifies the returned RequestBuilder already has the auth
            // header set — a caller adding their own headers shouldn't
            // need to re-attach the bearer token.
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/services/data/v66.0/limits"))
                .and(header("authorization", "Bearer tok"))
                .and(header("x-custom", "added-by-caller"))
                .respond_with(ResponseTemplate::new(200))
                .mount(&server)
                .await;

            let sf = server_fixture(server.uri());
            let resp = sf
                .request_builder(reqwest::Method::GET, "limits")
                .await
                .unwrap()
                .header("X-Custom", "added-by-caller")
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status().as_u16(), 200);
        }

        #[tokio::test]
        async fn execute_runs_caller_built_request() {
            // execute() is fully hands-off — no auth injection. Caller is
            // responsible for everything. Used here without a bearer token
            // intentionally to prove no auth is injected.
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/raw/path"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({"raw": true})))
                .mount(&server)
                .await;

            let sf = server_fixture(server.uri());
            let url = format!("{}/raw/path", server.uri());
            let req = sf.http_client().get(&url).build().unwrap();
            let resp = sf.execute(req).await.unwrap();
            assert_eq!(resp.status().as_u16(), 200);
            let body: Value = resp.json().await.unwrap();
            assert_eq!(body["raw"], true);
        }
    }

    /// Transport defaults the builder installs on the HTTP client it
    /// creates: response compression, redirect handling, timeouts.
    mod client_defaults {
        use super::*;
        use serde_json::{Value, json};
        use std::time::Duration;
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        #[tokio::test]
        async fn requests_advertise_gzip_encoding() {
            // SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/intro_rest_compression.htm
            // "Salesforce compresses a response only if the request
            // contains an Accept-Encoding: gzip, Accept-Encoding:
            // deflate, Accept-Encoding: br, or Accept-Encoding: zstd
            // header."
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/services/data/v66.0/limits"))
                .and(header("accept-encoding", "gzip"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
                .expect(1)
                .mount(&server)
                .await;

            let auth = Arc::new(StaticTokenAuth::new("tok", server.uri()));
            let sf = Cirrus::builder().auth(auth).build().unwrap();
            let v: Value = sf.get("limits").await.unwrap();
            assert_eq!(v["ok"], true);
        }

        #[tokio::test]
        async fn redirects_surface_as_errors_instead_of_being_followed() {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/services/data/v66.0/limits"))
                .respond_with(ResponseTemplate::new(302).insert_header("Location", "/elsewhere"))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/elsewhere"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
                .expect(0)
                .mount(&server)
                .await;

            let auth = Arc::new(StaticTokenAuth::new("tok", server.uri()));
            let sf = Cirrus::builder().auth(auth).build().unwrap();
            let err = sf.get::<Value>("limits").await.unwrap_err();
            assert!(matches!(err, CirrusError::Api { status: 302, .. }));
        }

        #[tokio::test]
        async fn an_echoed_request_in_a_2xx_body_is_scrubbed() {
            // A gateway can answer 200 with its own page. That body
            // doesn't fit the requested type, so an excerpt lands in
            // CirrusError::InvalidResponse and in the error's Display —
            // the same exposure the error-array path has.
            let token = "00D5f000000ABCD!AQcAQK_session_id";
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/services/data/v66.0/limits"))
                .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                    "<html>GET /services/data/v66.0/limits\nAuthorization: Bearer {token}</html>"
                )))
                .mount(&server)
                .await;

            let auth = Arc::new(StaticTokenAuth::new(token, server.uri()));
            let sf = Cirrus::builder().auth(auth).build().unwrap();
            let err = sf.get::<Value>("limits").await.unwrap_err();

            assert!(!err.to_string().contains(token), "{err}");
            match err {
                CirrusError::InvalidResponse(message) => {
                    assert!(!message.contains(token), "{message}");
                    assert!(message.contains("[redacted]"), "{message}");
                }
                other => panic!("expected an InvalidResponse error, got {other:?}"),
            }
        }

        #[tokio::test]
        async fn an_echoed_request_in_an_error_body_is_scrubbed() {
            // A gateway that answers with its own page — not the
            // Salesforce error array — lands in CirrusError::Api::raw
            // and in the error's Display. If it echoed the request, the
            // session token must not come with it.
            let token = "00D5f000000ABCD!AQcAQK_session_id";
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/services/data/v66.0/limits"))
                .respond_with(ResponseTemplate::new(502).set_body_string(format!(
                    "Bad Gateway\nGET /services/data/v66.0/limits\nAuthorization: Bearer {token}\n"
                )))
                .mount(&server)
                .await;

            let auth = Arc::new(StaticTokenAuth::new(token, server.uri()));
            let sf = Cirrus::builder()
                .auth(auth)
                .retry_policy(RetryPolicy::none())
                .build()
                .unwrap();
            let err = sf.get::<Value>("limits").await.unwrap_err();

            assert!(!err.to_string().contains(token), "{err}");
            match err {
                CirrusError::Api {
                    status,
                    raw: Some(raw),
                    ..
                } => {
                    assert_eq!(status, 502);
                    assert!(!raw.contains(token), "{raw}");
                    assert!(raw.contains("Bad Gateway"));
                }
                other => panic!("expected an Api error with a raw body, got {other:?}"),
            }
        }

        #[tokio::test]
        async fn read_timeout_aborts_a_request_the_org_never_answers() {
            // The deadline is armed at dispatch, so it fires while the
            // response head is still outstanding — not just between two
            // chunks of a body that has already started arriving.
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/services/data/v66.0/limits"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(json!({"ok": true}))
                        .set_delay(Duration::from_secs(30)),
                )
                .mount(&server)
                .await;

            let auth = Arc::new(StaticTokenAuth::new("tok", server.uri()));
            let sf = Cirrus::builder()
                .auth(auth)
                .read_timeout(Duration::from_millis(50))
                .retry_policy(RetryPolicy::none())
                .build()
                .unwrap();
            let err = sf.get::<Value>("limits").await.unwrap_err();
            match err {
                CirrusError::Http(e) => assert!(e.is_timeout(), "expected a timeout, got {e}"),
                other => panic!("expected a transport error, got {other:?}"),
            }
        }
    }

    /// Retry policy + Sforce-Limit-Info header surfacing. Tests use a
    /// retry policy with zero base/max delays so they don't sleep —
    /// the retry behavior is what we're verifying, not the timing.
    mod retry_and_limits {
        use super::*;
        use crate::RetryPolicy;
        use serde_json::{Value, json};
        use std::sync::Arc;
        use std::time::Duration;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        fn fast_retry_policy() -> RetryPolicy {
            RetryPolicy {
                base_delay: Duration::ZERO,
                max_delay: Duration::ZERO,
                jitter: false,
                ..RetryPolicy::default()
            }
        }

        fn fixture_with_policy(uri: String, policy: RetryPolicy) -> Cirrus {
            let auth = Arc::new(StaticTokenAuth::new("tok", uri));
            Cirrus::builder()
                .auth(auth)
                .retry_policy(policy)
                .build()
                .unwrap()
        }

        #[tokio::test]
        async fn retries_429_until_success() {
            let server = MockServer::start().await;

            // First two attempts return 429; third returns 200.
            // wiremock matches mocks in registration order with priority,
            // so we use `up_to_n_times` to scope the 429 mock to the
            // first two requests.
            Mock::given(method("GET"))
                .and(path("/services/data/v66.0/limits"))
                .respond_with(ResponseTemplate::new(429))
                .up_to_n_times(2)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/services/data/v66.0/limits"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
                .mount(&server)
                .await;

            let sf = fixture_with_policy(server.uri(), fast_retry_policy());
            let v: Value = sf.get("limits").await.unwrap();
            assert_eq!(v["ok"], true);
        }

        #[tokio::test]
        async fn retries_503_until_success() {
            let server = MockServer::start().await;

            Mock::given(method("GET"))
                .and(path("/services/data/v66.0/limits"))
                .respond_with(ResponseTemplate::new(503))
                .up_to_n_times(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/services/data/v66.0/limits"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
                .mount(&server)
                .await;

            let sf = fixture_with_policy(server.uri(), fast_retry_policy());
            let v: Value = sf.get("limits").await.unwrap();
            assert_eq!(v["ok"], true);
        }

        #[tokio::test]
        async fn surfaces_error_after_max_retries_exhausted() {
            let server = MockServer::start().await;

            // Default policy retries 3 times → 4 total attempts.
            Mock::given(method("GET"))
                .and(path("/services/data/v66.0/limits"))
                .respond_with(ResponseTemplate::new(503).set_body_json(json!([{
                    "errorCode": "SERVER_UNAVAILABLE",
                    "message": "Service Unavailable"
                }])))
                .expect(4)
                .mount(&server)
                .await;

            let sf = fixture_with_policy(server.uri(), fast_retry_policy());
            let err = sf.get::<Value>("limits").await.unwrap_err();
            match err {
                CirrusError::Api { status, .. } => assert_eq!(status, 503),
                other => panic!("expected Api error, got {other:?}"),
            }
        }

        #[tokio::test]
        async fn does_not_retry_4xx_caller_errors() {
            let server = MockServer::start().await;

            Mock::given(method("GET"))
                .and(path("/services/data/v66.0/limits"))
                .respond_with(ResponseTemplate::new(404).set_body_json(json!([{
                    "errorCode": "NOT_FOUND",
                    "message": "not found"
                }])))
                // expect(1) — 4xx caller errors must not retry.
                .expect(1)
                .mount(&server)
                .await;

            let sf = fixture_with_policy(server.uri(), fast_retry_policy());
            let err = sf.get::<Value>("limits").await.unwrap_err();
            assert!(matches!(err, CirrusError::Api { status: 404, .. }));
        }

        #[tokio::test]
        async fn does_not_retry_500_on_post() {
            // POST is non-idempotent — on any 5xx (429 is the only
            // any-method retry) we must not replay, to avoid
            // duplicate-record creation.
            let server = MockServer::start().await;

            Mock::given(method("POST"))
                .and(path("/services/data/v66.0/sobjects/Account"))
                .respond_with(ResponseTemplate::new(500).set_body_json(json!([{
                    "errorCode": "INTERNAL_ERROR",
                    "message": "boom"
                }])))
                .expect(1)
                .mount(&server)
                .await;

            let sf = fixture_with_policy(server.uri(), fast_retry_policy());
            let err = sf
                .post::<Value, _>("sobjects/Account", &json!({"Name": "Acme"}))
                .await
                .unwrap_err();
            assert!(matches!(err, CirrusError::Api { status: 500, .. }));
        }

        #[tokio::test]
        async fn does_not_retry_503_on_post() {
            // 503 gets no special exemption from the non-idempotent
            // rule: an intermediary can emit it after the origin
            // processed the request, so replaying a POST risks a
            // duplicate insert.
            let server = MockServer::start().await;

            Mock::given(method("POST"))
                .and(path("/services/data/v66.0/sobjects/Account"))
                .respond_with(ResponseTemplate::new(503))
                .expect(1)
                .mount(&server)
                .await;

            let sf = fixture_with_policy(server.uri(), fast_retry_policy());
            let err = sf
                .post::<Value, _>("sobjects/Account", &json!({"Name": "Acme"}))
                .await
                .unwrap_err();
            assert!(matches!(err, CirrusError::Api { status: 503, .. }));
        }

        #[tokio::test]
        async fn retries_500_on_get_when_idempotent_5xx_enabled() {
            let server = MockServer::start().await;

            Mock::given(method("GET"))
                .and(path("/services/data/v66.0/limits"))
                .respond_with(ResponseTemplate::new(500))
                .up_to_n_times(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/services/data/v66.0/limits"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
                .mount(&server)
                .await;

            let sf = fixture_with_policy(server.uri(), fast_retry_policy());
            let v: Value = sf.get("limits").await.unwrap();
            assert_eq!(v["ok"], true);
        }

        #[tokio::test]
        async fn none_policy_disables_retries_entirely() {
            let server = MockServer::start().await;

            Mock::given(method("GET"))
                .and(path("/services/data/v66.0/limits"))
                .respond_with(ResponseTemplate::new(429))
                .expect(1)
                .mount(&server)
                .await;

            let sf = fixture_with_policy(server.uri(), RetryPolicy::none());
            let err = sf.get::<Value>("limits").await.unwrap_err();
            assert!(matches!(err, CirrusError::Api { status: 429, .. }));
        }

        #[tokio::test]
        async fn retries_a_response_body_that_stops_mid_stream() {
            // wiremock always sends a complete body, so this serves the
            // truncated response from a raw socket: headers promising 40
            // bytes, 5 bytes of body, then a hang-up. Replaying the GET
            // is safe, and the retry budget is untouched at that point.
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let mut buf = [0u8; 2048];

                let (mut sock, _) = listener.accept().await.unwrap();
                let _ = sock.read(&mut buf).await;
                sock.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 40\r\n\r\n{\"ok\"",
                )
                .await
                .unwrap();
                sock.flush().await.unwrap();
                drop(sock);

                let (mut sock, _) = listener.accept().await.unwrap();
                let _ = sock.read(&mut buf).await;
                sock.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{\"ok\":true}",
                )
                .await
                .unwrap();
                sock.flush().await.unwrap();
                tokio::time::sleep(Duration::from_millis(100)).await;
            });

            let sf = fixture_with_policy(format!("http://{addr}"), fast_retry_policy());
            let v: Value = sf.get("limits").await.unwrap();
            assert_eq!(v["ok"], true);
            server.await.unwrap();
        }

        #[tokio::test]
        async fn captures_sforce_limit_info_on_response() {
            let server = MockServer::start().await;

            Mock::given(method("GET"))
                .and(path("/services/data/v66.0/limits"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(json!({"ok": true}))
                        .insert_header("Sforce-Limit-Info", "api-usage=42/15000"),
                )
                .mount(&server)
                .await;

            let sf = fixture_with_policy(server.uri(), RetryPolicy::none());
            // Before any request, no info captured.
            assert!(sf.last_limit_info().is_none());

            let _: Value = sf.get("limits").await.unwrap();

            let info = sf.last_limit_info().expect("limit info should be set");
            assert_eq!(info.used, 42);
            assert_eq!(info.allowed, 15000);
            assert_eq!(info.remaining(), 14958);
        }

        #[tokio::test]
        async fn limit_info_updates_on_subsequent_requests() {
            let server = MockServer::start().await;

            Mock::given(method("GET"))
                .and(path("/services/data/v66.0/limits"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(json!({"ok": true}))
                        .insert_header("Sforce-Limit-Info", "api-usage=10/100"),
                )
                .up_to_n_times(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/services/data/v66.0/limits"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(json!({"ok": true}))
                        .insert_header("Sforce-Limit-Info", "api-usage=11/100"),
                )
                .mount(&server)
                .await;

            let sf = fixture_with_policy(server.uri(), RetryPolicy::none());
            let _: Value = sf.get("limits").await.unwrap();
            assert_eq!(sf.last_limit_info().unwrap().used, 10);
            let _: Value = sf.get("limits").await.unwrap();
            assert_eq!(sf.last_limit_info().unwrap().used, 11);
        }

        #[tokio::test]
        async fn malformed_limit_info_header_is_ignored() {
            let server = MockServer::start().await;

            Mock::given(method("GET"))
                .and(path("/services/data/v66.0/limits"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(json!({"ok": true}))
                        // Wrong key, missing slash, etc. — just garbage.
                        .insert_header("Sforce-Limit-Info", "junk-data=oops"),
                )
                .mount(&server)
                .await;

            let sf = fixture_with_policy(server.uri(), RetryPolicy::none());
            let _: Value = sf.get("limits").await.unwrap();
            // Header didn't parse → no info stored.
            assert!(sf.last_limit_info().is_none());
        }

        #[tokio::test]
        async fn retry_after_header_overrides_backoff() {
            // The Retry-After hint, if present, takes precedence over
            // the policy's exponential schedule. We don't test the
            // *duration* directly (jitter would muddy that anyway) —
            // we just verify the retry happens and the request count
            // advances.
            let server = MockServer::start().await;

            Mock::given(method("GET"))
                .and(path("/services/data/v66.0/limits"))
                .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "0"))
                .up_to_n_times(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/services/data/v66.0/limits"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
                .mount(&server)
                .await;

            let sf = fixture_with_policy(server.uri(), fast_retry_policy());
            let v: Value = sf.get("limits").await.unwrap();
            assert_eq!(v["ok"], true);
        }
    }

    /// Auto-refresh on 401. Uses a custom AuthSession impl that hands
    /// out a different token on each `access_token()` call so we can
    /// observe the SDK switching tokens after invalidation.
    mod auth_refresh {
        use super::*;
        use crate::auth::{AuthResult, AuthSession, SharedAuth};
        use async_trait::async_trait;
        use serde_json::{Value, json};
        use std::borrow::Cow;
        use std::sync::Arc;
        use std::sync::Mutex;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        /// Test-only AuthSession that yields tokens from a sequence,
        /// counts `access_token()` calls, and tracks `invalidate()`
        /// calls. Subsequent calls past the end of the sequence
        /// return the last token (so a static-token-equivalent can be
        /// modeled by passing a single-element sequence).
        struct RotatingAuth {
            instance_url: String,
            tokens: Vec<String>,
            access_count: AtomicUsize,
            invalidations: Mutex<Vec<String>>,
        }

        impl RotatingAuth {
            fn new(instance_url: impl Into<String>, tokens: Vec<&str>) -> Self {
                Self {
                    instance_url: instance_url.into(),
                    tokens: tokens.into_iter().map(String::from).collect(),
                    access_count: AtomicUsize::new(0),
                    invalidations: Mutex::new(Vec::new()),
                }
            }
        }

        #[async_trait]
        impl AuthSession for RotatingAuth {
            async fn access_token(&self) -> AuthResult<Cow<'_, str>> {
                let n = self.access_count.fetch_add(1, Ordering::SeqCst);
                let idx = n.min(self.tokens.len() - 1);
                Ok(Cow::Borrowed(&self.tokens[idx]))
            }

            fn instance_url(&self) -> &str {
                &self.instance_url
            }

            async fn invalidate(&self, stale_token: &str) {
                if let Ok(mut g) = self.invalidations.lock() {
                    g.push(stale_token.to_string());
                }
            }
        }

        fn fixture(_uri: String, auth: SharedAuth) -> Cirrus {
            // _uri unused here — the AuthSession's instance_url drives
            // URL resolution. Keep the param for symmetry with other
            // test fixtures; the caller already has the server URI in
            // hand from MockServer::start.
            Cirrus::builder()
                .auth(auth)
                .retry_policy(crate::RetryPolicy::none()) // isolate auth-retry from transient-retry
                .build()
                .unwrap()
        }

        #[tokio::test]
        async fn refreshes_token_on_401_and_retries_once() {
            let server = MockServer::start().await;

            // First request (Bearer old): 401. Second (Bearer new): 200.
            Mock::given(method("GET"))
                .and(path("/services/data/v66.0/limits"))
                .and(header("authorization", "Bearer old"))
                .respond_with(ResponseTemplate::new(401).set_body_json(json!([{
                    "errorCode": "INVALID_SESSION_ID",
                    "message": "Session expired or invalid"
                }])))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/services/data/v66.0/limits"))
                .and(header("authorization", "Bearer new"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
                .expect(1)
                .mount(&server)
                .await;

            let auth = Arc::new(RotatingAuth::new(server.uri(), vec!["old", "new"]));
            let sf = fixture(server.uri(), auth.clone());

            let v: Value = sf.get("limits").await.unwrap();
            assert_eq!(v["ok"], true);

            // Verify the auth session saw the stale token.
            let inv = auth.invalidations.lock().unwrap();
            assert_eq!(inv.len(), 1);
            assert_eq!(inv[0], "old");
        }

        #[tokio::test]
        async fn transient_retry_budget_resets_after_auth_refresh() {
            // Each auth pass gets its own full transient-retry budget.
            // With max_retries = 1, pass one spends its whole budget on
            // the first 503 — the post-refresh 503 is only survivable
            // if the attempt counter reset alongside the token.
            let server = MockServer::start().await;

            // Pass 1 (Bearer old): 503 → transient retry → 401 → refresh.
            Mock::given(method("GET"))
                .and(path("/services/data/v66.0/limits"))
                .and(header("authorization", "Bearer old"))
                .respond_with(ResponseTemplate::new(503))
                .up_to_n_times(1)
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/services/data/v66.0/limits"))
                .and(header("authorization", "Bearer old"))
                .respond_with(ResponseTemplate::new(401).set_body_json(json!([{
                    "errorCode": "INVALID_SESSION_ID",
                    "message": "Session expired or invalid"
                }])))
                .expect(1)
                .mount(&server)
                .await;
            // Pass 2 (Bearer new): 503 → transient retry → 200.
            Mock::given(method("GET"))
                .and(path("/services/data/v66.0/limits"))
                .and(header("authorization", "Bearer new"))
                .respond_with(ResponseTemplate::new(503))
                .up_to_n_times(1)
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/services/data/v66.0/limits"))
                .and(header("authorization", "Bearer new"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
                .expect(1)
                .mount(&server)
                .await;

            let auth = Arc::new(RotatingAuth::new(server.uri(), vec!["old", "new"]));
            let sf = Cirrus::builder()
                .auth(auth.clone())
                .retry_policy(crate::RetryPolicy {
                    max_retries: 1,
                    base_delay: std::time::Duration::ZERO,
                    max_delay: std::time::Duration::ZERO,
                    jitter: false,
                    ..crate::RetryPolicy::default()
                })
                .build()
                .unwrap();

            let v: Value = sf.get("limits").await.unwrap();
            assert_eq!(v["ok"], true);

            let inv = auth.invalidations.lock().unwrap();
            assert_eq!(*inv, vec!["old"]);
        }

        #[tokio::test]
        async fn surfaces_401_when_refresh_returns_same_token() {
            // Static-auth-equivalent: even after invalidation, the
            // session can only produce the same token. Don't loop —
            // surface the original 401.
            let server = MockServer::start().await;

            Mock::given(method("GET"))
                .and(path("/services/data/v66.0/limits"))
                .respond_with(ResponseTemplate::new(401).set_body_json(json!([{
                    "errorCode": "INVALID_SESSION_ID",
                    "message": "..."
                }])))
                // Exactly 1 — no auth-retry should fire because the
                // post-invalidate token is identical to the stale one.
                .expect(1)
                .mount(&server)
                .await;

            let auth = Arc::new(RotatingAuth::new(server.uri(), vec!["only"]));
            let sf = fixture(server.uri(), auth);

            let err = sf.get::<Value>("limits").await.unwrap_err();
            assert!(matches!(err, CirrusError::Api { status: 401, .. }));
        }

        #[tokio::test]
        async fn second_401_after_refresh_surfaces_without_third_attempt() {
            // After auth-retry, a *second* 401 means the issue isn't
            // token expiry — it's permission/scope. Don't loop forever.
            let server = MockServer::start().await;

            // Both Bearer values get 401.
            Mock::given(method("GET"))
                .and(path("/services/data/v66.0/limits"))
                .respond_with(ResponseTemplate::new(401).set_body_json(json!([{
                    "errorCode": "INSUFFICIENT_ACCESS",
                    "message": "..."
                }])))
                .expect(2)
                .mount(&server)
                .await;

            let auth = Arc::new(RotatingAuth::new(server.uri(), vec!["t1", "t2"]));
            let sf = fixture(server.uri(), auth);

            let err = sf.get::<Value>("limits").await.unwrap_err();
            assert!(matches!(err, CirrusError::Api { status: 401, .. }));
        }

        #[tokio::test]
        async fn does_not_invalidate_on_non_401_errors() {
            // 403, 404, 500, etc. should NOT invalidate the auth
            // session — that's reserved for INVALID_SESSION_ID.
            let server = MockServer::start().await;

            Mock::given(method("GET"))
                .and(path("/services/data/v66.0/limits"))
                .respond_with(ResponseTemplate::new(403).set_body_json(json!([{
                    "errorCode": "INSUFFICIENT_ACCESS",
                    "message": "..."
                }])))
                .expect(1)
                .mount(&server)
                .await;

            let auth = Arc::new(RotatingAuth::new(server.uri(), vec!["t1", "t2"]));
            let sf = fixture(server.uri(), auth.clone());

            let _ = sf.get::<Value>("limits").await;

            // No invalidation should have happened on a 403.
            let inv = auth.invalidations.lock().unwrap();
            assert!(inv.is_empty());
        }
    }
}

/// Property tests for load-bearing URL/path helpers. These guard the
/// trailing-slash, double-slash, and percent-encoding invariants that
/// would otherwise be infinitely re-rediscoverable through targeted
/// unit tests. The trailing-slash bug we hit during sObject CRUD
/// (`.../v66.0//sobjects/...`) would have been caught by the no-double-
/// slash property below.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod property_tests {
    use super::*;
    use crate::auth::StaticTokenAuth;
    use proptest::prelude::*;
    use std::sync::Arc;

    fn fixture(instance: &str) -> Cirrus {
        let auth = Arc::new(StaticTokenAuth::new("tok", instance));
        Cirrus::builder().auth(auth).build().unwrap()
    }

    /// Path-shaped strings: ASCII alphanumerics plus characters that
    /// have historically tripped percent-encoding, *but with no run
    /// of `//`* — that's a caller-malformed input, not within the
    /// well-formed contract `resolve_url` operates on.
    fn path_segment() -> impl Strategy<Value = String> {
        "[A-Za-z0-9_./%=&+-]{1,32}".prop_filter("no double-slash runs in well-formed paths", |s| {
            !s.contains("//")
        })
    }

    /// Unreserved-only segment for `versioned_segments` round-trip
    /// properties — keeps the raw segment comparison free of percent-
    /// encoding noise. A separate non-property test pins the encoding
    /// behavior for reserved chars.
    fn nonempty_segment() -> impl Strategy<Value = String> {
        "[A-Za-z0-9_-]{1,32}"
    }

    /// Segment strategy that reaches the dot-segment forms URL path
    /// resolution treats specially, for the "no segment ever vanishes"
    /// property below.
    fn maybe_dotted_segment() -> impl Strategy<Value = String> {
        prop_oneof![
            "[A-Za-z0-9_-]{1,8}",
            "\\.{1,3}",
            "[A-Za-z0-9_-]{0,4}\\.[A-Za-z0-9_-]{0,4}",
        ]
        .prop_filter("segments are non-empty", |s: &String| !s.is_empty())
    }

    proptest! {
        /// For any non-fully-qualified path, `resolve_url` produces a
        /// URL that parses cleanly and never contains a `//` outside
        /// the scheme separator. This is the trailing-slash regression
        /// invariant.
        #[test]
        fn resolve_url_never_emits_double_slash(path in path_segment()) {
            let sf = fixture("https://my.salesforce.com");
            let url = sf.resolve_url(&path);
            // Strip the scheme separator first, then check for '//'.
            let after_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(&url);
            prop_assert!(
                !after_scheme.contains("//"),
                "resolve_url({path:?}) produced double slash: {url}",
            );
            prop_assert!(url::Url::parse(&url).is_ok(), "url should parse: {url}");
        }

        /// Fully-qualified URLs pass through `resolve_url` unchanged.
        /// This is the locator-passthrough contract (`nextRecordsUrl`,
        /// Bulk 2.0 result locators).
        #[test]
        fn resolve_url_passes_through_absolute_urls(host in "[a-z0-9-]{1,20}", path in path_segment()) {
            let sf = fixture("https://my.salesforce.com");
            let absolute = format!("https://{host}.example.com/{path}");
            prop_assert_eq!(sf.resolve_url(&absolute), absolute);
        }

        /// Leading-slash paths resolve against the instance URL, not
        /// the versioned data path. Verifies the three-mode dispatch
        /// doesn't accidentally version-prefix an instance-rooted path.
        /// `rest` is the part *after* the leading slash, so it must not
        /// itself start with `/` (we strip runs of leading slashes —
        /// see `resolve_url_never_emits_double_slash`).
        #[test]
        fn resolve_url_instance_rooted_skips_version(
            rest in path_segment().prop_filter("rest follows the leading slash", |s| !s.starts_with('/')),
        ) {
            let sf = fixture("https://my.salesforce.com");
            let url = sf.resolve_url(&format!("/{rest}"));
            prop_assert_eq!(url, format!("https://my.salesforce.com/{rest}"));
        }

        /// `versioned_segments` produces a URL where each segment is
        /// recoverable via the parsed `Url::path_segments`. This is the
        /// percent-encoding round-trip property used by upsert-by-
        /// external-ID with reserved characters in the value.
        #[test]
        fn versioned_segments_round_trip(
            seg1 in nonempty_segment(),
            seg2 in nonempty_segment(),
        ) {
            let sf = fixture("https://my.salesforce.com");
            let url_str = sf.versioned_segments(&[&seg1, &seg2]).unwrap();
            let parsed = url::Url::parse(&url_str).unwrap();
            let segments: Vec<&str> = parsed
                .path_segments()
                .map(|s| s.collect())
                .unwrap_or_default();
            // Expected layout: ["services", "data", "{version}", seg1, seg2]
            prop_assert_eq!(segments.len(), 5, "got segments {:?} from {}", segments, url_str);
            prop_assert_eq!(segments[0], "services");
            prop_assert_eq!(segments[1], "data");
            // segments[2] is the api version; we don't assert on it
            // because that's not what this property is about.
            // Unreserved-only strategy means segments compare raw.
            prop_assert_eq!(segments[3], seg1);
            prop_assert_eq!(segments[4], seg2);
        }

        /// `versioned_segments` either keeps every segment it was given
        /// or refuses the call — it never returns a URL that is a
        /// segment short. Dot segments are the way that happens:
        /// URL path resolution drops them instead of encoding them.
        #[test]
        fn versioned_segments_never_silently_drops_a_segment(
            segs in proptest::collection::vec(maybe_dotted_segment(), 1..5),
        ) {
            let sf = fixture("https://my.salesforce.com");
            let refs: Vec<&str> = segs.iter().map(String::as_str).collect();
            match sf.versioned_segments(&refs) {
                Ok(url_str) => {
                    let parsed = url::Url::parse(&url_str).unwrap();
                    let segments: Vec<&str> = parsed
                        .path_segments()
                        .map(|s| s.collect())
                        .unwrap_or_default();
                    // ["services", "data", "{version}", ..segs]
                    prop_assert_eq!(
                        segments.len(),
                        3 + segs.len(),
                        "segments {:?} lost a component: {}",
                        segs,
                        url_str,
                    );
                }
                Err(e) => prop_assert!(
                    matches!(e, CirrusError::InvalidInput { .. }),
                    "unexpected error {e:?}",
                ),
            }
        }

        /// `versioned_segments` never emits double slashes between
        /// segments. The pop_if_empty trick guards against that; this
        /// property pins it.
        #[test]
        fn versioned_segments_never_emits_double_slash(
            segs in proptest::collection::vec(nonempty_segment(), 1..6),
        ) {
            let sf = fixture("https://my.salesforce.com");
            let refs: Vec<&str> = segs.iter().map(String::as_str).collect();
            let url = sf.versioned_segments(&refs).unwrap();
            let after_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(&url);
            prop_assert!(
                !after_scheme.contains("//"),
                "got double slash in {url}",
            );
        }
    }

    /// Targeted regression: a `.` or `..` external-ID value must not
    /// silently shorten the URL. `PATCH .../sobjects/Account/Ext__c/.`
    /// would otherwise resolve to the sObject Rows resource with
    /// `Ext__c` read as the record ID.
    #[test]
    fn versioned_segments_rejects_relative_path_references() {
        let sf = fixture("https://my.salesforce.com");
        for value in [".", ".."] {
            let err = sf
                .versioned_segments(&["sobjects", "Account", "Ext_Id__c", value])
                .unwrap_err();
            match err {
                CirrusError::InvalidInput { field, message } => {
                    assert_eq!(field, "path segment");
                    assert!(message.contains(value), "message should name the segment");
                }
                other => panic!("expected InvalidInput, got {other:?}"),
            }
        }
    }

    /// Targeted regression: reserved characters in path segments must
    /// be percent-encoded so the segment boundary survives. The upsert-
    /// by-external-ID case with a `/` in the value depends on this.
    #[test]
    fn versioned_segments_percent_encodes_reserved_slash() {
        let sf = fixture("https://my.salesforce.com");
        // Pretend an external-ID value contains a slash.
        let url = sf
            .versioned_segments(&["sobjects", "Account", "Ext_Id__c", "abc/def"])
            .unwrap();
        // Must NOT split into an extra path segment.
        let parsed = url::Url::parse(&url).unwrap();
        let segs: Vec<&str> = parsed.path_segments().unwrap().collect();
        assert_eq!(
            segs.len(),
            7,
            "expected 7 segments (services, data, version, sobjects, Account, Ext_Id__c, abc%2Fdef), got {segs:?}",
        );
        assert!(
            segs[6].contains("%2F") || segs[6].contains("%2f"),
            "slash in external-ID value must be percent-encoded; got {:?}",
            segs[6],
        );
    }
}
