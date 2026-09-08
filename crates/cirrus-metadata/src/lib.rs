//! # `cirrus-metadata`
//!
//! A Rust client for the Salesforce **Metadata API** (SOAP). Built on top of
//! [`cirrus_auth`] for credentials, so any `AuthSession` configured for the
//! REST client (`cirrus`) works here too.
//!
//! Covered surface: the file-based deploy/retrieve flow, synchronous CRUD
//! (`createMetadata` / `readMetadata` / `updateMetadata` /
//! `upsertMetadata` / `deleteMetadata` / `renameMetadata`), the utility
//! surface (`listMetadata` / `describeMetadata` / `describeValueType`),
//! and a typed [`PackageManifest`] builder.
//!
//! ## Why SOAP?
//!
//! The Metadata API's REST surface only covers four `deployRequest`
//! endpoints. Everything else — `retrieve`, `listMetadata`,
//! `describeMetadata`, `createMetadata`, `readMetadata`, etc. — is
//! SOAP-only. SOAP is not deprecated; it's the canonical surface.
//!
//! ## Design principles
//!
//! - **No user-facing types.** The 200+ concrete metadata types
//!   (`CustomObject`, `ApexClass`, …) are caller-supplied XML or
//!   `serde_json::Value`. Only platform-contract envelopes are typed.
//! - **No legacy surface.** Operations Salesforce labels deprecated
//!   (`create()`, `update()`, `delete()` pre-API-31) are not exposed.
//! - **Auth is pluggable.** Any [`cirrus_auth::AuthSession`] works.
//! - **Same credentials as `cirrus`.** Both crates wrap the same
//!   `AuthSession` trait; one [`SharedAuth`] drives both clients.
//!
//! ## Quick start
//!
//! ```no_run
//! use cirrus_metadata::{MetadataClient, auth::StaticTokenAuth};
//! use std::sync::Arc;
//!
//! # async fn example() -> Result<(), cirrus_metadata::MetadataError> {
//! let auth = Arc::new(StaticTokenAuth::new(
//!     "00D...!AQ...",
//!     "https://my-org.my.salesforce.com",
//! ));
//!
//! let md = MetadataClient::builder()
//!     .auth(auth)
//!     .build()?;
//!
//! # let _ = md;
//! # Ok(())
//! # }
//! ```
//!
//! [`SharedAuth`]: cirrus_auth::SharedAuth

mod envelope;
mod error;
pub mod handlers;
mod package_manifest;
pub mod result;
pub mod retry;
mod transport;

/// Re-export of the [`cirrus_auth`] crate as `cirrus_metadata::auth`.
///
/// Users who add `cirrus-metadata` without `cirrus` get the auth flows
/// transparently. The re-exported types are byte-identical to
/// `cirrus::auth::*` since both crates re-export the same source.
pub use cirrus_auth as auth;

/// Re-export of [`reqwest`].
///
/// Several public APIs accept or return `reqwest` types
/// ([`MetadataClient::request_builder`],
/// [`MetadataClientBuilder::http_client`]). Using this re-export
/// instead of a separate `reqwest` dependency keeps the caller's
/// `reqwest` version aligned with the SDK's.
pub use reqwest;

pub use auth::{AuthError, AuthSession, SharedAuth};
pub use error::{MetadataError, MetadataResult, SoapFault};
pub use handlers::file_based::WaitConfig;
pub use package_manifest::{MetadataType, PackageManifest};
pub use result::{
    AsyncRequestState, AsyncResult, CancelDeployResult, CodeCoverageResult, CodeCoverageWarning,
    DeleteResult, DeployDetails, DeployMessage, DeployOptions, DeployProblemType, DeployResult,
    DeployStatus, DescribeMetadataObject, DescribeMetadataResult, DescribeValueTypeResult,
    FileProperties, ListMetadataQuery, ManageableState, MetadataApiError, PicklistEntry,
    RetrieveMessage, RetrieveRequest, RetrieveResult, RetrieveStatus, RunTestFailure,
    RunTestSuccess, RunTestsResult, SaveResult, TestLevel, UpsertResult, ValueTypeField,
};
pub use retry::RetryPolicy;
pub use transport::SoapOperation;

/// Default Metadata API version when the caller doesn't override it.
///
/// SOAP endpoint paths use bare version numbers without the `v` prefix
/// (`/services/Soap/m/66.0`).
pub const DEFAULT_API_VERSION: &str = "66.0";

/// Deadline for establishing a connection to the SOAP endpoint.
const DEFAULT_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Deadline for each read from an open response body.
///
/// A per-read deadline rather than a whole-request one: a retrieve can
/// legitimately stream tens of megabytes of base64 zip, so the transfer
/// gets as long as it needs while a peer that stops sending altogether
/// still surfaces an error the retry policy can act on.
const DEFAULT_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Default User-Agent header sent on every request.
pub(crate) const DEFAULT_USER_AGENT: &str = concat!(
    "cirrus-metadata/",
    env!("CARGO_PKG_VERSION"),
    " (Rust SDK for Salesforce Metadata API)"
);

use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT};

/// The Metadata API client.
///
/// Holds an HTTP client, an [`AuthSession`] for credentials, the API
/// version to target, and a [`RetryPolicy`] for transient-failure
/// handling. Cheap to clone — the auth session is `Arc`-shared and the
/// HTTP client is internally reference-counted.
#[derive(Clone)]
pub struct MetadataClient {
    pub(crate) http: reqwest::Client,
    pub(crate) auth: SharedAuth,
    pub(crate) api_version: String,
    pub(crate) retry_policy: RetryPolicy,
}

impl std::fmt::Debug for MetadataClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Mirror cirrus::Cirrus: omit `auth` (may carry secrets) and
        // the reqwest client (no useful Debug).
        f.debug_struct("MetadataClient")
            .field("api_version", &self.api_version)
            .field("instance_url", &self.auth.instance_url())
            .field("retry_policy", &self.retry_policy)
            .finish_non_exhaustive()
    }
}

impl MetadataClient {
    /// Returns a builder for constructing a [`MetadataClient`].
    pub fn builder() -> MetadataClientBuilder {
        MetadataClientBuilder::default()
    }

    /// Returns the configured Metadata API version (e.g. `"66.0"`).
    pub fn api_version(&self) -> &str {
        &self.api_version
    }

    /// Returns a reference to the underlying `reqwest` client. Useful
    /// for callers who want to compose additional requests against the
    /// same connection pool.
    pub fn http_client(&self) -> &reqwest::Client {
        &self.http
    }

    /// Returns the auth session backing this client.
    pub fn auth(&self) -> &SharedAuth {
        &self.auth
    }

    /// Returns the configured retry policy.
    pub fn retry_policy(&self) -> &RetryPolicy {
        &self.retry_policy
    }

    /// Returns the fully-resolved SOAP endpoint URL for this client,
    /// e.g. `https://my-org.my.salesforce.com/services/Soap/m/66.0`.
    ///
    /// The instance URL is read from the configured [`AuthSession`] on
    /// every call, so it reflects the *current* session — relevant for
    /// flows that can change instance URL on refresh (e.g. some token
    /// exchange scenarios).
    pub fn endpoint_url(&self) -> String {
        format!(
            "{}/services/Soap/m/{}",
            self.auth.instance_url(),
            self.api_version
        )
    }

    /// Returns a pre-configured `reqwest::RequestBuilder` for the SOAP
    /// endpoint, with `Content-Type` and `SOAPAction` already set.
    ///
    /// The bearer token is **not** injected — the Metadata API expects
    /// it inside the envelope's `<SessionHeader>`, not on the
    /// `Authorization` header. Fetch it via
    /// `client.auth().access_token().await?` and splice it into your
    /// envelope.
    ///
    /// **Security note:** because the token travels in the request
    /// *body*, redacting the `Authorization` header is not enough —
    /// any middleware or proxy that logs request bodies will capture
    /// the session token in plaintext. This applies to every request
    /// this client sends, including the typed [`call`](Self::call)
    /// path.
    ///
    /// Use this only when you need to bypass the typed
    /// [`SoapOperation`] path entirely (e.g. to record raw traffic).
    pub fn request_builder(&self) -> reqwest::RequestBuilder {
        self.http
            .post(self.endpoint_url())
            .header(reqwest::header::CONTENT_TYPE, "text/xml; charset=UTF-8")
            .header("SOAPAction", "\"\"")
    }

    /// Dispatch a typed SOAP operation.
    ///
    /// This is the entry point handlers use; it builds the envelope,
    /// POSTs, retries transient failures per the configured
    /// [`RetryPolicy`], refreshes the auth token on
    /// `INVALID_SESSION_ID` faults, and deserializes the response into
    /// `O::Response`. Returns [`MetadataError::Soap`] for server-side
    /// faults and [`MetadataError::Http`] / [`MetadataError::Http4xx5xx`]
    /// for transport-level failures.
    ///
    /// The session token travels inside the SOAP envelope (the request
    /// *body*) — see the security note on
    /// [`request_builder`](Self::request_builder) before wiring
    /// body-logging middleware around this client.
    pub async fn call<O: SoapOperation>(&self, op: &O) -> MetadataResult<O::Response> {
        transport::soap_call(self, op).await
    }
}

/// Builder for [`MetadataClient`].
///
/// Required: an [`AuthSession`] via [`auth`](Self::auth). Everything
/// else has a sensible default.
#[derive(Default)]
pub struct MetadataClientBuilder {
    auth: Option<SharedAuth>,
    api_version: Option<String>,
    user_agent: Option<String>,
    http_client: Option<reqwest::Client>,
    retry_policy: Option<RetryPolicy>,
}

impl MetadataClientBuilder {
    /// Sets the auth session (any [`AuthSession`] wrapped in `Arc`).
    /// Required.
    pub fn auth(mut self, auth: SharedAuth) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Sets the Metadata API version, e.g. `"66.0"`. Defaults to
    /// [`DEFAULT_API_VERSION`]. Note: SOAP endpoint paths use the bare
    /// number without a `v` prefix.
    pub fn api_version(mut self, version: impl Into<String>) -> Self {
        self.api_version = Some(version.into());
        self
    }

    /// Overrides the default User-Agent header. Ignored if
    /// [`http_client`](Self::http_client) is set.
    pub fn user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = Some(ua.into());
        self
    }

    /// Supplies a pre-configured `reqwest::Client`. Useful for sharing
    /// a connection pool across multiple SDK clients or for installing
    /// custom middleware. When provided, the builder's `user_agent`
    /// setting is ignored — configure that on the supplied client.
    ///
    /// The supplied client also brings its own timeouts and redirect
    /// policy. The client this builder constructs otherwise sets a
    /// 30 s connect timeout, a 60 s read timeout, and disables redirects
    /// so the session token in the SOAP envelope is never re-POSTed to a
    /// redirect target; a client configured here should do the same
    /// unless you have a reason not to.
    pub fn http_client(mut self, client: reqwest::Client) -> Self {
        self.http_client = Some(client);
        self
    }

    /// Sets the [`RetryPolicy`] for transient-failure handling.
    pub fn retry_policy(mut self, policy: RetryPolicy) -> Self {
        self.retry_policy = Some(policy);
        self
    }

    /// Finalizes the builder.
    pub fn build(self) -> MetadataResult<MetadataClient> {
        let auth = self.auth.ok_or(MetadataError::MissingField("auth"))?;

        let http = if let Some(c) = self.http_client {
            c
        } else {
            let ua = self.user_agent.as_deref().unwrap_or(DEFAULT_USER_AGENT);
            let mut headers = HeaderMap::new();
            headers.insert(
                USER_AGENT,
                HeaderValue::from_str(ua)
                    .map_err(|e| MetadataError::InvalidHeader(e.to_string()))?,
            );
            reqwest::Client::builder()
                .default_headers(headers)
                .connect_timeout(DEFAULT_CONNECT_TIMEOUT)
                .read_timeout(DEFAULT_READ_TIMEOUT)
                // The Metadata API carries the session token in the
                // request body, where a redirect's cross-host header
                // stripping can't reach it. Surfacing a 3xx as an error
                // beats re-POSTing the envelope — token included — to
                // whatever host the Location named.
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(MetadataError::HttpClient)?
        };

        Ok(MetadataClient {
            http,
            auth,
            api_version: self
                .api_version
                .unwrap_or_else(|| DEFAULT_API_VERSION.to_string()),
            retry_policy: self.retry_policy.unwrap_or_default(),
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn builder_requires_auth() {
        let err = MetadataClient::builder().build().unwrap_err();
        assert!(matches!(err, MetadataError::MissingField("auth")));
    }

    #[test]
    fn endpoint_url_uses_bare_version_no_v_prefix() {
        let auth = Arc::new(auth::StaticTokenAuth::new(
            "tok",
            "https://my-org.my.salesforce.com",
        ));
        let md = MetadataClient::builder().auth(auth).build().unwrap();
        assert_eq!(
            md.endpoint_url(),
            "https://my-org.my.salesforce.com/services/Soap/m/66.0"
        );
    }

    #[test]
    fn endpoint_url_honors_custom_api_version() {
        let auth = Arc::new(auth::StaticTokenAuth::new("tok", "https://x.example.com"));
        let md = MetadataClient::builder()
            .auth(auth)
            .api_version("58.0")
            .build()
            .unwrap();
        assert!(md.endpoint_url().ends_with("/services/Soap/m/58.0"));
    }

    #[test]
    fn debug_redacts_auth_and_client() {
        let auth = Arc::new(auth::StaticTokenAuth::new(
            "secret-token",
            "https://x.example.com",
        ));
        let md = MetadataClient::builder().auth(auth).build().unwrap();
        let dbg = format!("{md:?}");
        assert!(!dbg.contains("secret-token"));
    }
}
