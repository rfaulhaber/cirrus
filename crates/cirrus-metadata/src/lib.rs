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
//! the SOAP headers (`CallOptions`, `AllOrNoneHeader`,
//! `DebuggingHeader` and the `DebuggingInfo` response header), and a
//! typed [`PackageManifest`] builder.
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
//! ## Transport contract
//!
//! The session id travels inside every SOAP envelope, so the instance
//! URL must be `https`; exact `localhost` and the loopback literals are
//! the only exemption, for local mock servers, and it holds only while
//! no [`MetadataClientBuilder::proxy`] is configured. The rule is the one
//! `cirrus` applies, from [`cirrus_auth::transport`], checked when the
//! client is built and again on every call because an [`AuthSession`]
//! may change its instance URL. [`MetadataClientBuilder::allow_insecure_transport`]
//! is the opt-out for a deliberate plaintext hop. The HTTP client the
//! builder creates follows no redirects and uses no proxy unless one is
//! configured, and a `Retry-After` hint longer
//! than the policy's `max_delay` ends the retry loop instead of being
//! shortened. Response bodies are read through
//! [`cirrus_auth::transport::collect_body`] and buffered only up to a
//! limit on their decoded size: 2xx bodies up to
//! [`MetadataClientBuilder::max_response_size`]
//! ([`DEFAULT_MAX_RESPONSE_SIZE`] by default), anything else up to a
//! fixed 256 KiB.
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
mod headers;
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

/// Re-export of [`bytes::Bytes`].
///
/// [`MetadataClient::deploy`] takes the deployment zip as `Bytes` and
/// [`RetrieveResult::zip_bytes`] hands the retrieved zip back the same
/// way, so naming the type doesn't need a separate `bytes` dependency.
pub use bytes::Bytes;

/// Re-export of `base64::DecodeError`, the
/// [`source()`](std::error::Error::source) of
/// [`MetadataError::ZipDecode`], which [`RetrieveResult::zip_bytes`]
/// returns when the server's base64-encoded zip can't be decoded.
///
/// Renamed here because "decode error" alone is ambiguous at the crate
/// root; it is the same type `base64` exports, so downcasting the
/// source or matching on its variants needs no separate `base64`
/// dependency.
pub use base64::DecodeError as Base64DecodeError;

/// Re-export of [`quick_xml`].
///
/// [`MetadataError`] converts from `quick_xml::Error` and
/// `quick_xml::DeError`, so a custom [`SoapOperation`] can `?` either
/// out of its `render_body` or response handling; this re-export lets
/// that code name the types without adding `quick-xml` to its own
/// manifest, and keeps the version aligned with the SDK's.
pub use quick_xml;

pub use auth::{AuthError, AuthSession, SharedAuth};
pub use envelope::xml_escape;
pub use error::{MetadataError, MetadataResult, SoapFault};
pub use handlers::crud::CrudOptions;
pub use handlers::file_based::WaitConfig;
pub use headers::{
    DebuggingHeader, DebuggingInfo, LogCategory, LogCategoryLevel, LogInfo, SoapResponseHeaders,
};
pub use package_manifest::{MetadataType, PackageManifest};
pub use result::{
    AsyncRequestState, AsyncResult, CancelDeployResult, CodeCoverageResult, CodeCoverageWarning,
    CodeLocation, DeleteResult, DeployDetails, DeployMessage, DeployOptions, DeployProblemType,
    DeployResult, DeployStatus, DescribeMetadataObject, DescribeMetadataResult,
    DescribeValueTypeResult, FileProperties, FlowCoverageResult, FlowCoverageWarning,
    ListMetadataQuery, ManageableState, MetadataApiError, PicklistEntry, RetrieveMessage,
    RetrieveRequest, RetrieveResult, RetrieveStatus, RunTestFailure, RunTestSuccess,
    RunTestsResult, SaveResult, TestLevel, UpsertResult, ValueTypeField,
};
pub use retry::RetryPolicy;
pub use transport::SoapOperation;

// The README's Rust code blocks are compiled as doctests, so the quick
// start cannot drift from the API. The item exists only under
// `cfg(doctest)` and never reaches the published docs.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
pub struct ReadmeDoctests;

/// Default Metadata API version when the caller doesn't override it.
///
/// SOAP endpoint paths use bare version numbers without the `v` prefix
/// (`/services/Soap/m/66.0`).
pub const DEFAULT_API_VERSION: &str = "66.0";

/// Deadline for establishing a connection to the SOAP endpoint.
///
/// Override with [`MetadataClientBuilder::connect_timeout`].
pub const DEFAULT_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Read timeout for the HTTP client the builder creates.
///
/// It runs from the moment the request is dispatched until the response
/// head arrives — so it covers sending the envelope, which for a deploy
/// carries the whole base64-encoded zip — and from then on bounds the
/// gap between two chunks of the response body. Only that second phase
/// resets.
///
/// Widen it with [`MetadataClientBuilder::read_timeout`] for a large
/// deploy over a slow link: Salesforce caps the encoded zip at 50 MB,
/// which no fixed default covers on an arbitrary connection.
pub const DEFAULT_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// Largest response body, in decoded bytes, a successful call buffers
/// unless [`MetadataClientBuilder::max_response_size`] says otherwise:
/// 128 MiB.
///
/// The Metadata API base64-encodes a zip after compressing it and caps
/// "the resulting .zip file" at 50 MB (Metadata API Developer Guide,
/// `retrieve()`), so a retrieve response carries at most about 50 MB of
/// base64 inside its envelope. The rest of the default leaves room for
/// `checkDeployStatus` with `includeDetails` on a large deploy. A body
/// past the limit fails with [`MetadataError::ResponseTooLarge`].
pub const DEFAULT_MAX_RESPONSE_SIZE: usize = 128 << 20;

/// Largest non-2xx body a call buffers. A SOAP fault is a few hundred
/// bytes, and at most 2 KiB of a non-SOAP page is kept, so a body past
/// this came from an intermediary.
pub(crate) const NON_SUCCESS_BODY_CAP: usize = 256 * 1024;

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
    pub(crate) allow_insecure_transport: bool,
    /// Whether the client this crate built routes through a configured
    /// proxy, which withdraws the loopback exemption from the transport
    /// rule: the hop then does leave the machine.
    pub(crate) proxied: bool,
    pub(crate) call_options_client: Option<String>,
    pub(crate) max_response_size: Option<usize>,
}

impl std::fmt::Debug for MetadataClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Mirror cirrus::Cirrus: omit `auth` (may carry secrets) and
        // the reqwest client (no useful Debug).
        f.debug_struct("MetadataClient")
            .field("api_version", &self.api_version)
            .field("instance_url", &self.auth.instance_url())
            .field("retry_policy", &self.retry_policy)
            .field("allow_insecure_transport", &self.allow_insecure_transport)
            .field("proxied", &self.proxied)
            .field("call_options_client", &self.call_options_client)
            .field("max_response_size", &self.max_response_size)
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
    ///
    /// The envelope carries the `SessionHeader`, the client's
    /// `CallOptions` (see
    /// [`MetadataClientBuilder::call_options_client`]) and whatever
    /// [`SoapOperation::render_headers`] adds. Use
    /// [`call_with_response_headers`](Self::call_with_response_headers)
    /// to read the response's output headers too.
    pub async fn call<O: SoapOperation>(&self, op: &O) -> MetadataResult<O::Response> {
        transport::soap_call(self, op).await
    }

    /// Dispatch a typed SOAP operation like [`call`](Self::call), and
    /// also return the response's output headers.
    ///
    /// Today that is the `DebuggingInfo` header of a `checkDeployStatus`
    /// response; see [`SoapResponseHeaders`]. A header the response
    /// doesn't carry comes back as `None`.
    pub async fn call_with_response_headers<O: SoapOperation>(
        &self,
        op: &O,
    ) -> MetadataResult<(O::Response, SoapResponseHeaders)> {
        transport::soap_call_with_headers(self, op).await
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
    proxies: Vec<reqwest::Proxy>,
    retry_policy: Option<RetryPolicy>,
    // Outer `Option` is "did the caller set this"; inner `None` is the
    // caller asking for no deadline at all.
    connect_timeout: Option<Option<std::time::Duration>>,
    read_timeout: Option<Option<std::time::Duration>>,
    max_response_size: Option<Option<usize>>,
    allow_insecure_transport: bool,
    call_options_client: Option<String>,
}

impl MetadataClientBuilder {
    /// Sets the auth session (any [`AuthSession`] wrapped in `Arc`).
    /// Required.
    pub fn auth(mut self, auth: SharedAuth) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Sets the Metadata API version, e.g. `"66.0"`. Defaults to
    /// [`DEFAULT_API_VERSION`]. SOAP endpoint paths use the bare
    /// `XX.X` number, so [`build`](Self::build) rejects the REST
    /// client's `v66.0` form and anything else that is not
    /// digits-dot-digits.
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
    /// policy, so the builder's `connect_timeout` and `read_timeout`
    /// and [`proxy`](Self::proxy) settings are ignored. The client this
    /// builder constructs otherwise applies [`DEFAULT_CONNECT_TIMEOUT`]
    /// and [`DEFAULT_READ_TIMEOUT`], disables redirects so the session
    /// token in the SOAP envelope is never re-POSTed to a redirect
    /// target, and uses no proxy; a client configured here should do
    /// the same unless you have a reason not to. The loopback exemption
    /// to the https rule stays in force for a supplied client, so one
    /// that routes through a proxy (reqwest's default obeys
    /// `HTTP_PROXY` and the system proxy) carries the envelope to that
    /// proxy in the clear for a plaintext loopback instance.
    pub fn http_client(mut self, client: reqwest::Client) -> Self {
        self.http_client = Some(client);
        self
    }

    /// Sets the connect-phase timeout for the HTTP client this builder
    /// creates. Defaults to [`DEFAULT_CONNECT_TIMEOUT`]; pass `None` to
    /// wait indefinitely for a connection.
    ///
    /// Ignored when [`http_client`](Self::http_client) supplies a client.
    pub fn connect_timeout(mut self, timeout: impl Into<Option<std::time::Duration>>) -> Self {
        self.connect_timeout = Some(timeout.into());
        self
    }

    /// Sets the read timeout for the HTTP client this builder creates.
    /// Defaults to [`DEFAULT_READ_TIMEOUT`]; pass `None` to wait
    /// indefinitely.
    ///
    /// The deadline covers the whole in-flight request until the
    /// response head arrives — a deploy's base64 zip goes up inside it —
    /// and after that the gap between two response chunks. Widen it for
    /// a large deploy or retrieve over a slow link.
    ///
    /// Ignored when [`http_client`](Self::http_client) supplies a client.
    pub fn read_timeout(mut self, timeout: impl Into<Option<std::time::Duration>>) -> Self {
        self.read_timeout = Some(timeout.into());
        self
    }

    /// Caps the decoded size of a successful (2xx) response body, in
    /// bytes. Defaults to [`DEFAULT_MAX_RESPONSE_SIZE`]; pass `None` for
    /// no cap.
    ///
    /// The cap applies to every typed call. The default holds the
    /// largest response Salesforce documents, a retrieve with its zip.
    /// Raise it, or pass `None`, only for a client that trusts every
    /// host it talks to: a compressed body inflates far beyond its size
    /// on the wire, and the cap is what keeps one from filling memory.
    /// A larger body fails with [`MetadataError::ResponseTooLarge`]
    /// without being buffered, unless its status is one the retry
    /// policy retries, in which case the call is retried.
    ///
    /// Bodies of non-2xx responses are capped at a fixed 256 KiB
    /// regardless of this setting, and a response read through
    /// [`MetadataClient::request_builder`] is outside any cap.
    pub fn max_response_size(mut self, limit: impl Into<Option<usize>>) -> Self {
        self.max_response_size = Some(limit.into());
        self
    }

    /// Sets the [`RetryPolicy`] for transient-failure handling.
    pub fn retry_policy(mut self, policy: RetryPolicy) -> Self {
        self.retry_policy = Some(policy);
        self
    }

    /// Allows an instance URL that is neither `https` nor loopback, or
    /// that is loopback reached through a [`proxy`](Self::proxy).
    ///
    /// Every SOAP envelope carries the session id in its body, so by
    /// default [`build`](Self::build) and every call refuse to send one
    /// to a plaintext host (RFC 6750 §5.3). Set this only for a
    /// deliberate plaintext hop, such as a recording proxy on a trusted
    /// network, and never for an org.
    pub fn allow_insecure_transport(mut self, allow: bool) -> Self {
        self.allow_insecure_transport = allow;
        self
    }

    /// Routes every call the client this builder creates through
    /// `proxy`. May be called more than once; the first proxy that
    /// matches the endpoint URL is used, as on `reqwest::ClientBuilder`.
    ///
    /// Without this, the client uses no proxy at all: it ignores
    /// `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` and the operating
    /// system's proxy settings, which a stock `reqwest::Client` obeys.
    /// A plaintext loopback instance URL is exempt from the https rule
    /// because the hop never leaves the machine, and an ambient proxy
    /// would silently break that: the envelope, session id included,
    /// would be forwarded to the proxy in the clear.
    ///
    /// With a proxy configured here, the exemption is withdrawn: a
    /// plaintext loopback instance URL is refused like any other
    /// `http://` one unless
    /// [`allow_insecure_transport`](Self::allow_insecure_transport) is
    /// set. An `https` instance is tunneled through the proxy with
    /// `CONNECT`, so the session id stays inside TLS.
    ///
    /// Ignored when [`http_client`](Self::http_client) supplies a client.
    pub fn proxy(mut self, proxy: reqwest::Proxy) -> Self {
        self.proxies.push(proxy);
        self
    }

    /// Identifies this API client to Salesforce in the `CallOptions`
    /// SOAP header.
    ///
    /// The Metadata API Developer Guide describes the header's `client`
    /// field as "a value that identifies an API client". It is sent on
    /// every call the Metadata WSDL binds it to, which is every call
    /// except `describeValueType`. Without this setting no `CallOptions`
    /// header is sent.
    pub fn call_options_client(mut self, client: impl Into<String>) -> Self {
        self.call_options_client = Some(client.into());
        self
    }

    /// Finalizes the builder.
    ///
    /// Fails when no [`auth`](Self::auth) session was supplied, when
    /// [`api_version`](Self::api_version) is not a bare `XX.X` number,
    /// or when the auth session's instance URL would send the session
    /// id in the clear.
    pub fn build(self) -> MetadataResult<MetadataClient> {
        let auth = self.auth.ok_or(MetadataError::MissingField("auth"))?;
        let api_version = self
            .api_version
            .unwrap_or_else(|| DEFAULT_API_VERSION.to_string());
        validate_api_version(&api_version)?;
        // A supplied client's proxy configuration is its owner's
        // business; only a proxy this builder installs is known to be
        // on the path.
        let proxied = self.http_client.is_none() && !self.proxies.is_empty();
        check_transport_security(auth.instance_url(), self.allow_insecure_transport, proxied)?;

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
            let mut builder = reqwest::Client::builder()
                .default_headers(headers)
                // The Metadata API carries the session token in the
                // request body, where a redirect's cross-host header
                // stripping can't reach it. Surfacing a 3xx as an error
                // beats re-POSTing the envelope — token included — to
                // whatever host the Location named.
                .redirect(reqwest::redirect::Policy::none())
                // reqwest obeys HTTP_PROXY and the system proxy by
                // default, and a proxy on the path is what the loopback
                // exemption to the https rule assumes there is not. Only
                // a proxy named on the builder is used.
                .no_proxy();
            for proxy in self.proxies {
                builder = builder.proxy(proxy);
            }
            if let Some(t) = self
                .connect_timeout
                .unwrap_or(Some(DEFAULT_CONNECT_TIMEOUT))
            {
                builder = builder.connect_timeout(t);
            }
            if let Some(t) = self.read_timeout.unwrap_or(Some(DEFAULT_READ_TIMEOUT)) {
                builder = builder.read_timeout(t);
            }
            builder.build().map_err(MetadataError::HttpClient)?
        };

        Ok(MetadataClient {
            http,
            auth,
            api_version,
            retry_policy: self.retry_policy.unwrap_or_default(),
            allow_insecure_transport: self.allow_insecure_transport,
            proxied,
            call_options_client: self.call_options_client,
            max_response_size: self
                .max_response_size
                .unwrap_or(Some(DEFAULT_MAX_RESPONSE_SIZE)),
        })
    }
}

/// Refuses an instance URL that would carry the session id in the clear:
/// anything that is not `https` or loopback, under the rule shared with
/// `cirrus` in [`cirrus_auth::transport`]. The loopback exemption holds
/// only while no proxy is on the path (`proxied`), and `allow_insecure`
/// is the caller's deliberate opt-out of both.
pub(crate) fn check_transport_security(
    url: &str,
    allow_insecure: bool,
    proxied: bool,
) -> MetadataResult<()> {
    if allow_insecure {
        return Ok(());
    }
    let parsed = url::Url::parse(url).map_err(|e| {
        MetadataError::InvalidArgument(format!("instance URL `{url}` is not a valid URL: {e}"))
    })?;
    if parsed.scheme() == "https" {
        return Ok(());
    }
    let loopback = cirrus_auth::transport::is_loopback_host(&parsed);
    if loopback && !proxied {
        return Ok(());
    }
    let why = if loopback {
        "a loopback instance is reached through the configured proxy, so the Salesforce session \
         id inside every SOAP envelope would travel to the proxy in the clear"
    } else {
        "the Salesforce session id inside every SOAP envelope must not travel in the clear"
    };
    Err(MetadataError::InvalidArgument(format!(
        "instance URL `{url}` is not an https target, and {why}; opt out with \
         MetadataClientBuilder::allow_insecure_transport if the plaintext hop is deliberate",
    )))
}

/// Accepts the bare `XX.X` form the SOAP endpoint path uses.
///
/// The REST client's `vXX.X` is the mistake worth catching: it would
/// build `/services/Soap/m/v66.0`, a path the server does not serve, and
/// a value with path characters could address something outside
/// `/services/Soap/m/` altogether.
fn validate_api_version(version: &str) -> MetadataResult<()> {
    let well_formed = version.split_once('.').is_some_and(|(major, minor)| {
        !major.is_empty()
            && !minor.is_empty()
            && major.bytes().all(|b| b.is_ascii_digit())
            && minor.bytes().all(|b| b.is_ascii_digit())
    });
    if well_formed {
        return Ok(());
    }
    Err(MetadataError::InvalidArgument(format!(
        "api_version: expected the bare `XX.X` form the SOAP endpoint path uses (for example \
         `{DEFAULT_API_VERSION}`), got `{version}`",
    )))
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
    fn re_exports_name_the_types_the_public_api_uses() {
        // Callers must be able to name every type in a signature
        // without adding `bytes` or `base64` to their own manifest.
        let zip: Bytes = Bytes::from_static(b"PKzip");
        let err: Base64DecodeError = base64::DecodeError::InvalidPadding;
        assert_eq!(&zip[..], b"PKzip");
        assert!(matches!(err, base64::DecodeError::InvalidPadding));
        // The public `From<quick_xml::Error>` / `From<quick_xml::DeError>`
        // impls are usable by name through the crate's own re-export.
        let xml_err: MetadataError =
            <crate::quick_xml::DeError as serde::de::Error>::custom("bad").into();
        assert!(matches!(xml_err, MetadataError::Xml(_)));
    }

    #[test]
    fn a_configured_proxy_withdraws_the_loopback_exemption() {
        let proxy = reqwest::Proxy::all("http://proxy.corp.example:3128").unwrap();
        let loopback = Arc::new(auth::StaticTokenAuth::new("tok", "http://localhost:8080"));

        let err = MetadataClient::builder()
            .auth(loopback.clone())
            .proxy(proxy.clone())
            .build()
            .unwrap_err();
        match err {
            MetadataError::InvalidArgument(message) => {
                assert!(message.contains("proxy"), "{message}");
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }

        // The opt-out covers it, as it covers any plaintext hop.
        MetadataClient::builder()
            .auth(loopback.clone())
            .proxy(proxy.clone())
            .allow_insecure_transport(true)
            .build()
            .unwrap();

        // An https instance is tunneled, so nothing changes for it.
        let org = Arc::new(auth::StaticTokenAuth::new(
            "tok",
            "https://my-org.my.salesforce.com",
        ));
        MetadataClient::builder()
            .auth(org)
            .proxy(proxy)
            .build()
            .unwrap();

        // A supplied client's proxy settings are its owner's business:
        // the exemption stays.
        MetadataClient::builder()
            .auth(loopback)
            .http_client(reqwest::Client::builder().no_proxy().build().unwrap())
            .build()
            .unwrap();
    }

    #[tokio::test]
    async fn the_default_client_ignores_an_ambient_proxy() {
        // The variable is process-wide; nextest runs each test in its
        // own process, which is what makes setting it safe. Under a
        // threaded runner the test is a no-op.
        if std::env::var_os("NEXTEST").is_none() {
            return;
        }
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/services/Soap/m/66.0"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let closed = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        // SAFETY: this test runs in its own process (checked above), so
        // no other thread reads the environment while it is modified.
        unsafe {
            std::env::set_var("HTTP_PROXY", format!("http://127.0.0.1:{closed}"));
            std::env::remove_var("NO_PROXY");
            std::env::remove_var("no_proxy");
        }

        let err = reqwest::Client::new()
            .post(format!("{}/services/Soap/m/66.0", server.uri()))
            .send()
            .await
            .unwrap_err();
        assert!(err.is_connect(), "stock client ignored HTTP_PROXY: {err:?}");

        let auth = Arc::new(auth::StaticTokenAuth::new("tok", server.uri()));
        let md = MetadataClient::builder().auth(auth).build().unwrap();
        let response = md.request_builder().send().await.unwrap();
        assert_eq!(response.status().as_u16(), 200);
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
