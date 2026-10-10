//! Salesforce OAuth 2.0 authentication flows for the Cirrus SDK.
//!
//! Salesforce supports several OAuth 2.0 flows, each producing the same two
//! pieces of information: a bearer access token and an `instance_url` that
//! becomes the base URL for subsequent REST calls. The rest of the SDK is
//! flow-agnostic — it only needs an [`AuthSession`] that can hand over those
//! two values on demand.
//!
//! Implementations live in submodules (one per flow). They are responsible
//! for their own token acquisition, refresh, and any caching. The trait
//! method is `async` so an implementation may transparently refresh an
//! expired token when called.
//!
//! ## Crate boundary
//!
//! This crate is the canonical home of every auth flow used by the
//! Cirrus SDK. It is re-exported as `cirrus::auth` so end users never
//! depend on `cirrus-auth` directly — `cirrus = "..."` is enough. Other
//! Cirrus subcrates (e.g. `cirrus-metadata`) that need an authenticated
//! session depend on `cirrus-auth` so they don't pull in the full REST
//! client.
//!
//! ## Implementations
//!
//! - [`static_token`] — preset access token + instance URL. Useful for
//!   tests, scripts, or callers that have already obtained credentials by
//!   other means.
//! - [`jwt`] — OAuth 2.0 JWT Bearer flow for server-to-server auth.
//! - [`refresh`] — OAuth 2.0 Refresh Token grant. Long-lived sessions for
//!   any flow that produces a refresh token.
//! - [`client_credentials`] — OAuth 2.0 Client Credentials grant for
//!   server-to-server integrations that run as a pre-configured user.
//! - [`web_server`] — OAuth 2.0 Web Server flow with PKCE for
//!   user-interactive authorization. Yields a [`CompletedSession`] once
//!   the user comes back through the redirect URL, which
//!   [`WebServerFlow::refresh_auth`] turns into a [`RefreshTokenAuth`].
//! - [`token_exchange`] — OAuth 2.0 Token Exchange (RFC 8693).
//!
//! [`transport`] holds the https-or-loopback rule that every Cirrus
//! client applies before sending a bearer token anywhere, and the
//! bounded body reader, [`transport::collect_body`], that every client
//! reads responses through.
//!
//! ## Cargo features
//!
//! The TLS backend is chosen by feature, under reqwest's names: `rustls`
//! (the default: rustls with the aws-lc-rs provider and the platform's
//! trust store), `rustls-no-provider` (the application installs the
//! crypto provider before building a client), `native-tls` and
//! `native-tls-vendored` (the operating system's stack). `bundled-roots`
//! merges Mozilla's root set into every client the crate builds, through
//! [`transport::merge_bundled_roots`], for hosts with no system CA
//! bundle. The features forward to reqwest and unify across the build as
//! reqwest's own do; `rustls-no-provider` changes which provider TLS
//! uses, not whether aws-lc-rs compiles, since JWT assertions are signed
//! with it regardless.
//!
//! ## Transport and logging
//!
//! The token-endpoint client a flow builder creates applies
//! [`DEFAULT_TOKEN_CONNECT_TIMEOUT`] and [`DEFAULT_TOKEN_REQUEST_TIMEOUT`]
//! and follows no redirects. Every builder has `connect_timeout` and
//! `request_timeout` setters, and [`token_client_builder`] hands out the
//! same configuration as a `reqwest::ClientBuilder` to extend with a
//! private root CA, a proxy or a shared connection pool.
//!
//! A token-endpoint response body is read up to 64 KiB of decoded bytes;
//! a larger one fails with [`AuthError::ResponseTooLarge`] instead of
//! being buffered.
//!
//! Events are emitted under the `cirrus_auth::mint` (token caching and
//! minting), `cirrus_auth::token_endpoint` (the HTTP exchange) and
//! `cirrus_auth::rotation` (refresh-token rotation) targets. No event
//! carries a token, a credential or a response body.
//!
//! Flows Salesforce lists as legacy or deprecated are intentionally not
//! supported.

use std::borrow::Cow;
use std::sync::Arc;

mod assertion;
pub mod client_credentials;
mod error;
pub mod jwt;
mod mint;
pub mod refresh;
pub mod static_token;
#[cfg(test)]
mod test_support;
mod token_endpoint;
pub mod token_exchange;
pub mod transport;
pub mod web_server;

/// Re-export of [`reqwest`].
///
/// Every flow builder's `http_client` setter accepts a
/// `reqwest::Client`; using this re-export instead of a separate
/// `reqwest` dependency keeps the caller's `reqwest` version aligned
/// with the SDK's.
pub use reqwest;

/// Re-export of the [`async_trait`](https://docs.rs/async-trait) attribute
/// macro that [`AuthSession`] and
/// [`RotationHandler`](refresh::RotationHandler) are declared with. An
/// implementation of either trait needs the same macro on its `impl`
/// block; using this re-export instead of a separate `async-trait`
/// dependency keeps the macro's version aligned with the trait's.
pub use async_trait::async_trait;

/// Re-export of [`camino`], whose `Utf8PathBuf` is the path type
/// [`JwtAuthBuilder::private_key_pem_file`] takes. A `std::path::PathBuf`
/// converts with `Utf8PathBuf::try_from`.
pub use camino;

pub use client_credentials::{ClientCredentialsAuth, ClientCredentialsAuthBuilder};
pub use error::{AuthError, AuthResult};
pub use jwt::{JwtAuth, JwtAuthBuilder};
pub use refresh::{RefreshTokenAuth, RefreshTokenAuthBuilder};
pub use static_token::StaticTokenAuth;
pub use token_endpoint::{
    DEFAULT_TOKEN_CONNECT_TIMEOUT, DEFAULT_TOKEN_REQUEST_TIMEOUT, revoke_token,
    token_client_builder,
};
pub use token_exchange::{
    SubjectTokenType, TokenExchangeFlow, TokenExchangeFlowBuilder, TokenExchangeGrantType,
    TokenExchangeSession,
};
pub use web_server::{
    AuthorizeOptions, CompletedSession, PendingExchange, WebServerFlow, WebServerFlowBuilder,
};

// The README's Rust code blocks are compiled as doctests, so the quick
// start cannot drift from the API. The item exists only under
// `cfg(doctest)` and never reaches the published docs.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
pub struct ReadmeDoctests;

/// Abstraction over a Salesforce authentication session.
///
/// An implementation holds whatever credentials the chosen flow needs,
/// produces a bearer access token on demand (refreshing if necessary), and
/// reports the instance URL that REST requests should target.
///
/// The trait is `Send + Sync` and uses [`async_trait`](macro@crate::async_trait)
/// to remain `dyn`-compatible — the client stores `Arc<dyn AuthSession>` so
/// handlers don't care which flow was configured.
///
/// # Implementing the trait
///
/// A session that obtains its token elsewhere (a secrets manager, a
/// sidecar, a test double) implements the trait under the same macro,
/// which this crate re-exports so the implementation needs no dependency
/// of its own:
///
/// ```
/// use cirrus_auth::{AuthResult, AuthSession, async_trait};
/// use std::borrow::Cow;
///
/// struct VaultSession {
///     token: String,
///     instance_url: String,
/// }
///
/// #[async_trait]
/// impl AuthSession for VaultSession {
///     async fn access_token(&self) -> AuthResult<Cow<'_, str>> {
///         Ok(Cow::Borrowed(&self.token))
///     }
///
///     fn instance_url(&self) -> &str {
///         &self.instance_url
///     }
/// }
/// ```
///
/// Override [`invalidate`](Self::invalidate) as well when the token can
/// be re-obtained, so a `401 INVALID_SESSION_ID` leads to a fresh one.
#[async_trait]
pub trait AuthSession: Send + Sync {
    /// Returns a valid bearer access token. Implementations may refresh
    /// expired tokens transparently here; that is why the method is `async`.
    async fn access_token(&self) -> AuthResult<Cow<'_, str>>;

    /// Returns the instance URL for REST requests, e.g.
    /// `https://my-org.my.salesforce.com`. No trailing slash.
    fn instance_url(&self) -> &str;

    /// Invalidates a cached token that the SDK has determined is no
    /// longer valid (typically because Salesforce returned 401
    /// `INVALID_SESSION_ID` when it was used).
    ///
    /// The next [`access_token`](Self::access_token) call should mint
    /// a fresh token. The `stale_token` parameter lets implementations
    /// compare-and-swap — only clear the cache if the cached value
    /// still matches what the caller actually used. This avoids
    /// blowing away a *newer* token that another concurrent task may
    /// have refreshed in the meantime.
    ///
    /// Default impl is a no-op for static or stateless sessions
    /// ([`StaticTokenAuth`]) where there is nothing to invalidate.
    /// Stateful flows ([`JwtAuth`], [`RefreshTokenAuth`],
    /// [`ClientCredentialsAuth`]) override to clear their cached
    /// token.
    ///
    /// `stale_token` is borrowed for the duration of the call only —
    /// implementations should compare it against their cached value
    /// and not retain it.
    async fn invalidate(&self, stale_token: &str) {
        // Default: nothing to invalidate. Suppress the unused-arg
        // warning on the default impl without requiring overriders to
        // bind a different name.
        let _ = stale_token;
    }
}

/// `Arc<dyn AuthSession>` — the shape stored inside the client.
pub type SharedAuth = Arc<dyn AuthSession>;
