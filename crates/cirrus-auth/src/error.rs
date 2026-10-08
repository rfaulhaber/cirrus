//! Error types for `cirrus-auth`.
//!
//! Salesforce OAuth token endpoints return errors in the standard
//! `{error, error_description}` shape (RFC 6749 §5.2), which
//! [`AuthError::OAuth`] models directly. Everything else — missing
//! builder fields, transport failures, malformed responses — is
//! categorized into the remaining variants.
//!
//! The companion `cirrus` crate carries a `From<AuthError> for
//! CirrusError` impl so REST call sites that invoke an
//! [`crate::AuthSession`] can use `?` and surface the auth failure as
//! part of the unified client error.
//!
//! `AuthError` is intentionally `non_exhaustive` so we can grow it
//! without a SemVer break.

use thiserror::Error;

/// Specialized `Result` type for `cirrus-auth` operations.
pub type AuthResult<T> = Result<T, AuthError>;

/// Errors produced while acquiring or refreshing a Salesforce OAuth
/// session.
///
/// The `error_description` carried by [`AuthError::OAuth`] is
/// server-supplied free text that can include partial token material, so
/// it is redacted from both the `Display` and `Debug` representations of
/// this type — only the machine-readable `error` code is shown. Callers
/// that need the description can read it from the variant field directly.
///
/// Variants that wrap another error ([`HttpClient`](Self::HttpClient),
/// [`Http`](Self::Http), [`Serialization`](Self::Serialization),
/// [`Url`](Self::Url)) expose it through
/// [`source()`](std::error::Error::source) and do not repeat its text in
/// their own `Display`, so a reporter that walks the chain prints each
/// message once. Print the chain (anyhow's `{:#}`, for example) to see
/// the underlying cause; `{}` alone names only the category.
#[derive(Error)]
#[non_exhaustive]
pub enum AuthError {
    /// A required builder field was not set.
    #[error("missing required builder field: {0}")]
    MissingField(&'static str),

    /// OAuth token endpoint returned an error response (`error` /
    /// `error_description` shape from RFC 6749 §5.2).
    ///
    /// Only the machine-readable `error` code is surfaced via `Display`;
    /// `error_description` is redacted (see the type-level note) but
    /// remains available by matching on the field.
    #[error("OAuth error: {error}")]
    OAuth {
        error: String,
        error_description: Option<String>,
    },

    /// The `state` echoed back on an OAuth callback did not match the
    /// value carried in the [`PendingExchange`](crate::PendingExchange)
    /// the caller supplied.
    ///
    /// This is a security event, not a configuration problem: it means
    /// the callback was forged, or crossed with another authorization
    /// attempt's pending. Match on it to answer 400 and raise an audit
    /// alert rather than retrying. It does not catch the same callback
    /// hit twice with the same pending; see `PendingExchange` for why a
    /// pending is single-use.
    #[error("OAuth callback state does not match the value this flow issued")]
    StateMismatch,

    /// The [`PendingExchange`](crate::PendingExchange) handed to
    /// [`WebServerFlow::complete`](crate::WebServerFlow::complete) was
    /// issued by a flow with a different consumer key, redirect URI or
    /// login URL.
    ///
    /// An authorization code is bound to the client and redirect URI
    /// that requested it (RFC 6749 §4.1.3) and to the host that issued
    /// it, so no other flow can redeem it. This is a configuration
    /// problem, typically a sandbox authorization completed on a
    /// production flow, and is caught before any request is sent.
    #[error(
        "OAuth callback was started by a flow with a different consumer key, redirect URI or login URL"
    )]
    FlowMismatch,

    /// The token response reported a different `instance_url` than the
    /// one configured on the builder, which usually means the connected
    /// app points at another org.
    ///
    /// Both values are normalized (trailing slashes trimmed) before the
    /// comparison, which is ASCII-case-insensitive.
    #[error(
        "token response instance_url ({returned}) does not match configured instance_url ({configured})"
    )]
    InstanceUrlMismatch {
        configured: String,
        returned: String,
    },

    /// The token endpoint answered non-2xx with a body that is not the
    /// RFC 6749 §5.2 error shape — typically a proxy or gateway page
    /// rather than Salesforce.
    ///
    /// The body is neither carried nor logged: non-standard error pages
    /// can echo request parameters, including credentials. Its status,
    /// content type and length are recorded at `TRACE` on the
    /// `cirrus_auth::token_endpoint` target.
    #[error("token endpoint returned status {status} with an unrecognized error body")]
    UnexpectedResponse { status: u16 },

    /// The token endpoint's response body was longer than the SDK reads:
    /// a real token response is a few kilobytes of JSON, so an oversized
    /// body came from an intermediary.
    ///
    /// The cap applies to the decoded body, so a compressed response
    /// that inflates past it is refused too. Nothing past the limit was
    /// buffered, and the body is neither carried nor logged.
    #[error("token endpoint answered HTTP {status} with a body over {limit} bytes")]
    ResponseTooLarge {
        /// HTTP status of the oversized response.
        status: u16,
        /// The cap that was exceeded, in decoded bytes.
        limit: usize,
    },

    /// A configured login URL would carry credentials over cleartext
    /// HTTP. Salesforce serves every OAuth endpoint over HTTPS; loopback
    /// hosts are the only exception the SDK accepts.
    #[error("login URL {url} is not https; OAuth credentials must not cross the wire in cleartext")]
    InsecureLoginUrl { url: String },

    /// Signing the JWT bearer assertion failed (bad key material,
    /// unsupported key type).
    #[error("JWT signing failed: {0}")]
    Signing(String),

    /// The operating system's cryptographic RNG failed while generating
    /// a PKCE verifier or CSRF nonce.
    #[error("CSPRNG failure: {0}")]
    Randomness(String),

    /// Catch-all for auth failures not modelled by a dedicated variant
    /// (system clock outside the UNIX epoch, private-key loading, a
    /// token-mint task that did not run to completion). Carries the
    /// underlying message.
    #[error("authentication failed: {0}")]
    Other(String),

    /// The HTTP client a flow builder constructs could not be built. No
    /// request was made; the cause is the
    /// [`source()`](std::error::Error::source).
    #[error("failed to construct HTTP client")]
    HttpClient(#[source] reqwest::Error),

    /// Network or transport-level HTTP failure while contacting an
    /// OAuth endpoint.
    #[error("HTTP request failed")]
    Http(#[from] reqwest::Error),

    /// JSON serialization or deserialization failure.
    #[error("serialization error")]
    Serialization(#[from] serde_json::Error),

    /// URL parsing failure (instance URL, redirect URI, login URL,
    /// etc.).
    #[error("invalid URL")]
    Url(#[from] url::ParseError),
}

impl AuthError {
    /// Whether a later attempt could clear this failure: a transport
    /// error other than a request that could not be built, or a 429 or
    /// 5xx from the token endpoint, whether its body was read or was
    /// over the cap. An OAuth error such as
    /// `invalid_grant`, a mismatched instance URL and every
    /// configuration error are permanent until something changes on the
    /// caller's side, so they are never transient.
    ///
    /// The caching flows use this to decide whether a still-valid cached
    /// token may stand in for a failed refresh.
    pub fn is_transient(&self) -> bool {
        match self {
            Self::Http(e) => !e.is_builder(),
            Self::UnexpectedResponse { status } | Self::ResponseTooLarge { status, .. } => {
                *status == 429 || (500..600).contains(status)
            }
            _ => false,
        }
    }

    /// A copy of this error for a caller that shares the outcome of a
    /// mint another caller performed.
    ///
    /// Every variant that owns only strings is copied exactly, so a
    /// waiter matching on [`AuthError::OAuth`] sees the same code. The
    /// transport and JSON sources cannot be cloned, so those two variants
    /// become [`AuthError::Other`] carrying the original `Display` text.
    pub(crate) fn clone_for_waiter(&self) -> Self {
        match self {
            Self::MissingField(field) => Self::MissingField(field),
            Self::OAuth {
                error,
                error_description,
            } => Self::OAuth {
                error: error.clone(),
                error_description: error_description.clone(),
            },
            Self::StateMismatch => Self::StateMismatch,
            Self::FlowMismatch => Self::FlowMismatch,
            Self::InstanceUrlMismatch {
                configured,
                returned,
            } => Self::InstanceUrlMismatch {
                configured: configured.clone(),
                returned: returned.clone(),
            },
            Self::UnexpectedResponse { status } => Self::UnexpectedResponse { status: *status },
            Self::ResponseTooLarge { status, limit } => Self::ResponseTooLarge {
                status: *status,
                limit: *limit,
            },
            Self::InsecureLoginUrl { url } => Self::InsecureLoginUrl { url: url.clone() },
            Self::Signing(msg) => Self::Signing(msg.clone()),
            Self::Randomness(msg) => Self::Randomness(msg.clone()),
            Self::Other(msg) => Self::Other(msg.clone()),
            Self::HttpClient(e) => Self::Other(format!("failed to construct HTTP client: {e}")),
            Self::Http(e) => Self::Other(format!("HTTP request failed: {e}")),
            Self::Serialization(e) => Self::Other(format!("serialization error: {e}")),
            Self::Url(e) => Self::Url(*e),
        }
    }
}

// Hand-written so `OAuth.error_description` is redacted in `{:?}` output —
// a derived `Debug` would print the raw description verbatim, defeating the
// redaction applied at every other layer. The `error` code and all other
// variants are non-sensitive and printed as usual.
impl std::fmt::Debug for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingField(field) => f.debug_tuple("MissingField").field(field).finish(),
            Self::OAuth {
                error,
                error_description,
            } => f
                .debug_struct("OAuth")
                .field("error", error)
                .field(
                    "error_description",
                    &error_description.as_ref().map(|_| "[redacted]"),
                )
                .finish(),
            Self::StateMismatch => f.write_str("StateMismatch"),
            Self::FlowMismatch => f.write_str("FlowMismatch"),
            Self::InstanceUrlMismatch {
                configured,
                returned,
            } => f
                .debug_struct("InstanceUrlMismatch")
                .field("configured", configured)
                .field("returned", returned)
                .finish(),
            Self::UnexpectedResponse { status } => f
                .debug_struct("UnexpectedResponse")
                .field("status", status)
                .finish(),
            Self::ResponseTooLarge { status, limit } => f
                .debug_struct("ResponseTooLarge")
                .field("status", status)
                .field("limit", limit)
                .finish(),
            Self::InsecureLoginUrl { url } => f
                .debug_struct("InsecureLoginUrl")
                .field("url", url)
                .finish(),
            Self::Signing(msg) => f.debug_tuple("Signing").field(msg).finish(),
            Self::Randomness(msg) => f.debug_tuple("Randomness").field(msg).finish(),
            Self::Other(msg) => f.debug_tuple("Other").field(msg).finish(),
            Self::HttpClient(e) => f.debug_tuple("HttpClient").field(e).finish(),
            Self::Http(e) => f.debug_tuple("Http").field(e).finish(),
            Self::Serialization(e) => f.debug_tuple("Serialization").field(e).finish(),
            Self::Url(e) => f.debug_tuple("Url").field(e).finish(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn oauth_error_redacts_description_in_display_and_debug() {
        // A description carrying token-like material must not surface in
        // either formatted representation, but must remain readable via
        // the field.
        let err = AuthError::OAuth {
            error: "invalid_grant".to_string(),
            error_description: Some("00Dxx!AQ.SECRET_TOKEN_FRAGMENT".to_string()),
        };

        let display = err.to_string();
        assert!(display.contains("invalid_grant"));
        assert!(
            !display.contains("SECRET_TOKEN_FRAGMENT"),
            "Display leaked error_description: {display}"
        );

        let debug = format!("{err:?}");
        assert!(debug.contains("invalid_grant"));
        assert!(debug.contains("[redacted]"));
        assert!(
            !debug.contains("SECRET_TOKEN_FRAGMENT"),
            "Debug leaked error_description: {debug}"
        );

        // The description is still programmatically accessible.
        match err {
            AuthError::OAuth {
                error_description, ..
            } => assert!(error_description.is_some()),
            other => panic!("expected OAuth, got {other:?}"),
        }
    }

    #[test]
    fn only_transport_failures_and_server_side_statuses_are_transient() {
        assert!(AuthError::UnexpectedResponse { status: 503 }.is_transient());
        assert!(AuthError::UnexpectedResponse { status: 429 }.is_transient());
        assert!(!AuthError::UnexpectedResponse { status: 404 }.is_transient());
        assert!(
            AuthError::ResponseTooLarge {
                status: 503,
                limit: 1
            }
            .is_transient()
        );
        assert!(
            AuthError::ResponseTooLarge {
                status: 429,
                limit: 1
            }
            .is_transient()
        );
        assert!(
            !AuthError::ResponseTooLarge {
                status: 200,
                limit: 1
            }
            .is_transient()
        );
        assert!(
            !AuthError::OAuth {
                error: "invalid_grant".into(),
                error_description: None,
            }
            .is_transient()
        );
        assert!(
            !AuthError::InstanceUrlMismatch {
                configured: "a".into(),
                returned: "b".into(),
            }
            .is_transient()
        );
        assert!(!AuthError::Other("token mint task panicked".into()).is_transient());
    }

    #[test]
    fn waiter_clone_keeps_the_oauth_code_and_describes_unclonable_sources() {
        let oauth = AuthError::OAuth {
            error: "invalid_grant".into(),
            error_description: Some("expired access/refresh token".into()),
        };
        assert!(matches!(
            oauth.clone_for_waiter(),
            AuthError::OAuth { ref error, ref error_description }
                if error == "invalid_grant" && error_description.is_some()
        ));
        let json: AuthError = serde_json::from_str::<serde_json::Value>("not json")
            .unwrap_err()
            .into();
        let cloned = json.clone_for_waiter();
        assert!(
            matches!(cloned, AuthError::Other(ref msg) if msg.starts_with("serialization error: "))
        );
    }

    #[test]
    fn oauth_error_debug_shows_none_description_without_redaction_marker() {
        let err = AuthError::OAuth {
            error: "invalid_client".to_string(),
            error_description: None,
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("invalid_client"));
        assert!(debug.contains("None"));
        assert!(!debug.contains("[redacted]"));
    }

    /// A `reqwest::Error` produced without any network: an invalid default
    /// header value is reported when the client is built.
    fn client_build_error() -> reqwest::Error {
        reqwest::Client::builder()
            .user_agent("line\nbreak")
            .build()
            .unwrap_err()
    }

    #[test]
    fn display_does_not_repeat_the_text_of_the_source() {
        use std::error::Error as _;
        let errors = [
            AuthError::HttpClient(client_build_error()),
            AuthError::Http(client_build_error()),
            AuthError::Serialization(serde_json::from_str::<serde_json::Value>("{").unwrap_err()),
            AuthError::Url(url::Url::parse("not a url").unwrap_err()),
        ];
        for err in errors {
            let source = err.source().expect("variant carries a source").to_string();
            let display = err.to_string();
            assert!(
                !display.contains(&source),
                "{display:?} repeats its source {source:?}"
            );
        }
    }
}
