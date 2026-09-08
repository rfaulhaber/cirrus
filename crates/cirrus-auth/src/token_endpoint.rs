//! Shared OAuth token-exchange machinery used by every auth flow.
//!
//! Salesforce's `/services/oauth2/token` endpoint accepts several
//! `grant_type` values (JWT bearer, refresh token, authorization code,
//! device code, client credentials). The wire shape is the same for all of
//! them: an `application/x-www-form-urlencoded` POST body, and a JSON
//! response that's either a [`TokenResponse`] on 2xx or
//! `{error, error_description}` on 4xx/5xx. The flow-specific code in
//! [`crate::jwt`], [`crate::refresh`], etc. constructs the form body;
//! [`exchange`] handles the rest.

use crate::error::{AuthError, AuthResult};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

/// Margin subtracted from a cached token's lifetime when deciding whether
/// it is still usable. A token whose real expiry is within this window is
/// treated as already expired and re-minted proactively, so an in-flight
/// request never lands at Salesforce with a token that expired in transit.
/// This trades a slightly earlier refresh for eliminating a class of
/// avoidable 401 round-trips at every TTL boundary.
pub(super) const EXPIRY_MARGIN: Duration = Duration::from_secs(60);

/// Successful token-endpoint response.
///
/// Mirrors the documented Salesforce token response shape, which is the
/// standard OAuth 2.0 response (RFC 6749 §5.1: `access_token`, `token_type`,
/// `refresh_token`, `scope`) plus Salesforce-specific extensions
/// (`instance_url`, `id`, `issued_at`, `signature`).
///
/// Field availability depends on the flow + connected-app configuration:
/// - `refresh_token` — issued by the flows that support issuance (Web
///   Server, Token Exchange) when the connected app's scope set includes
///   `refresh_token`. A connected app with `isRefreshTokenRotationEnabled`
///   *also* returns one on every invocation of the refresh-token grant,
///   superseding the token that was just presented — which is why
///   [`crate::refresh`] reads this field back out. Never present on
///   Client Credentials or JWT Bearer.
///   (`isRefreshTokenRotationEnabled`: <https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_connectedapp.htm>)
/// - `id_token` — only when the requested `scope` includes `openid`
///   (OIDC).
/// - `scope` — present when the granted scope set differs from the
///   requested set, or always on some flows. Treat as best-effort.
/// - `issued_at` — milliseconds since epoch as a *string*, not a number.
/// - `expires_in` — token lifetime in seconds (RFC 6749 §5.1,
///   RECOMMENDED). Salesforce omits it on most flows; when present,
///   [`TokenResponse::cache_expiry`] caches for the shorter of it and the
///   configured TTL. Modeled as `Option<u64>` + `default` so its absence
///   never breaks parsing.
/// - `signature` / `id` / `token_type` — present on every successful
///   flow except where Salesforce explicitly omits (e.g. some on-behalf-of
///   exchanges).
#[derive(Deserialize)]
pub(super) struct TokenResponse {
    pub(super) access_token: String,
    pub(super) instance_url: String,
    /// Token lifetime in seconds, when the endpoint advertises one
    /// (RFC 6749 §5.1). Combined with the configured cache TTL by
    /// [`TokenResponse::cache_expiry`], which takes the shorter of the
    /// two.
    #[serde(default)]
    pub(super) expires_in: Option<u64>,
    #[serde(default)]
    pub(super) refresh_token: Option<String>,
    #[serde(default)]
    pub(super) id_token: Option<String>,
    #[serde(default)]
    pub(super) scope: Option<String>,
    #[serde(default)]
    pub(super) issued_at: Option<String>,
    /// Salesforce *user-identity URL*, e.g.
    /// `https://login.salesforce.com/id/00DRO0000004sJ7/005RO0000005V0E`.
    /// Distinct from `id_token` (which is OIDC). Useful for callers that
    /// want to know which user they authenticated as.
    #[serde(default)]
    pub(super) id: Option<String>,
    /// Base64-encoded HMAC-SHA256 of the concatenated `id` and
    /// `issued_at` values, signed with the connected app's consumer
    /// secret. Salesforce scopes it to one purpose: verifying that the
    /// identity URL in `id` was not modified in transit. `access_token`
    /// and `instance_url` are not inputs to the HMAC, so a valid
    /// signature says nothing about them. Absent on flows that don't
    /// have a consumer secret (some public-client variants).
    #[serde(default)]
    pub(super) signature: Option<String>,
    /// Always `"Bearer"` for the OAuth 2.0 flows Salesforce exposes.
    /// Parsed defensively so a future divergence wouldn't break the
    /// deserializer; not propagated onto session structs.
    #[serde(default)]
    #[allow(dead_code)]
    pub(super) token_type: Option<String>,
}

impl TokenResponse {
    /// Computes the cache-expiry [`Instant`] for this freshly-issued token.
    ///
    /// The effective lifetime is the *shorter* of the server-advertised
    /// `expires_in` (RFC 6749 §5.1) and the caller's configured
    /// `fallback_ttl`. The asymmetry is deliberate: caching for less time
    /// than the token is actually valid costs one extra mint, while
    /// caching for longer ships requests with a dead token. Shared by
    /// every caching flow so they stay consistent.
    pub(super) fn cache_expiry(&self, fallback_ttl: Duration) -> Instant {
        let ttl = match self.expires_in {
            Some(secs) => Duration::from_secs(secs).min(fallback_ttl),
            None => fallback_ttl,
        };
        // `Instant + Duration` panics on overflow and `expires_in` is
        // server-controlled, so add fallibly: an unrepresentable expiry
        // becomes "already expired", which re-mints rather than aborting
        // the caller's task.
        Instant::now().checked_add(ttl).unwrap_or_else(Instant::now)
    }
}

/// Connect timeout applied to the token-endpoint client the builders
/// construct when the caller supplies none.
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Total request timeout applied to that same client. Token responses are
/// a few hundred bytes, so a bound this generous only ever fires on a
/// stalled peer — and without it a silently dropped connection parks the
/// mint (and, for [`crate::refresh`], the lock it holds) indefinitely.
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Builds the `reqwest::Client` used for token exchanges when a flow
/// builder is not given one.
///
/// Two properties matter beyond the timeouts above. Redirects are
/// **not** followed: every grant in this crate carries its credential in
/// the form body (`client_secret`, `refresh_token`, the JWT `assertion`,
/// the RFC 8693 `subject_token`, the PKCE `code_verifier`), and reqwest
/// replays the body on a 307/308 — so a redirect from the token endpoint
/// would re-POST live credentials to whatever host the `Location` names.
/// A flow that is handed a caller-supplied client inherits that client's
/// policy instead, so callers sharing a connection pool should configure
/// both there.
pub(super) fn default_http_client() -> AuthResult<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .connect_timeout(DEFAULT_CONNECT_TIMEOUT)
        .timeout(DEFAULT_REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()?)
}

/// Normalizes a configured or server-returned Salesforce URL: surrounding
/// whitespace and *all* trailing slashes are removed.
///
/// Every builder, [`crate::StaticTokenAuth`], and [`check_instance_url`]
/// run values through this one function, so a URL that differs only in
/// trailing separators compares equal and `{url}/services/...`
/// concatenation never doubles one.
pub(super) fn normalize_url(url: &str) -> String {
    url.trim().trim_end_matches('/').to_string()
}

/// Rejects a login URL that would carry OAuth credentials in cleartext.
///
/// Salesforce serves every OAuth endpoint over HTTPS, and this crate puts
/// the credential in the request body, so a plain-HTTP host leaks it to
/// anyone on-path before any redirect to HTTPS could take effect. Loopback
/// hosts (`localhost`, `127.0.0.0/8`, `::1`) are exempt so local mock
/// servers and test harnesses can run without TLS.
///
/// Expects an already-[`normalize_url`]d value.
pub(super) fn require_secure_login_url(url: &str) -> AuthResult<()> {
    let parsed = url::Url::parse(url)?;
    let loopback = match parsed.host() {
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(addr)) => addr.is_loopback(),
        Some(url::Host::Ipv6(addr)) => addr.is_loopback(),
        None => false,
    };
    if parsed.scheme() == "https" || loopback {
        Ok(())
    } else {
        Err(AuthError::InsecureLoginUrl {
            url: url.to_string(),
        })
    }
}

/// Whether a cached token minted to expire at `expires_at` is still safe to
/// use, accounting for the [`EXPIRY_MARGIN`] refresh window. The JWT,
/// refresh, and client-credentials flows all call this, so they apply an
/// identical margin.
pub(super) fn token_is_fresh(expires_at: Instant) -> bool {
    expires_at > Instant::now() + EXPIRY_MARGIN
}

// Redact every secret-bearing field. The `id`, `issued_at`, `scope`,
// `token_type`, and `instance_url` fields are non-sensitive — emit them
// verbatim so debug output stays useful.
impl std::fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenResponse")
            .field("access_token", &"[redacted]")
            .field("instance_url", &self.instance_url)
            .field("expires_in", &self.expires_in)
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[redacted]"),
            )
            .field("id_token", &self.id_token.as_ref().map(|_| "[redacted]"))
            .field("scope", &self.scope)
            .field("issued_at", &self.issued_at)
            .field("id", &self.id)
            .field("signature", &self.signature.as_ref().map(|_| "[redacted]"))
            .field("token_type", &self.token_type)
            .finish()
    }
}

#[derive(Deserialize)]
struct OAuthErrorResponse {
    error: String,
    #[serde(default)]
    error_description: Option<String>,
}

// `error_description` is server-supplied free text and has historically
// contained partial token material in some Salesforce error paths.
// Redact the description so the OAuth error code is the only thing that
// surfaces in `{:?}`.
impl std::fmt::Debug for OAuthErrorResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthErrorResponse")
            .field("error", &self.error)
            .field(
                "error_description",
                &self.error_description.as_ref().map(|_| "[redacted]"),
            )
            .finish()
    }
}

/// POSTs a token-exchange form body to `{login_url}/services/oauth2/token`
/// and parses the response.
///
/// The caller assembles the form body with the flow-specific fields
/// (`grant_type`, `assertion`, `refresh_token`, etc.). On non-2xx, the body
/// is parsed as the OAuth error shape if possible; otherwise the raw body
/// is folded into a generic [`AuthError::Other`] message.
pub(super) async fn exchange<B>(
    http: &reqwest::Client,
    login_url: &str,
    body: &B,
) -> AuthResult<TokenResponse>
where
    B: Serialize + ?Sized,
{
    let url = format!("{login_url}/services/oauth2/token");
    let response = http.post(&url).form(body).send().await?;
    let status = response.status().as_u16();
    let bytes = response.bytes().await?;

    if !(200..300).contains(&status) {
        if let Ok(oauth_err) = serde_json::from_slice::<OAuthErrorResponse>(&bytes) {
            return Err(AuthError::OAuth {
                error: oauth_err.error,
                error_description: oauth_err.error_description,
            });
        }
        // The body didn't match the OAuth error shape. Do NOT fold it into
        // the error message: non-standard token-endpoint bodies (HTML error
        // pages, proxies, reflected request parameters) can echo token
        // material, and the error message flows into logs. Surface only the
        // status; expose the body solely at TRACE, which is off by default
        // and a deliberate per-target opt-in for debugging.
        tracing::trace!(
            target: "cirrus::auth",
            status,
            body = %String::from_utf8_lossy(&bytes),
            "token endpoint returned a non-2xx body that did not parse as an OAuth error",
        );
        return Err(AuthError::UnexpectedResponse { status });
    }

    serde_json::from_slice::<TokenResponse>(&bytes).map_err(AuthError::Serialization)
}

/// Validates that a token response's `instance_url` matches the value the
/// caller configured. A mismatch usually signals a misconfigured Connected
/// App (wrong org), which is more actionable when surfaced at auth time
/// than as a downstream API error.
///
/// Both sides go through [`normalize_url`] and the comparison ignores
/// ASCII case, so the mixed-case My Domain spelling Salesforce's own docs
/// use and a stray trailing slash both still match. `expected` is the
/// already-normalized builder value.
pub(super) fn check_instance_url(expected: &str, response: &TokenResponse) -> AuthResult<()> {
    let returned = normalize_url(&response.instance_url);
    if !returned.eq_ignore_ascii_case(expected) {
        return Err(AuthError::InstanceUrlMismatch {
            configured: expected.to_string(),
            returned,
        });
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Builds a token response carrying just the two always-present
    /// fields plus an optional `expires_in`.
    fn response(instance_url: &str, expires_in: Option<u64>) -> TokenResponse {
        TokenResponse {
            access_token: "tok".to_string(),
            instance_url: instance_url.to_string(),
            expires_in,
            refresh_token: None,
            id_token: None,
            scope: None,
            issued_at: None,
            id: None,
            signature: None,
            token_type: None,
        }
    }

    #[test]
    fn normalize_url_trims_whitespace_and_every_trailing_slash() {
        assert_eq!(
            normalize_url("  https://my-org.my.salesforce.com//  "),
            "https://my-org.my.salesforce.com"
        );
        assert_eq!(
            normalize_url("https://my-org.my.salesforce.com"),
            "https://my-org.my.salesforce.com"
        );
    }

    #[test]
    fn instance_url_check_tolerates_documented_trailing_slash() {
        // Salesforce's documented sample response carries a trailing
        // slash on instance_url.
        // SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/intro_understanding_web_server_oauth_flow.htm
        // (doc_version 222.0) — `"instance_url":"https://yourInstance.salesforce.com/"`
        let response = response("https://yourInstance.salesforce.com/", None);
        check_instance_url("https://yourInstance.salesforce.com", &response).unwrap();
    }

    #[test]
    fn instance_url_check_ignores_ascii_case() {
        // Salesforce's docs write My Domain hosts in mixed case
        // (`MyDomainName.my.salesforce.com`) while the token response
        // returns them lowercased.
        let response = response("https://mydomainname.my.salesforce.com", None);
        check_instance_url("https://MyDomainName.my.salesforce.com", &response).unwrap();
    }

    #[test]
    fn instance_url_check_reports_both_sides_on_mismatch() {
        let response = response("https://wrong-org.my.salesforce.com", None);
        let err = check_instance_url("https://my-org.my.salesforce.com", &response).unwrap_err();
        match err {
            AuthError::InstanceUrlMismatch {
                configured,
                returned,
            } => {
                assert_eq!(configured, "https://my-org.my.salesforce.com");
                assert_eq!(returned, "https://wrong-org.my.salesforce.com");
            }
            other => panic!("expected InstanceUrlMismatch, got {other:?}"),
        }
    }

    #[test]
    fn https_and_loopback_login_urls_are_accepted() {
        require_secure_login_url("https://my-org.my.salesforce.com").unwrap();
        require_secure_login_url("http://127.0.0.1:8080").unwrap();
        require_secure_login_url("http://localhost:8080").unwrap();
        require_secure_login_url("http://[::1]:8080").unwrap();
    }

    #[test]
    fn cleartext_login_url_is_rejected() {
        let err = require_secure_login_url("http://my-org.my.salesforce.com").unwrap_err();
        match err {
            AuthError::InsecureLoginUrl { url } => {
                assert_eq!(url, "http://my-org.my.salesforce.com");
            }
            other => panic!("expected InsecureLoginUrl, got {other:?}"),
        }
    }

    #[test]
    fn login_url_without_a_scheme_is_a_url_error() {
        let err = require_secure_login_url("my-org.my.salesforce.com").unwrap_err();
        assert!(matches!(err, AuthError::Url(_)), "got {err:?}");
    }

    #[test]
    fn cache_expiry_takes_the_shorter_of_expires_in_and_configured_ttl() {
        let ttl = Duration::from_secs(300);

        // Server advertises longer than the caller configured: the
        // caller's shorter window wins.
        let long = response("https://x", Some(7200)).cache_expiry(ttl);
        assert!(long <= Instant::now() + ttl);

        // Server advertises shorter: the server's window wins.
        let short = response("https://x", Some(30)).cache_expiry(ttl);
        assert!(short <= Instant::now() + Duration::from_secs(30));
    }

    #[test]
    fn cache_expiry_survives_an_absurd_expires_in() {
        // A hostile or broken endpoint can return any u64; the resulting
        // instant must not overflow the caller's task.
        let expiry = response("https://x", Some(u64::MAX)).cache_expiry(Duration::from_secs(300));
        assert!(expiry <= Instant::now() + Duration::from_secs(300));
    }
}
