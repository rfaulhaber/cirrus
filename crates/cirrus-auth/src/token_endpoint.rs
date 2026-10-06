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
use crate::transport::{CollectBodyError, collect_body};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

/// Margin subtracted from a cached token's lifetime when deciding whether
/// it is still usable. A token whose real expiry is within this window is
/// treated as already expired and re-minted proactively, so an in-flight
/// request never lands at Salesforce with a token that expired in transit.
/// This trades a slightly earlier refresh for eliminating a class of
/// avoidable 401 round-trips at every TTL boundary. The margin is not a
/// hard cut-off: when the proactive refresh fails transiently, the flows
/// keep using the cached token until its estimated expiry
/// (see [`crate::mint`]).
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

/// Connect-phase timeout of the token-endpoint client a flow builder
/// creates when it is not given one. Override per flow with the builder's
/// `connect_timeout`.
pub const DEFAULT_TOKEN_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Deadline for each token request that same client sends, from dispatch
/// until the whole response has arrived. Override per flow with the
/// builder's `request_timeout`.
///
/// Token responses are a few hundred bytes, so a bound this generous only
/// ever fires on a stalled peer. Without one, a connection the peer
/// accepts and never answers parks the mint, and every caller queued
/// behind it, indefinitely.
pub const DEFAULT_TOKEN_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// A `reqwest::ClientBuilder` carrying the settings the flow builders
/// apply to the token-endpoint client they create: the two default
/// timeouts and a redirect policy that follows nothing.
///
/// Redirects are not followed because every grant in this crate carries
/// its credential in the form body (`client_secret`, `refresh_token`, the
/// JWT `assertion`, the RFC 8693 `subject_token`, the PKCE
/// `code_verifier`), and reqwest replays the body on a 307/308, so a
/// redirect from the token endpoint would re-POST live credentials to
/// whatever host the `Location` header names.
///
/// Start from this builder when the token client needs a setting the
/// flow builders do not expose, such as a private root CA, a proxy or a
/// connection pool shared with other clients, so that adding it does not
/// silently drop the no-redirect rule or the timeouts:
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use cirrus_auth::{JwtAuth, reqwest, token_client_builder};
///
/// let ca = reqwest::Certificate::from_pem(&fs_err::read("corp-root.pem")?)?;
/// let http = token_client_builder().add_root_certificate(ca).build()?;
/// let auth = JwtAuth::builder()
///     .consumer_key("3MVG9...")
///     .username("integration-user@example.com")
///     .instance_url("https://my-org.my.salesforce.com")
///     .private_key_pem_file("./private.pem")?
///     .http_client(http)
///     .build()?;
/// # let _ = auth;
/// # Ok(())
/// # }
/// ```
pub fn token_client_builder() -> reqwest::ClientBuilder {
    hardened_client_builder(
        Some(DEFAULT_TOKEN_CONNECT_TIMEOUT),
        Some(DEFAULT_TOKEN_REQUEST_TIMEOUT),
    )
}

/// The no-redirect policy plus whichever timeouts are given; `None`
/// leaves that bound off.
fn hardened_client_builder(
    connect_timeout: Option<Duration>,
    request_timeout: Option<Duration>,
) -> reqwest::ClientBuilder {
    let mut builder = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none());
    if let Some(timeout) = connect_timeout {
        builder = builder.connect_timeout(timeout);
    }
    if let Some(timeout) = request_timeout {
        builder = builder.timeout(timeout);
    }
    builder
}

/// Finishes a client builder, reporting a failure as
/// [`AuthError::HttpClient`]: no request was made, so it must not read
/// as one that failed.
fn finish_client(builder: reqwest::ClientBuilder) -> AuthResult<reqwest::Client> {
    builder.build().map_err(AuthError::HttpClient)
}

/// The transport settings a flow builder collects for its token-endpoint
/// client: a caller-supplied client, or the timeouts to apply to the one
/// the builder constructs.
///
/// Each timeout is `None` until its setter is called; `Some(None)` is an
/// explicit request for no bound.
#[derive(Default)]
pub(super) struct HttpClientConfig {
    pub(super) client: Option<reqwest::Client>,
    pub(super) connect_timeout: Option<Option<Duration>>,
    pub(super) request_timeout: Option<Option<Duration>>,
}

impl HttpClientConfig {
    /// The client the flow will use. A supplied client wins outright,
    /// timeouts and redirect policy included.
    pub(super) fn into_client(self) -> AuthResult<reqwest::Client> {
        match self.client {
            Some(client) => Ok(client),
            None => finish_client(hardened_client_builder(
                self.connect_timeout
                    .unwrap_or(Some(DEFAULT_TOKEN_CONNECT_TIMEOUT)),
                self.request_timeout
                    .unwrap_or(Some(DEFAULT_TOKEN_REQUEST_TIMEOUT)),
            )),
        }
    }
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
    if crate::transport::is_secure_transport(&parsed) {
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

/// Whether a grant may be presented again after an attempt whose outcome
/// is unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum GrantReplay {
    /// Presenting the grant again has no side effect: a JWT bearer
    /// assertion stays valid for its whole window and Salesforce does not
    /// bind it to one use, and client credentials are not consumed. A 429,
    /// a 5xx and an ambiguous transport failure all retry.
    Safe,
    /// Presenting the grant again could consume or revoke something: an
    /// authorization code is single-use, a refresh token may have been
    /// rotated away by the attempt whose answer was lost, and a token
    /// exchange may issue tokens on every call. Only a failure where the
    /// request never left the client retries.
    Never,
}

/// Largest token-endpoint response body the SDK buffers. A token response
/// is a few kilobytes of JSON, so a body that does not fit came from an
/// intermediary rather than Salesforce.
pub(crate) const TOKEN_RESPONSE_BODY_CAP: usize = 64 * 1024;

/// Retries after the first token request, and the pause before each.
///
/// A mint therefore takes at most three request timeouts plus 750 ms. The
/// budget is deliberately small: the consumers' own retry policies do not
/// cover the mint, which runs before their request loop starts, and a
/// token endpoint that is down for longer than this should fail the call
/// rather than hold every request on the session.
const TOKEN_REQUEST_BACKOFF: [Duration; 2] =
    [Duration::from_millis(250), Duration::from_millis(500)];

/// Whether a failed send or a body that died mid-stream may be retried.
///
/// A request that could not be built fails the same way every time. A
/// connect-phase failure means nothing reached the server, so it retries
/// for every grant. Anything else is ambiguous and retries only for a
/// grant that is safe to replay.
fn transport_failure_is_retryable(error: &reqwest::Error, replay: GrantReplay) -> bool {
    if error.is_builder() {
        return false;
    }
    if error.is_connect() {
        return true;
    }
    replay == GrantReplay::Safe
}

/// POSTs a token-exchange form body to `{login_url}/services/oauth2/token`
/// and parses the response.
///
/// The caller assembles the form body with the flow-specific fields
/// (`grant_type`, `assertion`, `refresh_token`, etc.) and says whether the
/// grant is safe to replay. A connect failure is retried for every grant;
/// a 429, a 5xx and an ambiguous transport failure are retried only for a
/// [`GrantReplay::Safe`] grant, up to [`TOKEN_REQUEST_BACKOFF`]'s budget.
/// On a terminal non-2xx, the body is parsed as the OAuth error shape if
/// possible; otherwise only the status is surfaced as
/// [`AuthError::UnexpectedResponse`]. Such a body is neither carried nor
/// logged, since non-standard error pages can echo credentials. A body
/// over [`TOKEN_RESPONSE_BODY_CAP`] decoded bytes is refused as
/// [`AuthError::ResponseTooLarge`] on any status, without a retry.
pub(super) async fn exchange<B>(
    http: &reqwest::Client,
    login_url: &str,
    body: &B,
    replay: GrantReplay,
) -> AuthResult<TokenResponse>
where
    B: Serialize + ?Sized,
{
    let url = format!("{login_url}/services/oauth2/token");
    let mut attempt = 0usize;
    let (status, content_type, bytes) = loop {
        // `None` once the budget is spent: the attempt below is the last.
        let backoff = TOKEN_REQUEST_BACKOFF.get(attempt).copied();
        let response = match (http.post(&url).form(body).send().await, backoff) {
            (Ok(response), _) => response,
            (Err(e), Some(delay)) if transport_failure_is_retryable(&e, replay) => {
                tracing::warn!(
                    target: "cirrus_auth::token_endpoint",
                    attempt = attempt + 1,
                    error = %e,
                    "token request failed in transport; retrying",
                );
                tokio::time::sleep(delay).await;
                attempt += 1;
                continue;
            }
            (Err(e), _) => return Err(e.into()),
        };
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let bytes = match (
            collect_body(response, TOKEN_RESPONSE_BODY_CAP).await,
            backoff,
        ) {
            (Ok(bytes), _) => bytes,
            (Err(CollectBodyError::TooLarge { limit }), _) => {
                return Err(AuthError::ResponseTooLarge { status, limit });
            }
            // A body that dies mid-stream is as ambiguous as a lost
            // response: the server may already have acted on the grant.
            (Err(CollectBodyError::Transport(e)), Some(delay)) if replay == GrantReplay::Safe => {
                tracing::warn!(
                    target: "cirrus_auth::token_endpoint",
                    attempt = attempt + 1,
                    error = %e,
                    "token response body failed mid-stream; retrying",
                );
                tokio::time::sleep(delay).await;
                attempt += 1;
                continue;
            }
            (Err(CollectBodyError::Transport(e)), _) => return Err(e.into()),
        };
        if let Some(delay) = backoff
            && replay == GrantReplay::Safe
            && (status == 429 || (500..600).contains(&status))
        {
            tracing::warn!(
                target: "cirrus_auth::token_endpoint",
                attempt = attempt + 1,
                status,
                "token endpoint answered a retryable status; retrying",
            );
            tokio::time::sleep(delay).await;
            attempt += 1;
            continue;
        }
        break (status, content_type, bytes);
    };

    if !(200..300).contains(&status) {
        if let Ok(oauth_err) = serde_json::from_slice::<OAuthErrorResponse>(&bytes) {
            return Err(AuthError::OAuth {
                error: oauth_err.error,
                error_description: oauth_err.error_description,
            });
        }
        // A body outside the OAuth error shape came from an intermediary
        // (an HTML error page, a proxy), and those tend to echo the form
        // that provoked them, credentials included. The body is therefore
        // neither carried on the error nor logged at any level, since a
        // global TRACE filter would receive it. Status, content type and
        // length are enough to tell such a page from a Salesforce answer.
        tracing::trace!(
            target: "cirrus_auth::token_endpoint",
            status,
            content_type = content_type.as_deref().unwrap_or("<none>"),
            body_len = bytes.len(),
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
        // Salesforce's docs spell My Domain hosts in mixed case
        // (`MyDomainName.my.salesforce.com`) and a configured value can
        // be typed in any case, so the host compare is case-insensitive.
        // SOURCE: https://developer.salesforce.com/docs/atlas.en-us.sfdx_dev.meta/sfdx_dev/sfdx_dev_auth_jwt_flow.htm
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

    async fn mount_then_succeed(server: &wiremock::MockServer, first: u16, failures: u64) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .respond_with(ResponseTemplate::new(first))
            .up_to_n_times(failures)
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "00DXX!ACCESS",
                "instance_url": "https://my-org.my.salesforce.com",
            })))
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn a_replay_safe_grant_retries_429_and_5xx_within_the_budget() {
        let server = wiremock::MockServer::start().await;
        mount_then_succeed(&server, 503, 2).await;
        let http = token_client_builder().build().unwrap();
        let token = exchange(
            &http,
            &server.uri(),
            &[("grant_type", "client_credentials")],
            GrantReplay::Safe,
        )
        .await
        .unwrap();
        assert_eq!(token.access_token, "00DXX!ACCESS");
        assert_eq!(server.received_requests().await.unwrap().len(), 3);

        let server = wiremock::MockServer::start().await;
        mount_then_succeed(&server, 429, 1).await;
        exchange(
            &http,
            &server.uri(),
            &[("grant_type", "client_credentials")],
            GrantReplay::Safe,
        )
        .await
        .unwrap();
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn the_retry_budget_is_exhausted_after_three_attempts() {
        let server = wiremock::MockServer::start().await;
        mount_then_succeed(&server, 503, 3).await;
        let http = token_client_builder().build().unwrap();
        let err = exchange(
            &http,
            &server.uri(),
            &[("grant_type", "client_credentials")],
            GrantReplay::Safe,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, AuthError::UnexpectedResponse { status: 503 }),
            "{err:?}"
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn a_grant_marked_never_is_not_replayed_after_a_5xx() {
        let server = wiremock::MockServer::start().await;
        mount_then_succeed(&server, 503, 1).await;
        let http = token_client_builder().build().unwrap();
        let err = exchange(
            &http,
            &server.uri(),
            &[("grant_type", "refresh_token")],
            GrantReplay::Never,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, AuthError::UnexpectedResponse { status: 503 }),
            "{err:?}"
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn an_oversized_success_body_is_refused() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        let server = wiremock::MockServer::start().await;
        // A syntactically valid token response padded past the cap: the
        // size, not the shape, is what the endpoint refuses.
        let padded = serde_json::json!({
            "access_token": "00DXX!ACCESS",
            "instance_url": "https://my-org.my.salesforce.com",
            "scope": "x".repeat(1 << 20),
        });
        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(padded))
            .mount(&server)
            .await;
        let http = token_client_builder().build().unwrap();
        let err = exchange(
            &http,
            &server.uri(),
            &[("grant_type", "client_credentials")],
            GrantReplay::Safe,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(
                err,
                AuthError::ResponseTooLarge {
                    status: 200,
                    limit: TOKEN_RESPONSE_BODY_CAP
                }
            ),
            "{err:?}"
        );
        assert!(!err.to_string().contains("00DXX"), "{err}");
    }

    #[tokio::test]
    async fn an_oversized_error_body_is_refused_with_its_status() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        let server = wiremock::MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .respond_with(ResponseTemplate::new(503).set_body_bytes(vec![
                b'x';
                TOKEN_RESPONSE_BODY_CAP
                    + 1
            ]))
            .mount(&server)
            .await;
        let http = token_client_builder().build().unwrap();
        let err = exchange(
            &http,
            &server.uri(),
            &[("grant_type", "refresh_token")],
            GrantReplay::Never,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, AuthError::ResponseTooLarge { status: 503, .. }),
            "{err:?}"
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn an_oauth_error_is_never_retried() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        let server = wiremock::MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "invalid_grant"
            })))
            .mount(&server)
            .await;
        let http = token_client_builder().build().unwrap();
        let err = exchange(
            &http,
            &server.uri(),
            &[("grant_type", "client_credentials")],
            GrantReplay::Safe,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AuthError::OAuth { ref error, .. } if error == "invalid_grant"));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[test]
    fn https_and_loopback_login_urls_are_accepted() {
        require_secure_login_url("https://my-org.my.salesforce.com").unwrap();
        require_secure_login_url("http://127.0.0.1:8080").unwrap();
        require_secure_login_url("http://localhost:8080").unwrap();
        require_secure_login_url("http://[::1]:8080").unwrap();
    }

    #[test]
    fn a_dotted_localhost_login_url_is_rejected() {
        // `sf.localhost` is not the loopback exemption: resolvers may
        // forward it to DNS, so the shared rule in `crate::transport`
        // treats it like any other host.
        let err = require_secure_login_url("http://sf.localhost:8080").unwrap_err();
        assert!(
            matches!(err, AuthError::InsecureLoginUrl { .. }),
            "got {err:?}"
        );
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

    /// Records, as `target LEVEL field=value ...` lines, every event the
    /// recording thread emits under a `cirrus_auth` target while a
    /// [`Recording`] is alive.
    ///
    /// Installed once per process as the global subscriber, never as a
    /// scoped one: `tracing` caches each callsite's `Interest` process-wide,
    /// and the cache is filled by whichever thread reaches the callsite
    /// first. Under a scoped subscriber, a test running concurrently on
    /// another thread registers the callsite against the no-op dispatcher
    /// and caches `never`, after which this thread's events are dropped
    /// before any subscriber sees them. The global subscriber answers
    /// `Interest::sometimes()`, so every event consults `enabled`, which
    /// admits only a thread that is recording.
    struct Capture;

    thread_local! {
        static RECORDING: std::cell::RefCell<Option<Vec<String>>> =
            const { std::cell::RefCell::new(None) };
    }

    /// Collects the recording thread's events until it is dropped.
    struct Recording;

    impl Capture {
        fn record() -> Recording {
            static INSTALL: std::sync::Once = std::sync::Once::new();
            INSTALL.call_once(|| {
                tracing::subscriber::set_global_default(Capture)
                    .expect("no other global subscriber is installed in the test binary");
            });
            RECORDING.with(|lines| *lines.borrow_mut() = Some(Vec::new()));
            Recording
        }
    }

    impl Recording {
        fn lines(self) -> Vec<String> {
            RECORDING.with(|lines| lines.borrow_mut().take().unwrap_or_default())
        }
    }

    impl Drop for Recording {
        fn drop(&mut self) {
            RECORDING.with(|lines| *lines.borrow_mut() = None);
        }
    }

    impl tracing::Subscriber for Capture {
        fn register_callsite(
            &self,
            _: &'static tracing::Metadata<'static>,
        ) -> tracing::subscriber::Interest {
            tracing::subscriber::Interest::sometimes()
        }
        fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
            metadata.target().starts_with("cirrus_auth")
                && RECORDING.with(|lines| lines.borrow().is_some())
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            struct Line(String);
            impl tracing::field::Visit for Line {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    self.0.push_str(&format!(" {}={value:?}", field.name()));
                }
            }
            let metadata = event.metadata();
            let mut line = Line(format!("{} {}", metadata.target(), metadata.level()));
            event.record(&mut line);
            RECORDING.with(|lines| {
                if let Some(lines) = lines.borrow_mut().as_mut() {
                    lines.push(line.0);
                }
            });
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    #[tokio::test]
    async fn a_non_oauth_error_body_is_logged_by_shape_only() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        // An intermediary's error page can echo the form it was sent,
        // credentials included, so the event records only what tells a
        // proxy page from a Salesforce answer: status, content type and
        // length.
        let server = wiremock::MockServer::start().await;
        let body = "<html>proxy error: upstream token=LEAKED_SECRET</html>";
        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .respond_with(ResponseTemplate::new(502).set_body_raw(body, "text/html"))
            .mount(&server)
            .await;

        let recording = Capture::record();

        let http = token_client_builder().build().unwrap();
        let err = exchange(
            &http,
            &server.uri(),
            &[("grant_type", "refresh_token")],
            GrantReplay::Never,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AuthError::UnexpectedResponse { status: 502 }));

        let lines = recording.lines();
        let event = lines
            .iter()
            .find(|line| line.starts_with("cirrus_auth::token_endpoint TRACE"))
            .unwrap_or_else(|| {
                panic!("no TRACE event under cirrus_auth::token_endpoint in {lines:?}")
            });
        assert!(!event.contains("LEAKED_SECRET"), "{event}");
        for expected in [
            "status=502",
            "content_type=\"text/html\"",
            &format!("body_len={}", body.len()),
        ] {
            assert!(event.contains(expected), "missing {expected} in {event}");
        }
    }

    #[test]
    fn a_client_that_fails_to_build_is_an_http_client_error() {
        // An invalid default header value is reported when the client is
        // built, before any request exists.
        let err = finish_client(token_client_builder().user_agent("line\nbreak")).unwrap_err();
        assert!(
            matches!(err, AuthError::HttpClient(ref e) if e.is_builder()),
            "{err:?}"
        );
        assert_eq!(err.to_string(), "failed to construct HTTP client");
        assert!(!err.is_transient());
    }

    #[tokio::test]
    async fn token_client_builder_keeps_the_no_redirect_policy() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        let server = wiremock::MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .respond_with(ResponseTemplate::new(307).insert_header("Location", "/elsewhere"))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/elsewhere"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let http = token_client_builder().build().unwrap();
        let response = http
            .post(format!("{}/services/oauth2/token", server.uri()))
            .form(&[("grant_type", "refresh_token")])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 307);
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}
