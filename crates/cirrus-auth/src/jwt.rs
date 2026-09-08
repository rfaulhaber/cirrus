//! OAuth 2.0 JWT Bearer flow for Salesforce server-to-server auth.
//!
//! The caller pre-authorizes a Connected App by uploading a public X.509
//! certificate; this auth implementation holds the corresponding RSA private
//! key and mints fresh access tokens on demand by signing a short-lived JWT
//! and exchanging it at the OAuth token endpoint.
//!
//! ## `instance_url`
//!
//! `instance_url` is required at builder time and verified against the
//! value returned in the token response.
//!
//! ## Caching
//!
//! Each successful token exchange caches the access token for a configurable
//! TTL (default 30 minutes). The TTL is an upper bound, not a claim about
//! the token's true lifetime: the connected app's session policy is what
//! actually expires the token, and when the endpoint advertises an
//! `expires_in` shorter than the configured TTL the cache honours the
//! shorter of the two. After that window elapses, the next call mints a
//! new token regardless of whether the previous one would still have
//! worked.

use crate::AuthSession;
use crate::error::{AuthError, AuthResult};
use crate::token_endpoint::{
    check_instance_url, default_http_client, exchange, normalize_url, require_secure_login_url,
    token_is_fresh,
};
use async_trait::async_trait;
use camino::Utf8PathBuf;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Serialize;
use std::borrow::Cow;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

/// Salesforce production login URL — the default JWT audience and token
/// exchange host.
pub const PRODUCTION_LOGIN_URL: &str = "https://login.salesforce.com";

/// Salesforce sandbox login URL.
pub const SANDBOX_LOGIN_URL: &str = "https://test.salesforce.com";

/// Default cache TTL for an access token after it's issued.
const DEFAULT_TOKEN_TTL: Duration = Duration::from_secs(30 * 60);

/// JWT validity window, in seconds.
///
/// The signed assertion is a bearer credential in flight, so the window
/// is deliberately short: it only has to cover a single token request.
/// RFC 7523 §3 requires the authorization server to reject an `exp`
/// that has already passed and permits it to reject one that is
/// "unreasonably far in the future", so the slack that remains is there
/// for clock skew — it is the token endpoint's clock, not this host's,
/// that decides whether `exp` is still ahead.
// Salesforce is sometimes said to reject an assertion whose `exp` is
// more than three minutes ahead of its own clock. No fetchable doc page
// states such a ceiling and RFC 7523 sets no numeric bound, so this
// window sits under the reputed limit rather than at it: correct
// whether or not the ceiling is real.
const JWT_VALIDITY_SECS: i64 = 170;

#[derive(Serialize)]
struct JwtClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: i64,
}

// `iss` is the Connected App consumer key (a credential identifier) and
// `sub` is the Salesforce username (PII). Redact both so a stray
// `{:?}` in error-handling code never leaks them.
impl std::fmt::Debug for JwtClaims {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtClaims")
            .field("iss", &"[redacted]")
            .field("sub", &"[redacted]")
            .field("aud", &self.aud)
            .field("exp", &self.exp)
            .finish()
    }
}

#[derive(Clone)]
struct CachedToken {
    access_token: String,
    expires_at: Instant,
}

impl std::fmt::Debug for CachedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedToken")
            .field("access_token", &"[redacted]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// JWT Bearer flow auth session.
///
/// Construct via [`JwtAuth::builder`].
pub struct JwtAuth {
    consumer_key: String,
    username: String,
    encoding_key: EncodingKey,
    login_url: String,
    instance_url: String,
    token_ttl: Duration,
    http: reqwest::Client,
    cached: RwLock<Option<CachedToken>>,
}

impl std::fmt::Debug for JwtAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately omit consumer_key, username, and the encoding key —
        // all carry secrets or PII.
        f.debug_struct("JwtAuth")
            .field("login_url", &self.login_url)
            .field("instance_url", &self.instance_url)
            .field("token_ttl", &self.token_ttl)
            .finish_non_exhaustive()
    }
}

impl JwtAuth {
    /// Begins constructing a [`JwtAuth`].
    ///
    /// JWT bearer flow (RFC 7523): the SDK signs a JWT assertion with
    /// your connected app's private key and exchanges it for an access
    /// token at the configured login URL. Cached access tokens are
    /// refreshed transparently on 401.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use cirrus_auth::JwtAuth;
    /// use std::sync::Arc;
    ///
    /// # fn example() -> Result<(), cirrus_auth::AuthError> {
    /// let auth = JwtAuth::builder()
    ///     .consumer_key("3MVG9...")
    ///     .username("integration-user@example.com")
    ///     .login_url("https://login.salesforce.com")
    ///     .instance_url("https://my-org.my.salesforce.com")
    ///     .private_key_pem_file("./private.pem")?
    ///     .build()?;
    /// // Wrap as Arc<dyn AuthSession> and hand to a Cirrus client.
    /// let _shared = Arc::new(auth);
    /// # Ok(())
    /// # }
    /// ```
    pub fn builder() -> JwtAuthBuilder {
        JwtAuthBuilder::default()
    }

    async fn mint_token(&self) -> AuthResult<CachedToken> {
        tracing::info!(
            target: "cirrus::auth",
            flow = "jwt-bearer",
            login_url = %self.login_url,
            "minting fresh access token",
        );
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .map_err(|e| AuthError::Other(format!("system clock before UNIX epoch: {e}")))?;

        let claims = JwtClaims {
            iss: self.consumer_key.clone(),
            sub: self.username.clone(),
            aud: self.login_url.clone(),
            exp: now_secs + JWT_VALIDITY_SECS,
        };

        let header = Header::new(Algorithm::RS256);
        let assertion = jsonwebtoken::encode(&header, &claims, &self.encoding_key)
            .map_err(|e| AuthError::Signing(e.to_string()))?;

        let body = [
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", assertion.as_str()),
        ];

        let token = exchange(&self.http, &self.login_url, &body).await?;
        check_instance_url(&self.instance_url, &token)?;

        let expires_at = token.cache_expiry(self.token_ttl);
        Ok(CachedToken {
            access_token: token.access_token,
            expires_at,
        })
    }
}

#[async_trait]
impl AuthSession for JwtAuth {
    async fn access_token(&self) -> AuthResult<Cow<'_, str>> {
        // Fast path — read lock, return clone of cached token if still valid.
        {
            let guard = self.cached.read().await;
            if let Some(cached) = guard.as_ref()
                && token_is_fresh(cached.expires_at)
            {
                return Ok(Cow::Owned(cached.access_token.clone()));
            }
        }

        // Slow path — write lock, double-check, mint.
        let mut guard = self.cached.write().await;
        if let Some(cached) = guard.as_ref()
            && token_is_fresh(cached.expires_at)
        {
            return Ok(Cow::Owned(cached.access_token.clone()));
        }
        let new_token = self.mint_token().await?;
        let token_str = new_token.access_token.clone();
        *guard = Some(new_token);
        Ok(Cow::Owned(token_str))
    }

    fn instance_url(&self) -> &str {
        &self.instance_url
    }

    async fn invalidate(&self, stale_token: &str) {
        // Compare-and-swap: only clear the cached token if it still
        // matches what the failing request used. Avoids racing with a
        // concurrent task that already refreshed.
        let mut guard = self.cached.write().await;
        if let Some(cached) = guard.as_ref()
            && cached.access_token == stale_token
        {
            tracing::debug!(
                target: "cirrus::auth",
                flow = "jwt-bearer",
                "invalidating cached token (CAS matched)",
            );
            *guard = None;
        } else {
            tracing::trace!(
                target: "cirrus::auth",
                flow = "jwt-bearer",
                "invalidate called but cached token differs (concurrent refresh?); no-op",
            );
        }
    }
}

/// Builder for [`JwtAuth`].
#[derive(Default)]
pub struct JwtAuthBuilder {
    consumer_key: Option<String>,
    username: Option<String>,
    encoding_key: Option<EncodingKey>,
    login_url: Option<String>,
    instance_url: Option<String>,
    token_ttl: Option<Duration>,
    http_client: Option<reqwest::Client>,
}

impl std::fmt::Debug for JwtAuthBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Show which fields have been set without leaking secret-bearing values.
        f.debug_struct("JwtAuthBuilder")
            .field("consumer_key", &self.consumer_key.is_some())
            .field("username", &self.username.is_some())
            .field("private_key", &self.encoding_key.is_some())
            .field("login_url", &self.login_url)
            .field("instance_url", &self.instance_url)
            .field("token_ttl", &self.token_ttl)
            .finish_non_exhaustive()
    }
}

impl JwtAuthBuilder {
    /// Connected App's Consumer Key (a.k.a. Client ID) — used as the JWT
    /// `iss` claim.
    pub fn consumer_key(mut self, key: impl Into<String>) -> Self {
        self.consumer_key = Some(key.into());
        self
    }

    /// Salesforce username to authenticate as — used as the JWT `sub` claim.
    pub fn username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    /// Loads the RSA private key from a PEM file at the given path.
    pub fn private_key_pem_file(mut self, path: impl Into<Utf8PathBuf>) -> AuthResult<Self> {
        let path = path.into();
        let bytes = fs_err::read(path.as_std_path())
            .map_err(|e| AuthError::Other(format!("failed to read private key: {e}")))?;
        self.encoding_key = Some(
            EncodingKey::from_rsa_pem(&bytes)
                .map_err(|e| AuthError::Other(format!("invalid RSA PEM key: {e}")))?,
        );
        Ok(self)
    }

    /// Loads the RSA private key directly from PEM-encoded bytes. Useful
    /// when the key is held in memory (e.g. fetched from a secret manager).
    pub fn private_key_pem_bytes(mut self, bytes: &[u8]) -> AuthResult<Self> {
        self.encoding_key = Some(
            EncodingKey::from_rsa_pem(bytes)
                .map_err(|e| AuthError::Other(format!("invalid RSA PEM key: {e}")))?,
        );
        Ok(self)
    }

    /// Login URL — the host that receives the JWT, also used as the JWT
    /// `aud` claim. Defaults to [`PRODUCTION_LOGIN_URL`]. Use
    /// [`SANDBOX_LOGIN_URL`] for sandboxes.
    ///
    /// When the URL your users log in through is not
    /// `login.salesforce.com`, set this to your org's enhanced My Domain
    /// login URL instead — for example
    /// `https://MyDomainName.my.salesforce.com`, or
    /// `https://MyDomainName--SandboxName.sandbox.my.salesforce.com` for a
    /// sandbox. Salesforce recommends the My Domain form because it
    /// survives org migrations that change the underlying instance.
    ///
    /// This is the authorization server, not the org's REST host: keep
    /// [`instance_url`](Self::instance_url) pointing at the API endpoint
    /// even when the two happen to be the same host.
    ///
    /// Must be `https` (loopback hosts excepted, for local test servers).
    pub fn login_url(mut self, url: impl Into<String>) -> Self {
        self.login_url = Some(url.into());
        self
    }

    /// REST instance URL — the org's My Domain (e.g.
    /// `https://my-org.my.salesforce.com`). Required. Must match the
    /// `instance_url` that Salesforce returns from the token exchange.
    pub fn instance_url(mut self, url: impl Into<String>) -> Self {
        self.instance_url = Some(url.into());
        self
    }

    /// Upper bound on how long an access token is cached before
    /// re-minting. Defaults to 30 minutes. Set lower to refresh more
    /// aggressively; raising it does not extend a token past a shorter
    /// `expires_in` advertised by the token endpoint, which always wins.
    pub fn token_ttl(mut self, ttl: Duration) -> Self {
        self.token_ttl = Some(ttl);
        self
    }

    /// Supplies a pre-configured `reqwest::Client` for the token-exchange
    /// requests. Useful for sharing a connection pool across multiple SDK
    /// clients.
    ///
    /// The client built by default applies connect and request timeouts
    /// and refuses to follow redirects, so a redirect cannot replay the
    /// signed assertion to another host. A client supplied here replaces
    /// those defaults wholesale — configure both on it.
    pub fn http_client(mut self, client: reqwest::Client) -> Self {
        self.http_client = Some(client);
        self
    }

    /// Finalizes the builder.
    pub fn build(self) -> AuthResult<JwtAuth> {
        let consumer_key = self
            .consumer_key
            .ok_or(AuthError::MissingField("consumer_key"))?;
        let username = self.username.ok_or(AuthError::MissingField("username"))?;
        let encoding_key = self
            .encoding_key
            .ok_or(AuthError::MissingField("private_key"))?;
        let instance_url = normalize_url(
            &self
                .instance_url
                .ok_or(AuthError::MissingField("instance_url"))?,
        );
        let login_url = normalize_url(
            &self
                .login_url
                .unwrap_or_else(|| PRODUCTION_LOGIN_URL.to_string()),
        );
        require_secure_login_url(&login_url)?;
        let token_ttl = self.token_ttl.unwrap_or(DEFAULT_TOKEN_TTL);
        let http = match self.http_client {
            Some(client) => client,
            None => default_http_client()?,
        };

        Ok(JwtAuth {
            consumer_key,
            username,
            encoding_key,
            login_url,
            instance_url,
            token_ttl,
            http,
            cached: RwLock::new(None),
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    /// Throwaway test-only RSA private key. No security value.
    /// See `tests/fixtures/test_rsa_key.pem`.
    const TEST_PEM: &[u8] = include_bytes!("../tests/fixtures/test_rsa_key.pem");

    fn builder_with_required_fields() -> JwtAuthBuilder {
        JwtAuth::builder()
            .consumer_key("consumer-key-123")
            .username("integration@example.com")
            .private_key_pem_bytes(TEST_PEM)
            .unwrap()
            .instance_url("https://my-org.my.salesforce.com")
    }

    #[test]
    fn builder_requires_consumer_key() {
        let err = JwtAuth::builder()
            .username("u")
            .private_key_pem_bytes(TEST_PEM)
            .unwrap()
            .instance_url("https://x")
            .build()
            .unwrap_err();
        assert!(matches!(err, AuthError::MissingField("consumer_key")));
    }

    #[test]
    fn builder_requires_username() {
        let err = JwtAuth::builder()
            .consumer_key("k")
            .private_key_pem_bytes(TEST_PEM)
            .unwrap()
            .instance_url("https://x")
            .build()
            .unwrap_err();
        assert!(matches!(err, AuthError::MissingField("username")));
    }

    #[test]
    fn builder_requires_private_key() {
        let err = JwtAuth::builder()
            .consumer_key("k")
            .username("u")
            .instance_url("https://x")
            .build()
            .unwrap_err();
        assert!(matches!(err, AuthError::MissingField("private_key")));
    }

    #[test]
    fn builder_requires_instance_url() {
        let err = JwtAuth::builder()
            .consumer_key("k")
            .username("u")
            .private_key_pem_bytes(TEST_PEM)
            .unwrap()
            .build()
            .unwrap_err();
        assert!(matches!(err, AuthError::MissingField("instance_url")));
    }

    #[test]
    fn invalid_pem_is_surfaced_as_auth_error() {
        let err = JwtAuth::builder()
            .private_key_pem_bytes(b"not a pem")
            .unwrap_err();
        assert!(matches!(err, AuthError::Other(_)));
    }

    #[test]
    fn builder_strips_trailing_slashes_and_defaults_login_url() {
        let auth = builder_with_required_fields()
            .instance_url("https://my-org.my.salesforce.com//")
            .build()
            .unwrap();
        assert_eq!(auth.instance_url(), "https://my-org.my.salesforce.com");
        assert_eq!(auth.login_url, PRODUCTION_LOGIN_URL);
    }

    #[tokio::test]
    async fn mint_token_succeeds_and_caches() {
        let server = MockServer::start().await;
        let hits = Arc::new(AtomicUsize::new(0));
        let body = serde_json::json!({
            "access_token": "00DXX!ACCESS",
            "instance_url": "https://my-org.my.salesforce.com",
            "token_type": "Bearer",
            "scope": "api",
            "id": "https://login.salesforce.com/id/00DXX/005XX",
        });

        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .and(body_string_contains("grant_type=urn"))
            .and(body_string_contains("assertion="))
            .respond_with(CountingResponder {
                hits: hits.clone(),
                response: ResponseTemplate::new(200).set_body_json(body),
            })
            .mount(&server)
            .await;

        let auth = builder_with_required_fields()
            .login_url(server.uri())
            .build()
            .unwrap();

        let t1 = auth.access_token().await.unwrap();
        assert_eq!(&*t1, "00DXX!ACCESS");
        let t2 = auth.access_token().await.unwrap();
        assert_eq!(&*t2, "00DXX!ACCESS");

        // Second call must reuse the cached token, not call the endpoint again.
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn expired_cache_remints_token() {
        let server = MockServer::start().await;
        let hits = Arc::new(AtomicUsize::new(0));

        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .respond_with(CountingResponder {
                hits: hits.clone(),
                response: ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": "tok",
                    "instance_url": "https://my-org.my.salesforce.com"
                })),
            })
            .mount(&server)
            .await;

        let auth = builder_with_required_fields()
            .login_url(server.uri())
            .token_ttl(Duration::ZERO) // every call re-mints
            .build()
            .unwrap();

        let _ = auth.access_token().await.unwrap();
        let _ = auth.access_token().await.unwrap();
        let _ = auth.access_token().await.unwrap();

        assert_eq!(hits.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn oauth_error_response_is_surfaced() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "invalid_grant",
                "error_description": "user hasn't approved this consumer"
            })))
            .mount(&server)
            .await;

        let auth = builder_with_required_fields()
            .login_url(server.uri())
            .build()
            .unwrap();

        let err = auth.access_token().await.unwrap_err();
        match err {
            AuthError::OAuth {
                error,
                error_description,
            } => {
                assert_eq!(error, "invalid_grant");
                assert!(error_description.is_some());
            }
            other => panic!("expected OAuth error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn instance_url_mismatch_is_an_auth_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "tok",
                "instance_url": "https://different-org.my.salesforce.com"
            })))
            .mount(&server)
            .await;

        let auth = builder_with_required_fields()
            .login_url(server.uri())
            .build()
            .unwrap();

        let err = auth.access_token().await.unwrap_err();
        assert!(
            matches!(err, AuthError::InstanceUrlMismatch { .. }),
            "{err:?}"
        );
    }

    /// `invalidate(stale_token)` is a compare-and-swap: it should
    /// only clear the cached token when the cached value matches
    /// `stale_token`. This is the contract for all three flows
    /// (Jwt, Refresh, ClientCredentials); we test it here as the
    /// canonical example since the impls are identical.
    #[tokio::test]
    async fn invalidate_clears_cache_only_when_stale_token_matches() {
        let server = MockServer::start().await;
        let hits = Arc::new(AtomicUsize::new(0));
        let body = serde_json::json!({
            "access_token": "T1",
            "instance_url": "https://my-org.my.salesforce.com",
            "token_type": "Bearer",
        });

        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .respond_with(CountingResponder {
                hits: hits.clone(),
                response: ResponseTemplate::new(200).set_body_json(body),
            })
            .mount(&server)
            .await;

        let auth = builder_with_required_fields()
            .login_url(server.uri())
            .build()
            .unwrap();

        // First call mints T1; cache populated.
        let t = auth.access_token().await.unwrap();
        assert_eq!(&*t, "T1");
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        drop(t);

        // Invalidate with a *non-matching* stale_token — should be a
        // no-op, cache stays populated.
        auth.invalidate("not-the-cached-token").await;
        let t = auth.access_token().await.unwrap();
        assert_eq!(&*t, "T1");
        // No re-mint — the cache wasn't cleared.
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        drop(t);

        // Invalidate with the *matching* stale_token — clears cache.
        auth.invalidate("T1").await;
        // Next access call must re-mint.
        let t = auth.access_token().await.unwrap();
        assert_eq!(&*t, "T1"); // mock still returns T1
        assert_eq!(hits.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn builder_rejects_cleartext_login_url() {
        let err = builder_with_required_fields()
            .login_url("http://my-org.my.salesforce.com")
            .build()
            .unwrap_err();
        assert!(matches!(err, AuthError::InsecureLoginUrl { .. }), "{err:?}");
    }

    #[tokio::test]
    async fn assertion_carries_the_grant_type_and_claims_salesforce_validates() {
        // Salesforce validates the signed assertion, not the form field
        // names, so the claim set is the part a regression would break
        // silently. RFC 7523 §3 requires iss, sub, aud and exp; the
        // grant_type URN is fixed by §2.1.
        let server = MockServer::start().await;
        let captured = Arc::new(tokio::sync::Mutex::new(String::new()));
        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .respond_with(BodyCapturingResponder {
                captured: captured.clone(),
                response: ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": "tok",
                    "instance_url": "https://my-org.my.salesforce.com",
                })),
            })
            .mount(&server)
            .await;

        let auth = builder_with_required_fields()
            .login_url(server.uri())
            .build()
            .unwrap();
        auth.access_token().await.unwrap();

        let body = captured.lock().await;
        let params: Vec<(String, String)> = serde_urlencoded::from_str(&body).unwrap();
        let field = |name: &str| {
            params
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
                .unwrap_or_else(|| panic!("{name} missing from body: {body}"))
        };

        assert_eq!(
            field("grant_type"),
            "urn:ietf:params:oauth:grant-type:jwt-bearer"
        );

        let assertion = field("assertion");
        let mut parts = assertion.split('.');
        let header = decode_jwt_segment(parts.next().unwrap());
        let claims = decode_jwt_segment(parts.next().unwrap());
        assert!(parts.next().is_some(), "assertion must carry a signature");

        assert_eq!(header["alg"], "RS256");
        assert_eq!(claims["iss"], "consumer-key-123");
        assert_eq!(claims["sub"], "integration@example.com");
        // `aud` identifies the authorization server, so it tracks
        // login_url — never instance_url.
        assert_eq!(claims["aud"], server.uri());

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let exp = claims["exp"].as_i64().expect("exp must be a number");
        assert!(
            exp > now,
            "assertion is already expired: exp={exp} now={now}"
        );
        // Pins this crate's own validity window; RFC 7523 sets no
        // numeric bound and makes no claim about Salesforce's tolerance.
        assert!(
            exp <= now + JWT_VALIDITY_SECS,
            "exp exceeds the SDK's validity window: exp={exp} now={now}"
        );
    }

    /// Base64url-decodes one dot-separated JWT segment into JSON.
    fn decode_jwt_segment(segment: &str) -> serde_json::Value {
        let bytes = URL_SAFE_NO_PAD
            .decode(segment)
            .expect("segment is base64url");
        serde_json::from_slice(&bytes).expect("segment is JSON")
    }

    /// Captures the request body so assertions can read individual form
    /// parameters rather than substring-matching the whole body.
    struct BodyCapturingResponder {
        captured: Arc<tokio::sync::Mutex<String>>,
        response: ResponseTemplate,
    }

    impl Respond for BodyCapturingResponder {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            let body = String::from_utf8_lossy(&request.body).into_owned();
            if let Ok(mut guard) = self.captured.try_lock() {
                *guard = body;
            }
            self.response.clone()
        }
    }

    /// Wraps a [`ResponseTemplate`] and counts invocations. Wiremock's
    /// `expect()` would also work, but counting lets us assert post-hoc.
    struct CountingResponder {
        hits: Arc<AtomicUsize>,
        response: ResponseTemplate,
    }

    impl Respond for CountingResponder {
        fn respond(&self, _: &Request) -> ResponseTemplate {
            self.hits.fetch_add(1, Ordering::SeqCst);
            self.response.clone()
        }
    }
}
