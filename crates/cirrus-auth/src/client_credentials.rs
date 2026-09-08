//! OAuth 2.0 Client Credentials grant for server-to-server integrations.
//!
//! The client app trades its `consumer_key`/`consumer_secret` for an access
//! token tied to a pre-configured integration user on the External Client
//! App / Connected App. Per RFC 6749 §4.4 this grant is for confidential
//! clients only — there is no public-client variant — so `consumer_secret`
//! is mandatory.
//!
//! ## Salesforce-specific configuration
//!
//! Beyond the standard OAuth wire shape, Salesforce requires the connected
//! app's admin to designate a "Run As" user. That happens entirely on the
//! org side; the SDK has nothing to configure for it. If the connected app
//! is not set up with a run-as user, the token endpoint returns
//! `invalid_client` or `invalid_grant`, which surface as
//! [`AuthError::OAuth`].
//!
//! ## My Domain URL is mandatory
//!
//! Per the Salesforce help docs ("OAuth 2.0 Client Credentials Flow for
//! Server-to-Server Integration"): *"For this flow, requests to
//! `https://login.salesforce.com` and `https://test.salesforce.com` aren't
//! supported. Use your My Domain URL instead."* The builder therefore has
//! no `PRODUCTION_LOGIN_URL`/`SANDBOX_LOGIN_URL` defaults — `login_url` is
//! required and must be the org's My Domain (e.g.
//! `https://my-org.my.salesforce.com`).
//!
//! ## No refresh token
//!
//! Per RFC 6749 §4.4.3, the Client Credentials grant does not issue a
//! refresh token. Token rotation is handled by re-running the grant when
//! the local TTL elapses; semantics match [`crate::jwt::JwtAuth`].

use crate::AuthSession;
use crate::error::{AuthError, AuthResult};
use crate::token_endpoint::{
    check_instance_url, default_http_client, exchange, normalize_url, require_secure_login_url,
    token_is_fresh,
};
use async_trait::async_trait;
use std::borrow::Cow;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Default cache TTL for an access token after it's issued.
const DEFAULT_TOKEN_TTL: Duration = Duration::from_secs(30 * 60);

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

/// Client-credentials-grant auth session.
///
/// Construct via [`ClientCredentialsAuth::builder`].
pub struct ClientCredentialsAuth {
    consumer_key: String,
    consumer_secret: String,
    login_url: String,
    instance_url: String,
    token_ttl: Duration,
    http: reqwest::Client,
    cached: RwLock<Option<CachedToken>>,
}

impl std::fmt::Debug for ClientCredentialsAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Omit consumer_key and consumer_secret — both are credentials.
        f.debug_struct("ClientCredentialsAuth")
            .field("login_url", &self.login_url)
            .field("instance_url", &self.instance_url)
            .field("token_ttl", &self.token_ttl)
            .finish_non_exhaustive()
    }
}

impl ClientCredentialsAuth {
    /// Begins constructing a [`ClientCredentialsAuth`].
    ///
    /// Client-credentials grant (RFC 6749 §4.4): server-to-server flow
    /// where the connected app's consumer key + secret are exchanged
    /// directly for an access token, no user context. The connected
    /// app's "Run As" user determines record-level visibility.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use cirrus_auth::ClientCredentialsAuth;
    /// use std::sync::Arc;
    ///
    /// # fn example() -> Result<(), cirrus_auth::AuthError> {
    /// let auth = ClientCredentialsAuth::builder()
    ///     .consumer_key("3MVG9...")
    ///     .consumer_secret("28A2...")
    ///     .login_url("https://my-org.my.salesforce.com")
    ///     .instance_url("https://my-org.my.salesforce.com")
    ///     .build()?;
    /// // Wrap as Arc<dyn AuthSession> and hand to a Cirrus client.
    /// let _shared = Arc::new(auth);
    /// # Ok(())
    /// # }
    /// ```
    pub fn builder() -> ClientCredentialsAuthBuilder {
        ClientCredentialsAuthBuilder::default()
    }

    async fn mint_token(&self) -> AuthResult<CachedToken> {
        tracing::info!(
            target: "cirrus::auth",
            flow = "client-credentials",
            login_url = %self.login_url,
            "minting fresh access token",
        );
        let body = [
            ("grant_type", "client_credentials"),
            ("client_id", self.consumer_key.as_str()),
            ("client_secret", self.consumer_secret.as_str()),
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
impl AuthSession for ClientCredentialsAuth {
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
                flow = "client-credentials",
                "invalidating cached token (CAS matched)",
            );
            *guard = None;
        } else {
            tracing::trace!(
                target: "cirrus::auth",
                flow = "client-credentials",
                "invalidate called but cached token differs (concurrent refresh?); no-op",
            );
        }
    }
}

/// Builder for [`ClientCredentialsAuth`].
#[derive(Default)]
pub struct ClientCredentialsAuthBuilder {
    consumer_key: Option<String>,
    consumer_secret: Option<String>,
    login_url: Option<String>,
    instance_url: Option<String>,
    token_ttl: Option<Duration>,
    http_client: Option<reqwest::Client>,
}

impl std::fmt::Debug for ClientCredentialsAuthBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientCredentialsAuthBuilder")
            .field("consumer_key", &self.consumer_key.is_some())
            .field("consumer_secret", &self.consumer_secret.is_some())
            .field("login_url", &self.login_url)
            .field("instance_url", &self.instance_url)
            .field("token_ttl", &self.token_ttl)
            .finish_non_exhaustive()
    }
}

impl ClientCredentialsAuthBuilder {
    /// Connected App's Consumer Key (Client ID). Required.
    pub fn consumer_key(mut self, key: impl Into<String>) -> Self {
        self.consumer_key = Some(key.into());
        self
    }

    /// Connected App's Consumer Secret (Client Secret). Required —
    /// Client Credentials is a confidential-client-only grant.
    pub fn consumer_secret(mut self, secret: impl Into<String>) -> Self {
        self.consumer_secret = Some(secret.into());
        self
    }

    /// Login URL — the host serving `/services/oauth2/token`. Required;
    /// must be the org's My Domain URL (e.g.
    /// `https://my-org.my.salesforce.com`). Salesforce explicitly rejects
    /// this flow at `https://login.salesforce.com` and
    /// `https://test.salesforce.com`. Must be `https` (loopback hosts
    /// excepted, for local test servers).
    pub fn login_url(mut self, url: impl Into<String>) -> Self {
        self.login_url = Some(url.into());
        self
    }

    /// REST instance URL — the org's My Domain. Required. Must match the
    /// `instance_url` returned by the token-exchange response (compared
    /// after trailing slashes are trimmed, ignoring ASCII case).
    pub fn instance_url(mut self, url: impl Into<String>) -> Self {
        self.instance_url = Some(url.into());
        self
    }

    /// Upper bound on how long an access token is cached before
    /// re-minting. Defaults to 30 minutes. Raising it does not extend a
    /// token past a shorter `expires_in` advertised by the token
    /// endpoint, which always wins.
    pub fn token_ttl(mut self, ttl: Duration) -> Self {
        self.token_ttl = Some(ttl);
        self
    }

    /// Supplies a pre-configured `reqwest::Client`. Useful for sharing a
    /// connection pool.
    ///
    /// The client built by default applies connect and request timeouts
    /// and refuses to follow redirects, so a redirect cannot replay the
    /// consumer secret to another host. A client supplied here replaces
    /// those defaults wholesale — configure both on it.
    pub fn http_client(mut self, client: reqwest::Client) -> Self {
        self.http_client = Some(client);
        self
    }

    /// Finalizes the builder.
    pub fn build(self) -> AuthResult<ClientCredentialsAuth> {
        let consumer_key = self
            .consumer_key
            .ok_or(AuthError::MissingField("consumer_key"))?;
        let consumer_secret = self
            .consumer_secret
            .ok_or(AuthError::MissingField("consumer_secret"))?;
        let instance_url = normalize_url(
            &self
                .instance_url
                .ok_or(AuthError::MissingField("instance_url"))?,
        );
        let login_url = normalize_url(&self.login_url.ok_or(AuthError::MissingField("login_url"))?);
        require_secure_login_url(&login_url)?;
        let token_ttl = self.token_ttl.unwrap_or(DEFAULT_TOKEN_TTL);
        let http = match self.http_client {
            Some(client) => client,
            None => default_http_client()?,
        };

        Ok(ClientCredentialsAuth {
            consumer_key,
            consumer_secret,
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
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    fn builder_with_required_fields() -> ClientCredentialsAuthBuilder {
        ClientCredentialsAuth::builder()
            .consumer_key("consumer-key-123")
            .consumer_secret("top-secret")
            .instance_url("https://my-org.my.salesforce.com")
            .login_url("https://my-org.my.salesforce.com")
    }

    #[test]
    fn builder_requires_consumer_key() {
        let err = ClientCredentialsAuth::builder()
            .consumer_secret("s")
            .instance_url("https://x")
            .build()
            .unwrap_err();
        assert!(matches!(err, AuthError::MissingField("consumer_key")));
    }

    #[test]
    fn builder_requires_consumer_secret() {
        let err = ClientCredentialsAuth::builder()
            .consumer_key("k")
            .instance_url("https://x")
            .build()
            .unwrap_err();
        assert!(matches!(err, AuthError::MissingField("consumer_secret")));
    }

    #[test]
    fn builder_requires_instance_url() {
        let err = ClientCredentialsAuth::builder()
            .consumer_key("k")
            .consumer_secret("s")
            .login_url("https://x")
            .build()
            .unwrap_err();
        assert!(matches!(err, AuthError::MissingField("instance_url")));
    }

    #[test]
    fn builder_requires_login_url() {
        // Salesforce rejects Client Credentials at login.salesforce.com /
        // test.salesforce.com — there's no safe default, so the builder
        // must demand a My Domain URL up front.
        let err = ClientCredentialsAuth::builder()
            .consumer_key("k")
            .consumer_secret("s")
            .instance_url("https://x")
            .build()
            .unwrap_err();
        assert!(matches!(err, AuthError::MissingField("login_url")));
    }

    #[test]
    fn builder_strips_trailing_slashes_on_login_and_instance_url() {
        let auth = builder_with_required_fields()
            .instance_url("https://my-org.my.salesforce.com//")
            .login_url("https://my-org.my.salesforce.com/")
            .build()
            .unwrap();
        assert_eq!(auth.instance_url(), "https://my-org.my.salesforce.com");
        assert_eq!(auth.login_url, "https://my-org.my.salesforce.com");
    }

    #[tokio::test]
    async fn mint_succeeds_and_caches() {
        let server = MockServer::start().await;
        let hits = Arc::new(AtomicUsize::new(0));

        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .and(body_string_contains("grant_type=client_credentials"))
            .and(body_string_contains("client_id=consumer-key-123"))
            .and(body_string_contains("client_secret=top-secret"))
            .respond_with(CountingResponder {
                hits: hits.clone(),
                response: ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": "00DXX!ACCESS",
                    "instance_url": "https://my-org.my.salesforce.com",
                    "token_type": "Bearer",
                    "id": "https://login.salesforce.com/id/00DXX/005XX",
                })),
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
            .token_ttl(Duration::ZERO)
            .build()
            .unwrap();

        let _ = auth.access_token().await.unwrap();
        let _ = auth.access_token().await.unwrap();
        let _ = auth.access_token().await.unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn token_within_refresh_margin_is_treated_as_expired() {
        // A configured TTL shorter than the 60s refresh margin means every
        // cached token is already inside its refresh window, so each call
        // re-mints. 30s < 60s, so this is deterministic without sleeping.
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
            .token_ttl(Duration::from_secs(30))
            .build()
            .unwrap();

        let _ = auth.access_token().await.unwrap();
        let _ = auth.access_token().await.unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn shorter_server_expires_in_wins_over_configured_ttl() {
        // The response advertises a 1-second lifetime while the configured
        // TTL is the 30-minute default. The short server-advertised lifetime
        // must win, putting the token immediately inside the refresh margin
        // so it re-mints on every call.
        let server = MockServer::start().await;
        let hits = Arc::new(AtomicUsize::new(0));

        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .respond_with(CountingResponder {
                hits: hits.clone(),
                response: ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": "tok",
                    "instance_url": "https://my-org.my.salesforce.com",
                    "expires_in": 1
                })),
            })
            .mount(&server)
            .await;

        let auth = builder_with_required_fields()
            .login_url(server.uri())
            // Default 30-minute TTL — would otherwise cache for the whole run.
            .build()
            .unwrap();

        let _ = auth.access_token().await.unwrap();
        let _ = auth.access_token().await.unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn longer_server_expires_in_does_not_extend_configured_ttl() {
        // The mirror case: the endpoint advertises two hours while the
        // caller pinned the cache to 30 seconds because the org's session
        // policy is short. Honouring the server value would keep shipping
        // a dead token until the advertised lifetime elapsed, so the
        // configured bound has to win.
        let server = MockServer::start().await;
        let hits = Arc::new(AtomicUsize::new(0));

        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .respond_with(CountingResponder {
                hits: hits.clone(),
                response: ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": "tok",
                    "instance_url": "https://my-org.my.salesforce.com",
                    "expires_in": 7200
                })),
            })
            .mount(&server)
            .await;

        let auth = builder_with_required_fields()
            .login_url(server.uri())
            // Shorter than the 60s refresh margin, so a token cached for
            // this long is always already stale.
            .token_ttl(Duration::from_secs(30))
            .build()
            .unwrap();

        let _ = auth.access_token().await.unwrap();
        let _ = auth.access_token().await.unwrap();
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
    async fn invalid_client_surfaces_oauth_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "invalid_client",
                "error_description": "client identifier invalid"
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
                assert_eq!(error, "invalid_client");
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
                "instance_url": "https://wrong-org.my.salesforce.com"
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

    /// Counts invocations and returns a fixed response. Same shape as the
    /// JWT/Refresh tests' helpers; duplicated to keep test modules
    /// self-contained.
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
