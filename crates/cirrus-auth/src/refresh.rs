//! OAuth 2.0 Refresh Token grant for long-lived Salesforce sessions.
//!
//! Several Salesforce OAuth flows hand back a `refresh_token` alongside
//! the initial access token. This module wraps that grant in an
//! [`AuthSession`] so the rest of the SDK doesn't care which flow
//! originally produced the refresh token.
//!
//! ## Refresh token lifetime
//!
//! How long a refresh token keeps working is an org policy, not a
//! property of the token. The connected app's `refreshTokenPolicy` is a
//! required setting with four options: `infinite` (the default — valid
//! until revoked), `zero`, a fixed `specific_lifetime:n:HOURS|DAYS|MONTHS`,
//! or a sliding `specific_inactivity:n:HOURS|DAYS|MONTHS` window. So a
//! refresh token can also die by exceeding its lifetime, by going unused
//! past the inactivity window, or — under Refresh Token Rotation — by
//! being superseded.
//!
//! All of those surface identically: the grant fails with
//! [`AuthError::OAuth`] carrying `invalid_grant`. This session records no
//! terminal state, so the next call retries the same doomed grant. Treat a
//! persistent `invalid_grant` here as "the user must re-authorize" rather
//! than as a transient fault, and alert on it.
//!
//! ## Usage
//!
//! Perform the initial OAuth exchange to obtain a `refresh_token` and
//! `instance_url`, build a [`RefreshTokenAuth`] with those values, and
//! hand it (wrapped in `Arc<dyn AuthSession>`) to a Cirrus client. New
//! access tokens are minted on demand by hitting
//! `/services/oauth2/token` with `grant_type=refresh_token`.
//!
//! ## Confidential vs public clients
//!
//! Connected Apps configured as **confidential clients** require a
//! `client_secret` on every refresh; **public clients** (PKCE-based) do
//! not. The builder treats `consumer_secret` as optional — set it for
//! confidential clients, omit it for public.
//!
//! ## Token rotation
//!
//! Some orgs enable **Refresh Token Rotation**: each refresh-grant response
//! returns a new `refresh_token` and invalidates the one just used.
//! Rotation is server-controlled — when it is enabled the session adopts
//! each replacement transparently and keeps working. When it is disabled
//! (the default for classic Connected Apps) refresh responses carry no new
//! token and the original keeps being reused for as long as the org's
//! `refreshTokenPolicy` allows, so non-rotating orgs are unaffected.
//!
//! Adopting a rotated token in memory is enough for a process that holds
//! one session for its whole lifetime. Consumers that **persist** the
//! refresh token across restarts must register a [`RotationHandler`] via
//! [`RefreshTokenAuthBuilder::on_rotation`] to durably store each
//! replacement — otherwise a restart resurrects an already-invalidated
//! token, which the server rejects (and, under rotation, revokes the
//! entire token family, forcing re-authorization).
//!
//! Minting is cancellation-safe: the refresh exchange, rotation adoption,
//! and handler notification run in a task detached from the calling
//! future, so a caller dropped mid-refresh — a disconnected client, an
//! elapsed timeout, a losing `select!` branch — cannot strand a rotated
//! token. The replacement is still adopted and the handler still fires.
//! (Minting spawns onto the ambient Tokio runtime — already required by
//! this crate's HTTP stack — and panics outside one.)
//!
//! The flip side is that a detached mint holds the session's write lock
//! until it finishes, and abandoning the caller's future does not shorten
//! that. What bounds it is the token-endpoint client's own timeout, which
//! the default client sets. A client supplied through
//! [`RefreshTokenAuthBuilder::http_client`] with no timeouts of its own
//! reintroduces the unbounded case: against an endpoint that accepts the
//! connection and never answers, every concurrent `access_token` and
//! `invalidate` on this session blocks for as long as the stall lasts.
//!
//! Because reusing a rotated-away token revokes the whole family, one
//! stored token must back exactly one session: share a single
//! `Arc<RefreshTokenAuth>` across clients rather than building several
//! sessions from the same token.

use crate::AuthSession;
use crate::error::{AuthError, AuthResult};
use crate::token_endpoint::{
    check_instance_url, default_http_client, exchange, normalize_url, require_secure_login_url,
    token_is_fresh,
};
use async_trait::async_trait;
use std::borrow::Cow;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Salesforce production login URL — also the default token-exchange host.
pub const PRODUCTION_LOGIN_URL: &str = "https://login.salesforce.com";

/// Salesforce sandbox login URL.
pub const SANDBOX_LOGIN_URL: &str = "https://test.salesforce.com";

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

/// Interior state guarded by a single lock: the live refresh token (which
/// rotation may replace) and the cached access token. Folding both into one
/// lock makes rotation serialize against minting — every mint reads and
/// writes the pair through the same write guard, so two refreshes can never
/// race to rotate, and a rotated-away token is never reused.
struct AuthState {
    refresh_token: String,
    cached: Option<CachedToken>,
}

/// Callback invoked when the session adopts a rotated refresh token.
///
/// Salesforce orgs with **Refresh Token Rotation** enabled return a new
/// `refresh_token` on every refresh and invalidate the previous one.
/// [`RefreshTokenAuth`] adopts the replacement in memory automatically;
/// register a handler when the token is **persisted** somewhere durable so
/// the stored copy tracks each rotation. Without one, a restart reuses a
/// dead token.
///
/// The handler is awaited while the session holds its internal write lock,
/// before the triggering [`access_token`](AuthSession::access_token) call
/// returns. That ordering is deliberate — persistence completes before any
/// further token use, so a crash cannot strand the credential between
/// rotation and storage. Two consequences follow:
///
/// - The handler **must not** call back into the same session (for example
///   [`access_token`](AuthSession::access_token)): it would deadlock on the
///   held lock.
/// - A slow handler stalls every concurrent `access_token` call for its
///   duration. Keep it quick and give durable I/O its own timeout.
///
/// The handler runs even when the `access_token` call that triggered the
/// rotation is cancelled mid-flight: the mint executes in a task detached
/// from the caller, so a dropped future cannot skip persistence.
///
/// The signature is infallible: by the time it runs the rotation has
/// already taken effect at Salesforce and cannot be undone, so there is
/// nothing for the SDK to recover from. A handler that fails to persist
/// owns that failure — log it, retry internally, or accept that a restart
/// will require re-authorization.
#[async_trait]
pub trait RotationHandler: Send + Sync {
    /// Called with the replacement refresh token each time one is adopted.
    /// The previous token is already invalid at Salesforce when this runs.
    async fn on_rotation(&self, new_refresh_token: &str);
}

/// Everything a mint needs besides the mutable [`AuthState`], bundled
/// behind one `Arc` so the slow path can move a clone into the detached
/// mint task (which must own `'static` data).
struct MintConfig {
    consumer_key: String,
    consumer_secret: Option<String>,
    login_url: String,
    instance_url: String,
    token_ttl: Duration,
    http: reqwest::Client,
    rotation_handler: Option<Arc<dyn RotationHandler>>,
}

/// Refresh-token-grant auth session.
///
/// Construct via [`RefreshTokenAuth::builder`].
pub struct RefreshTokenAuth {
    config: Arc<MintConfig>,
    state: Arc<RwLock<AuthState>>,
}

impl std::fmt::Debug for RefreshTokenAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Omit consumer_key, consumer_secret, and the refresh/access tokens
        // held in `state` — all secrets.
        f.debug_struct("RefreshTokenAuth")
            .field("login_url", &self.config.login_url)
            .field("instance_url", &self.config.instance_url)
            .field("token_ttl", &self.config.token_ttl)
            .field("confidential", &self.config.consumer_secret.is_some())
            .field("rotation_handler", &self.config.rotation_handler.is_some())
            .finish_non_exhaustive()
    }
}

impl RefreshTokenAuth {
    /// Begins constructing a [`RefreshTokenAuth`].
    ///
    /// Refresh-token grant (RFC 6749 §6): once an access token is
    /// obtained through any flow that issues a refresh token (typically
    /// Web Server with PKCE), use that refresh token to mint new access
    /// tokens for as long as the connected app's `refreshTokenPolicy`
    /// keeps it valid — see the [module docs](self) for what ends that.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use cirrus_auth::RefreshTokenAuth;
    /// use std::sync::Arc;
    ///
    /// # fn example() -> Result<(), cirrus_auth::AuthError> {
    /// let auth = RefreshTokenAuth::builder()
    ///     .consumer_key("3MVG9...")
    ///     .refresh_token("5Aep861...")
    ///     .login_url("https://login.salesforce.com")
    ///     .instance_url("https://my-org.my.salesforce.com")
    ///     .build()?;
    /// // Wrap as Arc<dyn AuthSession> and hand to a Cirrus client.
    /// let _shared = Arc::new(auth);
    /// # Ok(())
    /// # }
    /// ```
    pub fn builder() -> RefreshTokenAuthBuilder {
        RefreshTokenAuthBuilder::default()
    }
}

impl MintConfig {
    /// Mints a fresh access token through the refresh grant, mutating
    /// `state` in place: the current refresh token is read from it, and a
    /// rotated replacement (if any) is written back.
    ///
    /// Called only under the `state` write lock, so the read-then-write of
    /// the refresh token is serialized against every other mint.
    async fn mint_token(&self, state: &mut AuthState) -> AuthResult<CachedToken> {
        tracing::info!(
            target: "cirrus::auth",
            flow = "refresh-token",
            login_url = %self.login_url,
            "minting fresh access token",
        );
        // Snapshot the current refresh token before the await: the body
        // borrows it, and it must not alias `state` when the rotated
        // replacement is written back below.
        let current_refresh = state.refresh_token.clone();

        // Compose the form body. consumer_secret is conditional on whether
        // the connected app is confidential.
        let mut body: Vec<(&str, &str)> = vec![
            ("grant_type", "refresh_token"),
            ("client_id", self.consumer_key.as_str()),
            ("refresh_token", current_refresh.as_str()),
        ];
        if let Some(secret) = self.consumer_secret.as_deref() {
            body.push(("client_secret", secret));
        }

        let token = exchange(&self.http, &self.login_url, &body).await?;

        // Adopt a rotated refresh token before any post-exchange failure
        // path (e.g. the instance_url check below). Once `exchange` returns
        // 2xx under Refresh Token Rotation, `current_refresh` is already
        // dead at Salesforce and the replacement is the only usable
        // credential — it must be persisted even if this call later aborts.
        if let Some(rotated) = token.refresh_token.as_deref()
            && rotated != current_refresh
        {
            state.refresh_token = rotated.to_string();
            tracing::info!(
                target: "cirrus::auth",
                flow = "refresh-token",
                "adopted rotated refresh token",
            );
            if let Some(handler) = &self.rotation_handler {
                handler.on_rotation(rotated).await;
            }
        }

        check_instance_url(&self.instance_url, &token)?;

        let expires_at = token.cache_expiry(self.token_ttl);
        Ok(CachedToken {
            access_token: token.access_token,
            expires_at,
        })
    }
}

#[async_trait]
impl AuthSession for RefreshTokenAuth {
    async fn access_token(&self) -> AuthResult<Cow<'_, str>> {
        // Fast path — read lock, return clone of cached token if still valid.
        {
            let guard = self.state.read().await;
            if let Some(cached) = guard.cached.as_ref()
                && token_is_fresh(cached.expires_at)
            {
                return Ok(Cow::Owned(cached.access_token.clone()));
            }
        }

        // Slow path — take an owned write guard, double-check, mint. The
        // write lock serializes refresh-token rotation: `mint_token` reads
        // and replaces the token through this guard, so no two mints can
        // race.
        //
        // The mint runs in a detached task because it is not cancellation-
        // safe: once the refresh grant reaches a Refresh Token Rotation org,
        // the token just presented is dead and the replacement exists only
        // in the response, so the adoption and handler notification must run
        // even if this caller is dropped mid-await (client disconnect,
        // timeout, `select!`). Awaiting the JoinHandle abandons only the
        // result, never the mint; the moved guard is released when the task
        // finishes, and the cache write stays inside the task so a cancelled
        // caller still leaves the fresh token behind.
        let mut guard = Arc::clone(&self.state).write_owned().await;
        if let Some(cached) = guard.cached.as_ref()
            && token_is_fresh(cached.expires_at)
        {
            return Ok(Cow::Owned(cached.access_token.clone()));
        }
        let config = Arc::clone(&self.config);
        let task = tokio::spawn(async move {
            let minted = config.mint_token(&mut guard).await?;
            let token = minted.access_token.clone();
            guard.cached = Some(minted);
            Ok::<_, AuthError>(token)
        });
        match task.await {
            Ok(result) => result.map(Cow::Owned),
            // Report only *that* the task failed. `JoinError`'s `Display`
            // embeds the panic payload verbatim, and the one piece of
            // caller code running inside the task is
            // `RotationHandler::on_rotation`, whose argument is a live
            // refresh token — a handler that panics with that value in its
            // message would put it into an error that every other path in
            // this crate would have redacted.
            Err(join_error) if join_error.is_panic() => {
                Err(AuthError::Other("token mint task panicked".to_string()))
            }
            Err(_) => Err(AuthError::Other(
                "token mint task did not run to completion".to_string(),
            )),
        }
    }

    fn instance_url(&self) -> &str {
        &self.config.instance_url
    }

    async fn invalidate(&self, stale_token: &str) {
        // Compare-and-swap: only clear the cached access token if it
        // still matches what the failing request used. The underlying
        // refresh_token isn't affected — we only ever want the
        // *short-lived* access token re-minted.
        let mut guard = self.state.write().await;
        if let Some(cached) = guard.cached.as_ref()
            && cached.access_token == stale_token
        {
            tracing::debug!(
                target: "cirrus::auth",
                flow = "refresh-token",
                "invalidating cached token (CAS matched)",
            );
            guard.cached = None;
        } else {
            tracing::trace!(
                target: "cirrus::auth",
                flow = "refresh-token",
                "invalidate called but cached token differs (concurrent refresh?); no-op",
            );
        }
    }
}

/// Builder for [`RefreshTokenAuth`].
#[derive(Default)]
pub struct RefreshTokenAuthBuilder {
    consumer_key: Option<String>,
    consumer_secret: Option<String>,
    refresh_token: Option<String>,
    login_url: Option<String>,
    instance_url: Option<String>,
    token_ttl: Option<Duration>,
    http_client: Option<reqwest::Client>,
    rotation_handler: Option<Arc<dyn RotationHandler>>,
}

impl std::fmt::Debug for RefreshTokenAuthBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefreshTokenAuthBuilder")
            .field("consumer_key", &self.consumer_key.is_some())
            .field("consumer_secret", &self.consumer_secret.is_some())
            .field("refresh_token", &self.refresh_token.is_some())
            .field("login_url", &self.login_url)
            .field("instance_url", &self.instance_url)
            .field("token_ttl", &self.token_ttl)
            .field("rotation_handler", &self.rotation_handler.is_some())
            .finish_non_exhaustive()
    }
}

impl RefreshTokenAuthBuilder {
    /// Connected App's Consumer Key (Client ID). Required.
    pub fn consumer_key(mut self, key: impl Into<String>) -> Self {
        self.consumer_key = Some(key.into());
        self
    }

    /// Connected App's Consumer Secret (Client Secret). Required for
    /// confidential clients; omit for public/PKCE clients.
    pub fn consumer_secret(mut self, secret: impl Into<String>) -> Self {
        self.consumer_secret = Some(secret.into());
        self
    }

    /// Refresh token issued by a prior OAuth flow (Web Server, Device,
    /// User-Agent). Required.
    ///
    /// This is the *initial* token. Against an org with Refresh Token
    /// Rotation enabled it is superseded at runtime as the session adopts
    /// each rotated replacement; register an
    /// [`on_rotation`](Self::on_rotation) handler to persist those
    /// replacements across restarts.
    pub fn refresh_token(mut self, token: impl Into<String>) -> Self {
        self.refresh_token = Some(token.into());
        self
    }

    /// Registers a [`RotationHandler`] invoked whenever the session adopts a
    /// rotated refresh token (Refresh Token Rotation). Optional: without a
    /// handler, rotations are still adopted in memory but not persisted —
    /// enough for a process that holds the session for its whole lifetime,
    /// insufficient for a consumer that stores the token across restarts.
    pub fn on_rotation(mut self, handler: Arc<dyn RotationHandler>) -> Self {
        self.rotation_handler = Some(handler);
        self
    }

    /// Login URL — the host that issued the refresh token. Defaults to
    /// [`PRODUCTION_LOGIN_URL`]. Use [`SANDBOX_LOGIN_URL`] for sandboxes,
    /// or your org's My Domain login URL where required. Must be `https`
    /// (loopback hosts excepted, for local test servers).
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
    /// and refuses to follow redirects, so a stalled endpoint cannot park
    /// a mint indefinitely and a redirect cannot replay the refresh token
    /// to another host. A client supplied here replaces those defaults
    /// wholesale: without its own timeouts, a token endpoint that accepts
    /// the connection and never answers blocks every concurrent
    /// [`access_token`](crate::AuthSession::access_token) and
    /// [`invalidate`](crate::AuthSession::invalidate) call on this session
    /// for as long as it stalls.
    pub fn http_client(mut self, client: reqwest::Client) -> Self {
        self.http_client = Some(client);
        self
    }

    /// Finalizes the builder.
    pub fn build(self) -> AuthResult<RefreshTokenAuth> {
        let consumer_key = self
            .consumer_key
            .ok_or(AuthError::MissingField("consumer_key"))?;
        let refresh_token = self
            .refresh_token
            .ok_or(AuthError::MissingField("refresh_token"))?;
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

        Ok(RefreshTokenAuth {
            config: Arc::new(MintConfig {
                consumer_key,
                consumer_secret: self.consumer_secret,
                login_url,
                instance_url,
                token_ttl,
                http,
                rotation_handler: self.rotation_handler,
            }),
            state: Arc::new(RwLock::new(AuthState {
                refresh_token,
                cached: None,
            })),
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

    fn builder_with_required_fields() -> RefreshTokenAuthBuilder {
        RefreshTokenAuth::builder()
            .consumer_key("consumer-key-123")
            .refresh_token("5Aep861KIwKdekr...refresh")
            .instance_url("https://my-org.my.salesforce.com")
    }

    #[test]
    fn builder_requires_consumer_key() {
        let err = RefreshTokenAuth::builder()
            .refresh_token("r")
            .instance_url("https://x")
            .build()
            .unwrap_err();
        assert!(matches!(err, AuthError::MissingField("consumer_key")));
    }

    #[test]
    fn builder_requires_refresh_token() {
        let err = RefreshTokenAuth::builder()
            .consumer_key("k")
            .instance_url("https://x")
            .build()
            .unwrap_err();
        assert!(matches!(err, AuthError::MissingField("refresh_token")));
    }

    #[test]
    fn builder_requires_instance_url() {
        let err = RefreshTokenAuth::builder()
            .consumer_key("k")
            .refresh_token("r")
            .build()
            .unwrap_err();
        assert!(matches!(err, AuthError::MissingField("instance_url")));
    }

    #[test]
    fn builder_strips_trailing_slashes_and_defaults_login_url() {
        let auth = builder_with_required_fields()
            .instance_url("https://my-org.my.salesforce.com//")
            .build()
            .unwrap();
        assert_eq!(auth.instance_url(), "https://my-org.my.salesforce.com");
        assert_eq!(auth.config.login_url, PRODUCTION_LOGIN_URL);
    }

    #[test]
    fn builder_rejects_cleartext_login_url() {
        let err = builder_with_required_fields()
            .login_url("http://my-org.my.salesforce.com")
            .build()
            .unwrap_err();
        assert!(matches!(err, AuthError::InsecureLoginUrl { .. }), "{err:?}");
    }

    #[tokio::test]
    async fn refresh_succeeds_and_caches() {
        let server = MockServer::start().await;
        let hits = Arc::new(AtomicUsize::new(0));

        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .and(body_string_contains("grant_type=refresh_token"))
            .and(body_string_contains("client_id=consumer-key-123"))
            .and(body_string_contains("refresh_token=5Aep861KIwKdekr"))
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
    async fn confidential_client_includes_consumer_secret() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .and(body_string_contains("client_secret=top-secret"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "tok",
                "instance_url": "https://my-org.my.salesforce.com"
            })))
            .mount(&server)
            .await;

        let auth = builder_with_required_fields()
            .consumer_secret("top-secret")
            .login_url(server.uri())
            .build()
            .unwrap();

        // The body matcher above asserts client_secret is present. If it
        // weren't, the mock would 404 and this would error.
        auth.access_token().await.unwrap();
    }

    #[tokio::test]
    async fn public_client_omits_consumer_secret() {
        let server = MockServer::start().await;
        // Match a body that does NOT include client_secret. wiremock has no
        // direct "does not contain" matcher, so we rely on the structure:
        // assert presence of grant_type and absence is verified by total
        // body inspection in the responder.
        let received_body = Arc::new(tokio::sync::Mutex::new(String::new()));
        let captured = received_body.clone();

        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .respond_with(BodyCapturingResponder {
                captured,
                response: ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": "tok",
                    "instance_url": "https://my-org.my.salesforce.com"
                })),
            })
            .mount(&server)
            .await;

        let auth = builder_with_required_fields()
            .login_url(server.uri())
            .build()
            .unwrap();
        auth.access_token().await.unwrap();

        let body = received_body.lock().await;
        assert!(
            !body.contains("client_secret"),
            "public client should not send client_secret, got: {body}"
        );
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
    async fn revoked_refresh_token_surfaces_oauth_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "invalid_grant",
                "error_description": "expired authorization code"
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
    async fn non_oauth_error_body_is_not_echoed_in_error() {
        // A non-2xx body that isn't the OAuth error shape (proxy HTML, etc.)
        // must not be folded into the error message — it can reflect token
        // material, and the message flows into logs. Only the status survives.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .respond_with(
                ResponseTemplate::new(502)
                    .set_body_string("<html>proxy error: upstream token=LEAKED_SECRET</html>"),
            )
            .mount(&server)
            .await;

        let auth = builder_with_required_fields()
            .login_url(server.uri())
            .build()
            .unwrap();

        let err = auth.access_token().await.unwrap_err();
        match &err {
            AuthError::UnexpectedResponse { status } => assert_eq!(*status, 502),
            other => panic!("expected UnexpectedResponse, got {other:?}"),
        }
        // Neither Display nor Debug should surface the body either.
        assert!(!format!("{err}").contains("LEAKED_SECRET"));
        assert!(!format!("{err:?}").contains("LEAKED_SECRET"));
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

    /// Counts invocations and returns a fixed response. Same as the JWT
    /// tests' helper — duplicated rather than shared to keep test modules
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

    /// Captures the request body for inspection. Used to assert that
    /// `client_secret` is absent in the public-client case.
    struct BodyCapturingResponder {
        captured: Arc<tokio::sync::Mutex<String>>,
        response: ResponseTemplate,
    }

    impl Respond for BodyCapturingResponder {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            let body = String::from_utf8_lossy(&request.body).into_owned();
            // try_lock works because this responder is invoked in the
            // request-handling task; the test reads after access_token returns.
            if let Ok(mut guard) = self.captured.try_lock() {
                *guard = body;
            }
            self.response.clone()
        }
    }

    // ----- Refresh Token Rotation (RTR) -----
    //
    // Wire shape per Salesforce Help, "Force one-time-use Refresh Tokens":
    // an RTR-enabled refresh-grant response is the standard token response
    // plus a fresh `refresh_token` that supersedes the one just sent.
    // https://help.salesforce.com/s/articleView?id=005316711&type=1

    /// The refresh token [`builder_with_required_fields`] starts with. Kept
    /// as a constant so rotation tests can assert it is *not* reused once a
    /// replacement is adopted.
    const INITIAL_REFRESH_TOKEN: &str = "5Aep861KIwKdekr...refresh";

    /// A 200 token response for `my-org`, optionally carrying a rotated
    /// `refresh_token` (present iff the org has RTR enabled).
    fn token_response(access_token: &str, rotated_refresh: Option<&str>) -> ResponseTemplate {
        let mut body = serde_json::json!({
            "access_token": access_token,
            "instance_url": "https://my-org.my.salesforce.com",
            "token_type": "Bearer",
        });
        if let Some(rotated) = rotated_refresh {
            body["refresh_token"] = serde_json::Value::String(rotated.to_string());
        }
        ResponseTemplate::new(200).set_body_json(body)
    }

    /// Returns a canned sequence of responses (clamping to the last for any
    /// extra hits) and records every request body for later inspection.
    struct SequencedResponder {
        hits: Arc<AtomicUsize>,
        request_bodies: Arc<tokio::sync::Mutex<Vec<String>>>,
        responses: Vec<ResponseTemplate>,
    }

    impl Respond for SequencedResponder {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            let idx = self.hits.fetch_add(1, Ordering::SeqCst);
            if let Ok(mut bodies) = self.request_bodies.try_lock() {
                bodies.push(String::from_utf8_lossy(&request.body).into_owned());
            }
            let i = idx.min(self.responses.len().saturating_sub(1));
            self.responses[i].clone()
        }
    }

    /// Records each rotated token it is handed, in order.
    struct RecordingHandler {
        seen: Arc<tokio::sync::Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl RotationHandler for RecordingHandler {
        async fn on_rotation(&self, new_refresh_token: &str) {
            self.seen.lock().await.push(new_refresh_token.to_string());
        }
    }

    #[tokio::test]
    async fn rotation_adopts_new_refresh_token_on_next_mint() {
        let server = MockServer::start().await;
        let bodies = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .respond_with(SequencedResponder {
                hits: Arc::new(AtomicUsize::new(0)),
                request_bodies: bodies.clone(),
                responses: vec![
                    token_response("ACCESS1", Some("R2")),
                    token_response("ACCESS2", Some("R3")),
                ],
            })
            .mount(&server)
            .await;

        let auth = builder_with_required_fields()
            .login_url(server.uri())
            .token_ttl(Duration::ZERO) // force a re-mint on every call
            .build()
            .unwrap();

        auth.access_token().await.unwrap();
        auth.access_token().await.unwrap();

        let bodies = bodies.lock().await;
        assert_eq!(bodies.len(), 2);
        assert!(
            bodies[0].contains(INITIAL_REFRESH_TOKEN),
            "first mint should use the original token: {}",
            bodies[0]
        );
        assert!(
            bodies[1].contains("refresh_token=R2"),
            "second mint should use the rotated token: {}",
            bodies[1]
        );
        assert!(
            !bodies[1].contains(INITIAL_REFRESH_TOKEN),
            "second mint must not reuse the invalidated token: {}",
            bodies[1]
        );
    }

    #[tokio::test]
    async fn handler_fires_once_per_rotation_in_order() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .respond_with(SequencedResponder {
                hits: Arc::new(AtomicUsize::new(0)),
                request_bodies: Arc::new(tokio::sync::Mutex::new(Vec::new())),
                responses: vec![
                    token_response("A1", Some("R2")),
                    token_response("A2", Some("R3")),
                ],
            })
            .mount(&server)
            .await;

        let seen = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let auth = builder_with_required_fields()
            .login_url(server.uri())
            .token_ttl(Duration::ZERO)
            .on_rotation(Arc::new(RecordingHandler { seen: seen.clone() }))
            .build()
            .unwrap();

        auth.access_token().await.unwrap();
        auth.access_token().await.unwrap();

        assert_eq!(*seen.lock().await, vec!["R2".to_string(), "R3".to_string()]);
    }

    #[tokio::test]
    async fn handler_not_fired_when_response_omits_refresh_token() {
        // Non-RTR org: refresh responses carry no `refresh_token`.
        let server = MockServer::start().await;
        let bodies = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .respond_with(SequencedResponder {
                hits: Arc::new(AtomicUsize::new(0)),
                request_bodies: bodies.clone(),
                responses: vec![token_response("A1", None), token_response("A2", None)],
            })
            .mount(&server)
            .await;

        let seen = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let auth = builder_with_required_fields()
            .login_url(server.uri())
            .token_ttl(Duration::ZERO)
            .on_rotation(Arc::new(RecordingHandler { seen: seen.clone() }))
            .build()
            .unwrap();

        auth.access_token().await.unwrap();
        auth.access_token().await.unwrap();

        assert!(
            seen.lock().await.is_empty(),
            "handler must not fire without rotation"
        );
        let bodies = bodies.lock().await;
        assert!(
            bodies[1].contains(INITIAL_REFRESH_TOKEN),
            "without rotation the original token keeps being reused: {}",
            bodies[1]
        );
    }

    #[tokio::test]
    async fn handler_not_fired_when_response_echoes_same_token() {
        // Defensive: a response that echoes the *same* refresh token is not
        // a rotation and must not fire the handler.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "A1",
                "instance_url": "https://my-org.my.salesforce.com",
                "refresh_token": INITIAL_REFRESH_TOKEN,
            })))
            .mount(&server)
            .await;

        let seen = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let auth = builder_with_required_fields()
            .login_url(server.uri())
            .on_rotation(Arc::new(RecordingHandler { seen: seen.clone() }))
            .build()
            .unwrap();

        auth.access_token().await.unwrap();

        assert!(
            seen.lock().await.is_empty(),
            "an echoed identical token is not a rotation"
        );
    }

    #[tokio::test]
    async fn handler_completes_before_access_token_returns() {
        // The handler is awaited under the write lock, so its effect must be
        // observable synchronously the instant `access_token` returns — a
        // fire-and-forget (spawned) handler would fail this.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .respond_with(token_response("A1", Some("R2")))
            .mount(&server)
            .await;

        let seen = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let auth = builder_with_required_fields()
            .login_url(server.uri())
            .on_rotation(Arc::new(RecordingHandler { seen: seen.clone() }))
            .build()
            .unwrap();

        auth.access_token().await.unwrap();
        // No await between the call above and this read other than the lock
        // acquisition itself; the handler has already run.
        assert_eq!(*seen.lock().await, vec!["R2".to_string()]);
    }

    #[tokio::test]
    async fn rotation_adopted_even_when_instance_url_mismatches() {
        // The rotated token must be adopted (and persisted) before the
        // instance_url check aborts the call — otherwise the mismatch error
        // would discard the only live credential.
        let server = MockServer::start().await;
        let bodies = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .respond_with(SequencedResponder {
                hits: Arc::new(AtomicUsize::new(0)),
                request_bodies: bodies.clone(),
                responses: vec![
                    // Rotates to R2 but reports the wrong instance_url → error.
                    ResponseTemplate::new(200).set_body_json(serde_json::json!({
                        "access_token": "A1",
                        "instance_url": "https://wrong-org.my.salesforce.com",
                        "refresh_token": "R2",
                    })),
                    // Correct org, rotates again to R3.
                    token_response("A2", Some("R3")),
                ],
            })
            .mount(&server)
            .await;

        let seen = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let auth = builder_with_required_fields()
            .login_url(server.uri())
            .token_ttl(Duration::ZERO)
            .on_rotation(Arc::new(RecordingHandler { seen: seen.clone() }))
            .build()
            .unwrap();

        let err = auth.access_token().await.unwrap_err();
        assert!(
            matches!(err, AuthError::InstanceUrlMismatch { .. }),
            "expected mismatch error, got {err:?}"
        );
        assert_eq!(
            *seen.lock().await,
            vec!["R2".to_string()],
            "R2 must be adopted despite the mismatch"
        );

        // The next mint uses the adopted R2, not the dead original.
        auth.access_token().await.unwrap();
        let bodies = bodies.lock().await;
        assert!(
            bodies[1].contains("refresh_token=R2"),
            "recovery mint should use the adopted token: {}",
            bodies[1]
        );
        assert!(
            !bodies[1].contains(INITIAL_REFRESH_TOKEN),
            "recovery mint must not reuse the invalidated original: {}",
            bodies[1]
        );
    }

    #[tokio::test]
    async fn cancelled_mint_still_adopts_rotation() {
        // Under Refresh Token Rotation an abandoned mint is catastrophic:
        // once the server processes the grant, the token that was presented
        // is dead and the replacement exists only in the response. A caller
        // dropped mid-exchange (client disconnect, timeout, `select!`) must
        // not abort the mint — it runs detached, adopts the rotation, and
        // fires the handler regardless.
        let server = MockServer::start().await;
        let bodies = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .respond_with(SequencedResponder {
                hits: Arc::new(AtomicUsize::new(0)),
                request_bodies: bodies.clone(),
                responses: vec![
                    // Slow enough that the caller's timeout below always
                    // elapses while the exchange is still in flight.
                    token_response("A1", Some("R2")).set_delay(Duration::from_millis(400)),
                    token_response("A2", Some("R3")),
                ],
            })
            .mount(&server)
            .await;

        let seen = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let auth = builder_with_required_fields()
            .login_url(server.uri())
            .token_ttl(Duration::ZERO) // the follow-up call below must re-mint
            .on_rotation(Arc::new(RecordingHandler { seen: seen.clone() }))
            .build()
            .unwrap();

        let cancelled = tokio::time::timeout(Duration::from_millis(50), auth.access_token()).await;
        assert!(cancelled.is_err(), "caller must be dropped mid-mint");

        // The mint outlives the cancelled caller: wait (bounded) for the
        // handler to observe the rotated token.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if *seen.lock().await == ["R2"] {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "rotation was not adopted after the caller was cancelled"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // This call completing also proves the write lock held during the
        // detached mint was released when it finished.
        auth.access_token().await.unwrap();
        let bodies = bodies.lock().await;
        assert_eq!(bodies.len(), 2);
        assert!(
            bodies[1].contains("refresh_token=R2"),
            "post-cancellation mint should use the adopted token: {}",
            bodies[1]
        );
        assert!(
            !bodies[1].contains(INITIAL_REFRESH_TOKEN),
            "post-cancellation mint must not present the invalidated token: {}",
            bodies[1]
        );
    }

    /// Panics when notified, with the live refresh token in the payload —
    /// drives the mint task's panic-recovery path and proves the payload
    /// never reaches the returned error.
    struct PanickingHandler;

    #[async_trait]
    impl RotationHandler for PanickingHandler {
        async fn on_rotation(&self, new_refresh_token: &str) {
            panic!("failed to persist refresh token {new_refresh_token}");
        }
    }

    #[tokio::test]
    async fn mint_task_panic_surfaces_as_auth_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .respond_with(token_response("A1", Some("R2")))
            .mount(&server)
            .await;

        let auth = builder_with_required_fields()
            .login_url(server.uri())
            .on_rotation(Arc::new(PanickingHandler))
            .build()
            .unwrap();

        let err = auth.access_token().await.unwrap_err();
        assert!(
            matches!(err, AuthError::Other(_)),
            "handler panic must surface as an AuthError, got {err:?}"
        );
        // tokio's `JoinError: Display` embeds the panic payload verbatim.
        // Formatting it into the error would put the rotated refresh token
        // into any log that prints the failure.
        assert!(
            !format!("{err}").contains("R2"),
            "panic payload leaked into Display: {err}"
        );
        assert!(
            !format!("{err:?}").contains("R2"),
            "panic payload leaked into Debug: {err:?}"
        );

        // R2 was adopted before the handler ran, and the unwinding task
        // released the lock. The next mint presents R2; the mock echoes the
        // same token back, which is not a rotation, so no handler fires and
        // the call succeeds.
        auth.access_token().await.unwrap();
    }

    #[test]
    fn debug_output_redacts_tokens_and_secrets() {
        let seen = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let auth = builder_with_required_fields()
            .consumer_secret("super-secret-value")
            .on_rotation(Arc::new(RecordingHandler { seen }))
            .build()
            .unwrap();

        let dbg = format!("{auth:?}");
        assert!(
            !dbg.contains(INITIAL_REFRESH_TOKEN),
            "refresh token leaked: {dbg}"
        );
        assert!(
            !dbg.contains("super-secret-value"),
            "consumer secret leaked: {dbg}"
        );
        assert!(
            !dbg.contains("consumer-key-123"),
            "consumer key leaked: {dbg}"
        );
        // The presence flag is fine to surface; the material is not.
        assert!(dbg.contains("rotation_handler: true"));

        let builder = builder_with_required_fields().consumer_secret("super-secret-value");
        let builder_dbg = format!("{builder:?}");
        assert!(
            !builder_dbg.contains(INITIAL_REFRESH_TOKEN),
            "builder leaked token: {builder_dbg}"
        );
        assert!(
            !builder_dbg.contains("super-secret-value"),
            "builder leaked secret: {builder_dbg}"
        );
    }
}
