//! OAuth 2.0 JWT Bearer flow for Salesforce server-to-server auth.
//!
//! This auth implementation holds the RSA private key behind a certificate
//! registered on the connected app, and mints access tokens on demand by
//! signing a short-lived JWT and exchanging it at the OAuth token
//! endpoint. Three things have to be in place on the org side:
//!
//! - **The certificate.** Salesforce uses the registered X.509 certificate
//!   to verify the assertion's signature, and for nothing else;
//!   registering it approves no app and no user.
//! - **Prior approval.** The flow "does require prior approval of the
//!   client app" for the user named in `sub`, in one of two ways: the
//!   app's permitted-users policy is "Admin approved users are
//!   pre-authorized" and the user's profile or a permission set is
//!   assigned to the app, or the policy is "All users may self-authorize"
//!   and the user has already approved the app through an interactive
//!   flow that issued a refresh token. Without either, the mint fails
//!   with `invalid_grant` ("User hasn't approved the connected app").
//! - **Scopes.** Salesforce looks at the user's previous approvals that
//!   include a refresh token and issues a token only when the approved
//!   scopes include at least one standard scope besides `refresh_token`.
//!   An app without the `refresh_token` scope fails with `invalid_request`
//!   ("The JWT bearer and SAML assertion bearer flows require a
//!   refresh_token scope. Install and preauthorize the app."). Scopes
//!   cannot be requested on the token call itself.
//!
//! Both failures surface as [`AuthError::OAuth`]; its `error_description`
//! field carries Salesforce's sentence, and its `Display` prints it.
//!
//! (<https://help.salesforce.com/s/articleView?id=xcloud.remoteaccess_oauth_jwt_flow.htm&type=5>,
//! <https://help.salesforce.com/s/articleView?id=xcloud.remoteaccess_oauth_flow_errors.htm&type=5>)
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
//! shorter of the two. The next call re-mints 60 seconds before that
//! window elapses (or halfway through a TTL under two minutes),
//! regardless of whether the previous token would still have worked;
//! see [`JwtAuthBuilder::token_ttl`].
//!
//! Minting is single-flight: callers that arrive while a mint is in
//! flight wait for it and share its outcome, success or failure, so a slow
//! or failing token endpoint costs one grant per window rather than one
//! per caller. If the mint fails transiently — a transport failure or a
//! 429 / 5xx — while the cached token is inside its refresh margin but not
//! yet expired, that token is returned and a warning is logged; an OAuth
//! error such as `invalid_grant` is never masked that way. The token
//! request itself is retried a bounded number of times, see
//! [`JwtAuthBuilder::http_client`].
//!
//! ## Signing backend
//!
//! The assertion is signed through jsonwebtoken's aws-lc-rs backend
//! directly rather than through its process-global crypto provider, so a
//! build that also enables jsonwebtoken's `rust_crypto` feature for its
//! own purposes does not affect token minting here.

use crate::AuthSession;
use crate::assertion::{bearer_assertion, private_key_from_pem, private_key_from_pem_file};
use crate::error::{AuthError, AuthResult};
use crate::mint::{CachedToken, MintState};
use crate::token_endpoint::{
    ClientAuth, GrantReplay, HttpClientConfig, check_instance_url, exchange, normalize_url,
    require_secure_login_url,
};
use async_trait::async_trait;
use camino::Utf8PathBuf;
use jsonwebtoken::EncodingKey;
use std::borrow::Cow;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Salesforce production login URL — the default JWT audience and token
/// exchange host.
pub const PRODUCTION_LOGIN_URL: &str = "https://login.salesforce.com";

/// Salesforce sandbox login URL.
pub const SANDBOX_LOGIN_URL: &str = "https://test.salesforce.com";

/// Default cache TTL for an access token after it's issued.
const DEFAULT_TOKEN_TTL: Duration = Duration::from_secs(30 * 60);

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
    state: RwLock<MintState>,
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
            target: "cirrus_auth::mint",
            flow = "jwt-bearer",
            login_url = %self.login_url,
            "minting fresh access token",
        );
        let assertion = bearer_assertion(
            &self.consumer_key,
            &self.username,
            &self.login_url,
            &self.encoding_key,
        )?;

        let body = [
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", assertion.as_str()),
        ];

        let token = exchange(
            &self.http,
            &self.login_url,
            &body,
            ClientAuth::Form,
            GrantReplay::Safe,
        )
        .await?;
        check_instance_url(&self.instance_url, &token)?;

        Ok(CachedToken::from_response(token, self.token_ttl))
    }
}

#[async_trait]
impl AuthSession for JwtAuth {
    async fn access_token(&self) -> AuthResult<Cow<'_, str>> {
        // Taken before any lock: the read lock below queues behind an
        // in-flight mint, so the start time is what tells a caller, under
        // the write lock, that a completed mint was concurrent with it and
        // that its outcome is this caller's too.
        let started = Instant::now();

        // Fast path — read lock, return the cached token while it is fresh.
        if let Some(token) = self.state.read().await.fresh_token() {
            return Ok(Cow::Owned(token));
        }

        // Slow path — write lock, then share rather than repeat: a mint
        // that finished while this caller waited decides this caller's
        // outcome too, whether it produced a token or a failure.
        let mut guard = self.state.write().await;
        if let Some(outcome) = guard.shared_outcome(started) {
            return outcome.map(Cow::Owned);
        }
        let minted = self.mint_token().await;
        guard.record("jwt-bearer", minted).map(Cow::Owned)
    }

    fn instance_url(&self) -> &str {
        &self.instance_url
    }

    async fn invalidate(&self, stale_token: &str) {
        self.state
            .write()
            .await
            .invalidate_if_matches("jwt-bearer", stale_token);
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
    http: HttpClientConfig,
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
    ///
    /// The path is a [`camino::Utf8PathBuf`] or anything that converts
    /// into one, such as a `&str`. A `std::path::PathBuf` from an argument
    /// parser or an environment variable converts with
    /// [`Utf8PathBuf::try_from`](camino::Utf8PathBuf::try_from); `camino`
    /// is re-exported as [`cirrus_auth::camino`](crate::camino) for that,
    /// and [`private_key_pem_bytes`](Self::private_key_pem_bytes) takes
    /// the file's contents when the path cannot be UTF-8.
    ///
    /// ```no_run
    /// use cirrus_auth::{JwtAuth, camino::Utf8PathBuf};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let key_path = std::path::PathBuf::from("./private.pem");
    /// let builder = JwtAuth::builder().private_key_pem_file(Utf8PathBuf::try_from(key_path)?)?;
    /// # let _ = builder;
    /// # Ok(())
    /// # }
    /// ```
    pub fn private_key_pem_file(mut self, path: impl Into<Utf8PathBuf>) -> AuthResult<Self> {
        self.encoding_key = Some(private_key_from_pem_file(&path.into())?);
        Ok(self)
    }

    /// Loads the RSA private key directly from PEM-encoded bytes. Useful
    /// when the key is held in memory (e.g. fetched from a secret manager).
    ///
    /// Both setters accept a PKCS#1 `RSA PRIVATE KEY` or a PKCS#8
    /// `PRIVATE KEY` block, reading the first block of a bundle. Anything
    /// else, such as the `PUBLIC KEY` or `CERTIFICATE` that sits next to
    /// the key in a Salesforce JWT setup, is refused here with
    /// [`AuthError::InvalidArgument`] naming the block, rather than
    /// failing to sign on the first token request.
    pub fn private_key_pem_bytes(mut self, bytes: &[u8]) -> AuthResult<Self> {
        self.encoding_key = Some(private_key_from_pem(bytes)?);
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
    ///
    /// A token is re-minted ahead of that bound by a refresh margin of
    /// 60 seconds, or half the TTL when the TTL is under two minutes, so
    /// a 30-second TTL caches for 15 seconds rather than for nothing.
    /// `Duration::ZERO` disables caching and mints on every call;
    /// `Duration::MAX` keeps the token until
    /// [`invalidate`](crate::AuthSession::invalidate) clears it.
    pub fn token_ttl(mut self, ttl: Duration) -> Self {
        self.token_ttl = Some(ttl);
        self
    }

    /// Supplies a pre-configured `reqwest::Client` for the token-exchange
    /// requests. Useful for sharing a connection pool across multiple SDK
    /// clients.
    ///
    /// The client built by default applies connect and request timeouts,
    /// uses no proxy and refuses to follow redirects, so a redirect cannot replay the
    /// signed assertion to another host. A client supplied here replaces
    /// those defaults wholesale, the timeout setters included; start from
    /// [`token_client_builder`](crate::token_client_builder) to keep them
    /// while adding settings.
    ///
    /// A token request that fails to connect, is lost in transit or is
    /// answered with a 429 or 5xx is retried up to twice, 250 ms then
    /// 500 ms later: the assertion stays valid for the whole window and
    /// Salesforce does not bind it to a single use. A mint can therefore
    /// take up to three request timeouts.
    pub fn http_client(mut self, client: reqwest::Client) -> Self {
        self.http.client = Some(client);
        self
    }

    /// Sets the connect-phase timeout of the token-endpoint client this
    /// builder creates. Defaults to
    /// [`DEFAULT_TOKEN_CONNECT_TIMEOUT`](crate::DEFAULT_TOKEN_CONNECT_TIMEOUT);
    /// `None` waits indefinitely for a connection.
    ///
    /// Ignored when [`http_client`](Self::http_client) supplies a client.
    pub fn connect_timeout(mut self, timeout: impl Into<Option<Duration>>) -> Self {
        self.http.connect_timeout = Some(timeout.into());
        self
    }

    /// Sets the deadline for each token request the client this builder
    /// creates sends, from dispatch until the whole response has arrived.
    /// Defaults to
    /// [`DEFAULT_TOKEN_REQUEST_TIMEOUT`](crate::DEFAULT_TOKEN_REQUEST_TIMEOUT);
    /// `None` removes the bound, and a token endpoint that accepts the
    /// connection and never answers then stalls the call indefinitely.
    /// Each retry of the request gets its own deadline.
    ///
    /// Ignored when [`http_client`](Self::http_client) supplies a client.
    pub fn request_timeout(mut self, timeout: impl Into<Option<Duration>>) -> Self {
        self.http.request_timeout = Some(timeout.into());
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
        let http = self.http.into_client()?;

        Ok(JwtAuth {
            consumer_key,
            username,
            encoding_key,
            login_url,
            instance_url,
            token_ttl,
            http,
            state: RwLock::new(MintState::default()),
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::assertion::ASSERTION_VALIDITY_SECS;
    use crate::test_support::decode_jwt_segment;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
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
    fn invalid_pem_is_refused_as_an_invalid_private_key() {
        let err = JwtAuth::builder()
            .private_key_pem_bytes(b"not a pem")
            .unwrap_err();
        assert!(
            matches!(
                err,
                AuthError::InvalidArgument {
                    name: "private_key",
                    ..
                }
            ),
            "{err:?}"
        );
    }

    /// The public half of `TEST_PEM` and a self-signed certificate for it.
    /// jsonwebtoken's PEM reader accepts both as RSA material, and
    /// Salesforce's JWT setup creates `server.key` and `server.crt` side by
    /// side, so loading the wrong file has to be caught here rather than
    /// at the first mint.
    const TEST_PUBLIC_KEY_PEM: &[u8] = include_bytes!("../tests/fixtures/test_rsa_public_key.pem");
    const TEST_CERTIFICATE_PEM: &[u8] =
        include_bytes!("../tests/fixtures/test_rsa_certificate.pem");

    fn is_invalid_private_key_naming(err: &AuthError, label: &str) -> bool {
        matches!(
            err,
            AuthError::InvalidArgument {
                name: "private_key",
                reason,
            } if reason.contains(label)
        )
    }

    #[test]
    fn a_public_key_is_refused_when_loaded() {
        let err = JwtAuth::builder()
            .private_key_pem_bytes(TEST_PUBLIC_KEY_PEM)
            .unwrap_err();
        assert!(is_invalid_private_key_naming(&err, "PUBLIC KEY"), "{err:?}");
    }

    #[test]
    fn a_certificate_is_refused_when_loaded() {
        let err = JwtAuth::builder()
            .private_key_pem_bytes(TEST_CERTIFICATE_PEM)
            .unwrap_err();
        assert!(
            is_invalid_private_key_naming(&err, "CERTIFICATE"),
            "{err:?}"
        );
    }

    #[test]
    fn a_bundle_is_read_from_its_first_block() {
        let mut key_first = TEST_PEM.to_vec();
        key_first.extend_from_slice(TEST_CERTIFICATE_PEM);
        JwtAuth::builder()
            .private_key_pem_bytes(&key_first)
            .unwrap();

        let mut certificate_first = TEST_CERTIFICATE_PEM.to_vec();
        certificate_first.extend_from_slice(TEST_PEM);
        let err = JwtAuth::builder()
            .private_key_pem_bytes(&certificate_first)
            .unwrap_err();
        assert!(
            is_invalid_private_key_naming(&err, "CERTIFICATE"),
            "{err:?}"
        );
    }

    #[test]
    fn a_key_file_holding_a_certificate_is_refused() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/test_rsa_certificate.pem"
        );
        let err = JwtAuth::builder().private_key_pem_file(path).unwrap_err();
        assert!(
            is_invalid_private_key_naming(&err, "CERTIFICATE"),
            "{err:?}"
        );
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
    async fn concurrent_callers_share_one_failed_mint() {
        // Six callers arrive while the cache is empty. The first mint
        // takes the lock and fails; the other five are queued behind it
        // and must get that outcome, not five more trips to the token
        // endpoint, each one a separate login attempt against the org.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_json(serde_json::json!({
                        "error": "invalid_grant",
                        "error_description": "user hasn't approved this consumer"
                    }))
                    .set_delay(Duration::from_millis(100)),
            )
            .mount(&server)
            .await;

        let auth = Arc::new(
            builder_with_required_fields()
                .login_url(server.uri())
                .build()
                .unwrap(),
        );
        let callers: Vec<_> = (0..6)
            .map(|_| {
                let auth = Arc::clone(&auth);
                tokio::spawn(async move { auth.access_token().await.map(Cow::into_owned) })
            })
            .collect();
        for caller in callers {
            let outcome = caller.await.unwrap();
            assert!(
                matches!(outcome, Err(AuthError::OAuth { ref error, .. }) if error == "invalid_grant"),
                "every caller shares the failed mint's outcome, got {outcome:?}"
            );
        }
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_503_from_the_token_endpoint_is_retried_for_the_jwt_grant() {
        // The signed assertion is valid for the whole retry window and
        // Salesforce does not bind it to a single use, so a 503 from the
        // login host is as safe to retry as the same 503 on an API call.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "00DXX!ACCESS",
                "instance_url": "https://my-org.my.salesforce.com",
            })))
            .expect(1)
            .mount(&server)
            .await;

        let auth = builder_with_required_fields()
            .login_url(server.uri())
            .build()
            .unwrap();
        let token = auth.access_token().await.unwrap();
        assert_eq!(&*token, "00DXX!ACCESS");
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
    /// `stale_token`. This pins the JWT flow's wiring of that contract;
    /// the refresh and client-credentials flows each have a test of
    /// their own, since a flow can wire its cache wrongly on its own.
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
        // Pins this crate's own validity window, which sits under the
        // five minutes Salesforce allows a client assertion.
        assert!(
            exp <= now + ASSERTION_VALIDITY_SECS,
            "exp exceeds the SDK's validity window: exp={exp} now={now}"
        );
    }

    /// Base64url-decodes one dot-separated JWT segment into JSON.
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
