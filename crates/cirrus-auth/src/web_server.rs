//! OAuth 2.0 Web Server flow with PKCE for interactive (user-in-the-loop) auth.
//!
//! Two phases driven by the caller:
//!
//! 1. [`WebServerFlow::start`] mints a fresh `code_verifier` + `state`,
//!    derives the `S256` challenge per RFC 7636, and returns the
//!    authorization URL the caller should redirect the user to. The
//!    secrets needed for completion are returned alongside as a
//!    [`PendingExchange`] — an opaque, serializable value the caller is
//!    responsible for persisting until the user comes back through the
//!    callback.
//!
//! 2. On callback, the caller passes the stored [`PendingExchange`] plus
//!    the `code` and `state` query parameters into
//!    [`WebServerFlow::complete`]. The state is verified, the code is
//!    exchanged for tokens at `/services/oauth2/token`, and a
//!    [`CompletedSession`] is returned containing the access token,
//!    instance URL, and (if the connected app's scopes include
//!    `refresh_token`) a refresh token.
//!
//! The library is **stateless between the two phases** — it never stores
//! the verifier internally. This composes cleanly with any web framework
//! the caller chooses, and lets multiple in-flight authorizations coexist
//! without a server-side store the SDK has to manage.
//!
//! The connected app's credentials live on the [`WebServerFlow`] and are
//! never part of the value the caller persists; see [`PendingExchange`]
//! for where that value may safely be kept.
//!
//! ## Wiring back into the SDK
//!
//! With a refresh token in hand, build a [`crate::RefreshTokenAuth`]:
//!
//! ```no_run
//! # use cirrus_auth::{RefreshTokenAuth, WebServerFlow};
//! # async fn ex() -> Result<(), Box<dyn std::error::Error>> {
//! # let flow = WebServerFlow::builder()
//! #     .consumer_key("k").redirect_uri("https://app/cb").build()?;
//! # let (_url, pending) = flow.start()?;
//! # let state = pending.state().to_string();
//! # let session = flow.complete(pending, "code", &state).await?;
//! let refresh_token = session.refresh_token
//!     .ok_or("connected app didn't return a refresh token")?;
//! let auth = RefreshTokenAuth::builder()
//!     .consumer_key("k")
//!     .refresh_token(refresh_token)
//!     .instance_url(session.instance_url)
//!     .build()?;
//! # Ok(()) }
//! ```
//!
//! ## Confidential vs public clients
//!
//! Public (PKCE-only) clients omit `consumer_secret` and rely on the
//! `code_verifier` for client authentication. Confidential clients still
//! send `client_secret` on the token exchange — Salesforce permits both.
//! The builder treats `consumer_secret` as optional accordingly.

use crate::error::{AuthError, AuthResult};
use crate::token_endpoint::{
    default_http_client, exchange, normalize_url, require_secure_login_url,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Salesforce production login URL — also the default authorization host.
pub const PRODUCTION_LOGIN_URL: &str = "https://login.salesforce.com";

/// Salesforce sandbox login URL.
pub const SANDBOX_LOGIN_URL: &str = "https://test.salesforce.com";

/// Number of random bytes for the PKCE `code_verifier`. RFC 7636 caps the
/// verifier at 128 characters (`code-verifier = 43*128unreserved`), and 96
/// raw bytes encode to exactly that, so this is the longest verifier the
/// grammar admits. 32 bytes is already cryptographically sufficient — the
/// RFC recommends it — but spending the full width costs nothing and
/// leaves no headroom question.
const VERIFIER_BYTES: usize = 96;

/// Number of random bytes for the `state` nonce. 16 bytes → 22 chars
/// post-encoding, well over the entropy needed to defeat CSRF.
const STATE_BYTES: usize = 16;

/// Configures the OAuth 2.0 Web Server flow.
///
/// Holds the connected app's credentials for the lifetime of the flow and
/// drives both phases: [`start`](Self::start) builds the authorization
/// URL, [`complete`](Self::complete) exchanges the returned code.
///
/// Construct via [`WebServerFlow::builder`].
#[derive(Clone)]
pub struct WebServerFlow {
    consumer_key: String,
    consumer_secret: Option<String>,
    redirect_uri: String,
    login_url: String,
    scopes: Vec<String>,
    prompt: Option<String>,
    login_hint: Option<String>,
    http: reqwest::Client,
}

// The connected app's client secret (and the key identifying it) must
// never reach logs — redact in `{:?}`.
impl std::fmt::Debug for WebServerFlow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebServerFlow")
            .field("consumer_key", &"[redacted]")
            .field(
                "consumer_secret",
                &self.consumer_secret.as_ref().map(|_| "[redacted]"),
            )
            .field("redirect_uri", &self.redirect_uri)
            .field("login_url", &self.login_url)
            .field("scopes", &self.scopes)
            .field("prompt", &self.prompt)
            .field("login_hint", &self.login_hint)
            .finish_non_exhaustive()
    }
}

impl WebServerFlow {
    /// Begins constructing a [`WebServerFlow`].
    pub fn builder() -> WebServerFlowBuilder {
        WebServerFlowBuilder::default()
    }

    /// Phase 1 — generate a fresh PKCE verifier + state nonce, build the
    /// authorization URL, and return both. The caller redirects the user
    /// to the URL and persists the [`PendingExchange`] until the callback.
    ///
    /// Any path on the configured `login_url` is preserved: an Experience
    /// Cloud site login such as `https://MyDomainName.my.site.com/fineapps`
    /// yields `.../fineapps/services/oauth2/authorize`, matching the
    /// endpoint [`complete`](Self::complete) will POST the code to.
    pub fn start(&self) -> AuthResult<(String, PendingExchange)> {
        let code_verifier = random_b64url(VERIFIER_BYTES)?;
        let state = random_b64url(STATE_BYTES)?;
        let code_challenge = pkce_s256_challenge(&code_verifier);

        let mut url = url::Url::parse(&self.login_url)?;
        let base_path = url.path().trim_end_matches('/').to_string();
        url.set_path(&format!("{base_path}/services/oauth2/authorize"));
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("response_type", "code");
            q.append_pair("client_id", &self.consumer_key);
            q.append_pair("redirect_uri", &self.redirect_uri);
            q.append_pair("code_challenge", &code_challenge);
            q.append_pair("code_challenge_method", "S256");
            q.append_pair("state", &state);
            if !self.scopes.is_empty() {
                q.append_pair("scope", &self.scopes.join(" "));
            }
            if let Some(p) = self.prompt.as_deref() {
                q.append_pair("prompt", p);
            }
            if let Some(h) = self.login_hint.as_deref() {
                q.append_pair("login_hint", h);
            }
        }

        let pending = PendingExchange {
            code_verifier,
            state,
        };

        Ok((url.into(), pending))
    }

    /// Phase 2 — verify the returned `state`, exchange `code` for tokens.
    ///
    /// `pending` is the value [`start`](Self::start) handed back, restored
    /// from wherever the caller stored it. Returns a [`CompletedSession`]
    /// with the access token, instance URL, and (if the connected app
    /// issued them) refresh and ID tokens.
    ///
    /// Fails with [`AuthError::StateMismatch`] when `returned_state` does
    /// not match the nonce this flow issued, without contacting the token
    /// endpoint.
    pub async fn complete(
        &self,
        pending: PendingExchange,
        code: &str,
        returned_state: &str,
    ) -> AuthResult<CompletedSession> {
        // CSRF defense: the state we generated in start() must match what
        // the IdP echoed back. A mismatch typically means a forged callback.
        // Compare in constant time so a network-positioned attacker can't
        // byte-by-byte oracle the state value via callback timing. The
        // 22-char state is fixed-length per construction, so a length
        // mismatch is also a mismatch — short-circuit it without leaking
        // which-byte info.
        if !constant_time_eq(returned_state.as_bytes(), pending.state.as_bytes()) {
            return Err(AuthError::StateMismatch);
        }

        let mut body: Vec<(&str, &str)> = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", self.consumer_key.as_str()),
            ("redirect_uri", self.redirect_uri.as_str()),
            ("code_verifier", pending.code_verifier.as_str()),
        ];
        if let Some(secret) = self.consumer_secret.as_deref() {
            body.push(("client_secret", secret));
        }

        let token = exchange(&self.http, &self.login_url, &body).await?;
        Ok(CompletedSession {
            access_token: token.access_token,
            refresh_token: token.refresh_token,
            id_token: token.id_token,
            instance_url: normalize_url(&token.instance_url),
            id: token.id,
            issued_at: token.issued_at,
            signature: token.signature,
            scope: token.scope,
        })
    }
}

/// Opaque, serializable handle holding the PKCE verifier + state nonce
/// between the authorize and token-exchange phases. The caller must
/// persist it until the OAuth callback fires and pass it back to
/// [`WebServerFlow::complete`].
///
/// It carries no connected-app credentials — only the two per-attempt
/// values the SDK generates. The `code_verifier` inside is still a
/// secret: anyone holding both it and an intercepted authorization code
/// can complete the exchange. Keep it somewhere the end user cannot read,
/// such as a server-side session store, or a cookie that is **encrypted**
/// rather than merely signed — a signed cookie is integrity-protected but
/// its contents are plainly readable by the browser.
#[derive(Clone, Serialize, Deserialize)]
pub struct PendingExchange {
    code_verifier: String,
    state: String,
}

// Redact the PKCE secret — leaking it lets anyone holding the
// authorization code complete the exchange. `state` is a CSRF nonce —
// non-secret to the user but better hygiene to keep out of logs.
impl std::fmt::Debug for PendingExchange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingExchange")
            .field("code_verifier", &"[redacted]")
            .field("state", &"[redacted]")
            .finish()
    }
}

impl PendingExchange {
    /// The `state` nonce sent in the authorization URL. Exposed so
    /// integration tests can drive the callback step; production
    /// callers normally don't need to read it. Treat as a CSRF
    /// token — avoid emitting to logs or telemetry.
    pub fn state(&self) -> &str {
        &self.state
    }
}

/// Result of a successful authorization-code exchange.
#[derive(Clone)]
pub struct CompletedSession {
    /// Bearer access token for immediate API calls.
    pub access_token: String,
    /// Long-lived refresh token. Present only if the connected app's
    /// scopes include `refresh_token` and the user granted it.
    pub refresh_token: Option<String>,
    /// OpenID Connect ID token. Present only if the requested scopes
    /// include `openid`.
    pub id_token: Option<String>,
    /// REST instance URL reported by the token endpoint, normalized to
    /// carry no trailing slash — Salesforce's documented sample response
    /// includes one — so `{instance_url}/services/...` concatenation is
    /// always well-formed.
    pub instance_url: String,
    /// Salesforce user-identity URL (e.g.
    /// `https://login.salesforce.com/id/{org_id}/{user_id}`). Identifies
    /// which user was authenticated.
    pub id: Option<String>,
    /// Token-issuance timestamp (milliseconds since epoch as a string).
    pub issued_at: Option<String>,
    /// Base64-encoded HMAC-SHA256 of the concatenated `id` and
    /// `issued_at` values, signed with the connected-app consumer secret.
    /// Salesforce defines it as an integrity check on the identity URL in
    /// `id`; `access_token` and `instance_url` are not covered by it, so
    /// a valid signature says nothing about their provenance.
    pub signature: Option<String>,
    /// Granted scopes, space-separated.
    pub scope: Option<String>,
}

// Tokens and the HMAC `signature` are secrets — redact in `{:?}`.
// `instance_url`, `id`, `issued_at`, and `scope` are non-secret.
impl std::fmt::Debug for CompletedSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompletedSession")
            .field("access_token", &"[redacted]")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[redacted]"),
            )
            .field("id_token", &self.id_token.as_ref().map(|_| "[redacted]"))
            .field("instance_url", &self.instance_url)
            .field("id", &self.id)
            .field("issued_at", &self.issued_at)
            .field("signature", &self.signature.as_ref().map(|_| "[redacted]"))
            .field("scope", &self.scope)
            .finish()
    }
}

/// Builder for [`WebServerFlow`].
#[derive(Default)]
pub struct WebServerFlowBuilder {
    consumer_key: Option<String>,
    consumer_secret: Option<String>,
    redirect_uri: Option<String>,
    login_url: Option<String>,
    scopes: Vec<String>,
    prompt: Option<String>,
    login_hint: Option<String>,
    http_client: Option<reqwest::Client>,
}

impl std::fmt::Debug for WebServerFlowBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebServerFlowBuilder")
            .field("consumer_key", &self.consumer_key.is_some())
            .field("consumer_secret", &self.consumer_secret.is_some())
            .field("redirect_uri", &self.redirect_uri)
            .field("login_url", &self.login_url)
            .field("scopes", &self.scopes)
            .field("prompt", &self.prompt)
            .field("login_hint", &self.login_hint)
            .finish_non_exhaustive()
    }
}

impl WebServerFlowBuilder {
    /// Connected App's Consumer Key (Client ID). Required.
    pub fn consumer_key(mut self, key: impl Into<String>) -> Self {
        self.consumer_key = Some(key.into());
        self
    }

    /// Connected App's Consumer Secret. Optional — set only for
    /// confidential clients. Public (PKCE-only) clients omit it.
    pub fn consumer_secret(mut self, secret: impl Into<String>) -> Self {
        self.consumer_secret = Some(secret.into());
        self
    }

    /// Redirect URI registered on the Connected App. Required. Must match
    /// exactly (Salesforce compares string-for-string).
    pub fn redirect_uri(mut self, uri: impl Into<String>) -> Self {
        self.redirect_uri = Some(uri.into());
        self
    }

    /// Authorization host. Defaults to [`PRODUCTION_LOGIN_URL`]. Use
    /// [`SANDBOX_LOGIN_URL`] for sandboxes or your org's My Domain login URL.
    ///
    /// A path is honoured, so an Experience Cloud site login URL such as
    /// `https://MyDomainName.my.site.com/fineapps` addresses that site's
    /// authorize and token endpoints. Must be `https` (loopback hosts
    /// excepted, for local test servers).
    pub fn login_url(mut self, url: impl Into<String>) -> Self {
        self.login_url = Some(url.into());
        self
    }

    /// Adds a scope to the authorization request. Multiple calls accumulate.
    /// Common values include `api`, `refresh_token`, `id`, `openid`.
    pub fn scope(mut self, scope: impl Into<String>) -> Self {
        self.scopes.push(scope.into());
        self
    }

    /// Replaces the entire scope set. Convenient when scopes are computed
    /// elsewhere as a slice.
    pub fn scopes<I, S>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.scopes = scopes.into_iter().map(Into::into).collect();
        self
    }

    /// Adds the OAuth `prompt` parameter (e.g. `login`, `consent`,
    /// `select_account`).
    pub fn prompt(mut self, prompt: impl Into<String>) -> Self {
        self.prompt = Some(prompt.into());
        self
    }

    /// Pre-fills the username field on the authorization page.
    pub fn login_hint(mut self, hint: impl Into<String>) -> Self {
        self.login_hint = Some(hint.into());
        self
    }

    /// Supplies a pre-configured `reqwest::Client` for the token exchange.
    /// Useful for sharing a connection pool.
    ///
    /// The client built by default applies connect and request timeouts
    /// and refuses to follow redirects, so a redirect cannot replay the
    /// authorization code and PKCE verifier to another host. A client
    /// supplied here replaces those defaults wholesale — configure both
    /// on it.
    pub fn http_client(mut self, client: reqwest::Client) -> Self {
        self.http_client = Some(client);
        self
    }

    /// Finalizes the builder.
    pub fn build(self) -> AuthResult<WebServerFlow> {
        let consumer_key = self
            .consumer_key
            .ok_or(AuthError::MissingField("consumer_key"))?;
        let redirect_uri = self
            .redirect_uri
            .ok_or(AuthError::MissingField("redirect_uri"))?;
        let login_url = normalize_url(
            &self
                .login_url
                .unwrap_or_else(|| PRODUCTION_LOGIN_URL.to_string()),
        );
        require_secure_login_url(&login_url)?;
        let http = match self.http_client {
            Some(client) => client,
            None => default_http_client()?,
        };
        Ok(WebServerFlow {
            consumer_key,
            consumer_secret: self.consumer_secret,
            redirect_uri,
            login_url,
            scopes: self.scopes,
            prompt: self.prompt,
            login_hint: self.login_hint,
            http,
        })
    }
}

/// Returns `len` cryptographically random bytes encoded as URL-safe base64
/// without padding — the format RFC 7636 requires for `code_verifier` and
/// the format we use for `state` to keep it URL-safe.
fn random_b64url(len: usize) -> AuthResult<String> {
    let mut bytes = vec![0u8; len];
    getrandom::fill(&mut bytes).map_err(|e| AuthError::Randomness(e.to_string()))?;
    Ok(URL_SAFE_NO_PAD.encode(&bytes))
}

/// Computes the RFC 7636 `S256` PKCE challenge: SHA-256 of the verifier
/// bytes, base64-url-no-pad encoded.
fn pkce_s256_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

/// Constant-time byte-slice equality. Mirrors the trivial algorithm
/// used by `subtle`/`ring`: XOR every byte and OR the accumulator. The
/// length check up front leaks length, which is fine here because the
/// expected `state` is always a fixed 22-char string we generate.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    /// Salesforce's documented token response for the web server flow.
    ///
    /// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/intro_understanding_web_server_oauth_flow.htm
    /// (doc_version 222.0) — field values copied from the guide's sample
    /// JSON body, including the trailing slash it puts on `instance_url`.
    fn documented_token_response() -> serde_json::Value {
        serde_json::json!({
            "id": "https://login.salesforce.com/id/00Dx0000000BV7z/005x00000012Q9P",
            "issued_at": "1278448101416",
            "refresh_token": "5Aep861KIwKdekr...refresh",
            "instance_url": "https://yourInstance.salesforce.com/",
            "signature": "CMJ4l+CCaPQiKjoOEwEig9H4wqhpuLSk4J2urAe+fVg=",
            "access_token": "00Dx0000000BV7z!AR8AQP0jITN80ESEsj5EbaZTFG0RNBaT1cyWk7TrqoDjoNIWQ2ME_sTZzBjfmOE6zMHq6y8PIW4eWze9JksNEkWUl.Cju7m4",
        })
    }

    fn flow_with_required_fields() -> WebServerFlowBuilder {
        WebServerFlow::builder()
            .consumer_key("consumer-key-123")
            .redirect_uri("https://app.example.com/oauth/callback")
    }

    #[test]
    fn pkce_s256_challenge_matches_rfc_7636_test_vector() {
        // RFC 7636 Appendix B test vector.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert_eq!(pkce_s256_challenge(verifier), expected);
    }

    #[test]
    fn random_b64url_returns_distinct_values() {
        let a = random_b64url(VERIFIER_BYTES).unwrap();
        let b = random_b64url(VERIFIER_BYTES).unwrap();
        assert_ne!(a, b);
        // 96 bytes encodes to exactly 128 base64-url chars (no padding),
        // the ceiling RFC 7636's `code-verifier = 43*128unreserved`
        // grammar allows.
        assert_eq!(a.len(), 128);
    }

    #[test]
    fn random_b64url_is_url_safe() {
        for _ in 0..10 {
            let s = random_b64url(32).unwrap();
            assert!(
                s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
                "non-url-safe char in: {s}"
            );
        }
    }

    #[test]
    fn flow_debug_redacts_credentials() {
        let flow = flow_with_required_fields()
            .consumer_secret("super-secret-value")
            .build()
            .unwrap();
        let debug = format!("{flow:?}");
        assert!(!debug.contains("super-secret-value"), "leaked: {debug}");
        assert!(!debug.contains("consumer-key-123"), "leaked: {debug}");
        assert!(debug.contains("[redacted]"));
        // Non-secret config stays visible for diagnostics.
        assert!(debug.contains("https://app.example.com/oauth/callback"));
    }

    #[test]
    fn builder_requires_consumer_key() {
        let err = WebServerFlow::builder()
            .redirect_uri("https://x")
            .build()
            .unwrap_err();
        assert!(matches!(err, AuthError::MissingField("consumer_key")));
    }

    #[test]
    fn builder_requires_redirect_uri() {
        let err = WebServerFlow::builder()
            .consumer_key("k")
            .build()
            .unwrap_err();
        assert!(matches!(err, AuthError::MissingField("redirect_uri")));
    }

    #[test]
    fn builder_rejects_cleartext_login_url() {
        let err = flow_with_required_fields()
            .login_url("http://my-org.my.salesforce.com")
            .build()
            .unwrap_err();
        assert!(matches!(err, AuthError::InsecureLoginUrl { .. }), "{err:?}");
    }

    #[test]
    fn start_builds_authorization_url_with_all_required_params() {
        let flow = flow_with_required_fields()
            .login_url("https://login.salesforce.com")
            .scope("api")
            .scope("refresh_token")
            .build()
            .unwrap();
        let (url, pending) = flow.start().unwrap();
        let parsed = url::Url::parse(&url).unwrap();
        assert_eq!(parsed.host_str(), Some("login.salesforce.com"));
        assert_eq!(parsed.path(), "/services/oauth2/authorize");

        let q: std::collections::HashMap<_, _> = parsed.query_pairs().collect();
        assert_eq!(q.get("response_type").map(|s| s.as_ref()), Some("code"));
        assert_eq!(
            q.get("client_id").map(|s| s.as_ref()),
            Some("consumer-key-123")
        );
        assert_eq!(
            q.get("redirect_uri").map(|s| s.as_ref()),
            Some("https://app.example.com/oauth/callback")
        );
        assert_eq!(
            q.get("code_challenge_method").map(|s| s.as_ref()),
            Some("S256")
        );
        assert_eq!(
            q.get("scope").map(|s| s.as_ref()),
            Some("api refresh_token")
        );
        assert!(q.contains_key("code_challenge"));
        assert!(q.contains_key("state"));

        // Challenge in the URL must match a fresh hash of the verifier
        // we held back in the PendingExchange.
        let expected_challenge = pkce_s256_challenge(&pending.code_verifier);
        assert_eq!(
            q.get("code_challenge").map(|s| s.as_ref()),
            Some(expected_challenge.as_str())
        );
        assert_eq!(
            q.get("state").map(|s| s.as_ref()),
            Some(pending.state.as_str())
        );
    }

    #[test]
    fn start_keeps_the_login_url_base_path() {
        // An Experience Cloud site login lives under the site's path; the
        // authorize URL must extend it rather than replace it, so both
        // phases address the same endpoint pair.
        let flow = flow_with_required_fields()
            .login_url("https://fineapps.my.site.com/fineapps/")
            .build()
            .unwrap();
        let (url, _) = flow.start().unwrap();
        let parsed = url::Url::parse(&url).unwrap();
        assert_eq!(parsed.path(), "/fineapps/services/oauth2/authorize");
    }

    #[test]
    fn start_includes_optional_params_when_set() {
        let flow = flow_with_required_fields()
            .prompt("login")
            .login_hint("user@example.com")
            .build()
            .unwrap();
        let (url, _) = flow.start().unwrap();
        let parsed = url::Url::parse(&url).unwrap();
        let q: std::collections::HashMap<_, _> = parsed.query_pairs().collect();
        assert_eq!(q.get("prompt").map(|s| s.as_ref()), Some("login"));
        assert_eq!(
            q.get("login_hint").map(|s| s.as_ref()),
            Some("user@example.com")
        );
    }

    #[test]
    fn start_omits_scope_when_empty() {
        let flow = flow_with_required_fields().build().unwrap();
        let (url, _) = flow.start().unwrap();
        let parsed = url::Url::parse(&url).unwrap();
        let q: std::collections::HashMap<_, _> = parsed.query_pairs().collect();
        assert!(!q.contains_key("scope"));
    }

    #[test]
    fn pending_exchange_round_trips_through_serde() {
        let flow = flow_with_required_fields().build().unwrap();
        let (_, pending) = flow.start().unwrap();
        let json = serde_json::to_string(&pending).unwrap();
        let restored: PendingExchange = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.state(), pending.state());
        assert_eq!(restored.code_verifier, pending.code_verifier);
    }

    #[test]
    fn serialized_pending_exchange_carries_no_connected_app_credentials() {
        // The caller is told to persist this value between the two
        // phases. Whatever store they choose must never receive the
        // connected app's key or secret.
        let flow = flow_with_required_fields()
            .consumer_secret("super-secret-value")
            .build()
            .unwrap();
        let (_, pending) = flow.start().unwrap();
        let json = serde_json::to_string(&pending).unwrap();
        assert!(!json.contains("super-secret-value"), "leaked: {json}");
        assert!(!json.contains("consumer-key-123"), "leaked: {json}");
        assert!(
            !json.contains("app.example.com"),
            "unexpected flow config in the persisted value: {json}"
        );
    }

    #[tokio::test]
    async fn complete_exchanges_code_for_session() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .and(body_string_contains("grant_type=authorization_code"))
            .and(body_string_contains("code=auth-code-xyz"))
            .and(body_string_contains("client_id=consumer-key-123"))
            .and(body_string_contains("code_verifier="))
            .respond_with(ResponseTemplate::new(200).set_body_json(documented_token_response()))
            .mount(&server)
            .await;

        let flow = flow_with_required_fields()
            .login_url(server.uri())
            .scope("api")
            .scope("refresh_token")
            .build()
            .unwrap();
        let (_url, pending) = flow.start().unwrap();
        let state = pending.state().to_string();

        let session = flow
            .complete(pending, "auth-code-xyz", &state)
            .await
            .unwrap();
        assert!(session.access_token.starts_with("00Dx0000000BV7z!"));
        assert!(
            session
                .refresh_token
                .as_deref()
                .is_some_and(|t| t.starts_with("5Aep861"))
        );
        // The documented body carries a trailing slash; the session
        // exposes the normalized form so path concatenation is safe.
        assert_eq!(session.instance_url, "https://yourInstance.salesforce.com");
        // Identity fields propagate through so callers can verify which
        // user authenticated.
        assert_eq!(
            session.id.as_deref(),
            Some("https://login.salesforce.com/id/00Dx0000000BV7z/005x00000012Q9P")
        );
        assert_eq!(session.issued_at.as_deref(), Some("1278448101416"));
        assert_eq!(
            session.signature.as_deref(),
            Some("CMJ4l+CCaPQiKjoOEwEig9H4wqhpuLSk4J2urAe+fVg=")
        );
    }

    #[tokio::test]
    async fn complete_sends_the_verifier_behind_the_published_challenge() {
        // The one property PKCE exists for: the token request must carry
        // the verifier whose S256 hash was published in the authorization
        // URL — not the challenge, and not some other value.
        let server = MockServer::start().await;
        let captured = Arc::new(tokio::sync::Mutex::new(String::new()));
        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .respond_with(BodyCapturingResponder {
                captured: captured.clone(),
                response: ResponseTemplate::new(200).set_body_json(documented_token_response()),
            })
            .mount(&server)
            .await;

        let flow = flow_with_required_fields()
            .login_url(server.uri())
            .build()
            .unwrap();
        let (url, pending) = flow.start().unwrap();
        let state = pending.state().to_string();
        let verifier = pending.code_verifier.clone();

        let published_challenge = url::Url::parse(&url)
            .unwrap()
            .query_pairs()
            .find(|(k, _)| k == "code_challenge")
            .map(|(_, v)| v.into_owned())
            .unwrap();

        flow.complete(pending, "c", &state).await.unwrap();

        let body = captured.lock().await;
        let sent = form_value(&body, "code_verifier").expect("code_verifier must be sent");
        assert_eq!(sent, verifier);
        assert_eq!(pkce_s256_challenge(&sent), published_challenge);
    }

    #[tokio::test]
    async fn complete_rejects_state_mismatch_without_calling_endpoint() {
        // No mock mounted — if we hit the network, the test will fail loudly.
        let server = MockServer::start().await;
        let flow = flow_with_required_fields()
            .login_url(server.uri())
            .build()
            .unwrap();
        let (_url, pending) = flow.start().unwrap();

        let err = flow
            .complete(pending, "code", "wrong-state")
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::StateMismatch), "{err:?}");
    }

    #[tokio::test]
    async fn confidential_client_includes_client_secret() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .and(body_string_contains("client_secret=hunter2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(documented_token_response()))
            .mount(&server)
            .await;

        let flow = flow_with_required_fields()
            .login_url(server.uri())
            .consumer_secret("hunter2")
            .build()
            .unwrap();
        let (_, pending) = flow.start().unwrap();
        let state = pending.state().to_string();
        flow.complete(pending, "c", &state).await.unwrap();
    }

    #[tokio::test]
    async fn public_client_omits_client_secret() {
        let server = MockServer::start().await;
        let captured = Arc::new(tokio::sync::Mutex::new(String::new()));

        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .respond_with(BodyCapturingResponder {
                captured: captured.clone(),
                response: ResponseTemplate::new(200).set_body_json(documented_token_response()),
            })
            .mount(&server)
            .await;

        let flow = flow_with_required_fields()
            .login_url(server.uri())
            .build()
            .unwrap();
        let (_, pending) = flow.start().unwrap();
        let state = pending.state().to_string();
        flow.complete(pending, "c", &state).await.unwrap();

        let body = captured.lock().await;
        assert!(
            !body.contains("client_secret"),
            "public client should not send client_secret, got: {body}"
        );
    }

    #[tokio::test]
    async fn openid_scope_surfaces_the_id_token() {
        // Salesforce returns a signed ID token when `openid` is among the
        // requested scopes; the caller paid a consent prompt for it, so it
        // must reach them rather than being dropped.
        let server = MockServer::start().await;
        let mut body = documented_token_response();
        body["id_token"] = serde_json::Value::String("eyJhbGciOiJSUzI1NiJ9.payload.sig".into());
        body["scope"] = serde_json::Value::String("api openid".into());
        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;

        let flow = flow_with_required_fields()
            .login_url(server.uri())
            .scope("api")
            .scope("openid")
            .build()
            .unwrap();
        let (_, pending) = flow.start().unwrap();
        let state = pending.state().to_string();
        let session = flow.complete(pending, "c", &state).await.unwrap();

        assert_eq!(
            session.id_token.as_deref(),
            Some("eyJhbGciOiJSUzI1NiJ9.payload.sig")
        );
        assert_eq!(session.scope.as_deref(), Some("api openid"));
        // The ID token is a credential — keep it out of debug output.
        let debug = format!("{session:?}");
        assert!(!debug.contains("eyJhbGciOiJSUzI1NiJ9"), "leaked: {debug}");
    }

    #[tokio::test]
    async fn user_denied_surfaces_oauth_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "invalid_grant",
                "error_description": "user denied access"
            })))
            .mount(&server)
            .await;

        let flow = flow_with_required_fields()
            .login_url(server.uri())
            .build()
            .unwrap();
        let (_, pending) = flow.start().unwrap();
        let state = pending.state().to_string();
        let err = flow.complete(pending, "c", &state).await.unwrap_err();
        assert!(matches!(err, AuthError::OAuth { .. }));
    }

    #[tokio::test]
    async fn token_request_is_not_followed_across_a_redirect() {
        // The token request carries the connected app secret and the PKCE
        // verifier. A 3xx from the configured login host must surface as an
        // error rather than replaying those credentials at whatever host the
        // `Location` header names.
        let login = MockServer::start().await;
        let elsewhere = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .respond_with(ResponseTemplate::new(307).insert_header(
                "Location",
                format!("{}/services/oauth2/token", elsewhere.uri()).as_str(),
            ))
            .mount(&login)
            .await;
        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(documented_token_response()))
            .mount(&elsewhere)
            .await;

        let flow = flow_with_required_fields()
            .login_url(login.uri())
            .consumer_secret("connected-app-secret")
            .build()
            .unwrap();
        let (_url, pending) = flow.start().unwrap();
        let state = pending.state().to_string();

        let err = flow.complete(pending, "c", &state).await.unwrap_err();
        assert!(
            matches!(err, AuthError::UnexpectedResponse { status: 307 }),
            "expected the redirect to surface as an error, got: {err:?}"
        );
        assert!(
            elsewhere
                .received_requests()
                .await
                .is_some_and(|r| r.is_empty()),
            "credentials were replayed at the redirect target"
        );
    }

    /// Reads one field out of a captured `application/x-www-form-urlencoded`
    /// request body.
    fn form_value(body: &str, key: &str) -> Option<String> {
        serde_urlencoded::from_str::<Vec<(String, String)>>(body)
            .ok()?
            .into_iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }

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
}
