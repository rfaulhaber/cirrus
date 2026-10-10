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
//! [`WebServerFlow::refresh_auth`] turns the [`CompletedSession`] into a
//! [`crate::RefreshTokenAuth`] builder that keeps this flow's login URL,
//! consumer key and secret, and HTTP client, and starts out holding the
//! access token the session was issued with, so the first call does not
//! spend a refresh grant on it:
//!
//! ```no_run
//! # use cirrus_auth::WebServerFlow;
//! # async fn ex() -> Result<(), Box<dyn std::error::Error>> {
//! let flow = WebServerFlow::builder()
//!     .consumer_key("3MVG9...")
//!     .consumer_secret("28A2...")
//!     .redirect_uri("https://app.example.com/oauth/callback")
//!     .scope("api")
//!     .scope("refresh_token")
//!     .build()?;
//! # let (_url, pending) = flow.start()?;
//! # let state = pending.state().to_string();
//! let session = flow.complete(pending, "code", &state).await?;
//! let auth = flow.refresh_auth(&session)?.build()?;
//! # Ok(()) }
//! ```
//!
//! Against an org with Refresh Token Rotation, register an
//! [`on_rotation`](crate::RefreshTokenAuthBuilder::on_rotation) handler
//! on that builder before `build` whenever the refresh token is persisted;
//! the [`refresh`](crate::refresh) module docs explain why.
//!
//! ## The consumer secret
//!
//! Two connected-app settings decide whether `client_secret` must
//! accompany the token requests, and both require it by default:
//!
//! - The code exchange in [`WebServerFlow::complete`] needs it unless
//!   "Require Secret for Web Server Flow" is off
//!   (`isConsumerSecretOptional = true` on the `ConnectedApp` metadata
//!   type, or its external-client-app equivalent).
//! - The refresh grant that [`WebServerFlow::refresh_auth`] sets up
//!   needs it unless "Require Secret for Refresh Token Flow" is off
//!   (`isSecretRequiredForRefreshToken = false`). The two settings are
//!   independent of each other.
//!
//! The flow sends the secret only when `consumer_secret` is set, so a
//! public client — a desktop or single-page app that cannot keep a
//! secret — needs an administrator to turn both settings off. PKCE
//! protects the code against interception; it does not stand in for the
//! secret. With a setting on and no secret, the token endpoint answers
//! with an [`AuthError::OAuth`] that names no setting.
//!
//! When the secret is set, the code exchange and the refresh grant carry
//! it and the consumer key in an `Authorization: Basic` header (RFC 6749
//! §2.3.1), which Salesforce documents for both requests, and leave both
//! out of the form body; a public client sends `client_id` in the body
//! and no header.
//!
//! A confidential client that must not hold the secret on the host can
//! authenticate both requests with a `client_assertion` instead: give
//! [`WebServerFlowBuilder::private_key_pem_bytes`] (or its file form) the
//! private key behind the app's uploaded certificate, and the code
//! exchange and the refresh grant each carry a freshly signed RS256 JWT
//! in place of `client_secret`. Salesforce reads the assertion only when
//! no secret is present, so the builder refuses both.
//!
//! (`isConsumerSecretOptional`, `isSecretRequiredForRefreshToken`:
//! <https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_connectedapp.htm>;
//! `client_assertion`:
//! <https://help.salesforce.com/s/articleView?id=xcloud.remoteaccess_oauth_web_server_flow.htm&type=5>)

use crate::assertion::{
    CLIENT_ASSERTION_TYPE_JWT_BEARER, check_client_authentication, client_assertion,
    private_key_from_pem, private_key_from_pem_file,
};
use crate::error::{AuthError, AuthResult};
use crate::refresh::{RefreshTokenAuth, RefreshTokenAuthBuilder};
use crate::token_endpoint::{
    ClientAuth, GrantReplay, HttpClientConfig, exchange, normalize_url, require_secure_login_url,
    revoke_token,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use camino::Utf8PathBuf;
use jsonwebtoken::EncodingKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Duration;

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
    client_assertion_key: Option<EncodingKey>,
    redirect_uri: String,
    login_url: String,
    scopes: Vec<String>,
    prompt: Option<String>,
    login_hint: Option<String>,
    http: reqwest::Client,
}

// The connected app's client secret (and the key identifying it) must
// never reach logs — redact in `{:?}`. `login_hint` is the end user's
// username, so it is personal data and gets the same treatment.
impl std::fmt::Debug for WebServerFlow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebServerFlow")
            .field("consumer_key", &"[redacted]")
            .field(
                "consumer_secret",
                &self.consumer_secret.as_ref().map(|_| "[redacted]"),
            )
            .field("client_assertion", &self.client_assertion_key.is_some())
            .field("redirect_uri", &self.redirect_uri)
            .field("login_url", &self.login_url)
            .field("scopes", &self.scopes)
            .field("prompt", &self.prompt)
            .field(
                "login_hint",
                &self.login_hint.as_ref().map(|_| "[redacted]"),
            )
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
    ///
    /// Parameters that vary per attempt, such as the user's `login_hint`
    /// or a `nonce` for the ID token, go through
    /// [`start_with`](Self::start_with).
    pub fn start(&self) -> AuthResult<(String, PendingExchange)> {
        self.start_with(&AuthorizeOptions::default())
    }

    /// [`start`](Self::start) with per-attempt [`AuthorizeOptions`].
    ///
    /// `prompt` and `login_hint` set in `options` replace the flow-level
    /// values for this attempt. A `nonce`, whether supplied or generated,
    /// is sent in the URL, kept in the returned [`PendingExchange`], and
    /// handed back on [`CompletedSession::nonce`] so the caller can check
    /// the ID token's claim against it.
    pub fn start_with(&self, options: &AuthorizeOptions) -> AuthResult<(String, PendingExchange)> {
        let code_verifier = random_b64url(VERIFIER_BYTES)?;
        let state = random_b64url(STATE_BYTES)?;
        let code_challenge = pkce_s256_challenge(&code_verifier);
        let nonce = match &options.nonce {
            Nonce::None => None,
            Nonce::Generate => Some(random_b64url(STATE_BYTES)?),
            Nonce::Value(value) => Some(value.clone()),
        };

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
            if let Some(p) = options.prompt.as_deref().or(self.prompt.as_deref()) {
                q.append_pair("prompt", p);
            }
            if let Some(h) = options.login_hint.as_deref().or(self.login_hint.as_deref()) {
                q.append_pair("login_hint", h);
            }
            if let Some(n) = nonce.as_deref() {
                q.append_pair("nonce", n);
            }
            if let Some(d) = options.display.as_deref() {
                q.append_pair("display", d);
            }
            // Salesforce's default is false; only the opt-in is sent.
            if options.immediate {
                q.append_pair("immediate", "true");
            }
            if let Some(p) = options.sso_provider.as_deref() {
                q.append_pair("sso_provider", p);
            }
            for (key, value) in &options.extra {
                q.append_pair(key, value);
            }
        }

        let pending = PendingExchange {
            code_verifier,
            state,
            nonce,
            flow: Some(self.fingerprint()),
        };

        Ok((url.into(), pending))
    }

    /// Digest of the configuration an authorization code is bound to:
    /// consumer key, redirect URI and login URL. Each part is length-
    /// prefixed so no choice of separator lets two configurations
    /// collide, and the result is hashed so a persisted pending reveals
    /// none of them.
    fn fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        for part in [&self.consumer_key, &self.redirect_uri, &self.login_url] {
            hasher.update((part.len() as u64).to_le_bytes());
            hasher.update(part.as_bytes());
        }
        URL_SAFE_NO_PAD.encode(hasher.finalize())
    }

    /// Phase 2 — verify the returned `state`, exchange `code` for tokens.
    ///
    /// `pending` is the value [`start`](Self::start) handed back, taken
    /// out of wherever the caller stored it: it is single-use, and a
    /// second `complete` with the same value re-presents a redeemed code
    /// (see [`PendingExchange`]). Returns a [`CompletedSession`] with the
    /// access token, instance URL, and (if the connected app issued them)
    /// refresh and ID tokens.
    ///
    /// Fails without contacting the token endpoint with
    /// [`AuthError::StateMismatch`] when `returned_state` does not match
    /// the state carried in `pending`, and with
    /// [`AuthError::FlowMismatch`] when `pending` was issued by a flow
    /// with a different consumer key, redirect URI or login URL. Both
    /// phases must run on the same configuration, though not on the same
    /// flow value.
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

        // A code is bound to the client, redirect URI and issuing host
        // (RFC 6749 §4.1.3), so a pending from a differently configured
        // flow could only fail at the token endpoint, as an opaque
        // invalid_grant. A pending persisted before the digest existed
        // carries none and is accepted as before.
        if pending
            .flow
            .as_deref()
            .is_some_and(|recorded| recorded != self.fingerprint())
        {
            return Err(AuthError::FlowMismatch);
        }

        // The client authenticates with its secret or with a freshly
        // signed assertion, never both: Salesforce reads the assertion
        // only when no secret is present, and `build` refuses the pair.
        // A secret goes in the Basic header together with the consumer
        // key, and the form then carries neither, since Salesforce
        // ignores the header when the body repeats the pair.
        let assertion;
        let mut body: Vec<(&str, &str)> = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", self.redirect_uri.as_str()),
            ("code_verifier", pending.code_verifier.as_str()),
        ];
        let client_auth = match self.consumer_secret.as_deref() {
            Some(client_secret) => ClientAuth::Basic {
                client_id: &self.consumer_key,
                client_secret,
            },
            None => {
                body.push(("client_id", self.consumer_key.as_str()));
                ClientAuth::Form
            }
        };
        if let Some(key) = &self.client_assertion_key {
            assertion = client_assertion(&self.consumer_key, &self.login_url, key)?;
            body.push(("client_assertion", assertion.as_str()));
            body.push(("client_assertion_type", CLIENT_ASSERTION_TYPE_JWT_BEARER));
        }

        let token = exchange(
            &self.http,
            &self.login_url,
            &body,
            client_auth,
            GrantReplay::Never,
        )
        .await?;
        Ok(CompletedSession {
            access_token: token.access_token,
            refresh_token: token.refresh_token,
            id_token: token.id_token,
            instance_url: normalize_url(&token.instance_url),
            id: token.id,
            issued_at: token.issued_at,
            signature: token.signature,
            scope: token.scope,
            sfdc_site_url: token.sfdc_site_url,
            sfdc_site_id: token.sfdc_site_id,
            nonce: pending.nonce,
        })
    }

    /// Prepares a [`RefreshTokenAuth`] for the session this flow just
    /// completed, so the rest of the SDK can keep renewing it.
    ///
    /// The builder carries over the connected app's consumer key and
    /// secret (or the private key that signs its `client_assertion`),
    /// this flow's `login_url` and HTTP client, the session's
    /// `instance_url` and refresh token, and the access token that came
    /// with it (see
    /// [`initial_access_token`](RefreshTokenAuthBuilder::initial_access_token)),
    /// so the first call reuses that token instead of spending a refresh
    /// grant on it. Add [`on_rotation`](RefreshTokenAuthBuilder::on_rotation)
    /// or a `token_ttl` before calling `build`.
    ///
    /// Fails with [`AuthError::MissingField`] naming `refresh_token` when
    /// the session has none: the connected app's scopes must include
    /// `refresh_token` and the user must have granted it.
    ///
    /// Revokes a token this flow's login host issued: a
    /// [`CompletedSession`]'s refresh token, which revokes its access
    /// tokens with it, or an access token alone. Posts to
    /// `{login_url}/services/oauth2/revoke` with this flow's HTTP client;
    /// see [`revoke_token`] for the wire contract. A
    /// session that has become a [`RefreshTokenAuth`] is revoked through
    /// [`RefreshTokenAuth::revoke`] instead, which knows the live,
    /// possibly rotated, token.
    pub async fn revoke(&self, token: &str) -> AuthResult<()> {
        revoke_token(&self.http, &self.login_url, token).await
    }

    /// Whether the refresh grant itself needs the consumer secret is the
    /// app's "Require Secret for Refresh Token Flow" setting, which is
    /// separate from the web-server one; see the
    /// [`refresh`](crate::refresh) module docs.
    pub fn refresh_auth(&self, session: &CompletedSession) -> AuthResult<RefreshTokenAuthBuilder> {
        let refresh_token = session
            .refresh_token
            .clone()
            .ok_or(AuthError::MissingField("refresh_token"))?;
        let mut builder = RefreshTokenAuth::builder()
            .consumer_key(&self.consumer_key)
            .refresh_token(refresh_token)
            .login_url(&self.login_url)
            .instance_url(&session.instance_url)
            .initial_access_token(&session.access_token)
            .http_client(self.http.clone());
        if let Some(secret) = &self.consumer_secret {
            builder = builder.consumer_secret(secret);
        }
        if let Some(key) = &self.client_assertion_key {
            builder = builder.client_assertion_key(key.clone());
        }
        Ok(builder)
    }
}

/// Per-attempt parameters for the authorization request built by
/// [`WebServerFlow::start_with`].
///
/// A flow is shared across every login it serves, so values that differ
/// from one attempt to the next live here: the `login_hint` for the user
/// about to sign in, the `prompt` for this attempt, a `nonce` to bind an
/// ID token to it, and the `display`, `immediate` and `sso_provider`
/// parameters Salesforce documents for the authorize endpoint. `prompt`
/// and `login_hint` set here replace the flow-level values for the one
/// attempt.
#[derive(Clone, Default)]
pub struct AuthorizeOptions {
    login_hint: Option<String>,
    prompt: Option<String>,
    nonce: Nonce,
    display: Option<String>,
    immediate: bool,
    sso_provider: Option<String>,
    extra: Vec<(String, String)>,
}

/// Where the `nonce` parameter comes from, if anywhere.
#[derive(Clone, Default)]
enum Nonce {
    #[default]
    None,
    Generate,
    Value(String),
}

// `login_hint` is the end user's username, redacted like the flow's own.
// The nonce is kept out of logs for the same reason `state` is.
impl std::fmt::Debug for AuthorizeOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let nonce = match self.nonce {
            Nonce::None => "none",
            Nonce::Generate => "generated",
            Nonce::Value(_) => "[redacted]",
        };
        f.debug_struct("AuthorizeOptions")
            .field(
                "login_hint",
                &self.login_hint.as_ref().map(|_| "[redacted]"),
            )
            .field("prompt", &self.prompt)
            .field("nonce", &nonce)
            .field("display", &self.display)
            .field("immediate", &self.immediate)
            .field("sso_provider", &self.sso_provider)
            .field("extra", &self.extra)
            .finish()
    }
}

impl AuthorizeOptions {
    /// Pre-fills the username on the login page for this attempt,
    /// replacing the flow-level
    /// [`login_hint`](WebServerFlowBuilder::login_hint). For an Experience
    /// Cloud site login Salesforce also needs `prompt=login` for the hint
    /// to take effect.
    pub fn login_hint(mut self, hint: impl Into<String>) -> Self {
        self.login_hint = Some(hint.into());
        self
    }

    /// The OAuth `prompt` for this attempt (`login`, `consent`,
    /// `select_account`, or several separated by spaces), replacing the
    /// flow-level [`prompt`](WebServerFlowBuilder::prompt).
    pub fn prompt(mut self, prompt: impl Into<String>) -> Self {
        self.prompt = Some(prompt.into());
        self
    }

    /// Sends this value as the `nonce`, which Salesforce echoes in the ID
    /// token when the `openid` scope is requested. It travels in the
    /// [`PendingExchange`] and comes back on [`CompletedSession::nonce`]
    /// for the caller to compare with the token's `nonce` claim.
    pub fn nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Nonce::Value(nonce.into());
        self
    }

    /// Like [`nonce`](Self::nonce), with a fresh random value (16 bytes,
    /// URL-safe base64) generated when the authorization URL is built.
    pub fn generate_nonce(mut self) -> Self {
        self.nonce = Nonce::Generate;
        self
    }

    /// The `display` type of the login and authorization pages: `page`
    /// (Salesforce's default), `popup`, `touch` or `mobile`.
    pub fn display(mut self, display: impl Into<String>) -> Self {
        self.display = Some(display.into());
        self
    }

    /// Sends `immediate=true`: a user who is logged in and has already
    /// approved the app skips the approval step, and any other user comes
    /// back with `immediate_unsuccessful` instead of a login page. Not
    /// available for Experience Cloud sites. `false`, Salesforce's
    /// default, sends no parameter.
    pub fn immediate(mut self, immediate: bool) -> Self {
        self.immediate = immediate;
        self
    }

    /// Developer name of a single sign-on identity provider configured
    /// for the login URL, to send the user straight to it.
    pub fn sso_provider(mut self, provider: impl Into<String>) -> Self {
        self.sso_provider = Some(provider.into());
        self
    }

    /// Appends any other query parameter to the authorization URL.
    /// Multiple calls accumulate, and a key the flow already sends is
    /// repeated rather than replaced.
    pub fn param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra.push((key.into(), value.into()));
        self
    }
}

/// Opaque, serializable handle holding the PKCE verifier + state nonce
/// between the authorize and token-exchange phases. The caller must
/// persist it until the OAuth callback fires and pass it back to
/// [`WebServerFlow::complete`].
///
/// It carries no connected-app credentials — only the per-attempt values
/// the SDK generates and a digest of the flow configuration that issued
/// it. The `code_verifier` inside is still a secret: anyone holding both
/// it and an intercepted authorization code can complete the exchange.
/// Keep it somewhere the end user cannot read, such as a server-side
/// session store, or a cookie that is **encrypted** rather than merely
/// signed — a signed cookie is integrity-protected but its contents are
/// plainly readable by the browser.
///
/// A pending is **single-use**. Take it out of the store, keyed by its
/// [`state`](Self::state), before calling `complete`, so a callback that
/// is hit twice (a refreshed callback page, a retried request) finds
/// nothing rather than presenting the redeemed code again: RFC 6749
/// §4.1.2 has the server deny that second exchange and lets it revoke
/// every token the code already produced. The state check cannot catch
/// this case, because both values come from the same stored pending.
///
/// Both phases must run on a flow with the same consumer key, redirect
/// URI and login URL. An authorization code is bound to all three, so no
/// other flow could redeem it; `complete` compares the digest recorded
/// here and fails with [`AuthError::FlowMismatch`] before any request
/// when they differ.
#[derive(Clone, Serialize, Deserialize)]
pub struct PendingExchange {
    code_verifier: String,
    state: String,
    /// Digest of the issuing flow's configuration, see
    /// [`WebServerFlow::fingerprint`]. Absent from values persisted
    /// before it was recorded, which `complete` accepts unchecked.
    /// The `nonce` sent in the authorization URL, when
    /// [`AuthorizeOptions`] asked for one. Absent from values persisted
    /// before it existed.
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    flow: Option<String>,
}

// Redact the PKCE secret — leaking it lets anyone holding the
// authorization code complete the exchange. `state` is a CSRF nonce and
// `nonce` an ID-token one — non-secret to the user but better hygiene to
// keep out of logs. The flow digest reveals nothing about the
// configuration it was taken from.
impl std::fmt::Debug for PendingExchange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingExchange")
            .field("code_verifier", &"[redacted]")
            .field("state", &"[redacted]")
            .field("nonce", &self.nonce.as_ref().map(|_| "[redacted]"))
            .field("flow", &self.flow)
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

    /// The `nonce` sent in the authorization URL, if [`AuthorizeOptions`]
    /// asked for one. The same value is returned on
    /// [`CompletedSession::nonce`] once the exchange succeeds.
    pub fn nonce(&self) -> Option<&str> {
        self.nonce.as_deref()
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
    /// Experience Cloud site URL, returned when the authenticated user is
    /// a member of a site (for example a login through
    /// `https://acme.my.site.com/portal`). `None` for a direct org login.
    pub sfdc_site_url: Option<String>,
    /// Experience Cloud site ID for the same case. Some Connect REST
    /// requests need it, and nothing else in the response carries it.
    pub sfdc_site_id: Option<String>,
    /// The `nonce` the authorization request carried, if
    /// [`AuthorizeOptions`] set one. Compare it with the `nonce` claim of
    /// `id_token` before trusting that token; this crate does not
    /// validate ID tokens itself.
    pub nonce: Option<String>,
}

// Tokens and the HMAC `signature` are secrets — redact in `{:?}`.
// `instance_url`, `id`, `issued_at`, `scope` and the site fields are
// non-secret; the nonce is kept out of logs like `state`.
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
            .field("sfdc_site_url", &self.sfdc_site_url)
            .field("sfdc_site_id", &self.sfdc_site_id)
            .field("nonce", &self.nonce.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

/// Builder for [`WebServerFlow`].
#[derive(Default)]
pub struct WebServerFlowBuilder {
    consumer_key: Option<String>,
    consumer_secret: Option<String>,
    private_key: Option<EncodingKey>,
    redirect_uri: Option<String>,
    login_url: Option<String>,
    scopes: Vec<String>,
    prompt: Option<String>,
    login_hint: Option<String>,
    http: HttpClientConfig,
}

impl std::fmt::Debug for WebServerFlowBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebServerFlowBuilder")
            .field("consumer_key", &self.consumer_key.is_some())
            .field("consumer_secret", &self.consumer_secret.is_some())
            .field("private_key", &self.private_key.is_some())
            .field("redirect_uri", &self.redirect_uri)
            .field("login_url", &self.login_url)
            .field("scopes", &self.scopes)
            .field("prompt", &self.prompt)
            .field("login_hint", &self.login_hint.is_some())
            .finish_non_exhaustive()
    }
}

impl WebServerFlowBuilder {
    /// Connected App's Consumer Key (Client ID). Required.
    pub fn consumer_key(mut self, key: impl Into<String>) -> Self {
        self.consumer_key = Some(key.into());
        self
    }

    /// Connected App's Consumer Secret. Salesforce requires it on the code
    /// exchange unless the app's "Require Secret for Web Server Flow"
    /// setting is off (`isConsumerSecretOptional = true`), which is not
    /// the default, or the exchange authenticates with a
    /// [`client_assertion`](Self::private_key_pem_bytes) instead; the
    /// refresh grant has a setting of its own, see the
    /// [module docs](self). Sent only when set.
    pub fn consumer_secret(mut self, secret: impl Into<String>) -> Self {
        self.consumer_secret = Some(secret.into());
        self
    }

    /// Authenticates the code exchange, and the refresh grant that
    /// [`WebServerFlow::refresh_auth`] sets up, with a `client_assertion`
    /// signed by this RSA private key instead of with `consumer_secret`,
    /// for a host that must not hold the secret. The key is the one
    /// behind the certificate uploaded to the connected app. Each token
    /// request carries a fresh RS256 JWT naming the consumer key as `iss`
    /// and `sub` and the token endpoint as `aud`, plus
    /// `client_assertion_type`, and no `client_secret`.
    ///
    /// Set this or `consumer_secret`, not both: Salesforce reads the
    /// assertion only when no secret is present, so
    /// [`build`](Self::build) refuses the pair with
    /// [`AuthError::InvalidArgument`]. Accepts the same PEM as
    /// [`JwtAuthBuilder::private_key_pem_bytes`](crate::JwtAuthBuilder::private_key_pem_bytes):
    /// an `RSA PRIVATE KEY` or `PRIVATE KEY` block first.
    pub fn private_key_pem_bytes(mut self, bytes: &[u8]) -> AuthResult<Self> {
        self.private_key = Some(private_key_from_pem(bytes)?);
        Ok(self)
    }

    /// The file form of
    /// [`private_key_pem_bytes`](Self::private_key_pem_bytes). The path
    /// is a [`camino::Utf8PathBuf`] or anything that converts into one.
    pub fn private_key_pem_file(mut self, path: impl Into<Utf8PathBuf>) -> AuthResult<Self> {
        self.private_key = Some(private_key_from_pem_file(&path.into())?);
        Ok(self)
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
    /// The client built by default applies connect and request timeouts,
    /// uses no proxy and refuses to follow redirects, so a redirect cannot replay the
    /// authorization code and PKCE verifier to another host. A client
    /// supplied here replaces those defaults wholesale, the timeout setters
    /// included; start from
    /// [`token_client_builder`](crate::token_client_builder) to keep them
    /// while adding settings.
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
        check_client_authentication(self.consumer_secret.as_deref(), self.private_key.as_ref())?;
        let http = self.http.into_client()?;
        Ok(WebServerFlow {
            consumer_key,
            consumer_secret: self.consumer_secret,
            client_assertion_key: self.private_key,
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
    use crate::AuthSession;
    use crate::test_support::decode_jwt_segment;
    use base64::engine::general_purpose::STANDARD;
    use std::sync::Arc;
    use wiremock::matchers::{body_string_contains, header, method, path};
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
            .login_hint("user@example.com")
            .build()
            .unwrap();
        let debug = format!("{flow:?}");
        assert!(!debug.contains("super-secret-value"), "leaked: {debug}");
        assert!(!debug.contains("consumer-key-123"), "leaked: {debug}");
        // SOURCE: https://help.salesforce.com/s/articleView?id=xcloud.remoteaccess_oauth_web_server_flow.htm
        // `login_hint` "provides a valid username value": it is the end
        // user's identity, redacted the way the JWT flow redacts `sub`.
        assert!(!debug.contains("user@example.com"), "leaked: {debug}");
        assert!(debug.contains("[redacted]"));
        // Non-secret config stays visible for diagnostics.
        assert!(debug.contains("https://app.example.com/oauth/callback"));
    }

    #[test]
    fn builder_debug_redacts_the_login_hint() {
        let builder = flow_with_required_fields().login_hint("user@example.com");
        let debug = format!("{builder:?}");
        assert!(!debug.contains("user@example.com"), "leaked: {debug}");
        assert!(debug.contains("login_hint: true"), "{debug}");
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
    fn start_with_appends_the_per_attempt_parameters() {
        // SOURCE: https://help.salesforce.com/s/articleView?id=xcloud.remoteaccess_oauth_web_server_flow.htm
        // (release 264) lists these optional authorize parameters:
        // `display` (page, popup, touch, mobile), `immediate` ("A boolean
        // value ... The default value is false"), `login_hint`, `nonce`,
        // `prompt` and `sso_provider` ("The developer name of a single
        // sign-on (SSO) identity provider").
        let flow = flow_with_required_fields().build().unwrap();
        let options = AuthorizeOptions::default()
            .login_hint("user@example.com")
            .prompt("consent")
            .display("popup")
            .immediate(true)
            .sso_provider("Corporate_Okta")
            .param("custom_param", "custom value");
        let (url, _) = flow.start_with(&options).unwrap();
        let parsed = url::Url::parse(&url).unwrap();
        let q: std::collections::HashMap<_, _> = parsed.query_pairs().collect();

        let get = |k: &str| q.get(k).map(|s| s.as_ref());
        assert_eq!(get("login_hint"), Some("user@example.com"));
        assert_eq!(get("prompt"), Some("consent"));
        assert_eq!(get("display"), Some("popup"));
        assert_eq!(get("immediate"), Some("true"));
        assert_eq!(get("sso_provider"), Some("Corporate_Okta"));
        assert_eq!(get("custom_param"), Some("custom value"));
    }

    #[test]
    fn start_with_overrides_the_flow_level_prompt_and_login_hint() {
        let flow = flow_with_required_fields()
            .prompt("login")
            .login_hint("default@example.com")
            .build()
            .unwrap();
        let options = AuthorizeOptions::default()
            .prompt("consent")
            .login_hint("this-user@example.com");
        let (url, _) = flow.start_with(&options).unwrap();
        let parsed = url::Url::parse(&url).unwrap();
        let pairs: Vec<_> = parsed.query_pairs().collect();

        let values = |k: &str| {
            pairs
                .iter()
                .filter(|(key, _)| key == k)
                .map(|(_, v)| v.to_string())
                .collect::<Vec<_>>()
        };
        // Exactly one of each: the override replaces, it does not add.
        assert_eq!(values("prompt"), ["consent"]);
        assert_eq!(values("login_hint"), ["this-user@example.com"]);
    }

    #[test]
    fn start_sends_only_the_configured_parameters() {
        // Salesforce documents `immediate` as defaulting to false, and the
        // other per-attempt parameters have no default: none of them may
        // appear unless asked for, and the session then carries no nonce.
        let flow = flow_with_required_fields().build().unwrap();
        let (url, pending) = flow.start().unwrap();
        let parsed = url::Url::parse(&url).unwrap();
        let q: std::collections::HashMap<_, _> = parsed.query_pairs().collect();
        for key in ["nonce", "display", "immediate", "sso_provider"] {
            assert!(!q.contains_key(key), "unexpected {key} in {url}");
        }
        assert_eq!(pending.nonce(), None);
    }

    #[tokio::test]
    async fn start_with_a_generated_nonce_carries_it_to_the_completed_session() {
        // The nonce published in the authorize URL is what Salesforce
        // echoes in the ID token. The caller validates that claim after
        // `complete`, so the same value must survive the persisted
        // pending and come back on the session.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(documented_token_response()))
            .mount(&server)
            .await;
        let flow = flow_with_required_fields()
            .login_url(server.uri())
            .scope("openid")
            .build()
            .unwrap();
        let (url, pending) = flow
            .start_with(&AuthorizeOptions::default().generate_nonce())
            .unwrap();
        let published = url::Url::parse(&url)
            .unwrap()
            .query_pairs()
            .find(|(k, _)| k == "nonce")
            .map(|(_, v)| v.into_owned())
            .expect("nonce must be in the authorize URL");
        assert!(published.len() >= 22, "nonce too short: {published}");

        let restored: PendingExchange =
            serde_json::from_str(&serde_json::to_string(&pending).unwrap()).unwrap();
        let state = restored.state().to_string();
        let session = flow.complete(restored, "c", &state).await.unwrap();
        assert_eq!(session.nonce.as_deref(), Some(published.as_str()));
    }

    #[test]
    fn start_with_an_explicit_nonce_uses_it_verbatim() {
        let flow = flow_with_required_fields().build().unwrap();
        let (url, pending) = flow
            .start_with(&AuthorizeOptions::default().nonce("caller-chosen-nonce"))
            .unwrap();
        let parsed = url::Url::parse(&url).unwrap();
        let q: std::collections::HashMap<_, _> = parsed.query_pairs().collect();
        assert_eq!(
            q.get("nonce").map(|s| s.as_ref()),
            Some("caller-chosen-nonce")
        );
        assert_eq!(pending.nonce(), Some("caller-chosen-nonce"));
    }

    #[test]
    fn authorize_options_debug_redacts_the_login_hint_and_nonce() {
        let options = AuthorizeOptions::default()
            .login_hint("user@example.com")
            .nonce("caller-chosen-nonce")
            .display("popup");
        let debug = format!("{options:?}");
        assert!(!debug.contains("user@example.com"), "leaked: {debug}");
        assert!(!debug.contains("caller-chosen-nonce"), "leaked: {debug}");
        assert!(debug.contains("popup"), "{debug}");
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
    async fn revoke_posts_the_token_to_the_flows_login_url() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/services/oauth2/revoke"))
            .and(body_string_contains("token=5Aep861KIwKdekr...refresh"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        let flow = flow_with_required_fields()
            .login_url(server.uri())
            .build()
            .unwrap();
        flow.revoke("5Aep861KIwKdekr...refresh").await.unwrap();
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
        // The documented sample is a non-site login: no site fields.
        assert_eq!(session.sfdc_site_url, None);
        assert_eq!(session.sfdc_site_id, None);
    }

    #[tokio::test]
    async fn complete_surfaces_the_experience_cloud_site_fields() {
        // SOURCE: https://help.salesforce.com/s/articleView?id=xcloud.remoteaccess_oauth_web_server_flow.htm
        // (release 264): the token response lists `sfdc_site_url` ("If the
        // user is a member of an Experience Cloud site, the site URL is
        // provided") and `sfdc_site_id` ("the user's site ID is provided").
        // The page names the keys but prints no sample values; the ones
        // here are shaped like a site URL and a Network record id.
        let server = MockServer::start().await;
        let mut body = documented_token_response();
        body["sfdc_site_url"] = serde_json::Value::String("https://acme.my.site.com/portal".into());
        body["sfdc_site_id"] = serde_json::Value::String("0DB5e000000TN1aGAG".into());
        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;

        let flow = flow_with_required_fields()
            .login_url(server.uri())
            .build()
            .unwrap();
        let (_, pending) = flow.start().unwrap();
        let state = pending.state().to_string();
        let session = flow.complete(pending, "c", &state).await.unwrap();

        assert_eq!(
            session.sfdc_site_url.as_deref(),
            Some("https://acme.my.site.com/portal")
        );
        assert_eq!(session.sfdc_site_id.as_deref(), Some("0DB5e000000TN1aGAG"));
        // Neither value is a credential, so diagnostics may show them.
        let debug = format!("{session:?}");
        assert!(debug.contains("0DB5e000000TN1aGAG"), "{debug}");
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
    async fn refresh_auth_requires_a_refresh_token() {
        // A connected app without the `refresh_token` scope issues none;
        // the hand-off has nothing to renew with and must say which field.
        let server = MockServer::start().await;
        let mut body = documented_token_response();
        body.as_object_mut().unwrap().remove("refresh_token");
        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;
        let flow = flow_with_required_fields()
            .login_url(server.uri())
            .build()
            .unwrap();
        let (_, pending) = flow.start().unwrap();
        let state = pending.state().to_string();
        let session = flow.complete(pending, "c", &state).await.unwrap();

        let err = flow.refresh_auth(&session).unwrap_err();
        assert!(
            matches!(err, AuthError::MissingField("refresh_token")),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn refresh_auth_serves_the_issued_access_token_without_a_mint() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .and(body_string_contains("grant_type=authorization_code"))
            .respond_with(ResponseTemplate::new(200).set_body_json(documented_token_response()))
            .mount(&server)
            .await;
        let flow = flow_with_required_fields()
            .login_url(server.uri())
            .build()
            .unwrap();
        let (_, pending) = flow.start().unwrap();
        let state = pending.state().to_string();
        let session = flow.complete(pending, "c", &state).await.unwrap();

        let auth = flow.refresh_auth(&session).unwrap().build().unwrap();
        let token = auth.access_token().await.unwrap();
        assert_eq!(token, session.access_token);
        assert_eq!(auth.instance_url(), session.instance_url);
        // Only the code exchange reached the endpoint. A refresh grant here
        // would, under Refresh Token Rotation, replace the refresh token
        // the caller just stored.
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1, "unexpected refresh grant");
    }

    #[tokio::test]
    async fn refresh_auth_carries_the_flow_configuration_into_the_refresh_grant() {
        // The refresh grant must go to the host that issued the code, with
        // the same client id and secret; a builder that fell back to the
        // production login URL or dropped the secret would be rejected by
        // a sandbox or a confidential app at the first renewal.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .and(body_string_contains("grant_type=authorization_code"))
            .respond_with(ResponseTemplate::new(200).set_body_json(documented_token_response()))
            .mount(&server)
            .await;
        let mut refreshed = documented_token_response();
        refreshed["access_token"] = serde_json::Value::String("REFRESHED".into());
        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .and(body_string_contains("grant_type=refresh_token"))
            .and(header(
                "authorization",
                format!("Basic {}", STANDARD.encode("consumer-key-123:hunter2")),
            ))
            .and(body_string_contains(
                "refresh_token=5Aep861KIwKdekr...refresh",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(refreshed))
            .mount(&server)
            .await;

        let flow = flow_with_required_fields()
            .login_url(server.uri())
            .consumer_secret("hunter2")
            .build()
            .unwrap();
        let (_, pending) = flow.start().unwrap();
        let state = pending.state().to_string();
        let session = flow.complete(pending, "c", &state).await.unwrap();

        let auth = flow.refresh_auth(&session).unwrap().build().unwrap();
        auth.invalidate(&session.access_token).await;
        let token = auth.access_token().await.unwrap();
        assert_eq!(token, "REFRESHED");
    }

    #[tokio::test]
    async fn complete_rejects_a_pending_started_by_a_differently_configured_flow() {
        // A code is bound to the client, redirect URI and host that issued
        // it, so a pending from a sandbox flow completed on a production
        // flow can only fail remotely. Catch it locally, before any
        // request: neither server has a mock, so a POST fails loudly.
        let sandbox = MockServer::start().await;
        let production = MockServer::start().await;
        let started_on = flow_with_required_fields()
            .login_url(sandbox.uri())
            .build()
            .unwrap();
        let completed_on = flow_with_required_fields()
            .login_url(production.uri())
            .build()
            .unwrap();
        let (_, pending) = started_on.start().unwrap();
        let state = pending.state().to_string();

        let err = completed_on
            .complete(pending, "c", &state)
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::FlowMismatch), "{err:?}");
        assert!(
            production
                .received_requests()
                .await
                .is_some_and(|r| r.is_empty()),
            "the code was posted despite the mismatch"
        );
    }

    #[tokio::test]
    async fn complete_accepts_a_pending_from_an_identically_configured_flow() {
        // The two phases usually run in different processes, each with
        // its own flow value built from the same settings; the check must
        // compare configuration, not identity.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(documented_token_response()))
            .mount(&server)
            .await;
        let started_on = flow_with_required_fields()
            .login_url(server.uri())
            .consumer_secret("hunter2")
            .build()
            .unwrap();
        let completed_on = flow_with_required_fields()
            .login_url(server.uri())
            .consumer_secret("hunter2")
            .build()
            .unwrap();
        let (_, pending) = started_on.start().unwrap();
        let state = pending.state().to_string();

        completed_on.complete(pending, "c", &state).await.unwrap();
    }

    #[tokio::test]
    async fn complete_accepts_a_pending_persisted_without_a_fingerprint() {
        // A pending written by a build that recorded no flow fingerprint
        // may still be in a store during a rolling deploy; it carries the
        // two fields a token request needs and must keep working.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .and(body_string_contains("code_verifier=legacy-verifier"))
            .respond_with(ResponseTemplate::new(200).set_body_json(documented_token_response()))
            .mount(&server)
            .await;
        let flow = flow_with_required_fields()
            .login_url(server.uri())
            .build()
            .unwrap();
        let pending: PendingExchange = serde_json::from_str(
            r#"{"code_verifier":"legacy-verifier","state":"legacy-state-value"}"#,
        )
        .unwrap();

        flow.complete(pending, "c", "legacy-state-value")
            .await
            .unwrap();
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

    /// Throwaway RSA key shared with the JWT tests; see
    /// `tests/fixtures/test_rsa_key.pem`.
    const TEST_PEM: &[u8] = include_bytes!("../tests/fixtures/test_rsa_key.pem");

    #[tokio::test]
    async fn complete_signs_a_client_assertion_when_a_private_key_is_set() {
        // SOURCE: https://help.salesforce.com/s/articleView?id=xcloud.remoteaccess_oauth_web_server_flow.htm&type=5
        // (release 264), "Use client_assertion instead of client_secret":
        // iss and sub are the client_id, aud is the token servlet URL, exp
        // is within 5 minutes, and only RS256 is supported.
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
            .private_key_pem_bytes(TEST_PEM)
            .unwrap()
            .build()
            .unwrap();
        let (_, pending) = flow.start().unwrap();
        let state = pending.state().to_string();
        flow.complete(pending, "c", &state).await.unwrap();

        let body = captured.lock().await;
        let params: Vec<(String, String)> = serde_urlencoded::from_str(&body).unwrap();
        let field = |name: &str| {
            params
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
                .unwrap_or_else(|| panic!("{name} missing from body: {body}"))
        };
        assert!(params.iter().all(|(k, _)| k != "client_secret"), "{body}");
        assert_eq!(
            field("client_assertion_type"),
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        );
        let assertion = field("client_assertion");
        let mut parts = assertion.split('.');
        let header = decode_jwt_segment(parts.next().unwrap());
        let claims = decode_jwt_segment(parts.next().unwrap());
        assert!(parts.next().is_some(), "assertion must carry a signature");
        assert_eq!(header["alg"], "RS256");
        assert_eq!(claims["iss"], "consumer-key-123");
        assert_eq!(claims["sub"], "consumer-key-123");
        assert_eq!(
            claims["aud"],
            format!("{}/services/oauth2/token", server.uri())
        );
    }

    #[tokio::test]
    async fn refresh_auth_carries_the_private_key_into_the_refresh_grant() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .and(body_string_contains("grant_type=authorization_code"))
            .respond_with(ResponseTemplate::new(200).set_body_json(documented_token_response()))
            .mount(&server)
            .await;
        let mut refreshed = documented_token_response();
        refreshed["access_token"] = serde_json::Value::String("REFRESHED".into());
        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .and(body_string_contains("grant_type=refresh_token"))
            .and(body_string_contains("client_assertion="))
            .and(body_string_contains(
                "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(refreshed))
            .mount(&server)
            .await;

        let flow = flow_with_required_fields()
            .login_url(server.uri())
            .private_key_pem_bytes(TEST_PEM)
            .unwrap()
            .build()
            .unwrap();
        let (_, pending) = flow.start().unwrap();
        let state = pending.state().to_string();
        let session = flow.complete(pending, "c", &state).await.unwrap();

        let auth = flow.refresh_auth(&session).unwrap().build().unwrap();
        auth.invalidate(&session.access_token).await;
        assert_eq!(auth.access_token().await.unwrap(), "REFRESHED");
    }

    #[test]
    fn builder_refuses_a_private_key_alongside_a_consumer_secret() {
        let err = flow_with_required_fields()
            .consumer_secret("hunter2")
            .private_key_pem_bytes(TEST_PEM)
            .unwrap()
            .build()
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

    #[tokio::test]
    async fn confidential_client_authenticates_with_a_basic_header() {
        // SOURCE: https://help.salesforce.com/s/articleView?id=xcloud.remoteaccess_oauth_web_server_flow.htm&type=5
        // (release 264), "HTTP Basic Authentication Scheme": "Instead of
        // sending client credentials as parameters in the body of the
        // POST, Salesforce supports the HTTP Basic authentication scheme.
        // This scheme's format requires the client_id and client_secret
        // in the authorization header of the post as follows:
        // Authorization: Basic64Encode(client_id:secret)". And: "If the
        // client_id and client_secret are sent in the POST's body, the
        // authorization header is ignored", so neither may stay in the
        // form.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .and(header(
                "authorization",
                format!("Basic {}", STANDARD.encode("consumer-key-123:hunter2")),
            ))
            .and(body_string_contains("grant_type=authorization_code"))
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

        let requests = server.received_requests().await.unwrap();
        let body = String::from_utf8(requests[0].body.clone()).unwrap();
        let params: Vec<(String, String)> = serde_urlencoded::from_str(&body).unwrap();
        assert!(
            params
                .iter()
                .all(|(k, _)| k != "client_id" && k != "client_secret"),
            "{body}"
        );
    }

    #[tokio::test]
    async fn public_client_sends_only_the_client_id_in_the_body() {
        // With no secret there is nothing to put in a Basic header: the
        // client identifies itself with `client_id` in the form alone.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .and(body_string_contains("client_id=consumer-key-123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(documented_token_response()))
            .mount(&server)
            .await;

        let flow = flow_with_required_fields()
            .login_url(server.uri())
            .build()
            .unwrap();
        let (_, pending) = flow.start().unwrap();
        let state = pending.state().to_string();
        flow.complete(pending, "c", &state).await.unwrap();

        let requests = server.received_requests().await.unwrap();
        assert!(
            requests[0].headers.get("authorization").is_none(),
            "{:?}",
            requests[0].headers
        );
        let body = String::from_utf8(requests[0].body.clone()).unwrap();
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
