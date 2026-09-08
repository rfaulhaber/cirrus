//! OAuth 2.0 Token Exchange flow (RFC 8693) for trading an external
//! identity provider's token for a Salesforce access token.
//!
//! Use this when Salesforce is one component in a federated identity
//! architecture: a central IdP issues access / refresh / id / SAML / JWT
//! tokens, and you want a Salesforce session for the same end user
//! without making them log in to Salesforce separately. The caller's
//! `subject_token` (from the IdP) is exchanged at the Salesforce token
//! endpoint for a fresh Salesforce token.
//!
//! ## Wire shape
//!
//! POST `/services/oauth2/token` with form body:
//!
//! - `grant_type` — always
//!   `urn:ietf:params:oauth:grant-type:token-exchange` (the RFC 8693
//!   URN; Salesforce's token-exchange docs define no other value).
//! - `subject_token` — the IdP-issued token.
//! - `subject_token_type` — one of the five well-known URNs in
//!   [`SubjectTokenType`].
//! - `client_id` — connected app consumer key.
//! - `client_secret` — required for confidential clients (the connected
//!   app's `Require Secret for Token Exchange Flow` setting), omitted
//!   for public clients.
//! - `scope` — optional space-separated scopes.
//! - `token_handler` — optional Apex token-exchange-handler name. The
//!   docs strongly recommend setting this; otherwise Salesforce uses the
//!   org's default handler.
//!
//! ## My Domain URL is required
//!
//! The builder requires `login_url`: Salesforce's token-exchange examples
//! address the org directly as `MyDomainName.my.salesforce.com` (or the
//! Experience Cloud `MyDomainName.my.site.com`), and there is no sensible
//! default for an org-scoped host.
//!
//! No `subject_token` length limit and no restriction on the token
//! endpoint host are enforced here: any `login_url` you configure is used
//! as given. The request and response shapes follow RFC 8693, and the
//! connected-app side of the flow (`isTokenExchangeEnabled`,
//! `isSecretRequiredForTokenExchange`, and the `OauthTokenExchangeHandler`
//! type) is documented in the Metadata API guide.
//!
//! ## What you get back
//!
//! A [`TokenExchangeSession`] containing the Salesforce `access_token`,
//! `instance_url`, and (depending on the connected app's scopes and the
//! request) optional `refresh_token`, `id_token`, `scope`, `issued_at`.
//! If a `refresh_token` is returned, wire it into a
//! [`crate::RefreshTokenAuth`] for ongoing API access — the same
//! pattern as Web Server PKCE.

use crate::error::{AuthError, AuthResult};
use crate::token_endpoint::{
    default_http_client, exchange, normalize_url, require_secure_login_url,
};

/// RFC 8693 grant-type URN — the only `grant_type` Salesforce's token
/// exchange flow accepts.
pub const GRANT_TYPE_TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

/// RFC 8693 `subject_token_type` URNs supported by Salesforce.
///
/// The connected app's `OauthTokenExchangeHandler` metadata controls
/// which of these are accepted (`isAccessTokenSupported`,
/// `isRefreshTokenSupported`, `isIdTokenSupported`, `isSaml2Supported`,
/// `isJwtSupported`). [`Custom`](Self::Custom) is provided as an escape
/// hatch for token-type URNs not enumerated here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubjectTokenType {
    /// `urn:ietf:params:oauth:token-type:access_token` — OAuth 2.0 access token.
    AccessToken,
    /// `urn:ietf:params:oauth:token-type:refresh_token` — OAuth 2.0 refresh token.
    RefreshToken,
    /// `urn:ietf:params:oauth:token-type:id_token` — OpenID Connect ID token.
    IdToken,
    /// `urn:ietf:params:oauth:token-type:saml2` — base64 URL-encoded SAML 2.0 assertion.
    Saml2,
    /// `urn:ietf:params:oauth:token-type:jwt` — any token formatted as a JWT.
    Jwt,
    /// Escape hatch for an unrecognized URN.
    Custom(String),
}

impl SubjectTokenType {
    /// Returns the URN as it should appear in the form body.
    pub fn as_urn(&self) -> &str {
        match self {
            Self::AccessToken => "urn:ietf:params:oauth:token-type:access_token",
            Self::RefreshToken => "urn:ietf:params:oauth:token-type:refresh_token",
            Self::IdToken => "urn:ietf:params:oauth:token-type:id_token",
            Self::Saml2 => "urn:ietf:params:oauth:token-type:saml2",
            Self::Jwt => "urn:ietf:params:oauth:token-type:jwt",
            Self::Custom(s) => s,
        }
    }
}

/// One-shot RFC 8693 token-exchange request.
///
/// Construct via [`TokenExchangeFlow::builder`].
//
// Wire-shape provenance: the reference Salesforce pages for this flow —
// including whether `https://login.salesforce.com` is rejected outright
// and whether `subject_token` has a documented length ceiling — live on
// help.salesforce.com and were not reachable, so neither is asserted nor
// enforced. The reachable pages that do govern the flow are the Apex
// `token_exchange_handler` guide and the Metadata API's
// `meta_oauthtokenexchangehandler`, neither of which states a length
// limit or a permitted host.
pub struct TokenExchangeFlow {
    consumer_key: String,
    consumer_secret: Option<String>,
    login_url: String,
    subject_token: String,
    subject_token_type: SubjectTokenType,
    scopes: Vec<String>,
    token_handler: Option<String>,
    http: reqwest::Client,
}

// `subject_token` is the IdP-issued credential being exchanged — a
// short-lived but live secret. `consumer_key` is a credential
// identifier; `consumer_secret` the confidential-client secret. Redact
// all three.
impl std::fmt::Debug for TokenExchangeFlow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenExchangeFlow")
            .field("consumer_key", &"[redacted]")
            .field(
                "consumer_secret",
                &self.consumer_secret.as_ref().map(|_| "[redacted]"),
            )
            .field("login_url", &self.login_url)
            .field("subject_token", &"[redacted]")
            .field("subject_token_type", &self.subject_token_type)
            .field("scopes", &self.scopes)
            .field("token_handler", &self.token_handler)
            .finish_non_exhaustive()
    }
}

impl TokenExchangeFlow {
    /// Begins constructing a [`TokenExchangeFlow`].
    pub fn builder() -> TokenExchangeFlowBuilder {
        TokenExchangeFlowBuilder::default()
    }

    /// Performs the token exchange and returns the resulting Salesforce
    /// session. This consumes `self` because each invocation uses a
    /// specific `subject_token` that may already have been consumed at the
    /// IdP — re-running with the same builder would risk a double-spend
    /// of the IdP's token.
    pub async fn exchange(self) -> AuthResult<TokenExchangeSession> {
        let scope_joined;
        let mut body: Vec<(&str, &str)> = vec![
            ("grant_type", GRANT_TYPE_TOKEN_EXCHANGE),
            ("subject_token", self.subject_token.as_str()),
            ("subject_token_type", self.subject_token_type.as_urn()),
            ("client_id", self.consumer_key.as_str()),
        ];
        if let Some(secret) = self.consumer_secret.as_deref() {
            body.push(("client_secret", secret));
        }
        if !self.scopes.is_empty() {
            scope_joined = self.scopes.join(" ");
            body.push(("scope", scope_joined.as_str()));
        }
        if let Some(handler) = self.token_handler.as_deref() {
            body.push(("token_handler", handler));
        }

        let token = exchange(&self.http, &self.login_url, &body).await?;
        Ok(TokenExchangeSession {
            access_token: token.access_token,
            refresh_token: token.refresh_token,
            id_token: token.id_token,
            instance_url: normalize_url(&token.instance_url),
            issued_at: token.issued_at,
            scope: token.scope,
            id: token.id,
            signature: token.signature,
        })
    }
}

/// Result of a successful Token Exchange.
#[derive(Clone)]
pub struct TokenExchangeSession {
    /// Bearer access token for immediate Salesforce API calls.
    pub access_token: String,
    /// Refresh token, if the connected app + requested scopes caused one
    /// to be issued.
    pub refresh_token: Option<String>,
    /// OpenID Connect ID token, if `openid` was in the requested scopes.
    pub id_token: Option<String>,
    /// REST instance URL for subsequent API calls, normalized to carry no
    /// trailing slash — Salesforce's documented sample response includes
    /// one — so `{instance_url}/services/...` concatenation is always
    /// well-formed.
    pub instance_url: String,
    /// `issued_at` timestamp from the response (milliseconds-since-epoch as
    /// a string per Salesforce's wire format).
    pub issued_at: Option<String>,
    /// Granted scopes, space-separated.
    pub scope: Option<String>,
    /// Salesforce user-identity URL (e.g.
    /// `https://login.salesforce.com/id/{org_id}/{user_id}`). Distinct
    /// from `id_token` (which is OIDC-specific).
    pub id: Option<String>,
    /// Base64-encoded HMAC-SHA256 of the concatenated `id` and
    /// `issued_at` values, keyed on the connected-app consumer secret.
    /// Salesforce defines it as an integrity check on the identity URL in
    /// `id`; `access_token` and `instance_url` are not covered by it, so
    /// a valid signature says nothing about their provenance.
    pub signature: Option<String>,
}

// Tokens and the HMAC `signature` are secrets — redact in `{:?}`.
// `instance_url`, `id`, `issued_at`, and `scope` are non-secret.
impl std::fmt::Debug for TokenExchangeSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenExchangeSession")
            .field("access_token", &"[redacted]")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[redacted]"),
            )
            .field("id_token", &self.id_token.as_ref().map(|_| "[redacted]"))
            .field("instance_url", &self.instance_url)
            .field("issued_at", &self.issued_at)
            .field("scope", &self.scope)
            .field("id", &self.id)
            .field("signature", &self.signature.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

/// Builder for [`TokenExchangeFlow`].
#[derive(Default)]
pub struct TokenExchangeFlowBuilder {
    consumer_key: Option<String>,
    consumer_secret: Option<String>,
    login_url: Option<String>,
    subject_token: Option<String>,
    subject_token_type: Option<SubjectTokenType>,
    scopes: Vec<String>,
    token_handler: Option<String>,
    http_client: Option<reqwest::Client>,
}

impl std::fmt::Debug for TokenExchangeFlowBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenExchangeFlowBuilder")
            .field("consumer_key", &self.consumer_key.is_some())
            .field("consumer_secret", &self.consumer_secret.is_some())
            .field("login_url", &self.login_url)
            .field("subject_token", &self.subject_token.is_some())
            .field("subject_token_type", &self.subject_token_type)
            .field("scopes", &self.scopes)
            .field("token_handler", &self.token_handler)
            .finish_non_exhaustive()
    }
}

impl TokenExchangeFlowBuilder {
    /// Connected App's Consumer Key (Client ID). Required.
    pub fn consumer_key(mut self, key: impl Into<String>) -> Self {
        self.consumer_key = Some(key.into());
        self
    }

    /// Connected App's Consumer Secret. Send only when the connected app
    /// has `Require Secret for Token Exchange Flow` enabled (or
    /// `isSecretRequiredForTokenExchange = true` for an external client
    /// app). Public clients (mobile, SPA) should omit this.
    pub fn consumer_secret(mut self, secret: impl Into<String>) -> Self {
        self.consumer_secret = Some(secret.into());
        self
    }

    /// Login URL — the org's My Domain URL (or Experience Cloud site
    /// URL), which is what Salesforce's token-exchange examples address.
    /// Required, and must be `https` (loopback hosts excepted, for local
    /// test servers).
    pub fn login_url(mut self, url: impl Into<String>) -> Self {
        self.login_url = Some(url.into());
        self
    }

    /// The IdP-issued token to exchange. Required. Sent verbatim in the
    /// form body; no client-side length or format validation is applied,
    /// so a token the org rejects surfaces as an
    /// [`AuthError::OAuth`] from the endpoint.
    pub fn subject_token(mut self, token: impl Into<String>) -> Self {
        self.subject_token = Some(token.into());
        self
    }

    /// The type of the IdP token. Required.
    pub fn subject_token_type(mut self, ty: SubjectTokenType) -> Self {
        self.subject_token_type = Some(ty);
        self
    }

    /// Adds a scope. Multiple calls accumulate. The final set must be a
    /// subset of the connected app's assigned scopes.
    pub fn scope(mut self, scope: impl Into<String>) -> Self {
        self.scopes.push(scope.into());
        self
    }

    /// Replaces the entire scope set.
    pub fn scopes<I, S>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.scopes = scopes.into_iter().map(Into::into).collect();
        self
    }

    /// Apex token-exchange handler name. Strongly recommended per docs:
    /// without it, Salesforce uses the org's default handler (you must
    /// have at least one).
    pub fn token_handler(mut self, name: impl Into<String>) -> Self {
        self.token_handler = Some(name.into());
        self
    }

    /// Supplies a pre-configured `reqwest::Client` for the exchange.
    ///
    /// The client built by default applies connect and request timeouts
    /// and refuses to follow redirects, so a redirect cannot replay the
    /// IdP-issued `subject_token` to another host. A client supplied here
    /// replaces those defaults wholesale — configure both on it.
    pub fn http_client(mut self, client: reqwest::Client) -> Self {
        self.http_client = Some(client);
        self
    }

    /// Finalizes the builder.
    pub fn build(self) -> AuthResult<TokenExchangeFlow> {
        let consumer_key = self
            .consumer_key
            .ok_or(AuthError::MissingField("consumer_key"))?;
        let subject_token = self
            .subject_token
            .ok_or(AuthError::MissingField("subject_token"))?;
        let subject_token_type = self
            .subject_token_type
            .ok_or(AuthError::MissingField("subject_token_type"))?;
        let login_url = normalize_url(&self.login_url.ok_or(AuthError::MissingField("login_url"))?);
        require_secure_login_url(&login_url)?;
        let http = match self.http_client {
            Some(client) => client,
            None => default_http_client()?,
        };
        Ok(TokenExchangeFlow {
            consumer_key,
            consumer_secret: self.consumer_secret,
            login_url,
            subject_token,
            subject_token_type,
            scopes: self.scopes,
            token_handler: self.token_handler,
            http,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    /// Salesforce's documented token response shape for the grants that
    /// share this endpoint.
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
            "token_type": "Bearer",
        })
    }

    fn builder_with_required_fields() -> TokenExchangeFlowBuilder {
        TokenExchangeFlow::builder()
            .consumer_key("consumer-key-123")
            .login_url("https://my-org.my.salesforce.com")
            .subject_token("idp-issued-token-xyz")
            .subject_token_type(SubjectTokenType::AccessToken)
    }

    #[test]
    fn subject_token_type_urns_match_rfc_8693() {
        assert_eq!(
            SubjectTokenType::AccessToken.as_urn(),
            "urn:ietf:params:oauth:token-type:access_token"
        );
        assert_eq!(
            SubjectTokenType::RefreshToken.as_urn(),
            "urn:ietf:params:oauth:token-type:refresh_token"
        );
        assert_eq!(
            SubjectTokenType::IdToken.as_urn(),
            "urn:ietf:params:oauth:token-type:id_token"
        );
        assert_eq!(
            SubjectTokenType::Saml2.as_urn(),
            "urn:ietf:params:oauth:token-type:saml2"
        );
        assert_eq!(
            SubjectTokenType::Jwt.as_urn(),
            "urn:ietf:params:oauth:token-type:jwt"
        );
        assert_eq!(
            SubjectTokenType::Custom("urn:custom:foo".into()).as_urn(),
            "urn:custom:foo"
        );
    }

    #[test]
    fn grant_type_urn_matches_spec() {
        assert_eq!(
            GRANT_TYPE_TOKEN_EXCHANGE,
            "urn:ietf:params:oauth:grant-type:token-exchange"
        );
    }

    #[test]
    fn builder_requires_consumer_key() {
        let err = TokenExchangeFlow::builder()
            .login_url("https://x")
            .subject_token("t")
            .subject_token_type(SubjectTokenType::Jwt)
            .build()
            .unwrap_err();
        assert!(matches!(err, AuthError::MissingField("consumer_key")));
    }

    #[test]
    fn builder_requires_login_url() {
        let err = TokenExchangeFlow::builder()
            .consumer_key("k")
            .subject_token("t")
            .subject_token_type(SubjectTokenType::Jwt)
            .build()
            .unwrap_err();
        assert!(matches!(err, AuthError::MissingField("login_url")));
    }

    #[test]
    fn builder_requires_subject_token() {
        let err = TokenExchangeFlow::builder()
            .consumer_key("k")
            .login_url("https://x")
            .subject_token_type(SubjectTokenType::Jwt)
            .build()
            .unwrap_err();
        assert!(matches!(err, AuthError::MissingField("subject_token")));
    }

    #[test]
    fn builder_requires_subject_token_type() {
        let err = TokenExchangeFlow::builder()
            .consumer_key("k")
            .login_url("https://x")
            .subject_token("t")
            .build()
            .unwrap_err();
        assert!(matches!(err, AuthError::MissingField("subject_token_type")));
    }

    #[test]
    fn builder_strips_trailing_slashes_on_login_url() {
        let flow = builder_with_required_fields()
            .login_url("https://my-org.my.salesforce.com//")
            .build()
            .unwrap();
        assert_eq!(flow.login_url, "https://my-org.my.salesforce.com");
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
    async fn exchange_sends_required_params() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .and(body_string_contains(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange",
            ))
            .and(body_string_contains("subject_token=idp-issued-token-xyz"))
            .and(body_string_contains(
                "subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token",
            ))
            .and(body_string_contains("client_id=consumer-key-123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(documented_token_response()))
            .mount(&server)
            .await;

        let session = builder_with_required_fields()
            .login_url(server.uri())
            .build()
            .unwrap()
            .exchange()
            .await
            .unwrap();
        assert!(session.access_token.starts_with("00Dx0000000BV7z!"));
        // The documented body carries a trailing slash on instance_url;
        // the session exposes the normalized form.
        assert_eq!(session.instance_url, "https://yourInstance.salesforce.com");
        assert_eq!(session.issued_at.as_deref(), Some("1278448101416"));
        // Identity fields propagate through so federated-identity callers
        // can correlate the exchanged session with the original IdP user.
        assert_eq!(
            session.id.as_deref(),
            Some("https://login.salesforce.com/id/00Dx0000000BV7z/005x00000012Q9P")
        );
        assert_eq!(
            session.signature.as_deref(),
            Some("CMJ4l+CCaPQiKjoOEwEig9H4wqhpuLSk4J2urAe+fVg=")
        );
    }

    #[tokio::test]
    async fn exchange_includes_optional_params_when_set() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .and(body_string_contains("client_secret=hunter2"))
            .and(body_string_contains("scope=api+refresh_token"))
            .and(body_string_contains("token_handler=MyHandler"))
            .respond_with(ResponseTemplate::new(200).set_body_json({
                let mut body = documented_token_response();
                body["id_token"] = serde_json::Value::String("eyJ...".into());
                body["scope"] = serde_json::Value::String("api refresh_token".into());
                body
            }))
            .mount(&server)
            .await;

        let session = builder_with_required_fields()
            .login_url(server.uri())
            .consumer_secret("hunter2")
            .scope("api")
            .scope("refresh_token")
            .token_handler("MyHandler")
            .build()
            .unwrap()
            .exchange()
            .await
            .unwrap();
        assert_eq!(session.id_token.as_deref(), Some("eyJ..."));
        assert!(
            session
                .refresh_token
                .as_deref()
                .is_some_and(|t| t.starts_with("5Aep861"))
        );
        assert_eq!(session.scope.as_deref(), Some("api refresh_token"));
    }

    #[tokio::test]
    async fn public_client_omits_client_secret() {
        let server = MockServer::start().await;
        let captured = Arc::new(tokio::sync::Mutex::new(String::new()));
        let captured_clone = captured.clone();

        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .respond_with(BodyCapturingResponder {
                captured: captured_clone,
                response: ResponseTemplate::new(200).set_body_json(documented_token_response()),
            })
            .mount(&server)
            .await;

        builder_with_required_fields()
            .login_url(server.uri())
            .build()
            .unwrap()
            .exchange()
            .await
            .unwrap();

        let body = captured.lock().await;
        assert!(
            !body.contains("client_secret"),
            "public client should not send client_secret, got: {body}"
        );
    }

    #[tokio::test]
    async fn rejected_subject_token_surfaces_oauth_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "invalid_grant",
                "error_description": "subject_token validation failed"
            })))
            .mount(&server)
            .await;

        let err = builder_with_required_fields()
            .login_url(server.uri())
            .build()
            .unwrap()
            .exchange()
            .await
            .unwrap_err();
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
