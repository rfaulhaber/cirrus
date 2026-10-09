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
//! A [`TokenExchangeFlow`] holds the connected app's configuration and is
//! built once; each end user's token then goes through
//! [`TokenExchangeFlow::exchange`], so a back end that exchanges one IdP
//! token per request shares one HTTP client and connection pool across
//! them. The flow is `Clone`.
//!
//! ## Wire shape
//!
//! POST `/services/oauth2/token` with form body:
//!
//! - `grant_type` — `urn:ietf:params:oauth:grant-type:token-exchange`
//!   (the RFC 8693 URN) for most apps, or
//!   `urn:ietf:params:oauth:grant-type:hybrid-token-exchange` for hybrid
//!   mobile apps; see [`TokenExchangeGrantType`].
//! - `subject_token` — the IdP-issued token, at most
//!   [`MAX_SUBJECT_TOKEN_CHARS`] characters.
//! - `subject_token_type` — one of the five well-known URNs in
//!   [`SubjectTokenType`].
//! - `client_id` — connected app consumer key.
//! - `client_secret` — required when the connected app's "Require Secret
//!   for Token Exchange Flow" setting (`isSecretRequiredForTokenExchange`
//!   on an external client app) is on; Salesforce advises against
//!   sending it from a public client.
//! - `scope` — optional space-separated scopes, a subset of the app's.
//! - `token_handler` — optional Apex token-exchange-handler name. The
//!   docs strongly recommend setting it; otherwise Salesforce uses the
//!   org's default handler.
//!
//! The request takes the RFC 8693 grant and subject-token URNs and adds
//! Salesforce's `token_handler` parameter. The response is Salesforce's
//! ordinary token response rather than RFC 8693's: the documented sample
//! carries `access_token`, `signature`, `scope`, `id_token`,
//! `instance_url`, `id`, `token_type` and `issued_at`, no
//! `issued_token_type`, and can add the refresh tokens, ID tokens and
//! hybrid tokens the request asked for.
//!
//! ## My Domain URL is required
//!
//! The builder requires `login_url`: the request goes to the token
//! endpoint on the org's My Domain login URL or Experience Cloud site
//! URL, and there is no sensible default for an org-scoped host.
//!
//! (<https://help.salesforce.com/s/articleView?id=xcloud.remoteaccess_token_exchange_configure.htm&type=5>,
//! release 264. The connected-app side, `isTokenExchangeEnabled`,
//! `isSecretRequiredForTokenExchange` and the `OauthTokenExchangeHandler`
//! type, is in the Metadata API guide.)
//!
//! ## What you get back
//!
//! A [`TokenExchangeSession`] containing the Salesforce `access_token`,
//! `instance_url`, and (depending on the connected app's scopes and the
//! request) optional `refresh_token`, `id_token`, `scope`, `issued_at`.
//! If a `refresh_token` is returned, build a [`crate::RefreshTokenAuth`]
//! from it for ongoing API access, giving the builder the same
//! `login_url`, consumer key and secret this flow used; whether the
//! refresh grant needs the secret is a connected-app setting of its own,
//! see the [`refresh`](crate::refresh) module docs. A token the exchange
//! issued is revoked with [`TokenExchangeFlow::revoke`].

use crate::error::{AuthError, AuthResult};
use crate::token_endpoint::{
    GrantReplay, HttpClientConfig, exchange, normalize_url, require_secure_login_url, revoke_token,
};
use std::time::Duration;

/// RFC 8693 grant-type URN, the `grant_type` for most apps.
pub const GRANT_TYPE_TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

/// Salesforce's grant-type URN for hybrid mobile apps.
pub const GRANT_TYPE_HYBRID_TOKEN_EXCHANGE: &str =
    "urn:ietf:params:oauth:grant-type:hybrid-token-exchange";

/// Longest `subject_token` Salesforce accepts, in characters.
/// [`TokenExchangeFlow::exchange`] refuses a longer one before sending it.
pub const MAX_SUBJECT_TOKEN_CHARS: usize = 10_000;

/// The `grant_type` a [`TokenExchangeFlow`] sends. Salesforce documents
/// two: the RFC 8693 URN for most use cases, and a hybrid variant for
/// hybrid mobile apps, whose response can carry the hybrid tokens such an
/// app needs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum TokenExchangeGrantType {
    /// `urn:ietf:params:oauth:grant-type:token-exchange`, the default.
    #[default]
    TokenExchange,
    /// `urn:ietf:params:oauth:grant-type:hybrid-token-exchange`.
    HybridTokenExchange,
}

impl TokenExchangeGrantType {
    /// Returns the URN as it goes into the form body.
    pub fn as_urn(self) -> &'static str {
        match self {
            Self::TokenExchange => GRANT_TYPE_TOKEN_EXCHANGE,
            Self::HybridTokenExchange => GRANT_TYPE_HYBRID_TOKEN_EXCHANGE,
        }
    }
}

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

/// RFC 8693 token exchange for one connected app, reusable across end
/// users.
///
/// Construct via [`TokenExchangeFlow::builder`], then call
/// [`exchange`](Self::exchange) once per IdP-issued token. Cloning is
/// cheap: the HTTP client inside is shared.
#[derive(Clone)]
pub struct TokenExchangeFlow {
    consumer_key: String,
    consumer_secret: Option<String>,
    login_url: String,
    grant_type: TokenExchangeGrantType,
    scopes: Vec<String>,
    token_handler: Option<String>,
    http: reqwest::Client,
}

// `consumer_key` is a credential identifier and `consumer_secret` the
// confidential-client secret. Redact both.
impl std::fmt::Debug for TokenExchangeFlow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenExchangeFlow")
            .field("consumer_key", &"[redacted]")
            .field(
                "consumer_secret",
                &self.consumer_secret.as_ref().map(|_| "[redacted]"),
            )
            .field("login_url", &self.login_url)
            .field("grant_type", &self.grant_type)
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

    /// Revokes a token this flow's login host issued: a
    /// [`TokenExchangeSession`]'s refresh token, which revokes its access
    /// tokens with it, or an access token alone. Posts to
    /// `{login_url}/services/oauth2/revoke` with this flow's HTTP client;
    /// see [`revoke_token`] for the wire contract.
    pub async fn revoke(&self, token: &str) -> AuthResult<()> {
        revoke_token(&self.http, &self.login_url, token).await
    }

    /// Exchanges one IdP-issued token for a Salesforce session.
    ///
    /// `subject_token` is sent verbatim and must be at most
    /// [`MAX_SUBJECT_TOKEN_CHARS`] characters; a longer one is refused
    /// with [`AuthError::InvalidArgument`] before any request, since the
    /// org would answer only with an opaque `invalid_grant`. A token the
    /// org rejects for any other reason surfaces as [`AuthError::OAuth`]
    /// from the endpoint.
    ///
    /// The request is not re-sent once it has left the client: an
    /// exchange may issue tokens on every call, so an ambiguous failure
    /// such as a lost response or a 5xx is reported rather than retried,
    /// and only a connect failure is. Present a given IdP token once; its
    /// issuer may treat it as single-use.
    pub async fn exchange(
        &self,
        subject_token: &str,
        subject_token_type: SubjectTokenType,
    ) -> AuthResult<TokenExchangeSession> {
        let length = subject_token.chars().count();
        if length > MAX_SUBJECT_TOKEN_CHARS {
            return Err(AuthError::InvalidArgument {
                name: "subject_token",
                reason: format!(
                    "is {length} characters; Salesforce accepts at most {MAX_SUBJECT_TOKEN_CHARS}"
                ),
            });
        }
        let scope_joined;
        let mut body: Vec<(&str, &str)> = vec![
            ("grant_type", self.grant_type.as_urn()),
            ("subject_token", subject_token),
            ("subject_token_type", subject_token_type.as_urn()),
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

        let token = exchange(&self.http, &self.login_url, &body, GrantReplay::Never).await?;
        Ok(TokenExchangeSession {
            access_token: token.access_token,
            refresh_token: token.refresh_token,
            id_token: token.id_token,
            instance_url: normalize_url(&token.instance_url),
            issued_at: token.issued_at,
            scope: token.scope,
            id: token.id,
            signature: token.signature,
            sfdc_site_url: token.sfdc_site_url,
            sfdc_site_id: token.sfdc_site_id,
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
    /// Experience Cloud site URL, returned when the exchanged user is a
    /// member of a site. `None` for a direct org login.
    pub sfdc_site_url: Option<String>,
    /// Experience Cloud site ID for the same case. Some Connect REST
    /// requests need it, and nothing else in the response carries it.
    pub sfdc_site_id: Option<String>,
}

// Tokens and the HMAC `signature` are secrets — redact in `{:?}`.
// `instance_url`, `id`, `issued_at`, `scope` and the site fields are
// non-secret.
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
            .field("sfdc_site_url", &self.sfdc_site_url)
            .field("sfdc_site_id", &self.sfdc_site_id)
            .finish()
    }
}

/// Builder for [`TokenExchangeFlow`].
#[derive(Default)]
pub struct TokenExchangeFlowBuilder {
    consumer_key: Option<String>,
    consumer_secret: Option<String>,
    login_url: Option<String>,
    grant_type: TokenExchangeGrantType,
    scopes: Vec<String>,
    token_handler: Option<String>,
    http: HttpClientConfig,
}

impl std::fmt::Debug for TokenExchangeFlowBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenExchangeFlowBuilder")
            .field("consumer_key", &self.consumer_key.is_some())
            .field("consumer_secret", &self.consumer_secret.is_some())
            .field("login_url", &self.login_url)
            .field("grant_type", &self.grant_type)
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

    /// The `grant_type` to send. Defaults to
    /// [`TokenExchangeGrantType::TokenExchange`]; a hybrid mobile app sets
    /// [`HybridTokenExchange`](TokenExchangeGrantType::HybridTokenExchange).
    pub fn grant_type(mut self, grant_type: TokenExchangeGrantType) -> Self {
        self.grant_type = grant_type;
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
    /// replaces those defaults wholesale, the timeout setters included;
    /// start from [`token_client_builder`](crate::token_client_builder) to
    /// keep them while adding settings.
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
    pub fn build(self) -> AuthResult<TokenExchangeFlow> {
        let consumer_key = self
            .consumer_key
            .ok_or(AuthError::MissingField("consumer_key"))?;
        let login_url = normalize_url(&self.login_url.ok_or(AuthError::MissingField("login_url"))?);
        require_secure_login_url(&login_url)?;
        let http = self.http.into_client()?;
        Ok(TokenExchangeFlow {
            consumer_key,
            consumer_secret: self.consumer_secret,
            login_url,
            grant_type: self.grant_type,
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

    /// Salesforce's documented token-exchange response.
    ///
    /// SOURCE: https://help.salesforce.com/s/articleView?id=xcloud.remoteaccess_token_exchange_configure.htm&type=5
    /// (release 264), step 12 "App Receives Response" — field values
    /// copied from the page's sample, which masks the access token. The
    /// sample carries no `refresh_token` and no RFC 8693
    /// `issued_token_type`.
    fn documented_token_response() -> serde_json::Value {
        serde_json::json!({
            "access_token": "*******************",
            "signature": "ts6wm/svX3jXlCGR4uu+SbA04M6qhD1SAgVTEwZ59P4=",
            "scope": "openid api",
            "id_token": "XXXXXX",
            "instance_url": "https://MyDomainName.my.salesforce.com",
            "id": "https://MyDomainName.my.salesforce.com/id/00Dxxxxxxxxxxxx/005xxxxxxxxxxxx",
            "token_type": "Bearer",
            "issued_at": "1667600739962",
        })
    }

    fn builder_with_required_fields() -> TokenExchangeFlowBuilder {
        TokenExchangeFlow::builder()
            .consumer_key("consumer-key-123")
            .login_url("https://my-org.my.salesforce.com")
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
    fn grant_type_urns_match_the_setup_page() {
        // SOURCE: https://help.salesforce.com/s/articleView?id=xcloud.remoteaccess_token_exchange_configure.htm&type=5
        // (release 264): "For most use cases, use
        // urn:ietf:params:oauth:grant-type:token-exchange. For hybrid
        // mobile apps, use urn:ietf:params:oauth:grant-type:hybrid-token-exchange."
        assert_eq!(
            GRANT_TYPE_TOKEN_EXCHANGE,
            "urn:ietf:params:oauth:grant-type:token-exchange"
        );
        assert_eq!(
            GRANT_TYPE_HYBRID_TOKEN_EXCHANGE,
            "urn:ietf:params:oauth:grant-type:hybrid-token-exchange"
        );
        assert_eq!(
            TokenExchangeGrantType::TokenExchange.as_urn(),
            GRANT_TYPE_TOKEN_EXCHANGE
        );
        assert_eq!(
            TokenExchangeGrantType::HybridTokenExchange.as_urn(),
            GRANT_TYPE_HYBRID_TOKEN_EXCHANGE
        );
        assert_eq!(
            TokenExchangeGrantType::default(),
            TokenExchangeGrantType::TokenExchange
        );
    }

    #[test]
    fn builder_requires_consumer_key() {
        let err = TokenExchangeFlow::builder()
            .login_url("https://x")
            .build()
            .unwrap_err();
        assert!(matches!(err, AuthError::MissingField("consumer_key")));
    }

    #[test]
    fn builder_requires_login_url() {
        let err = TokenExchangeFlow::builder()
            .consumer_key("k")
            .build()
            .unwrap_err();
        assert!(matches!(err, AuthError::MissingField("login_url")));
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
    async fn revoke_posts_the_token_to_the_flows_login_url() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/services/oauth2/revoke"))
            .and(body_string_contains("token=5Aep861KIwKdekr...refresh"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        let flow = builder_with_required_fields()
            .login_url(server.uri())
            .build()
            .unwrap();
        flow.revoke("5Aep861KIwKdekr...refresh").await.unwrap();
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
            .exchange("idp-issued-token-xyz", SubjectTokenType::AccessToken)
            .await
            .unwrap();
        assert_eq!(session.access_token, "*******************");
        assert_eq!(
            session.instance_url,
            "https://MyDomainName.my.salesforce.com"
        );
        assert_eq!(session.issued_at.as_deref(), Some("1667600739962"));
        assert_eq!(session.scope.as_deref(), Some("openid api"));
        assert_eq!(session.id_token.as_deref(), Some("XXXXXX"));
        // Identity fields propagate through so federated-identity callers
        // can correlate the exchanged session with the original IdP user.
        assert_eq!(
            session.id.as_deref(),
            Some("https://MyDomainName.my.salesforce.com/id/00Dxxxxxxxxxxxx/005xxxxxxxxxxxx")
        );
        assert_eq!(
            session.signature.as_deref(),
            Some("ts6wm/svX3jXlCGR4uu+SbA04M6qhD1SAgVTEwZ59P4=")
        );
        // The documented sample carries no refresh token and is a non-site
        // login.
        assert_eq!(session.refresh_token, None);
        assert_eq!(session.sfdc_site_url, None);
        assert_eq!(session.sfdc_site_id, None);
    }

    #[tokio::test]
    async fn one_flow_exchanges_many_subject_tokens() {
        // The app configuration is per flow and the IdP token per call, so
        // a portal back end builds the flow, and its HTTP client, once.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(documented_token_response()))
            .expect(2)
            .mount(&server)
            .await;
        let flow = builder_with_required_fields()
            .login_url(server.uri())
            .build()
            .unwrap();

        flow.exchange("first-idp-token", SubjectTokenType::AccessToken)
            .await
            .unwrap();
        flow.clone()
            .exchange("second-idp-token", SubjectTokenType::Jwt)
            .await
            .unwrap();

        let bodies: Vec<String> = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|request| String::from_utf8_lossy(&request.body).into_owned())
            .collect();
        assert!(
            bodies[0].contains("subject_token=first-idp-token"),
            "{bodies:?}"
        );
        assert!(
            bodies[1].contains("subject_token=second-idp-token")
                && bodies[1].contains("token-type%3Ajwt"),
            "{bodies:?}"
        );
    }

    #[tokio::test]
    async fn the_hybrid_grant_type_is_sent_when_configured() {
        // SOURCE: https://help.salesforce.com/s/articleView?id=xcloud.remoteaccess_token_exchange_configure.htm&type=5
        // (release 264): "For hybrid mobile apps, use
        // urn:ietf:params:oauth:grant-type:hybrid-token-exchange."
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .and(body_string_contains(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ahybrid-token-exchange",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(documented_token_response()))
            .expect(1)
            .mount(&server)
            .await;
        builder_with_required_fields()
            .login_url(server.uri())
            .grant_type(TokenExchangeGrantType::HybridTokenExchange)
            .build()
            .unwrap()
            .exchange("idp-issued-token-xyz", SubjectTokenType::AccessToken)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn an_oversized_subject_token_is_refused_before_any_request() {
        // SOURCE: the same page, `subject_token`: "The maximum length is
        // 10,000 characters." A token at the limit is sent; one over it is
        // refused without a request, since the org would only answer with
        // an opaque invalid_grant.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(documented_token_response()))
            .mount(&server)
            .await;
        let flow = builder_with_required_fields()
            .login_url(server.uri())
            .build()
            .unwrap();

        let err = flow
            .exchange(
                &"é".repeat(MAX_SUBJECT_TOKEN_CHARS + 1),
                SubjectTokenType::Jwt,
            )
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                AuthError::InvalidArgument {
                    name: "subject_token",
                    ..
                }
            ),
            "{err:?}"
        );
        assert!(server.received_requests().await.unwrap().is_empty());

        flow.exchange(&"é".repeat(MAX_SUBJECT_TOKEN_CHARS), SubjectTokenType::Jwt)
            .await
            .unwrap();
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn exchange_surfaces_the_experience_cloud_site_fields() {
        // SOURCE: https://help.salesforce.com/s/articleView?id=xcloud.remoteaccess_oauth_web_server_flow.htm
        // and https://help.salesforce.com/s/articleView?id=xcloud.remoteaccess_oauth_refresh_token_flow.htm
        // (release 264) list `sfdc_site_url` and `sfdc_site_id` in the
        // token response for a site member. The token-exchange page does
        // not repeat the response table; the response parser is shared
        // across grants, so an exchange that returns them must surface
        // them rather than drop them.
        let server = MockServer::start().await;
        let mut body = documented_token_response();
        body["sfdc_site_url"] = serde_json::Value::String("https://acme.my.site.com/portal".into());
        body["sfdc_site_id"] = serde_json::Value::String("0DB5e000000TN1aGAG".into());
        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;

        let session = builder_with_required_fields()
            .login_url(server.uri())
            .build()
            .unwrap()
            .exchange("idp-issued-token-xyz", SubjectTokenType::AccessToken)
            .await
            .unwrap();

        assert_eq!(
            session.sfdc_site_url.as_deref(),
            Some("https://acme.my.site.com/portal")
        );
        assert_eq!(session.sfdc_site_id.as_deref(), Some("0DB5e000000TN1aGAG"));
        let debug = format!("{session:?}");
        assert!(debug.contains("0DB5e000000TN1aGAG"), "{debug}");
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
                // Step 11 of the setup page: the response carries "any
                // other tokens or parameters that you've requested,
                // including refresh tokens".
                let mut body = documented_token_response();
                body["refresh_token"] =
                    serde_json::Value::String("5Aep861KIwKdekr...refresh".into());
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
            .exchange("idp-issued-token-xyz", SubjectTokenType::AccessToken)
            .await
            .unwrap();
        assert_eq!(
            session.refresh_token.as_deref(),
            Some("5Aep861KIwKdekr...refresh")
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
            .exchange("idp-issued-token-xyz", SubjectTokenType::AccessToken)
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
            .exchange("idp-issued-token-xyz", SubjectTokenType::AccessToken)
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
