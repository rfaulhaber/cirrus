# cirrus-auth

Salesforce OAuth 2.0 authentication flows for the Cirrus SDK.

This project is in no way affiliated with Salesforce.

`cirrus-auth` ships the authentication layer for the
[`cirrus`](../cirrus/) family of Salesforce SDK crates. It defines the
`AuthSession` trait that every flow implements, plus the concrete flows
themselves.

## Are you a `cirrus` user?

You probably don't need to depend on this crate directly. `cirrus`
re-exports its entire surface as `cirrus::auth::*`, so

```rust,ignore
use cirrus::auth::{JwtAuth, StaticTokenAuth};
```

works without an explicit `cirrus-auth` dependency. Use this crate
directly only if you're writing another Cirrus sibling crate (e.g.
`cirrus-metadata`) that needs an authenticated session but not the full
REST client.

## Flows

- **JWT Bearer** (RFC 7523) — `JwtAuth::builder()`
- **Refresh Token** (RFC 6749 §6) — `RefreshTokenAuth::builder()`
- **Client Credentials** (RFC 6749 §4.4) — `ClientCredentialsAuth::builder()`
- **Web Server with PKCE** (RFC 6749 §4.1 + RFC 7636) — `WebServerFlow::builder()`
- **Token Exchange** (RFC 8693) — `TokenExchangeFlow::builder()`
- **Static token** — `StaticTokenAuth::new(token, instance_url)` for
  paste-from-`sf-org-display` workflows or tests; surrounding whitespace on
  the token is trimmed

Flows Salesforce labels legacy or deprecated (username-password OAuth,
SOAP login, etc.) are intentionally not supported.

## `AuthSession`

Every flow implements the same async trait:

```rust,ignore
#[async_trait]
pub trait AuthSession: Send + Sync {
    async fn access_token(&self) -> AuthResult<Cow<'_, str>>;
    fn instance_url(&self) -> &str;
    async fn invalidate(&self, stale_token: &str) { /* default no-op */ }
}
```

Stateful flows (`JwtAuth`, `RefreshTokenAuth`, `ClientCredentialsAuth`)
cache their access token and refresh on demand. `invalidate` uses
compare-and-swap so two concurrent tasks can't clobber each other's
freshly minted tokens. Static and stateless sessions inherit the no-op
default.

`SharedAuth` is a convenience alias for `Arc<dyn AuthSession>` — the
shape the Cirrus client stores.

## Web Server flow

`WebServerFlow` drives both halves of the interactive flow and holds the
connected app's credentials throughout:

```rust,ignore
let flow = WebServerFlow::builder()
    .consumer_key("3MVG9...")
    .consumer_secret("28A2...")   // confidential clients only
    .redirect_uri("https://app.example.com/oauth/callback")
    .scope("api")
    .scope("refresh_token")
    .build()?;

// Phase 1 — redirect the user to `url`, persist `pending`.
let (url, pending) = flow.start()?;

// Phase 2 — on callback, with `pending` restored from your store.
let session = flow.complete(pending, &code, &state).await?;
```

`PendingExchange` carries only the per-attempt PKCE verifier and CSRF
nonce — never the consumer key or secret. The verifier is still a secret:
keep it in a server-side session or an encrypted cookie, not a merely
signed one.

## Errors

`AuthError` (re-exported by `cirrus` as `cirrus::AuthError`) covers OAuth
token-endpoint errors, missing builder fields, transport failures, and
malformed responses. Failures a caller usually wants to branch on have
their own variants — `StateMismatch` (a forged or replayed callback),
`InstanceUrlMismatch` (wrong org), `UnexpectedResponse` (a non-OAuth
error body), `InsecureLoginUrl`, `Signing`, `Randomness`, `HttpClient` (a
client that could not be built, as distinct from `Http`, a request that
failed) — so no one has to match on message text. Variants that wrap
another error expose it through `source()` and don't repeat it in
`Display`; print the chain (anyhow's `{:#}`) to see the cause. It's
`#[non_exhaustive]` so future variants don't break downstream `match` arms.

## Transport defaults

When a flow builder isn't given an `http_client`, the client it builds
applies a 10 s connect timeout and a 30 s request deadline
(`DEFAULT_TOKEN_CONNECT_TIMEOUT` and `DEFAULT_TOKEN_REQUEST_TIMEOUT`; every
builder has `connect_timeout` and `request_timeout` setters) and refuses to
follow redirects: the grants here carry their credential in the request
body, which reqwest replays on a 307/308. TLS is verified against the
operating system's trust store, which the client loads when the flow is
built: a `FROM scratch` or distroless image without `ca-certificates` fails
at `build()` with `AuthError::HttpClient`, so install a CA bundle or add the
roots yourself. `token_client_builder()` returns a `reqwest::ClientBuilder`
with the same settings, for adding a private root CA, a proxy or a shared
connection pool without losing them. Login URLs must be `https`; exact
`localhost` and the
loopback literals are excepted for local test servers, and `*.localhost`
names are not. The same rule, `cirrus_auth::transport::is_secure_transport`,
governs instance URLs in `cirrus` and `cirrus-metadata`.

A token-endpoint response body is read through
`cirrus_auth::transport::collect_body`, which stops at 64 KiB of decoded
bytes: a real token response is a few kilobytes, and the client decodes
gzip, so a body that does not fit came from an intermediary and fails with
`AuthError::ResponseTooLarge` without being buffered. `collect_body` is
public so other clients can bound their own response reads the same way.

Token requests are retried a bounded number of times (two retries, 250 ms
then 500 ms apart). A connect failure retries for every grant. A 429, a 5xx
and a lost response retry only for the JWT bearer and client-credentials
grants, which have no side effect to duplicate; the refresh, authorization
code and token-exchange grants are never re-sent once the request has left
the client, because the answer that was lost may have rotated or consumed
the credential.

## Token caching

`JwtAuth`, `ClientCredentialsAuth` and `RefreshTokenAuth` cache the access
token and mint single-flight: callers that arrive while a mint is in flight
share its outcome, success or failure, so one slow or failing token
endpoint costs one grant per window rather than one per caller. When a
proactive refresh inside the 60 s expiry margin fails transiently, the
still-valid cached token is returned with a warning; an OAuth error such as
`invalid_grant` is never masked. `AuthError::is_transient` is the same
classification, exposed for callers.

## Logging

Events are emitted under three `tracing` targets: `cirrus_auth::mint`
(token caching, minting and compare-and-swap invalidation),
`cirrus_auth::token_endpoint` (the HTTP exchange, retries included) and
`cirrus_auth::rotation` (adopting a rotated refresh token). A filter such
as `RUST_LOG=cirrus_auth=debug` covers all three. No event carries a
token, a credential or a response body; a non-OAuth error body from the
token endpoint is recorded only as its status, content type and length,
at `TRACE`.

## Crypto backend

JWT assertions are signed through jsonwebtoken's aws-lc-rs backend directly
rather than its process-global crypto provider. A build that also enables
jsonwebtoken's `rust_crypto` feature for its own purposes therefore does not
affect token minting here, although jsonwebtoken itself requires exactly one
backend or an explicitly installed provider for its own `encode` and
`decode`.

`cirrus` carries a `From<AuthError> for CirrusError` impl, so REST call
sites that need an auth token can use `?` and surface the failure as
`CirrusError::Auth(AuthError)` without extra plumbing.

## Example

```rust,no_run
use cirrus_auth::{AuthSession, JwtAuth};
use std::sync::Arc;

# fn example() -> Result<(), cirrus_auth::AuthError> {
let auth = JwtAuth::builder()
    .consumer_key("3MVG9...")
    .username("integration-user@example.com")
    .login_url("https://login.salesforce.com")
    .instance_url("https://my-org.my.salesforce.com")
    .private_key_pem_file("./private.pem")?
    .build()?;

let shared: Arc<dyn AuthSession> = Arc::new(auth);
# let _ = shared;
# Ok(())
# }
```

Hand `shared` to `cirrus::Cirrus::builder().auth(shared)` to build a REST
client, or to any other crate that consumes `Arc<dyn AuthSession>`.

## License

Licensed under the MIT license.
