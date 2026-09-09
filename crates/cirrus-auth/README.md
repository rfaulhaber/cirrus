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
  paste-from-`sf-org-display` workflows or tests

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
error body), `InsecureLoginUrl`, `Signing`, `Randomness` — so no one has
to match on message text. It's `#[non_exhaustive]` so future variants
don't break downstream `match` arms.

## Transport defaults

When a flow builder isn't given an `http_client`, the client it builds
applies connect and request timeouts and refuses to follow redirects: the
grants here carry their credential in the request body, which reqwest
replays on a 307/308. Login URLs must be `https` (loopback hosts
excepted, for local test servers).

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
