# cirrus-auth

Salesforce OAuth 2.0 authentication flows for the Cirrus SDK.

API reference: [docs.rs/cirrus-auth](https://docs.rs/cirrus-auth)

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
- **Token Exchange** (RFC 8693) — `TokenExchangeFlow::builder()`, built
  once per connected app and reused: `exchange(subject_token, type)` takes
  each IdP token, `TokenExchangeGrantType::HybridTokenExchange` selects the
  grant Salesforce documents for hybrid mobile apps, and a `subject_token`
  over 10,000 characters is refused before any request
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

The `async_trait` macro is re-exported, so a session that obtains its
token elsewhere (a secrets manager, a sidecar, a test double) implements
the trait under `#[cirrus_auth::async_trait]` with no dependency of its
own; the trait's docs carry a compiled example.

## Web Server flow

`WebServerFlow` drives both halves of the interactive flow and holds the
connected app's credentials throughout:

```rust,ignore
let flow = WebServerFlow::builder()
    .consumer_key("3MVG9...")
    .consumer_secret("28A2...")   // required unless the app waives it
    .redirect_uri("https://app.example.com/oauth/callback")
    .scope("api")
    .scope("refresh_token")
    .build()?;

// Phase 1 — redirect the user to `url`, persist `pending`.
let (url, pending) = flow.start()?;

// Phase 2 — on callback, with `pending` restored from your store.
let session = flow.complete(pending, &code, &state).await?;

// Keep the session renewable: the builder inherits this flow's login URL,
// key, secret and HTTP client, and starts with the access token just issued.
let auth = flow.refresh_auth(&session)?.build()?;
```

Salesforce requires `client_secret` on the code exchange and again on the
refresh grant unless the app's "Require Secret for Web Server Flow" and
"Require Secret for Refresh Token Flow" settings are turned off; both are
on by default and independent, and PKCE does not stand in for either. A
host that must not hold the secret sets `private_key_pem_bytes` (or
`private_key_pem_file`) instead, with the private key behind the app's
uploaded certificate: both requests then carry a freshly signed RS256
`client_assertion` and no `client_secret`. The same two setters exist on
`RefreshTokenAuthBuilder`. Because Salesforce ignores the assertion when
a secret is present, a builder given both fails with
`AuthError::InvalidArgument`.

When a secret is set, these flows and `ClientCredentialsAuth` send it with
the consumer key in an `Authorization: Basic` header rather than the form
body, as Salesforce documents for each of them; a public client sends
`client_id` in the body and no header.

## Signing out

`RefreshTokenAuth::revoke` posts the session's live refresh token — under
Refresh Token Rotation, the replacement adopted last, which nothing else
holds — to `/services/oauth2/revoke`, which revokes every access token
issued through it, and clears the local cache; drop the session
afterwards. `WebServerFlow::revoke` and `TokenExchangeFlow::revoke`
revoke a token their login host issued with the flow's own client, and
`revoke_token(&client, login_url, token)` does the same for a token held
elsewhere. Salesforce answers 200 on success and 400 with
`unsupported_token_type` or `invalid_token` otherwise, surfaced as
`AuthError::OAuth`; the request is sent once.

`start_with(&AuthorizeOptions)` adds the parameters that vary per attempt:
`login_hint`, `prompt`, `display`, `immediate`, `sso_provider`, any extra
pair, and a `nonce` (supplied or generated) that comes back on
`CompletedSession::nonce` for checking the ID token's claim.

`PendingExchange` carries only the per-attempt PKCE verifier and CSRF
nonce, plus a digest of the flow configuration that issued it — never the
consumer key or secret. The verifier is still a secret: keep it in a
server-side session or an encrypted cookie, not a merely signed one. A
pending is single-use: take it out of the store, keyed by its state,
before calling `complete`, so a callback hit twice finds nothing instead
of presenting the redeemed code again. Both phases must run on a flow with
the same consumer key, redirect URI and login URL; `complete` checks the
digest and fails with `FlowMismatch` before any request when they differ.

## Errors

`AuthError` (re-exported by `cirrus` as `cirrus::AuthError`) covers OAuth
token-endpoint errors, missing or unusable builder fields, transport
failures, and malformed responses. Failures a caller usually wants to
branch on have their own variants — `StateMismatch` (a forged or crossed
callback), `FlowMismatch` (a pending completed on a differently configured
flow), `InstanceUrlMismatch` (wrong org), `UnexpectedResponse` (a non-OAuth
error body), `InvalidArgument` (a value a flow cannot use: the shared
login hosts on the client-credentials builder, a PEM that holds no private
key, a secret alongside a client-assertion key, an oversized
`subject_token`), `InsecureLoginUrl`, `Signing`, `Randomness`,
`HttpClient` (a client that could not be built, as distinct from `Http`, a
request that failed) — so no one has to match on message text. `OAuth`
prints Salesforce's `error_description` after the code, so an
`invalid_grant` says which of the dozen documented causes it was; before
the description is stored, every non-public value the failing request sent
(secret, token, assertion, consumer key) is replaced with `[redacted]` and
the text is capped at 256 characters. Variants that wrap another error
expose it through `source()` and don't repeat it in `Display`; print the
chain (anyhow's `{:#}`) to see the cause. It's `#[non_exhaustive]` so
future variants don't break downstream `match` arms.

## Cargo features

The TLS backend is a feature, under reqwest's names, and `rustls` is the
default, so a manifest that names no features builds as it always has.

| Feature | Effect |
|---|---|
| `rustls` (default) | rustls with the aws-lc-rs crypto provider, verifying against the operating system's trust store through `rustls-platform-verifier`. |
| `rustls-no-provider` | rustls with the crypto provider left to the application, which calls `rustls::crypto::CryptoProvider::install_default` before building a client; reqwest panics at construction otherwise. For a process that standardizes on `ring` or a FIPS provider. |
| `native-tls` | The operating system's TLS stack: OpenSSL on Linux, Secure Transport on macOS, SChannel on Windows. |
| `native-tls-vendored` | `native-tls` with OpenSSL built from source, for a static or cross-compiled binary. |
| `bundled-roots` | Merges Mozilla's root set (`webpki-root-certs`) into the trust store of every client this crate builds, alongside the platform's, so a host with no system CA bundle can still build one. Presumes a backend. |

Pick a backend other than the default with `default-features = false`:

```toml
[dependencies]
cirrus-auth = { version = "0.4.2", default-features = false, features = ["native-tls"] }
```

Enabling both backends is allowed and makes reqwest default to `native-tls`.
The features only forward to reqwest, so they unify across the whole build
the way reqwest's own do: a dependency that enables `reqwest/rustls` for
itself brings aws-lc-rs back whatever this crate was told. `rustls-no-provider`
changes which provider TLS uses, not whether aws-lc-rs compiles; JWT
assertions are signed with it regardless (see
[Crypto backend](#crypto-backend)).

The crate re-exports `reqwest` with the features it uses itself: `gzip`,
`system-proxy`, `form` and the chosen backend. Code that reaches
`RequestBuilder::json`, `query` or `multipart` through `cirrus_auth::reqwest`
adds reqwest with those features to its own manifest.

## Transport defaults

When a flow builder isn't given an `http_client`, the client it builds
applies a 10 s connect timeout and a 30 s request deadline
(`DEFAULT_TOKEN_CONNECT_TIMEOUT` and `DEFAULT_TOKEN_REQUEST_TIMEOUT`; every
builder has `connect_timeout` and `request_timeout` setters) and refuses to
follow redirects: the grants here carry their credential in the request
body, which reqwest replays on a 307/308. TLS is verified against the
operating system's trust store, which the client loads when the flow is
built: a `FROM scratch` or distroless image without `ca-certificates` fails
at `build()` with `AuthError::HttpClient`. Install a CA bundle, enable the
`bundled-roots` feature (see [Cargo features](#cargo-features)) or add the
roots yourself. `token_client_builder()` returns a `reqwest::ClientBuilder`
with the same settings, for adding a private root CA, a proxy or a shared
connection pool without losing them. The client uses no proxy: `HTTP_PROXY`,
`HTTPS_PROXY`, `ALL_PROXY` and the system proxy are ignored, where a stock
`reqwest::Client` obeys them, so a deployment that needs one adds it with
`token_client_builder().proxy(..)`. Login URLs must be `https`; exact
`localhost` and the loopback literals are excepted for local test servers,
which the no-proxy default is what keeps on the machine, and `*.localhost`
names are not. The same rule, `cirrus_auth::transport::is_secure_transport`
(and `is_secure_transport_for`, which withdraws the loopback exemption for a
client that routes through a proxy), governs instance URLs in `cirrus` and
`cirrus-metadata`.

A token-endpoint response body is read through
`cirrus_auth::transport::collect_body`, which stops at 64 KiB of decoded
bytes: a real token response is a few kilobytes, and the client decodes
gzip, so a body that does not fit came from an intermediary and fails with
`AuthError::ResponseTooLarge` without being buffered (an oversized 429 or
5xx is retried first, exactly like the status alone). `collect_body` is
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
`decode`. For the same reason aws-lc-rs stays in the build under the
`rustls-no-provider` feature: that feature decides which crypto provider TLS
uses, and the signing here uses aws-lc-rs regardless.

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

`private_key_pem_file` takes a `camino::Utf8PathBuf` or anything that
converts into one; `camino` is re-exported as `cirrus_auth::camino`, and a
`std::path::PathBuf` converts with `Utf8PathBuf::try_from`. Both PEM
setters read the first block and refuse anything but an `RSA PRIVATE KEY`
or `PRIVATE KEY`, naming what they found, so passing `server.crt` in place
of `server.key` fails at build time rather than at the first token
request.

## License

Licensed under the MIT license.
