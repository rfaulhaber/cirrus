# cirrus

An ergonomic Rust HTTP client for the Salesforce REST API.

This project is in no way affiliated with Salesforce.

`cirrus` is a strongly-typed, async-first client built on `reqwest` and
`tokio`. It covers the everyday surface of the Salesforce REST API — CRUD,
SOQL/SOSL, Bulk 2.0, composite, Tooling, Apex REST, Event Monitoring — plus a
small set of cross-cutting niceties (retry/backoff, auto-refresh on 401, a
streaming pagination iterator, conditional-request helpers, structured
`tracing` events) that you'd otherwise have to assemble by hand.

It also exposes an [open-ended escape hatch](#design-the-escape-hatch) so any
endpoint not yet typed is a one-liner away.

## Quick start

`cirrus` runs on the [tokio](https://tokio.rs) runtime — internal retry/backoff
sleeps and the auth-cache synchronization both rely on it. Add tokio alongside
`cirrus` so you get a runtime entrypoint (`#[tokio::main]`) and a scheduler:

```toml
[dependencies]
cirrus = "0.6.0"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

```rust,no_run
use cirrus::auth::StaticTokenAuth;
use cirrus::Cirrus;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Arc::new(StaticTokenAuth::new(
        std::env::var("SF_ACCESS_TOKEN")?,
        std::env::var("SF_INSTANCE_URL")?,
    ));
    let sf = Cirrus::builder().auth(auth).build()?;

    // SOQL
    let result = sf.query("SELECT Id, Name FROM Account LIMIT 5").await?;
    for record in result.records {
        println!("{}", record);
    }

    Ok(())
}
```

## Features

### REST surface

- **sObject CRUD** — `sf.sobject("Account").{create, retrieve, update, delete, upsert}`
  with typed and untyped variants. Multipart blob upload for `ContentVersion` /
  `Document` / `Attachment`.
- **SOQL** — `sf.query(...)`, `sf.query_all(...)`, `sf.query_more(...)`. Typed
  variants (`query_as::<T>(...)`) and a `futures::Stream` pagination iterator
  (`query_stream(...)`) that walks `nextRecordsUrl` locators transparently.
- **SOSL** — `sf.search(...)` and `sf.parameterized_search(...)`.
- **Composite** — all four shapes: `composite/batch`, `composite/tree`,
  `composite/sobjects` (collections), and the generic chained-reference
  `/composite` endpoint.
- **Bulk API 2.0** — ingest (`bulk().ingest()`) and query (`bulk().query()`)
  with the full lifecycle: `create`, `upload`, `close`, `abort`, `get`,
  `results` (with `Sforce-Locator` cursor pagination), raw CSV downloads.
- **Tooling API** — `tooling().{describe_global, sobject(name).*, query, search,
  execute_anonymous}`.
- **Apex REST** — thin passthrough for custom `/services/apexrest/...`
  endpoints.
- **Event Monitoring** — `event_monitoring().{download, download_url}` for
  binary `EventLogFile` CSV downloads.
- **Versions, limits, describe** — `sf.versions()`, `sf.limits()`,
  `sf.sobjects().describe_global()`, `sf.sobject(name).describe()`.

### Authentication

Five OAuth 2.0 flows + static-token mode, all behind a common `AuthSession`
trait so handlers don't care which flow you used.

- **JWT Bearer** (RFC 7523) — `auth::JwtAuth::builder()`
- **Refresh Token** (RFC 6749 §6) — `auth::RefreshTokenAuth::builder()`
- **Client Credentials** (RFC 6749 §4.4) —
  `auth::ClientCredentialsAuth::builder()`
- **Web Server with PKCE** (RFC 6749 §4.1 + RFC 7636) —
  `auth::WebServerFlow::builder()`
- **Token Exchange** (RFC 8693) — `auth::TokenExchangeFlow::builder()`
- **Static token** — `auth::StaticTokenAuth::new(token, instance_url)` for
  paste-from-`sf-org-display` workflows

Auto-refresh on 401: when an expired token surfaces, `JwtAuth`,
`RefreshTokenAuth`, and `ClientCredentialsAuth` invalidate their cache and
retry once with a fresh token, transparently. Compare-and-swap semantics avoid
clobbering a token a concurrent task just refreshed.

The flows live in the [`cirrus-auth`](../cirrus-auth/) sub-crate and are
re-exported as `cirrus::auth::*` — `cirrus = "0.6.0"` alone is enough; you
don't need to add `cirrus-auth` to your `Cargo.toml`. Auth errors come
back as `CirrusError::Auth(cirrus_auth::AuthError)`, so `?` works at the
boundary between auth and REST without extra plumbing.

### Cross-cutting

- **`CirrusError` is `#[non_exhaustive]`** — match the variants you handle and
  keep a `_` arm; a new variant in a later release stays an additive change.
- **Retry + backoff** — `RetryPolicy` covers 429, 503, and transient 5xx with
  full jitter; honors `Retry-After`. Configurable; off by default for non-idempotent 5xx.
- **Sforce-Limit-Info capture** — every response sent through the typed verb
  methods and handlers has its API quota header parsed and surfaced via
  `sf.last_limit_info()`. `request_builder` and `execute` step outside the
  request loop, so they don't advance it.
- **Pagination as `futures::Stream`** — composes with `StreamExt` from any
  async ecosystem, so the consumer API surface isn't tied to a specific
  combinator crate. Drop the stream → no further fetches. (Execution still
  runs on tokio, like the rest of the crate.)
- **Conditional requests** — `describe_*_if_modified_since(SystemTime)` returns
  `Option<T>`; `None` on 304 Not Modified.
- **Structured `tracing` events** — `cirrus::retry`, `cirrus::auth`,
  `cirrus::limit_info` targets. Never logs tokens or bodies.
- **Transport defaults** — the HTTP client the builder creates advertises
  gzip and decompresses responses, applies a 10 s connect timeout and a 120 s
  read timeout, and doesn't follow redirects — a 3xx surfaces as
  `CirrusError::Api` rather than re-sending the token to the `Location` host.
  The read timeout runs until the response head arrives, so it bounds the
  request-body upload and the org's processing time too, and only then becomes
  a per-chunk deadline; widen it with `CirrusBuilder::read_timeout` for large
  Bulk 2.0 / blob **uploads** and for calls the org takes a long time to
  answer. Supplying your own client via `CirrusBuilder::http_client` replaces
  all of it.

### The escape hatch

The Salesforce REST surface is too large to wrap every endpoint. The client
exposes verb methods that handle path resolution, auth, retry, and the
`Sforce-Limit-Info` capture for *any* endpoint:

```rust,ignore
sf.get::<MyShape>("limits").await?;                        // versioned
sf.post::<_, MyShape>("/services/apexrest/foo", &body).await?;  // instance-rooted
sf.get::<MyShape>("https://...").await?;                   // fully-qualified
```

Three-mode path resolution: relative → `/services/data/{version}/...`,
leading-`/` → instance-rooted, `http(s)://` → passthrough.
Whichever mode applies, the resolved target must be `https` (loopback hosts
excepted) because the request carries the org session token — a plaintext
target is rejected with `CirrusError::InvalidInput` and no request is sent,
and `Cirrus::builder().build()` fails outright on an `http://` instance URL.
`CirrusBuilder::allow_insecure_transport(true)` is the opt-out for a
deliberate plaintext hop, such as a recording proxy on a trusted network.

Salesforce request headers (`Sforce-Auto-Assign`, `Sforce-Call-Options`,
`Sforce-Query-Options`, …) go through `send_with_headers`, which keeps retry,
the 401 auto-refresh and the `Sforce-Limit-Info` capture:

```rust,ignore
let created: Value = sf
    .send_with_headers(
        Method::POST,
        "sobjects/Lead",
        None,
        &[("Sforce-Auto-Assign", "FALSE")],
        Some(&lead),
    )
    .await?;
```

For the remaining unusual cases (binary download, SSE), `request_builder` and
`execute` give you a pre-authenticated `reqwest::RequestBuilder` and a full
bypass respectively. Both step outside the request loop, so retry, the 401
auto-refresh and the limit-info capture don't apply to them.

## Examples

See the [`examples/`](examples/) directory:

- `simple_query.rs` — connect, run a SOQL query, print results
- `crud_cycle.rs` — full create → retrieve → update → delete on an `Account`
- `bulk_ingest.rs` — Bulk API 2.0 CSV ingest
- `streaming_pagination.rs` — iterate all records via `query_stream`
- `apex_passthrough.rs` — call a custom Apex REST endpoint

Run an example after setting the required env vars (any sandbox / Developer
Edition / scratch org):

```bash
export SF_INSTANCE_URL=https://my-org.develop.my.salesforce.com
export SF_ACCESS_TOKEN=00D...!AQ...   # from `sf org display`
cargo run --example simple_query
```

## Testing

```bash
cargo nextest run             # default unit + property + wiremock tests (no network)
cargo clippy --all-targets    # strict lints; deny set listed in Cargo.toml
cargo fmt                     # rustfmt
```

Integration tests against a real org are gated behind `#[ignore]` and an
opt-in env-var:

```bash
cp .env.example .env          # fill in your org URL + token
cargo nextest run --test integration --run-ignored only -j 1
```

The integration harness refuses to run unless the configured instance URL
matches a known sandbox / Developer Edition / scratch My Domain pattern. See
`tests/integration/common.rs` for details.

## License

Licensed under the MIT license.
