# cirrus-metadata

Salesforce Metadata API (SOAP) client for the Cirrus SDK.

API reference: [docs.rs/cirrus-metadata](https://docs.rs/cirrus-metadata)

This project is in no way affiliated with Salesforce.

`cirrus-metadata` is the SOAP-Metadata-API sibling of
[`cirrus`](../cirrus/) (REST) and [`cirrus-auth`](../cirrus-auth/) (OAuth).
It covers the surfaces that don't exist in the Metadata REST API: file-based
`retrieve`, the CRUD-Based Calls (`createMetadata` / `readMetadata` /
`updateMetadata` / `upsertMetadata` / `deleteMetadata` / `renameMetadata`),
and the utility surface (`listMetadata`, `describeMetadata`,
`describeValueType`).

## Why a SOAP crate in 2026?

Salesforce's Metadata *REST* API only covers four `deployRequest`
endpoints (initiate, status, cancel, quick-deploy). Everything else —
including `retrieve` itself — is SOAP-only and is not deprecated. If you
already have `cirrus` and only need to ship a `.zip` to an org,
`Cirrus::metadata()` (REST) is enough. Reach for `cirrus-metadata` when
you need anything beyond `deployRequest`.

## Relationship to `cirrus` and `cirrus-auth`

- Depends only on `cirrus-auth` — no `cirrus` dependency, so callers that
  use the SOAP API but not the REST client don't pull in the REST surface.
- Re-exports the auth crate as `cirrus_metadata::auth::*`, so a stand-alone
  `cirrus-metadata` user can write `use cirrus_metadata::auth::JwtAuth;`
  without an explicit `cirrus-auth` line in `Cargo.toml`.
- Shares the `AuthSession` trait with `cirrus`: one `Arc<dyn AuthSession>`
  drives both clients side-by-side.

## What's covered

- **File-based deploy/retrieve** — `deploy`, `check_deploy_status`,
  `cancel_deploy`, `deploy_recent_validation`, `retrieve`,
  `check_retrieve_status`, plus `wait_for_deploy` / `wait_for_retrieve`
  polling helpers with configurable timeout and backoff. The helpers
  return every terminal state as `Ok`, a failed job included;
  `DeployResult::into_result` / `RetrieveResult::into_result` turn one
  into `MetadataError::DeployFailed` / `RetrieveFailed` for `?`.
  `wait_for_retrieve_done` polls without the one-shot zip fetch, for a
  wait that has to stay cancellable.
- **CRUD-based calls** — `create_metadata`, `read_metadata`,
  `update_metadata`, `upsert_metadata`, `delete_metadata`,
  `rename_metadata`. Up to 10 components per call, per the Metadata API
  contract; `create_metadata`, `update_metadata`, `read_metadata` and
  `delete_metadata` raise that to 200 for `CustomMetadata` and
  `CustomApplication`, while `upsert_metadata` is a flat 10 for every
  type. The type name is a `&str` or a `MetadataType`, and the envelope
  binds `xsi` and `xsd`, so values typed `xsi:type="xsd:boolean"` paste
  straight from a `-meta.xml` file.
- **Utility** — `list_metadata`, `describe_metadata`, `describe_value_type`.
- **Typed `package.xml`** — `PackageManifest` builder with round-trippable
  XML serialization. `MetadataType` carries constants for the common
  types, converts from borrowed strings (so `describe_metadata`'s
  `xml_name`s feed it directly) and `MetadataType::new` accepts any other
  Salesforce-defined type name. `CUSTOM_LABEL` retrieves labels by name;
  `CUSTOM_LABELS` is the wildcard-only container.
- **SOAP headers** — `MetadataClientBuilder::call_options_client` sends the
  `CallOptions` header, the `_with` CRUD methods take `CrudOptions` for the
  `AllOrNoneHeader`, and `deploy_with_debugging` sends a `DebuggingHeader`
  whose `DebuggingInfo` log comes back from `wait_for_deploy_with_debugging`.
- **Open-ended escape hatch** — `MetadataClient::request_builder()` for
  hand-rolling envelopes against operations the typed surface hasn't
  modeled, with `SoapOperation` carrying the typed call path:
  `render_headers` adds request headers (text escaped with the public
  `xml_escape`), and `MetadataClient::call_with_response_headers` returns
  the response's `DebuggingInfo` header next to the typed response.
- **Cross-cutting** — retry/backoff via `RetryPolicy`, automatic
  `INVALID_SESSION_ID` refresh against the configured `AuthSession`, SOAP
  fault parsing into a typed `MetadataError::Soap`.
- **Transport defaults** — the instance URL must be `https` (exact
  `localhost` and the loopback literals excepted) because the session id
  rides in every envelope; `MetadataClientBuilder::allow_insecure_transport`
  is the opt-out, and the same rule governs `cirrus`. The HTTP client the
  builder creates applies a 30 s connect timeout and a 120 s read timeout
  (`MetadataClientBuilder::connect_timeout` / `read_timeout` override either),
  and doesn't follow redirects — a 3xx surfaces as an error rather than
  re-POSTing the envelope, session token included, to the `Location` host.
  A read timeout is surfaced, not replayed, unless
  `RetryPolicy::retry_read_timeouts` is set, and a `Retry-After` longer than
  `max_delay` ends the retry loop instead of being shortened. A response body
  is buffered only up to a limit on its decoded size: 2xx bodies up to
  `MetadataClientBuilder::max_response_size` (128 MiB by default, above a
  retrieve's 50 MB zip in base64; `None` lifts it), anything else up to
  256 KiB, and a larger body fails with `MetadataError::ResponseTooLarge`
  (or is retried, when its status is one the retry policy retries). Errors that
  retain a non-SOAP body have the session id replaced with `[redacted]`.
  The read timeout runs until the response head arrives, so it also bounds
  the upload of a deploy's base64 zip, and only then becomes a per-chunk
  deadline; widen it for a large deploy or retrieve over a slow link.
  TLS is verified against the operating system's trust store, which the
  client loads when it is built: a `FROM scratch` or distroless image
  without `ca-certificates` fails at `build()` with
  `MetadataError::HttpClient`, so install a CA bundle or hand over a
  `reqwest::Client` that carries its own roots (`add_root_certificate`).
  Supplying your own client via `MetadataClientBuilder::http_client` replaces
  all of it.

## Design principles

- **No user-facing types.** The 200+ concrete metadata types
  (`CustomObject`, `ApexClass`, `Flow`, …) are caller-supplied XML or
  generic via `serde`. Only platform-contract envelopes are typed.
- **No legacy surface.** Operations Salesforce labels deprecated
  (pre-API-31 `create` / `update` / `delete`) are intentionally not
  exposed.
- **Doc-driven wire shapes.** Every handler ships with wiremock coverage
  whose request/response bodies match Salesforce's documented examples.

## Quick start

```toml
[dependencies]
cirrus-metadata = "0.4.0"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

```rust,no_run
use cirrus_metadata::auth::StaticTokenAuth;
use cirrus_metadata::{
    ListMetadataQuery, MetadataClient, MetadataType, PackageManifest, RetrieveRequest,
};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Arc::new(StaticTokenAuth::new(
        std::env::var("SF_ACCESS_TOKEN")?,
        std::env::var("SF_INSTANCE_URL")?,
    ));

    let md = MetadataClient::builder().auth(auth).build()?;

    // List every Apex class in the org. `list_metadata` takes the
    // queries plus the API version the listing is made against.
    let classes = md
        .list_metadata(
            vec![ListMetadataQuery {
                type_name: "ApexClass".into(),
                folder: None,
            }],
            md.api_version(),
        )
        .await?;

    for f in &classes {
        println!("{}\t{}", f.full_name, f.id.as_deref().unwrap_or(""));
    }

    // Build a retrieve manifest and pull the matching components.
    let manifest = PackageManifest::new(md.api_version())
        .add(MetadataType::APEX_CLASS, ["MyService"])
        .add(MetadataType::CUSTOM_OBJECT, ["Account"]);

    let async_result = md
        .retrieve(RetrieveRequest {
            api_version: md.api_version().to_string(),
            single_package: true,
            unpackaged: Some(manifest),
            ..Default::default()
        })
        .await?;

    // A retrieve that ended `Failed` still comes back as `Ok`;
    // `into_result` turns it into `MetadataError::RetrieveFailed`, whose
    // message names the status, error code and per-file problems and
    // which carries the full result.
    let result = md
        .wait_for_retrieve(&async_result.id)
        .await?
        .into_result()?;

    // `zip_file` holds the base64 payload Salesforce returns;
    // `zip_bytes()` decodes it into the actual archive.
    if let Some(zip) = result.zip_bytes()? {
        std::fs::write("retrieved.zip", zip)?;
    }

    Ok(())
}
```

## SOAP headers

The Metadata API's SOAP headers are typed. A write is partial by default;
`CrudOptions { all_or_none: true }` rolls the whole call back when any
record fails. `call_options_client` identifies your client in the
`CallOptions` header of every call that takes one. `deploy_with_debugging`
asks for an Apex debug log, which the status check returns in the
`DebuggingInfo` header once the deployment has finished and ran tests.

```rust,no_run
use cirrus_metadata::auth::StaticTokenAuth;
use cirrus_metadata::{
    Bytes, CrudOptions, DebuggingHeader, DeployOptions, LogCategory, LogCategoryLevel, LogInfo,
    MetadataClient, TestLevel, WaitConfig,
};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Arc::new(StaticTokenAuth::new(
        std::env::var("SF_ACCESS_TOKEN")?,
        std::env::var("SF_INSTANCE_URL")?,
    ));
    let md = MetadataClient::builder()
        .auth(auth)
        .call_options_client("my-tool/1.0")
        .build()?;

    // Either both classes are created or neither is.
    let results = md
        .create_metadata_with(
            "ApexClass",
            &[
                "<fullName>One</fullName><apiVersion>66.0</apiVersion><status>Active</status>\
                 <content>cHVibGljIGNsYXNzIE9uZSB7fQ==</content>",
                "<fullName>Two</fullName><apiVersion>66.0</apiVersion><status>Active</status>\
                 <content>cHVibGljIGNsYXNzIFR3byB7fQ==</content>",
            ],
            CrudOptions { all_or_none: true },
        )
        .await?;
    assert!(results.iter().all(|r| r.success));

    // Deploy with an Apex debug log, then read it back from the wait.
    let zip = Bytes::from(std::fs::read("deploy.zip")?);
    let job = md
        .deploy_with_debugging(
            zip,
            DeployOptions {
                test_level: Some(TestLevel::RunLocalTests),
                ..Default::default()
            },
            DebuggingHeader {
                categories: vec![LogInfo {
                    category: LogCategory::ApexCode,
                    level: LogCategoryLevel::Fine,
                }],
            },
        )
        .await?;
    let (result, debugging) = md
        .wait_for_deploy_with_debugging(&job.id, WaitConfig::default())
        .await?;
    result.into_result()?;
    if let Some(info) = debugging {
        println!("{}", info.debug_log);
    }

    Ok(())
}
```

## Errors

`MetadataError` covers transport failures (`MetadataError::Http`), SOAP
faults (`MetadataError::Soap { status, fault, .. }`, where `fault.code()`
returns the faultcode with its `sf:` prefix stripped), non-SOAP error
bodies from proxies and gateways (`MetadataError::Http4xx5xx`), bodies over
the size limit (`MetadataError::ResponseTooLarge`),
envelope and response-shape problems (`MetadataError::Xml`,
`MetadataError::InvalidResponse`), client-side argument validation
(`MetadataError::InvalidArgument`), jobs that finished without
succeeding (`MetadataError::DeployFailed` / `RetrieveFailed`, produced by
`into_result` and carrying the full result), exhausted polling budgets
(`MetadataError::PollTimeout`), and auth errors
(`MetadataError::Auth`, which is `#[from] AuthError`). Use `?` to
propagate from any `AuthSession::access_token` call alongside SOAP
traffic.

`MetadataError` is `#[non_exhaustive]` so future variants don't break
downstream `match` arms. Variants that wrap another error (`Http`,
`HttpClient`) expose it through `source()` and don't repeat it in
`Display`; print the chain (anyhow's `{:#}`) to see the cause.

## Logging

Events are emitted under `cirrus_metadata::auth` (the `INVALID_SESSION_ID`
refresh), `cirrus_metadata::retry` (backoff scheduling) and
`cirrus_metadata::poll` (the deploy and retrieve polling helpers). The
auth flows log under `cirrus_auth::*`, so a filter such as
`RUST_LOG=cirrus_metadata=debug,cirrus_auth=debug` covers both layers. No
event carries a session id or a credential.

## Integration tests

Live tests against a real sandbox / Developer Edition / scratch org live
under `tests/integration/` and are `#[ignore]`-gated. They share the
workspace's `.env` and the same URL safety guard as `cirrus` and
`cirrus-auth` — see the workspace-root `.env.example`.

```bash
cargo nextest run -p cirrus-metadata --test integration \
    --run-ignored only -j 1
```

## License

Licensed under the MIT license.
