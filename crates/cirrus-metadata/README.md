# cirrus-metadata

Salesforce Metadata API (SOAP) client for the Cirrus SDK.

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
  polling helpers with configurable timeout and backoff.
- **CRUD-based calls** — `create_metadata`, `read_metadata`,
  `update_metadata`, `upsert_metadata`, `delete_metadata`,
  `rename_metadata`. Up to 10 components per call, per the Metadata API
  contract — 200 for `CustomMetadata` and `CustomApplication`.
- **Utility** — `list_metadata`, `describe_metadata`, `describe_value_type`.
- **Typed `package.xml`** — `PackageManifest` builder with round-trippable
  XML serialization. `MetadataType` carries constants for the common
  types and `MetadataType::new` accepts any other Salesforce-defined
  type name.
- **Open-ended escape hatch** — `MetadataClient::request_builder()` for
  hand-rolling envelopes against operations the typed surface hasn't
  modeled, with `SoapOperation` carrying the typed call path.
- **Cross-cutting** — retry/backoff via `RetryPolicy`, automatic
  `INVALID_SESSION_ID` refresh against the configured `AuthSession`, SOAP
  fault parsing into a typed `MetadataError::Soap`.

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
cirrus-metadata = "0.2"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

```rust,ignore
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

    let result = md.wait_for_retrieve(&async_result.id).await?;

    // `zip_file` holds the base64 payload Salesforce returns;
    // `zip_bytes()` decodes it into the actual archive.
    if let Some(zip) = result.zip_bytes()? {
        fs_err::write("retrieved.zip", zip)?;
    }

    Ok(())
}
```

## Errors

`MetadataError` covers transport failures (`MetadataError::Http`), SOAP
faults (`MetadataError::Soap { status, fault }`, where `fault.code()`
returns the faultcode with its `sf:` prefix stripped), non-SOAP error
bodies from proxies and gateways (`MetadataError::Http4xx5xx`),
envelope and response-shape problems (`MetadataError::Xml`,
`MetadataError::InvalidResponse`), client-side argument validation
(`MetadataError::InvalidArgument`), exhausted polling budgets
(`MetadataError::PollTimeout`), and auth errors
(`MetadataError::Auth`, which is `#[from] AuthError`). Use `?` to
propagate from any `AuthSession::access_token` call alongside SOAP
traffic.

`MetadataError` is `#[non_exhaustive]` so future variants don't break
downstream `match` arms.

## Integration tests

Live tests against a real sandbox / Developer Edition / scratch org live
under `tests/integration/` and are `#[ignore]`-gated. They share the
workspace's `.env` and the same URL safety guard as `cirrus` and
`cirrus-auth` — see the workspace-root `.env.example`.

```bash
cargo nextest run -p cirrus-metadata --test integration \
    --run-ignored only -- --test-threads=1
```

## License

Licensed under the MIT license.
