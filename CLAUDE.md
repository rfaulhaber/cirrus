# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`cirrus` is a family of Rust crates for the Salesforce platform (unaffiliated with Salesforce). Pre-1.0.

Workspace members:

- **`cirrus`** — HTTP client for the Salesforce REST API. The original single-crate release; now the workspace's REST surface.
- **`cirrus-auth`** — OAuth 2.0 flows + the `AuthSession` trait. Re-exported by both `cirrus` and `cirrus-metadata` so end users don't add it as an explicit dependency. Has no dependency on its consumers, which keeps siblings free to depend on it without pulling in the REST client.
- **`cirrus-metadata`** — Salesforce Metadata API (SOAP) client: file-based deploy/retrieve, CRUD-based calls, and the utility surface (`listMetadata`, `describeMetadata`, `describeValueType`).

Current versions are tracked in each crate's `Cargo.toml`; crates.io is the source of truth for what's published.

### Shipped surface

`cirrus`:
- Phase 1: versions, limits, describe (global + per-object), sObject CRUD, query/queryAll/queryMore, search/parameterizedSearch.
- Phase 2: composite/batch, composite/tree, composite/sobjects (incl. `retrieve_with_body`), generic `/composite`, Bulk 2.0 (ingest + query), Apex REST passthrough, Tooling API, Event Monitoring.
- Phase 3: Metadata REST API (`Cirrus::metadata()` — the four `deployRequest` endpoints). The rest of the Metadata API surface is SOAP-only and lives in `cirrus-metadata`.
- Cross-cutting: open-ended client escape hatch, pagination stream (`futures::Stream`), retry + backoff policy, `Sforce-Limit-Info` surfacing, auto-refresh on 401, multipart blob uploads.
- Transport contract: session-token targets must be `https` (loopback excepted) or the request is refused with `CirrusError::InvalidInput` — `CirrusBuilder::allow_insecure_transport(true)` is the opt-out; the client the builder creates advertises gzip, sets a 10s connect and 120s read timeout (both overridable), and follows no redirects. `CirrusError` is `#[non_exhaustive]`.

`cirrus-auth`:
- All five priority OAuth flows: JWT Bearer (RFC 7523), Refresh Token (RFC 6749 §6), Client Credentials (RFC 6749 §4.4), Web Server with PKCE (RFC 6749 §4.1 + RFC 7636), Token Exchange (RFC 8693).
- `StaticTokenAuth` for paste-from-`sf-org-display` workflows and tests.
- Shared `AuthSession` trait, `SharedAuth = Arc<dyn AuthSession>` alias, automatic compare-and-swap on `invalidate`.

`cirrus-metadata`:
- File-based: `deploy`, `check_deploy_status`, `cancel_deploy`, `deploy_recent_validation`, `retrieve`, `check_retrieve_status`, plus `wait_for_deploy` / `wait_for_retrieve` polling helpers.
- CRUD-based: `create_metadata`, `read_metadata`, `update_metadata`, `upsert_metadata`, `delete_metadata`, `rename_metadata`. Per Salesforce's contract the cap is 10 components per call; `create`/`update`/`read`/`delete` raise it to 200 for `CustomMetadata` and `CustomApplication`, and `upsert` stays at 10 for every type.
- Utility: `list_metadata`, `describe_metadata`, `describe_value_type`.
- Typed `package.xml` via `PackageManifest` builder; `MetadataType` ships constants for the common types and `MetadataType::new` names anything else.
- Open-ended escape hatch (`MetadataClient::request_builder()`), retry policy, and `INVALID_SESSION_ID` auto-refresh against the configured `AuthSession`.

Tests: ~565 unit + ~33 doctest workspace-wide, all wiremock-backed, fast (<10s wall). Integration tests against real orgs are `#[ignore]`-gated and live under each crate's `tests/integration/`.

### Project-wide rules

- **No legacy or deprecated Salesforce APIs.** Skip anything Salesforce marks legacy or deprecated: Bulk 1.0, SOAP login, username-password OAuth, pre-API-31 CRUD calls, etc. This applies across every crate.
- **No org-specific types.** The SDK never models concrete sObjects like `Account` or `Contact`. Record types are caller-supplied generics; only platform-contract envelopes (response shapes Salesforce defines) are typed.
- **Doc-driven wire shapes.** Test fixtures must match Salesforce's documented examples, not prior assumptions about the wire shape. See [Test conventions](#test-conventions).

## Architecture

### Open-ended client (escape hatch)

Every typed handler layers over a small set of public verb methods on `Cirrus`: `get`, `get_with_query`, `post`, `put`, `patch`, `delete`, `send_with_headers` (the header-carrying verb — it stays inside the retry / 401-refresh / limit-info loop, unlike the two below), plus `request_builder` (auth-injected) and `execute` (hands-off bypass). Path resolution is three-mode:

- **Relative** (`limits`) → versioned: `{instance}/services/data/{version}/limits`
- **Leading slash** (`/services/apexrest/foo`) → instance-rooted
- **Fully-qualified** (`https://...`) → passthrough

When adding a new typed handler, **layer over the public verbs** — don't introduce parallel transport code. Use `versioned_segments` + `send_at` only if a path segment needs percent-encoding (e.g., upsert by external ID with `/` in the value).

### Send-method family

Four internal send paths cover every wire shape we've needed. Pick by request/response shape, not by handler name. All four go through the same retry policy, 401 auto-refresh, and `Sforce-Limit-Info` capture.

| Helper | Request body | Response | Used by |
|---|---|---|---|
| `Cirrus::send` (and public verbs) | `Serialize` JSON or none | typed JSON → `R` | most REST |
| `send_with_body` | raw `bytes::Bytes` + Content-Type | typed JSON → `R` | Bulk 2.0 CSV ingest upload |
| `fetch_raw` | query params only | `(HeaderMap, bytes::Bytes)` | Bulk 2.0 query results, Event Monitoring downloads |
| `send_multipart` | JSON metadata part + binary part | typed JSON → `R` | sObject blob inserts/updates (ContentVersion / Document / Attachment) |

If you find yourself wanting a fifth, first check whether the existing four would work with caller-side adaptation.

### Handler module conventions (cirrus)

- One module per platform-level surface: `crates/cirrus/src/handlers/{sobjects, query, search, composite, bulk, tooling, apex, event_monitoring, metadata, limits, versions}.rs`.
- Handler struct holds `&'a Cirrus`; constructed via top-level methods on `Cirrus` (e.g., `sf.tooling()`, `sf.bulk().query()`, `sf.sobject("Account")`, `sf.metadata()`).
- Methods that return records expose two variants: the default (returns `serde_json::Value`) and `_as::<R>` for typed deserialization.
- Platform envelopes live in `crates/cirrus/src/response.rs` and are re-exported at the crate root.
- Pagination support: handlers with paginated GETs add `_stream` / `_stream_as` variants returning `pagination::Records<R>` (a `futures::Stream`). See `query`/`tooling.query` for the pattern.

### Auth crate boundary

- `crates/cirrus-auth/src/` houses every OAuth flow plus the `AuthSession` trait. It owns its own error type, `AuthError` / `AuthResult`, and has no dependency on `cirrus` or `cirrus-metadata` — that's what lets siblings depend on it directly.
- Both `cirrus` and `cirrus-metadata` re-export the entire auth crate (as `cirrus::auth` and `cirrus_metadata::auth` respectively) and pull `AuthError` / `AuthSession` / `SharedAuth` to the crate root. End users write `use cirrus::auth::JwtAuth;` without an explicit `cirrus-auth` dependency.
- `CirrusError::Auth(#[from] AuthError)` and `MetadataError::Auth(#[from] AuthError)` let `?` propagate auth failures from `self.auth.access_token().await?` without conversions. Pattern-match on `CirrusError::Auth(AuthError::OAuth { .. })` for auth-flavored errors.
- When adding a new flow or modifying auth code, work in `cirrus-auth` — do **not** add auth code back into the consumer crates.
- Sensitive fields (`access_token`, `refresh_token`, `id_token`, JWT `iss`/`sub`, OAuth `signature`) have custom `Debug` impls that emit `[redacted]`. Preserve this when adding new types that carry secrets.

### cirrus-metadata architecture (SOAP)

The Metadata API has two surfaces: a small REST slice covering `deployRequest` (in `cirrus::handlers::metadata`) and a much larger SOAP surface for everything else (`retrieve`, `listMetadata`, `describeMetadata`, the CRUD-based calls, etc.). `cirrus-metadata` covers the SOAP surface — SOAP is the canonical Metadata API, not a legacy holdout.

- **Transport core (`transport.rs`):** `SoapOperation` is the trait/dispatch path analogous to `Cirrus::send`. Every typed handler builds a `SoapOperation` and routes through `MetadataClient::call`. Retry + `INVALID_SESSION_ID` refresh wrap the call.
- **Envelopes (`envelope.rs`):** wraps the operation body with SOAP namespaces, `<SessionHeader>` (the Metadata API expects the bearer token inside the envelope, not on the `Authorization` header — `request_builder()` deliberately does not inject auth), and the action header. Property-tested for XML round-trip safety.
- **Handlers (`handlers/{file_based, crud, utility}.rs`):** add methods directly to `MetadataClient` via inherent `impl` blocks so callers see `md.deploy(...)`, `md.list_metadata(...)`, etc. at the top level — no `.utility()` / `.crud()` accessor pattern.
- **Package manifests (`package_manifest.rs`):** typed builder for `package.xml`; `MetadataType` carries constants for the ~40 most-commonly-used types and `MetadataType::new` takes any other Salesforce-defined name. Round-trips through `quick-xml`. Used as `RetrieveRequest::unpackaged`.
- **Caller-supplied metadata bodies:** the 200+ concrete metadata types (`CustomObject`, `ApexClass`, `Flow`, …) are **not** modeled. Callers pass XML strings or `serde`-generic bodies via the `_as::<T>` variants of the CRUD methods. Only platform envelopes are typed.

## Test conventions

- Wiremock for handler tests; **no live network in the default test suite.**
- Mock JSON / XML fixtures must cite specific doc pages. A historical regression (`BulkQueryJob.query` modeled despite Salesforce never returning it) was caused by matching mocks to prior assumptions instead of docs. **Doc-driven > prior-knowledge.**
- Each new handler ships with wiremock coverage of: happy path, error array / SOAP fault, edge cases documented in the wire shape (partial-success semantics, header cursors, etc.).
- If you can't verify a wire-shape claim against docs, flag it explicitly in code — see `ExecuteAnonymousResult` in `crates/cirrus/src/response.rs` for the established "Wire-shape provenance" docstring pattern.

### Integration tests

Live tests against a real Salesforce sandbox / Developer Edition / scratch org live under `crates/<crate>/tests/integration.rs` (one binary per crate, submodules under `crates/<crate>/tests/integration/`). All `#[ignore]`-gated so they don't run by default. The three crates share the workspace-root `.env`.

```bash
# Configure once: copy .env.example to .env, fill in the values
cp .env.example .env

# Run a crate's integration suite (sequential — they share org state)
cargo nextest run -p cirrus           --test integration --run-ignored only -j 1
cargo nextest run -p cirrus-auth      --test integration --run-ignored only -j 1
cargo nextest run -p cirrus-metadata  --test integration --run-ignored only -j 1
```

The harness (`tests/integration/common.rs` in each crate) refuses to run unless `INSTANCE_URL` matches a known sandbox / Developer Edition / scratch My Domain pattern: `.sandbox.`, `.develop.`, `.scratch.`, or `.trailblaze.` infix before `.my.salesforce.com`. The `.trailblaze.` partition is used by free Developer Edition orgs from developer.salesforce.com signup (subdomain typically ends `-dev-ed`). Override with `CIRRUS_INTEGRATION_FORCE=1` only after verifying the target org is safe for destructive writes — the safe-list catches Enhanced Domains URLs but not legacy pre-Spring-'23 sandbox URLs, and Salesforce occasionally introduces new partition infixes (audit when adding orgs in unfamiliar shapes).

Auth supports two paths: paste a static token from `sf org display`, or configure JWT bearer flow with a connected app + private key. Static-token mode is the easy bootstrap; JWT exercises the full auth flow. Once `CIRRUS_INTEGRATION=1` is set, an incomplete auth configuration fails the run instead of skipping, so an opted-in run can't come back green having made no calls. `INSTANCE_URL` and `LOGIN_URL` must both be `https`; `CIRRUS_INTEGRATION_FORCE=1` waives the org classification, never that.

Don't add network-touching tests to the default (`cargo test`) suite — those should always be wiremock-backed and offline.

## Repository Layout

This is a **Cargo workspace**. The repo root holds workspace-level config (`Cargo.toml` workspace manifest, `clippy.toml`, `deny.toml`, `flake.nix`, `rust-toolchain.toml`). Each member crate lives under `crates/<name>/` with the standard `src/lib.rs` layout.

```
cirrus/
├── Cargo.toml                  # [workspace] manifest, [workspace.dependencies], [workspace.lints]
├── clippy.toml, deny.toml      # apply to all workspace members
├── flake.nix, flake.lock       # Nix dev shell
├── rust-toolchain.toml         # toolchain pin
└── crates/
    ├── cirrus/                 # REST client
    │   ├── Cargo.toml          # depends on cirrus-auth (workspace dep)
    │   ├── src/
    │   ├── tests/              # unit + integration (gated)
    │   └── examples/
    ├── cirrus-auth/            # OAuth flows + AuthSession trait
    │   ├── Cargo.toml          # no dependency on cirrus or cirrus-metadata
    │   ├── src/
    │   │   ├── lib.rs          # AuthSession trait, re-exports
    │   │   ├── error.rs        # AuthError / AuthResult
    │   │   ├── static_token.rs
    │   │   ├── jwt.rs
    │   │   ├── refresh.rs
    │   │   ├── client_credentials.rs
    │   │   ├── web_server.rs
    │   │   ├── token_exchange.rs
    │   │   └── token_endpoint.rs   # shared OAuth POST helper
    │   └── tests/fixtures/     # JWT RSA test key
    └── cirrus-metadata/        # Salesforce SOAP Metadata API client
        ├── Cargo.toml          # depends on cirrus-auth, NOT on cirrus
        ├── src/
        │   ├── lib.rs          # MetadataClient + builder, re-exports
        │   ├── transport.rs    # SoapOperation trait + dispatch
        │   ├── envelope.rs     # SOAP envelope builder
        │   ├── package_manifest.rs
        │   ├── result.rs       # typed response envelopes
        │   ├── error.rs        # MetadataError / MetadataResult / SoapFault
        │   ├── retry.rs        # RetryPolicy
        │   └── handlers/{file_based,crud,utility}.rs
        └── tests/              # unit + integration (gated)
```

Shared dependency versions are declared in `[workspace.dependencies]` (including path-and-version entries for `cirrus-auth` and `cirrus-metadata`) and inherited per-crate via `dep.workspace = true`. Lint denials live in `[workspace.lints.clippy]` and are activated per-crate via `[lints] workspace = true`. New sibling crates inherit both automatically.

## Development Environment

The project uses a Nix flake with `direnv`; the committed `.envrc` is `use flake` and needs one `direnv allow` per clone. The dev shell provides `rustc`/`cargo` (stable), `clippy`, `rust-analyzer`, `cargo-nextest`, and `cargo-release`. Outside Nix, the `rust-toolchain.toml` pins channel `stable` with `clippy` and `rustfmt`.

Edition is **2024** — code may use features unavailable in older editions. The workspace resolver is `"3"` (requires Cargo ≥ 1.85). The published MSRV is `rust-version = "1.88"` in `[workspace.package]`, inherited by every member; it is set by the dependency graph (`jsonwebtoken` 11 and `time`), and a dedicated CI job pins that exact toolchain so the declared floor stays honest.

## Common Commands

All commands run from the workspace root unless noted.

```bash
cargo build --workspace                    # Build all member crates
cargo nextest run --workspace              # Run all tests (preferred — flake provides nextest)
cargo test --workspace                     # Fallback test runner
cargo nextest run -p <crate> <pattern>     # Run a single test by name substring in a specific crate
cargo test --doc --workspace               # Run doctests
cargo clippy --all-targets --workspace     # Lint (CI-equivalent — many rules are `deny`)
cargo fmt --all                            # Format every crate
cargo package -p <crate> --allow-dirty     # Pre-flight publish check (resolves against crates.io index)
nix build                                  # Reproducible package build via the flake
cargo release -p <crate> <level>           # Release a specific crate; signs commits/tags, pushes to origin, only from main
```

## Coding Constraints (enforced by lints)

The workspace `Cargo.toml` sets these clippy lints to `deny` via `[workspace.lints.clippy]` — every member crate inherits them. Code that trips them will fail `cargo clippy`:

- `unwrap_used`, `expect_used`, `panic`, `todo`, `unimplemented` — no panicking constructs; propagate errors with `Result`.
- `dbg_macro`, `print_stdout`, `print_stderr` — no ad-hoc stdout/stderr printing. Use `tracing` instead.
- `await_holding_lock`, `await_holding_refcell_ref`, `await_holding_invalid_type` — async correctness.
- `disallowed_types`, `disallowed_methods` — see `clippy.toml`.

`clippy.toml` bans the following in favor of replacements:

- `std::path::Path` / `std::path::PathBuf` → use `camino::Utf8Path` / `camino::Utf8PathBuf`.
- `std::fs::*` (read, write, open, create, remove, copy, rename, metadata, canonicalize, etc.) → use the `fs_err` equivalents so error messages include the offending path.
- `std::fs::OpenOptions` → `fs_err::OpenOptions`.

`camino` and `fs-err` are workspace dependencies, currently consumed by `cirrus-auth` (JWT key file loading). New crates that touch the filesystem should add them via `dep.workspace = true`.

## Comment conventions

Comments (both `//` and doc comments) describe the code as it stands, for the next person who reads it. Three rules:

1. **Don't imply a development process.** Comments describe what the code *is* and *why*, not how it got there. Avoid change-narrative phrasing — "previously", "now uses", "no longer", "refactored to", "we changed this", "fixed a regression", "extracted from". A reader has no access to the prior state, so a comment framed as a diff is noise. Write the rationale declaratively: not "extracted this to avoid duplication" but "all N call sites route through this so the behavior lives in one place". Change history belongs in commit messages, not in the source.
2. **Keep public doc comments crates.io-friendly.** `///` and `//!` on public items are published to docs.rs. Lead with behavior a *user* of the API cares about, not internal implementation detail. Don't reference private helpers, internal layering, or "the impl" in a way that only makes sense with the source open. Implementation notes that matter only to a maintainer belong in plain `//` comments on the relevant code, not in the published doc. (Items that are `pub(crate)`/`pub(super)`/private aren't published, so their docs can be as internal as needed.)
3. **Make it useful to the next maintainer.** A comment should earn its place by explaining something the code can't: a non-obvious constraint (why a value is computed before an `await` to keep a future `Send`), a wire-shape provenance, a security rationale (why a field is redacted), or where the canonical place to make a related change is. Don't restate what the code already says.

## Release Process

Each crate has its own `[package.metadata.release]` for `cargo-release`. Common config:

- Releases only from `main`.
- Commits and tags are GPG-signed.
- Tags are pushed to `origin`.
- `publish = true` — releases push to crates.io.

Tag prefixes are set per-crate to avoid collisions:

| Crate | Tag prefix | Example |
|---|---|---|
| `cirrus` | `v` | `v0.2.1` (grandfathered from the pre-workspace era) |
| `cirrus-auth` | `cirrus-auth-v` | `cirrus-auth-v0.2.2` |
| `cirrus-metadata` | `cirrus-metadata-v` | `cirrus-metadata-v0.1.0` |

Only `crates/cirrus/Cargo.toml` carries a `pre-release-replacements` entry — it rewrites the `cirrus = "x.y.z"` snippet in its README on release.

### Publish ordering

`cargo-release` does **not** sequence the workspace. Each `cargo release -p <crate>` is an independent invocation. Because `cargo package` resolves dependencies against the crates.io *index* (path deps are stripped from the published manifest, leaving only the `version` constraint), downstream crates cannot be packaged until their workspace deps are live on crates.io. Always publish in dependency order:

```
cirrus-auth → cirrus → cirrus-metadata
```

If you bump `cirrus-auth`, also bump the `[workspace.dependencies] cirrus-auth = { ..., version = "..." }` pin in the root `Cargo.toml`. Same for `cirrus-metadata`.
