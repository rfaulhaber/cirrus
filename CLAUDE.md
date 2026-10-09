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
- Phase 1: versions, limits, describe (global + per-object), sObject CRUD (plus retrieve/upsert/delete by external ID; `UpsertOptions { update_only }` sends `updateOnly`; `upsert` refuses a client built for v41.0–v45.0, where a successful update is a bare 204), query/queryAll/queryMore, search/parameterizedSearch. Conditional record requests: `retrieve_if_modified_since[_as]` maps a 304 to `None` and `update_if_unmodified_since` sends `If-Unmodified-Since` (a 412 stays `CirrusError::Api`), both limited to the headers Salesforce documents for sObject Rows (the ETag family is Account-only and left to `send_with_headers`). `create_with_headers` / `update_with_headers` take the Assignment Rule, Duplicate Rule, MRU and Call Options headers as pairs, and `QueryOptions::batch_size` sends `Sforce-Query-Options` through the `query_with_options` / `query_all_with_options` / `query_more_with_options` / `*_stream_with_options` family (the streams re-send it on every page; Salesforce documents the header for the Query resource only). `retrieve_blob` downloads a blob field (sObject Blob Get) inside the request loop. An upsert whose external ID matches several records is `CirrusError::MultipleMatches { records }`, the documented 300 list passed through as `serde_json::Value`s because its entry shape is undocumented. `cirrus::soql::{quote, escape_like}` and `cirrus::sosl::escape_term` escape values interpolated into a statement; the `q` parameter's percent-encoding is transport encoding only, and the query/search docs name the 16,384-byte URI cap.
- Phase 2: composite/batch, composite/tree, composite/graph (`CompositeHandler::graph` posts any `Serialize` body; `CompositeGraphRequest` / `CompositeGraph` build the envelope from `CompositeSubrequest`, and `CompositeGraphResponse` / `CompositeGraphResult` carry each graph's `isSuccessful` with its nodes in the generic `CompositeResponse` shape; up to 500 nodes over 75 graphs, each graph atomic), composite/sobjects (incl. `retrieve_with_body`) and a typed `SObjectCollection<T>` / `CollectionRecord<T>` body with `create_records` / `update_records` / `upsert_records`, which, before any request, refuse more than `COLLECTION_MAX_RECORDS` (200) rows and validate each row (it must serialize as a JSON object; an `attributes.type` naming another sObject is `InvalidInput`, one naming the target is replaced by the helper's), generic `/composite`, Bulk 2.0 (ingest + query; `BulkIngestSpec` / `BulkQuerySpec` are `#[non_exhaustive]` with constructors, each `create` refuses an operation its endpoint does not take, `create_with_data` is the one-request multipart create for job data up to `MAX_MULTIPART_JOB_DATA_CHARS`, both handlers `list` the org's jobs through `BulkJobListOptions` with the follow-up built from the `queryLocator` rather than `nextRecordsUrl`'s path, `results` reads only the literal `Sforce-Locator: null` as the last page and refuses a 2xx page whose header is missing or not text with `InvalidResponse`, and `result_pages` returns the parallel-download cursors on API 58.0+), Apex REST passthrough (JSON verbs, plus `send_raw` for a non-JSON body or response and for reading an error body the Apex class wrote in full), Tooling API (incl. `tooling/composite`, `apex_log_body` for the raw `ApexLog/{id}/Body` text), Event Monitoring (`download` / `download_url` hold the file whole under the response-size cap; `download_stream` / `download_url_stream` return a `ByteStream` of chunks once the response head has passed the loop, outside the cap, with nothing replayed after the body starts).
- Phase 3: Metadata REST API (`Cirrus::metadata()` — the four `deployRequest` endpoints). The rest of the Metadata API surface is SOAP-only and lives in `cirrus-metadata`. `DeployResult::is_done` / `is_success` read the outcome off `status` when a response omits the `done` / `success` flags, as the documented status-check shape does; `details` accepts both the `runTestResults` / `numRun` example spelling and the `runTestResult` / `numTestsRun` DeployDetails names. The REST deploy types are `DeployResult`, `DeployDetails` and `RunTestsResult`, the names the Metadata REST deploy page and `cirrus-metadata` use; the former `DeployResultDetails` / `DeployResultInnerDetails` / `RunTestResults` remain as deprecated aliases.
- Cross-cutting: open-ended client escape hatch (paths go out as written; `Cirrus::versioned_url` and `cirrus::encode_path_segment` are the public encoders, and the Apex handler refuses a raw `#`; `Cirrus::send_raw` / `ApexHandler::send_raw` send an optional `RawBody` with its own `Content-Type` and return a `RawResponse` of status, headers and body bytes for every status the loop lets through, keeping only an `INVALID_SESSION_ID` 401 as an error so the refresh runs, which is how a non-JSON Apex body or a whole Apex error body is read; caller headers, the JSON body and the query are checked and encoded before the loop, so a malformed one is `InvalidHeader` / `Serialization` / `InvalidInput { field: "query" }` with no request, and a builder error that still reaches the loop is `InvalidInput { field: "request" }`, never `Http`; after a 401 refresh the retry carries the token the refresh obtained, so a session that mints on every call is asked once), pagination stream (`futures::Stream`, Tokio-bound through the transport's timers; `Records::pending_locator` keeps a failed page's locator, `Records::from_locator` / `from_page` resume from a saved locator or seed from a fetched page, `total_size` reports the query's total), retry + backoff policy, `Sforce-Limit-Info` surfacing, auto-refresh on an `INVALID_SESSION_ID` 401 only, multipart blob uploads. Server-issued locators are confined before dispatch (`src/locator.rs`): `query_more` sends only `query/{locator}`, `queryAll/{locator}` and `tooling/query/{locator}`, and `download_url` only `sobjects/EventLogFile/{id}/LogFile`, as a bare path or the same path on the session's instance, with no query string, fragment, `%`, backslash or dot segment; anything else is `InvalidInput` / `InvalidResponse` with no request. `build_with_latest_version` validates the discovered version like `build()` does, and `ApiVersion::version_number` requires bare digits. `build()` refuses an API version below `MIN_API_VERSION` (v41.0, where the End-of-Life page's supported tier starts; 31.0–40.0 are scheduled for retirement), so the modeled response shapes are the ones documented from there on (search answered a bare array before 37.0). Every response envelope in `cirrus` and every result struct in `cirrus-metadata` derives `Serialize` alongside `Deserialize`, so a parsed result (a cached `DescribeGlobal`, say) can be persisted and read back; ID and field lists take `&[impl AsRef<str>]`, so `Vec<String>` works without a borrow step.
- Transport contract: session-token targets must be `https` (exact `localhost` and loopback literals excepted while the client uses no proxy; the rule lives in `cirrus_auth::transport`) or the request is refused with `CirrusError::InvalidInput` — `CirrusBuilder::allow_insecure_transport(true)` is the opt-out; the client the builder creates advertises gzip, sets a 10s connect and 120s read timeout (both overridable), follows no redirects, and uses no proxy (`HTTP_PROXY` and the system proxy are ignored, unlike a stock `reqwest::Client`; `CirrusBuilder::proxy` names one, and an http loopback target then needs `allow_insecure_transport` since the hop no longer stays on the machine; a client supplied through `http_client` keeps the exemption and owns its own proxy rules). `Retry-After` is honored up to `RetryPolicy::max_delay` and a longer hint surfaces the response; read timeouts are not replayed unless `RetryPolicy::retry_read_timeouts` is set. Both rules are mirrored in `cirrus-metadata`. Every response body is read through `cirrus_auth::transport::collect_body`, which bounds the decoded size (gzip is on in every client): a 2xx body is capped by `CirrusBuilder::max_response_size` (default `DEFAULT_MAX_RESPONSE_SIZE`, 1 GiB, above the documented 1 GB Bulk result file; `None` lifts it), any other body at 256 KiB, and the drain before a retry at 64 KiB; an oversized body is `CirrusError::ResponseTooLarge`. `Cirrus::execute` hands back the raw response, and the streaming Event Monitoring downloads hand the body over as a `ByteStream`; both are outside the cap. A 2xx body that does not fit the requested type keeps a 256-byte body excerpt and a capped serde message, so a record value never reaches an error's `Display`. `CirrusError::Http` is built by one `From<reqwest::Error>` that clears the request URL's query string (SOQL `q`, `executeAnonymous` `anonymousBody`) and keeps the path. `CirrusError` is `#[non_exhaustive]`, and so is its `Api` variant: a non-2xx body parses as the documented error array or as the bare object some per-operation pages print, keys beyond `message`/`errorCode`/`fields` survive on `SalesforceError::extra`, an empty body leaves `raw` as `None`, and `retry_after` carries the response's `Retry-After` hint for a caller that owns its own retries (`MetadataError::Soap` / `Http4xx5xx` mirror the hint and the `#[non_exhaustive]` marking). A 403 `REQUEST_LIMIT_EXCEEDED` is never retried in either crate because it also signals the concurrent long-running-request cap, which the default backoff cannot outlast.

`cirrus-auth`:
- All five priority OAuth flows: JWT Bearer (RFC 7523), Refresh Token (RFC 6749 §6), Client Credentials (RFC 6749 §4.4), Web Server with PKCE (RFC 6749 §4.1 + RFC 7636), Token Exchange (RFC 8693). `TokenExchangeFlow` is `Clone` and `exchange(&self, subject_token, subject_token_type)` is per call; `TokenExchangeGrantType` selects the documented hybrid grant, and a `subject_token` over `MAX_SUBJECT_TOKEN_CHARS` (10,000) is refused before any request.
- Client authentication and sign-out: `RefreshTokenAuthBuilder` and `WebServerFlowBuilder` take `private_key_pem_bytes` / `private_key_pem_file` to send a freshly signed RS256 `client_assertion` (iss and sub the consumer key, aud the token endpoint, 170 s validity, signed by the same `src/assertion.rs` code as the JWT bearer assertion) in place of `client_secret`, and `WebServerFlow::refresh_auth` carries the key; `build` refuses a key alongside a secret. `AuthError::InvalidArgument { name, reason }` is the variant for a value a flow cannot use: that pair, the shared login hosts on the client-credentials builder, a PEM whose first block is not `RSA PRIVATE KEY` / `PRIVATE KEY`, an oversized `subject_token`. `revoke_token` posts to `/services/oauth2/revoke` once (400 maps to `AuthError::OAuth`), `RefreshTokenAuth::revoke` revokes the live, possibly rotated, refresh token and clears the cache, and `WebServerFlow::revoke` / `TokenExchangeFlow::revoke` use the flow's client. The detached refresh mint runs `in_current_span()`.
- Web Server flow lifecycle: `WebServerFlow::start_with(&AuthorizeOptions)` sends the per-attempt `login_hint` / `prompt` (replacing the flow-level values), `nonce` (supplied or generated, returned on `CompletedSession::nonce`), `display`, `immediate`, `sso_provider` and extra pairs. `PendingExchange` is single-use (callers take it out of their store before `complete`) and carries a SHA-256 digest of the issuing flow's consumer key, redirect URI and login URL; `complete` fails with `AuthError::FlowMismatch` before any request when they differ, and a pending persisted without the digest is accepted. `WebServerFlow::refresh_auth(&session)` returns a `RefreshTokenAuthBuilder` carrying the flow's key, secret, login URL and HTTP client plus the session's instance URL and refresh token, seeded through `RefreshTokenAuthBuilder::initial_access_token` so the first call spends no refresh grant. `CompletedSession` and `TokenExchangeSession` expose the Experience Cloud `sfdc_site_url` / `sfdc_site_id`. Whether `client_secret` is required on the code exchange and on the refresh grant are two independent connected-app settings (`isConsumerSecretOptional`, `isSecretRequiredForRefreshToken`), both requiring it by default; the flows send it only when set.
- `StaticTokenAuth` for paste-from-`sf-org-display` workflows and tests.
- Shared `AuthSession` trait, `SharedAuth = Arc<dyn AuthSession>` alias, automatic compare-and-swap on `invalidate`. `async_trait` and `camino` are re-exported for implementers and for `private_key_pem_file` callers. `AuthError::OAuth`'s `Display` shows `error_description`, scrubbed of every non-public form value the failing request sent and capped at 256 characters before it is stored; `AuthError` derives `Debug`.
- Caching flows share one mint outcome among callers queued behind it (`src/mint.rs`), fall back to a still-valid cached token when a refresh inside the refresh margin fails transiently, and retry the token request (connect failures for every grant; 429/5xx and lost responses too for JWT and client credentials, never for refresh, authorization code or token exchange). The refresh margin is 60 s, or half of `token_ttl` when the TTL is under two minutes (`token_endpoint::refresh_margin`), so only `Duration::ZERO` disables caching; the cache window saturates at a ten-year ceiling, so `Duration::MAX` caches until `invalidate`. A refresh mint runs detached from its caller but not from the runtime; `RefreshTokenAuth::quiesce` waits for an in-flight mint and its `RotationHandler` before a shutdown. JWT signing binds to jsonwebtoken's aws-lc-rs provider directly, not the process-global one.
- Transport: the token-endpoint client a builder creates applies `DEFAULT_TOKEN_CONNECT_TIMEOUT` (10 s) and `DEFAULT_TOKEN_REQUEST_TIMEOUT` (30 s), follows no redirects and uses no proxy (`HTTP_PROXY` and the system proxy are ignored; `token_client_builder().proxy(..)` adds one); every builder has `connect_timeout` / `request_timeout` setters, and `cirrus_auth::token_client_builder()` hands out the same configuration as a `reqwest::ClientBuilder` to extend. A client that fails to build is `AuthError::HttpClient`. Tracing targets are `cirrus_auth::{mint,token_endpoint,rotation}`; a non-OAuth token-endpoint error body is recorded only as status, content type and length. A token-endpoint body is read through `cirrus_auth::transport::collect_body` (the shared bounded body reader every client uses) and capped at 64 KiB decoded; a larger one is `AuthError::ResponseTooLarge`, retried first for a replay-safe grant when the status is 429 or 5xx. `StaticTokenAuth::new` trims the token.

`cirrus-metadata`:
- File-based: `deploy`, `check_deploy_status`, `cancel_deploy`, `deploy_recent_validation`, `retrieve`, `check_retrieve_status`, plus `wait_for_deploy` / `wait_for_retrieve` polling helpers and the poll-only `wait_for_retrieve_done`. The helpers return every terminal state as `Ok`; `DeployResult::into_result` / `RetrieveResult::into_result` turn a job that did not succeed into `MetadataError::DeployFailed` / `RetrieveFailed`, which carry the whole result. `DeployOptions.run_tests` requires `test_level: Some(TestLevel::RunSpecifiedTests)` (Salesforce faults otherwise), and `deploy` refuses any other pairing with `InvalidArgument` before encoding the zip. `TestLevel` has `as_str` / `Display` / `FromStr` and serde under its wire literals; `DeployOptions` derives serde under the API's camelCase keys, matching the REST struct. `RunTestsResult` carries `flow_coverage` / `flow_coverage_warnings` and `CodeCoverageResult` the `CodeLocation` arrays (`locations_not_covered`, `locations_covered`, `dml_info`, `method_info`, `soql_info`) per the DeployResult page. `RetrieveResult::zip_bytes` returns `MetadataResult`, failing as `MetadataError::ZipDecode` with the base64 error as its source.
- CRUD-based: `create_metadata`, `read_metadata`, `update_metadata`, `upsert_metadata`, `delete_metadata`, `rename_metadata`. Per Salesforce's contract the cap is 10 components per call; `create`/`update`/`read`/`delete` raise it to 200 for `CustomMetadata` and `CustomApplication`, and `upsert` stays at 10 for every type. Each of `create`/`update`/`upsert`/`delete` has a `_with` form taking `CrudOptions`; `CrudOptions::all_or_none` sends the `AllOrNoneHeader` so the whole call rolls back when any record fails (API 34.0+; the default stays Salesforce's save-what-succeeds). The type name is any `AsRef<str>` (a `&str` or a `MetadataType`), passed as a trailing generic so `read_metadata::<T, _, _>` still turbofishes. The envelope binds `xsi` and `xsd`, so caller XML typed as `xsi:type="xsd:boolean"` needs no declaration of its own.
- Utility: `list_metadata`, `describe_metadata`, `describe_value_type`.
- SOAP headers: `MetadataClientBuilder::call_options_client` sends `CallOptions` on every call the WSDL binds it to (all but `describeValueType`). `deploy_with_debugging` / `deploy_recent_validation_with_debugging` send a `DebuggingHeader` (categories only; the schema-required `debugLevel` goes out nil), and `check_deploy_status_with_debugging` / `wait_for_deploy_with_debugging` return the `DebuggingInfo` log from the response header. A default call's envelope carries only the `SessionHeader`.
- Typed `package.xml` via `PackageManifest` builder; `MetadataType` ships constants for the common types and `MetadataType::new` names anything else. `MetadataType` converts from `&str`, `&String`, `String` and `&MetadataType`, so a manifest can be built straight from `describe_metadata`'s owned `xml_name`s. `CUSTOM_LABEL` (singular) is the type for named labels and CRUD calls; `CUSTOM_LABELS` is the wildcard-only container.
- Open-ended escape hatch (`MetadataClient::request_builder()`), retry policy, and `INVALID_SESSION_ID` auto-refresh against the configured `AuthSession`. A custom `SoapOperation` adds request headers through `render_headers` (and opts out of the client's `CallOptions` with `ACCEPTS_CALL_OPTIONS = false`), `MetadataClient::call_with_response_headers` returns the response's `DebuggingInfo` header, and `xml_escape` is public for rendering both.
- Transport contract: same https-or-loopback rule as `cirrus` (shared in `cirrus_auth::transport`), checked at build and on every call since the instance URL is re-read from the session; `MetadataClientBuilder::allow_insecure_transport(true)` is the opt-out, and `MetadataClientBuilder::proxy` names a proxy (the default client uses none) and withdraws the loopback exemption like `CirrusBuilder::proxy` does. `api_version` must be the bare `XX.X` form. Errors that retain a non-SOAP body are scrubbed of the session id. Bodies are read through `cirrus_auth::transport::collect_body`: a 2xx body is capped by `MetadataClientBuilder::max_response_size` (default `DEFAULT_MAX_RESPONSE_SIZE`, 128 MiB, above a 50 MB retrieve zip in base64; `None` lifts it) and any other body at 256 KiB. An oversized body is `MetadataError::ResponseTooLarge`, except on a status the retry policy retries, where it is retried like any other. Deserializer messages in `MetadataError::Xml` are capped at 512 bytes because serde quotes the value it rejected, and `RetrieveResult`'s `Debug` prints the size of the zip, not the zip. A response element nesting deeper than 64 levels (`envelope::MAX_RESPONSE_DEPTH`, sized so a debug build's deserializer cannot overflow a 2 MiB stack first) is `MetadataError::InvalidResponse`. `MetadataError` converts from `quick_xml::Error` / `quick_xml::DeError` (the crate re-exports `quick_xml` so a custom `SoapOperation` can name them) and from nothing else: there is deliberately no `From<std::io::Error>`, so a caller's disk error is never filed as `Xml`. The wire enums with a `#[serde(other)] Unknown` fallback (`AsyncRequestState`, `DeployStatus`, `DeployProblemType`, `RetrieveStatus`, `ManageableState`; `DeployStatus`, `BulkOperation`, `BulkJobState` and `BulkJobType` in `cirrus`) are `#[non_exhaustive]`, pinned by `compile_fail` doctests, so naming a new literal stays additive.

Tests: ~1000 unit + ~45 doctest workspace-wide, all wiremock-backed, fast (<10s wall). The three ambient-proxy tests set `HTTP_PROXY` in their own process and run only under nextest (gated on the `NEXTEST` variable), since a threaded runner would leak the variable into every other test. Integration tests against real orgs are `#[ignore]`-gated and live under each crate's `tests/integration/`.

### Project-wide rules

- **No legacy or deprecated Salesforce APIs.** Skip anything Salesforce marks legacy or deprecated: Bulk 1.0, SOAP login, username-password OAuth, pre-API-31 CRUD calls, etc. This applies across every crate.
- **No org-specific types.** The SDK never models concrete sObjects like `Account` or `Contact`. Record types are caller-supplied generics; only platform-contract envelopes (response shapes Salesforce defines) are typed.
- **Doc-driven wire shapes.** Test fixtures must match Salesforce's documented examples, not prior assumptions about the wire shape. See [Test conventions](#test-conventions).
- **Errors name their category and expose their cause.** A `CirrusError`, `AuthError` or `MetadataError` variant that wraps another error exposes it through `source()` only; its `Display` does not repeat the inner text, so chain reporters print each message once.

## Architecture

### Open-ended client (escape hatch)

Every typed handler layers over a small set of public verb methods on `Cirrus`: `get`, `get_with_query`, `post`, `put`, `patch`, `delete`, `send_with_headers` / `send_json_with_headers` (the header-carrying verbs, bodiless and with a JSON body — they stay inside the retry / 401-refresh / limit-info loop, unlike the two below), `send_with_replay` / `send_json_with_replay` (same loop, with an explicit `Replay` for endpoints whose HTTP method misstates their effect — Apex REST uses `Replay::Never` throughout), plus `request_builder` (auth-injected) and `execute` (hands-off bypass). Path resolution is three-mode:

- **Relative** (`limits`) → versioned: `{instance}/services/data/{version}/limits`
- **Leading slash** (`/services/apexrest/foo`) → instance-rooted
- **Fully-qualified** (`https://...`) → passthrough

When adding a new typed handler, **layer over the public verbs** — don't introduce parallel transport code. Use `versioned_url` + `send_at` only if a path segment needs percent-encoding (e.g., upsert by external ID with `/` in the value).

### Send-method family

Six send paths cover every wire shape we've needed, five internal and one public. Pick by request/response shape, not by handler name. All six go through the same retry policy, 401 auto-refresh, and `Sforce-Limit-Info` capture, which live in one loop, `dispatch_with`; its `finish` step is what varies, deciding what a response becomes once its status has passed the retry check (`dispatch` collects and parses the body, `fetch_stream` hands it over uncollected).

| Helper | Request body | Response | Used by |
|---|---|---|---|
| `Cirrus::send` (and public verbs) | `Serialize` JSON or none | typed JSON → `R` | most REST |
| `send_with_body` | raw `bytes::Bytes` + Content-Type | typed JSON → `R` | Bulk 2.0 CSV ingest upload |
| `fetch_raw` | query params only | `(HeaderMap, bytes::Bytes)` | Bulk 2.0 query results, Event Monitoring downloads, sObject blob downloads, the Tooling Apex log body |
| `fetch_stream` | query params only | `ByteStream` (status, headers, body as `Stream<Item = CirrusResult<Bytes>>`), outside `max_response_size`; a non-2xx body is collected and parsed as usual | Event Monitoring streaming downloads |
| `send_multipart` | JSON metadata part + binary part | typed JSON → `R` | sObject blob inserts/updates (ContentVersion / Document / Attachment) |
| `send_raw` (public) | optional `RawBody` (bytes + its Content-Type) or none | `RawResponse` (status, headers, bytes) for any status; only an `INVALID_SESSION_ID` 401 is an error, and a non-2xx body is token-scrubbed | `Cirrus::send_raw`, `ApexHandler::send_raw` |

If you find yourself wanting a seventh, first check whether the existing six would work with caller-side adaptation.

### Handler module conventions (cirrus)

- One module per platform-level surface: `crates/cirrus/src/handlers/{sobjects, query, search, composite, bulk, tooling, apex, event_monitoring, metadata, limits, versions}.rs`.
- Handler struct holds `&'a Cirrus`; constructed via top-level methods on `Cirrus` (e.g., `sf.tooling()`, `sf.bulk().query()`, `sf.sobject("Account")`, `sf.metadata()`). Every handler derives `Clone, Copy` so a copy can move into an `async move` fan-out, and a sub-handler accessor (`bulk().ingest()`, `composite().sobjects()`, `tooling().sobject(..)`) returns the client's `'a`, never a borrow of the temporary parent.
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
- **Envelopes (`envelope.rs`):** wraps the operation body with SOAP namespaces, `<SessionHeader>` (the Metadata API expects the bearer token inside the envelope, not on the `Authorization` header — `request_builder()` deliberately does not inject auth), and the action header. Property-tested for XML round-trip safety. The response parser locates the `{Op}Response` and `DebuggingInfo` elements as byte ranges into the response text and the transport deserializes those slices in place, so a retrieve's base64 zip is never copied. Request headers beyond `SessionHeader` come from the client's `CallOptions` and `SoapOperation::render_headers`; the typed header pieces live in `headers.rs`.
- **Handlers (`handlers/{file_based, crud, utility}.rs`):** add methods directly to `MetadataClient` via inherent `impl` blocks so callers see `md.deploy(...)`, `md.list_metadata(...)`, etc. at the top level — no `.utility()` / `.crud()` accessor pattern.
- **Package manifests (`package_manifest.rs`):** typed builder for `package.xml`; `MetadataType` carries constants for the ~40 most-commonly-used types and `MetadataType::new` takes any other Salesforce-defined name. Round-trips through `quick-xml`. Used as `RetrieveRequest::unpackaged`.
- **Caller-supplied metadata bodies:** the 200+ concrete metadata types (`CustomObject`, `ApexClass`, `Flow`, …) are **not** modeled. Callers pass XML strings or `serde`-generic bodies via the `_as::<T>` variants of the CRUD methods. Only platform envelopes are typed.

## Test conventions

- Wiremock for handler tests; **no live network in the default test suite.**
- Mock JSON / XML fixtures must cite specific doc pages. A historical regression (`BulkQueryJob.query` modeled despite Salesforce never returning it) was caused by matching mocks to prior assumptions instead of docs. **Doc-driven > prior-knowledge.**
- Each new handler ships with wiremock coverage of: happy path, error array / SOAP fault, edge cases documented in the wire shape (partial-success semantics, header cursors, etc.).
- If you can't verify a wire-shape claim against docs, flag it explicitly in code — see `ExecuteAnonymousResult` in `crates/cirrus/src/response.rs` for the established "Wire-shape provenance" docstring pattern.
- Each README is compiled as doctests through a `#[cfg(doctest)]` item in the crate's `lib.rs`. Fence a complete program `rust,no_run` so it compiles against the real API, and only a deliberate fragment `rust,ignore`; a bare fence would run as a test.

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
        │   ├── headers.rs      # CallOptions / AllOrNone / Debugging headers, DebuggingInfo
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
nix flake check                            # Build and run the whole test suite in the Nix sandbox
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

`crates/cirrus/Cargo.toml` and `crates/cirrus-metadata/Cargo.toml` each carry a `pre-release-replacements` entry that rewrites the `<crate> = "x.y.z"` pin in the crate's README on release; the `cirrus-auth` README has no pin. Each crate directory holds `LICENSE` as a symlink to the workspace-root file, which `cargo package` dereferences, so the published `.crate` carries the MIT text.

### Publish ordering

`cargo-release` does **not** sequence the workspace. Each `cargo release -p <crate>` is an independent invocation. Because `cargo package` resolves dependencies against the crates.io *index* (path deps are stripped from the published manifest, leaving only the `version` constraint), downstream crates cannot be packaged until their workspace deps are live on crates.io. Always publish in dependency order:

```
cirrus-auth → cirrus → cirrus-metadata
```

If you bump `cirrus-auth`, also bump the `[workspace.dependencies] cirrus-auth = { ..., version = "..." }` pin in the root `Cargo.toml`. Same for `cirrus-metadata`.
