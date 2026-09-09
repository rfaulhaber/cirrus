// Integration tests run with #[ignore] so they don't pollute default
// `cargo test`. We allow panicking/printing constructs that the main
// crate forbids — these are tests, the lints aren't useful here.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]

//! Integration tests for `cirrus-auth` against a real Salesforce
//! sandbox / dev / scratch org. All tests are `#[ignore]` so they
//! don't run with default `cargo test`. Run with:
//!
//! ```bash
//! cargo nextest run -p cirrus-auth --run-ignored only \
//!     -E 'binary(integration)' -j 1
//! # or, with cargo's built-in runner:
//! cargo test -p cirrus-auth --test integration -- --ignored --test-threads=1
//! ```
//!
//! Sequential (`-j 1`) is unnecessary here — these tests
//! are read-only and don't mutate org state — but keeping it matches
//! the workspace convention.
//!
//! These tests share the **same environment variables** as the
//! `cirrus` crate's integration tests; see `tests/integration/common.rs`
//! for the contract.
//!
//! # What's covered
//!
//! - `smoke` — verifies that whichever auth mode is configured
//!   (`StaticTokenAuth` or `JwtAuth`) actually produces a bearer token
//!   that Salesforce will accept on a tiny REST call, and that the
//!   `AuthSession` trait surface (`access_token`, `instance_url`,
//!   `invalidate`) behaves correctly against a live org.
//! - `jwt` — full JWT bearer flow exercise: mint a token, verify it
//!   maps to the expected user via `/services/oauth2/userinfo`, and
//!   verify the cache returns the same token across consecutive calls
//!   without re-hitting the token endpoint.
//!
//! Refresh, Client Credentials, and Token Exchange flows are **not**
//! covered here — each requires bespoke connected-app setup that the
//! shared `.env.example` doesn't carry. Add a separate module per flow
//! if/when those connected apps become available.

#[path = "integration/common.rs"]
mod common;

#[path = "integration/smoke.rs"]
mod smoke;

#[path = "integration/jwt.rs"]
mod jwt;
