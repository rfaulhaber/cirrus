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

//! Integration tests for `cirrus-metadata` against a real Salesforce
//! sandbox / dev / scratch org. All tests are `#[ignore]` so they
//! don't run with default `cargo test`. Run with:
//!
//! ```bash
//! cargo nextest run -p cirrus-metadata --run-ignored only \
//!     -E 'binary(integration)' -j 1
//! # or, with cargo's built-in runner:
//! cargo test -p cirrus-metadata --test integration -- --ignored --test-threads=1
//! ```
//!
//! Sequential (`-j 1`) keeps the CRUD and file-based tests
//! from colliding on shared org state and saturating the Daily API
//! Request quota. Read-only smoke tests would be fine in parallel but
//! it's simpler to keep one rule for all of them.
//!
//! Configuration via `.env` at the repo root or shell environment —
//! the same env vars the `cirrus` and `cirrus-auth` crates consume.
//! See `tests/integration/common.rs` for the full contract.
//!
//! # Test layout
//!
//! - `common` — shared harness (env loading, client construction,
//!   safety guards, cleanup helpers).
//! - `smoke` — read-only verifications: `describeMetadata`,
//!   `listMetadata`, endpoint URL shape, retry-policy reuse.
//! - `crud` — CustomLabel create → read → update → delete cycle via
//!   the SOAP CRUD operations.
//! - `file_based` — `deploy` + `wait_for_deploy` + `retrieve` +
//!   `wait_for_retrieve` with a minimal CustomLabel-only package.

#[path = "integration/common.rs"]
mod common;

#[path = "integration/smoke.rs"]
mod smoke;

#[path = "integration/crud.rs"]
mod crud;

#[path = "integration/file_based.rs"]
mod file_based;
