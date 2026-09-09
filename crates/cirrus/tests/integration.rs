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

//! Integration tests against a real Salesforce sandbox / dev / scratch
//! org. All tests are `#[ignore]` so they don't run with default
//! `cargo test`. Run with:
//!
//! ```bash
//! cargo nextest run --run-ignored only -E 'binary(integration)' -j 1
//! # or, with cargo's built-in runner:
//! cargo test --test integration -- --ignored --test-threads=1
//! ```
//!
//! Sequential (`-j 1`) keeps tests from colliding on
//! shared org state and Daily API Request quota. Parallel execution
//! is fine for the read-only smoke tests but unsafe for the write
//! suite (sObject CRUD, Bulk ingest, etc.) that share an Account
//! pool.
//!
//! Configuration via `.env` at the repo root or shell environment.
//! See `tests/integration/common.rs` for the full env-var contract.
//!
//! # Test layout
//!
//! - `common` — shared harness (env loading, client construction,
//!   safety guards). Used by every test module.
//! - `smoke` — read-only verifications: versions, limits,
//!   version-negotiation, `Sforce-Limit-Info` capture.
//! - `sobjects` — Account create → retrieve → update → delete, plus
//!   global and per-object describe.
//! - `query` — SOQL envelopes, typed deserialization, the pagination
//!   stream, and `queryAll` over soft-deleted records.
//! - `composite` — composite/sobjects, composite/batch, and typed
//!   composite retrieve.
//! - `tooling` — `executeAnonymous` result shapes, Tooling describe,
//!   and Tooling query.
//!
//! Bulk 2.0 has no integration module yet.

#[path = "integration/common.rs"]
mod common;

#[path = "integration/smoke.rs"]
mod smoke;

#[path = "integration/sobjects.rs"]
mod sobjects;

#[path = "integration/query.rs"]
mod query;

#[path = "integration/composite.rs"]
mod composite;

#[path = "integration/tooling.rs"]
mod tooling;
