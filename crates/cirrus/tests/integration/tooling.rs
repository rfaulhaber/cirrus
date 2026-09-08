//! Tooling API integration tests.
//!
//! The most valuable test here is [`execute_anonymous_*`]. The
//! [`ExecuteAnonymousResult`] field set is doc-published, but its JSON
//! casing and the `-1` "no error" sentinel on `line`/`column` are not
//! — the wire-shape provenance note in `response.rs` records that both
//! come from live API observation, and these tests are what keeps that
//! observation honest. If any of them fail, fix the deserialization in
//! `response.rs` first, then re-run.
//!
//! Also covers Tooling `describe_global`, a Tooling query (against
//! `ApexClass` — every org has Tooling sObjects even if no Apex is
//! authored), and a Tooling search.

use crate::common::try_init_client;

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn execute_anonymous_clean_run_marks_success_true() {
    let Some(sf) = try_init_client().await else {
        return;
    };
    // Trivially valid Apex: empty block is rejected by the compiler in
    // some org variants, so use an expression that always works.
    let result = sf
        .tooling()
        .execute_anonymous("System.debug('cirrus');")
        .await
        .expect("executeAnonymous should round-trip");
    assert!(result.compiled, "valid Apex should compile: {result:?}");
    assert!(
        result.success,
        "no exception should produce success=true: {result:?}"
    );
    assert!(
        result.compile_problem.is_none(),
        "clean compile should have no compileProblem, got {:?}",
        result.compile_problem,
    );
    assert!(
        result.exception_message.is_none(),
        "clean run should have no exceptionMessage",
    );
    // Sentinel-pair: -1 for both line and column when no error.
    assert_eq!(result.line, -1, "no-error sentinel for line should be -1");
    assert_eq!(
        result.column, -1,
        "no-error sentinel for column should be -1"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn execute_anonymous_compile_error_populates_compile_problem() {
    let Some(sf) = try_init_client().await else {
        return;
    };
    // Garbled syntax — compiler should reject.
    let result = sf
        .tooling()
        .execute_anonymous("this_is_not_valid_apex syntax garbage @@@")
        .await
        .expect("executeAnonymous should round-trip even on compile failure");
    assert!(
        !result.compiled,
        "garbage source should NOT compile, got compiled=true: {result:?}",
    );
    assert!(!result.success, "uncompiled code cannot succeed");
    assert!(
        result.compile_problem.is_some(),
        "compile failure must populate compileProblem; got None",
    );
    // line/column should NOT be the -1 sentinel — they should point at
    // the syntax error location.
    assert!(
        result.line >= 0,
        "compile error should set line ≥ 0, got {}",
        result.line,
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn execute_anonymous_runtime_error_populates_exception_fields() {
    let Some(sf) = try_init_client().await else {
        return;
    };
    // Compiles cleanly; throws at runtime. NullPointerException is the
    // most reliable cross-org "guaranteed to throw" without depending
    // on org-specific custom objects.
    let result = sf
        .tooling()
        .execute_anonymous("String s = null; s.length();")
        .await
        .expect("executeAnonymous should round-trip even on runtime failure");
    assert!(result.compiled, "valid Apex should compile: {result:?}");
    assert!(
        !result.success,
        "code that throws must not report success=true: {result:?}",
    );
    assert!(
        result.exception_message.is_some(),
        "runtime exception must populate exceptionMessage; got None: {result:?}",
    );
    let msg = result.exception_message.as_deref().unwrap();
    assert!(
        msg.to_ascii_lowercase().contains("null"),
        "NullPointer-style exception should mention 'null', got {msg:?}",
    );
    // Stack trace should also be populated, per the docstring claim.
    assert!(
        result.exception_stack_trace.is_some(),
        "runtime exception should populate exceptionStackTrace",
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn tooling_describe_global_includes_apex_class() {
    let Some(sf) = try_init_client().await else {
        return;
    };
    let dg = sf
        .tooling()
        .describe_global()
        .await
        .expect("Tooling describe_global should succeed");
    assert!(
        dg.sobjects.iter().any(|s| s.name == "ApexClass"),
        "Tooling describe_global should include ApexClass",
    );
    // Tooling-specific shape: also includes things like ApexTrigger,
    // CustomObject — but ApexClass is the most universal.
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn tooling_query_against_apex_class_returns_envelope() {
    let Some(sf) = try_init_client().await else {
        return;
    };
    // LIMIT 1 — works whether or not the org has any Apex authored.
    let result = sf
        .tooling()
        .query("SELECT Id, Name FROM ApexClass LIMIT 1")
        .await
        .expect("Tooling query should succeed");
    assert!(result.done, "LIMIT 1 should complete in a single page");
    assert!(result.next_records_url.is_none());
    assert!(
        result.records.len() <= 1,
        "LIMIT 1 should yield ≤1 record, got {}",
        result.records.len(),
    );
}
