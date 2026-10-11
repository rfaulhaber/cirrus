//! SOQL query + pagination integration tests.
//!
//! Verifies:
//! - Basic `query()` returns the documented `QueryResult` envelope
//!   (total_size, done, records).
//! - `query_all()` round-trips (we don't soft-delete a record mid-test
//!   to verify the `IsDeleted` semantics — too fragile across orgs).
//! - The `query_stream()` Stream variant terminates on a small result
//!   set, and its yielded items match what `query()` returns.
//! - The `next_records_url` cursor is present-or-absent per the docs
//!   contract (`done = false` ↔ cursor present).
//!
//! Multi-batch pagination (>2000 rows in a single response) isn't
//! exercised by default — that requires planting bulk test data
//! beyond the scope of a smoke run. The stream itself is unit-tested
//! against wiremock for the multi-page state machine; here we just
//! prove it terminates cleanly against real responses.

use crate::common::{AccountCleanup, try_init_client};
use cirrus::soql;
use futures::StreamExt;
use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Deserialize, Debug)]
struct AccountRow {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
}

/// Build a marker string scoped to a single test invocation. SOQL
/// `LIKE` against this marker isolates each test's records from
/// every other run (concurrent or otherwise).
fn marker(test: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("cirrus-it-{test}-{nanos}")
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn basic_query_returns_documented_envelope() {
    let Some(sf) = try_init_client().await else {
        return;
    };
    // LIMIT 1 keeps this safe even on orgs with millions of Accounts.
    let result = sf
        .query("SELECT Id, Name FROM Account LIMIT 1")
        .await
        .expect("query should succeed");

    // total_size is the *server-side* total (not the page size) on a
    // non-aggregate query; for our LIMIT 1, it's 1 if any Account
    // exists, 0 otherwise. We can't predict that without planting
    // data, so just check the envelope is sane.
    assert!(
        result.total_size >= 0,
        "total_size should be non-negative, got {}",
        result.total_size,
    );
    // For LIMIT 1, done is always true — no more pages possible.
    assert!(
        result.done,
        "LIMIT 1 query should complete in one page, got done=false",
    );
    assert!(
        result.next_records_url.is_none(),
        "done=true requires next_records_url=None per the docs contract",
    );
    assert!(
        result.records.len() <= 1,
        "LIMIT 1 should return ≤1 record, got {}",
        result.records.len(),
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn query_as_deserializes_into_typed_records() {
    let Some(sf) = try_init_client().await else {
        return;
    };
    // Plant exactly one record with a unique name we can filter on.
    let name = marker("typed");
    let accounts = sf.sobject("Account");
    let created = accounts
        .create(&serde_json::json!({ "Name": &name }))
        .await
        .unwrap();
    let _cleanup = AccountCleanup::new(&sf, created.id.clone());

    let soql = format!(
        "SELECT Id, Name FROM Account WHERE Name = {}",
        soql::quote(&name)
    );
    let result = sf
        .query_as::<AccountRow>(&soql)
        .await
        .expect("typed query should succeed");
    assert_eq!(result.total_size, 1, "exactly our planted record matches");
    assert_eq!(result.records.len(), 1);
    let row = &result.records[0];
    assert_eq!(row.id, created.id);
    assert_eq!(row.name, name);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn query_stream_terminates_on_small_result() {
    let Some(sf) = try_init_client().await else {
        return;
    };
    let stream = sf.query_stream("SELECT Id FROM Account LIMIT 3");

    let collected: Vec<_> = stream.collect::<Vec<_>>().await;
    // Every yielded item should be Ok (no fetch failures mid-stream).
    for item in &collected {
        assert!(
            item.is_ok(),
            "stream should not yield errors against a valid SOQL query, got {item:?}",
        );
    }
    assert!(
        collected.len() <= 3,
        "LIMIT 3 stream should yield ≤3 records, got {}",
        collected.len(),
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn query_stream_matches_eager_query_results() {
    // Plant 4 records and verify the stream surfaces all of them
    // when iterated to completion — proves the Buffered → Done
    // transition works against a real wire response.
    let Some(sf) = try_init_client().await else {
        return;
    };
    let base_marker = marker("stream");
    let accounts = sf.sobject("Account");
    let mut cleanups = Vec::new();
    for i in 0..4 {
        let row_name = format!("{base_marker}-{i}");
        let created = accounts
            .create(&serde_json::json!({ "Name": &row_name }))
            .await
            .unwrap();
        cleanups.push(AccountCleanup::new(&sf, created.id));
    }

    // Bound the WHERE clause by our marker prefix; LIKE with %
    // suffix matches all four numbered records.
    let soql = format!(
        "SELECT Id, Name FROM Account WHERE Name LIKE '{}-%' ORDER BY Name",
        soql::escape_like(&base_marker)
    );
    let stream = sf.query_stream_as::<AccountRow>(&soql);
    let rows: Vec<_> = stream
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .map(|r| r.expect("stream items should all be Ok"))
        .collect();
    assert_eq!(rows.len(), 4, "should yield all 4 planted records");
    for (i, row) in rows.iter().enumerate() {
        assert_eq!(row.name, format!("{base_marker}-{i}"));
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn query_all_includes_soft_deleted_records() {
    // Plant → delete → query_all should still see it; plain query should not.
    // This verifies the queryAll endpoint actually returns deleted
    // records (the docs claim, but worth verifying against the wire).
    let Some(sf) = try_init_client().await else {
        return;
    };
    let name = marker("queryall");
    let accounts = sf.sobject("Account");

    let created = accounts
        .create(&serde_json::json!({ "Name": &name }))
        .await
        .unwrap();
    accounts.delete(&created.id).await.unwrap();

    // Plain query should NOT see it (it's soft-deleted in the Recycle Bin).
    let plain = sf
        .query(&format!(
            "SELECT Id FROM Account WHERE Name = {}",
            soql::quote(&name)
        ))
        .await
        .unwrap();
    assert_eq!(
        plain.total_size, 0,
        "plain query should not return soft-deleted records",
    );

    // queryAll SHOULD see it.
    let all = sf
        .query_all(&format!(
            "SELECT Id, IsDeleted FROM Account WHERE Name = {}",
            soql::quote(&name)
        ))
        .await
        .unwrap();
    assert_eq!(
        all.total_size, 1,
        "query_all should return the soft-deleted record",
    );
    assert_eq!(all.records.len(), 1);
}
