//! Composite API integration tests — exercise the multi-call
//! batching endpoints against a real org.
//!
//! Covers:
//! - `composite/sobjects` create + delete (Salesforce's "SObject
//!   Collections" — bulk-create up to 200 records per call).
//! - `composite/batch` — heterogeneous subrequests that run in order and
//!   commit independently; a later failure never rolls back an earlier
//!   subrequest. All-or-nothing behaviour is `/composite` with
//!   `allOrNone: true`.
//!
//! Doesn't cover (deferred):
//! - `composite/tree` — requires constructing a referenced-record graph
//!   that's not interesting until we add a use case in the SDK examples.
//! - Full `/composite` chained-reference endpoint — large surface,
//!   moderate-frequency use; can be added later when there's a real
//!   regression to guard against.

use crate::common::{AccountCleanup, try_init_client};
use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};

fn marker(test: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("cirrus-it-{test}-{nanos}")
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn composite_sobjects_create_then_delete() {
    let Some(sf) = try_init_client().await else {
        return;
    };
    let base = marker("composite-create");
    // SObject Collections require the `attributes.type` envelope on each record.
    let body = serde_json::json!({
        "allOrNone": false,
        "records": [
            { "attributes": { "type": "Account" }, "Name": format!("{base}-0") },
            { "attributes": { "type": "Account" }, "Name": format!("{base}-1") },
            { "attributes": { "type": "Account" }, "Name": format!("{base}-2") },
        ]
    });

    let results = sf
        .composite()
        .sobjects()
        .create(&body)
        .await
        .expect("composite create should succeed");
    let ids: Vec<String> = results.iter().filter_map(|r| r.id.clone()).collect();
    let mut cleanups: Vec<_> = ids
        .iter()
        .map(|id| AccountCleanup::new(&sf, id.clone()))
        .collect();

    assert_eq!(results.len(), 3, "should get one result per input record");
    for r in &results {
        assert!(r.success, "all three creates should succeed: {r:?}");
        assert!(r.errors.is_empty(), "successful creates have empty errors");
        let id = r.id.as_deref().expect("successful create has id");
        assert!(
            id.starts_with("001"),
            "Account IDs start with 001, got {id}"
        );
    }

    // Now delete them via composite — exercises the delete variant too.
    let del_results = sf
        .composite()
        .sobjects()
        .delete(&ids, false)
        .await
        .expect("composite delete should succeed");
    assert_eq!(del_results.len(), 3, "one result per id");
    for r in &del_results {
        assert!(r.success, "all deletes should succeed: {r:?}");
    }
    for cleanup in &mut cleanups {
        cleanup.disarm();
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn composite_batch_with_versions_and_limits() {
    // Two unrelated subrequests in a single round-trip. Uses GET-only
    // subrequests so the test doesn't depend on plant-and-cleanup
    // scaffolding. Verifies the `BatchResponse` envelope shape end-to-end.
    let Some(sf) = try_init_client().await else {
        return;
    };
    let api_version = sf.api_version().to_string();
    let body = serde_json::json!({
        "batchRequests": [
            { "method": "GET", "url": format!("{api_version}/limits") },
            { "method": "GET", "url": format!("{api_version}/sobjects/Account/describe") },
        ]
    });

    let response = sf
        .composite()
        .batch(&body)
        .await
        .expect("composite batch should succeed");
    assert!(
        !response.has_errors,
        "GET-only subrequests should not error"
    );
    assert_eq!(
        response.results.len(),
        2,
        "should get one result per subrequest",
    );

    // Each subresult has a status_code and result. We can't strongly
    // type the inner result without modeling every endpoint, so verify
    // the shape via serde_json::Value.
    for sub in &response.results {
        assert_eq!(
            sub.status_code, 200,
            "GET should return 200, got {}",
            sub.status_code
        );
    }
}

#[derive(Deserialize)]
struct IdEnvelope {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn composite_sobjects_retrieve_typed() {
    // Plant a record, then use composite/sobjects retrieve to fetch
    // it back as a typed shape. Verifies the typed-retrieve variant
    // doesn't drop fields or break on the `attributes` envelope.
    let Some(sf) = try_init_client().await else {
        return;
    };
    let name = marker("composite-retrieve");
    let accounts = sf.sobject("Account");
    let created = accounts
        .create(&serde_json::json!({ "Name": &name }))
        .await
        .unwrap();
    let id = created.id.clone();
    let _cleanup = AccountCleanup::new(&sf, created.id);

    let rows: Vec<IdEnvelope> = sf
        .composite()
        .sobjects()
        .retrieve_as("Account", &[&id], &["Id", "Name"])
        .await
        .expect("composite retrieve_as should succeed");
    assert_eq!(rows.len(), 1, "asked for one id, expect one row");
    assert_eq!(rows[0].id, id);
    assert_eq!(rows[0].name, name);
}
