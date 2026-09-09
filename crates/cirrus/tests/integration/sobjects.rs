//! sObject CRUD integration tests — exercise the full
//! create → retrieve → update → delete cycle against a real org.
//!
//! Uses `Account` because it's universally available on every org
//! edition and has no required custom fields. Each test tags its
//! records with a unique marker (`cirrus-it-{nanos}`) in the
//! `Name` field so:
//!
//! - Concurrent test runs don't collide on each other's records.
//! - Failed-cleanup leftovers are identifiable in case manual cleanup
//!   becomes necessary.
//!
//! **Always run serially (`-j 1`)** — see top-level integration
//! test docs. Even with unique markers, paralleling these saturates
//! the API quota faster than it needs to.
//!
//! Cleanup is best-effort via an RAII guard so a panic mid-test still
//! deletes the record. Salesforce's REST API tolerates double-deletes
//! (returns 404), so re-runs are idempotent.

use crate::common::try_init_client;
use cirrus::Cirrus;
use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};

/// Produces a unique-enough record name for a test run. Salesforce's
/// `Name` field on Account is 255 chars max — well within budget.
fn unique_name(test: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("cirrus-it-{test}-{nanos}")
}

/// RAII cleanup guard. On drop, attempts a best-effort delete of the
/// given Account id. Uses `tokio::runtime::Handle::current()` via
/// `block_in_place` is overkill here — we instead spawn into the
/// current runtime via a blocking send.
struct AccountCleanup<'a> {
    sf: &'a Cirrus,
    id: Option<String>,
}

impl<'a> AccountCleanup<'a> {
    fn new(sf: &'a Cirrus, id: String) -> Self {
        Self { sf, id: Some(id) }
    }

    /// Disarm the guard — call this after an explicit successful
    /// delete so the destructor doesn't try a second time.
    fn disarm(&mut self) {
        self.id = None;
    }
}

impl Drop for AccountCleanup<'_> {
    fn drop(&mut self) {
        if let Some(id) = self.id.take() {
            // Best-effort delete on drop. We're inside a sync Drop, so
            // we have to bridge to async. block_in_place + spawn is
            // the standard trick for in-Drop cleanup within #[tokio::test].
            let sf = self.sf.clone();
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    if let Err(e) = sf.sobject("Account").delete(&id).await {
                        eprintln!(
                            "cleanup warning: failed to delete Account {id}: {e} \
                             (will need manual cleanup)",
                        );
                    }
                });
            });
        }
    }
}

#[derive(Deserialize)]
struct AccountRow {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Description")]
    description: Option<String>,
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn account_full_crud_cycle() {
    let Some(sf) = try_init_client().await else {
        return;
    };
    let accounts = sf.sobject("Account");

    // ─── CREATE ───
    let name = unique_name("crud");
    let created = accounts
        .create(&serde_json::json!({
            "Name": &name,
            "Description": "initial",
        }))
        .await
        .expect("create should succeed");
    assert!(created.success, "create response should report success");
    assert!(
        created.id.starts_with("001"),
        "Account IDs start with 001 prefix, got {}",
        created.id,
    );
    assert!(
        created.errors.is_empty(),
        "create should have empty error array on success, got {:?}",
        created.errors,
    );

    let mut cleanup = AccountCleanup::new(&sf, created.id.clone());

    // ─── RETRIEVE (typed) ───
    let row: AccountRow = accounts
        .retrieve_with_fields_as(&created.id, &["Id", "Name", "Description"])
        .await
        .expect("retrieve should succeed");
    assert_eq!(row.id, created.id);
    assert_eq!(row.name, name);
    assert_eq!(row.description.as_deref(), Some("initial"));

    // ─── UPDATE ───
    accounts
        .update(
            &created.id,
            &serde_json::json!({ "Description": "updated" }),
        )
        .await
        .expect("update should succeed");

    let after_update: AccountRow = accounts
        .retrieve_with_fields_as(&created.id, &["Id", "Name", "Description"])
        .await
        .expect("post-update retrieve should succeed");
    assert_eq!(
        after_update.description.as_deref(),
        Some("updated"),
        "Description should reflect the update",
    );
    assert_eq!(
        after_update.name, name,
        "Name should be unchanged by a partial PATCH",
    );

    // ─── DELETE ───
    accounts
        .delete(&created.id)
        .await
        .expect("delete should succeed");
    cleanup.disarm(); // we deleted explicitly; don't double-delete on drop

    // Verify the record really is gone — retrieve should now 404.
    let after_delete = accounts.retrieve(&created.id).await;
    assert!(
        after_delete.is_err(),
        "retrieving a deleted Account should fail, got Ok({:?})",
        after_delete.ok(),
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn account_retrieve_untyped_returns_value() {
    // Validates the default Value-returning retrieve path against a
    // real record. Distinct from the typed-deserialization variant in
    // case the underlying wire shape ever drifts.
    let Some(sf) = try_init_client().await else {
        return;
    };
    let accounts = sf.sobject("Account");
    let name = unique_name("untyped");

    let created = accounts
        .create(&serde_json::json!({ "Name": &name }))
        .await
        .unwrap();
    let mut cleanup = AccountCleanup::new(&sf, created.id.clone());

    let value = accounts.retrieve(&created.id).await.unwrap();
    let obj = value
        .as_object()
        .expect("Account retrieve returns a JSON object");
    assert_eq!(
        obj.get("Id").and_then(|v| v.as_str()),
        Some(created.id.as_str()),
    );
    assert_eq!(
        obj.get("Name").and_then(|v| v.as_str()),
        Some(name.as_str())
    );
    // Salesforce always emits the `attributes` envelope on a single-record retrieve.
    assert!(
        obj.contains_key("attributes"),
        "single-record retrieve should include attributes envelope",
    );

    accounts.delete(&created.id).await.unwrap();
    cleanup.disarm();
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn describe_global_returns_account() {
    // Validates DescribeGlobal deserialization against a real org —
    // every org has Account, so this is a stable assertion.
    let Some(sf) = try_init_client().await else {
        return;
    };
    let dg = sf.sobjects().describe_global().await.unwrap();
    assert!(
        dg.sobjects.iter().any(|s| s.name == "Account"),
        "DescribeGlobal should include Account",
    );
    assert!(
        !dg.encoding.is_empty(),
        "encoding field should be populated, got empty string",
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn describe_per_object_returns_fields() {
    // Validates per-object describe — Account always has Name and Id.
    let Some(sf) = try_init_client().await else {
        return;
    };
    let v = sf.sobject("Account").describe().await.unwrap();
    let fields = v
        .get("fields")
        .and_then(|f| f.as_array())
        .expect("describe response should have a fields array");
    let field_names: Vec<&str> = fields
        .iter()
        .filter_map(|f| f.get("name").and_then(|n| n.as_str()))
        .collect();
    assert!(
        field_names.contains(&"Id"),
        "Account.describe should include Id; got {field_names:?}",
    );
    assert!(
        field_names.contains(&"Name"),
        "Account.describe should include Name; got {field_names:?}",
    );
}
