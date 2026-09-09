//! CustomLabel CRUD integration test — create → read → update → delete
//! cycle against a real org via the SOAP Metadata API.
//!
//! Why CustomLabel? It's:
//! - Universally available on every edition (no setup required).
//! - The simplest mutable component — three required fields
//!   (`fullName`, `value`, `language`), no compilation step, no
//!   references to other components.
//! - Cheap to delete cleanly (no cascade considerations).
//!
//! Each test tags its component with a unique `fullName`
//! (`CirrusIt_…_{nanos}`) so:
//! - Concurrent test runs don't collide.
//! - Failed-cleanup leftovers are identifiable.
//!
//! Cleanup runs via an RAII guard so a panic mid-test still attempts
//! a delete. `deleteMetadata` returns one `DeleteResult` per component
//! carrying `success` and `errors` — a refused delete is a non-fault
//! response, not an error — so the guard has to inspect both. Deleting
//! a non-existent component lands there too (`success: false` with an
//! `INVALID_CROSS_REFERENCE_KEY` error), which is why re-running is
//! idempotent.
//!
//! SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_deleteMetadata.htm

use crate::common::{try_init_client, unique_name};
use cirrus_metadata::MetadataClient;
use serde::Deserialize;

const TYPE_NAME: &str = "CustomLabel";

/// Inner XML of a `<metadata>` element for a CustomLabel.
fn render_custom_label(full_name: &str, value: &str) -> String {
    // Field order matches the Salesforce-published schema; `xml_escape`
    // would belong here if we ever interpolated user-supplied
    // metadata, but full_name and value are test-controlled so we
    // assume valid characters.
    format!(
        "<fullName>{full_name}</fullName>\
         <categories>cirrus-it</categories>\
         <language>en_US</language>\
         <protected>false</protected>\
         <shortDescription>cirrus integration test</shortDescription>\
         <value>{value}</value>"
    )
}

/// Caller-shape for `readMetadata`-of-CustomLabel.
///
/// `full_name` is `Option<String>` even though the field is required
/// on a live component: Salesforce's `readMetadata` response includes
/// a placeholder `<records xsi:nil="true"/>` element when the
/// requested component doesn't exist (e.g. immediately after a
/// delete), and that placeholder deserializes into a record where
/// every field is missing. Callers must treat `full_name.is_some()`
/// as the "real result" signal.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CustomLabelRecord {
    #[serde(default)]
    full_name: Option<String>,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    language: Option<String>,
}

/// RAII cleanup guard. On drop, attempts a best-effort delete of the
/// CustomLabel `full_name`.
struct LabelCleanup<'a> {
    md: &'a MetadataClient,
    full_name: Option<String>,
}

impl<'a> LabelCleanup<'a> {
    fn new(md: &'a MetadataClient, full_name: String) -> Self {
        Self {
            md,
            full_name: Some(full_name),
        }
    }

    fn disarm(&mut self) {
        self.full_name = None;
    }
}

impl Drop for LabelCleanup<'_> {
    fn drop(&mut self) {
        if let Some(name) = self.full_name.take() {
            // Bridge sync Drop → async via the surrounding runtime.
            // Same pattern the cirrus sObject CRUD test uses.
            let md = self.md.clone();
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    match md.delete_metadata(TYPE_NAME, &[name.as_str()]).await {
                        Err(e) => eprintln!(
                            "cleanup warning: failed to delete CustomLabel {name}: {e} \
                             (will need manual cleanup)",
                        ),
                        Ok(results) => {
                            for result in results.iter().filter(|r| !r.success) {
                                eprintln!(
                                    "cleanup warning: org refused the delete of CustomLabel \
                                     {name}: {:?} (will need manual cleanup)",
                                    result.errors,
                                );
                            }
                        }
                    }
                });
            });
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn custom_label_full_crud_cycle() {
    let Some(md) = try_init_client().await else {
        return;
    };
    let name = unique_name("crud");

    // ─── CREATE ───
    let xml = render_custom_label(&name, "initial value");
    let results = md
        .create_metadata(TYPE_NAME, &[xml.as_str()])
        .await
        .expect("create_metadata should round-trip against a real org");
    assert_eq!(results.len(), 1, "one input → one SaveResult");
    let created = &results[0];
    assert!(
        created.success,
        "create_metadata failed for {name}: {:?}",
        created.errors,
    );
    assert_eq!(created.full_name, name);

    let mut cleanup = LabelCleanup::new(&md, name.clone());

    // ─── READ ───
    let records: Vec<CustomLabelRecord> = md
        .read_metadata(TYPE_NAME, &[name.as_str()])
        .await
        .expect("read_metadata should succeed");
    assert_eq!(records.len(), 1, "read_metadata should return one record");
    let read = &records[0];
    assert_eq!(read.full_name.as_deref(), Some(name.as_str()));
    assert_eq!(
        read.value.as_deref(),
        Some("initial value"),
        "round-tripped value should match what we created",
    );
    assert_eq!(read.language.as_deref(), Some("en_US"));

    // ─── UPDATE ───
    let updated_xml = render_custom_label(&name, "updated value");
    let results = md
        .update_metadata(TYPE_NAME, &[updated_xml.as_str()])
        .await
        .expect("update_metadata should succeed");
    assert_eq!(results.len(), 1);
    assert!(
        results[0].success,
        "update_metadata failed for {name}: {:?}",
        results[0].errors,
    );

    // Confirm the update landed.
    let post_update: Vec<CustomLabelRecord> =
        md.read_metadata(TYPE_NAME, &[name.as_str()]).await.unwrap();
    assert_eq!(
        post_update[0].full_name.as_deref(),
        Some(name.as_str()),
        "post-update read should still resolve the component",
    );
    assert_eq!(
        post_update[0].value.as_deref(),
        Some("updated value"),
        "post-update read should reflect the new value",
    );

    // ─── DELETE ───
    let results = md
        .delete_metadata(TYPE_NAME, &[name.as_str()])
        .await
        .expect("delete_metadata should succeed");
    assert_eq!(results.len(), 1);
    assert!(
        results[0].success,
        "delete_metadata failed for {name}: {:?}",
        results[0].errors,
    );
    cleanup.disarm();

    // Confirm gone — read returns one placeholder record with every
    // field empty (the `xsi:nil="true"` shape — see CustomLabelRecord
    // docs). The "is the component still there?" signal is
    // `full_name.is_some()` after filtering nil placeholders.
    let post_delete: Vec<CustomLabelRecord> = md
        .read_metadata(TYPE_NAME, &[name.as_str()])
        .await
        .expect("read_metadata after delete should not error");
    let real: Vec<_> = post_delete
        .iter()
        .filter(|r| r.full_name.is_some())
        .collect();
    assert!(
        real.is_empty(),
        "deleted CustomLabel should not be readable; got {} live records",
        real.len(),
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn delete_metadata_for_unknown_full_name_returns_unsuccessful() {
    let Some(md) = try_init_client().await else {
        return;
    };
    // A name with the cirrus-it prefix that definitely doesn't exist
    // (random nanos suffix). The Metadata API returns a non-fault
    // response with `success: false` and a populated `errors` list —
    // *not* a SOAP fault. The point of this test is to confirm the
    // typed `DeleteResult` parser handles that response shape.
    let bogus = unique_name("missing");
    let results = md
        .delete_metadata(TYPE_NAME, &[bogus.as_str()])
        .await
        .expect("delete_metadata for missing component should not error");
    assert_eq!(results.len(), 1);
    assert!(
        !results[0].success,
        "delete of a missing component should not be reported as success",
    );
    assert!(
        !results[0].errors.is_empty(),
        "delete failure should carry at least one MetadataApiError",
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn upsert_metadata_inserts_then_updates() {
    // Exercises the upsertMetadata wire path on both branches of its
    // distinguishing `created` flag:
    //   1. First call → insert path → `created == true`.
    //   2. Second call on the same fullName with a different value →
    //      update path → `created == false`.
    //
    // Available in API v31+ — every supported org version covers this.
    let Some(md) = try_init_client().await else {
        return;
    };
    let name = unique_name("upsert");

    // ─── First upsert: INSERT ───
    let insert_xml = render_custom_label(&name, "first value");
    let results = md
        .upsert_metadata(TYPE_NAME, &[insert_xml.as_str()])
        .await
        .expect("upsert_metadata should round-trip against a real org");
    assert_eq!(results.len(), 1, "one input → one UpsertResult");
    let inserted = &results[0];
    assert!(
        inserted.success,
        "first upsert (insert path) failed for {name}: {:?}",
        inserted.errors,
    );
    assert_eq!(inserted.full_name, name);
    assert!(
        inserted.created,
        "first upsert of a fresh fullName should set created=true; \
         got created=false (suggests the component already existed)",
    );

    let mut cleanup = LabelCleanup::new(&md, name.clone());

    // ─── Second upsert: UPDATE ───
    let update_xml = render_custom_label(&name, "updated value");
    let results = md
        .upsert_metadata(TYPE_NAME, &[update_xml.as_str()])
        .await
        .expect("second upsert_metadata should succeed");
    assert_eq!(results.len(), 1);
    let updated = &results[0];
    assert!(
        updated.success,
        "second upsert (update path) failed for {name}: {:?}",
        updated.errors,
    );
    assert!(
        !updated.created,
        "second upsert on an existing fullName must set created=false; \
         server reported created=true (the insert-vs-update distinction is broken)",
    );

    // Verify the second value actually landed — `created=false` alone
    // could mean "no-op", so confirm the value mutated.
    let records: Vec<CustomLabelRecord> =
        md.read_metadata(TYPE_NAME, &[name.as_str()]).await.unwrap();
    assert_eq!(
        records[0].value.as_deref(),
        Some("updated value"),
        "post-upsert read should reflect the second value",
    );

    // Explicit cleanup so the test exits clean rather than relying
    // on the drop guard. Drop guards are for panic safety, not the
    // happy path. The guard stays armed until the delete is confirmed
    // successful — deleteMetadata reports a refused delete as
    // `success: false` rather than as an error.
    let results = md
        .delete_metadata(TYPE_NAME, &[name.as_str()])
        .await
        .expect("cleanup delete_metadata should succeed");
    assert_eq!(results.len(), 1);
    assert!(
        results[0].success,
        "cleanup delete_metadata failed for {name}: {:?}",
        results[0].errors,
    );
    cleanup.disarm();
}
