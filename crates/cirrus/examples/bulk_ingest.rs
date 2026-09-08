#![allow(clippy::print_stdout)]
//! Bulk API 2.0 CSV ingest: create job → upload CSV → close → poll → results.
//!
//! Inserts three Accounts via the Bulk API rather than three separate REST
//! calls. The SDK exposes the building blocks; you choose the poll cadence
//! (Salesforce processes ingests asynchronously and the right interval
//! depends on payload size).
//!
//! Run:
//!
//! ```bash
//! export SF_INSTANCE_URL=https://your-org.develop.my.salesforce.com
//! export SF_ACCESS_TOKEN=00D...!AQ...
//! cargo run --example bulk_ingest
//! ```

use cirrus::Cirrus;
use cirrus::auth::StaticTokenAuth;
use cirrus::{BulkIngestSpec, BulkJobState, BulkOperation};
use std::sync::Arc;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Arc::new(StaticTokenAuth::new(
        std::env::var("SF_ACCESS_TOKEN")?,
        std::env::var("SF_INSTANCE_URL")?,
    ));
    let sf = Cirrus::builder().auth(auth).build()?;
    let bulk = sf.bulk();
    let ingest = bulk.ingest();

    let spec = BulkIngestSpec {
        object: Some("Account".into()),
        operation: BulkOperation::Insert,
        external_id_field_name: None,
        line_ending: None,
        column_delimiter: None,
        assignment_rule_id: None,
    };
    let job = ingest.create(&spec).await?;
    println!("created job: id={}, state={:?}", job.id, job.state);

    // Salesforce requires the CSV to have a header row matching the
    // sObject field names.
    let csv = "Name,Description\n\
               cirrus-bulk-1,from bulk example\n\
               cirrus-bulk-2,from bulk example\n\
               cirrus-bulk-3,from bulk example\n";
    ingest.upload(&job.id, bytes::Bytes::from(csv)).await?;
    println!("uploaded {} bytes of CSV", csv.len());

    ingest.close(&job.id).await?;
    println!("closed job; polling for completion...");

    // Poll until terminal. Bounded loop so a stuck job won't hang
    // forever — adjust the cap for larger payloads.
    let mut current = ingest.get(&job.id).await?;
    for _ in 0..20 {
        match current.state {
            BulkJobState::JobComplete | BulkJobState::Failed | BulkJobState::Aborted => break,
            _ => {
                tokio::time::sleep(Duration::from_secs(2)).await;
                current = ingest.get(&job.id).await?;
            }
        }
    }
    println!(
        "final state: {:?}, processed={:?}, failed={:?}",
        current.state, current.number_records_processed, current.number_records_failed,
    );

    Ok(())
}
