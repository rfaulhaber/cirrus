#![allow(clippy::print_stdout)]
//! Call a custom Apex REST endpoint at `/services/apexrest/MyEndpoint`.
//!
//! The Apex passthrough handler is a thin wrapper: path normalization +
//! the same auth / retry / Sforce-Limit-Info plumbing as every other
//! handler. Bodies and responses are entirely caller-defined — Apex
//! devs author the contract.
//!
//! Run (after deploying an Apex class with `@RestResource`):
//!
//! ```bash
//! export SF_INSTANCE_URL=https://your-org.develop.my.salesforce.com
//! export SF_ACCESS_TOKEN=00D...!AQ...
//! cargo run --example apex_passthrough
//! ```

use cirrus::Cirrus;
use cirrus::auth::StaticTokenAuth;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Serialize)]
struct Request {
    name: String,
}

#[derive(Deserialize)]
struct Response {
    greeting: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Arc::new(StaticTokenAuth::new(
        std::env::var("SF_ACCESS_TOKEN")?,
        std::env::var("SF_INSTANCE_URL")?,
    ));
    let sf = Cirrus::builder().auth(auth).build()?;

    // POST /services/apexrest/Hello with a JSON body, expecting a
    // {"greeting": "..."} response. Path normalization accepts both
    // "Hello" and "/Hello". The path is sent as written, so a segment
    // built from data is encoded first:
    // format!("Hello/{}", cirrus::encode_path_segment(name)).
    let req = Request {
        name: "world".into(),
    };
    let resp: Response = sf.apex().post("Hello", &req).await?;
    println!("{}", resp.greeting);

    Ok(())
}
