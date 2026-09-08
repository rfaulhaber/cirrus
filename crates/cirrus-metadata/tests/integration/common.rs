//! Integration-test harness — env loading, client construction, safety
//! guards.
//!
//! Mirrors `crates/cirrus/tests/integration/common.rs` so the cirrus,
//! cirrus-auth, and cirrus-metadata integration suites share a single
//! `.env` and the same environment-variable contract.
//!
//! # Required environment
//!
//! ```text
//! CIRRUS_INTEGRATION=1
//! CIRRUS_INTEGRATION_INSTANCE_URL=https://your-org.{sandbox,develop,scratch,trailblaze}.my.salesforce.com
//! ```
//!
//! Plus *one of*:
//!
//! - `CIRRUS_INTEGRATION_ACCESS_TOKEN=...` — static-token mode
//! - **JWT bearer mode** — all four required:
//!   - `CIRRUS_INTEGRATION_USERNAME=...`
//!   - `CIRRUS_INTEGRATION_CONSUMER_KEY=...`
//!   - `CIRRUS_INTEGRATION_PRIVATE_KEY_PATH=...`
//!   - `CIRRUS_INTEGRATION_LOGIN_URL=...`
//!
//! See `.env.example` at the repo root for the template.
//!
//! `INSTANCE_URL` and `LOGIN_URL` must both be `https`, and
//! `CIRRUS_INTEGRATION_FORCE=1` does not waive that — a bearer token or
//! a signed JWT assertion on a plaintext request is disclosed to the
//! network.

#![allow(dead_code)] // helper functions used by sibling test modules

use cirrus_auth::{JwtAuth, SharedAuth, StaticTokenAuth};
use cirrus_metadata::MetadataClient;
use std::sync::{Arc, Once};

pub(crate) const ENV_ENABLED: &str = "CIRRUS_INTEGRATION";
pub(crate) const ENV_INSTANCE_URL: &str = "CIRRUS_INTEGRATION_INSTANCE_URL";
pub(crate) const ENV_ACCESS_TOKEN: &str = "CIRRUS_INTEGRATION_ACCESS_TOKEN";
pub(crate) const ENV_USERNAME: &str = "CIRRUS_INTEGRATION_USERNAME";
pub(crate) const ENV_CONSUMER_KEY: &str = "CIRRUS_INTEGRATION_CONSUMER_KEY";
pub(crate) const ENV_PRIVATE_KEY_PATH: &str = "CIRRUS_INTEGRATION_PRIVATE_KEY_PATH";
pub(crate) const ENV_LOGIN_URL: &str = "CIRRUS_INTEGRATION_LOGIN_URL";
pub(crate) const ENV_FORCE: &str = "CIRRUS_INTEGRATION_FORCE";

const SAFE_PARTITIONS: &[&str] = &[
    ".sandbox.my.salesforce.com",
    ".develop.my.salesforce.com",
    ".scratch.my.salesforce.com",
    ".trailblaze.my.salesforce.com",
];

/// Requires `https` and anchors the host check to the parsed host —
/// substring matching over the whole URL would let a production instance
/// through if a safe-partition string appeared in the path or query.
pub fn is_safe_test_url(url: &str) -> bool {
    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };
    if parsed.scheme() != "https" {
        return false;
    }
    let Some(host) = parsed.host_str() else {
        return false;
    };
    SAFE_PARTITIONS.iter().any(|p| host.ends_with(p))
}

/// Every credential this harness handles — org session ids, signed JWT
/// assertions, the connected app's consumer key — is a bearer secret,
/// and RFC 6750 §5.3 requires TLS for any request that carries one.
fn requires_https(env_key: &str, url: &str) {
    let is_https = url::Url::parse(url).is_ok_and(|parsed| parsed.scheme() == "https");
    assert!(
        is_https,
        "{env_key} ({url}) must be an https URL — the credentials this \
         harness sends must not cross the network in the clear.",
    );
}

fn load_dotenv() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = dotenvy::dotenv();
    });
}

/// Constructs a [`MetadataClient`] from environment configuration.
///
/// Returns `None` (with a stderr skip message) when env vars aren't
/// set or the URL fails the safety guard. Tests should `return` on
/// `None` so they pass cleanly without hitting the network.
pub async fn try_init_client() -> Option<MetadataClient> {
    load_dotenv();

    if std::env::var(ENV_ENABLED).ok().as_deref() != Some("1") {
        eprintln!("skipping: set {ENV_ENABLED}=1 (and other CIRRUS_INTEGRATION_* vars) to enable",);
        return None;
    }

    let Ok(instance_url) = std::env::var(ENV_INSTANCE_URL) else {
        eprintln!("skipping: {ENV_INSTANCE_URL} not set");
        return None;
    };

    // `FORCE` waives the org classification below, never transport
    // security, so the scheme is checked separately from the safe-list.
    requires_https(ENV_INSTANCE_URL, &instance_url);

    let force = std::env::var(ENV_FORCE).ok().as_deref() == Some("1");
    if !is_safe_test_url(&instance_url) && !force {
        eprintln!(
            "REFUSING TO RUN: {ENV_INSTANCE_URL} ({instance_url}) doesn't match a known \
             https sandbox/dev/scratch pattern. Set {ENV_FORCE}=1 to override the host \
             check — but verify the org is safe for destructive writes first.",
        );
        return None;
    }

    let auth = build_auth(&instance_url).await?;

    let client = MetadataClient::builder()
        .auth(auth)
        .build()
        .expect("constructing MetadataClient from valid env should not fail");
    Some(client)
}

async fn build_auth(instance_url: &str) -> Option<SharedAuth> {
    if let Ok(token) = std::env::var(ENV_ACCESS_TOKEN) {
        let shared: SharedAuth = Arc::new(StaticTokenAuth::new(token, instance_url));
        return Some(shared);
    }

    let username = std::env::var(ENV_USERNAME).ok()?;
    let consumer_key = std::env::var(ENV_CONSUMER_KEY).ok()?;
    let private_key_path = std::env::var(ENV_PRIVATE_KEY_PATH).ok()?;
    let login_url = std::env::var(ENV_LOGIN_URL).ok()?;

    requires_https(ENV_LOGIN_URL, &login_url);

    let builder = match JwtAuth::builder()
        .consumer_key(consumer_key)
        .username(username)
        .login_url(login_url)
        .instance_url(instance_url)
        .private_key_pem_file(private_key_path.clone())
    {
        Ok(b) => b,
        Err(e) => {
            eprintln!(
                "skipping: failed to load private key from \
                 {ENV_PRIVATE_KEY_PATH} ({private_key_path}): {e}",
            );
            return None;
        }
    };

    let auth = match builder.build() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("skipping: JwtAuth construction failed: {e}");
            return None;
        }
    };
    let shared: SharedAuth = Arc::new(auth);
    Some(shared)
}

/// Produces a unique-enough fullName for a test run. Salesforce
/// component fullNames have varying length limits; CustomLabel and
/// ApexClass both tolerate 40+ chars.
///
/// Use this for `fullName` on created components and as a marker
/// substring so failed-cleanup leftovers are identifiable.
pub fn unique_name(test: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    // Salesforce component fullNames are restricted to
    // [A-Za-z][A-Za-z0-9_]* — keep the test marker alphanumeric and
    // strip any path separators.
    let safe_test: String = test
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    format!("CirrusIt_{safe_test}_{nanos}")
}

#[cfg(test)]
mod tests {
    use super::is_safe_test_url;

    #[test]
    fn url_classifier_accepts_known_safe_partitions() {
        assert!(is_safe_test_url(
            "https://acme--sandbox1.sandbox.my.salesforce.com"
        ));
        assert!(is_safe_test_url(
            "https://my-trailhead-playground.develop.my.salesforce.com"
        ));
        assert!(is_safe_test_url(
            "https://test-7emx29.scratch.my.salesforce.com"
        ));
        assert!(is_safe_test_url(
            "https://cunning-bear-jezk1j-dev-ed.trailblaze.my.salesforce.com"
        ));
    }

    #[test]
    fn url_classifier_refuses_plaintext_http() {
        assert!(!is_safe_test_url("http://acme.develop.my.salesforce.com"));
        assert!(!is_safe_test_url(
            "http://acme--sandbox1.sandbox.my.salesforce.com"
        ));
    }

    #[test]
    fn url_classifier_refuses_production_my_domain() {
        assert!(!is_safe_test_url("https://acme.my.salesforce.com"));
        // Pre-Enhanced-Domains sandbox URLs lack the .sandbox. infix.
        assert!(!is_safe_test_url(
            "https://acme--sandbox1.my.salesforce.com"
        ));
    }

    #[test]
    fn url_classifier_refuses_safe_partition_outside_host() {
        // The safe-partition string appearing in the path, query, or a
        // deceptive subdomain prefix must not satisfy the guard — only
        // the actual host counts.
        assert!(!is_safe_test_url(
            "https://acme.my.salesforce.com/?x=.sandbox.my.salesforce.com"
        ));
        assert!(!is_safe_test_url(
            "https://acme.my.salesforce.com.sandbox.my.salesforce.evil.example"
        ));
    }
}
