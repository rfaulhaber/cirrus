//! Integration-test harness — env loading, client construction, safety
//! guards.
//!
//! Every integration test calls [`try_init_client`] at the top. It
//! returns `Some(Cirrus)` when fully configured, `None` (with a
//! human-readable skip message) when env vars aren't set. Tests that
//! get `None` should `return` immediately so they pass cleanly without
//! hitting the network.
//!
//! # Required environment
//!
//! ```text
//! CIRRUS_INTEGRATION=1
//! CIRRUS_INTEGRATION_INSTANCE_URL=https://your-org.{sandbox,develop,scratch}.my.salesforce.com
//! ```
//!
//! Plus *one of*:
//!
//! - `CIRRUS_INTEGRATION_ACCESS_TOKEN=...` — static-token mode
//!   (paste from `sf org display`)
//! - **JWT bearer mode** — all four required:
//!   - `CIRRUS_INTEGRATION_USERNAME=...`
//!   - `CIRRUS_INTEGRATION_CONSUMER_KEY=...`
//!   - `CIRRUS_INTEGRATION_PRIVATE_KEY_PATH=...`
//!   - `CIRRUS_INTEGRATION_LOGIN_URL=...` — `https://login.salesforce.com`
//!     for Developer Edition and production-tier login; for a sandbox or
//!     scratch org, that org's own My Domain login URL
//!
//! Variables can come from a `.env` file at the project root or from
//! the shell. Shell takes precedence. `.env` should be gitignored —
//! see `.env.example` in the repo root.
//!
//! # Safety: URL pattern guard
//!
//! Refuses to run unless the configured `INSTANCE_URL` matches a
//! known sandbox/dev/scratch My Domain pattern (per [Salesforce's
//! Enhanced Domains][enh] documentation):
//!
//! - `.sandbox.my.salesforce.com` — sandboxes
//! - `.develop.my.salesforce.com` — Trailhead Playgrounds, newer dev orgs
//! - `.scratch.my.salesforce.com` — scratch orgs (sfdx CLI)
//! - `.trailblaze.my.salesforce.com` — free Developer Edition orgs from
//!   the developer.salesforce.com signup flow (subdomain ends in `-dev-ed`)
//!
//! Anything else (including legacy pre-Enhanced-Domains URLs and
//! production My Domains) requires `CIRRUS_INTEGRATION_FORCE=1`
//! to override. Set this only when you've verified the target org is
//! safe for destructive write operations.
//!
//! [enh]: https://help.salesforce.com/s/articleView?id=000393816

#![allow(dead_code)] // helper functions used by sibling test modules

use cirrus::Cirrus;
use cirrus::auth::{JwtAuth, SharedAuth, StaticTokenAuth};
use std::sync::{Arc, Once};

pub(crate) const ENV_ENABLED: &str = "CIRRUS_INTEGRATION";
pub(crate) const ENV_INSTANCE_URL: &str = "CIRRUS_INTEGRATION_INSTANCE_URL";
pub(crate) const ENV_ACCESS_TOKEN: &str = "CIRRUS_INTEGRATION_ACCESS_TOKEN";
pub(crate) const ENV_USERNAME: &str = "CIRRUS_INTEGRATION_USERNAME";
pub(crate) const ENV_CONSUMER_KEY: &str = "CIRRUS_INTEGRATION_CONSUMER_KEY";
pub(crate) const ENV_PRIVATE_KEY_PATH: &str = "CIRRUS_INTEGRATION_PRIVATE_KEY_PATH";
pub(crate) const ENV_LOGIN_URL: &str = "CIRRUS_INTEGRATION_LOGIN_URL";
pub(crate) const ENV_FORCE: &str = "CIRRUS_INTEGRATION_FORCE";

/// Known-safe partition infixes for sandbox/dev/scratch orgs (with
/// Enhanced Domains, the current standard since Spring '23).
///
/// `.trailblaze.` is the partition for free Developer Edition orgs
/// created via the developer.salesforce.com signup flow — their
/// subdomain ends in `-dev-ed` and they're explicitly for testing.
const SAFE_PARTITIONS: &[&str] = &[
    ".sandbox.my.salesforce.com",
    ".develop.my.salesforce.com",
    ".scratch.my.salesforce.com",
    ".trailblaze.my.salesforce.com",
];

/// Returns true if the URL matches a known-safe sandbox/dev/scratch
/// pattern. Used to gate write-capable integration tests away from
/// production My Domains.
///
/// The check is anchored to the parsed URL's host — a plain substring
/// match over the whole URL would let a production instance through if
/// a safe-partition string appeared in the path or query.
pub fn is_safe_test_url(url: &str) -> bool {
    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };
    let Some(host) = parsed.host_str() else {
        return false;
    };
    SAFE_PARTITIONS.iter().any(|p| host.ends_with(p))
}

/// Loads a `.env` from the project root once per test process. Idempotent.
fn load_dotenv() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // Best-effort: missing .env is fine, env-only mode also works.
        let _ = dotenvy::dotenv();
    });
}

/// Tries to construct a [`Cirrus`] from environment configuration.
///
/// - Returns `Some(client)` if fully configured.
/// - Returns `None` with a stderr skip message if env vars aren't set
///   or if the URL fails the safety guard. Tests should `return` on
///   `None`.
///
/// **Don't** unwrap or panic on `None` — that would defeat the
/// "tests pass cleanly when unconfigured" property.
pub async fn try_init_client() -> Option<Cirrus> {
    load_dotenv();

    if std::env::var(ENV_ENABLED).ok().as_deref() != Some("1") {
        eprintln!("skipping: set {ENV_ENABLED}=1 (and other CIRRUS_INTEGRATION_* vars) to enable",);
        return None;
    }

    let Ok(instance_url) = std::env::var(ENV_INSTANCE_URL) else {
        eprintln!("skipping: {ENV_INSTANCE_URL} not set");
        return None;
    };

    let force = std::env::var(ENV_FORCE).ok().as_deref() == Some("1");
    if !is_safe_test_url(&instance_url) && !force {
        eprintln!(
            "REFUSING TO RUN: {ENV_INSTANCE_URL} ({instance_url}) doesn't match a known \
             sandbox/dev/scratch pattern. Expected one of: \
             *.sandbox.my.salesforce.com, *.develop.my.salesforce.com, \
             *.scratch.my.salesforce.com, *.trailblaze.my.salesforce.com. \
             Set {ENV_FORCE}=1 to override — but verify the org is safe \
             for destructive writes first.",
        );
        return None;
    }

    let auth = build_auth(&instance_url).await?;

    let client = Cirrus::builder()
        .auth(auth)
        .build()
        .expect("constructing Cirrus from valid env should not fail");
    Some(client)
}

async fn build_auth(instance_url: &str) -> Option<SharedAuth> {
    // Prefer static token if set — fastest bootstrap, doesn't exercise
    // a flow but most contributors will have one handy via `sf org display`.
    if let Ok(token) = std::env::var(ENV_ACCESS_TOKEN) {
        let auth = StaticTokenAuth::new(token, instance_url);
        return Some(Arc::new(auth));
    }

    // Otherwise try JWT bearer flow — exercises our full auth flow,
    // requires more setup (connected app + cert).
    let username = std::env::var(ENV_USERNAME).ok()?;
    let consumer_key = std::env::var(ENV_CONSUMER_KEY).ok()?;
    let private_key_path = std::env::var(ENV_PRIVATE_KEY_PATH).ok()?;
    let login_url = std::env::var(ENV_LOGIN_URL).ok()?;

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
    Some(Arc::new(auth))
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
        // Free Developer Edition orgs from developer.salesforce.com
        // signup use the .trailblaze. partition with a -dev-ed subdomain.
        assert!(is_safe_test_url(
            "https://cunning-bear-jezk1j-dev-ed.trailblaze.my.salesforce.com"
        ));
    }

    #[test]
    fn url_classifier_refuses_production_my_domain() {
        assert!(!is_safe_test_url("https://acme.my.salesforce.com"));
    }

    #[test]
    fn url_classifier_refuses_legacy_sandbox_url() {
        // Pre-Enhanced-Domains sandbox URLs lack the .sandbox. infix.
        // Treat as production and require explicit override.
        assert!(!is_safe_test_url(
            "https://acme--sandbox1.my.salesforce.com"
        ));
    }

    #[test]
    fn url_classifier_refuses_unrelated_hosts() {
        assert!(!is_safe_test_url("https://example.com"));
        assert!(!is_safe_test_url("https://localhost"));
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
            "https://acme.my.salesforce.com/.sandbox.my.salesforce.com"
        ));
        assert!(!is_safe_test_url(
            "https://acme.my.salesforce.com.sandbox.my.salesforce.evil.example"
        ));
    }
}
