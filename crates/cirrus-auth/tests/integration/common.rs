//! Integration-test harness — env loading, auth construction, safety
//! guards.
//!
//! Mirrors `crates/cirrus/tests/integration/common.rs` so the two
//! crates share the same environment-variable contract. A single
//! `.env` at the repo root configures both test suites.
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
//! See `.env.example` at the repo root for the full template.
//!
//! With `CIRRUS_INTEGRATION=1` set, a missing or half-filled auth
//! configuration fails the run instead of skipping — a blank `KEY=`
//! counts as unset. Skipping there would report an all-green run that
//! made no calls.
//!
//! `INSTANCE_URL` and `LOGIN_URL` must both be `https`, and
//! `CIRRUS_INTEGRATION_FORCE=1` does not waive that — a bearer token or
//! a signed JWT assertion on a plaintext request is disclosed to the
//! network.

#![allow(dead_code)] // helper functions used by sibling test modules

use cirrus_auth::{JwtAuth, SharedAuth, StaticTokenAuth};
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

/// Reads an environment variable, treating a set-but-blank value as
/// unset. `KEY=` is the natural way to clear a stale value in a `.env`,
/// and it must not select the auth mode that variable belongs to.
fn env_var(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// The four variables the JWT bearer flow needs.
struct JwtConfig {
    username: String,
    consumer_key: String,
    private_key_path: String,
    login_url: String,
}

/// Reads the JWT block, or `None` when none of its variables is set.
///
/// A half-filled block fails the run instead of skipping: once
/// `CIRRUS_INTEGRATION=1` is set the operator has opted in, and a silent
/// skip reports an all-green run that exercised nothing.
fn jwt_config() -> Option<JwtConfig> {
    match (
        env_var(ENV_USERNAME),
        env_var(ENV_CONSUMER_KEY),
        env_var(ENV_PRIVATE_KEY_PATH),
        env_var(ENV_LOGIN_URL),
    ) {
        (Some(username), Some(consumer_key), Some(private_key_path), Some(login_url)) => {
            Some(JwtConfig {
                username,
                consumer_key,
                private_key_path,
                login_url,
            })
        }
        (None, None, None, None) => None,
        (username, consumer_key, private_key_path, login_url) => panic!(
            "JWT mode is only partially configured — missing or blank: {}. \
             All four of {ENV_USERNAME}, {ENV_CONSUMER_KEY}, \
             {ENV_PRIVATE_KEY_PATH} and {ENV_LOGIN_URL} are required. \
             See .env.example.",
            missing_names(&[
                (ENV_USERNAME, username.is_none()),
                (ENV_CONSUMER_KEY, consumer_key.is_none()),
                (ENV_PRIVATE_KEY_PATH, private_key_path.is_none()),
                (ENV_LOGIN_URL, login_url.is_none()),
            ]),
        ),
    }
}

fn missing_names(vars: &[(&str, bool)]) -> String {
    vars.iter()
        .filter(|(_, missing)| *missing)
        .map(|(name, _)| *name)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Message for an opted-in run that configured neither auth path.
fn no_auth_configured() -> String {
    format!(
        "{ENV_ENABLED}=1 but no auth is configured. Set {ENV_ACCESS_TOKEN} \
         for static-token mode, or all four of {ENV_USERNAME}, \
         {ENV_CONSUMER_KEY}, {ENV_PRIVATE_KEY_PATH} and {ENV_LOGIN_URL} \
         for JWT mode. See .env.example."
    )
}

fn load_dotenv() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = dotenvy::dotenv();
    });
}

/// Resolves the configured `instance_url` after applying the safety
/// guard. Returns `None` (and prints a skip message) when integration
/// tests aren't enabled or the URL's host isn't a known
/// sandbox/dev/scratch partition; panics when they are enabled but
/// `INSTANCE_URL` is missing or isn't `https`.
pub fn try_instance_url() -> Option<String> {
    load_dotenv();

    if std::env::var(ENV_ENABLED).ok().as_deref() != Some("1") {
        eprintln!("skipping: set {ENV_ENABLED}=1 (and other CIRRUS_INTEGRATION_* vars) to enable",);
        return None;
    }

    let Some(instance_url) = env_var(ENV_INSTANCE_URL) else {
        panic!("{ENV_ENABLED}=1 but {ENV_INSTANCE_URL} is not set. See .env.example.");
    };

    // `FORCE` waives the org classification below, never transport
    // security, so the scheme is checked separately from the safe-list.
    requires_https(ENV_INSTANCE_URL, &instance_url);

    let force = std::env::var(ENV_FORCE).ok().as_deref() == Some("1");
    if !is_safe_test_url(&instance_url) && !force {
        eprintln!(
            "REFUSING TO RUN: {ENV_INSTANCE_URL} ({instance_url}) doesn't match a known \
             https sandbox/dev/scratch pattern. Set {ENV_FORCE}=1 to override the \
             host check.",
        );
        return None;
    }
    Some(instance_url)
}

/// Builds an [`AuthSession`] from environment, preferring static-token
/// mode when both are available. Returns `None` only when the harness
/// itself is disabled or refuses the configured URL; an opted-in run
/// with no usable auth configuration panics rather than skipping.
///
/// [`AuthSession`]: cirrus_auth::AuthSession
pub async fn try_init_auth() -> Option<SharedAuth> {
    let instance_url = try_instance_url()?;

    if let Some(token) = env_var(ENV_ACCESS_TOKEN) {
        let shared: SharedAuth = Arc::new(StaticTokenAuth::new(token, instance_url));
        return Some(shared);
    }

    let jwt = try_init_jwt_auth().await?;
    let shared: SharedAuth = Arc::new(jwt);
    Some(shared)
}

/// Builds a [`JwtAuth`] from environment, *ignoring* `ACCESS_TOKEN`.
///
/// Returns `None` when the JWT block is absent altogether and
/// static-token mode is configured instead — that is a legitimate
/// setup, and the JWT-specific tests skip. A half-filled JWT block, no
/// auth configuration at all, or a `LOGIN_URL` that isn't `https`
/// panics.
///
/// Use this from JWT-specific tests that must exercise the full
/// bearer flow rather than fall through to the static-token shortcut.
pub async fn try_init_jwt_auth() -> Option<JwtAuth> {
    let instance_url = try_instance_url()?;

    let Some(jwt) = jwt_config() else {
        assert!(
            env_var(ENV_ACCESS_TOKEN).is_some(),
            "{}",
            no_auth_configured()
        );
        eprintln!("skipping: JWT mode not configured ({ENV_ACCESS_TOKEN} only)");
        return None;
    };

    requires_https(ENV_LOGIN_URL, &jwt.login_url);

    let builder = JwtAuth::builder()
        .consumer_key(jwt.consumer_key)
        .username(jwt.username)
        .login_url(jwt.login_url)
        .instance_url(instance_url)
        .private_key_pem_file(jwt.private_key_path.clone())
        .unwrap_or_else(|e| {
            panic!(
                "failed to load the private key at {ENV_PRIVATE_KEY_PATH} \
                 ({}): {e}. Note that `~` is not expanded — give an \
                 absolute path.",
                jwt.private_key_path,
            )
        });

    let auth = builder
        .build()
        .unwrap_or_else(|e| panic!("JwtAuth construction failed: {e}"));
    Some(auth)
}

/// Lightweight verifier: hits a trivial Salesforce REST endpoint
/// (`/services/data`) with the given bearer token and asserts the org
/// accepted it. Used as an end-to-end check that a minted token is
/// actually valid against the live org, without pulling in the `cirrus`
/// crate as a dev-dep.
///
/// Returns the HTTP status the org returned for the call so the caller
/// can also assert on it.
pub async fn ping_with_token(instance_url: &str, token: &str) -> reqwest::Result<u16> {
    let url = format!("{instance_url}/services/data");
    let resp = reqwest::Client::new()
        .get(&url)
        .bearer_auth(token)
        .send()
        .await?;
    Ok(resp.status().as_u16())
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
