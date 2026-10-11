//! Read-only smoke tests — verify the SDK can talk to a real org at
//! all and that the simplest endpoints come back with the shape we
//! expect.
//!
//! These hit:
//! - `GET /services/data` (versions list)
//! - `GET /services/data/{v}/limits` (org limits)
//! - The version-negotiation helper that picks the highest version
//! - The `Sforce-Limit-Info` header capture path
//!
//! No writes; no test-data dependencies. Safe to run on any
//! sandbox/dev/scratch org without setup.

use crate::common::try_init_client;
use cirrus::ApiVersion;

/// URL of the `latest` alias entry the versions list documents. Its
/// `version` is not guaranteed to be a `major.minor` pair.
const LATEST_ALIAS_URL: &str = "/services/data/latest";

#[tokio::test]
#[ignore]
async fn versions_endpoint_returns_nonempty_list() {
    let Some(sf) = try_init_client().await else {
        return;
    };
    let versions = sf.versions().await.expect("versions() should succeed");
    assert!(
        !versions.is_empty(),
        "real org should expose at least one API version",
    );
    // Spot-check the wire shape — every entry should have all three
    // documented fields populated.
    for v in &versions {
        let is_alias = v.url == LATEST_ALIAS_URL;
        assert!(!v.label.is_empty(), "label should be populated");
        assert!(
            is_alias || v.url.starts_with("/services/data/v"),
            "url should be path-rooted, got {}",
            v.url,
        );
        assert!(
            (is_alias && v.version_number().is_none())
                || (!v.version.is_empty() && v.version.contains('.')),
            "version should be major.minor, got {}",
            v.version,
        );
    }
}

#[tokio::test]
#[ignore]
async fn versions_are_sortable_via_version_number() {
    // Verifies our numeric-ordering claim against real data —
    // catches the lexical-ordering bug if it ever creeps back in.
    let Some(sf) = try_init_client().await else {
        return;
    };
    let versions = sf.versions().await.unwrap();
    let numeric: Vec<_> = versions
        .iter()
        .filter(|v| v.url != LATEST_ALIAS_URL)
        .collect();
    let parsed: Vec<_> = numeric.iter().filter_map(|v| v.version_number()).collect();
    assert_eq!(
        parsed.len(),
        numeric.len(),
        "every numeric version should parse cleanly",
    );

    let latest = ApiVersion::latest(&versions).expect("at least one version");
    let max_pair = parsed.iter().max().copied().unwrap();
    assert_eq!(
        latest.version_number(),
        Some(max_pair),
        "ApiVersion::latest should agree with explicit max",
    );
}

#[tokio::test]
#[ignore]
async fn latest_api_version_returns_v_prefixed_string() {
    let Some(sf) = try_init_client().await else {
        return;
    };
    let latest = sf.latest_api_version().await.unwrap();
    assert!(
        latest.starts_with('v'),
        "latest_api_version should return v-prefixed string, got {latest}",
    );
    // major.minor after the v
    let after = &latest[1..];
    assert!(
        after.contains('.') && after.split('.').all(|p| p.parse::<u32>().is_ok()),
        "latest_api_version should be vN.M with numeric parts, got {latest}",
    );
}

#[tokio::test]
#[ignore]
async fn build_with_latest_version_uses_negotiated_value() {
    use cirrus::Cirrus;
    use cirrus::auth::StaticTokenAuth;
    use std::sync::Arc;

    let Some(bootstrap) = try_init_client().await else {
        return;
    };
    let latest = bootstrap.latest_api_version().await.unwrap();

    // Reconstruct via build_with_latest_version using the same auth/url.
    // We can't easily re-use bootstrap's auth (it's behind dyn AuthSession),
    // so reach into env directly for the static-token path. JWT path is
    // already covered by mint events in unit tests.
    let Ok(token) = std::env::var(super::common::ENV_ACCESS_TOKEN) else {
        eprintln!("skipping: build_with_latest_version test requires static-token mode");
        return;
    };
    let url = std::env::var(super::common::ENV_INSTANCE_URL).unwrap();
    let auth = Arc::new(StaticTokenAuth::new(token, url));
    let sf = Cirrus::builder()
        .auth(auth)
        .build_with_latest_version()
        .await
        .unwrap();
    assert_eq!(sf.api_version(), latest);
}

#[tokio::test]
#[ignore]
async fn limits_endpoint_returns_known_limit_keys() {
    let Some(sf) = try_init_client().await else {
        return;
    };
    let limits = sf.limits().await.expect("limits() should succeed");

    // Spot-check well-known limit keys documented across editions.
    // DailyApiRequests should always be present.
    assert!(
        limits.contains_key("DailyApiRequests"),
        "expected DailyApiRequests in limits map; keys: {:?}",
        limits.keys().collect::<Vec<_>>(),
    );
    let daily = &limits["DailyApiRequests"];
    assert!(daily.max > 0, "DailyApiRequests.Max should be positive");
    assert!(
        daily.remaining <= daily.max,
        "remaining should not exceed max",
    );
}

#[tokio::test]
#[ignore]
async fn sforce_limit_info_header_is_captured() {
    let Some(sf) = try_init_client().await else {
        return;
    };
    // Before any request, last_limit_info should be None.
    assert!(sf.last_limit_info().is_none());

    // The Sforce-Limit-Info header is only set on *versioned* API
    // responses — the pre-version-resolution `/services/data`
    // discovery endpoint (i.e. `sf.versions()`) doesn't emit it, since
    // it doesn't count against API request quota. Use `limits()` —
    // that's a versioned call that always touches the quota.
    let _ = sf.limits().await.unwrap();
    let info = sf
        .last_limit_info()
        .expect("expected Sforce-Limit-Info to be captured after first versioned call");
    assert!(
        info.allowed > 0,
        "limit-info allowed should be positive, got {}",
        info.allowed,
    );
    assert!(
        info.used <= info.allowed,
        "used ({}) should not exceed allowed ({})",
        info.used,
        info.allowed,
    );
}
