//! Read-only smoke tests for the [`AuthSession`] surface against a
//! real org.
//!
//! These run whichever mode is configured (static or JWT) — they're
//! checking that the trait contract holds end-to-end, not that any
//! specific flow works. Per-flow tests live in sibling modules
//! (currently only `jwt`).
//!
//! [`AuthSession`]: cirrus_auth::AuthSession

use crate::common::{
    assert_token_is_accepted, try_init_auth, try_instance_url, userinfo_with_token,
};

#[tokio::test]
#[ignore]
async fn auth_session_produces_a_usable_bearer_token() {
    let Some(auth) = try_init_auth().await else {
        return;
    };

    let token = auth
        .access_token()
        .await
        .expect("access_token should succeed against a real org");
    assert!(!token.is_empty(), "minted token should not be empty");

    let instance_url = try_instance_url().expect("instance URL was just validated");
    assert_token_is_accepted(&instance_url, &token).await;
}

#[tokio::test]
#[ignore]
async fn the_probe_rejects_a_token_the_org_never_issued() {
    // Negative control for the probe the other tests rely on: a resource
    // that accepted any bearer would let every "the org accepts this
    // token" assertion pass on a dead or garbage token.
    // SOURCE: https://help.salesforce.com/s/articleView?id=xcloud.remoteaccess_using_userinfo_endpoint.htm&type=5
    // "403 (forbidden) — Bad_OAuth_Token | Invalid access token".
    let Some(instance_url) = try_instance_url() else {
        return;
    };
    let (status, body) = userinfo_with_token(&instance_url, "00D000000000000!not-a-session-id")
        .await
        .expect("UserInfo call should not fail at the transport layer");
    assert!(
        matches!(status, 401 | 403),
        "UserInfo should refuse a token the org never issued (got HTTP {status})"
    );
    assert!(body.is_none());
}

#[tokio::test]
#[ignore]
async fn auth_session_instance_url_round_trips() {
    let Some(auth) = try_init_auth().await else {
        return;
    };
    let configured = try_instance_url().expect("instance URL was just validated");

    // The trait's `instance_url()` returns the *normalized* (trailing-
    // slash-stripped) value. We pre-validate `configured` doesn't have
    // a trailing slash by trimming on the comparison side.
    assert_eq!(
        auth.instance_url(),
        configured.trim_end_matches('/'),
        "AuthSession::instance_url should round-trip the configured value",
    );
}

#[tokio::test]
#[ignore]
async fn invalidate_then_access_token_still_returns_a_valid_token() {
    let Some(auth) = try_init_auth().await else {
        return;
    };

    // First mint.
    let first = auth.access_token().await.unwrap().to_string();

    // Invalidate that exact token. Stateful flows clear their cache;
    // stateless static-token auth is a no-op.
    auth.invalidate(&first).await;

    // Second mint. For static-token: same value. For stateful flows: a
    // *fresh* token (or the same one if the cache was repopulated by
    // a concurrent call — unlikely in this single-threaded test).
    let second = auth.access_token().await.unwrap();
    assert!(
        !second.is_empty(),
        "post-invalidate access_token should still produce a valid bearer",
    );

    // Either way, the post-invalidate token should be accepted by the
    // org — that's the property `invalidate` is supposed to preserve.
    let instance_url = try_instance_url().unwrap();
    assert_token_is_accepted(&instance_url, &second).await;
}
