//! JWT bearer flow end-to-end tests.
//!
//! These exercise the full RFC 7521 / 7523 assertion flow against
//! Salesforce's `/services/oauth2/token` endpoint:
//!
//! 1. Sign a JWT with the connected app's private key.
//! 2. POST it as a `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`
//!    assertion.
//! 3. Parse the resulting `access_token` + `instance_url`.
//! 4. Verify the org accepts the token on a real call.
//!
//! Requires the four JWT env vars (`USERNAME`, `CONSUMER_KEY`,
//! `PRIVATE_KEY_PATH`, `LOGIN_URL`). When only static-token mode is
//! configured, every test in this module skips silently.

use crate::common::{
    assert_token_is_accepted, configured_username, try_init_jwt_auth, try_instance_url,
};
use cirrus_auth::AuthSession;

/// Asserts that the org accepts `token` and that it was minted for the
/// configured user: the JWT names the user in `sub`, so a token for
/// anyone else means the assertion was built wrongly.
async fn assert_minted_for_the_configured_user(token: &str) {
    let instance_url = try_instance_url().unwrap();
    let username = assert_token_is_accepted(&instance_url, token).await;
    let expected = configured_username().expect("JWT mode sets the username");
    assert!(
        username.eq_ignore_ascii_case(&expected),
        "the token belongs to {username}, not the configured user",
    );
}

#[tokio::test]
#[ignore]
async fn jwt_flow_mints_a_token_accepted_by_the_org() {
    let Some(auth) = try_init_jwt_auth().await else {
        return;
    };

    let token = auth
        .access_token()
        .await
        .expect("JWT bearer exchange should succeed against a real org");
    assert!(!token.is_empty(), "minted JWT token should not be empty");
    assert!(
        token.len() > 20,
        "Salesforce access tokens are usually >20 chars; got {} chars",
        token.len(),
    );

    assert_minted_for_the_configured_user(&token).await;
}

#[tokio::test]
#[ignore]
async fn jwt_flow_caches_token_across_calls() {
    let Some(auth) = try_init_jwt_auth().await else {
        return;
    };

    let first = auth.access_token().await.unwrap().to_string();
    let second = auth.access_token().await.unwrap().to_string();
    // The cache should return the same value — *not* a freshly-signed
    // assertion exchange on every call. If these differ, the cache
    // never populated (or the TTL is misconfigured).
    //
    // Compared with `assert!` rather than `assert_eq!` so a failure
    // can't Debug-format two live org session ids into the panic
    // message; the crate redacts them everywhere else.
    assert!(
        first == second,
        "JwtAuth should cache the access token across consecutive \
         access_token() calls (got {} then {} chars)",
        first.len(),
        second.len(),
    );
}

#[tokio::test]
#[ignore]
async fn jwt_token_after_invalidate_is_usable() {
    let Some(auth) = try_init_jwt_auth().await else {
        return;
    };

    let first = auth.access_token().await.unwrap().to_string();
    auth.invalidate(&first).await;
    let second = auth.access_token().await.unwrap().to_string();

    // Whether the second call re-minted is not observable from here:
    // Salesforce may re-issue the same session id within a short window,
    // and a cached token would pass every check below just as well. The
    // offline `invalidate_clears_cache_only_when_stale_token_matches`
    // pins the re-mint; this checks only that what comes back after an
    // invalidate is a token the org accepts for the configured user.
    assert!(
        !second.is_empty(),
        "post-invalidate JWT mint should succeed"
    );
    assert_minted_for_the_configured_user(&second).await;
}
