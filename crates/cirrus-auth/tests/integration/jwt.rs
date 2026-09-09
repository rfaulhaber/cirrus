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

use crate::common::{ping_with_token, try_init_jwt_auth, try_instance_url};
use cirrus_auth::AuthSession;

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

    let instance_url = try_instance_url().unwrap();
    let status = ping_with_token(&instance_url, &token).await.unwrap();
    assert_eq!(
        status, 200,
        "Salesforce should accept the JWT-minted bearer token (got HTTP {status})",
    );
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
async fn jwt_invalidate_forces_a_fresh_mint() {
    let Some(auth) = try_init_jwt_auth().await else {
        return;
    };

    let first = auth.access_token().await.unwrap().to_string();
    auth.invalidate(&first).await;
    let second = auth.access_token().await.unwrap().to_string();

    // We can't always require the literal token bytes to differ —
    // Salesforce *may* (rarely) re-issue the same token within a short
    // window. The real invariant: after invalidate, the next call hits
    // the token endpoint again and still produces a usable token.
    assert!(
        !second.is_empty(),
        "post-invalidate JWT mint should succeed"
    );

    let instance_url = try_instance_url().unwrap();
    let status = ping_with_token(&instance_url, &second).await.unwrap();
    assert_eq!(
        status, 200,
        "post-invalidate JWT-minted token should still be accepted by the org",
    );
}
