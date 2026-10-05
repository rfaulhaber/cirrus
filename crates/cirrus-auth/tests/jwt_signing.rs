//! JWT assertions must be signed without consulting jsonwebtoken's
//! process-global crypto provider.
//!
//! A downstream build that enables jsonwebtoken's `rust_crypto` feature
//! next to this workspace's `aws_lc_rs` leaves that global provider
//! unusable: with both backends on, jsonwebtoken installs a provider
//! whose factories panic. Installing an unusable provider here models
//! that build without changing this crate's features. The install is
//! process-wide and one-shot, which is why this test has its own binary.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use cirrus_auth::{AuthSession, JwtAuth};
use jsonwebtoken::crypto::{CryptoProvider, KeyUtils};
use jsonwebtoken::errors::ErrorKind;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

static UNUSABLE_PROVIDER: CryptoProvider = CryptoProvider {
    signer_factory: |_, _| Err(ErrorKind::InvalidAlgorithm.into()),
    verifier_factory: |_, _| Err(ErrorKind::InvalidAlgorithm.into()),
    key_utils: KeyUtils::new_unimplemented(),
};

#[tokio::test]
async fn minting_does_not_depend_on_the_process_global_crypto_provider() {
    UNUSABLE_PROVIDER
        .install_default()
        .expect("this test binary installs the process provider exactly once");

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/services/oauth2/token"))
        .and(body_string_contains("grant_type=urn"))
        .and(body_string_contains("assertion="))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "00DXX!ACCESS",
            "instance_url": "https://my-org.my.salesforce.com",
            "token_type": "Bearer",
        })))
        .mount(&server)
        .await;

    let auth = JwtAuth::builder()
        .consumer_key("consumer-key-123")
        .username("integration@example.com")
        .private_key_pem_bytes(include_bytes!("fixtures/test_rsa_key.pem"))
        .unwrap()
        .instance_url("https://my-org.my.salesforce.com")
        .login_url(server.uri())
        .build()
        .unwrap();

    let token = auth.access_token().await.unwrap();
    assert_eq!(&*token, "00DXX!ACCESS");
}
