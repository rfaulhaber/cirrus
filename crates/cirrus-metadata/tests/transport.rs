//! End-to-end transport tests for `cirrus-metadata`.
//!
//! Each test stands up a wiremock server, points a `MetadataClient` at
//! it, and verifies one of:
//!
//! - happy-path round trip with typed response deserialization,
//! - SOAP fault → typed `MetadataError::Soap`,
//! - `INVALID_SESSION_ID` fault → token invalidate + retry once,
//! - same fault with non-refreshable auth → surfaced verbatim,
//! - HTTP 503 → retry per `RetryPolicy`,
//! - non-envelope body → `MetadataError::Http4xx5xx`,
//! - 3xx redirect → surfaced as an error, never followed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use async_trait::async_trait;
use cirrus_metadata::auth::{AuthResult, AuthSession, StaticTokenAuth};
use cirrus_metadata::{MetadataClient, MetadataError, MetadataResult, RetryPolicy, SoapOperation};
use serde::Deserialize;
use std::borrow::Cow;
use std::sync::{Arc, Mutex};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// -- Test operation ----------------------------------------------------------

/// Minimal SOAP op for transport testing. No body, returns a typed message.
struct Ping;

#[derive(Debug, Deserialize, PartialEq)]
struct PingResponse {
    result: PingResult,
}

#[derive(Debug, Deserialize, PartialEq)]
struct PingResult {
    msg: String,
}

impl SoapOperation for Ping {
    const NAME: &'static str = "ping";
    // Declared replay-safe so the transport's retry loop is exercised;
    // `Mutate` below covers the non-idempotent default.
    const IDEMPOTENT: bool = true;
    type Response = PingResponse;
    fn render_body(&self) -> MetadataResult<String> {
        Ok(String::new())
    }
}

/// Same as [`Ping`] but with the default `IDEMPOTENT = false`, standing
/// in for mutating calls (`deploy`, `createMetadata`, …).
struct Mutate;

impl SoapOperation for Mutate {
    const NAME: &'static str = "ping";
    type Response = PingResponse;
    fn render_body(&self) -> MetadataResult<String> {
        Ok(String::new())
    }
}

// -- Mock AuthSession that can refresh --------------------------------------

/// Token-rotating mock auth. Tracks the sequence of tokens issued and
/// the tokens passed to `invalidate`. Each `invalidate` call swaps in
/// the next token from `tokens`; once exhausted, falls back to the
/// last token.
struct RotatingAuth {
    instance_url: String,
    state: Mutex<RotatingState>,
}

struct RotatingState {
    tokens: Vec<String>,
    current: usize,
    invalidations: Vec<String>,
}

impl RotatingAuth {
    fn new(instance_url: impl Into<String>, tokens: Vec<&str>) -> Arc<Self> {
        Arc::new(Self {
            instance_url: instance_url.into(),
            state: Mutex::new(RotatingState {
                tokens: tokens.into_iter().map(String::from).collect(),
                current: 0,
                invalidations: Vec::new(),
            }),
        })
    }

    fn invalidations(&self) -> Vec<String> {
        self.state.lock().unwrap().invalidations.clone()
    }
}

#[async_trait]
impl AuthSession for RotatingAuth {
    async fn access_token(&self) -> AuthResult<Cow<'_, str>> {
        let state = self.state.lock().unwrap();
        let idx = state.current.min(state.tokens.len().saturating_sub(1));
        Ok(Cow::Owned(state.tokens[idx].clone()))
    }

    fn instance_url(&self) -> &str {
        &self.instance_url
    }

    async fn invalidate(&self, stale_token: &str) {
        let mut state = self.state.lock().unwrap();
        state.invalidations.push(stale_token.to_string());
        // Advance to the next token if one is available.
        if state.current + 1 < state.tokens.len() {
            state.current += 1;
        }
    }
}

// Sanity: ensure `async-trait` resolves the dep correctly. The mock
// uses it.
const _: fn() = || {
    fn assert_send<T: Send + Sync>() {}
    assert_send::<RotatingAuth>();
};

// -- Fixture responses -------------------------------------------------------

fn success_body(msg: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns="http://soap.sforce.com/2006/04/metadata">
  <soapenv:Body>
    <pingResponse>
      <result><msg>{msg}</msg></result>
    </pingResponse>
  </soapenv:Body>
</soapenv:Envelope>"#
    )
}

fn fault_body(code: &str, message: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <soapenv:Fault>
      <faultcode>sf:{code}</faultcode>
      <faultstring>{code}: {message}</faultstring>
    </soapenv:Fault>
  </soapenv:Body>
</soapenv:Envelope>"#
    )
}

fn client_for(_server: &MockServer, auth: Arc<dyn AuthSession>) -> MetadataClient {
    MetadataClient::builder()
        .auth(auth)
        .retry_policy(RetryPolicy {
            // Keep tests deterministic — no jitter, short delays.
            base_delay: std::time::Duration::from_millis(1),
            max_delay: std::time::Duration::from_millis(5),
            jitter: false,
            ..RetryPolicy::default()
        })
        .build()
        .unwrap()
}

// -- Tests -------------------------------------------------------------------

#[tokio::test]
async fn happy_path_round_trip() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/services/Soap/m/66.0"))
        .and(header("content-type", "text/xml; charset=UTF-8"))
        .and(header("soapaction", "\"\""))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/xml; charset=UTF-8")
                .set_body_string(success_body("hello")),
        )
        .mount(&server)
        .await;

    let auth = Arc::new(StaticTokenAuth::new("tok", server.uri()));
    let md = client_for(&server, auth);

    let resp = md.call(&Ping).await.unwrap();
    assert_eq!(
        resp,
        PingResponse {
            result: PingResult {
                msg: "hello".into()
            }
        }
    );
}

#[tokio::test]
async fn envelope_includes_session_token_and_operation_name() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/services/Soap/m/66.0"))
        .and(wiremock::matchers::body_string_contains(
            "<met:sessionId>my-secret-token</met:sessionId>",
        ))
        .and(wiremock::matchers::body_string_contains("<met:ping>"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/xml; charset=UTF-8")
                .set_body_string(success_body("ok")),
        )
        .mount(&server)
        .await;

    let auth = Arc::new(StaticTokenAuth::new("my-secret-token", server.uri()));
    let md = client_for(&server, auth);

    md.call(&Ping).await.unwrap();
}

#[tokio::test]
async fn soap_fault_surfaces_as_typed_error() {
    let server = MockServer::start().await;

    // Salesforce sends faults with HTTP 500 by default. An application
    // fault returns the same answer on every attempt, so the 500 must
    // not draw the operation through the retry budget first — one
    // request, then the typed error.
    //
    // SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_error_handling.htm
    // "it uses SOAP fault messages defined in those WSDLs for errors
    // resulting from badly formed messages, failed authentication, or
    // similar problems."
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(500)
                .insert_header("content-type", "text/xml; charset=UTF-8")
                .set_body_string(fault_body("INVALID_TYPE", "no such metadata type")),
        )
        .expect(1)
        .mount(&server)
        .await;

    let auth = Arc::new(StaticTokenAuth::new("tok", server.uri()));
    let md = client_for(&server, auth);

    let err = md.call(&Ping).await.unwrap_err();
    match err {
        MetadataError::Soap { status, fault } => {
            assert_eq!(status, 500);
            assert_eq!(fault.code(), "INVALID_TYPE");
            assert!(fault.faultstring.contains("no such metadata type"));
        }
        other => panic!("expected Soap error, got {other:?}"),
    }
}

#[tokio::test]
async fn invalid_session_triggers_token_refresh_and_retry() {
    let server = MockServer::start().await;

    // First request: fault. Second: success. Distinguish by token in
    // the body so wiremock routes correctly.
    Mock::given(method("POST"))
        .and(wiremock::matchers::body_string_contains(
            "<met:sessionId>stale-token</met:sessionId>",
        ))
        .respond_with(
            ResponseTemplate::new(500)
                .insert_header("content-type", "text/xml; charset=UTF-8")
                .set_body_string(fault_body("INVALID_SESSION_ID", "session expired")),
        )
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(wiremock::matchers::body_string_contains(
            "<met:sessionId>fresh-token</met:sessionId>",
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/xml; charset=UTF-8")
                .set_body_string(success_body("after-refresh")),
        )
        .mount(&server)
        .await;

    let auth = RotatingAuth::new(server.uri(), vec!["stale-token", "fresh-token"]);
    let md = MetadataClient::builder()
        .auth(auth.clone())
        .retry_policy(RetryPolicy::none())
        .build()
        .unwrap();

    let resp = md.call(&Ping).await.unwrap();
    assert_eq!(resp.result.msg, "after-refresh");
    // The auth session should have been told to invalidate the stale token.
    assert_eq!(auth.invalidations(), vec!["stale-token".to_string()]);
}

#[tokio::test]
async fn invalid_session_with_unrefreshable_auth_surfaces_fault() {
    let server = MockServer::start().await;

    // Static auth can't refresh — every request uses the same token.
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(500)
                .insert_header("content-type", "text/xml; charset=UTF-8")
                .set_body_string(fault_body("INVALID_SESSION_ID", "session expired")),
        )
        .mount(&server)
        .await;

    let auth = Arc::new(StaticTokenAuth::new("static-tok", server.uri()));
    let md = MetadataClient::builder()
        .auth(auth)
        .retry_policy(RetryPolicy::none())
        .build()
        .unwrap();

    let err = md.call(&Ping).await.unwrap_err();
    match err {
        MetadataError::Soap { fault, .. } => {
            assert_eq!(fault.code(), "INVALID_SESSION_ID");
        }
        other => panic!("expected Soap error, got {other:?}"),
    }
}

#[tokio::test]
async fn http_503_is_retried() {
    let server = MockServer::start().await;

    // First call: 503 with empty body. Retry policy should kick in.
    // Use up_to_n_times to make wiremock serve the 503 once.
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Subsequent calls: success.
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/xml; charset=UTF-8")
                .set_body_string(success_body("retried")),
        )
        .mount(&server)
        .await;

    let auth = Arc::new(StaticTokenAuth::new("tok", server.uri()));
    let md = MetadataClient::builder()
        .auth(auth)
        .retry_policy(RetryPolicy {
            max_retries: 2,
            base_delay: std::time::Duration::from_millis(1),
            max_delay: std::time::Duration::from_millis(5),
            jitter: false,
            ..RetryPolicy::default()
        })
        .build()
        .unwrap();

    let resp = md.call(&Ping).await.unwrap();
    assert_eq!(resp.result.msg, "retried");
}

#[tokio::test]
async fn http_503_is_not_retried_for_non_idempotent_op() {
    let server = MockServer::start().await;

    // A 503 can be emitted by an intermediary after the origin
    // processed the request, so a mutating operation must surface it
    // rather than replay.
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(503))
        .expect(1)
        .mount(&server)
        .await;

    let auth = Arc::new(StaticTokenAuth::new("tok", server.uri()));
    let md = MetadataClient::builder()
        .auth(auth)
        .retry_policy(RetryPolicy {
            max_retries: 2,
            base_delay: std::time::Duration::from_millis(1),
            max_delay: std::time::Duration::from_millis(5),
            jitter: false,
            ..RetryPolicy::default()
        })
        .build()
        .unwrap();

    let err = md.call(&Mutate).await.unwrap_err();
    match err {
        MetadataError::Http4xx5xx { status, .. } => assert_eq!(status, 503),
        other => panic!("expected Http4xx5xx, got {other:?}"),
    }
}

#[tokio::test]
async fn non_envelope_body_surfaces_as_http_error() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(502)
                .insert_header("content-type", "text/html")
                .set_body_string("<html>bad gateway</html>"),
        )
        .mount(&server)
        .await;

    let auth = Arc::new(StaticTokenAuth::new("tok", server.uri()));
    let md = MetadataClient::builder()
        .auth(auth)
        .retry_policy(RetryPolicy::none())
        .build()
        .unwrap();

    let err = md.call(&Ping).await.unwrap_err();
    match err {
        MetadataError::Http4xx5xx { status, raw } => {
            assert_eq!(status, 502);
            assert!(raw.contains("bad gateway"));
        }
        other => panic!("expected Http4xx5xx, got {other:?}"),
    }
}

#[tokio::test]
async fn request_builder_escape_hatch_returns_post_with_soap_headers() {
    // Doesn't exercise round-trip; just confirms the escape hatch is
    // shaped correctly. Useful for callers who need fully-custom
    // envelopes.
    let server = MockServer::start().await;
    let auth = Arc::new(StaticTokenAuth::new("tok", server.uri()));
    let md = MetadataClient::builder().auth(auth).build().unwrap();

    Mock::given(method("POST"))
        .and(path("/services/Soap/m/66.0"))
        .and(header("soapaction", "\"\""))
        .and(header("content-type", "text/xml; charset=UTF-8"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<ok/>"))
        .mount(&server)
        .await;

    let resp = md.request_builder().body("<custom/>").send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
}

#[tokio::test]
async fn transient_fault_on_idempotent_op_is_retried() {
    let server = MockServer::start().await;

    // SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api.meta/api/sforce_api_calls_concepts_core_data_objects.htm
    // ExceptionCode SERVER_UNAVAILABLE: "A server that's necessary for
    // this call is unavailable. Other types of requests could still
    // work." Unlike a request-shape fault, that can clear on a replay.
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(500)
                .insert_header("content-type", "text/xml; charset=UTF-8")
                .set_body_string(fault_body("SERVER_UNAVAILABLE", "try again")),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/xml; charset=UTF-8")
                .set_body_string(success_body("recovered")),
        )
        .mount(&server)
        .await;

    let auth = Arc::new(StaticTokenAuth::new("tok", server.uri()));
    let md = client_for(&server, auth);

    let resp = md.call(&Ping).await.unwrap();
    assert_eq!(resp.result.msg, "recovered");
}

#[tokio::test]
async fn invalid_session_refresh_does_not_resend_the_stale_token() {
    let server = MockServer::start().await;

    // The refresh path is reached on the first fault rather than after
    // the retry budget has been spent re-sending a token the server has
    // already rejected — so the stale token goes out exactly once.
    Mock::given(method("POST"))
        .and(wiremock::matchers::body_string_contains(
            "<met:sessionId>stale-token</met:sessionId>",
        ))
        .respond_with(
            ResponseTemplate::new(500)
                .insert_header("content-type", "text/xml; charset=UTF-8")
                .set_body_string(fault_body("INVALID_SESSION_ID", "session expired")),
        )
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(wiremock::matchers::body_string_contains(
            "<met:sessionId>fresh-token</met:sessionId>",
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/xml; charset=UTF-8")
                .set_body_string(success_body("after-refresh")),
        )
        .expect(1)
        .mount(&server)
        .await;

    let auth = RotatingAuth::new(server.uri(), vec!["stale-token", "fresh-token"]);
    let md = client_for(&server, auth);

    let resp = md.call(&Ping).await.unwrap();
    assert_eq!(resp.result.msg, "after-refresh");
}

#[tokio::test]
async fn response_text_reaches_the_caller_verbatim() {
    let server = MockServer::start().await;

    // Entity references split character data into separate parser
    // events; the whitespace on either side must survive the round trip
    // so metadata values arrive exactly as the org stores them.
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/xml; charset=UTF-8")
                .set_body_string(success_body("Tom &amp; Jerry")),
        )
        .mount(&server)
        .await;

    let auth = Arc::new(StaticTokenAuth::new("tok", server.uri()));
    let md = client_for(&server, auth);

    let resp = md.call(&Ping).await.unwrap();
    assert_eq!(resp.result.msg, "Tom & Jerry");
}

#[tokio::test]
async fn redirects_are_not_followed() {
    let target = MockServer::start().await;
    let server = MockServer::start().await;

    // Nothing may reach the redirect target: the session token rides in
    // the SOAP envelope, so following the hop would hand it to whatever
    // host the Location named.
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&target)
        .await;

    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(307).insert_header("location", format!("{}/x", target.uri())),
        )
        .expect(1)
        .mount(&server)
        .await;

    let auth = Arc::new(StaticTokenAuth::new("tok", server.uri()));
    let md = client_for(&server, auth);

    let err = md.call(&Ping).await.unwrap_err();
    match err {
        MetadataError::Http4xx5xx { status, .. } => assert_eq!(status, 307),
        other => panic!("expected Http4xx5xx with status 307, got {other:?}"),
    }
}
