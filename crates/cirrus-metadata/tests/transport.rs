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
//! - 3xx redirect → surfaced as an error, never followed,
//! - builder read timeout → transport error once the deadline passes,
//! - a body that stops mid-stream → replayed like a failed send.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use async_trait::async_trait;
use cirrus_metadata::auth::{AuthResult, AuthSession, StaticTokenAuth};
use cirrus_metadata::{
    ListMetadataQuery, MetadataClient, MetadataError, MetadataResult, RetryPolicy, SoapOperation,
    xml_escape,
};
use serde::Deserialize;
use std::borrow::Cow;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use wiremock::matchers::{body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, Respond, ResponseTemplate};

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

/// Replay-safe op whose response carries a number, so a value the typed
/// envelope cannot parse has a specific element to be named after.
struct Count;

#[derive(Debug, Deserialize)]
struct CountResponse {
    #[allow(dead_code)]
    result: CountResult,
}

#[derive(Debug, Deserialize)]
struct CountResult {
    #[allow(dead_code)]
    count: i32,
}

impl SoapOperation for Count {
    const NAME: &'static str = "count";
    const IDEMPOTENT: bool = true;
    type Response = CountResponse;
    fn render_body(&self) -> MetadataResult<String> {
        Ok(String::new())
    }
}

/// Answers every request with the request's own body, the way a proxy
/// or WAF error page echoes the request that provoked it.
struct EchoBody(u16);

impl Respond for EchoBody {
    fn respond(&self, request: &wiremock::Request) -> ResponseTemplate {
        ResponseTemplate::new(self.0)
            .insert_header("content-type", "text/html")
            .set_body_bytes(request.body.clone())
    }
}

/// Static token whose instance URL can be switched after the client is
/// built — the shape of a session that re-reads its instance URL on
/// refresh and comes back with a different one.
struct FlippingAuth {
    secure: String,
    insecure: String,
    flipped: AtomicBool,
}

#[async_trait]
impl AuthSession for FlippingAuth {
    async fn access_token(&self) -> AuthResult<Cow<'_, str>> {
        Ok(Cow::Borrowed("tok"))
    }

    fn instance_url(&self) -> &str {
        if self.flipped.load(Ordering::SeqCst) {
            &self.insecure
        } else {
            &self.secure
        }
    }

    async fn invalidate(&self, _stale_token: &str) {}
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
        MetadataError::Soap { status, fault, .. } => {
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
        MetadataError::Http4xx5xx { status, raw, .. } => {
            assert_eq!(status, 502);
            assert!(raw.contains("bad gateway"));
        }
        other => panic!("expected Http4xx5xx, got {other:?}"),
    }
}

#[tokio::test]
async fn a_terminal_soap_fault_carries_the_retry_after_hint() {
    // SOURCE: https://datatracker.ietf.org/doc/html/rfc7231#section-7.1.3
    // Under RetryPolicy::none the client makes no retries of its own,
    // so a caller who does needs the server's window.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(500)
                .insert_header("content-type", "text/xml; charset=UTF-8")
                .insert_header("Retry-After", "60")
                .set_body_string(fault_body("SERVER_UNAVAILABLE", "try again later")),
        )
        .mount(&server)
        .await;

    let md = client_with_cap(&server, None, RetryPolicy::none());
    let err = md.call(&Ping).await.unwrap_err();
    match err {
        MetadataError::Soap {
            status,
            fault,
            retry_after,
            ..
        } => {
            assert_eq!(status, 500);
            assert_eq!(fault.code(), "SERVER_UNAVAILABLE");
            assert_eq!(retry_after, Some(std::time::Duration::from_secs(60)));
        }
        other => panic!("expected Soap error, got {other:?}"),
    }
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn a_non_soap_error_carries_the_retry_after_hint() {
    // A gateway 503 on a non-idempotent operation is never replayed, so
    // its hint reaches the caller even with retries enabled.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(503)
                .insert_header("content-type", "text/html")
                .insert_header("Retry-After", "30")
                .set_body_string("<html>upstream busy</html>"),
        )
        .mount(&server)
        .await;

    let md = client_with_cap(&server, None, fast_retries());
    let err = md.call(&Mutate).await.unwrap_err();
    match err {
        MetadataError::Http4xx5xx {
            status,
            retry_after,
            ..
        } => {
            assert_eq!(status, 503);
            assert_eq!(retry_after, Some(std::time::Duration::from_secs(30)));
        }
        other => panic!("expected Http4xx5xx, got {other:?}"),
    }
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn an_error_without_retry_after_carries_no_hint() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(500)
                .insert_header("content-type", "text/xml; charset=UTF-8")
                .set_body_string(fault_body("INVALID_TYPE", "no such metadata type")),
        )
        .mount(&server)
        .await;

    let md = client_with_cap(&server, None, RetryPolicy::none());
    let err = md.call(&Ping).await.unwrap_err();
    assert!(
        matches!(
            err,
            MetadataError::Soap {
                retry_after: None,
                ..
            }
        ),
        "{err:?}"
    );
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

#[tokio::test]
async fn the_builder_read_timeout_bounds_a_call_the_org_never_answers() {
    // The deadline is armed at dispatch, so it fires while the response
    // head is still outstanding — the phase a deploy spends pushing its
    // base64 zip — not only between two chunks of an arriving body.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_delay(std::time::Duration::from_secs(30)))
        .mount(&server)
        .await;

    let auth = Arc::new(StaticTokenAuth::new("tok", server.uri()));
    let md = MetadataClient::builder()
        .auth(auth)
        .read_timeout(std::time::Duration::from_millis(50))
        .retry_policy(RetryPolicy::none())
        .build()
        .unwrap();

    let err = md.call(&Ping).await.unwrap_err();
    match err {
        MetadataError::Http(e) => assert!(e.is_timeout(), "expected a timeout, got {e}"),
        other => panic!("expected a transport error, got {other:?}"),
    }
}

#[tokio::test]
async fn a_response_body_that_stops_mid_stream_is_replayed() {
    // A body failure arrives after the response head, so it can't be
    // classified by status the way a 503 is — it is exactly as
    // ambiguous as a send that never got an answer, and follows the
    // same replay rules. `Ping` is declared idempotent, so it replays.
    //
    // wiremock always sends a complete body, so this serves the
    // truncated response from a raw socket: headers promising 400
    // bytes, a fragment, then a hang-up.
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let body = success_body("hello");
    let server = tokio::spawn(async move {
        let mut buf = [0u8; 8192];

        let (mut sock, _) = listener.accept().await.unwrap();
        let _ = sock.read(&mut buf).await;
        sock.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: 400\r\n\r\n<?xml version=\"1.0\"?><soapenv:Envelope",
        )
        .await
        .unwrap();
        sock.flush().await.unwrap();
        drop(sock);

        let (mut sock, _) = listener.accept().await.unwrap();
        let _ = sock.read(&mut buf).await;
        sock.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        sock.flush().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    });

    let auth = Arc::new(StaticTokenAuth::new("tok", format!("http://{addr}")));
    let md = MetadataClient::builder()
        .auth(auth)
        .retry_policy(RetryPolicy {
            base_delay: std::time::Duration::from_millis(1),
            max_delay: std::time::Duration::from_millis(5),
            jitter: false,
            ..RetryPolicy::default()
        })
        .build()
        .unwrap();

    let resp = md.call(&Ping).await.unwrap();
    assert_eq!(
        resp,
        PingResponse {
            result: PingResult {
                msg: "hello".into()
            }
        }
    );
    server.await.unwrap();
}

// -- Transport security (shared rule with cirrus) -----------------------------

#[tokio::test]
async fn build_rejects_a_plaintext_instance_url() {
    // SOURCE: https://www.rfc-editor.org/rfc/rfc6750#section-5.3
    // "Clients MUST always use TLS [RFC5246] (https) or equivalent
    // transport security when making requests with bearer tokens." The
    // session id rides in every envelope's <sessionId>, so the instance
    // URL has to be https — or loopback, where the hop never leaves the
    // machine — exactly as `Cirrus::builder()` already requires of the
    // same `AuthSession`.
    let auth = Arc::new(StaticTokenAuth::new(
        "tok",
        "http://my-org.my.salesforce.com",
    ));
    let err = MetadataClient::builder().auth(auth).build().unwrap_err();
    match err {
        MetadataError::InvalidArgument(msg) => {
            assert!(msg.contains("https"), "{msg}");
            assert!(msg.contains("allow_insecure_transport"), "{msg}");
        }
        other => panic!("expected InvalidArgument, got {other:?}"),
    }
}

#[tokio::test]
async fn a_call_refuses_an_instance_url_that_turned_plaintext() {
    // `endpoint_url` re-reads the session's instance URL on every call,
    // so the build-time check alone would let a later, insecure URL
    // through. 192.0.2.1 is TEST-NET-1 (RFC 5737): never routable, so a
    // request that did go out could only time out.
    let auth = Arc::new(FlippingAuth {
        secure: "https://my-org.my.salesforce.com".into(),
        insecure: "http://192.0.2.1".into(),
        flipped: AtomicBool::new(false),
    });
    let md = MetadataClient::builder()
        .auth(auth.clone())
        .connect_timeout(std::time::Duration::from_millis(50))
        .retry_policy(RetryPolicy::none())
        .build()
        .unwrap();
    auth.flipped.store(true, Ordering::SeqCst);

    let err = md.call(&Ping).await.unwrap_err();
    assert!(
        matches!(err, MetadataError::InvalidArgument(_)),
        "expected InvalidArgument, got {err:?}"
    );
}

#[tokio::test]
async fn an_echoed_error_body_does_not_leak_the_session_id() {
    // A gateway that blocks the POST and reflects the offending request
    // puts the live session id about 270 bytes into its page — inside
    // the raw-body cap — and the SDK itself logs this error with
    // `error = %e` in `wait_for_deploy`.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(EchoBody(400))
        .mount(&server)
        .await;

    let auth = Arc::new(StaticTokenAuth::new("00Dxx!AQ-very-secret", server.uri()));
    let md = MetadataClient::builder()
        .auth(auth)
        .retry_policy(RetryPolicy::none())
        .build()
        .unwrap();

    let err = md.call(&Ping).await.unwrap_err();
    assert!(
        matches!(err, MetadataError::Http4xx5xx { status: 400, .. }),
        "{err:?}"
    );
    let shown = format!("{err}");
    let debugged = format!("{err:?}");
    assert!(
        !shown.contains("very-secret"),
        "Display leaked the token: {shown}"
    );
    assert!(
        !debugged.contains("very-secret"),
        "Debug leaked the token: {debugged}"
    );
    assert!(shown.contains("[redacted]"), "{shown}");
}

#[tokio::test]
async fn a_non_soap_2xx_echo_does_not_leak_the_session_id() {
    // Same echo, but with a 2xx status: the body is retained as a short
    // excerpt on InvalidResponse. Whether the excerpt stops before the
    // session header or cuts through the token, no part of the token may
    // reach the caller.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(EchoBody(200))
        .mount(&server)
        .await;

    let auth = Arc::new(StaticTokenAuth::new("00Dxx!AQ-very-secret", server.uri()));
    let md = MetadataClient::builder()
        .auth(auth)
        .retry_policy(RetryPolicy::none())
        .build()
        .unwrap();

    let err = md.call(&Ping).await.unwrap_err();
    assert!(matches!(err, MetadataError::InvalidResponse(_)), "{err:?}");
    let shown = format!("{err}");
    assert!(shown.contains("body starts:"), "{shown}");
    assert!(
        !shown.contains("00Dxx"),
        "Display leaked the token: {shown}"
    );
    assert!(
        !shown.contains("sessionId>0"),
        "Display leaked session id text: {shown}"
    );
}

// -- Retry parity with cirrus --------------------------------------------------

#[tokio::test]
async fn a_read_timeout_is_not_replayed() {
    // The read timeout is the caller's deadline on getting an answer at
    // all; re-sending the request up to `max_retries` more times would
    // quietly multiply that deadline and the org's work by four.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_delay(std::time::Duration::from_secs(5)))
        .mount(&server)
        .await;

    let auth = Arc::new(StaticTokenAuth::new("tok", server.uri()));
    let md = MetadataClient::builder()
        .auth(auth)
        .read_timeout(std::time::Duration::from_millis(50))
        .retry_policy(RetryPolicy {
            base_delay: std::time::Duration::from_millis(1),
            max_delay: std::time::Duration::from_millis(5),
            jitter: false,
            ..RetryPolicy::default()
        })
        .build()
        .unwrap();

    let err = md.call(&Ping).await.unwrap_err();
    match err {
        MetadataError::Http(e) => assert!(e.is_timeout(), "expected a timeout, got {e}"),
        other => panic!("expected a transport error, got {other:?}"),
    }
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn a_retry_after_beyond_max_delay_ends_the_retry_loop() {
    // SOURCE: https://datatracker.ietf.org/doc/html/rfc7231#section-7.1.3
    // Retry-After "indicates how long the user agent ought to wait before
    // making a follow-up request." A hint longer than the policy's
    // `max_delay` cannot be honored, and retrying sooner than the server
    // asked only spends requests inside its window — so the response
    // surfaces at once instead.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("Retry-After", "120")
                .set_body_string("rate limited"),
        )
        .mount(&server)
        .await;

    let auth = Arc::new(StaticTokenAuth::new("tok", server.uri()));
    let md = client_for(&server, auth);

    let err = md.call(&Ping).await.unwrap_err();
    assert!(
        matches!(err, MetadataError::Http4xx5xx { status: 429, .. }),
        "expected the 429 to surface, got {err:?}"
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

// -- Builder validation -----------------------------------------------------------

#[test]
fn build_rejects_an_api_version_that_is_not_a_bare_number() {
    // SOAP endpoint paths carry the bare `XX.X` form. The REST client's
    // `v66.0` and anything with path characters would otherwise build a
    // URL the server does not serve, or one outside `/services/Soap/m/`.
    let auth = Arc::new(StaticTokenAuth::new(
        "tok",
        "https://my-org.my.salesforce.com",
    ));
    for bad in ["v66.0", "66", "66.0/../x", "latest", ""] {
        let err = MetadataClient::builder()
            .auth(auth.clone())
            .api_version(bad)
            .build()
            .unwrap_err();
        match err {
            MetadataError::InvalidArgument(msg) => {
                assert!(msg.contains(bad), "{bad:?}: {msg}");
            }
            other => panic!("{bad:?}: expected InvalidArgument, got {other:?}"),
        }
    }
    for good in ["58.0", "66.0", "100.0"] {
        MetadataClient::builder()
            .auth(auth.clone())
            .api_version(good)
            .build()
            .unwrap_or_else(|e| panic!("{good:?} rejected: {e}"));
    }
}

// -- Parse failures name what broke ------------------------------------------------

#[tokio::test]
async fn a_typed_parse_failure_names_the_operation_and_element() {
    // A value the typed envelope cannot parse should point at the
    // element, so a Salesforce release that changes one field out of
    // dozens does not need a traffic capture to diagnose.
    let server = MockServer::start().await;
    let body = r#"<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns="http://soap.sforce.com/2006/04/metadata">
  <soapenv:Body>
    <countResponse>
      <result><count>many</count></result>
    </countResponse>
  </soapenv:Body>
</soapenv:Envelope>"#;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/xml")
                .set_body_string(body),
        )
        .mount(&server)
        .await;

    let auth = Arc::new(StaticTokenAuth::new("tok", server.uri()));
    let md = client_for(&server, auth);

    let err = md.call(&Count).await.unwrap_err();
    let msg = match err {
        MetadataError::Xml(msg) => msg,
        other => panic!("expected Xml, got {other:?}"),
    };
    assert!(msg.contains("countResponse"), "{msg}");
    assert!(msg.contains("result.count"), "{msg}");
}

#[tokio::test]
async fn a_non_soap_2xx_body_carries_an_excerpt() {
    // The non-2xx branch keeps a capped excerpt of a non-SOAP body; a
    // 2xx from an intermediary (a maintenance page, a captive portal)
    // deserves the same, or the caller only learns that "a body" failed.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/html")
                .set_body_string("<html>scheduled maintenance</html>"),
        )
        .mount(&server)
        .await;

    let auth = Arc::new(StaticTokenAuth::new("tok", server.uri()));
    let md = client_for(&server, auth);

    let err = md.call(&Ping).await.unwrap_err();
    match err {
        MetadataError::InvalidResponse(msg) => {
            assert!(msg.contains("200"), "{msg}");
            assert!(msg.contains("scheduled maintenance"), "{msg}");
        }
        other => panic!("expected InvalidResponse, got {other:?}"),
    }
}

#[tokio::test]
async fn build_accepts_a_plaintext_instance_url_when_opted_in() {
    let auth = Arc::new(StaticTokenAuth::new(
        "tok",
        "http://my-org.my.salesforce.com",
    ));
    MetadataClient::builder()
        .auth(auth)
        .allow_insecure_transport(true)
        .build()
        .unwrap();
}

#[tokio::test]
async fn retry_read_timeouts_restores_replay_of_idempotent_operations() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_delay(std::time::Duration::from_secs(5)))
        .mount(&server)
        .await;

    let auth = Arc::new(StaticTokenAuth::new("tok", server.uri()));
    let md = MetadataClient::builder()
        .auth(auth)
        .read_timeout(std::time::Duration::from_millis(50))
        .retry_policy(RetryPolicy {
            max_retries: 2,
            base_delay: std::time::Duration::from_millis(1),
            max_delay: std::time::Duration::from_millis(5),
            jitter: false,
            retry_read_timeouts: true,
            ..RetryPolicy::default()
        })
        .build()
        .unwrap();

    let err = md.call(&Ping).await.unwrap_err();
    assert!(
        matches!(err, MetadataError::Http(ref e) if e.is_timeout()),
        "{err:?}"
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 3);
}

// -- Request headers ---------------------------------------------------------

const CALL_OPTIONS_AFTER_SESSION: &str = "</met:SessionHeader>\
     <met:CallOptions><met:client>cirrus-tests/1.0</met:client></met:CallOptions>\
     </soapenv:Header>";

fn empty_list_metadata_response() -> ResponseTemplate {
    ResponseTemplate::new(200)
        .insert_header("content-type", "text/xml; charset=UTF-8")
        .set_body_string(
            r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <listMetadataResponse xmlns="http://soap.sforce.com/2006/04/metadata"/>
  </soapenv:Body>
</soapenv:Envelope>"#,
        )
}

fn apex_class_query() -> Vec<ListMetadataQuery> {
    vec![ListMetadataQuery {
        type_name: "ApexClass".into(),
        folder: None,
    }]
}

fn client_with_call_options(server: &MockServer, client: &str) -> MetadataClient {
    MetadataClient::builder()
        .auth(Arc::new(StaticTokenAuth::new("tok", server.uri())))
        .call_options_client(client)
        .build()
        .unwrap()
}

/// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_calloptions.htm
/// CallOptions: "client | string | A value that identifies an API
/// client."; the header applies to all calls.
/// SOURCE: API 66.0 Metadata WSDL (sforce.660.metadata.wsdl): the
/// `CallOptions{client: string}` element, bound as an input header of
/// every operation except describeValueType.
#[tokio::test]
async fn call_options_client_rides_on_a_call_after_the_session_header() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(body_string_contains("<met:listMetadata>"))
        .and(body_string_contains(CALL_OPTIONS_AFTER_SESSION))
        .respond_with(empty_list_metadata_response())
        .expect(1)
        .mount(&server)
        .await;

    let md = client_with_call_options(&server, "cirrus-tests/1.0");
    md.list_metadata(apex_class_query(), "66.0").await.unwrap();
}

#[tokio::test]
async fn call_options_client_is_xml_escaped() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(body_string_contains(
            "<met:CallOptions><met:client>a&lt;b</met:client></met:CallOptions>",
        ))
        .respond_with(empty_list_metadata_response())
        .expect(1)
        .mount(&server)
        .await;

    let md = client_with_call_options(&server, "a<b");
    md.list_metadata(apex_class_query(), "66.0").await.unwrap();
}

#[tokio::test]
async fn a_client_without_call_options_sends_none() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(body_string_contains("CallOptions"))
        .respond_with(empty_list_metadata_response())
        .expect(0)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(body_string_contains(
            "</met:SessionHeader></soapenv:Header><soapenv:Body><met:listMetadata>",
        ))
        .respond_with(empty_list_metadata_response())
        .expect(1)
        .mount(&server)
        .await;

    let md = client_for(&server, Arc::new(StaticTokenAuth::new("tok", server.uri())));
    md.list_metadata(apex_class_query(), "66.0").await.unwrap();
}

/// SOURCE: API 66.0 Metadata WSDL (sforce.660.metadata.wsdl): the
/// binding of describeValueType lists only SessionHeader as an input
/// header; CallOptions is bound on every other operation.
#[tokio::test]
async fn describe_value_type_sends_no_call_options() {
    let server = MockServer::start().await;
    // Mounted first: a request carrying CallOptions would reach this
    // mock, not the one below, and fail its expectation.
    Mock::given(method("POST"))
        .and(body_string_contains("CallOptions"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(body_string_contains("<met:describeValueType>"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/xml; charset=UTF-8")
                .set_body_string(
                    r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <describeValueTypeResponse xmlns="http://soap.sforce.com/2006/04/metadata">
      <result>
        <apiCreatable>true</apiCreatable>
        <apiDeletable>true</apiDeletable>
        <apiReadable>true</apiReadable>
        <apiUpdatable>true</apiUpdatable>
      </result>
    </describeValueTypeResponse>
  </soapenv:Body>
</soapenv:Envelope>"#,
                ),
        )
        .expect(1)
        .mount(&server)
        .await;

    let md = client_with_call_options(&server, "cirrus-tests/1.0");
    md.describe_value_type("{http://soap.sforce.com/2006/04/metadata}ApexClass")
        .await
        .unwrap();
}

/// A custom operation that contributes its own header element.
struct PingWithHeaders {
    client_tag: &'static str,
}

impl SoapOperation for PingWithHeaders {
    const NAME: &'static str = "ping";
    const IDEMPOTENT: bool = true;
    type Response = PingResponse;
    fn render_body(&self) -> MetadataResult<String> {
        Ok(String::new())
    }
    fn render_headers(&self) -> MetadataResult<String> {
        Ok(format!(
            "<met:AllOrNoneHeader><met:allOrNone>true</met:allOrNone></met:AllOrNoneHeader>\
             <met:Custom>{}</met:Custom>",
            xml_escape(self.client_tag),
        ))
    }
}

/// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_headers.htm
/// Lists AllOrNoneHeader, CallOptions, DebuggingHeader and
/// SessionHeader as the Metadata API's SOAP headers.
#[tokio::test]
async fn a_custom_operations_headers_follow_the_clients_call_options() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(body_string_contains(
            "</met:SessionHeader>\
             <met:CallOptions><met:client>cirrus-tests/1.0</met:client></met:CallOptions>\
             <met:AllOrNoneHeader><met:allOrNone>true</met:allOrNone></met:AllOrNoneHeader>\
             <met:Custom>a&amp;b</met:Custom>\
             </soapenv:Header>",
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/xml; charset=UTF-8")
                .set_body_string(success_body("ok")),
        )
        .expect(1)
        .mount(&server)
        .await;

    let md = client_with_call_options(&server, "cirrus-tests/1.0");
    md.call(&PingWithHeaders { client_tag: "a&b" })
        .await
        .unwrap();
}

/// A custom operation can opt out of the client's CallOptions.
struct PingWithoutCallOptions;

impl SoapOperation for PingWithoutCallOptions {
    const NAME: &'static str = "ping";
    const ACCEPTS_CALL_OPTIONS: bool = false;
    type Response = PingResponse;
    fn render_body(&self) -> MetadataResult<String> {
        Ok(String::new())
    }
}

#[tokio::test]
async fn an_operation_can_decline_the_clients_call_options() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(body_string_contains("CallOptions"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/xml; charset=UTF-8")
                .set_body_string(success_body("ok")),
        )
        .expect(1)
        .mount(&server)
        .await;

    let md = client_with_call_options(&server, "cirrus-tests/1.0");
    md.call(&PingWithoutCallOptions).await.unwrap();
}

/// A failing `render_headers` surfaces before anything is sent.
struct PingWithBrokenHeaders;

impl SoapOperation for PingWithBrokenHeaders {
    const NAME: &'static str = "ping";
    type Response = PingResponse;
    fn render_body(&self) -> MetadataResult<String> {
        Ok(String::new())
    }
    fn render_headers(&self) -> MetadataResult<String> {
        Err(MetadataError::InvalidArgument("no header".into()))
    }
}

#[tokio::test]
async fn a_failing_render_headers_is_returned_without_a_request() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let md = client_for(&server, Arc::new(StaticTokenAuth::new("tok", server.uri())));
    let err = md.call(&PingWithBrokenHeaders).await.unwrap_err();
    assert!(matches!(err, MetadataError::InvalidArgument(_)));
}

// -- Response headers --------------------------------------------------------

fn success_body_with_header(header_xml: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns="http://soap.sforce.com/2006/04/metadata">
  <soapenv:Header>{header_xml}</soapenv:Header>
  <soapenv:Body>
    <pingResponse>
      <result><msg>ok</msg></result>
    </pingResponse>
  </soapenv:Body>
</soapenv:Envelope>"#
    )
}

/// SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_debuggingheader.htm
/// "After the deployment finishes, and if tests were run, the response
/// of checkDeployStatus() contains the debug log output in the
/// debugLog field of a DebuggingInfo output header."
/// SOURCE: API 66.0 Metadata WSDL (sforce.660.metadata.wsdl): the
/// `DebuggingInfo{debugLog: string}` element, an output header of
/// checkDeployStatus. The guide publishes no response envelope, so the
/// header's placement under `<soapenv:Header>` follows the WSDL's
/// binding, with the default metadata namespace on its children.
#[tokio::test]
async fn call_with_response_headers_returns_the_debugging_info_header() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/xml; charset=UTF-8")
                .set_body_string(success_body_with_header(
                    "<DebuggingInfo><debugLog>USER_DEBUG a &amp; b</debugLog></DebuggingInfo>",
                )),
        )
        .mount(&server)
        .await;

    let md = client_for(&server, Arc::new(StaticTokenAuth::new("tok", server.uri())));
    let (resp, headers) = md.call_with_response_headers(&Ping).await.unwrap();
    assert_eq!(resp.result.msg, "ok");
    assert_eq!(
        headers.debugging_info.unwrap().debug_log,
        "USER_DEBUG a & b"
    );
}

#[tokio::test]
async fn call_with_response_headers_has_no_debugging_info_without_the_header() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/xml; charset=UTF-8")
                .set_body_string(success_body("ok")),
        )
        .mount(&server)
        .await;

    let md = client_for(&server, Arc::new(StaticTokenAuth::new("tok", server.uri())));
    let (_, headers) = md.call_with_response_headers(&Ping).await.unwrap();
    assert!(headers.debugging_info.is_none());
}

#[tokio::test]
async fn a_malformed_debugging_info_names_the_header() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/xml; charset=UTF-8")
                .set_body_string(success_body_with_header(
                    "<DebuggingInfo><other>x</other></DebuggingInfo>",
                )),
        )
        .mount(&server)
        .await;

    let md = client_for(&server, Arc::new(StaticTokenAuth::new("tok", server.uri())));
    let err = md.call_with_response_headers(&Ping).await.unwrap_err();
    match err {
        MetadataError::Xml(msg) => assert!(msg.contains("DebuggingInfo"), "{msg}"),
        other => panic!("expected Xml, got {other:?}"),
    }
}

/// `call` discards the headers without failing on them.
#[tokio::test]
async fn call_ignores_response_headers() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/xml; charset=UTF-8")
                .set_body_string(success_body_with_header(
                    "<DebuggingInfo><debugLog>log</debugLog></DebuggingInfo>",
                )),
        )
        .mount(&server)
        .await;

    let md = client_for(&server, Arc::new(StaticTokenAuth::new("tok", server.uri())));
    md.call(&Ping).await.unwrap();
}

#[tokio::test]
async fn call_does_not_parse_a_response_header_it_discards() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/xml; charset=UTF-8")
                .set_body_string(success_body_with_header(
                    "<DebuggingInfo><other>x</other></DebuggingInfo>",
                )),
        )
        .mount(&server)
        .await;

    let md = client_for(&server, Arc::new(StaticTokenAuth::new("tok", server.uri())));
    md.call(&Ping).await.unwrap();
}

// -- Response size limits ------------------------------------------------------
//
// The envelopes are this file's `ping` fixtures; the gzip bodies exercise the
// transport rather than a Salesforce wire shape. SOURCE for the compressed
// response a client that sends `Accept-Encoding: gzip` must expect:
// https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/intro_rest_compression.htm
// (doc_version 264.0) — "If compressed, the response contains a
// Content-Encoding header with the compression algorithm so that your client
// knows to decompress it."

/// The fixed cap on a non-2xx body, mirrored from the crate.
const NON_SUCCESS_BODY_CAP: usize = 256 * 1024;

fn client_with_cap(
    server: &MockServer,
    cap: impl Into<Option<usize>>,
    policy: RetryPolicy,
) -> MetadataClient {
    MetadataClient::builder()
        .auth(Arc::new(StaticTokenAuth::new("tok", server.uri())))
        .max_response_size(cap)
        .retry_policy(policy)
        .build()
        .unwrap()
}

fn fast_retries() -> RetryPolicy {
    RetryPolicy {
        base_delay: std::time::Duration::ZERO,
        max_delay: std::time::Duration::ZERO,
        jitter: false,
        ..RetryPolicy::default()
    }
}

/// A gzip body a few kilobytes on the wire and `len` bytes decoded.
fn gzip_of_zeros(len: usize) -> Vec<u8> {
    use std::io::Write;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    encoder.write_all(&vec![0u8; len]).unwrap();
    encoder.finish().unwrap()
}

fn inflating_503() -> ResponseTemplate {
    ResponseTemplate::new(503)
        .insert_header("content-encoding", "gzip")
        .set_body_bytes(gzip_of_zeros(8 << 20))
}

#[test]
fn the_default_response_cap_covers_a_retrieve_and_is_reported_in_debug() {
    // SOURCE: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_retrieve.htm
    // "The resulting .zip file can't exceed 50 MB."
    assert_eq!(cirrus_metadata::DEFAULT_MAX_RESPONSE_SIZE, 128 << 20);
    const { assert!(cirrus_metadata::DEFAULT_MAX_RESPONSE_SIZE > 50 * 1_000_000) };
    let md = MetadataClient::builder()
        .auth(Arc::new(StaticTokenAuth::new(
            "tok",
            "https://my-org.my.salesforce.com",
        )))
        .build()
        .unwrap();
    assert!(
        format!("{md:?}").contains("max_response_size: Some(134217728)"),
        "{md:?}"
    );
}

#[tokio::test]
async fn a_success_body_over_the_cap_is_refused() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/xml")
                .set_body_string(success_body(&"x".repeat(4096))),
        )
        .mount(&server)
        .await;

    let md = client_with_cap(&server, 1024, RetryPolicy::none());
    let err = md.call(&Ping).await.unwrap_err();
    assert!(
        matches!(
            err,
            MetadataError::ResponseTooLarge {
                status: 200,
                limit: 1024
            }
        ),
        "{err:?}"
    );
}

#[tokio::test]
async fn no_cap_lets_a_body_through_that_a_cap_refuses() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/xml")
                .set_body_string(success_body(&"x".repeat(2 << 20))),
        )
        .mount(&server)
        .await;

    let capped = client_with_cap(&server, 1 << 20, RetryPolicy::none());
    let err = capped.call(&Ping).await.unwrap_err();
    assert!(
        matches!(err, MetadataError::ResponseTooLarge { status: 200, .. }),
        "{err:?}"
    );

    let uncapped = client_with_cap(&server, None, RetryPolicy::none());
    let resp = uncapped.call(&Ping).await.unwrap();
    assert_eq!(resp.result.msg.len(), 2 << 20);
}

#[tokio::test]
async fn a_gzip_error_body_is_capped_after_decoding() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(inflating_503())
        .mount(&server)
        .await;

    let md = client_with_cap(&server, None, RetryPolicy::none());
    let err = md.call(&Ping).await.unwrap_err();
    assert!(
        matches!(
            err,
            MetadataError::ResponseTooLarge {
                status: 503,
                limit: NON_SUCCESS_BODY_CAP
            }
        ),
        "{err:?}"
    );
}

#[tokio::test]
async fn a_retryable_status_with_an_oversized_body_is_retried() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(inflating_503())
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/xml")
                .set_body_string(success_body("hello")),
        )
        .expect(1)
        .mount(&server)
        .await;

    let md = client_with_cap(&server, None, fast_retries());
    let resp = md.call(&Ping).await.unwrap();
    assert_eq!(resp.result.msg, "hello");
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn an_oversized_body_is_reported_once_the_retries_are_spent() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(inflating_503())
        .mount(&server)
        .await;

    let md = client_with_cap(&server, None, fast_retries());
    let err = md.call(&Ping).await.unwrap_err();
    assert!(
        matches!(err, MetadataError::ResponseTooLarge { status: 503, .. }),
        "{err:?}"
    );
    // The first attempt plus the policy's retries.
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        1 + RetryPolicy::default().max_retries as usize
    );
}

#[tokio::test]
async fn an_oversized_body_on_a_status_that_is_not_retried_surfaces_at_once() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(inflating_503())
        .mount(&server)
        .await;

    // `Mutate` is not replay-safe, so a 503 is final.
    let md = client_with_cap(&server, None, fast_retries());
    let err = md.call(&Mutate).await.unwrap_err();
    assert!(
        matches!(err, MetadataError::ResponseTooLarge { status: 503, .. }),
        "{err:?}"
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

// -- Bodies that are not UTF-8 -------------------------------------------------

#[tokio::test]
async fn a_non_utf8_error_body_keeps_a_lossy_excerpt() {
    let server = MockServer::start().await;
    let mut body = b"<html>bad gateway ".to_vec();
    body.extend_from_slice(&[0xff, 0xfe]);
    body.extend_from_slice(b"</html>");
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(502).set_body_bytes(body))
        .mount(&server)
        .await;

    let md = client_with_cap(&server, None, RetryPolicy::none());
    let err = md.call(&Ping).await.unwrap_err();
    match err {
        MetadataError::Http4xx5xx { status, raw, .. } => {
            assert_eq!(status, 502);
            assert!(raw.contains("bad gateway"), "{raw}");
            assert!(raw.contains('\u{fffd}'), "{raw}");
        }
        other => panic!("expected Http4xx5xx, got {other:?}"),
    }
}

#[tokio::test]
async fn a_non_utf8_2xx_body_is_an_invalid_response_with_an_excerpt() {
    let server = MockServer::start().await;
    let mut body = b"<html>maintenance ".to_vec();
    body.extend_from_slice(&[0xff, 0xfe]);
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
        .mount(&server)
        .await;

    let md = client_with_cap(&server, None, RetryPolicy::none());
    let err = md.call(&Ping).await.unwrap_err();
    match err {
        MetadataError::InvalidResponse(msg) => {
            assert!(msg.contains("not valid UTF-8"), "{msg}");
            assert!(msg.contains("maintenance"), "{msg}");
        }
        other => panic!("expected InvalidResponse, got {other:?}"),
    }
}
