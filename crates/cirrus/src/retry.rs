//! Retry policy and backoff machinery for transient HTTP failures.
//!
//! Salesforce's REST surface (and any HTTP API) periodically emits
//! transient failures — rate limits (429), service unavailable (503),
//! short-lived 5xx, network blips. A small amount of automatic retry
//! with exponential backoff hides almost all of these from the caller
//! without sacrificing correctness.
//!
//! This module is designed around three principles:
//!
//! 1. **Default to "do less."** 429 (rate limited — the server refused
//!    the request without processing it) retries for any method; every
//!    5xx, 503 included, retries only on request methods that are
//!    spec-idempotent (GET, HEAD, DELETE, PUT), because nothing
//!    guarantees the request wasn't processed before an intermediary
//!    emitted the error — and a duplicate `INSERT` is a worse failure
//!    mode than a one-shot error surfaced to the caller. A handler
//!    whose HTTP method understates its effect (anonymous Apex over
//!    GET, a Bulk 2.0 job-data upload over PUT) opts out of replay
//!    entirely, so only 429 and connect-phase failures retry there.
//!
//!    Note on Salesforce specifics: the REST API's documented
//!    rate-limit signal is **403 with `errorCode:
//!    REQUEST_LIMIT_EXCEEDED`** (its status-code table doesn't include
//!    429 at all). That response is deliberately *not* retried — it
//!    means a rolling 24-hour quota is exhausted, and replaying only
//!    burns more of it. 429 is retried anyway because proxies and API
//!    gateways in front of an org do emit it.
//! 2. **Honor server hints.** When the server provides a
//!    [`Retry-After`] header — either RFC 7231 §7.1.3 form,
//!    delta-seconds or an HTTP-date — use that delay instead of our
//!    backoff schedule.
//! 3. **Jitter to avoid thundering herd.** Default policy applies
//!    *full jitter* — random uniform `[0, computed_delay]` — per
//!    AWS's recommendations for distributed clients hitting a shared
//!    backend.
//!
//! [`Retry-After`]: https://datatracker.ietf.org/doc/html/rfc7231#section-7.1.3

use crate::error::CirrusError;
use std::time::Duration;

/// Configuration for retry-on-transient-failure behavior.
///
/// Construct via [`RetryPolicy::default`] for sensible defaults, or
/// [`RetryPolicy::none`] to disable retries entirely. All fields are
/// public for ad-hoc tweaking.
///
/// # Example
///
/// ```no_run
/// use cirrus::{Cirrus, RetryPolicy, auth::StaticTokenAuth};
/// use std::sync::Arc;
/// use std::time::Duration;
///
/// # fn example() -> Result<(), cirrus::CirrusError> {
/// let policy = RetryPolicy {
///     max_retries: 5,
///     base_delay: Duration::from_millis(250),
///     ..RetryPolicy::default()
/// };
/// let auth = Arc::new(StaticTokenAuth::new("tok", "https://x.my.salesforce.com"));
/// let sf = Cirrus::builder()
///     .auth(auth)
///     .retry_policy(policy)
///     .build()?;
/// # let _ = sf;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Maximum number of *additional* attempts after the initial
    /// request. `0` disables retries; `3` (default) means up to four
    /// total attempts.
    pub max_retries: u32,
    /// Base delay for the exponential backoff schedule. Default
    /// 100 ms.
    pub base_delay: Duration,
    /// Cap on the computed backoff delay — prevents pathological
    /// growth on high attempt counts. Default 30 s.
    pub max_delay: Duration,
    /// Apply *full jitter* — pick a random delay in `[0, computed]`
    /// rather than using the deterministic exponential value. Default
    /// `true`, recommended for distributed clients.
    pub jitter: bool,
    /// When `true`, retry idempotent methods (GET, HEAD, DELETE, PUT)
    /// on transient 5xx errors (500, 502, 504). When `false`, only
    /// retry on 429 (any method) and 503 (idempotent methods — 503 is
    /// the canonical "temporarily unavailable, try again" status, so
    /// it stays retryable even with this flag off). Default `true`.
    ///
    /// Non-idempotent methods (POST, PATCH) are *never* retried on
    /// 5xx, regardless of this flag — duplicate-record risk outweighs
    /// the convenience.
    pub retry_idempotent_5xx: bool,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(30),
            jitter: true,
            retry_idempotent_5xx: true,
        }
    }
}

impl RetryPolicy {
    /// A policy that disables retries. Useful for non-idempotent flows
    /// or for tests that want deterministic single-shot semantics.
    pub fn none() -> Self {
        Self {
            max_retries: 0,
            ..Self::default()
        }
    }
}

/// Whether a request may be re-sent when the outcome of an attempt is
/// unknown — an ambiguous mid-request failure, or a 5xx that an
/// intermediary may have emitted after the origin already processed the
/// call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Replay {
    /// Replay whenever the request method is spec-idempotent. The
    /// default across the REST surface.
    ByMethod,
    /// Never replay once the request reached the server, whatever the
    /// method says. Connect-phase failures still retry (the request
    /// never arrived) and so does 429 (the request was refused rather
    /// than processed).
    ///
    /// For the call sites whose HTTP method understates their effect:
    /// `GET tooling/executeAnonymous` runs arbitrary Apex, and `PUT
    /// jobs/ingest/{job}/batches` submits job data rather than
    /// replacing a resource.
    Never,
}

/// Whether an ambiguous outcome may be replayed: the method has to be
/// spec-idempotent *and* the call site must not have opted out.
fn is_replayable(method: &reqwest::Method, replay: Replay) -> bool {
    matches!(replay, Replay::ByMethod) && is_idempotent(method)
}

/// Decision point: should we retry this HTTP response?
///
/// `attempt` is the zero-indexed *previous* attempt count — i.e. on
/// the first call after the initial failure, `attempt == 0`. This
/// makes the comparison `attempt < max_retries` directly express
/// "have we already retried fewer times than the cap?".
pub(crate) fn should_retry_status(
    policy: &RetryPolicy,
    method: &reqwest::Method,
    replay: Replay,
    status: u16,
    attempt: u32,
) -> bool {
    if attempt >= policy.max_retries {
        return false;
    }
    match status {
        // Rate limited: the request was refused, not processed, so a
        // replay is safe for any method. (Salesforce's own rate-limit
        // signal is 403 REQUEST_LIMIT_EXCEEDED — deliberately not
        // retried, see the module doc; 429 comes from intermediaries.)
        429 => true,
        // 503 is the canonical "temporarily unavailable" status, but
        // an intermediary can emit it after the origin processed the
        // request — so like every other 5xx it only replays when the
        // request is replay-safe. Unlike 500/502/504 it stays
        // retryable even when `retry_idempotent_5xx` is off.
        503 => is_replayable(method, replay),
        500 | 502 | 504 if policy.retry_idempotent_5xx => is_replayable(method, replay),
        _ => false,
    }
}

/// Decision point: should we retry this network-level failure?
///
/// Network errors that occur mid-request (connection reset, read
/// timeout) are ambiguous — the server may or may not have processed
/// the request before the connection dropped — so those retry only when
/// the request is replay-safe, where a duplicated effect is harmless.
/// Connect-phase errors (DNS failure, TCP RST, TLS handshake failure,
/// connect timeout) mean the request never reached the server, so
/// retrying is safe for any method. Same policy as the
/// `cirrus-metadata` sibling.
///
/// Errors raised while *building* the request — an instance URL that
/// doesn't parse, a header value reqwest rejects — are permanent: no
/// amount of backoff turns them into a request, so they surface on the
/// first attempt instead of burning the budget on identical failures.
pub(crate) fn should_retry_network(
    policy: &RetryPolicy,
    method: &reqwest::Method,
    replay: Replay,
    error: &CirrusError,
    attempt: u32,
) -> bool {
    if attempt >= policy.max_retries {
        return false;
    }
    let CirrusError::Http(http) = error else {
        return false;
    };
    if http.is_builder() {
        return false;
    }
    if http.is_connect() {
        return true;
    }
    is_replayable(method, replay)
}

fn is_idempotent(method: &reqwest::Method) -> bool {
    matches!(
        *method,
        reqwest::Method::GET
            | reqwest::Method::HEAD
            | reqwest::Method::DELETE
            | reqwest::Method::PUT
            | reqwest::Method::OPTIONS
            | reqwest::Method::TRACE
    )
}

/// Parse a `Retry-After` header value in either RFC 7231 §7.1.3 form:
/// delta-seconds, or an HTTP-date converted to the delay remaining
/// until then. A date already in the past yields
/// [`Duration::ZERO`] — the server is saying "now".
///
/// Both forms matter here because the 429/503 responses this reads come
/// from proxies and API gateways in front of the org rather than from
/// Salesforce itself, and those emit either shape.
pub(crate) fn parse_retry_after(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    let raw = headers.get(reqwest::header::RETRY_AFTER)?;
    let s = raw.to_str().ok()?.trim();
    if let Ok(secs) = s.parse::<u64>() {
        return Some(Duration::from_secs(secs));
    }
    let deadline = httpdate::parse_http_date(s).ok()?;
    Some(
        deadline
            .duration_since(std::time::SystemTime::now())
            .unwrap_or(Duration::ZERO),
    )
}

/// Compute the next backoff delay.
///
/// Precedence:
/// 1. If a `Retry-After` hint is present, honor it (capped at
///    [`max_delay`](RetryPolicy::max_delay)).
/// 2. Otherwise compute `base_delay * 2^attempt`, capped at
///    `max_delay`.
/// 3. If [`jitter`](RetryPolicy::jitter) is enabled, sample uniformly
///    from `[0, computed]`. If the random source fails, fall back to
///    the deterministic value.
pub(crate) fn compute_delay(
    policy: &RetryPolicy,
    attempt: u32,
    retry_after: Option<Duration>,
) -> Duration {
    if let Some(hint) = retry_after {
        let capped = hint.min(policy.max_delay);
        tracing::warn!(
            target: "cirrus::retry",
            attempt = attempt + 1,
            delay_ms = capped.as_millis() as u64,
            source = "retry-after-header",
            "scheduling request retry",
        );
        return capped;
    }
    // base_delay * 2^attempt, in milliseconds, saturating on overflow.
    let factor: u128 = 1u128.checked_shl(attempt).unwrap_or(u128::MAX);
    let computed_ms = policy.base_delay.as_millis().saturating_mul(factor);
    // Saturate to max_delay so we never sleep more than the cap.
    let max_ms = policy.max_delay.as_millis();
    let capped_ms = computed_ms.min(max_ms);
    let computed = Duration::from_millis(capped_ms.min(u64::MAX as u128) as u64);

    let final_delay = if !policy.jitter {
        computed
    } else {
        let max_ms = computed.as_millis() as u64;
        if max_ms == 0 {
            Duration::ZERO
        } else {
            let mut buf = [0u8; 8];
            if getrandom::fill(&mut buf).is_err() {
                // Random source down — degrade gracefully to deterministic.
                computed
            } else {
                let r = u64::from_le_bytes(buf) % (max_ms + 1);
                Duration::from_millis(r)
            }
        }
    };
    tracing::warn!(
        target: "cirrus::retry",
        attempt = attempt + 1,
        delay_ms = final_delay.as_millis() as u64,
        source = "exponential-backoff",
        "scheduling request retry",
    );
    final_delay
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_retries_three_times() {
        let p = RetryPolicy::default();
        assert_eq!(p.max_retries, 3);
        assert!(p.jitter);
        assert!(p.retry_idempotent_5xx);
    }

    #[test]
    fn none_policy_disables_retry() {
        let p = RetryPolicy::none();
        assert!(!should_retry_status(
            &p,
            &reqwest::Method::GET,
            Replay::ByMethod,
            429,
            0
        ));
        assert!(!should_retry_status(
            &p,
            &reqwest::Method::GET,
            Replay::ByMethod,
            503,
            0
        ));
    }

    #[test]
    fn retries_429_for_any_method() {
        let p = RetryPolicy::default();
        for m in [
            reqwest::Method::GET,
            reqwest::Method::POST,
            reqwest::Method::PATCH,
            reqwest::Method::DELETE,
        ] {
            assert!(
                should_retry_status(&p, &m, Replay::ByMethod, 429, 0),
                "429 retry for {m}"
            );
        }
    }

    #[test]
    fn retries_5xx_only_for_idempotent_methods() {
        let p = RetryPolicy::default();
        for status in [500, 502, 503, 504] {
            assert!(should_retry_status(
                &p,
                &reqwest::Method::GET,
                Replay::ByMethod,
                status,
                0
            ));
            assert!(should_retry_status(
                &p,
                &reqwest::Method::DELETE,
                Replay::ByMethod,
                status,
                0
            ));
            assert!(should_retry_status(
                &p,
                &reqwest::Method::PUT,
                Replay::ByMethod,
                status,
                0
            ));
            // Non-idempotent — never retry, 503 included: an
            // intermediary may emit it after the origin processed
            // the request.
            assert!(!should_retry_status(
                &p,
                &reqwest::Method::POST,
                Replay::ByMethod,
                status,
                0
            ));
            assert!(!should_retry_status(
                &p,
                &reqwest::Method::PATCH,
                Replay::ByMethod,
                status,
                0
            ));
        }
    }

    #[tokio::test]
    async fn retries_connect_errors_for_any_method() {
        // Port 1 on loopback is unbound, so the connect is refused
        // before any request bytes are written — a real connect-phase
        // reqwest::Error without touching the network.
        let p = RetryPolicy::default();
        let err: CirrusError = reqwest::Client::new()
            .post("http://127.0.0.1:1/")
            .send()
            .await
            .unwrap_err()
            .into();
        assert!(should_retry_network(
            &p,
            &reqwest::Method::POST,
            Replay::ByMethod,
            &err,
            0
        ));
        assert!(should_retry_network(
            &p,
            &reqwest::Method::PATCH,
            Replay::ByMethod,
            &err,
            0
        ));
        assert!(should_retry_network(
            &p,
            &reqwest::Method::GET,
            Replay::ByMethod,
            &err,
            0
        ));
        // The cap still applies.
        assert!(!should_retry_network(
            &p,
            &reqwest::Method::POST,
            Replay::ByMethod,
            &err,
            3
        ));
    }

    #[tokio::test]
    async fn does_not_retry_request_builder_errors() {
        // An unparseable URL is latched by the builder and returned
        // from send(); replaying it can only fail the same way.
        let p = RetryPolicy::default();
        let err: CirrusError = reqwest::Client::new()
            .get("not a url/services/data/v66.0/limits")
            .send()
            .await
            .unwrap_err()
            .into();
        match &err {
            CirrusError::Http(http) => assert!(http.is_builder(), "expected a builder error"),
            other => panic!("expected a transport error, got {other:?}"),
        }
        assert!(!should_retry_network(
            &p,
            &reqwest::Method::GET,
            Replay::ByMethod,
            &err,
            0
        ));
    }

    #[test]
    fn never_replay_blocks_5xx_retry_on_idempotent_methods() {
        // GET tooling/executeAnonymous and PUT jobs/ingest/{id}/batches
        // ride idempotent methods but must not be replayed once the
        // request has reached the org.
        let p = RetryPolicy::default();
        for status in [500, 502, 503, 504] {
            assert!(!should_retry_status(
                &p,
                &reqwest::Method::GET,
                Replay::Never,
                status,
                0
            ));
            assert!(!should_retry_status(
                &p,
                &reqwest::Method::PUT,
                Replay::Never,
                status,
                0
            ));
        }
        // 429 means the request was refused before processing, so it
        // stays retryable even for a non-replayable call.
        assert!(should_retry_status(
            &p,
            &reqwest::Method::GET,
            Replay::Never,
            429,
            0
        ));
    }

    #[tokio::test]
    async fn never_replay_keeps_connect_retries_but_drops_ambiguous_ones() {
        let p = RetryPolicy::default();
        let connect_err: CirrusError = reqwest::Client::new()
            .get("http://127.0.0.1:1/")
            .send()
            .await
            .unwrap_err()
            .into();
        // Nothing reached the server, so a replay can't duplicate an
        // effect — this retries whatever the call site asked for.
        assert!(should_retry_network(
            &p,
            &reqwest::Method::GET,
            Replay::Never,
            &connect_err,
            0
        ));

        // A response that never arrives is ambiguous: the org may have
        // processed the request already.
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_delay(Duration::from_secs(30)))
            .mount(&server)
            .await;
        let stalled: CirrusError = reqwest::Client::builder()
            .read_timeout(Duration::from_millis(50))
            .build()
            .unwrap()
            .get(server.uri())
            .send()
            .await
            .unwrap_err()
            .into();
        assert!(should_retry_network(
            &p,
            &reqwest::Method::GET,
            Replay::ByMethod,
            &stalled,
            0
        ));
        assert!(!should_retry_network(
            &p,
            &reqwest::Method::GET,
            Replay::Never,
            &stalled,
            0
        ));
    }

    #[test]
    fn does_not_retry_4xx_caller_errors() {
        let p = RetryPolicy::default();
        for status in [400, 401, 403, 404, 405, 422] {
            assert!(
                !should_retry_status(&p, &reqwest::Method::GET, Replay::ByMethod, status, 0),
                "should not retry {status}"
            );
        }
    }

    #[test]
    fn stops_retrying_at_max_retries() {
        let p = RetryPolicy::default();
        assert!(should_retry_status(
            &p,
            &reqwest::Method::GET,
            Replay::ByMethod,
            429,
            0
        ));
        assert!(should_retry_status(
            &p,
            &reqwest::Method::GET,
            Replay::ByMethod,
            429,
            2
        ));
        // attempt == 3 means we've already retried 3 times — stop.
        assert!(!should_retry_status(
            &p,
            &reqwest::Method::GET,
            Replay::ByMethod,
            429,
            3
        ));
        assert!(!should_retry_status(
            &p,
            &reqwest::Method::GET,
            Replay::ByMethod,
            429,
            99
        ));
    }

    #[test]
    fn retry_5xx_disabled_skips_other_5xx_but_keeps_429_503() {
        let p = RetryPolicy {
            retry_idempotent_5xx: false,
            ..RetryPolicy::default()
        };
        assert!(should_retry_status(
            &p,
            &reqwest::Method::GET,
            Replay::ByMethod,
            429,
            0
        ));
        assert!(should_retry_status(
            &p,
            &reqwest::Method::GET,
            Replay::ByMethod,
            503,
            0
        ));
        assert!(!should_retry_status(
            &p,
            &reqwest::Method::GET,
            Replay::ByMethod,
            500,
            0
        ));
        assert!(!should_retry_status(
            &p,
            &reqwest::Method::GET,
            Replay::ByMethod,
            502,
            0
        ));
        // The 503 carve-out is idempotent-methods-only.
        assert!(!should_retry_status(
            &p,
            &reqwest::Method::POST,
            Replay::ByMethod,
            503,
            0
        ));
    }

    #[test]
    fn parse_retry_after_handles_seconds() {
        let mut h = reqwest::header::HeaderMap::new();
        h.insert(
            reqwest::header::RETRY_AFTER,
            reqwest::header::HeaderValue::from_static("5"),
        );
        assert_eq!(parse_retry_after(&h), Some(Duration::from_secs(5)));
    }

    #[test]
    fn parse_retry_after_handles_http_date_in_the_future() {
        let deadline = std::time::SystemTime::now() + Duration::from_secs(120);
        let mut h = reqwest::header::HeaderMap::new();
        h.insert(
            reqwest::header::RETRY_AFTER,
            reqwest::header::HeaderValue::from_str(&httpdate::fmt_http_date(deadline)).unwrap(),
        );
        let d = parse_retry_after(&h).expect("HTTP-date form should parse");
        // The header has one-second resolution, so allow a little slack.
        assert!(
            d >= Duration::from_secs(118) && d <= Duration::from_secs(121),
            "expected roughly 120s, got {d:?}",
        );
    }

    #[test]
    fn parse_retry_after_clamps_a_past_http_date_to_zero() {
        let mut h = reqwest::header::HeaderMap::new();
        h.insert(
            reqwest::header::RETRY_AFTER,
            reqwest::header::HeaderValue::from_static("Wed, 21 Oct 2015 07:28:00 GMT"),
        );
        assert_eq!(parse_retry_after(&h), Some(Duration::ZERO));
    }

    #[test]
    fn parse_retry_after_returns_none_for_unparseable_values() {
        let mut h = reqwest::header::HeaderMap::new();
        h.insert(
            reqwest::header::RETRY_AFTER,
            reqwest::header::HeaderValue::from_static("soonish"),
        );
        assert_eq!(parse_retry_after(&h), None);
    }

    #[test]
    fn parse_retry_after_returns_none_when_absent() {
        let h = reqwest::header::HeaderMap::new();
        assert_eq!(parse_retry_after(&h), None);
    }

    #[test]
    fn compute_delay_honors_retry_after_capped_at_max() {
        let p = RetryPolicy {
            max_delay: Duration::from_secs(10),
            ..RetryPolicy::default()
        };
        // Hint within cap → use it.
        assert_eq!(
            compute_delay(&p, 0, Some(Duration::from_secs(3))),
            Duration::from_secs(3)
        );
        // Hint over cap → clamp.
        assert_eq!(
            compute_delay(&p, 0, Some(Duration::from_secs(99))),
            Duration::from_secs(10)
        );
    }

    #[test]
    fn compute_delay_caps_exponential_at_max_delay() {
        // No jitter so we can assert exact values.
        let p = RetryPolicy {
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(1),
            jitter: false,
            ..RetryPolicy::default()
        };
        assert_eq!(compute_delay(&p, 0, None), Duration::from_millis(100));
        assert_eq!(compute_delay(&p, 1, None), Duration::from_millis(200));
        assert_eq!(compute_delay(&p, 2, None), Duration::from_millis(400));
        assert_eq!(compute_delay(&p, 3, None), Duration::from_millis(800));
        // 100ms * 2^4 = 1600ms → clamped to 1000ms (max_delay).
        assert_eq!(compute_delay(&p, 4, None), Duration::from_secs(1));
        // Way beyond cap — still clamped, no overflow.
        assert_eq!(compute_delay(&p, 100, None), Duration::from_secs(1));
    }

    #[test]
    fn compute_delay_jitter_stays_within_bounds() {
        let p = RetryPolicy {
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(60),
            jitter: true,
            ..RetryPolicy::default()
        };
        // 100ms * 2^2 = 400ms ceiling.
        for _ in 0..50 {
            let d = compute_delay(&p, 2, None);
            assert!(d <= Duration::from_millis(400));
        }
    }

    #[test]
    fn compute_delay_with_zero_base_returns_zero() {
        let p = RetryPolicy {
            base_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
            jitter: true,
            ..RetryPolicy::default()
        };
        assert_eq!(compute_delay(&p, 0, None), Duration::ZERO);
        assert_eq!(compute_delay(&p, 5, None), Duration::ZERO);
    }
}
