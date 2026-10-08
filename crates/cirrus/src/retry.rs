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
//!    mode than a one-shot error surfaced to the caller. Where the
//!    HTTP method misstates what an endpoint does, the call site says
//!    so with a [`Replay`]: Apex REST, anonymous Apex and the Bulk 2.0
//!    job-data upload never replay, so only 429 and connect-phase
//!    failures retry there, and the sObject Collections `POST`
//!    retrieve always replays because it is a read.
//!    [`Cirrus::send_with_replay`] gives callers the same choice.
//!
//!    Note on Salesforce specifics: the REST API's documented
//!    rate-limit signal is **403 with `errorCode:
//!    REQUEST_LIMIT_EXCEEDED`** (its status-code table doesn't include
//!    429 at all). Salesforce raises it for two different limits: the
//!    rolling 24-hour request quota, and the cap on concurrent
//!    long-running requests (5 on Developer Edition and trial orgs,
//!    25 on production orgs and sandboxes), which clears on its own
//!    as those requests finish. Only the message text tells the two
//!    apart, and Salesforce does not document it. The response is
//!    deliberately *not* retried either way: a replay inside the quota
//!    burns more of it, and this backoff (well under a second in total
//!    by default) cannot outlast requests that by definition have run
//!    for 20 seconds or more. 429 is retried anyway because proxies
//!    and API gateways in front of an org do emit it. See the
//!    [API request limits] cheat sheet.
//! 2. **Honor server hints.** When the server provides a
//!    [`Retry-After`] header — either RFC 7231 §7.1.3 form,
//!    delta-seconds or an HTTP-date — use that delay instead of our
//!    backoff schedule. A hint longer than
//!    [`max_delay`](RetryPolicy::max_delay) cannot be honored, and
//!    retrying sooner than the server asked only spends requests inside
//!    its window, so the response surfaces to the caller at once.
//! 3. **Jitter to avoid thundering herd.** Default policy applies
//!    *full jitter* — random uniform `[0, computed_delay]` — per
//!    AWS's recommendations for distributed clients hitting a shared
//!    backend.
//!
//! [`Retry-After`]: https://datatracker.ietf.org/doc/html/rfc7231#section-7.1.3
//! [`Cirrus::send_with_replay`]: crate::Cirrus::send_with_replay
//! [API request limits]: https://developer.salesforce.com/docs/platform/salesforce-app-limits-cheatsheet/guide/salesforce-app-limits-platform-api.html

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
    /// growth on high attempt counts. Default 30 s. Also the longest
    /// `Retry-After` hint the client will wait out: a longer hint ends
    /// the retry loop and the response surfaces to the caller.
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
    /// When `true`, a request that hits the read timeout is re-sent on
    /// the same terms as a connection reset — only when the call is
    /// replay-safe. Default `false`: the read timeout is the caller's
    /// deadline on getting an answer, a slow org is not a transient
    /// fault, and each replay takes another of the org's concurrent
    /// long-running-request slots. With this on, the worst case is
    /// `(max_retries + 1) × read_timeout` plus backoff, doubled across
    /// a 401 refresh. Connect-phase timeouts are unaffected: the request
    /// never reached the server, so they always retry.
    pub retry_read_timeouts: bool,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(30),
            jitter: true,
            retry_idempotent_5xx: true,
            retry_read_timeouts: false,
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
/// unknown: an ambiguous mid-request failure, or a 5xx that an
/// intermediary may have emitted after the origin already processed
/// the call.
///
/// Connect-phase failures and 429 responses retry under every variant,
/// because in both cases the request was never processed. The variant
/// only decides what happens once a request has reached the server.
/// Every typed verb and handler picks a value; pass one yourself
/// through [`Cirrus::send_with_replay`] when the HTTP method says
/// something different from what the endpoint does.
///
/// [`Cirrus::send_with_replay`]: crate::Cirrus::send_with_replay
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Replay {
    /// Replay whenever the request method is spec-idempotent (GET,
    /// HEAD, PUT, DELETE, OPTIONS, TRACE) and never for POST or PATCH.
    /// The default across the REST surface.
    #[default]
    ByMethod,
    /// Never replay once the request reached the server, whatever the
    /// method says. For endpoints whose method understates their
    /// effect: Apex REST, where a `GET` can run any Apex;
    /// `GET tooling/executeAnonymous`; and the Bulk 2.0 job-data `PUT`,
    /// which submits data rather than replacing it.
    Never,
    /// Replay whatever the method, for a read that rides a
    /// non-idempotent method. The sObject Collections retrieve carries
    /// its ID list in a `POST` body, so it uses this. Pass it only when
    /// the endpoint is documented as side-effect free.
    Always,
}

/// Whether an ambiguous outcome may be replayed.
fn is_replayable(method: &reqwest::Method, replay: Replay) -> bool {
    match replay {
        Replay::ByMethod => is_idempotent(method),
        Replay::Never => false,
        Replay::Always => true,
    }
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
        // replay is safe for any method. (Salesforce's own signal is
        // 403 REQUEST_LIMIT_EXCEEDED, for the daily quota and for the
        // concurrent long-running-request cap alike — deliberately not
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
/// Network errors that occur mid-request (a connection reset, a body
/// that stops) are ambiguous — the server may or may not have processed
/// the request before the connection dropped — so those retry only when
/// the request is replay-safe, where a duplicated effect is harmless.
/// A read timeout is surfaced rather than replayed unless
/// [`RetryPolicy::retry_read_timeouts`] is on: it is the caller's
/// deadline, and a replay would quietly multiply it. Connect-phase
/// errors (DNS failure, TCP RST, TLS handshake failure, connect
/// timeout) mean the request never reached the server, so retrying is
/// safe for any method. Same policy as the `cirrus-metadata` sibling.
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
    if http.is_timeout() && !policy.retry_read_timeouts {
        return false;
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

/// Compute the next backoff delay, or `None` when the retry should not
/// happen at all.
///
/// Precedence:
/// 1. A `Retry-After` hint within [`max_delay`](RetryPolicy::max_delay)
///    is used as is. A longer hint yields `None`: the client cannot
///    wait that long under its own policy, and retrying early would
///    land inside the window the server asked it to stay out of.
/// 2. Otherwise compute `base_delay * 2^attempt`, capped at
///    `max_delay`.
/// 3. If [`jitter`](RetryPolicy::jitter) is enabled, sample uniformly
///    from `[0, computed]`. If the random source fails, fall back to
///    the deterministic value.
pub(crate) fn compute_delay(
    policy: &RetryPolicy,
    attempt: u32,
    retry_after: Option<Duration>,
) -> Option<Duration> {
    if let Some(hint) = retry_after {
        if hint > policy.max_delay {
            tracing::warn!(
                target: "cirrus::retry",
                attempt = attempt + 1,
                retry_after_ms = hint.as_millis() as u64,
                max_delay_ms = policy.max_delay.as_millis() as u64,
                "Retry-After exceeds max_delay; surfacing the response instead of retrying",
            );
            return None;
        }
        tracing::warn!(
            target: "cirrus::retry",
            attempt = attempt + 1,
            delay_ms = hint.as_millis() as u64,
            source = "retry-after-header",
            "scheduling request retry",
        );
        return Some(hint);
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
                let sample = u64::from_le_bytes(buf);
                // `[0, max_ms]` inclusive. When max_ms is u64::MAX the
                // range is already the whole of u64, so the sample
                // stands as is — computing the span would overflow.
                let r = match max_ms.checked_add(1) {
                    Some(span) => sample % span,
                    None => sample,
                };
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
    Some(final_delay)
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

    #[test]
    fn always_replay_retries_5xx_on_post() {
        // The sObject Collections retrieve is a read sent as POST, so a
        // 5xx replays for it exactly as it would for the GET form.
        let p = RetryPolicy::default();
        for status in [500, 502, 503, 504] {
            assert!(should_retry_status(
                &p,
                &reqwest::Method::POST,
                Replay::Always,
                status,
                0
            ));
            assert!(!should_retry_status(
                &p,
                &reqwest::Method::POST,
                Replay::ByMethod,
                status,
                0
            ));
        }
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
        // processed the request already. By default the read timeout is
        // the caller's deadline, so it is surfaced for every call site.
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
        assert!(!should_retry_network(
            &p,
            &reqwest::Method::GET,
            Replay::ByMethod,
            &stalled,
            0
        ));

        // Opting into timeout replay re-enables it for replay-safe calls
        // only; `Never` still drops the ambiguous outcome.
        let p = RetryPolicy {
            retry_read_timeouts: true,
            ..RetryPolicy::default()
        };
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
    fn compute_delay_honors_a_retry_after_within_max_delay_and_refuses_a_longer_one() {
        let p = RetryPolicy {
            max_delay: Duration::from_secs(10),
            ..RetryPolicy::default()
        };
        // Within the cap, the hint is used as is — right up to the cap.
        assert_eq!(
            compute_delay(&p, 0, Some(Duration::from_secs(3))),
            Some(Duration::from_secs(3))
        );
        assert_eq!(
            compute_delay(&p, 0, Some(Duration::from_secs(10))),
            Some(Duration::from_secs(10))
        );
        // Beyond it, the retry does not happen: sleeping for a
        // truncated interval would retry inside the server's window.
        assert_eq!(compute_delay(&p, 0, Some(Duration::from_secs(99))), None);
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
        assert_eq!(compute_delay(&p, 0, None), Some(Duration::from_millis(100)));
        assert_eq!(compute_delay(&p, 1, None), Some(Duration::from_millis(200)));
        assert_eq!(compute_delay(&p, 2, None), Some(Duration::from_millis(400)));
        assert_eq!(compute_delay(&p, 3, None), Some(Duration::from_millis(800)));
        // 100ms * 2^4 = 1600ms → clamped to 1000ms (max_delay).
        assert_eq!(compute_delay(&p, 4, None), Some(Duration::from_secs(1)));
        // Way beyond cap — still clamped, no overflow.
        assert_eq!(compute_delay(&p, 100, None), Some(Duration::from_secs(1)));
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
            let d = compute_delay(&p, 2, None).unwrap();
            assert!(d <= Duration::from_millis(400));
        }
    }

    #[test]
    fn compute_delay_survives_an_unbounded_max_delay() {
        // "No ceiling" is expressible through the public policy, and at
        // a high attempt count the capped delay saturates at u64::MAX
        // milliseconds — the upper edge of the jitter sample.
        let p = RetryPolicy {
            max_retries: 60,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::MAX,
            jitter: true,
            ..RetryPolicy::default()
        };
        for attempt in [0, 57, 58, 63, 64, 100] {
            let d = compute_delay(&p, attempt, None).unwrap();
            assert!(d <= Duration::from_millis(u64::MAX));
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
        assert_eq!(compute_delay(&p, 0, None), Some(Duration::ZERO));
        assert_eq!(compute_delay(&p, 5, None), Some(Duration::ZERO));
    }
}
