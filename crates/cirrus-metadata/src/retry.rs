//! Retry policy and backoff machinery for transient HTTP failures.
//!
//! Policy: retry only what's clearly safe — 429 (rate limited, the
//! request was refused without being processed) for every operation,
//! and 5xx / mid-request network failures only for operations declared
//! idempotent — honor a `Retry-After` hint up to
//! [`RetryPolicy::max_delay`] and surface the response when the hint is
//! longer, and add jitter to avoid thundering herds. A read timeout is
//! surfaced rather than replayed unless
//! [`RetryPolicy::retry_read_timeouts`] is on. The same rules apply in
//! `cirrus`.
//!
//! The Metadata API SOAP endpoint is always POST, so the HTTP method
//! carries no idempotency signal; instead each [`SoapOperation`]
//! declares whether it is safe to replay via
//! [`SoapOperation::idempotent()`], which defaults to the
//! [`SoapOperation::IDEMPOTENT`] const. Read-only calls
//! (`checkDeployStatus`, `listMetadata`, …) are; mutating calls
//! (`deploy`, `createMetadata`, …) are not — a 503 emitted by an
//! intermediary after the origin processed a `create` would otherwise be
//! replayed into a duplicate. Not every status poll qualifies:
//! `checkRetrieveStatus` is replayable only while `includeZip` is
//! `false`, because the call that returns the zip also deletes it from
//! the server, so it decides per request rather than per operation.
//! Retries apply only to the SOAP dispatch path; the open-ended
//! [`request_builder`] escape hatch is hands-off.
//!
//! Status alone doesn't settle it. The Metadata API delivers SOAP faults
//! with HTTP 500, so the dispatcher parses the response envelope before
//! deciding: a parsed fault replays only when its code is one Salesforce
//! documents as a temporarily unavailable server, and every other fault
//! is surfaced on the first attempt.
//!
//! [`SoapOperation`]: crate::transport::SoapOperation
//! [`SoapOperation::idempotent()`]: crate::transport::SoapOperation::idempotent
//! [`SoapOperation::IDEMPOTENT`]: crate::transport::SoapOperation::IDEMPOTENT
//! [`request_builder`]: crate::MetadataClient::request_builder

use crate::error::{MetadataError, SoapFault};
use std::time::Duration;

/// Configuration for transient-failure retry behavior.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Maximum number of *additional* attempts after the initial
    /// request. `0` disables retries; `3` (default) means up to four
    /// total attempts.
    pub max_retries: u32,
    /// Base delay for the exponential backoff schedule. Default 100 ms.
    pub base_delay: Duration,
    /// Cap on the computed backoff delay. Default 30 s. Also the
    /// longest `Retry-After` hint the client will wait out: a longer
    /// hint ends the retry loop and the response surfaces to the caller.
    pub max_delay: Duration,
    /// Apply full jitter — pick a random delay in `[0, computed]`
    /// rather than using the deterministic exponential value. Default
    /// `true`.
    pub jitter: bool,
    /// When `true`, retry idempotent operations on transient 5xx
    /// errors (500, 502, 504). When `false`, only retry on 429 (any
    /// operation) and 503 (idempotent operations). Default `true`.
    ///
    /// Non-idempotent operations (`deploy`, the CRUD calls, …) are
    /// *never* retried on 5xx, regardless of this flag.
    pub retry_idempotent_5xx: bool,
    /// When `true`, a request that hits the read timeout is re-sent on
    /// the same terms as a connection reset — only for an idempotent
    /// operation. Default `false`: the read timeout is the caller's
    /// deadline on getting an answer, a `checkDeployStatus` the org
    /// takes 150 s to build is not a transient fault, and each replay
    /// makes the org build it again. With this on, the worst case is
    /// `(max_retries + 1) × read_timeout` plus backoff, doubled across
    /// an `INVALID_SESSION_ID` refresh. Connect-phase timeouts are
    /// unaffected: the request never reached the server, so they
    /// always retry.
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

/// Decision point: should we retry this HTTP response?
///
/// `attempt` is the zero-indexed *previous* attempt count.
/// `idempotent` is the operation's [`IDEMPOTENT`] declaration — the
/// SOAP surface is POST-only, so the HTTP method can't stand in for it.
///
/// [`IDEMPOTENT`]: crate::transport::SoapOperation::IDEMPOTENT
pub(crate) fn should_retry_status(
    policy: &RetryPolicy,
    idempotent: bool,
    status: u16,
    attempt: u32,
) -> bool {
    if attempt >= policy.max_retries {
        return false;
    }
    match status {
        // Rate limited: the request was refused, not processed, so a
        // replay is safe for any operation.
        429 => true,
        // 503 is the canonical "temporarily unavailable" status, but
        // an intermediary can emit it after the origin processed the
        // request — so it only replays idempotent operations. Unlike
        // 500/502/504 it stays retryable even when
        // `retry_idempotent_5xx` is off.
        503 => idempotent,
        500 | 502 | 504 if policy.retry_idempotent_5xx => idempotent,
        _ => false,
    }
}

/// Exception codes that describe a temporarily unavailable server
/// rather than a problem with the request.
///
/// Salesforce answers a Metadata API SOAP fault with HTTP 500, so the
/// status alone can't tell a deterministic application error from a
/// transient one. Everything outside this list is left out on purpose.
/// `INVALID_TYPE`, `INVALID_CROSS_REFERENCE_KEY` and
/// `INVALID_SESSION_ID` return the same fault on every attempt, so
/// replaying them only spends API calls and delays the error.
/// `REQUEST_LIMIT_EXCEEDED` is different: it signals the rolling
/// 24-hour quota, where a replay burns more of it, but also the cap on
/// concurrent long-running requests, which clears by itself as they
/// finish. A replay of that case would need a backoff far longer than
/// this policy's (under a second in total by default), because the
/// requests holding the slots have by definition run for 20 seconds or
/// more; a caller that wants to wait them out does so around the call.
///
/// Descriptions from the `ExceptionCode` reference:
/// `SERVER_UNAVAILABLE` — "A server that's necessary for this call is
/// unavailable. Other types of requests could still work.";
/// `API_CURRENTLY_DISABLED` — "Because of a system problem, API
/// functionality is temporarily unavailable."
/// <https://developer.salesforce.com/docs/atlas.en-us.api.meta/api/sforce_api_calls_concepts_core_data_objects.htm>
const TRANSIENT_FAULT_CODES: [&str; 2] = ["SERVER_UNAVAILABLE", "API_CURRENTLY_DISABLED"];

/// Decision point: is this SOAP fault worth replaying?
///
/// Applied on top of [`should_retry_status`] — a fault only replays when
/// both the status and the fault code say the attempt can succeed.
pub(crate) fn is_transient_fault(fault: &SoapFault) -> bool {
    TRANSIENT_FAULT_CODES.contains(&fault.code())
}

/// Decision point: should we retry this network-level failure?
///
/// Errors raised while *building* the request — an instance URL that
/// doesn't parse, a header value reqwest rejects — are permanent: no
/// amount of backoff turns them into a request, so they surface on the
/// first attempt instead of burning the budget on identical failures.
/// Connect-phase errors mean the request never reached the server, so
/// retrying is safe even for non-idempotent operations; this covers DNS
/// failures, TCP RSTs, TLS handshake failures and connect timeouts. A
/// read timeout is the caller's deadline and is surfaced unless
/// [`RetryPolicy::retry_read_timeouts`] is on. Every other mid-request
/// failure is ambiguous — the server may have processed the request —
/// so it replays only idempotent operations.
pub(crate) fn should_retry_network(
    policy: &RetryPolicy,
    idempotent: bool,
    error: &MetadataError,
    attempt: u32,
) -> bool {
    if attempt >= policy.max_retries {
        return false;
    }
    let MetadataError::Http(http) = error else {
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
    idempotent
}

/// Parse a `Retry-After` header value in either RFC 7231 §7.1.3 form:
/// delta-seconds, or an HTTP-date converted to the delay remaining
/// until then. A date already in the past yields [`Duration::ZERO`] —
/// the server is saying "now".
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
/// A `Retry-After` hint within [`RetryPolicy::max_delay`] is used as is.
/// A longer hint yields `None`: the client cannot wait that long under
/// its own policy, and retrying early would land inside the window the
/// server asked it to stay out of. Without a hint the delay is
/// `base_delay * 2^attempt`, capped at `max_delay` and jittered when
/// the policy says so.
pub(crate) fn compute_delay(
    policy: &RetryPolicy,
    attempt: u32,
    retry_after: Option<Duration>,
) -> Option<Duration> {
    if let Some(hint) = retry_after {
        if hint > policy.max_delay {
            tracing::warn!(
                target: "cirrus_metadata::retry",
                attempt = attempt + 1,
                retry_after_ms = hint.as_millis() as u64,
                max_delay_ms = policy.max_delay.as_millis() as u64,
                "Retry-After exceeds max_delay; surfacing the response instead of retrying",
            );
            return None;
        }
        tracing::warn!(
            target: "cirrus_metadata::retry",
            attempt = attempt + 1,
            delay_ms = hint.as_millis() as u64,
            source = "retry-after-header",
            "scheduling request retry",
        );
        return Some(hint);
    }
    let factor: u128 = 1u128.checked_shl(attempt).unwrap_or(u128::MAX);
    let computed_ms = policy.base_delay.as_millis().saturating_mul(factor);
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
        target: "cirrus_metadata::retry",
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
    }

    #[test]
    fn none_policy_disables_retry() {
        let p = RetryPolicy::none();
        assert!(!should_retry_status(&p, true, 503, 0));
    }

    #[test]
    fn retries_429_for_any_operation() {
        let p = RetryPolicy::default();
        // Rate limited = refused before processing; safe to replay
        // even for mutating calls.
        assert!(should_retry_status(&p, false, 429, 0));
        assert!(should_retry_status(&p, true, 429, 0));
    }

    #[test]
    fn retries_5xx_only_for_idempotent_operations() {
        let p = RetryPolicy::default();
        for status in [500, 502, 503, 504] {
            assert!(should_retry_status(&p, true, status, 0));
            // A mutating call's outcome is ambiguous — the request
            // may have landed. Don't replay, 503 included.
            assert!(!should_retry_status(&p, false, status, 0));
        }
    }

    #[test]
    fn retry_5xx_disabled_keeps_idempotent_503() {
        let p = RetryPolicy {
            retry_idempotent_5xx: false,
            ..RetryPolicy::default()
        };
        assert!(should_retry_status(&p, true, 503, 0));
        assert!(!should_retry_status(&p, true, 500, 0));
        assert!(!should_retry_status(&p, true, 502, 0));
    }

    #[test]
    fn stops_at_max_retries() {
        let p = RetryPolicy::default();
        assert!(should_retry_status(&p, false, 429, 2));
        assert!(!should_retry_status(&p, false, 429, 3));
    }

    fn fault(code: &str) -> SoapFault {
        SoapFault {
            faultcode: format!("sf:{code}"),
            faultstring: format!("{code}: message"),
        }
    }

    #[test]
    fn transient_faults_are_limited_to_unavailable_server_codes() {
        assert!(is_transient_fault(&fault("SERVER_UNAVAILABLE")));
        assert!(is_transient_fault(&fault("API_CURRENTLY_DISABLED")));
    }

    #[test]
    fn faults_outside_the_transient_list_are_not_replayed() {
        // The first three return the identical fault on every attempt.
        // REQUEST_LIMIT_EXCEEDED can clear, but not inside this
        // policy's backoff, so it surfaces on the first attempt too.
        for code in [
            "INVALID_TYPE",
            "INVALID_SESSION_ID",
            "REQUEST_LIMIT_EXCEEDED",
            "INVALID_CROSS_REFERENCE_KEY",
        ] {
            assert!(
                !is_transient_fault(&fault(code)),
                "{code} treated as transient"
            );
        }
    }

    #[test]
    fn parse_retry_after_handles_seconds() {
        let mut h = reqwest::header::HeaderMap::new();
        h.insert(
            reqwest::header::RETRY_AFTER,
            reqwest::header::HeaderValue::from_static("7"),
        );
        assert_eq!(parse_retry_after(&h), Some(Duration::from_secs(7)));
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
        assert_eq!(
            compute_delay(&p, 0, Some(Duration::from_secs(3))),
            Some(Duration::from_secs(3))
        );
        assert_eq!(
            compute_delay(&p, 0, Some(Duration::from_secs(10))),
            Some(Duration::from_secs(10))
        );
        // Beyond the cap the retry does not happen: sleeping for a
        // truncated interval would retry inside the server's window.
        assert_eq!(compute_delay(&p, 0, Some(Duration::from_secs(99))), None);
    }

    #[test]
    fn compute_delay_caps_exponential_at_max_delay() {
        let p = RetryPolicy {
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(1),
            jitter: false,
            ..RetryPolicy::default()
        };
        assert_eq!(compute_delay(&p, 0, None), Some(Duration::from_millis(100)));
        assert_eq!(compute_delay(&p, 4, None), Some(Duration::from_secs(1)));
        assert_eq!(compute_delay(&p, 100, None), Some(Duration::from_secs(1)));
    }

    #[tokio::test]
    async fn does_not_retry_request_builder_errors() {
        // An unparseable URL is latched by the builder and returned
        // from send(); replaying it can only fail the same way.
        let p = RetryPolicy::default();
        let err: MetadataError = reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .post("not a url/services/Soap/m/66.0")
            .send()
            .await
            .unwrap_err()
            .into();
        match &err {
            MetadataError::Http(http) => assert!(http.is_builder(), "expected a builder error"),
            other => panic!("expected a transport error, got {other:?}"),
        }
        assert!(!should_retry_network(&p, true, &err, 0));
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
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    /// Strategy producing a deterministic (non-jittered) policy.
    /// Jitter randomizes within `[0, computed]`, which makes the
    /// monotonicity property unprovable for any single sample. The
    /// jitter path itself gets its own property below.
    fn deterministic_policy() -> impl Strategy<Value = RetryPolicy> {
        (1u64..=500u64, 1u64..=60_000u64).prop_map(|(base_ms, max_ms)| {
            // Force max_delay >= base_delay so the cap math has
            // somewhere to land.
            let max_ms = max_ms.max(base_ms);
            RetryPolicy {
                base_delay: Duration::from_millis(base_ms),
                max_delay: Duration::from_millis(max_ms),
                jitter: false,
                ..RetryPolicy::default()
            }
        })
    }

    /// Same shape as `deterministic_policy` but with jitter enabled.
    /// Sampled separately because the jitter path has different
    /// invariants (upper bound, not monotonicity).
    fn jittered_policy() -> impl Strategy<Value = RetryPolicy> {
        (1u64..=500u64, 1u64..=60_000u64).prop_map(|(base_ms, max_ms)| {
            let max_ms = max_ms.max(base_ms);
            RetryPolicy {
                base_delay: Duration::from_millis(base_ms),
                max_delay: Duration::from_millis(max_ms),
                jitter: true,
                ..RetryPolicy::default()
            }
        })
    }

    proptest! {
        /// Cap invariant: regardless of attempt count or `retry_after`
        /// hint, a delay that is returned never exceeds `max_delay`, and
        /// the only case that returns no delay is a hint beyond it. The
        /// `1u128.checked_shl(attempt)` saturating path means
        /// `attempt = u32::MAX` should still bound the result.
        ///
        /// Covers both jittered and non-jittered policies — jitter
        /// picks within `[0, computed]`, so the cap holds.
        #[test]
        fn compute_delay_respects_max_delay_cap(
            policy in jittered_policy(),
            attempt in 0u32..=u32::MAX,
            hint_ms in proptest::option::of(0u64..=300_000u64),
        ) {
            let hint = hint_ms.map(Duration::from_millis);
            match compute_delay(&policy, attempt, hint) {
                Some(delay) => prop_assert!(
                    delay <= policy.max_delay,
                    "delay {:?} exceeded max_delay {:?} (attempt={attempt}, hint={hint:?})",
                    delay,
                    policy.max_delay,
                ),
                None => prop_assert!(
                    hint.is_some_and(|h| h > policy.max_delay),
                    "no delay without an over-cap hint (attempt={attempt}, hint={hint:?})",
                ),
            }
        }

        /// Without jitter and without a `retry_after` hint, the
        /// exponential schedule is monotonically non-decreasing.
        /// Concretely: `delay(a) <= delay(b)` whenever `a <= b`.
        /// Catches base/exp/shift off-by-ones — including the
        /// `1u128.checked_shl` saturating path at `attempt >= 128`.
        #[test]
        fn compute_delay_is_monotonic_without_jitter_or_hint(
            policy in deterministic_policy(),
            a in 0u32..=200,
            b in 0u32..=200,
        ) {
            let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
            let dl = compute_delay(&policy, lo, None).unwrap();
            let dh = compute_delay(&policy, hi, None).unwrap();
            prop_assert!(
                dl <= dh,
                "non-monotonic: delay({lo})={dl:?} > delay({hi})={dh:?} for policy {policy:?}",
            );
        }

        /// A `retry_after` hint always wins over the computed
        /// exponential value: within `max_delay` it is returned as is,
        /// beyond it the retry is refused. This is the
        /// explicit-server-control path documented in
        /// `should_retry_status` / `parse_retry_after`.
        #[test]
        fn compute_delay_with_hint_returns_the_hint_or_refuses(
            policy in deterministic_policy(),
            attempt in 0u32..=200,
            hint_ms in 0u64..=120_000u64,
        ) {
            let hint = Duration::from_millis(hint_ms);
            let delay = compute_delay(&policy, attempt, Some(hint));
            prop_assert_eq!(delay, (hint <= policy.max_delay).then_some(hint));
        }

        /// `u32::MAX` attempts shouldn't panic. The `1u128.checked_shl`
        /// path triggers above `attempt >= 128`; `saturating_mul` and
        /// the final `min(u64::MAX as u128)` cast must handle the
        /// saturated factor without overflow.
        ///
        /// Run only with the non-jittered policy because the jittered
        /// path is also exercised by the cap-invariant property.
        #[test]
        fn compute_delay_does_not_panic_at_overflow_attempts(
            policy in deterministic_policy(),
            attempt in (u32::MAX - 100)..=u32::MAX,
        ) {
            let delay = compute_delay(&policy, attempt, None).unwrap();
            prop_assert!(delay <= policy.max_delay);
        }
    }
}
