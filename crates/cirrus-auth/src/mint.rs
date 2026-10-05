//! Token-cache bookkeeping shared by the caching flows ([`crate::jwt`],
//! [`crate::client_credentials`], [`crate::refresh`]).
//!
//! Three behaviours live here so the flows cannot drift apart:
//!
//! - A cached token is reused while it is fresh, meaning more than
//!   [`EXPIRY_MARGIN`](crate::token_endpoint::EXPIRY_MARGIN) away from
//!   its estimated expiry.
//! - A mint is single-flight. Callers that queue on the flow's lock while
//!   a mint is in flight share that mint's outcome, success or failure,
//!   instead of each repeating the grant in turn. A caller notes when it
//!   started before taking any lock — the read lock itself queues behind
//!   an in-flight mint — and hands that instant to
//!   [`shared_outcome`](MintState::shared_outcome) once it holds the
//!   write lock; a mint that completed after the caller started was
//!   concurrent with it.
//! - A transient failure while the cached token is inside its margin but
//!   not yet expired falls back to that token, which Salesforce would
//!   still accept. An OAuth error is never masked that way.

use crate::error::{AuthError, AuthResult};
use crate::token_endpoint::token_is_fresh;
use std::time::Instant;

/// An access token together with the instant after which it is not
/// trusted any more.
#[derive(Clone)]
pub(crate) struct CachedToken {
    pub(crate) access_token: String,
    pub(crate) expires_at: Instant,
}

impl std::fmt::Debug for CachedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedToken")
            .field("access_token", &"[redacted]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// The latest failed mint, kept so callers queued behind it can share it.
struct Failure {
    /// The error in its waiter form (see [`AuthError::clone_for_waiter`]).
    error: AuthError,
    /// Whether the failure was one the cached token may stand in for.
    transient: bool,
}

/// Cache state for one flow, guarded by the flow's own lock.
#[derive(Default)]
pub(crate) struct MintState {
    cached: Option<CachedToken>,
    /// When the latest mint completed, success or failure. Invalidation
    /// clears the cache without a mint and leaves this alone.
    last_completed: Option<Instant>,
    /// Cleared by the next successful mint.
    failure: Option<Failure>,
}

impl MintState {
    /// The cached token while it is fresh.
    pub(crate) fn fresh_token(&self) -> Option<String> {
        self.cached
            .as_ref()
            .filter(|c| token_is_fresh(c.expires_at))
            .map(|c| c.access_token.clone())
    }

    /// For a caller that began at `started`, before taking any lock: the
    /// outcome of a mint that completed since then, which is this caller's
    /// outcome too. `None` means no mint completed in that time, or the one
    /// that did left nothing usable behind, so the caller should mint.
    pub(crate) fn shared_outcome(&self, started: Instant) -> Option<AuthResult<String>> {
        if self
            .last_completed
            .is_none_or(|completed| completed < started)
        {
            return None;
        }
        if let Some(token) = self.fresh_token() {
            return Some(Ok(token));
        }
        let failure = self.failure.as_ref()?;
        Some(match self.still_valid_token() {
            Some(token) if failure.transient => Ok(token),
            _ => Err(failure.error.clone_for_waiter()),
        })
    }

    /// Records a finished mint and produces the minting caller's result.
    ///
    /// The minting caller gets the original error with its full source
    /// chain; waiters get the waiter form. A transient failure while the
    /// cached token is still valid returns that token instead and logs a
    /// warning, so a token-endpoint blip inside the refresh margin does
    /// not fail requests Salesforce would have accepted.
    pub(crate) fn record(
        &mut self,
        flow: &'static str,
        result: AuthResult<CachedToken>,
    ) -> AuthResult<String> {
        self.last_completed = Some(Instant::now());
        match result {
            Ok(token) => {
                let access_token = token.access_token.clone();
                self.cached = Some(token);
                self.failure = None;
                Ok(access_token)
            }
            Err(error) => {
                let transient = error.is_transient();
                self.failure = Some(Failure {
                    error: error.clone_for_waiter(),
                    transient,
                });
                match self.still_valid_token() {
                    Some(token) if transient => {
                        tracing::warn!(
                            target: "cirrus_auth::mint",
                            flow,
                            error = %error,
                            "token mint failed transiently; using the cached token, which is \
                             inside its refresh margin but not yet expired",
                        );
                        Ok(token)
                    }
                    _ => Err(error),
                }
            }
        }
    }

    /// Compare-and-swap invalidation: clears the cached token only when
    /// it is the one the failing request used, so a token a concurrent
    /// caller just minted survives.
    pub(crate) fn invalidate_if_matches(&mut self, flow: &'static str, stale_token: &str) {
        if self
            .cached
            .as_ref()
            .is_some_and(|c| c.access_token == stale_token)
        {
            tracing::debug!(
                target: "cirrus_auth::mint",
                flow,
                "invalidating cached token (CAS matched)",
            );
            self.cached = None;
        } else {
            tracing::trace!(
                target: "cirrus_auth::mint",
                flow,
                "invalidate called but cached token differs (concurrent refresh?); no-op",
            );
        }
    }

    /// The cached token while its estimated expiry is still ahead, margin
    /// or not.
    fn still_valid_token(&self) -> Option<String> {
        self.cached
            .as_ref()
            .filter(|c| c.expires_at > Instant::now())
            .map(|c| c.access_token.clone())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::token_endpoint::EXPIRY_MARGIN;
    use std::time::Duration;

    fn token(value: &str, lifetime: Duration) -> CachedToken {
        CachedToken {
            access_token: value.into(),
            expires_at: Instant::now() + lifetime,
        }
    }

    fn oauth(error: &str) -> AuthError {
        AuthError::OAuth {
            error: error.into(),
            error_description: None,
        }
    }

    /// An instant strictly after every stamp recorded so far, even on a
    /// coarse clock.
    fn later() -> Instant {
        std::thread::sleep(Duration::from_millis(2));
        Instant::now()
    }

    #[test]
    fn a_successful_mint_is_cached_and_clears_the_last_failure() {
        let mut state = MintState::default();
        state
            .record("test", Err(oauth("invalid_grant")))
            .unwrap_err();
        assert!(state.failure.is_some());
        let out = state
            .record("test", Ok(token("fresh", Duration::from_secs(600))))
            .unwrap();
        assert_eq!(out, "fresh");
        assert_eq!(state.fresh_token().as_deref(), Some("fresh"));
        assert!(state.failure.is_none());
    }

    #[test]
    fn waiters_share_a_failure_that_completed_while_they_waited() {
        let mut state = MintState::default();
        let started = Instant::now();
        // Nothing completed yet: the caller has to mint.
        assert!(state.shared_outcome(started).is_none());
        state
            .record("test", Err(oauth("invalid_grant")))
            .unwrap_err();
        let shared = state.shared_outcome(started).expect("a mint completed");
        assert!(
            matches!(shared, Err(AuthError::OAuth { ref error, .. }) if error == "invalid_grant"),
            "{shared:?}"
        );
        // A caller that began after the failure mints again rather than
        // inheriting a stale outcome.
        assert!(state.shared_outcome(later()).is_none());
    }

    #[test]
    fn waiters_share_a_success_that_completed_while_they_waited() {
        let mut state = MintState::default();
        let started = Instant::now();
        state
            .record("test", Ok(token("fresh", Duration::from_secs(600))))
            .unwrap();
        assert_eq!(
            state.shared_outcome(started).unwrap().unwrap(),
            "fresh".to_string()
        );
    }

    #[test]
    fn a_transient_failure_inside_the_margin_returns_the_cached_token_to_everyone() {
        let mut state = MintState::default();
        // Inside the margin (not fresh) but not expired.
        state
            .record("test", Ok(token("inside-margin", EXPIRY_MARGIN / 2)))
            .unwrap();
        assert!(state.fresh_token().is_none());
        let started = later();
        let minter = state
            .record("test", Err(AuthError::UnexpectedResponse { status: 503 }))
            .unwrap();
        assert_eq!(minter, "inside-margin");
        let waiter = state.shared_outcome(started).unwrap().unwrap();
        assert_eq!(waiter, "inside-margin");
    }

    #[test]
    fn an_oauth_failure_inside_the_margin_is_not_masked() {
        let mut state = MintState::default();
        state
            .record("test", Ok(token("inside-margin", EXPIRY_MARGIN / 2)))
            .unwrap();
        let started = later();
        let minter = state
            .record("test", Err(oauth("invalid_grant")))
            .unwrap_err();
        assert!(matches!(minter, AuthError::OAuth { .. }));
        let waiter = state.shared_outcome(started).unwrap().unwrap_err();
        assert!(matches!(waiter, AuthError::OAuth { .. }));
    }

    #[test]
    fn an_expired_cached_token_is_not_used_as_a_fallback() {
        let mut state = MintState::default();
        state
            .record("test", Ok(token("expired", Duration::ZERO)))
            .unwrap();
        let err = state
            .record("test", Err(AuthError::UnexpectedResponse { status: 503 }))
            .unwrap_err();
        assert!(matches!(err, AuthError::UnexpectedResponse { status: 503 }));
    }

    #[test]
    fn invalidate_clears_only_a_matching_token_and_is_not_a_completed_mint() {
        let mut state = MintState::default();
        state
            .record("test", Ok(token("current", Duration::from_secs(600))))
            .unwrap();
        let started = later();
        state.invalidate_if_matches("test", "someone-elses");
        assert_eq!(state.fresh_token().as_deref(), Some("current"));
        state.invalidate_if_matches("test", "current");
        assert!(state.fresh_token().is_none());
        // Invalidation leaves nothing for a concurrent caller to share.
        assert!(state.shared_outcome(started).is_none());
    }
}
