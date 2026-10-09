//! Helpers shared by the unit tests of several modules.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, Once};
use tracing::span::{Attributes, Id, Record};
use tracing::subscriber::Interest;
use tracing::{Event, Metadata, Subscriber};
use tracing_core::span::Current;

/// Records, as `target LEVEL field=value ...` lines, every event the
/// recording thread emits under a `cirrus_auth` target while a
/// [`Recording`] is alive, and tracks the spans that thread enters so
/// `tracing::Span::current()` answers inside a task spawned onto a
/// current-thread runtime.
///
/// Installed once per process as the global subscriber, never as a
/// scoped one: `tracing` caches each callsite's `Interest` process-wide,
/// and the cache is filled by whichever thread reaches the callsite
/// first. Under a scoped subscriber, a test running concurrently on
/// another thread registers the callsite against the no-op dispatcher
/// and caches `never`, after which this thread's events are dropped
/// before any subscriber sees them. The global subscriber answers
/// `Interest::sometimes()`, so every event consults `enabled`, which
/// admits only a thread that is recording.
pub(crate) struct Capture {
    next_span: AtomicU64,
    spans: Mutex<HashMap<u64, &'static Metadata<'static>>>,
}

thread_local! {
    static RECORDING: RefCell<Option<Vec<String>>> = const { RefCell::new(None) };
    static ENTERED: RefCell<Vec<Id>> = const { RefCell::new(Vec::new()) };
}

/// Collects the recording thread's events until it is dropped.
pub(crate) struct Recording;

impl Capture {
    pub(crate) fn record() -> Recording {
        static INSTALL: Once = Once::new();
        INSTALL.call_once(|| {
            tracing::subscriber::set_global_default(Capture {
                next_span: AtomicU64::new(1),
                spans: Mutex::new(HashMap::new()),
            })
            .expect("no other global subscriber is installed in the test binary");
        });
        RECORDING.with(|lines| *lines.borrow_mut() = Some(Vec::new()));
        Recording
    }
}

impl Recording {
    pub(crate) fn lines(self) -> Vec<String> {
        RECORDING.with(|lines| lines.borrow_mut().take().unwrap_or_default())
    }
}

impl Drop for Recording {
    fn drop(&mut self) {
        RECORDING.with(|lines| *lines.borrow_mut() = None);
    }
}

impl Subscriber for Capture {
    fn register_callsite(&self, _: &'static Metadata<'static>) -> Interest {
        Interest::sometimes()
    }

    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.target().starts_with("cirrus_auth")
            && RECORDING.with(|lines| lines.borrow().is_some())
    }

    fn new_span(&self, attributes: &Attributes<'_>) -> Id {
        let id = self.next_span.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut spans) = self.spans.lock() {
            spans.insert(id, attributes.metadata());
        }
        Id::from_u64(id)
    }

    fn record(&self, _: &Id, _: &Record<'_>) {}

    fn record_follows_from(&self, _: &Id, _: &Id) {}

    fn event(&self, event: &Event<'_>) {
        struct Line(String);
        impl tracing::field::Visit for Line {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0.push_str(&format!(" {}={value:?}", field.name()));
            }
        }
        let metadata = event.metadata();
        let mut line = Line(format!("{} {}", metadata.target(), metadata.level()));
        event.record(&mut line);
        RECORDING.with(|lines| {
            if let Some(lines) = lines.borrow_mut().as_mut() {
                lines.push(line.0);
            }
        });
    }

    fn enter(&self, id: &Id) {
        ENTERED.with(|stack| stack.borrow_mut().push(id.clone()));
    }

    fn exit(&self, id: &Id) {
        ENTERED.with(|stack| {
            let mut stack = stack.borrow_mut();
            if stack.last() == Some(id) {
                stack.pop();
            }
        });
    }

    fn current_span(&self) -> Current {
        let Some(id) = ENTERED.with(|stack| stack.borrow().last().cloned()) else {
            return Current::none();
        };
        let metadata = self
            .spans
            .lock()
            .ok()
            .and_then(|spans| spans.get(&id.into_u64()).copied());
        match metadata {
            Some(metadata) => Current::new(id, metadata),
            None => Current::none(),
        }
    }
}

/// Decodes one base64url segment of a compact JWS as JSON.
pub(crate) fn decode_jwt_segment(segment: &str) -> serde_json::Value {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segment)
        .expect("segment is base64url");
    serde_json::from_slice(&bytes).expect("segment is JSON")
}
