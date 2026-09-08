//! Error types for the `cirrus-metadata` SDK.
//!
//! The Metadata API speaks SOAP 1.1, so its error shape is different from the
//! REST surface modeled by `cirrus`. Failures arrive as `<soapenv:Fault>`
//! elements with a `faultcode` (e.g. `sf:INVALID_SESSION_ID`,
//! `sf:INVALID_TYPE`) and a `faultstring` description. [`SoapFault`] models
//! that shape and [`MetadataError::Soap`] carries it alongside the HTTP
//! status.
//!
//! Auth-flow errors come from [`cirrus_auth`] as [`AuthError`] and are
//! wrapped by [`MetadataError::Auth`]; the `From` impl lets handlers
//! propagate them via `?`.

use cirrus_auth::AuthError;
use thiserror::Error;

/// Specialized `Result` type for `cirrus-metadata` operations.
pub type MetadataResult<T> = Result<T, MetadataError>;

/// A parsed SOAP 1.1 `<Fault>` element.
///
/// Salesforce returns faults with a colon-qualified `faultcode` whose local
/// part is the canonical error code (e.g. `sf:INVALID_SESSION_ID` →
/// `INVALID_SESSION_ID`). [`Self::code`] returns that local part with the
/// prefix stripped, which is what callers usually want to match on.
#[derive(Debug, Clone)]
pub struct SoapFault {
    /// Full `faultcode` value as it appeared on the wire, e.g.
    /// `sf:INVALID_SESSION_ID`.
    pub faultcode: String,
    /// Human-readable `faultstring`.
    pub faultstring: String,
}

impl SoapFault {
    /// Returns the local part of [`faultcode`](Self::faultcode) — the
    /// substring after the last `:`. For `sf:INVALID_SESSION_ID` this is
    /// `INVALID_SESSION_ID`. If the faultcode has no `:` the full string is
    /// returned.
    pub fn code(&self) -> &str {
        self.faultcode
            .rsplit_once(':')
            .map(|(_, local)| local)
            .unwrap_or(&self.faultcode)
    }

    /// True if this fault represents an expired or invalid session,
    /// triggering the SDK's auth-retry path.
    pub(crate) fn is_invalid_session(&self) -> bool {
        self.code() == "INVALID_SESSION_ID"
    }
}

/// Errors produced by the `cirrus-metadata` client.
///
/// Marked `#[non_exhaustive]`: match on the variants you handle and keep
/// a `_` arm, so a new variant in a later release is an additive change.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum MetadataError {
    /// A required builder field was not set.
    #[error("missing required builder field: {0}")]
    MissingField(&'static str),

    /// Failed to construct the underlying HTTP client.
    #[error("failed to construct HTTP client: {0}")]
    HttpClient(#[source] reqwest::Error),

    /// Network or transport-level HTTP failure.
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    /// The server returned a SOAP fault (`<soapenv:Fault>`).
    #[error("Metadata API SOAP fault (status {status}) [{}]: {}", .fault.code(), .fault.faultstring)]
    Soap {
        /// HTTP status code accompanying the fault. SOAP 1.1 faults
        /// usually arrive with HTTP 500, but Salesforce occasionally
        /// returns 200 with a fault body, so callers should inspect
        /// [`fault`](Self::Soap::fault) rather than relying on status
        /// alone.
        status: u16,
        /// The parsed SOAP fault.
        fault: SoapFault,
    },

    /// The server returned a non-2xx status with a body that wasn't a
    /// recognizable SOAP envelope. The raw body is preserved for
    /// inspection.
    #[error("HTTP {status} from Metadata API (non-SOAP body): {raw}")]
    Http4xx5xx {
        /// HTTP status code returned.
        status: u16,
        /// Raw response body, capped at 2 KiB (longer bodies are
        /// truncated with a marker — non-SOAP shapes come from
        /// proxies/gateways, and retaining them unboundedly would let
        /// echoed request data flow into logs).
        raw: String,
    },

    /// An auth flow (token acquisition, refresh, OAuth exchange) failed.
    /// Wraps the underlying [`AuthError`] from `cirrus-auth`.
    #[error(transparent)]
    Auth(#[from] AuthError),

    /// XML serialization or deserialization failure.
    #[error("XML error: {0}")]
    Xml(String),

    /// Header value rejected by reqwest (invalid bytes, etc.).
    #[error("invalid header value: {0}")]
    InvalidHeader(String),

    /// Response could not be interpreted as the requested type or shape.
    #[error("invalid response: {0}")]
    InvalidResponse(String),

    /// Client-side argument validation failed before reaching the wire
    /// (per-call component caps exceeded, required field missing, etc.).
    /// Distinct from [`Self::InvalidResponse`], which signals a
    /// server-side shape problem.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// A polling helper hit its configured wall-clock budget before the
    /// async operation completed. The job is not canceled — re-poll with
    /// `check_deploy_status` / `check_retrieve_status` to continue
    /// observing it.
    #[error("polling timed out: {0}")]
    PollTimeout(String),
}

/// Ceiling on how much of a non-SOAP error body is preserved in
/// [`MetadataError::Http4xx5xx`]. Such bodies come from proxies and
/// gateways, which can echo request data — capping what we retain
/// bounds what can end up in the caller's logs via `Display`/`Debug`.
const RAW_ERROR_BODY_CAP: usize = 2048;

/// Decodes an error body for inclusion in an error, bounded by
/// [`RAW_ERROR_BODY_CAP`] bytes and marked when anything was dropped.
///
/// Only the capped byte prefix is decoded, so a multi-megabyte body never
/// gets a full owned copy. Lossy decoding expands each invalid byte to a
/// three-byte U+FFFD, which can push even that prefix past the cap, so the
/// decoded string is trimmed again at a char boundary.
pub(crate) fn cap_raw_body(bytes: &[u8]) -> String {
    let mut truncated = bytes.len() > RAW_ERROR_BODY_CAP;
    let head = &bytes[..bytes.len().min(RAW_ERROR_BODY_CAP)];
    let mut body = String::from_utf8_lossy(head).into_owned();
    if body.len() > RAW_ERROR_BODY_CAP {
        let mut end = RAW_ERROR_BODY_CAP;
        while !body.is_char_boundary(end) {
            end -= 1;
        }
        body.truncate(end);
        truncated = true;
    }
    if truncated {
        body.push_str("… <truncated>");
    }
    body
}

impl From<quick_xml::Error> for MetadataError {
    fn from(e: quick_xml::Error) -> Self {
        MetadataError::Xml(e.to_string())
    }
}

impl From<quick_xml::DeError> for MetadataError {
    fn from(e: quick_xml::DeError) -> Self {
        MetadataError::Xml(e.to_string())
    }
}

// `quick_xml::Writer::write_event` returns `std::io::Result<()>` even
// when the underlying buffer is a `Vec<u8>`. Folding that into the XML
// variant keeps the public error surface small.
impl From<std::io::Error> for MetadataError {
    fn from(e: std::io::Error) -> Self {
        MetadataError::Xml(e.to_string())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn cap_raw_body_truncates_oversized_bodies() {
        let body = "x".repeat(RAW_ERROR_BODY_CAP * 3);
        let capped = cap_raw_body(body.as_bytes());
        assert!(capped.ends_with("… <truncated>"));
        assert!(capped.len() < RAW_ERROR_BODY_CAP + 32);
        // Small bodies pass through untouched.
        assert_eq!(cap_raw_body(b"tiny"), "tiny");
    }

    #[test]
    fn cap_raw_body_bounds_a_large_non_utf8_body() {
        // Each invalid byte decodes to a three-byte U+FFFD, so capping
        // the decoded string alone would still leave ~3x the cap in the
        // error value — and decoding first would materialize a copy of
        // the whole body before any of that.
        let body = vec![0xffu8; RAW_ERROR_BODY_CAP * 4];
        let capped = cap_raw_body(&body);
        assert!(capped.ends_with("… <truncated>"));
        assert!(
            capped.len() < RAW_ERROR_BODY_CAP + 32,
            "capped body is {} bytes",
            capped.len()
        );
    }

    #[test]
    fn cap_raw_body_keeps_a_body_exactly_at_the_cap_whole() {
        let body = "x".repeat(RAW_ERROR_BODY_CAP);
        assert_eq!(cap_raw_body(body.as_bytes()), body);
    }

    #[test]
    fn fault_code_strips_namespace_prefix() {
        let f = SoapFault {
            faultcode: "sf:INVALID_SESSION_ID".into(),
            faultstring: "session expired".into(),
        };
        assert_eq!(f.code(), "INVALID_SESSION_ID");
        assert!(f.is_invalid_session());
    }

    #[test]
    fn fault_code_passes_through_when_unqualified() {
        let f = SoapFault {
            faultcode: "INVALID_TYPE".into(),
            faultstring: "no such type".into(),
        };
        assert_eq!(f.code(), "INVALID_TYPE");
        assert!(!f.is_invalid_session());
    }

    #[test]
    fn soap_error_display_includes_code_and_message() {
        let err = MetadataError::Soap {
            status: 500,
            fault: SoapFault {
                faultcode: "sf:INVALID_TYPE".into(),
                faultstring: "no such metadata type".into(),
            },
        };
        let msg = err.to_string();
        assert!(msg.contains("500"));
        assert!(msg.contains("INVALID_TYPE"));
        assert!(msg.contains("no such metadata type"));
    }
}
