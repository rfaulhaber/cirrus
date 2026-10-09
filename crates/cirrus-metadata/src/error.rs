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

use crate::result::{DeployResult, RetrieveResult};
use cirrus_auth::AuthError;
use std::time::Duration;
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
///
/// Variants that wrap another error ([`HttpClient`](Self::HttpClient),
/// [`Http`](Self::Http), [`ZipDecode`](Self::ZipDecode)) expose it
/// through [`source()`](std::error::Error::source) and do not repeat its text in
/// their own `Display`, so a reporter that walks the chain prints each
/// message once. Print the chain (anyhow's `{:#}`, for example) to see
/// the underlying cause; `{}` alone names only the category.
///
/// [`DeployFailed`](Self::DeployFailed) and
/// [`RetrieveFailed`](Self::RetrieveFailed) carry a job's result rather
/// than another error, and their `Display` summarizes it.
///
/// [`Soap`](Self::Soap) and [`Http4xx5xx`](Self::Http4xx5xx) are
/// `#[non_exhaustive]` themselves: destructure them with `..` so a
/// later field is an additive change.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum MetadataError {
    /// A required builder field was not set.
    #[error("missing required builder field: {0}")]
    MissingField(&'static str),

    /// Failed to construct the underlying HTTP client.
    #[error("failed to construct HTTP client")]
    HttpClient(#[source] reqwest::Error),

    /// Network or transport-level HTTP failure.
    #[error("HTTP request failed")]
    Http(#[from] reqwest::Error),

    /// The server returned a SOAP fault (`<soapenv:Fault>`).
    #[error("Metadata API SOAP fault (status {status}) [{}]: {}", .fault.code(), .fault.faultstring)]
    #[non_exhaustive]
    Soap {
        /// HTTP status code accompanying the fault. SOAP 1.1 faults
        /// usually arrive with HTTP 500, but Salesforce occasionally
        /// returns 200 with a fault body, so callers should inspect
        /// [`fault`](Self::Soap::fault) rather than relying on status
        /// alone.
        status: u16,
        /// The parsed SOAP fault.
        fault: SoapFault,
        /// The response's `Retry-After` hint, when it carried one in a
        /// form the client could read (delta-seconds or an HTTP-date,
        /// per RFC 7231 §7.1.3). A caller that owns its own retries —
        /// under [`RetryPolicy::none`](crate::RetryPolicy::none), once
        /// the retry budget is spent, or on an operation the policy
        /// never replays — can wait as long as the server asked.
        /// `None` when the header was absent or unreadable.
        retry_after: Option<Duration>,
    },

    /// The server returned a non-2xx status with a body that wasn't a
    /// recognizable SOAP envelope. The raw body is preserved for
    /// inspection.
    #[error("HTTP {status} from Metadata API (non-SOAP body): {raw}")]
    #[non_exhaustive]
    Http4xx5xx {
        /// HTTP status code returned.
        status: u16,
        /// Raw response body, capped at 2 KiB (longer bodies are
        /// truncated with a marker — non-SOAP shapes come from
        /// proxies/gateways, and retaining them unboundedly would let
        /// echoed request data flow into logs). The session id of the
        /// attempt, and the content of any echoed `<sessionId>`
        /// element, are replaced with `[redacted]`.
        raw: String,
        /// The response's `Retry-After` hint, as on
        /// [`Soap`](Self::Soap). A gateway's 429 or 503 is where it
        /// most often appears.
        retry_after: Option<Duration>,
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

    /// The response body was longer than the client buffers, so it was
    /// not read.
    ///
    /// The limit counts decoded bytes. A successful (2xx) response is
    /// held to
    /// [`MetadataClientBuilder::max_response_size`](crate::MetadataClientBuilder::max_response_size);
    /// every other response is held to a fixed 256 KiB, far above a SOAP
    /// fault. A retryable status whose body is oversized is retried like
    /// any other; this error reports the final attempt.
    #[error("HTTP {status} response body exceeded the {limit}-byte limit")]
    ResponseTooLarge {
        /// HTTP status of the oversized response.
        status: u16,
        /// The limit that was exceeded, in decoded bytes.
        limit: usize,
    },

    /// Response could not be interpreted as the requested type or shape.
    /// A 2xx body that is not a SOAP envelope carries a short excerpt
    /// here, with the session id redacted as for [`Self::Http4xx5xx`].
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

    /// A deployment finished without succeeding.
    ///
    /// Produced by [`DeployResult::into_result`]; the whole result,
    /// `details` included, rides along so the component and test
    /// failures stay reachable after `?`. The `Display` names the
    /// status, the error counts and the first few failures. Boxed
    /// because the result is far larger than any other variant and
    /// every call returns this enum.
    #[error("{}", .0.failure_summary())]
    DeployFailed(Box<DeployResult>),

    /// A retrieve finished without succeeding.
    ///
    /// Produced by [`RetrieveResult::into_result`]; the whole result
    /// rides along so `error_status_code`, `error_message` and
    /// `messages` stay reachable after `?`. The `Display` names the
    /// status, the error fields and the first few per-file problems.
    #[error("{}", .0.failure_summary())]
    RetrieveFailed(Box<RetrieveResult>),

    /// The `zipFile` of a retrieve result was not valid base64.
    ///
    /// Produced by [`RetrieveResult::zip_bytes`]. The decoder's error is
    /// the [`source()`](std::error::Error::source); it is the type
    /// re-exported as [`Base64DecodeError`](crate::Base64DecodeError).
    #[error("retrieved zip is not valid base64")]
    ZipDecode(#[from] base64::DecodeError),
}

/// Ceiling on how much of a non-SOAP error body is preserved in
/// [`MetadataError::Http4xx5xx`]. Such bodies come from proxies and
/// gateways, which can echo request data — capping what we retain
/// bounds the size of what can end up in the caller's logs via
/// `Display`/`Debug`; the session id itself is removed separately by
/// [`MetadataError::redact_secrets`], since it sits well inside any
/// useful cap.
const RAW_ERROR_BODY_CAP: usize = 2048;

/// Ceiling on the excerpt carried by the [`MetadataError::InvalidResponse`]
/// raised when a 2xx body is not a SOAP envelope. Tighter than
/// [`RAW_ERROR_BODY_CAP`]: the excerpt only has to show what answered.
const NON_SOAP_BODY_EXCERPT_CAP: usize = 256;

/// Ceiling on the deserializer message carried by a
/// [`MetadataError::Xml`]. serde's `invalid_type` and `unknown_variant`
/// errors quote the offending value, and a metadata field can hold
/// arbitrarily long text, so the message is as unbounded as the data.
/// The path of the failing element, which locates the mismatch, is
/// short and is kept outside the cap.
pub(crate) const PARSE_MESSAGE_CAP: usize = 512;

/// Decodes an error body for inclusion in an error, bounded by
/// [`RAW_ERROR_BODY_CAP`] bytes and marked when anything was dropped.
pub(crate) fn cap_raw_body(bytes: &[u8]) -> String {
    cap_body(bytes, RAW_ERROR_BODY_CAP)
}

/// Decodes the start of a 2xx body that was not a SOAP envelope, bounded
/// by [`NON_SOAP_BODY_EXCERPT_CAP`] bytes.
pub(crate) fn cap_body_excerpt(bytes: &[u8]) -> String {
    cap_body(bytes, NON_SOAP_BODY_EXCERPT_CAP)
}

/// Truncates `text` to at most `cap` bytes at a char boundary, marked
/// when anything was dropped.
pub(crate) fn cap_text(text: &str, cap: usize) -> String {
    if text.len() <= cap {
        return text.to_owned();
    }
    let mut end = cap;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}… <truncated>", &text[..end])
}

/// Only the capped byte prefix is decoded, so a multi-megabyte body never
/// gets a full owned copy. Lossy decoding expands each invalid byte to a
/// three-byte U+FFFD, which can push even that prefix past the cap, so the
/// decoded string is trimmed again at a char boundary.
fn cap_body(bytes: &[u8], cap: usize) -> String {
    let mut truncated = bytes.len() > cap;
    let head = &bytes[..bytes.len().min(cap)];
    let mut body = String::from_utf8_lossy(head).into_owned();
    if body.len() > cap {
        let mut end = cap;
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

/// Stand-in for credential material removed from a stored error body.
const REDACTED: &str = "[redacted]";

impl MetadataError {
    /// Removes the session id from every variant that retains body text
    /// from an intermediary.
    ///
    /// A body is only retained when it was not a SOAP envelope, and such
    /// bodies are written by proxies, gateways and WAFs, which routinely
    /// echo the request that provoked them — envelope and `<sessionId>`
    /// included. That text is interpolated into the error's `Display`,
    /// so an ordinary `tracing::error!("{e}")` would otherwise write a
    /// live session id into the caller's log sink.
    ///
    /// Every new variant that stores body text has to be added here.
    pub(crate) fn redact_secrets(self, token: &str) -> Self {
        match self {
            Self::Http4xx5xx {
                status,
                raw,
                retry_after,
            } => Self::Http4xx5xx {
                status,
                raw: redact_body(&raw, token),
                retry_after,
            },
            Self::InvalidResponse(message) => Self::InvalidResponse(redact_body(&message, token)),
            other => other,
        }
    }
}

/// Replaces the live token, plus the content of any echoed `<sessionId>`
/// element, with [`REDACTED`]. The second pass matters because an echoed
/// envelope may carry a token other than this attempt's — one rotated
/// mid-call — that the exact match misses.
fn redact_body(body: &str, token: &str) -> String {
    let stripped = if token.is_empty() {
        body.to_string()
    } else {
        body.replace(token, REDACTED)
    };
    redact_session_id_elements(&stripped)
}

fn redact_session_id_elements(body: &str) -> String {
    const LOCAL_NAME: &str = "sessionId>";
    let mut out = String::with_capacity(body.len());
    let mut cursor = 0;
    while let Some(offset) = body[cursor..].find(LOCAL_NAME) {
        let name_start = cursor + offset;
        let name_end = name_start + LOCAL_NAME.len();
        // An opening tag is `<`, an optional `prefix:`, then the name; a
        // closing tag has `/` right after the `<` and is left alone.
        let before = &body[cursor..name_start];
        let is_opening_tag = before.rfind('<').is_some_and(|lt| {
            let between = &before[lt + 1..];
            !between.starts_with('/')
                && between
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b':' | b'_' | b'-' | b'.'))
        });
        out.push_str(&body[cursor..name_end]);
        if !is_opening_tag {
            cursor = name_end;
            continue;
        }
        out.push_str(REDACTED);
        // Skip the element's text content, up to its closing tag.
        cursor = body[name_end..]
            .find('<')
            .map_or(body.len(), |i| name_end + i);
    }
    out.push_str(&body[cursor..]);
    out
}

// These impls are part of the public API: a custom `SoapOperation` can
// `?` a quick-xml error out of `render_body`, naming the types through
// the crate's `quick_xml` re-export. Nothing else converts into `Xml`,
// so a caller's own I/O or parsing failure is never misfiled as a
// server XML problem.
impl From<quick_xml::Error> for MetadataError {
    fn from(e: quick_xml::Error) -> Self {
        MetadataError::Xml(cap_text(&e.to_string(), PARSE_MESSAGE_CAP))
    }
}

impl From<quick_xml::DeError> for MetadataError {
    fn from(e: quick_xml::DeError) -> Self {
        MetadataError::Xml(cap_text(&e.to_string(), PARSE_MESSAGE_CAP))
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
    fn redact_secrets_strips_the_token_and_any_session_id_element() {
        let echoed = "<html>blocked: <met:sessionId>00Dxx!live</met:sessionId> and \
                      <sessionId>00Dxx!rotated</sessionId> and <sessionIdHint>x</sessionIdHint></html>";
        let err = MetadataError::Http4xx5xx {
            status: 400,
            raw: echoed.into(),
            retry_after: None,
        }
        .redact_secrets("00Dxx!live");
        let MetadataError::Http4xx5xx { raw, .. } = &err else {
            panic!("variant changed: {err:?}");
        };
        assert!(!raw.contains("00Dxx!live"), "{raw}");
        assert!(!raw.contains("00Dxx!rotated"), "{raw}");
        assert_eq!(
            raw,
            "<html>blocked: <met:sessionId>[redacted]</met:sessionId> and \
             <sessionId>[redacted]</sessionId> and <sessionIdHint>x</sessionIdHint></html>"
        );
    }

    #[test]
    fn redact_secrets_covers_invalid_response_and_leaves_other_variants() {
        let err = MetadataError::InvalidResponse("body starts: <sessionId>tok</sessionId>".into())
            .redact_secrets("tok");
        assert_eq!(
            err.to_string(),
            "invalid response: body starts: <sessionId>[redacted]</sessionId>"
        );
        let untouched =
            MetadataError::InvalidArgument("tok is fine here".into()).redact_secrets("tok");
        assert_eq!(untouched.to_string(), "invalid argument: tok is fine here");
    }

    #[test]
    fn cap_text_keeps_short_text_and_marks_a_cut() {
        assert_eq!(cap_text("short", 16), "short");
        assert_eq!(cap_text("exactly16bytes!!", 16), "exactly16bytes!!");
        assert_eq!(
            cap_text("0123456789abcdefX", 16),
            "0123456789abcdef… <truncated>"
        );
    }

    #[test]
    fn cap_text_cuts_at_a_char_boundary() {
        // Each `é` is two bytes, so a cut at byte 5 would split one.
        let capped = cap_text("ééééé", 5);
        assert_eq!(capped, "éé… <truncated>");
    }

    #[test]
    fn quick_xml_messages_that_quote_input_are_capped() {
        let quoted = "v".repeat(PARSE_MESSAGE_CAP * 8);
        let err: MetadataError =
            <quick_xml::DeError as serde::de::Error>::custom(format!("unknown variant `{quoted}`"))
                .into();
        let MetadataError::Xml(msg) = &err else {
            panic!("variant changed: {err:?}");
        };
        assert!(msg.ends_with("… <truncated>"), "{msg}");
        assert!(msg.len() < PARSE_MESSAGE_CAP + 32, "{} bytes", msg.len());
    }

    #[test]
    fn cap_body_excerpt_is_tighter_than_the_raw_cap() {
        let body = "x".repeat(RAW_ERROR_BODY_CAP);
        let excerpt = cap_body_excerpt(body.as_bytes());
        assert!(excerpt.ends_with("… <truncated>"));
        assert!(
            excerpt.len() < NON_SOAP_BODY_EXCERPT_CAP + 32,
            "{}",
            excerpt.len()
        );
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
            retry_after: None,
        };
        let msg = err.to_string();
        assert!(msg.contains("500"));
        assert!(msg.contains("INVALID_TYPE"));
        assert!(msg.contains("no such metadata type"));
    }

    /// A `reqwest::Error` produced without any network: an invalid default
    /// header value is reported when the client is built.
    fn client_build_error() -> reqwest::Error {
        reqwest::Client::builder()
            .user_agent("line\nbreak")
            .build()
            .unwrap_err()
    }

    #[test]
    fn display_does_not_repeat_the_text_of_the_source() {
        use std::error::Error as _;
        let errors = [
            MetadataError::HttpClient(client_build_error()),
            MetadataError::Http(client_build_error()),
            MetadataError::ZipDecode(base64::DecodeError::InvalidPadding),
        ];
        for err in errors {
            let source = err.source().expect("variant carries a source").to_string();
            let display = err.to_string();
            assert!(
                !display.contains(&source),
                "{display:?} repeats its source {source:?}"
            );
        }
    }
}
