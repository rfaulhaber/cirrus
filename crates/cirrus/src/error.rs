//! Error types for the Cirrus SDK.
//!
//! Salesforce REST endpoints return errors as a JSON array of objects with a
//! consistent shape (`message`, `errorCode`, optional `fields`), regardless of
//! the success-response shape. [`SalesforceError`] models that shape, and
//! [`CirrusError::Api`] carries the parsed array along with the HTTP
//! status.
//!
//! Auth-flow errors (OAuth token endpoints, JWT signing, missing builder
//! fields on a flow) come from the [`cirrus_auth`] crate as
//! [`AuthError`](cirrus_auth::AuthError) and are wrapped by
//! [`CirrusError::Auth`]. The `From<AuthError>` impl lets handlers
//! propagate them via `?` without extra boilerplate.

use cirrus_auth::AuthError;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Specialized `Result` type for Cirrus operations.
pub type CirrusResult<T> = Result<T, CirrusError>;

/// A single Salesforce API error entry.
///
/// Salesforce REST endpoints return errors as a JSON array of these objects.
/// The shape is schema-independent and applies to every REST resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SalesforceError {
    /// Human-readable description of the error.
    pub message: String,
    /// Salesforce-defined error code (e.g. `INVALID_FIELD`, `NOT_FOUND`).
    #[serde(rename = "errorCode")]
    pub error_code: String,
    /// Field names involved in the error, when applicable (validation errors).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<String>,
}

/// Errors produced by the Cirrus client.
#[derive(Debug, Error)]
pub enum CirrusError {
    /// A required builder field was not set.
    #[error("missing required builder field: {0}")]
    MissingField(&'static str),

    /// Failed to construct the underlying HTTP client.
    #[error("failed to construct HTTP client: {0}")]
    HttpClient(#[source] reqwest::Error),

    /// Network or transport-level HTTP failure.
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    /// Salesforce returned a non-2xx response. `errors` holds the parsed
    /// Salesforce error array; if the body could not be parsed as the
    /// canonical shape, the raw body is in `raw`.
    #[error("Salesforce API error (status {status}): {}", display_errors(.errors, .raw))]
    Api {
        /// HTTP status code returned by Salesforce.
        status: u16,
        /// Parsed Salesforce error entries. Empty if the body was not parseable
        /// as the canonical error array.
        errors: Vec<SalesforceError>,
        /// Raw response body, capped at 2 KiB (longer bodies are
        /// truncated with a marker — non-Salesforce shapes come from
        /// proxies/gateways, and retaining them unboundedly would let
        /// echoed request data flow into logs). Populated when `errors`
        /// is empty so callers can see what came back.
        ///
        /// Bearer-token material is replaced with `[redacted]` before
        /// the body is stored, because those intermediary pages tend to
        /// echo the request that provoked them and this value reaches
        /// the error's `Display`.
        raw: Option<String>,
    },

    /// An auth flow (token acquisition, refresh, OAuth exchange) failed.
    /// Wraps the underlying [`AuthError`] from `cirrus-auth`.
    #[error(transparent)]
    Auth(#[from] AuthError),

    /// JSON serialization or deserialization failure.
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// URL parsing failure (instance URL, redirect URI, etc.).
    #[error("invalid URL: {0}")]
    Url(#[from] url::ParseError),

    /// Header value rejected by reqwest (invalid bytes, etc.).
    #[error("invalid header value: {0}")]
    InvalidHeader(String),

    /// A caller-supplied value was rejected before any request went out
    /// — a builder setting the SDK can't use, or a value that can't be
    /// expressed as a URL path segment.
    #[error("invalid {field}: {message}")]
    InvalidInput {
        /// What was rejected, e.g. `"api_version"` or `"path segment"`.
        field: &'static str,
        /// Why it was rejected, and which form is accepted instead.
        message: String,
    },

    /// Response could not be interpreted as the requested type or
    /// shape. When the message quotes an excerpt of what arrived,
    /// bearer-token material in it is replaced with `[redacted]` first.
    #[error("invalid response: {0}")]
    InvalidResponse(String),
}

/// Stand-in for credential material removed from a stored error body.
const REDACTED: &str = "[redacted]";

impl CirrusError {
    /// Removes bearer-token material from every variant that carries
    /// response-body text.
    ///
    /// A body is only ever retained when it didn't match the shape the
    /// SDK asked for — the error array on a 4xx/5xx, or the requested
    /// type on a 2xx. Both cases are dominated by pages written by
    /// proxies, gateways and WAFs, which routinely echo the offending
    /// request (headers included) back to the client. That text is
    /// interpolated into the error's `Display`, so an ordinary
    /// `tracing::error!("{e}")` would otherwise write a live org session
    /// id into the caller's log sink.
    ///
    /// Every new variant that stores body text has to be added here.
    pub(crate) fn redact_secrets(self, token: &str) -> Self {
        match self {
            Self::Api {
                status,
                errors,
                raw: Some(raw),
            } => Self::Api {
                status,
                errors,
                raw: Some(redact_body(&raw, token)),
            },
            Self::InvalidResponse(message) => Self::InvalidResponse(redact_body(&message, token)),
            other => other,
        }
    }
}

/// Replaces the live token, plus any `Bearer <credential>` run, with
/// [`REDACTED`]. The second pass matters because an echoed request may
/// carry a differently-encoded or already-rotated token that the exact
/// match misses.
fn redact_body(body: &str, token: &str) -> String {
    let stripped = if token.is_empty() {
        body.to_string()
    } else {
        body.replace(token, REDACTED)
    };
    redact_bearer_credentials(&stripped)
}

fn redact_bearer_credentials(body: &str) -> String {
    const KEYWORD: &str = "bearer";
    // ASCII-lowercasing preserves byte length, so offsets found here
    // index `body` unchanged.
    let haystack = body.to_ascii_lowercase();
    let mut out = String::with_capacity(body.len());
    let mut cursor = 0;
    while let Some(offset) = haystack[cursor..].find(KEYWORD) {
        let keyword_end = cursor + offset + KEYWORD.len();
        let after = &body[keyword_end..];
        let spacing = after.len() - after.trim_start_matches([' ', '\t']).len();
        let credential = &after[spacing..];
        let credential_len = credential
            .find(char::is_whitespace)
            .unwrap_or(credential.len());
        if spacing == 0 || credential_len == 0 {
            // A bare "bearer" with nothing after it — leave it be.
            out.push_str(&body[cursor..keyword_end]);
            cursor = keyword_end;
            continue;
        }
        out.push_str(&body[cursor..keyword_end + spacing]);
        out.push_str(REDACTED);
        cursor = keyword_end + spacing + credential_len;
    }
    out.push_str(&body[cursor..]);
    out
}

fn display_errors(errors: &[SalesforceError], raw: &Option<String>) -> String {
    if errors.is_empty() {
        return raw
            .as_deref()
            .map(|r| format!("<unparsed body: {r}>"))
            .unwrap_or_else(|| "<no body>".to_string());
    }
    errors
        .iter()
        .map(|e| {
            if e.fields.is_empty() {
                format!("[{}] {}", e.error_code, e.message)
            } else {
                format!(
                    "[{}] {} (fields: {})",
                    e.error_code,
                    e.message,
                    e.fields.join(", ")
                )
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn display_errors_formats_single_error() {
        let err = CirrusError::Api {
            status: 400,
            errors: vec![SalesforceError {
                message: "Required field missing".to_string(),
                error_code: "REQUIRED_FIELD_MISSING".to_string(),
                fields: vec!["Name".to_string()],
            }],
            raw: None,
        };
        let msg = err.to_string();
        assert!(msg.contains("400"));
        assert!(msg.contains("REQUIRED_FIELD_MISSING"));
        assert!(msg.contains("Name"));
    }

    #[test]
    fn display_errors_falls_back_to_raw_body() {
        let err = CirrusError::Api {
            status: 500,
            errors: vec![],
            raw: Some("Internal Server Error".to_string()),
        };
        let msg = err.to_string();
        assert!(msg.contains("500"));
        assert!(msg.contains("Internal Server Error"));
    }

    #[test]
    fn redact_secrets_strips_an_echoed_session_token() {
        // The shape a gateway 502 page takes when it echoes the
        // offending request line and headers.
        let token = "00D5f000000ABCD!AQcAQK_echoed_session_id";
        let err = CirrusError::Api {
            status: 502,
            errors: vec![],
            raw: Some(format!(
                "Bad Gateway — upstream rejected:\nGET /services/data/v66.0/query?q=SELECT+Id\nAuthorization: Bearer {token}\n"
            )),
        }
        .redact_secrets(token);

        let CirrusError::Api { raw: Some(raw), .. } = &err else {
            panic!("expected an Api error with a raw body");
        };
        assert!(!raw.contains(token), "token survived redaction: {raw}");
        assert!(raw.contains("[redacted]"));
        // Everything else about the page is still there to debug with.
        assert!(raw.contains("Bad Gateway"));
        assert!(raw.contains("/services/data/v66.0/query"));
        assert!(!err.to_string().contains(token));
    }

    #[test]
    fn redact_secrets_strips_bearer_credentials_the_token_match_misses() {
        // A stale or re-encoded credential in the echoed request is not
        // the token this attempt used, so the keyword scan has to catch
        // it. Case is irrelevant, and repeats are all replaced.
        let err = CirrusError::Api {
            status: 400,
            errors: vec![],
            raw: Some(
                "authorization: bearer stale-one\nX-Forwarded-Authorization: BEARER stale-two\n"
                    .to_string(),
            ),
        }
        .redact_secrets("current-token");

        let CirrusError::Api { raw: Some(raw), .. } = &err else {
            panic!("expected an Api error with a raw body");
        };
        assert!(!raw.contains("stale-one"), "{raw}");
        assert!(!raw.contains("stale-two"), "{raw}");
        assert_eq!(raw.matches("[redacted]").count(), 2, "{raw}");
    }

    #[test]
    fn redact_secrets_strips_a_token_echoed_in_an_invalid_response() {
        // A 2xx body that doesn't fit the requested type keeps an
        // excerpt, and an interposed hop can answer 200 with the same
        // echoed request a 502 page carries.
        let token = "00D5f000000ABCD!AQcAQK_two_hundred";
        let err = CirrusError::InvalidResponse(format!(
            "endpoint returned 200 but the body did not deserialize into the requested type: \
             expected value at line 1 column 1; body starts: \
             <html>GET /services/data/v66.0/limits Authorization: Bearer {token}</html>"
        ))
        .redact_secrets(token);

        let CirrusError::InvalidResponse(message) = &err else {
            panic!("expected an InvalidResponse error");
        };
        assert!(
            !message.contains(token),
            "token survived redaction: {message}"
        );
        assert!(message.contains("[redacted]"));
        assert!(message.contains("/services/data/v66.0/limits"));
        assert!(!err.to_string().contains(token));
    }

    #[test]
    fn redact_secrets_leaves_ordinary_bodies_alone() {
        let err = CirrusError::Api {
            status: 503,
            errors: vec![],
            raw: Some("Service Unavailable — bearer".to_string()),
        }
        .redact_secrets("tok");
        let CirrusError::Api { raw: Some(raw), .. } = &err else {
            panic!("expected an Api error with a raw body");
        };
        assert_eq!(raw, "Service Unavailable — bearer");
    }

    #[test]
    fn salesforce_error_deserializes_canonical_shape() {
        let json = r#"[{"message":"bad","errorCode":"INVALID_FIELD","fields":["Foo"]}]"#;
        let parsed: Vec<SalesforceError> = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].error_code, "INVALID_FIELD");
        assert_eq!(parsed[0].fields, vec!["Foo"]);
    }

    #[test]
    fn salesforce_error_handles_missing_fields() {
        let json = r#"[{"message":"bad","errorCode":"INVALID_SESSION_ID"}]"#;
        let parsed: Vec<SalesforceError> = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.len(), 1);
        assert!(parsed[0].fields.is_empty());
    }
}
