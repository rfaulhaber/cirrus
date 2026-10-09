//! Error types for the Cirrus SDK.
//!
//! Salesforce REST endpoints return errors as a JSON array of objects with a
//! consistent shape (`message`, `errorCode`, optional `fields`), regardless of
//! the success-response shape. [`SalesforceError`] models that shape, and
//! [`CirrusError::Api`] carries the parsed entries along with the HTTP
//! status. A few per-operation doc pages print a single error object in
//! place of the array; that form parses as a one-entry list.
//!
//! Auth-flow errors (OAuth token endpoints, JWT signing, missing builder
//! fields on a flow) come from the [`cirrus_auth`] crate as
//! [`AuthError`](cirrus_auth::AuthError) and are wrapped by
//! [`CirrusError::Auth`]. The `From<AuthError>` impl lets handlers
//! propagate them via `?` without extra boilerplate.

use cirrus_auth::AuthError;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;

/// Specialized `Result` type for Cirrus operations.
pub type CirrusResult<T> = Result<T, CirrusError>;

/// The `errorCode` Salesforce puts on a 401 whose cause is the bearer
/// token itself. No other 401 is cured by a fresh token.
const INVALID_SESSION_ID: &str = "INVALID_SESSION_ID";

/// A single Salesforce API error entry.
///
/// Salesforce REST endpoints return errors as a JSON array of these objects
/// (a few per-operation examples print one object without the array; both
/// parse). The shape is schema-independent and applies to every REST
/// resource.
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
    /// Every other key on the error object, under its wire name.
    ///
    /// Some errors carry more than the three documented members: a
    /// `DUPLICATES_DETECTED` error, for one, brings the matching records
    /// when the request asked for them with
    /// `Sforce-Duplicate-Rule-Header: includeRecordDetails=true`. Those
    /// members are kept here rather than dropped, so a caller can offer
    /// "use the existing record" from the error alone. Serializing the
    /// error writes them back at the top level.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// Errors produced by the Cirrus client.
///
/// Marked `#[non_exhaustive]`: match on the variants you handle and keep
/// a `_` arm, so a new variant in a later release is an additive change.
///
/// Variants that wrap another error ([`HttpClient`](Self::HttpClient),
/// [`Http`](Self::Http), [`Serialization`](Self::Serialization),
/// [`Url`](Self::Url)) expose it through
/// [`source()`](std::error::Error::source) and do not repeat its text in
/// their own `Display`, so a reporter that walks the chain prints each
/// message once. Print the chain (anyhow's `{:#}`, for example) to see
/// the underlying cause; `{}` alone names only the category.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CirrusError {
    /// A required builder field was not set.
    #[error("missing required builder field: {0}")]
    MissingField(&'static str),

    /// Failed to construct the underlying HTTP client.
    #[error("failed to construct HTTP client")]
    HttpClient(#[source] reqwest::Error),

    /// Network or transport-level HTTP failure.
    ///
    /// The wrapped error names the request's path but never its query
    /// string: SOQL travels as `q` and an `executeAnonymous` script as
    /// `anonymousBody`, and the error is what callers log.
    #[error("HTTP request failed")]
    Http(#[source] reqwest::Error),

    /// Salesforce returned a non-2xx response. `errors` holds the parsed
    /// Salesforce error entries (the documented array, or the bare object
    /// some per-operation pages print); if the body could not be parsed
    /// as either, the raw body is in `raw`.
    ///
    /// The one exception is a 300 whose body is a JSON array, which is
    /// [`MultipleMatches`](Self::MultipleMatches): that array lists
    /// records, not errors.
    ///
    /// The variant is `#[non_exhaustive]`: destructure it with `..` so a
    /// later field is an additive change.
    #[error("Salesforce API error (status {status}): {}", display_errors(.errors, .raw))]
    #[non_exhaustive]
    Api {
        /// HTTP status code returned by Salesforce.
        status: u16,
        /// Parsed Salesforce error entries. Empty if the body was not
        /// parseable as the error array or as a single error object.
        errors: Vec<SalesforceError>,
        /// Raw response body, capped at 2 KiB (longer bodies are
        /// truncated with a marker — non-Salesforce shapes come from
        /// proxies/gateways, and retaining them unboundedly would let
        /// echoed request data flow into logs). Populated when `errors`
        /// is empty so callers can see what came back; `None` when the
        /// body was empty too.
        ///
        /// Bearer-token material is replaced with `[redacted]` before
        /// the body is stored, because those intermediary pages tend to
        /// echo the request that provoked them and this value reaches
        /// the error's `Display`.
        raw: Option<String>,
        /// The response's `Retry-After` hint, when it carried one in a
        /// form the client could read (delta-seconds or an HTTP-date,
        /// per RFC 7231 §7.1.3). A caller that owns its own retries —
        /// under [`RetryPolicy::none`](crate::RetryPolicy::none), once
        /// the retry budget is spent, or on a request the policy never
        /// replays — can wait as long as the server asked. `None` when
        /// the header was absent or unreadable.
        retry_after: Option<Duration>,
    },

    /// A 300 response whose body is a JSON array: the records the request
    /// matched.
    ///
    /// The documented case is an upsert by external ID whose value is not
    /// unique: "If the external ID value isn't unique, an HTTP status code
    /// 300 is returned, plus a list of the records that matched the query"
    /// ([Insert or Update (Upsert) a Record Using an External ID][upsert]).
    /// Such an upsert neither creates nor updates anything, and `records`
    /// is the list it answers with, each entry untouched, so a caller can
    /// pick the record it meant and retry by ID. Salesforce does not
    /// document the shape of the entries, which is why they are
    /// [`serde_json::Value`]s.
    ///
    /// Every 300 with a JSON-array body, from any endpoint, parses into
    /// this variant; a 300 with any other body stays [`Api`](Self::Api).
    ///
    /// The list is bounded only by the client's 256 KiB cap on non-2xx
    /// bodies, not by the 2 KiB cap on [`Api`](Self::Api)'s `raw`.
    /// `Display` reports only how many records matched, because the
    /// entries are record data.
    ///
    /// The variant is `#[non_exhaustive]`: destructure it with `..` so a
    /// later field is an additive change.
    ///
    /// [upsert]: https://developer.salesforce.com/docs/platform/api-rest/guide/dome-upsert.html
    //
    // Wire-shape provenance: the Upsert page linked above prints no example
    // body for the 300. That the list is a JSON array is the reading of "a
    // list"; the page does not document the entries' members.
    #[error("HTTP 300: the request matched {} records", .records.len())]
    #[non_exhaustive]
    MultipleMatches {
        /// The matching records as Salesforce sent them.
        records: Vec<serde_json::Value>,
    },

    /// An auth flow (token acquisition, refresh, OAuth exchange) failed.
    /// Wraps the underlying [`AuthError`] from `cirrus-auth`.
    #[error(transparent)]
    Auth(#[from] AuthError),

    /// Failed to serialize a request body to JSON — the `deployOptions`
    /// or blob-field metadata part of a multipart upload. Response
    /// bodies that don't match the shape the SDK asked for surface as
    /// [`CirrusError::InvalidResponse`] instead.
    #[error("serialization error")]
    Serialization(#[from] serde_json::Error),

    /// URL parsing failure (instance URL, redirect URI, etc.).
    #[error("invalid URL")]
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

    /// The response body was longer than the client buffers, so it was
    /// not read.
    ///
    /// The limit counts decoded bytes. A successful (2xx) response is
    /// held to [`CirrusBuilder::max_response_size`](crate::CirrusBuilder::max_response_size);
    /// every other response is held to a fixed 256 KiB, far above the
    /// error shapes Salesforce documents. A retryable status whose body
    /// is oversized is still retried; this error reports the final
    /// attempt.
    #[error("HTTP {status} response body exceeded the {limit}-byte limit")]
    ResponseTooLarge {
        /// HTTP status of the oversized response.
        status: u16,
        /// The limit that was exceeded, in decoded bytes.
        limit: usize,
    },

    /// Response could not be interpreted as the requested type or
    /// shape. When the message quotes an excerpt of what arrived,
    /// bearer-token material in it is replaced with `[redacted]` first.
    #[error("invalid response: {0}")]
    InvalidResponse(String),
}

/// Stand-in for credential material removed from a stored error body.
const REDACTED: &str = "[redacted]";

impl From<reqwest::Error> for CirrusError {
    /// Every transport error enters the crate here. reqwest attaches the
    /// request URL to timeout, connect and reset errors and prints it in
    /// both `Display` and `Debug`; the query string is caller data (a
    /// SOQL `q`, an `executeAnonymous` script), so it is dropped while
    /// the path stays for diagnostics.
    fn from(mut error: reqwest::Error) -> Self {
        if let Some(url) = error.url_mut() {
            url.set_query(None);
        }
        Self::Http(error)
    }
}

impl CirrusError {
    /// Whether this is Salesforce's own report that the bearer token is
    /// expired or invalid: a 401 whose error array carries
    /// `INVALID_SESSION_ID`. A 401 that an Apex REST class sets, or that
    /// a scope check produces, is the endpoint's verdict on the request
    /// and is not one of these.
    pub(crate) fn is_invalid_session(&self) -> bool {
        matches!(
            self,
            Self::Api { status: 401, errors, .. }
                if errors.iter().any(|e| e.error_code == INVALID_SESSION_ID)
        )
    }

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
                retry_after,
            } => Self::Api {
                status,
                errors,
                raw: Some(redact_body(&raw, token)),
                retry_after,
            },
            Self::InvalidResponse(message) => Self::InvalidResponse(redact_body(&message, token)),
            Self::MultipleMatches { records } => Self::MultipleMatches {
                records: records
                    .into_iter()
                    .map(|record| redact_json(record, token))
                    .collect(),
            },
            other => other,
        }
    }

    /// Attaches the response's `Retry-After` hint to an
    /// [`Api`](Self::Api) error. Every other variant passes through
    /// unchanged: the hint belongs to a response, and only `Api` is one.
    pub(crate) fn with_retry_after(self, retry_after: Option<Duration>) -> Self {
        match self {
            Self::Api {
                status,
                errors,
                raw,
                ..
            } => Self::Api {
                status,
                errors,
                raw,
                retry_after,
            },
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

/// Applies [`redact_body`] to every string leaf of `value`. Object keys
/// and non-string leaves pass through unchanged.
fn redact_json(value: serde_json::Value, token: &str) -> serde_json::Value {
    use serde_json::Value;
    match value {
        Value::String(text) => Value::String(redact_body(&text, token)),
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(|item| redact_json(item, token))
                .collect(),
        ),
        Value::Object(members) => Value::Object(
            members
                .into_iter()
                .map(|(key, member)| (key, redact_json(member, token)))
                .collect(),
        ),
        other => other,
    }
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
                extra: Default::default(),
            }],
            raw: None,
            retry_after: None,
        };
        let msg = err.to_string();
        assert!(msg.contains("400"));
        assert!(msg.contains("REQUIRED_FIELD_MISSING"));
        assert!(msg.contains("Name"));
    }

    #[test]
    fn multiple_matches_display_reports_the_count_and_no_record_data() {
        let err = CirrusError::MultipleMatches {
            records: vec![
                serde_json::json!({"Name": "Acme Confidential"}),
                serde_json::json!({"Name": "Globex Confidential"}),
            ],
        };
        let msg = err.to_string();
        assert!(msg.contains("2 records"), "{msg}");
        assert!(!msg.contains("Confidential"), "{msg}");
    }

    #[test]
    fn display_errors_falls_back_to_raw_body() {
        let err = CirrusError::Api {
            status: 500,
            errors: vec![],
            raw: Some("Internal Server Error".to_string()),
            retry_after: None,
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
            retry_after: None,
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
            retry_after: None,
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
    fn redact_secrets_strips_a_token_nested_in_multiple_matches_records() {
        // The 300 list is kept whole and its entries are arbitrary JSON,
        // so an interposed hop that answers 300 with an echoed request
        // can put the token in any string leaf, at any depth.
        let token = "00D5f000000ABCD!AQcAQK_nested_session_id";
        let err = CirrusError::MultipleMatches {
            records: vec![
                serde_json::json!({
                    "Id": "001xx000003DGb2AAG",
                    "Echo": {
                        "Authorization": format!("Bearer {token}"),
                        "Trace": ["hop-1", format!("session {token} rejected")],
                        "Attempts": 3,
                        "Final": false,
                        "Retry": null,
                    },
                }),
                serde_json::json!(token),
            ],
        }
        .redact_secrets(token);

        let CirrusError::MultipleMatches { records } = &err else {
            panic!("expected a MultipleMatches error");
        };
        assert!(!format!("{err:?}").contains(token), "{err:?}");
        assert_eq!(
            records,
            &vec![
                serde_json::json!({
                    "Id": "001xx000003DGb2AAG",
                    "Echo": {
                        "Authorization": "Bearer [redacted]",
                        "Trace": ["hop-1", "session [redacted] rejected"],
                        "Attempts": 3,
                        "Final": false,
                        "Retry": null,
                    },
                }),
                serde_json::json!("[redacted]"),
            ]
        );
    }

    #[test]
    fn redact_secrets_leaves_ordinary_bodies_alone() {
        let err = CirrusError::Api {
            status: 503,
            errors: vec![],
            raw: Some("Service Unavailable — bearer".to_string()),
            retry_after: None,
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
        assert!(parsed[0].extra.is_empty());
    }

    #[test]
    fn salesforce_error_keeps_undocumented_keys_under_their_wire_names() {
        // Wire-shape provenance: the Duplicate Rule Header page
        // (https://developer.salesforce.com/docs/platform/api-rest/guide/headers-duplicaterules.html)
        // says includeRecordDetails=true returns "all fields in the
        // duplicate record" on a DUPLICATES_DETECTED error, but no REST
        // page shows the key that carries them. The key below is the
        // SOAP name; what the test pins is that any key beyond message,
        // errorCode and fields reaches the caller, whatever it is called.
        let json = r#"[{
            "message": "You're creating a duplicate record. We recommend you use an existing record instead.",
            "errorCode": "DUPLICATES_DETECTED",
            "duplicateResult": {"matchResults": [{"matchRecords": [{"record": {"Id": "00Q5f000001AbCdEAK"}}]}]}
        }]"#;
        let parsed: Vec<SalesforceError> = serde_json::from_str(json).unwrap();
        assert_eq!(parsed[0].error_code, "DUPLICATES_DETECTED");
        assert!(parsed[0].fields.is_empty());
        assert_eq!(
            parsed[0].extra["duplicateResult"]["matchResults"][0]["matchRecords"][0]["record"]["Id"],
            "00Q5f000001AbCdEAK"
        );

        // The members go back out at the top level, not nested under
        // the field that holds them.
        let round_trip = serde_json::to_value(&parsed[0]).unwrap();
        assert!(round_trip.get("extra").is_none(), "{round_trip}");
        assert_eq!(
            round_trip["duplicateResult"],
            parsed[0].extra["duplicateResult"]
        );
        assert!(round_trip.get("fields").is_none(), "{round_trip}");
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
            CirrusError::HttpClient(client_build_error()),
            CirrusError::Http(client_build_error()),
            CirrusError::Serialization(serde_json::from_str::<serde_json::Value>("{").unwrap_err()),
            CirrusError::Url(url::Url::parse("not a url").unwrap_err()),
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
