//! SOAP transport — request dispatch, retry, and auth-refresh.
//!
//! [`SoapOperation`] is the trait every handler implements; it specifies
//! the operation's name and response shape, and renders the body XML
//! (and, optionally, extra SOAP headers). [`soap_call`] is the
//! dispatcher that:
//!
//! 1. Asks [`AuthSession`] for a bearer token.
//! 2. Builds the envelope around the rendered body, with the client's
//!    `CallOptions` and the operation's own headers after the
//!    `SessionHeader`.
//! 3. POSTs to `/services/Soap/m/{api_version}` with the SOAP-required
//!    headers (`Content-Type: text/xml; charset=UTF-8`, `SOAPAction: ""`),
//!    after confirming the instance URL is still `https` or loopback —
//!    the session id rides in the body, and the URL is re-read from the
//!    session on every call.
//! 4. Reads the response body under a size limit, then parses the
//!    envelope in place into either a typed `O::Response` or a
//!    [`MetadataError::Soap`] carrying the [`SoapFault`];
//!    [`soap_call_with_headers`] also deserializes the `DebuggingInfo`
//!    output header.
//! 5. Retries transient failures per the client's [`RetryPolicy`]. The
//!    envelope is parsed first, so an application-level fault is
//!    surfaced immediately instead of being replayed under the 5xx
//!    rule. A body over the size limit is treated like a retryable
//!    status whose body was dropped.
//! 6. On `INVALID_SESSION_ID` faults, invalidates the cached token and
//!    retries the entire call once with a freshly-minted token.
//! 7. Scrubs the attempt's session id from any error that retains body
//!    text, since an intermediary's error page may echo the envelope.
//!
//! [`AuthSession`]: cirrus_auth::AuthSession
//! [`SoapFault`]: crate::error::SoapFault

use crate::envelope::{self, EnvelopeBody, ParsedEnvelope};
use crate::error::{MetadataError, MetadataResult, PARSE_MESSAGE_CAP, cap_text};
use crate::headers::{self, DebuggingInfo, SoapResponseHeaders};
use crate::retry;
use crate::{MetadataClient, NON_SUCCESS_BODY_CAP};
use bytes::Bytes;
use cirrus_auth::transport::{CollectBodyError, collect_body};
use serde::de::DeserializeOwned;
use std::ops::Range;

/// A typed SOAP operation against the Metadata API.
///
/// Implement this for each call. The transport handles the envelope,
/// auth header, retry, and fault detection — the implementor only
/// renders the operation-specific body XML and names the response type.
///
/// ## The response wrapper
///
/// The Metadata API returns success responses as
/// `<{NAME}Response>...</{NAME}Response>`. The transport preserves that
/// outer wrapper when deserializing, so response structs can be named
/// after the wire element and use serde's standard derive to map child
/// elements:
///
/// ```ignore
/// #[derive(serde::Deserialize)]
/// struct ListMetadataResponse {
///     #[serde(default, rename = "result")]
///     result: Vec<FileProperties>,
/// }
/// ```
///
/// quick-xml's serde deserializer doesn't enforce that the struct's
/// name matches the root element's name; the child-field mapping is
/// what matters.
pub trait SoapOperation {
    /// Unqualified SOAP operation name, e.g. `"deploy"`. Used both to
    /// wrap the body in `<met:NAME>...</met:NAME>` and to recognize
    /// `<NAMEResponse>` on the way back.
    const NAME: &'static str;

    /// Whether the operation is safe to replay when the outcome of a
    /// sent request is unknown (a 5xx from an intermediary, a
    /// mid-request network failure). Every SOAP call is an HTTP POST,
    /// so the HTTP method carries no idempotency signal; the retry path
    /// reads [`idempotent()`](Self::idempotent), which defaults to this
    /// const. Defaults to `false` (never replay); read-only operations
    /// (`checkDeployStatus`, `listMetadata`, …) opt in. An operation
    /// whose replay safety depends on its arguments overrides
    /// [`idempotent()`](Self::idempotent) instead of setting this.
    const IDEMPOTENT: bool = false;

    /// Whether the client's `CallOptions` header is sent with this
    /// operation. Defaults to `true`: the Metadata WSDL binds
    /// `CallOptions` on every operation except `describeValueType`,
    /// which opts out.
    const ACCEPTS_CALL_OPTIONS: bool = true;

    /// The typed response shape. Deserialized via `quick-xml`'s serde
    /// implementation from the full
    /// `<{NAME}Response>...</{NAME}Response>` element.
    type Response: DeserializeOwned;

    /// Render the operation-specific body XML — everything between
    /// `<met:NAME>` and `</met:NAME>`. May be empty for operations that
    /// take no arguments.
    ///
    /// The renderer is responsible for any inner XML namespaces; the
    /// outer `met:` prefix is added by the transport.
    fn render_body(&self) -> MetadataResult<String>;

    /// Render extra elements for `<soapenv:Header>`, such as
    /// `<met:AllOrNoneHeader>`. Defaults to none.
    ///
    /// Render them with the `met:` prefix and escape text with
    /// [`xml_escape`](crate::xml_escape). The transport adds the
    /// `SessionHeader` and the client's `CallOptions` itself; the
    /// elements returned here follow them. Called once per
    /// [`MetadataClient::call`], so a retry or an
    /// `INVALID_SESSION_ID` refresh resends the same headers.
    fn render_headers(&self) -> MetadataResult<String> {
        Ok(String::new())
    }

    /// Whether *this* request is safe to replay. Defaults to
    /// [`IDEMPOTENT`](Self::IDEMPOTENT).
    ///
    /// Override when replay safety depends on the arguments rather than
    /// the operation — `checkRetrieveStatus` is a plain status read
    /// while `includeZip` is `false`, but the call that fetches the zip
    /// also deletes it from the server and must never be replayed.
    fn idempotent(&self) -> bool {
        Self::IDEMPOTENT
    }
}

/// Dispatch one SOAP operation through the client.
pub(crate) async fn soap_call<O: SoapOperation>(
    client: &MetadataClient,
    op: &O,
) -> MetadataResult<O::Response> {
    // The output headers are dropped unparsed, so a header a caller
    // never asked for cannot fail the call.
    dispatch(client, op).await.map(|(response, _)| response)
}

/// Dispatch one SOAP operation and return the output headers next to
/// the typed response.
pub(crate) async fn soap_call_with_headers<O: SoapOperation>(
    client: &MetadataClient,
    op: &O,
) -> MetadataResult<(O::Response, SoapResponseHeaders)> {
    let (response, raw_headers) = dispatch(client, op).await?;
    let debugging_info = raw_headers
        .debugging_info
        .map(|range| {
            let mut de = quick_xml::de::Deserializer::from_str(&raw_headers.text[range]);
            serde_path_to_error::deserialize::<_, DebuggingInfo>(&mut de).map_err(|e| {
                MetadataError::Xml(format!(
                    "DebuggingInfo: {} at `{}`",
                    cap_text(&e.inner().to_string(), PARSE_MESSAGE_CAP),
                    e.path()
                ))
            })
        })
        .transpose()?;
    Ok((response, SoapResponseHeaders { debugging_info }))
}

/// Renders the request headers that follow the `SessionHeader`: the
/// client's `CallOptions` when the operation takes it, then the
/// operation's own.
fn render_request_headers<O: SoapOperation>(
    client: &MetadataClient,
    op: &O,
) -> MetadataResult<String> {
    let mut out = String::new();
    if O::ACCEPTS_CALL_OPTIONS
        && let Some(call_options_client) = &client.call_options_client
    {
        headers::render_call_options(call_options_client, &mut out);
    }
    out.push_str(&op.render_headers()?);
    Ok(out)
}

/// A successful response: the text of the whole envelope and where in it
/// the response element and the `DebuggingInfo` header sit. The envelope
/// is kept whole and located in place, because copying the response
/// element out would duplicate a retrieve's base64 zip, which can run to
/// tens of megabytes.
struct SoapResponse {
    text: String,
    body: Range<usize>,
    debugging_info: Option<Range<usize>>,
}

/// The output headers of a response, still inside the envelope text they
/// were located in.
struct OutputHeaders {
    text: String,
    debugging_info: Option<Range<usize>>,
}

async fn dispatch<O: SoapOperation>(
    client: &MetadataClient,
    op: &O,
) -> MetadataResult<(O::Response, OutputHeaders)> {
    let response_local = format!("{}Response", O::NAME);
    let body_xml = op.render_body()?;
    let headers_xml = render_request_headers(client, op)?;
    let response = call_with_auth_retry(
        client,
        O::NAME,
        op.idempotent(),
        &headers_xml,
        &body_xml,
        &response_local,
    )
    .await?;
    // `from_str` borrows text nodes straight out of the envelope text;
    // the `from_reader` path would copy every event — including the
    // multi-megabyte base64 `<zipFile>` — through an internal buffer
    // first. The path wrapper names the element that failed, so a
    // field Salesforce changes in a release is diagnosable without a
    // traffic capture; the message it wraps is capped because serde
    // quotes the value it rejected.
    let mut de = quick_xml::de::Deserializer::from_str(&response.text[response.body]);
    let parsed: O::Response = serde_path_to_error::deserialize(&mut de).map_err(|e| {
        MetadataError::Xml(format!(
            "{response_local}: {} at `{}`",
            cap_text(&e.inner().to_string(), PARSE_MESSAGE_CAP),
            e.path()
        ))
    })?;
    Ok((
        parsed,
        OutputHeaders {
            text: response.text,
            debugging_info: response.debugging_info,
        },
    ))
}

/// Outer loop: handles INVALID_SESSION_ID auto-refresh (at most once).
/// Each iteration mints a fresh token from [`AuthSession`] and runs the
/// inner HTTP retry loop.
async fn call_with_auth_retry(
    client: &MetadataClient,
    op_name: &str,
    idempotent: bool,
    headers_xml: &str,
    body_xml: &str,
    response_local: &str,
) -> MetadataResult<SoapResponse> {
    // First iteration fetches a token from the auth session. On a
    // refresh-after-INVALID_SESSION_ID we thread the *already-fetched*
    // fresh token in here, instead of calling access_token() a second
    // time — for flows like JWT bearer the second call would re-sign
    // and re-hit the token endpoint.
    let mut next_token: Option<String> = None;
    let mut auth_retried = false;
    loop {
        let token_str = match next_token.take() {
            Some(t) => t,
            None => {
                let token = client.auth.access_token().await?;
                token.into_owned()
            }
        };

        let envelope = envelope::build_envelope(&token_str, op_name, headers_xml, body_xml);
        // Bytes is Arc-backed — clones on retry are cheap.
        let body = Bytes::from(envelope.into_bytes());
        // An intermediary's error page may echo the envelope, token
        // included; scrub it here, where the attempt's token is still in
        // hand, before the error can reach a log sink.
        let result = send_with_retries(client, idempotent, body, response_local)
            .await
            .map_err(|e| e.redact_secrets(&token_str));

        if !auth_retried
            && let Err(MetadataError::Soap { fault, .. }) = &result
            && fault.is_invalid_session()
        {
            tracing::warn!(
                target: "cirrus_metadata::auth",
                "INVALID_SESSION_ID fault; invalidating cached token and retrying once",
            );
            client.auth.invalidate(&token_str).await;
            // Compare-and-fail: if the auth session can't actually
            // refresh (e.g. StaticTokenAuth), surface the original
            // fault rather than looping. We keep the fresh token to
            // reuse on the next iteration.
            let fresh = client.auth.access_token().await?.into_owned();
            if fresh == token_str {
                tracing::warn!(
                    target: "cirrus_metadata::auth",
                    "auth session returned the same token after invalidate; surfacing fault \
                     (likely static auth or scope/permission issue)",
                );
                return result;
            }
            next_token = Some(fresh);
            auth_retried = true;
            continue;
        }
        return result;
    }
}

/// Inner loop: retries transient failures per [`RetryPolicy`]. Returns
/// the response envelope's text with the locations of its
/// `<{NAME}Response>...</{NAME}Response>` element and output headers on
/// success.
async fn send_with_retries(
    client: &MetadataClient,
    idempotent: bool,
    envelope_bytes: Bytes,
    response_local: &str,
) -> MetadataResult<SoapResponse> {
    crate::check_transport_security(client.auth.instance_url(), client.allow_insecure_transport)?;
    let url = client.endpoint_url();
    let mut attempt: u32 = 0;
    loop {
        let request = client
            .http
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, "text/xml; charset=UTF-8")
            // SOAP 1.1 requires SOAPAction; Salesforce expects the
            // literal empty-string form (`""`).
            .header("SOAPAction", "\"\"")
            // Bytes is Arc-backed; clone is a refcount bump, not a
            // memcpy of the envelope body.
            .body(envelope_bytes.clone());

        match request.send().await {
            Ok(response) => {
                let status = response.status().as_u16();
                let headers = response.headers().clone();
                let status_retryable =
                    retry::should_retry_status(&client.retry_policy, idempotent, status, attempt);

                let cap = if (200..300).contains(&status) {
                    client.max_response_size.unwrap_or(usize::MAX)
                } else {
                    NON_SUCCESS_BODY_CAP
                };
                let bytes = match collect_body(response, cap).await {
                    Ok(b) => b,
                    Err(CollectBodyError::TooLarge { limit }) => {
                        // An oversized body is dropped unread, like the
                        // body of any other retryable status.
                        if status_retryable && let Some(delay) = backoff(client, attempt, &headers)
                        {
                            tokio::time::sleep(delay).await;
                            attempt += 1;
                            continue;
                        }
                        return Err(MetadataError::ResponseTooLarge { status, limit });
                    }
                    Err(CollectBodyError::Transport(e)) => {
                        // The response died mid-body — as ambiguous as
                        // a failed send, so it follows the same replay
                        // rules.
                        let err: MetadataError = e.into();
                        let retryable = status_retryable
                            || retry::should_retry_network(
                                &client.retry_policy,
                                idempotent,
                                &err,
                                attempt,
                            );
                        if retryable && let Some(delay) = backoff(client, attempt, &headers) {
                            tokio::time::sleep(delay).await;
                            attempt += 1;
                            continue;
                        }
                        return Err(err);
                    }
                    // `CollectBodyError` is `non_exhaustive`.
                    Err(other) => return Err(MetadataError::InvalidResponse(other.to_string())),
                };

                // SOAP faults can arrive with HTTP 500 or (uncommonly)
                // HTTP 200, so the body decides the outcome — not the
                // status. Parsing before the retry decision is what
                // keeps a deterministic application fault (INVALID_TYPE,
                // REQUEST_LIMIT_EXCEEDED, INVALID_SESSION_ID) from being
                // replayed under the 5xx rule and surfaced only after
                // the whole retry budget is spent.
                //
                // The text is validated as UTF-8 once, here, and the
                // envelope is then parsed in place. `Vec::from` reuses
                // the buffer of a uniquely owned `Bytes`, which the
                // reader builds for any multi-chunk body. A body that
                // fails either step keeps its bytes for the excerpt.
                let parsed: Result<(String, ParsedEnvelope), (MetadataError, Vec<u8>)> =
                    match String::from_utf8(Vec::from(bytes)) {
                        Ok(text) => match envelope::parse_envelope(&text, response_local) {
                            Ok(parsed) => Ok((text, parsed)),
                            Err(e) => Err((e, text.into_bytes())),
                        },
                        Err(e) => Err((
                            MetadataError::InvalidResponse(format!(
                                "response is not valid UTF-8: {}",
                                e.utf8_error()
                            )),
                            e.into_bytes(),
                        )),
                    };
                match parsed {
                    Ok((
                        text,
                        ParsedEnvelope {
                            headers: response_headers,
                            body: EnvelopeBody::Success(body),
                        },
                    )) => {
                        return Ok(SoapResponse {
                            text,
                            body,
                            debugging_info: response_headers.debugging_info,
                        });
                    }
                    Ok((
                        _,
                        ParsedEnvelope {
                            body: EnvelopeBody::Fault(fault),
                            ..
                        },
                    )) => {
                        if status_retryable
                            && retry::is_transient_fault(&fault)
                            && let Some(delay) = backoff(client, attempt, &headers)
                        {
                            tokio::time::sleep(delay).await;
                            attempt += 1;
                            continue;
                        }
                        return Err(MetadataError::Soap {
                            status,
                            fault,
                            retry_after: retry::parse_retry_after(&headers),
                        });
                    }
                    Err((parse_err, raw)) => {
                        // No SOAP envelope means the response came from
                        // an intermediary rather than the org, so the
                        // status is all we have to go on.
                        if status_retryable && let Some(delay) = backoff(client, attempt, &headers)
                        {
                            tokio::time::sleep(delay).await;
                            attempt += 1;
                            continue;
                        }
                        // 2xx with a body we couldn't parse is a
                        // server-shape problem, not an HTTP error:
                        // route through InvalidResponse so the variant
                        // name matches the wire, with a short excerpt
                        // so the caller can see what answered. Non-2xx
                        // with non-SOAP body keeps Http4xx5xx.
                        if (200..300).contains(&status) {
                            return Err(MetadataError::InvalidResponse(format!(
                                "HTTP {status} with non-SOAP body: {parse_err}; body starts: {}",
                                crate::error::cap_body_excerpt(&raw)
                            )));
                        }
                        return Err(MetadataError::Http4xx5xx {
                            status,
                            raw: crate::error::cap_raw_body(&raw),
                            retry_after: retry::parse_retry_after(&headers),
                        });
                    }
                }
            }
            Err(e) => {
                let err: MetadataError = e.into();
                if retry::should_retry_network(&client.retry_policy, idempotent, &err, attempt)
                    && let Some(delay) = retry::compute_delay(&client.retry_policy, attempt, None)
                {
                    tokio::time::sleep(delay).await;
                    attempt += 1;
                    continue;
                }
                return Err(err);
            }
        }
    }
}

/// The backoff for `attempt`, honoring a `Retry-After` hint on the
/// response that prompted the retry — or `None` when the hint is longer
/// than the policy's `max_delay`, in which case the response surfaces
/// instead of being retried inside the server's window.
fn backoff(
    client: &MetadataClient,
    attempt: u32,
    headers: &reqwest::header::HeaderMap,
) -> Option<std::time::Duration> {
    let retry_after = retry::parse_retry_after(headers);
    retry::compute_delay(&client.retry_policy, attempt, retry_after)
}
