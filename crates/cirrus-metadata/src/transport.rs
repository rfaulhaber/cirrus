//! SOAP transport — request dispatch, retry, and auth-refresh.
//!
//! [`SoapOperation`] is the trait every handler implements; it specifies
//! the operation's name and response shape, and renders the body XML.
//! [`soap_call`] is the dispatcher that:
//!
//! 1. Asks [`AuthSession`] for a bearer token.
//! 2. Builds the envelope around the rendered body.
//! 3. POSTs to `/services/Soap/m/{api_version}` with the SOAP-required
//!    headers (`Content-Type: text/xml; charset=UTF-8`, `SOAPAction: ""`).
//! 4. Parses the response envelope into either a typed `O::Response` or
//!    a [`MetadataError::Soap`] carrying the [`SoapFault`].
//! 5. Retries transient failures per the client's [`RetryPolicy`]. The
//!    envelope is parsed first, so an application-level fault is
//!    surfaced immediately instead of being replayed under the 5xx
//!    rule.
//! 6. On `INVALID_SESSION_ID` faults, invalidates the cached token and
//!    retries the entire call once with a freshly-minted token.
//!
//! [`AuthSession`]: cirrus_auth::AuthSession
//! [`SoapFault`]: crate::error::SoapFault

use crate::MetadataClient;
use crate::envelope::{self, EnvelopeBody};
use crate::error::{MetadataError, MetadataResult};
use crate::retry;
use bytes::Bytes;
use serde::de::DeserializeOwned;

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
    /// so this declaration is the only idempotency signal the retry
    /// policy has. Defaults to `false` (never replay); read-only
    /// operations (`checkDeployStatus`, `listMetadata`, …) opt in.
    const IDEMPOTENT: bool = false;

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
    let response_local = format!("{}Response", O::NAME);
    let body_xml = op.render_body()?;
    let inner =
        call_with_auth_retry(client, O::NAME, op.idempotent(), &body_xml, &response_local).await?;
    // `from_str` borrows text nodes straight out of `inner`; the
    // `from_reader` path would copy every event — including the
    // multi-megabyte base64 `<zipFile>` — through an internal buffer
    // first.
    let parsed: O::Response = quick_xml::de::from_str(&inner)?;
    Ok(parsed)
}

/// Outer loop: handles INVALID_SESSION_ID auto-refresh (at most once).
/// Each iteration mints a fresh token from [`AuthSession`] and runs the
/// inner HTTP retry loop.
async fn call_with_auth_retry(
    client: &MetadataClient,
    op_name: &str,
    idempotent: bool,
    body_xml: &str,
    response_local: &str,
) -> MetadataResult<String> {
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

        let envelope = envelope::build_envelope(&token_str, op_name, body_xml);
        // Bytes is Arc-backed — clones on retry are cheap.
        let body = Bytes::from(envelope.into_bytes());
        let result = send_with_retries(client, idempotent, body, response_local).await;

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
/// the response envelope's `<{NAME}Response>...</{NAME}Response>`
/// element on success.
async fn send_with_retries(
    client: &MetadataClient,
    idempotent: bool,
    envelope_bytes: Bytes,
    response_local: &str,
) -> MetadataResult<String> {
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

                let bytes = match response.bytes().await {
                    Ok(b) => b,
                    Err(e) => {
                        // The response died mid-body — as ambiguous as
                        // a failed send, so it follows the same replay
                        // rules.
                        let err: MetadataError = e.into();
                        if status_retryable
                            || retry::should_retry_network(
                                &client.retry_policy,
                                idempotent,
                                &err,
                                attempt,
                            )
                        {
                            sleep_before_retry(client, attempt, &headers).await;
                            attempt += 1;
                            continue;
                        }
                        return Err(err);
                    }
                };

                // SOAP faults can arrive with HTTP 500 or (uncommonly)
                // HTTP 200, so the body decides the outcome — not the
                // status. Parsing before the retry decision is what
                // keeps a deterministic application fault (INVALID_TYPE,
                // REQUEST_LIMIT_EXCEEDED, INVALID_SESSION_ID) from being
                // replayed under the 5xx rule and surfaced only after
                // the whole retry budget is spent.
                match envelope::parse_envelope(&bytes, response_local) {
                    Ok(EnvelopeBody::Success(inner)) => return Ok(inner),
                    Ok(EnvelopeBody::Fault(fault)) => {
                        if status_retryable && retry::is_transient_fault(&fault) {
                            sleep_before_retry(client, attempt, &headers).await;
                            attempt += 1;
                            continue;
                        }
                        return Err(MetadataError::Soap { status, fault });
                    }
                    Err(parse_err) => {
                        // No SOAP envelope means the response came from
                        // an intermediary rather than the org, so the
                        // status is all we have to go on.
                        if status_retryable {
                            sleep_before_retry(client, attempt, &headers).await;
                            attempt += 1;
                            continue;
                        }
                        // 2xx with a body we couldn't parse is a
                        // server-shape problem, not an HTTP error:
                        // route through InvalidResponse so the variant
                        // name matches the wire. Non-2xx with non-SOAP
                        // body keeps Http4xx5xx.
                        if (200..300).contains(&status) {
                            return Err(MetadataError::InvalidResponse(format!(
                                "HTTP {status} with non-SOAP body: {parse_err}"
                            )));
                        }
                        return Err(MetadataError::Http4xx5xx {
                            status,
                            raw: crate::error::cap_raw_body(&bytes),
                        });
                    }
                }
            }
            Err(e) => {
                let err: MetadataError = e.into();
                if retry::should_retry_network(&client.retry_policy, idempotent, &err, attempt) {
                    let delay = retry::compute_delay(&client.retry_policy, attempt, None);
                    tokio::time::sleep(delay).await;
                    attempt += 1;
                    continue;
                }
                return Err(err);
            }
        }
    }
}

/// Wait out the backoff for `attempt`, honoring a `Retry-After` hint on
/// the response that prompted the retry.
async fn sleep_before_retry(
    client: &MetadataClient,
    attempt: u32,
    headers: &reqwest::header::HeaderMap,
) {
    let retry_after = retry::parse_retry_after(headers);
    let delay = retry::compute_delay(&client.retry_policy, attempt, retry_after);
    tokio::time::sleep(delay).await;
}
