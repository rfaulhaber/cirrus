//! SOAP 1.1 envelope construction and parsing for the Metadata API.
//!
//! Salesforce's Metadata API sits behind a single SOAP endpoint
//! (`/services/Soap/m/{api_version}`). Every request is the same envelope
//! shape — `<soapenv:Envelope>` containing a `<met:SessionHeader>` with the
//! bearer token, and a body element named after the operation. Every
//! response is either a matching `{Operation}Response` element or a
//! `<soapenv:Fault>`.
//!
//! ## Why hand-build instead of using `quick-xml`'s serde serializer?
//!
//! The envelope wrapper is structurally constant — only the session token,
//! operation name, and inner body XML vary. Serde-driven serialization
//! would have to wrestle with mixing two namespaces (`soapenv:` and
//! `met:`), and quick-xml's namespace handling at the serde layer is
//! finicky. Hand-rolling the wrapper keeps the wire bytes predictable
//! while still letting individual handlers use quick-xml's serde for the
//! body content if they choose.
//!
//! ## What the response parser returns
//!
//! [`parse_envelope`] walks the response with a pull parser, tracking
//! element depth manually to be robust against unknown namespace prefixes
//! and arbitrary nesting inside the response body. It returns a
//! [`ParsedEnvelope`]: the body — either a parsed [`SoapFault`] or the
//! byte range of the full `<{Operation}Response>...</{Operation}Response>`
//! element — and the output headers found in `<Header>`. Handlers then
//! deserialize that slice of the response text via quick-xml's serde
//! implementation into their typed response shape. Keeping the outer
//! wrapper lets response structs be named after the wire element and
//! handle multi-`<result>` shapes (e.g. `listMetadata`) without a
//! synthetic root.
//!
//! The only output header the Metadata API documents is
//! `DebuggingInfo`; it is returned as a byte range the same way as the
//! body element. Any other `<Header>` child is skipped.
//!
//! Elements are located, never copied: a range is the span of the
//! response text from the `<` of the opening tag to the `>` of the
//! closing one, so a `<zipFile>` holding tens of megabytes of base64 is
//! parsed in place. Because the slice is the server's own text, character
//! data comes out verbatim — text is never trimmed and entity references
//! stay as they arrived — and metadata values reach the caller exactly
//! as the org stores them.

use crate::error::{MetadataError, MetadataResult, SoapFault};
use quick_xml::Reader;
use quick_xml::escape::unescape;
use quick_xml::events::{BytesRef, BytesText, Event};
use std::ops::Range;

/// SOAP 1.1 envelope namespace.
const SOAP_NS: &str = "http://schemas.xmlsoap.org/soap/envelope/";
/// Salesforce Metadata API namespace.
const METADATA_NS: &str = "http://soap.sforce.com/2006/04/metadata";
/// XML Schema Instance namespace. Needed by CRUD ops that use
/// `xsi:type` to discriminate concrete Metadata subtypes
/// (`CustomObject`, `ApexClass`, etc.); declared on every envelope so
/// individual handlers don't have to repeat the declaration.
const XSI_NS: &str = "http://www.w3.org/2001/XMLSchema-instance";

/// A parsed SOAP response: the body outcome plus the output headers
/// carried in `<Header>`.
#[derive(Debug)]
pub(crate) struct ParsedEnvelope {
    pub(crate) headers: ResponseHeaders,
    pub(crate) body: EnvelopeBody,
}

/// Output headers of a response, as locations in the response text
/// awaiting deserialization.
#[derive(Debug, Default)]
pub(crate) struct ResponseHeaders {
    /// Byte range of the full `<DebuggingInfo>...</DebuggingInfo>`
    /// element.
    pub(crate) debugging_info: Option<Range<usize>>,
}

/// Outcome of parsing a SOAP response envelope body.
#[derive(Debug)]
pub(crate) enum EnvelopeBody {
    /// Operation succeeded. The range, into the text that was parsed, is
    /// the full `<{Operation}Response>...</{Operation}Response>` element
    /// — the caller deserializes that slice into the typed response. The
    /// outer element is included so response structs can be named to
    /// match the wire element and so multi-`<result>` responses work
    /// without a synthetic root.
    Success(Range<usize>),
    /// Server returned `<soapenv:Fault>`.
    Fault(SoapFault),
}

/// Ceiling on element nesting inside a response body.
///
/// The located element is handed to `quick-xml`'s serde deserializer,
/// whose recursion tracks the document's nesting one stack frame per
/// level. `describeValueType` returns the self-referential
/// `ValueTypeField`, so an endpoint that can shape the response body
/// would otherwise turn nesting depth into an unrecoverable stack
/// overflow. No documented Metadata API response nests anywhere near
/// this deep.
const MAX_RESPONSE_DEPTH: i32 = 256;

/// Extra capacity reserved for the constant envelope wrapper — the two
/// tag pairs plus the three namespace declarations. Comfortably above
/// the actual wrapper length, so building an envelope never reallocates
/// past the initial allocation.
const ENVELOPE_WRAPPER_HEADROOM: usize = 512;

/// Build a complete SOAP envelope.
///
/// `session_token` is the bearer token from the [`AuthSession`]; it goes
/// into `<met:SessionHeader><met:sessionId>`. `operation_name` becomes the
/// body element (e.g. `"deploy"` → `<met:deploy>...</met:deploy>`).
/// `headers_xml` is spliced into `<soapenv:Header>` right after the
/// `SessionHeader`; empty yields the session-header-only envelope.
/// `body_xml` is the already-rendered inner body content — it may
/// reference the `met:` prefix or declare its own namespaces.
///
/// [`AuthSession`]: cirrus_auth::AuthSession
pub(crate) fn build_envelope(
    session_token: &str,
    operation_name: &str,
    headers_xml: &str,
    body_xml: &str,
) -> String {
    // XML-escape the token. Salesforce tokens are alphanumeric + `!.`,
    // but escaping is cheap insurance against future format changes.
    let token = xml_escape(session_token);
    // A deploy body carries the base64 zip — tens of megabytes at the
    // documented maximum. Sizing the buffer for the whole envelope up
    // front keeps that payload out of a doubling-realloc schedule whose
    // final growth step would otherwise overshoot to twice the
    // envelope's size.
    let capacity = body_xml.len()
        + headers_xml.len()
        + token.len()
        + SOAP_NS.len()
        + METADATA_NS.len()
        + XSI_NS.len()
        + 2 * operation_name.len()
        + ENVELOPE_WRAPPER_HEADROOM;
    let mut out = String::with_capacity(capacity);
    out.push_str(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
    out.push_str(r#"<soapenv:Envelope xmlns:soapenv=""#);
    out.push_str(SOAP_NS);
    out.push_str(r#"" xmlns:met=""#);
    out.push_str(METADATA_NS);
    out.push_str(r#"" xmlns:xsi=""#);
    out.push_str(XSI_NS);
    out.push_str(r#""><soapenv:Header><met:SessionHeader><met:sessionId>"#);
    out.push_str(&token);
    out.push_str("</met:sessionId></met:SessionHeader>");
    out.push_str(headers_xml);
    out.push_str("</soapenv:Header><soapenv:Body><met:");
    out.push_str(operation_name);
    out.push('>');
    out.push_str(body_xml);
    out.push_str("</met:");
    out.push_str(operation_name);
    out.push_str("></soapenv:Body></soapenv:Envelope>");
    out
}

/// Parse a SOAP 1.1 response envelope.
///
/// Walks the input with a pull parser, locating the output headers of
/// a `<Header>` that precedes the body, then looking for a `<Body>`
/// child that is either `<Fault>` or an element whose local name equals
/// `expected_response_local_name` (typically `"{Operation}Response"`).
/// Namespace prefixes are not consulted — we match on local names only
/// so the parser is robust against `S:` / `soap:` / `soapenv:` variants
/// that different SOAP servers emit. The ranges in the result index
/// into `xml`.
pub(crate) fn parse_envelope(
    xml: &str,
    expected_response_local_name: &str,
) -> MetadataResult<ParsedEnvelope> {
    // `Reader::from_str` is the slice-backed (allocation-free) variant —
    // its `read_event()` returns events that borrow from the input.
    // The generic `Reader<R: BufRead>` only exposes `read_event_into(&mut buf)`,
    // which would force every helper to thread a buffer.
    //
    // Text is deliberately left untrimmed. Element ranges are located by
    // reader offsets, and character data — whitespace between tags
    // included — arrives as its own event, so the offset before the event
    // that opens an element is that element's `<`.
    let mut reader = Reader::from_str(xml);

    let mut headers = ResponseHeaders::default();

    // Walk until we enter <Body>.
    loop {
        match reader.read_event()? {
            Event::Start(e) if e.name().local_name().as_ref() == b"Header" => {
                headers = parse_header(&mut reader)?;
            }
            Event::Start(e) if e.name().local_name().as_ref() == b"Body" => {
                let body = parse_body(&mut reader, expected_response_local_name)?;
                return Ok(ParsedEnvelope { headers, body });
            }
            Event::Eof => {
                return Err(MetadataError::InvalidResponse(
                    "SOAP envelope missing <Body>".into(),
                ));
            }
            _ => {}
        }
    }
}

/// Offset of the first byte the reader has not yet consumed: the start
/// of the next event, or just past the `>` of the event returned last.
fn position(reader: &Reader<&[u8]>) -> MetadataResult<usize> {
    usize::try_from(reader.buffer_position()).map_err(|_| {
        MetadataError::InvalidResponse("response offset exceeds the addressable range".into())
    })
}

/// Parse a `<Header>` element. Locates a direct `<DebuggingInfo>` child
/// (matched on local name, like [`parse_body`]) and skips every other
/// child, nesting-capped at [`MAX_RESPONSE_DEPTH`]. Returns at the
/// closing `</Header>`.
fn parse_header(reader: &mut Reader<&[u8]>) -> MetadataResult<ResponseHeaders> {
    let mut headers = ResponseHeaders::default();
    // Depth below <Header> while skipping a child; 0 between children.
    let mut skipped_depth: i32 = 0;
    loop {
        let event_start = position(reader)?;
        match reader.read_event()? {
            Event::Start(e) => {
                if skipped_depth == 0 && e.name().local_name().as_ref() == b"DebuggingInfo" {
                    skip_element(reader)?;
                    headers.debugging_info = Some(event_start..position(reader)?);
                } else {
                    skipped_depth += 1;
                    if skipped_depth > MAX_RESPONSE_DEPTH {
                        return Err(MetadataError::InvalidResponse(format!(
                            "response nesting exceeds {MAX_RESPONSE_DEPTH} levels"
                        )));
                    }
                }
            }
            Event::End(_) => {
                if skipped_depth == 0 {
                    return Ok(headers);
                }
                skipped_depth -= 1;
            }
            Event::Eof => {
                return Err(MetadataError::InvalidResponse(
                    "truncated <Header>: EOF before closing tag".into(),
                ));
            }
            _ => {}
        }
    }
}

fn parse_body(
    reader: &mut Reader<&[u8]>,
    expected_response_local_name: &str,
) -> MetadataResult<EnvelopeBody> {
    loop {
        let event_start = position(reader)?;
        match reader.read_event()? {
            Event::Start(e) => {
                let local = e.name().local_name();
                if local.as_ref() == b"Fault" {
                    return parse_fault(reader).map(EnvelopeBody::Fault);
                }
                if local.as_ref() == expected_response_local_name.as_bytes() {
                    skip_element(reader)?;
                    return Ok(EnvelopeBody::Success(event_start..position(reader)?));
                }
                return Err(MetadataError::InvalidResponse(format!(
                    "unexpected <Body> child <{}>: expected <{}> or <Fault>",
                    String::from_utf8_lossy(local.as_ref()),
                    expected_response_local_name,
                )));
            }
            // Self-closing tag. A self-closing `<{Op}Response/>` is a
            // valid empty response (e.g. `listMetadata` with no
            // matches); surface it as an empty success element so the
            // caller's typed Vec/Option fields default cleanly. Any
            // other empty element is an unexpected child.
            Event::Empty(e) => {
                let local = e.name().local_name();
                if local.as_ref() == expected_response_local_name.as_bytes() {
                    return Ok(EnvelopeBody::Success(event_start..position(reader)?));
                }
                return Err(MetadataError::InvalidResponse(format!(
                    "unexpected empty <Body> child <{}/>: expected <{}> or <Fault>",
                    String::from_utf8_lossy(local.as_ref()),
                    expected_response_local_name,
                )));
            }
            Event::Eof => {
                return Err(MetadataError::InvalidResponse("empty SOAP <Body>".into()));
            }
            _ => {}
        }
    }
}

/// Advance the reader past the end tag of the element whose start tag it
/// has just returned, so the caller can read the element's extent off
/// the reader's offsets.
///
/// Nesting is capped at [`MAX_RESPONSE_DEPTH`] so a pathologically deep
/// body is rejected here rather than driving unbounded recursion in the
/// serde deserializer that later consumes the element.
fn skip_element(reader: &mut Reader<&[u8]>) -> MetadataResult<()> {
    let mut depth: i32 = 1;
    loop {
        match reader.read_event()? {
            Event::Start(_) => {
                depth += 1;
                if depth > MAX_RESPONSE_DEPTH {
                    return Err(MetadataError::InvalidResponse(format!(
                        "response nesting exceeds {MAX_RESPONSE_DEPTH} levels"
                    )));
                }
            }
            Event::End(_) => {
                depth -= 1;
                if depth == 0 {
                    return Ok(());
                }
            }
            Event::Eof => {
                return Err(MetadataError::InvalidResponse(
                    "unexpected EOF inside response element".into(),
                ));
            }
            // Text, entity references, CDATA, comments, empty elements:
            // they are part of the extent and need no handling. A
            // declaration, PI or doctype shouldn't appear inside a SOAP
            // body; ignore defensively rather than failing.
            _ => {}
        }
    }
}

/// Parse a `<Fault>` element. Extracts `<faultcode>` and `<faultstring>`
/// text content as direct children; everything else (`<detail>`,
/// `<faultactor>`) is skipped.
fn parse_fault(reader: &mut Reader<&[u8]>) -> MetadataResult<SoapFault> {
    let mut faultcode = String::new();
    let mut faultstring = String::new();
    // Which direct-child field we're currently collecting text into.
    // Set when entering a tracked child, cleared on its closing tag.
    #[derive(Clone, Copy)]
    enum Field {
        Code,
        String_,
    }
    let mut field: Option<Field> = None;
    // Depth relative to <Fault>: <Fault> itself is depth 1, direct
    // children are depth 2, grandchildren depth 3+. We only collect
    // text at depth 2 — `<detail>`'s nested structure is ignored.
    let mut depth: i32 = 1;
    let mut tracked_child_depth: i32 = 0;

    loop {
        match reader.read_event()? {
            Event::Start(e) => {
                depth += 1;
                if depth == 2 {
                    field = match e.name().local_name().as_ref() {
                        b"faultcode" => Some(Field::Code),
                        b"faultstring" => Some(Field::String_),
                        _ => None,
                    };
                    if field.is_some() {
                        tracked_child_depth = depth;
                    }
                }
            }
            Event::Text(t) => {
                if depth == tracked_child_depth
                    && let Some(f) = field
                {
                    let s = unescape_text(&t)?;
                    match f {
                        Field::Code => faultcode.push_str(&s),
                        Field::String_ => faultstring.push_str(&s),
                    }
                }
            }
            // Salesforce wraps faultstring in CDATA when the message
            // contains XML metacharacters (`<`, `>`, `&`). CDATA bytes
            // are already raw — no entity unescape needed.
            Event::CData(c) => {
                if depth == tracked_child_depth
                    && let Some(f) = field
                {
                    let bytes = c.into_inner();
                    let s = std::str::from_utf8(&bytes).map_err(|e| {
                        MetadataError::InvalidResponse(format!(
                            "<Fault> CDATA contained invalid UTF-8: {e}"
                        ))
                    })?;
                    match f {
                        Field::Code => faultcode.push_str(s),
                        Field::String_ => faultstring.push_str(s),
                    }
                }
            }
            // Entity/character references inside faultcode/faultstring
            // arrive as their own events; resolve and append them like
            // the `Text` they interrupt.
            Event::GeneralRef(r) => {
                if depth == tracked_child_depth
                    && let Some(f) = field
                {
                    let s = resolve_ref(&r)?;
                    match f {
                        Field::Code => faultcode.push_str(&s),
                        Field::String_ => faultstring.push_str(&s),
                    }
                }
            }
            Event::End(_) => {
                if depth == tracked_child_depth {
                    field = None;
                    tracked_child_depth = 0;
                }
                depth -= 1;
                if depth == 0 {
                    // The reader preserves text verbatim, so a
                    // pretty-printed fault indents its field content.
                    // `SoapFault::code()` compares the local part
                    // exactly, so the surrounding layout must not
                    // become part of the value.
                    return Ok(SoapFault {
                        faultcode: faultcode.trim().to_string(),
                        faultstring: faultstring.trim().to_string(),
                    });
                }
            }
            Event::Eof => {
                return Err(MetadataError::InvalidResponse(
                    "truncated <Fault>: EOF before closing tag".into(),
                ));
            }
            _ => {}
        }
    }
}

fn unescape_text(t: &BytesText<'_>) -> MetadataResult<String> {
    // The reader yields Text events still entity-escaped: `decode`
    // only handles the byte encoding, `unescape` resolves entities.
    let decoded = t.decode().map_err(quick_xml::Error::from)?;
    Ok(unescape(&decoded)
        .map_err(quick_xml::Error::from)?
        .into_owned())
}

/// Resolve a `GeneralRef` event (`&lt;`, `&#x30;`, …) to its textual
/// value. The event carries only the name between `&` and `;`, so
/// re-wrap it and let `unescape` handle both predefined entities and
/// numeric character references.
fn resolve_ref(r: &BytesRef<'_>) -> MetadataResult<String> {
    let name = r.decode().map_err(quick_xml::Error::from)?;
    Ok(unescape(&format!("&{name};"))
        .map_err(quick_xml::Error::from)?
        .into_owned())
}

/// Escapes the five XML entities (`<`, `>`, `&`, `'`, `"`) so `s` can be
/// spliced into element text or an attribute value.
///
/// Implementors of [`SoapOperation`](crate::SoapOperation) use it when
/// rendering body or header XML by hand. Returns a borrow when `s` needs
/// no escaping.
// Production tokens and most metadata names never contain these
// characters, so we scan first and borrow — saves one allocation per
// token / fullName / type name on the SOAP envelope hot path.
pub fn xml_escape(s: &str) -> std::borrow::Cow<'_, str> {
    // Fast path: byte scan. All five escapable chars are single-byte
    // ASCII, so checking the byte stream is correct for UTF-8 input
    // (multibyte UTF-8 bytes all have the high bit set; we never
    // false-positive on them).
    if !s
        .bytes()
        .any(|b| matches!(b, b'<' | b'>' | b'&' | b'\'' | b'"'))
    {
        return std::borrow::Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '\'' => out.push_str("&apos;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
    std::borrow::Cow::Owned(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// The slice of `xml` that `parse_envelope` locates as the success
    /// element.
    fn success_element<'a>(xml: &'a str, expected: &str) -> &'a str {
        match parse_envelope(xml, expected).unwrap().body {
            EnvelopeBody::Success(range) => &xml[range],
            other => panic!("expected Success, got {other:?}"),
        }
    }

    #[test]
    fn build_envelope_round_trip_shape() {
        let env = build_envelope("TOKEN", "ping", "", "<inner/>");
        assert!(env.contains("xmlns:soapenv="));
        assert!(env.contains("xmlns:met="));
        assert!(env.contains("xmlns:xsi="));
        assert!(env.contains("<met:sessionId>TOKEN</met:sessionId>"));
        assert!(env.contains("<met:ping><inner/></met:ping>"));
    }

    #[test]
    fn build_envelope_escapes_token() {
        // Defensive — real tokens never have these chars, but make
        // sure the escape is wired.
        let env = build_envelope("a<b&c", "ping", "", "");
        assert!(env.contains("a&lt;b&amp;c"));
        assert!(!env.contains("a<b&c</"));
    }

    #[test]
    fn build_envelope_with_no_headers_keeps_the_session_header_only_shape() {
        let env = build_envelope("TOKEN", "ping", "", "<inner/>");
        assert_eq!(
            env,
            concat!(
                r#"<?xml version="1.0" encoding="UTF-8"?>"#,
                r#"<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" "#,
                r#"xmlns:met="http://soap.sforce.com/2006/04/metadata" "#,
                r#"xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">"#,
                "<soapenv:Header><met:SessionHeader><met:sessionId>TOKEN</met:sessionId>",
                "</met:SessionHeader></soapenv:Header>",
                "<soapenv:Body><met:ping><inner/></met:ping></soapenv:Body></soapenv:Envelope>",
            )
        );
    }

    #[test]
    fn build_envelope_places_extra_headers_after_the_session_header() {
        let env = build_envelope(
            "TOKEN",
            "ping",
            "<met:CallOptions><met:client>c</met:client></met:CallOptions>",
            "<inner/>",
        );
        assert!(env.contains(
            "</met:SessionHeader><met:CallOptions><met:client>c</met:client></met:CallOptions>\
             </soapenv:Header><soapenv:Body>"
        ));
    }

    #[test]
    fn build_envelope_sizes_the_buffer_for_the_headers() {
        let headers = "<met:H>".repeat(2048);
        let env = build_envelope("TOKEN", "ping", &headers, "<inner/>");
        assert!(env.len() > headers.len());
        assert!(env.capacity() >= env.len());
    }

    #[test]
    fn parse_envelope_returns_the_debugging_info_header() {
        // Wire-shape provenance: the WSDL (API 66.0 Metadata WSDL) binds
        // `DebuggingInfo{debugLog}` as an output header of
        // checkDeployStatus; children carry the default metadata
        // namespace like body content does.
        let xml = r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns="http://soap.sforce.com/2006/04/metadata">
  <soapenv:Header>
    <DebuggingInfo><debugLog>47.0 APEX_CODE,FINE
Execute Anonymous: a &amp; b</debugLog></DebuggingInfo>
  </soapenv:Header>
  <soapenv:Body>
    <pingResponse><result><msg>ok</msg></result></pingResponse>
  </soapenv:Body>
</soapenv:Envelope>"#;
        let parsed = parse_envelope(xml, "pingResponse").unwrap();
        let info = &xml[parsed.headers.debugging_info.unwrap()];
        assert!(info.starts_with("<DebuggingInfo>"), "{info}");
        assert!(info.ends_with("</DebuggingInfo>"), "{info}");
        assert!(
            info.contains("<debugLog>47.0 APEX_CODE,FINE\nExecute Anonymous: a &amp; b</debugLog>")
        );
        assert!(matches!(parsed.body, EnvelopeBody::Success(_)));
    }

    #[test]
    fn parse_envelope_skips_unknown_header_children() {
        let xml = r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header>
    <LimitInfoHeader><limitInfo><type>API REQUESTS</type><current>1</current></limitInfo></LimitInfoHeader>
    <DebuggingInfo><debugLog>log</debugLog></DebuggingInfo>
    <Other/>
  </soapenv:Header>
  <soapenv:Body><pingResponse/></soapenv:Body>
</soapenv:Envelope>"#;
        let parsed = parse_envelope(xml, "pingResponse").unwrap();
        assert_eq!(
            parsed.headers.debugging_info.map(|range| &xml[range]),
            Some("<DebuggingInfo><debugLog>log</debugLog></DebuggingInfo>")
        );
    }

    #[test]
    fn parse_envelope_accepts_a_prefixed_debugging_info() {
        let xml = r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:met="http://soap.sforce.com/2006/04/metadata">
  <soapenv:Header><met:DebuggingInfo><met:debugLog>log</met:debugLog></met:DebuggingInfo></soapenv:Header>
  <soapenv:Body><pingResponse/></soapenv:Body>
</soapenv:Envelope>"#;
        let parsed = parse_envelope(xml, "pingResponse").unwrap();
        let info = &xml[parsed.headers.debugging_info.unwrap()];
        assert_eq!(
            info,
            "<met:DebuggingInfo><met:debugLog>log</met:debugLog></met:DebuggingInfo>"
        );
    }

    #[test]
    fn parse_envelope_without_a_header_has_no_debugging_info() {
        let xml = r#"<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body><pingResponse/></soapenv:Body>
</soapenv:Envelope>"#;
        let parsed = parse_envelope(xml, "pingResponse").unwrap();
        assert!(parsed.headers.debugging_info.is_none());
    }

    #[test]
    fn parse_envelope_reads_headers_of_a_fault_response() {
        let xml = r#"<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header><DebuggingInfo><debugLog>log</debugLog></DebuggingInfo></soapenv:Header>
  <soapenv:Body><soapenv:Fault><faultcode>sf:X</faultcode><faultstring>x</faultstring></soapenv:Fault></soapenv:Body>
</soapenv:Envelope>"#;
        let parsed = parse_envelope(xml, "pingResponse").unwrap();
        assert!(matches!(parsed.body, EnvelopeBody::Fault(_)));
        assert!(parsed.headers.debugging_info.is_some());
    }

    #[test]
    fn parse_envelope_rejects_a_truncated_header() {
        let xml = r#"<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header><Other><a>"#;
        let err = parse_envelope(xml, "pingResponse").unwrap_err();
        assert!(matches!(err, MetadataError::InvalidResponse(_)));
    }

    #[test]
    fn parse_envelope_rejects_excessive_nesting_in_a_skipped_header_child() {
        let depth = (MAX_RESPONSE_DEPTH as usize) + 8;
        let mut xml =
            String::from(r#"<E xmlns="http://schemas.xmlsoap.org/soap/envelope/"><Header><Other>"#);
        for _ in 0..depth {
            xml.push_str("<a>");
        }
        for _ in 0..depth {
            xml.push_str("</a>");
        }
        xml.push_str("</Other></Header><Body><pingResponse/></Body></E>");
        let err = parse_envelope(&xml, "pingResponse").unwrap_err();
        assert!(matches!(err, MetadataError::InvalidResponse(_)));
        assert!(err.to_string().contains("nesting"));
    }

    #[test]
    fn parse_envelope_returns_success_with_wrapper() {
        let xml = r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns="http://soap.sforce.com/2006/04/metadata">
  <soapenv:Body>
    <pingResponse>
      <result><msg>ok</msg></result>
    </pingResponse>
  </soapenv:Body>
</soapenv:Envelope>"#;
        let s = success_element(xml, "pingResponse");
        // The outer wrapper is preserved so callers can deserialize a
        // struct named like the wire element.
        assert_eq!(
            s,
            "<pingResponse>\n      <result><msg>ok</msg></result>\n    </pingResponse>"
        );
    }

    #[test]
    fn parse_envelope_returns_fault() {
        let xml = r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <soapenv:Fault>
      <faultcode>sf:INVALID_SESSION_ID</faultcode>
      <faultstring>INVALID_SESSION_ID: Session expired or invalid</faultstring>
    </soapenv:Fault>
  </soapenv:Body>
</soapenv:Envelope>"#;
        let body = parse_envelope(xml, "pingResponse").unwrap().body;
        let EnvelopeBody::Fault(f) = body else {
            panic!("expected Fault, got {body:?}");
        };
        assert_eq!(f.faultcode, "sf:INVALID_SESSION_ID");
        assert_eq!(f.code(), "INVALID_SESSION_ID");
        assert!(f.faultstring.contains("Session expired"));
        assert!(f.is_invalid_session());
    }

    #[test]
    fn parse_envelope_ignores_fault_detail_structure() {
        // <detail> contains nested elements; we should still parse
        // faultcode + faultstring correctly.
        let xml = r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <soapenv:Fault>
      <faultcode>sf:INVALID_TYPE</faultcode>
      <faultstring>no such metadata type</faultstring>
      <detail>
        <sf:fault xmlns:sf="urn:fault.metadata.soap.sforce.com">
          <sf:exceptionCode>INVALID_TYPE</sf:exceptionCode>
          <sf:exceptionMessage>...</sf:exceptionMessage>
        </sf:fault>
      </detail>
    </soapenv:Fault>
  </soapenv:Body>
</soapenv:Envelope>"#;
        let body = parse_envelope(xml, "anything").unwrap().body;
        let EnvelopeBody::Fault(f) = body else {
            panic!("expected Fault");
        };
        assert_eq!(f.code(), "INVALID_TYPE");
        assert_eq!(f.faultstring, "no such metadata type");
    }

    #[test]
    fn parse_envelope_extracts_cdata_faultstring() {
        // Salesforce wraps faultstring in CDATA when the message
        // contains `<`, `>`, or `&`. parse_fault must extract text
        // from both `Event::Text` and `Event::CData` so
        // is_invalid_session() works on real-org fault responses.
        let xml = r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <soapenv:Fault>
      <faultcode>sf:INVALID_SESSION_ID</faultcode>
      <faultstring><![CDATA[INVALID_SESSION_ID: Session expired or invalid <token>]]></faultstring>
    </soapenv:Fault>
  </soapenv:Body>
</soapenv:Envelope>"#;
        let body = parse_envelope(xml, "anything").unwrap().body;
        let EnvelopeBody::Fault(f) = body else {
            panic!("expected Fault, got {body:?}");
        };
        assert_eq!(f.code(), "INVALID_SESSION_ID");
        assert!(f.faultstring.contains("Session expired"));
        assert!(f.faultstring.contains("<token>"));
        assert!(f.is_invalid_session());
    }

    #[test]
    fn parse_envelope_errors_on_unexpected_body_child() {
        let xml = r#"<?xml version="1.0"?>
<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/">
  <Body><surpriseResponse/></Body>
</Envelope>"#;
        let err = parse_envelope(xml, "pingResponse").unwrap_err();
        assert!(matches!(err, MetadataError::InvalidResponse(_)));
        assert!(err.to_string().contains("surpriseResponse"));
    }

    #[test]
    fn parse_envelope_rejects_truncated_fault() {
        // EOF inside <Fault> must surface as InvalidResponse rather
        // than an Ok with an empty SoapFault — downstream pattern
        // matches depend on truncation being distinguishable from a
        // genuine empty fault.
        let xml = r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <soapenv:Fault>
      <faultcode>sf:INVALID_SESSION_ID</faultcode>
"#;
        let err = parse_envelope(xml, "ignored").unwrap_err();
        assert!(matches!(err, MetadataError::InvalidResponse(_)));
        assert!(err.to_string().contains("truncated"));
    }

    #[test]
    fn parse_envelope_preserves_nested_response_content() {
        // Make sure nested success-body content is located whole.
        let xml = r#"<?xml version="1.0"?>
<E xmlns="http://schemas.xmlsoap.org/soap/envelope/">
  <Body>
    <listMetadataResponse>
      <result><type>ApexClass</type><fullName>Foo</fullName></result>
      <result><type>ApexClass</type><fullName>Bar</fullName></result>
    </listMetadataResponse>
  </Body>
</E>"#;
        let s = success_element(xml, "listMetadataResponse");
        assert!(s.starts_with("<listMetadataResponse>"));
        assert!(s.ends_with("</listMetadataResponse>"));
        assert_eq!(s.matches("<result>").count(), 2);
        assert!(s.contains("<fullName>Foo</fullName>"));
        assert!(s.contains("<fullName>Bar</fullName>"));
    }

    #[test]
    fn parse_envelope_preserves_whitespace_around_entities() {
        // quick-xml reports an entity reference as its own event, which
        // splits the surrounding character data in two. The located
        // element must carry both halves — spaces included — so a
        // CustomLabel whose value is `Tom & Jerry` doesn't reach the
        // caller as `Tom&Jerry`.
        let xml = r#"<?xml version="1.0"?>
<E xmlns="http://schemas.xmlsoap.org/soap/envelope/">
  <Body>
    <readMetadataResponse>
      <result><value>Tom &amp; Jerry</value><pad>  padded  </pad></result>
    </readMetadataResponse>
  </Body>
</E>"#;
        let s = success_element(xml, "readMetadataResponse");
        assert!(
            s.contains("<value>Tom &amp; Jerry</value>"),
            "entity-adjacent whitespace was dropped: {s}"
        );
        assert!(
            s.contains("<pad>  padded  </pad>"),
            "leading/trailing whitespace was dropped: {s}"
        );
    }

    #[test]
    fn parse_fault_trims_layout_whitespace_from_fields() {
        // Pretty-printed faults indent their field content. The
        // surrounding layout must not become part of the value, or
        // `code()` stops matching `INVALID_SESSION_ID`.
        let xml = r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <soapenv:Fault>
      <faultcode>
        sf:INVALID_SESSION_ID
      </faultcode>
      <faultstring>
        INVALID_SESSION_ID: Session expired or invalid
      </faultstring>
    </soapenv:Fault>
  </soapenv:Body>
</soapenv:Envelope>"#;
        let body = parse_envelope(xml, "anything").unwrap().body;
        let EnvelopeBody::Fault(f) = body else {
            panic!("expected Fault, got {body:?}");
        };
        assert_eq!(f.faultcode, "sf:INVALID_SESSION_ID");
        assert_eq!(f.code(), "INVALID_SESSION_ID");
        assert_eq!(
            f.faultstring,
            "INVALID_SESSION_ID: Session expired or invalid"
        );
        assert!(f.is_invalid_session());
    }

    #[test]
    fn parse_envelope_rejects_excessive_nesting() {
        // `describeValueType` returns a self-referential ValueTypeField,
        // so nesting depth would otherwise map onto deserializer stack
        // frames. Rejecting here bounds every operation at once.
        let depth = (MAX_RESPONSE_DEPTH as usize) + 8;
        let mut xml = String::from(
            r#"<E xmlns="http://schemas.xmlsoap.org/soap/envelope/"><Body><describeValueTypeResponse>"#,
        );
        for _ in 0..depth {
            xml.push_str("<fields>");
        }
        for _ in 0..depth {
            xml.push_str("</fields>");
        }
        xml.push_str("</describeValueTypeResponse></Body></E>");

        let err = parse_envelope(&xml, "describeValueTypeResponse").unwrap_err();
        assert!(matches!(err, MetadataError::InvalidResponse(_)));
        assert!(err.to_string().contains("nesting"));
    }

    #[test]
    fn parse_envelope_accepts_nesting_below_the_ceiling() {
        let depth = (MAX_RESPONSE_DEPTH as usize) - 8;
        let mut xml = String::from(
            r#"<E xmlns="http://schemas.xmlsoap.org/soap/envelope/"><Body><describeValueTypeResponse>"#,
        );
        for _ in 0..depth {
            xml.push_str("<fields>");
        }
        for _ in 0..depth {
            xml.push_str("</fields>");
        }
        xml.push_str("</describeValueTypeResponse></Body></E>");

        let body = parse_envelope(&xml, "describeValueTypeResponse")
            .unwrap()
            .body;
        assert!(matches!(body, EnvelopeBody::Success(_)));
    }

    #[test]
    fn parse_envelope_locates_an_empty_response_element() {
        let xml = r#"<E xmlns="http://schemas.xmlsoap.org/soap/envelope/"><Body>
  <listMetadataResponse xmlns="http://soap.sforce.com/2006/04/metadata"/>
</Body></E>"#;
        assert_eq!(
            success_element(xml, "listMetadataResponse"),
            r#"<listMetadataResponse xmlns="http://soap.sforce.com/2006/04/metadata"/>"#
        );
    }

    #[test]
    fn parse_envelope_locates_a_prefixed_element_with_its_declarations() {
        let xml = r#"<S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/"><S:Body><ns1:pingResponse xmlns:ns1="http://soap.sforce.com/2006/04/metadata"><ns1:result><!-- c --><ns1:msg><![CDATA[a < b]]></ns1:msg></ns1:result></ns1:pingResponse></S:Body></S:Envelope>"#;
        assert_eq!(
            success_element(xml, "pingResponse"),
            r#"<ns1:pingResponse xmlns:ns1="http://soap.sforce.com/2006/04/metadata"><ns1:result><!-- c --><ns1:msg><![CDATA[a < b]]></ns1:msg></ns1:result></ns1:pingResponse>"#
        );
    }

    #[test]
    fn parse_envelope_ranges_land_on_char_boundaries_after_multibyte_text() {
        // Offsets are bytes: everything before the element is several
        // bytes per character, so a character count would slice mid-code
        // point.
        let xml = r#"<E xmlns="http://schemas.xmlsoap.org/soap/envelope/"><Header><DebuggingInfo><debugLog>ééé</debugLog></DebuggingInfo></Header>
<!-- ünïcödé -->
<Body><pingResponse><result><msg>日本語</msg></result></pingResponse></Body></E>"#;
        let parsed = parse_envelope(xml, "pingResponse").unwrap();
        assert_eq!(
            &xml[parsed.headers.debugging_info.unwrap()],
            "<DebuggingInfo><debugLog>ééé</debugLog></DebuggingInfo>"
        );
        let EnvelopeBody::Success(range) = parsed.body else {
            panic!("expected Success");
        };
        assert_eq!(
            &xml[range],
            "<pingResponse><result><msg>日本語</msg></result></pingResponse>"
        );
    }

    #[test]
    fn parse_envelope_range_spans_a_large_element_exactly() {
        // A response element can hold tens of megabytes of base64, so the
        // range has to cover the element and nothing around it.
        let payload = "A".repeat(1 << 20);
        let xml = format!(
            r#"<E xmlns="http://schemas.xmlsoap.org/soap/envelope/"><Body><checkRetrieveStatusResponse><result><zipFile>{payload}</zipFile></result></checkRetrieveStatusResponse></Body></E>"#
        );
        let EnvelopeBody::Success(range) = parse_envelope(&xml, "checkRetrieveStatusResponse")
            .unwrap()
            .body
        else {
            panic!("expected Success");
        };
        assert_eq!(
            range.start,
            xml.find("<checkRetrieveStatusResponse>").unwrap()
        );
        assert_eq!(
            range.end,
            xml.find("</Body>").unwrap(),
            "the range ends just past the closing tag"
        );
        assert!(range.len() > payload.len());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    /// Strategy for XML-legal text content: avoids the control
    /// characters that XML 1.0 forbids in CharData (everything below
    /// U+0020 except TAB/LF/CR) and avoids the surrogate range so the
    /// generator stays UTF-8 valid. Includes the five entity chars,
    /// runs of ASCII, multi-byte Unicode, and the empty string.
    fn xml_text() -> impl Strategy<Value = String> {
        proptest::collection::vec(
            prop_oneof![
                Just('<'),
                Just('>'),
                Just('&'),
                Just('\''),
                Just('"'),
                Just(' '),
                Just('\t'),
                Just('\n'),
                Just('\r'),
                // Printable ASCII excluding the entity chars above.
                "[!#$%()*+,\\-./0-9:;=?@A-Z\\[\\]^_`a-z{|}~]"
                    .prop_map(|s| s.chars().next().unwrap_or('a')),
                // Latin-1 supplement / Latin Extended (the most common
                // non-ASCII Salesforce metadata names: accented org names).
                "[\\u{00A0}-\\u{024F}]".prop_map(|s| s.chars().next().unwrap_or('a')),
                // Small slice of higher-plane Unicode (BMP, no surrogates).
                "[\\u{0370}-\\u{D7FF}]".prop_map(|s| s.chars().next().unwrap_or('a')),
            ],
            0..32,
        )
        .prop_map(|chars| chars.into_iter().collect())
    }

    proptest! {
        /// For any XML-legal UTF-8 string `s`, embedding `xml_escape(s)`
        /// inside an XML element and parsing it back recovers `s` byte
        /// for byte. Guards the escape/unescape pairing against
        /// asymmetries that would corrupt round-tripped content.
        #[test]
        fn xml_escape_round_trips_through_quick_xml(s in xml_text()) {
            let escaped = xml_escape(&s);
            let doc = format!("<x>{escaped}</x>");
            let mut reader = quick_xml::Reader::from_str(&doc);
            let mut got = String::new();
            loop {
                match reader.read_event() {
                    Ok(quick_xml::events::Event::Text(t)) => {
                        got.push_str(&unescape(&t.decode().unwrap()).unwrap());
                    }
                    Ok(quick_xml::events::Event::GeneralRef(r)) => {
                        got.push_str(&resolve_ref(&r).unwrap());
                    }
                    Ok(quick_xml::events::Event::Eof) => break,
                    Ok(_) => {}
                    Err(e) => prop_assert!(false, "parser rejected escaped doc: {e} (input={s:?}, escaped={escaped:?})"),
                }
            }
            prop_assert_eq!(&got, &s);
        }

        /// `xml_escape` is idempotent against XML-safe input: applying
        /// it to a string with no metacharacters returns a borrow of
        /// the same bytes. The fast-path scan in `xml_escape` exists
        /// specifically to avoid the allocation on this common case.
        #[test]
        fn xml_escape_is_borrow_when_no_metachars(s in "[A-Za-z0-9_./:-]{0,32}") {
            // Strategy excludes all five entity chars, so the input is
            // XML-safe by construction.
            let escaped = xml_escape(&s);
            prop_assert!(
                matches!(escaped, std::borrow::Cow::Borrowed(_)),
                "expected Borrowed for metachar-free input {s:?}",
            );
            prop_assert_eq!(escaped.as_ref(), s.as_str());
        }
    }

    /// XML generator for the inner contents of a `<Fault>` element.
    /// Builds random combinations of text, CDATA, nested elements,
    /// and the two real fields (faultcode, faultstring). The point
    /// is to verify `parse_fault` doesn't panic on shapes the unit
    /// tests didn't enumerate.
    fn fault_body() -> impl Strategy<Value = String> {
        // We use the actual entity-safe content here — the parser's
        // job is to read what real Salesforce emits, which is always
        // well-formed XML.
        let safe_text = "[A-Za-z0-9 ._:-]{0,32}";
        let element_name = "[a-z][a-z0-9_]{0,8}";

        // Build a vec of "child fragments" then assemble.
        let fragment = prop_oneof![
            // <faultcode>...</faultcode>
            safe_text.prop_map(|t| format!("<faultcode>{t}</faultcode>")),
            // <faultstring> with text or CDATA — the case the CDATA bug fix exists for.
            safe_text.prop_map(|t| format!("<faultstring>{t}</faultstring>")),
            safe_text.prop_map(|t| format!("<faultstring><![CDATA[{t}]]></faultstring>")),
            // <detail> with arbitrary nested elements — should be ignored.
            (element_name, safe_text)
                .prop_map(|(n, t)| { format!("<detail><{n}>{t}</{n}></detail>") }),
            // <faultactor> — also ignored.
            safe_text.prop_map(|t| format!("<faultactor>{t}</faultactor>")),
            // Stray whitespace between elements is normal in real envelopes.
            "[ \\t\\n]{0,4}".prop_map(|s| s),
        ];
        proptest::collection::vec(fragment, 0..6).prop_map(|frags| frags.concat())
    }

    proptest! {
        /// For any combination of fault-shaped fragments, `parse_envelope`
        /// returns either `Ok(EnvelopeBody::Fault(_))` or a typed
        /// `MetadataError` — never panics, never hangs, never returns
        /// `Ok` with a non-fault body. The Salesforce wire contract
        /// isn't fully under our control, so this property keeps the
        /// parser robust against variations not enumerated in the unit
        /// tests above.
        #[test]
        fn parse_fault_never_panics_on_shaped_input(body in fault_body()) {
            let envelope = format!(
                r#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <soapenv:Fault>{body}</soapenv:Fault>
  </soapenv:Body>
</soapenv:Envelope>"#
            );
            match parse_envelope(&envelope, "anyResponse").map(|parsed| parsed.body) {
                Ok(EnvelopeBody::Fault(_)) => {} // expected
                Ok(EnvelopeBody::Success(_)) => {
                    prop_assert!(false, "Fault body parsed as Success: {body}");
                }
                Err(MetadataError::InvalidResponse(_)) => {} // also acceptable
                Err(e) => prop_assert!(
                    false,
                    "unexpected error kind from parse_envelope: {e:?} on body {body:?}",
                ),
            }
        }
    }
}
