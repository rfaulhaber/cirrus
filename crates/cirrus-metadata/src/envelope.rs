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
//! and arbitrary nesting inside the response body. It returns either a
//! parsed [`SoapFault`] or the re-emitted text of the full
//! `<{Operation}Response>...</{Operation}Response>` element. Handlers then
//! deserialize that via quick-xml's serde implementation into their
//! typed response shape. Keeping the outer wrapper lets response structs
//! be named after the wire element and handle multi-`<result>` shapes
//! (e.g. `listMetadata`) without a synthetic root.
//!
//! The re-emitted element reproduces the server's character data
//! verbatim — text is never trimmed and entity references are written
//! back as they arrived — so metadata values reach the caller exactly as
//! the org stores them.

use crate::error::{MetadataError, MetadataResult, SoapFault};
use quick_xml::Reader;
use quick_xml::Writer;
use quick_xml::escape::unescape;
use quick_xml::events::{BytesRef, BytesText, Event};

/// SOAP 1.1 envelope namespace.
const SOAP_NS: &str = "http://schemas.xmlsoap.org/soap/envelope/";
/// Salesforce Metadata API namespace.
const METADATA_NS: &str = "http://soap.sforce.com/2006/04/metadata";
/// XML Schema Instance namespace. Needed by CRUD ops that use
/// `xsi:type` to discriminate concrete Metadata subtypes
/// (`CustomObject`, `ApexClass`, etc.); declared on every envelope so
/// individual handlers don't have to repeat the declaration.
const XSI_NS: &str = "http://www.w3.org/2001/XMLSchema-instance";

/// Outcome of parsing a SOAP response envelope.
#[derive(Debug)]
pub(crate) enum EnvelopeBody {
    /// Operation succeeded. The string is the full
    /// `<{Operation}Response>...</{Operation}Response>` element — the
    /// caller deserializes it into the typed response. The outer
    /// element is included so response structs can be named to match
    /// the wire element and so multi-`<result>` responses work without
    /// a synthetic root.
    Success(String),
    /// Server returned `<soapenv:Fault>`.
    Fault(SoapFault),
}

/// Ceiling on element nesting inside a response body.
///
/// The collected element is handed to `quick-xml`'s serde deserializer,
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
/// `body_xml` is the already-rendered inner body content — it may
/// reference the `met:` prefix or declare its own namespaces.
///
/// [`AuthSession`]: cirrus_auth::AuthSession
pub(crate) fn build_envelope(session_token: &str, operation_name: &str, body_xml: &str) -> String {
    // XML-escape the token. Salesforce tokens are alphanumeric + `!.`,
    // but escaping is cheap insurance against future format changes.
    let token = xml_escape(session_token);
    // A deploy body carries the base64 zip — tens of megabytes at the
    // documented maximum. Sizing the buffer for the whole envelope up
    // front keeps that payload out of a doubling-realloc schedule whose
    // final growth step would otherwise overshoot to twice the
    // envelope's size.
    let capacity = body_xml.len()
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
    out.push_str("</met:sessionId></met:SessionHeader></soapenv:Header><soapenv:Body><met:");
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
/// Walks the input with a pull parser, looking for a `<Body>` child that
/// is either `<Fault>` or an element whose local name equals
/// `expected_response_local_name` (typically `"{Operation}Response"`).
/// Namespace prefixes are not consulted — we match on local names only
/// so the parser is robust against `S:` / `soap:` / `soapenv:` variants
/// that different SOAP servers emit.
pub(crate) fn parse_envelope(
    xml: &[u8],
    expected_response_local_name: &str,
) -> MetadataResult<EnvelopeBody> {
    // `Reader::from_str` is the slice-backed (allocation-free) variant —
    // its `read_event()` returns events that borrow from the input.
    // The generic `Reader<R: BufRead>` only exposes `read_event_into(&mut buf)`,
    // which would force every helper to thread a buffer.
    let s = std::str::from_utf8(xml)
        .map_err(|e| MetadataError::InvalidResponse(format!("response is not valid UTF-8: {e}")))?;
    // Text is deliberately left untrimmed. The same reader re-emits the
    // response element that handlers deserialize, and quick-xml splits
    // character data around every entity reference into separate
    // events — trimming would delete the whitespace on either side of
    // an `&amp;` and strip significant leading/trailing whitespace from
    // metadata values the org stores verbatim.
    let mut reader = Reader::from_str(s);

    // Walk until we enter <Body>.
    loop {
        match reader.read_event()? {
            Event::Start(e) if e.name().local_name().as_ref() == b"Body" => {
                return parse_body(&mut reader, expected_response_local_name);
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

fn parse_body(
    reader: &mut Reader<&[u8]>,
    expected_response_local_name: &str,
) -> MetadataResult<EnvelopeBody> {
    loop {
        match reader.read_event()? {
            Event::Start(e) => {
                let local = e.name().local_name();
                if local.as_ref() == b"Fault" {
                    return parse_fault(reader).map(EnvelopeBody::Fault);
                }
                if local.as_ref() == expected_response_local_name.as_bytes() {
                    let owned = e.into_owned();
                    let mut buf = Vec::new();
                    collect_element(reader, owned, &mut buf)?;
                    return Ok(EnvelopeBody::Success(into_utf8(buf)?));
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
                    let owned = e.into_owned();
                    let mut buf = Vec::new();
                    {
                        let mut writer = Writer::new(&mut buf);
                        writer.write_event(Event::Empty(owned))?;
                    }
                    return Ok(EnvelopeBody::Success(into_utf8(buf)?));
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

/// Reinterpret writer output as UTF-8. The writer re-emits slices of an
/// input that was UTF-8-validated on entry, so this only fails if
/// `quick-xml` ever hands back a partial code point.
fn into_utf8(buf: Vec<u8>) -> MetadataResult<String> {
    String::from_utf8(buf).map_err(|e| {
        MetadataError::InvalidResponse(format!("response element is not valid UTF-8: {e}"))
    })
}

/// Re-emit a complete element (start tag + all children + end tag) into
/// `out`. `start` is the already-consumed opening tag; the reader is
/// positioned just inside it.
///
/// Nesting is capped at [`MAX_RESPONSE_DEPTH`] so a pathologically deep
/// body is rejected here rather than driving unbounded recursion in the
/// serde deserializer that consumes `out`.
fn collect_element(
    reader: &mut Reader<&[u8]>,
    start: quick_xml::events::BytesStart<'static>,
    out: &mut Vec<u8>,
) -> MetadataResult<()> {
    let mut writer = Writer::new(out);
    let end = start.to_end().into_owned();
    writer.write_event(Event::Start(start))?;
    let mut depth: i32 = 1;
    loop {
        match reader.read_event()? {
            Event::Start(e) => {
                depth += 1;
                if depth > MAX_RESPONSE_DEPTH {
                    return Err(MetadataError::InvalidResponse(format!(
                        "response nesting exceeds {MAX_RESPONSE_DEPTH} levels"
                    )));
                }
                writer.write_event(Event::Start(e))?;
            }
            Event::End(e) => {
                depth -= 1;
                if depth == 0 {
                    // Re-emit the captured outer end tag so the
                    // element name in the output matches the input
                    // even if the original used a namespace prefix.
                    writer.write_event(Event::End(end))?;
                    return Ok(());
                }
                writer.write_event(Event::End(e))?;
            }
            Event::Empty(e) => {
                writer.write_event(Event::Empty(e))?;
            }
            Event::Text(e) => {
                writer.write_event(Event::Text(e))?;
            }
            // Entity/character references (`&amp;`, `&#x30;`, …) arrive
            // as their own events, not folded into `Text` — dropping
            // one would silently corrupt the re-emitted element.
            Event::GeneralRef(e) => {
                writer.write_event(Event::GeneralRef(e))?;
            }
            Event::CData(e) => {
                writer.write_event(Event::CData(e))?;
            }
            Event::Comment(e) => {
                writer.write_event(Event::Comment(e))?;
            }
            Event::Eof => {
                return Err(MetadataError::InvalidResponse(
                    "unexpected EOF inside response element".into(),
                ));
            }
            // Decl / PI / DocType shouldn't appear inside a SOAP body;
            // ignore defensively rather than failing.
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

/// Minimal XML escape — only the five mandatory entities. Used for the
/// session token before splicing it into the envelope, and by handlers
/// rendering body XML by hand. Production tokens and most metadata
/// names never contain these characters, so we scan first and return a
/// borrow when no escape is needed — saves one allocation per token /
/// fullName / type name on the SOAP envelope hot path.
pub(crate) fn xml_escape(s: &str) -> std::borrow::Cow<'_, str> {
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

    #[test]
    fn build_envelope_round_trip_shape() {
        let env = build_envelope("TOKEN", "ping", "<inner/>");
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
        let env = build_envelope("a<b&c", "ping", "");
        assert!(env.contains("a&lt;b&amp;c"));
        assert!(!env.contains("a<b&c</"));
    }

    #[test]
    fn parse_envelope_returns_success_with_wrapper() {
        let xml = br#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns="http://soap.sforce.com/2006/04/metadata">
  <soapenv:Body>
    <pingResponse>
      <result><msg>ok</msg></result>
    </pingResponse>
  </soapenv:Body>
</soapenv:Envelope>"#;
        let body = parse_envelope(xml, "pingResponse").unwrap();
        let EnvelopeBody::Success(s) = body else {
            panic!("expected Success, got {body:?}");
        };
        // The outer wrapper is preserved so callers can deserialize a
        // struct named like the wire element.
        assert!(s.contains("<pingResponse>"));
        assert!(s.contains("</pingResponse>"));
        assert!(s.contains("<result>"));
        assert!(s.contains("<msg>ok</msg>"));
    }

    #[test]
    fn parse_envelope_returns_fault() {
        let xml = br#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <soapenv:Fault>
      <faultcode>sf:INVALID_SESSION_ID</faultcode>
      <faultstring>INVALID_SESSION_ID: Session expired or invalid</faultstring>
    </soapenv:Fault>
  </soapenv:Body>
</soapenv:Envelope>"#;
        let body = parse_envelope(xml, "pingResponse").unwrap();
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
        let xml = br#"<?xml version="1.0"?>
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
        let body = parse_envelope(xml, "anything").unwrap();
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
        let xml = br#"<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <soapenv:Fault>
      <faultcode>sf:INVALID_SESSION_ID</faultcode>
      <faultstring><![CDATA[INVALID_SESSION_ID: Session expired or invalid <token>]]></faultstring>
    </soapenv:Fault>
  </soapenv:Body>
</soapenv:Envelope>"#;
        let body = parse_envelope(xml, "anything").unwrap();
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
        let xml = br#"<?xml version="1.0"?>
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
        let xml = br#"<?xml version="1.0"?>
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
        // Make sure deeply nested success-body content round-trips
        // through the writer.
        let xml = br#"<?xml version="1.0"?>
<E xmlns="http://schemas.xmlsoap.org/soap/envelope/">
  <Body>
    <listMetadataResponse>
      <result><type>ApexClass</type><fullName>Foo</fullName></result>
      <result><type>ApexClass</type><fullName>Bar</fullName></result>
    </listMetadataResponse>
  </Body>
</E>"#;
        let body = parse_envelope(xml, "listMetadataResponse").unwrap();
        let EnvelopeBody::Success(s) = body else {
            panic!("expected Success");
        };
        assert!(s.contains("<listMetadataResponse>"));
        assert_eq!(s.matches("<result>").count(), 2);
        assert!(s.contains("<fullName>Foo</fullName>"));
        assert!(s.contains("<fullName>Bar</fullName>"));
    }

    #[test]
    fn parse_envelope_preserves_whitespace_around_entities() {
        // quick-xml reports an entity reference as its own event, which
        // splits the surrounding character data in two. The re-emitted
        // element must carry both halves — spaces included — so a
        // CustomLabel whose value is `Tom & Jerry` doesn't reach the
        // caller as `Tom&Jerry`.
        let xml = br#"<?xml version="1.0"?>
<E xmlns="http://schemas.xmlsoap.org/soap/envelope/">
  <Body>
    <readMetadataResponse>
      <result><value>Tom &amp; Jerry</value><pad>  padded  </pad></result>
    </readMetadataResponse>
  </Body>
</E>"#;
        let body = parse_envelope(xml, "readMetadataResponse").unwrap();
        let EnvelopeBody::Success(s) = body else {
            panic!("expected Success, got {body:?}");
        };
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
        let xml = br#"<?xml version="1.0"?>
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
        let body = parse_envelope(xml, "anything").unwrap();
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

        let err = parse_envelope(xml.as_bytes(), "describeValueTypeResponse").unwrap_err();
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

        let body = parse_envelope(xml.as_bytes(), "describeValueTypeResponse").unwrap();
        assert!(matches!(body, EnvelopeBody::Success(_)));
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
            match parse_envelope(envelope.as_bytes(), "anyResponse") {
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
