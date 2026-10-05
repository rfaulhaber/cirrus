//! Apex REST passthrough — `/services/apexrest/{path}`.
//!
//! Apex REST lets Salesforce admins/developers expose custom Apex classes as
//! REST endpoints by annotating them with `@RestResource(urlMapping='...')`.
//! The wire shape (request body, response body) is entirely defined by the
//! developer who wrote the Apex class — Salesforce only provides the
//! transport, auth, and (on non-2xx) the standard `[{message, errorCode}]`
//! error array.
//!
//! The handler prepends `/services/apexrest/` to the path you supply
//! (stripping a single leading slash if present). Pass just the Apex
//! `urlMapping` (e.g. `"MyEndpoint"` or `"/MyEndpoint/123"`).
//!
//! # Path encoding
//!
//! The handler does **not** percent-encode path segments. For paths
//! containing reserved characters (spaces, `&`), pre-encode the
//! segments yourself before calling. `?` and `#` end the path when the
//! URL is parsed — everything after the first of them becomes the query
//! string or the fragment — so percent-encode those (`%3F`, `%23`) to
//! address a segment that really contains one.
//!
//! Relative segments (`.` and `..`, in either literal or percent-encoded
//! spelling) are rejected with [`CirrusError::InvalidInput`], because URL
//! parsing resolves them away and a path assembled from untrusted input
//! could otherwise reach an endpoint outside `/services/apexrest/` while
//! still carrying the org's bearer token. Pre-encoding does not avoid
//! this — `%2e%2e` normalizes to `..` — so such segments have to be
//! refused rather than escaped.
//!
//! A backslash, or any character up to and including `U+0020` (every C0
//! control plus the space), is refused for the same reason. URL parsing
//! treats `\` as a path separator, removes tab, line feed and carriage
//! return wherever they appear, and trims C0 controls and spaces from both
//! ends of the URL — each of which can reconstitute a dot segment that a
//! check on the literal text has already accepted, as `".. "` does.
//!
//! [`CirrusError::InvalidInput`]: crate::CirrusError::InvalidInput

use crate::error::{CirrusError, CirrusResult};
use crate::{Cirrus, Replay};
use serde::Serialize;
use serde::de::DeserializeOwned;

impl Cirrus {
    /// Returns a handler for Apex REST endpoints exposed under
    /// `/services/apexrest/`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use cirrus::{Cirrus, auth::StaticTokenAuth};
    /// # use std::sync::Arc;
    /// use serde::{Deserialize, Serialize};
    /// #[derive(Serialize)]
    /// struct Request { name: String }
    /// #[derive(Deserialize)]
    /// struct Response { greeting: String }
    /// # async fn example() -> Result<(), cirrus::CirrusError> {
    /// # let auth = Arc::new(StaticTokenAuth::new("tok", "https://x.my.salesforce.com"));
    /// # let sf = Cirrus::builder().auth(auth).build()?;
    /// let req = Request { name: "world".into() };
    /// let resp: Response = sf.apex().post("Hello", &req).await?;
    /// println!("{}", resp.greeting);
    /// # Ok(())
    /// # }
    /// ```
    pub fn apex(&self) -> ApexHandler<'_> {
        ApexHandler { client: self }
    }
}

/// Handler for `/services/apexrest/{path}` endpoints.
///
/// Each method takes the Apex `urlMapping` (with or without a leading
/// slash) and forwards through the corresponding [`Cirrus`] verb.
/// Body and response types are caller-defined since Apex REST endpoints
/// have no platform-defined wire shape.
///
/// Every method returns [`CirrusError::InvalidInput`] without issuing a
/// request when the supplied path contains an empty or relative
/// (`.` / `..`) segment, a backslash, or any character up to and
/// including `U+0020` — the C0 controls and the space — see the
/// [module docs](self#path-encoding).
///
/// No method here is replayed once the request has reached the org,
/// whatever its HTTP verb. The status codes come from developer code:
/// Salesforce documents the Apex REST 500 as an unhandled Apex
/// exception rather than a transient failure, and nothing stops an
/// `@HttpGet`, `@HttpPut` or `@HttpDelete` method from writing, so a
/// re-sent request would run that Apex again, DML and callouts
/// included. Only 429 and connect-phase failures retry, and a 401 the
/// Apex sets is surfaced as-is rather than treated as an expired token.
/// For an endpoint the org documents as read-only,
/// [`Cirrus::send_with_replay`] with [`Replay::ByMethod`] restores the
/// default retry behaviour.
///
/// [`CirrusError::InvalidInput`]: crate::CirrusError::InvalidInput
#[derive(Debug)]
pub struct ApexHandler<'a> {
    client: &'a Cirrus,
}

impl ApexHandler<'_> {
    /// `GET /services/apexrest/{path}`.
    pub async fn get<R: DeserializeOwned>(&self, path: &str) -> CirrusResult<R> {
        self.client
            .send_with_replay::<R, ()>(
                reqwest::Method::GET,
                &apex_path(path)?,
                None,
                &[],
                None,
                Replay::Never,
            )
            .await
    }

    /// `GET /services/apexrest/{path}` with a query string. `query` is
    /// any [`Serialize`] value — typically `&[("key", "value")]` or a
    /// struct.
    pub async fn get_with_query<R, Q>(&self, path: &str, query: &Q) -> CirrusResult<R>
    where
        R: DeserializeOwned,
        Q: Serialize + ?Sized,
    {
        self.client
            .get_with_query_no_replay(&apex_path(path)?, query)
            .await
    }

    /// `POST /services/apexrest/{path}` with a JSON body.
    pub async fn post<R, B>(&self, path: &str, body: &B) -> CirrusResult<R>
    where
        R: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        self.client
            .send_with_replay(
                reqwest::Method::POST,
                &apex_path(path)?,
                None,
                &[],
                Some(body),
                Replay::Never,
            )
            .await
    }

    /// `PUT /services/apexrest/{path}` with a JSON body.
    pub async fn put<R, B>(&self, path: &str, body: &B) -> CirrusResult<R>
    where
        R: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        self.client
            .send_with_replay(
                reqwest::Method::PUT,
                &apex_path(path)?,
                None,
                &[],
                Some(body),
                Replay::Never,
            )
            .await
    }

    /// `PATCH /services/apexrest/{path}` with a JSON body.
    pub async fn patch<R, B>(&self, path: &str, body: &B) -> CirrusResult<R>
    where
        R: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        self.client
            .send_with_replay(
                reqwest::Method::PATCH,
                &apex_path(path)?,
                None,
                &[],
                Some(body),
                Replay::Never,
            )
            .await
    }

    /// `DELETE /services/apexrest/{path}`.
    pub async fn delete<R: DeserializeOwned>(&self, path: &str) -> CirrusResult<R> {
        self.client
            .send_with_replay::<R, ()>(
                reqwest::Method::DELETE,
                &apex_path(path)?,
                None,
                &[],
                None,
                Replay::Never,
            )
            .await
    }
}

/// Normalizes an Apex REST path into an instance-rooted form.
///
/// - `"MyEndpoint"` → `"/services/apexrest/MyEndpoint"`
/// - `"/MyEndpoint"` → `"/services/apexrest/MyEndpoint"`
/// - `"MyEndpoint/sub/123"` → `"/services/apexrest/MyEndpoint/sub/123"`
///
/// The leading `/` triggers [`crate::Cirrus`]'s instance-rooted branch,
/// bypassing the versioned `/services/data/{version}/` prefix.
///
/// Errors when any content-bearing segment of the addressed path is
/// empty or relative, or when the path contains a backslash or any
/// character up to and including `U+0020`, so that a path built from
/// untrusted input cannot resolve outside the Apex REST root. A single
/// trailing slash is kept: Apex `urlMapping` values are documented with
/// one.
fn apex_path(path: &str) -> CirrusResult<String> {
    // For a special scheme, WHATWG URL parsing treats `\` as a path
    // separator, removes tab, LF and CR from anywhere in the input, and
    // trims every C0 control and space from both ends of the URL — all
    // before it looks for dot segments. Each of those can reconstitute a
    // dot segment that the split below has already accepted: `Cases\..\`,
    // `Cases/.<TAB>./` and `".. "` all resolve out of the Apex REST root.
    // Refusing the whole class up front is what makes the per-segment
    // check trustworthy.
    if let Some(c) = path.chars().find(|&c| c == '\\' || c <= '\u{20}') {
        let reason = if c == '\\' {
            "URL parsing treats it as a path separator for the org's https scheme"
        } else {
            "URL parsing removes or trims C0 controls and spaces before it resolves dot segments"
        };
        return Err(CirrusError::InvalidInput {
            field: "Apex REST path",
            message: format!("{c:?} cannot appear in the path: {reason}"),
        });
    }
    let trimmed = path.trim_start_matches('/');
    // The first `?` or `#` ends the path; what follows is the query
    // string or the fragment and can't move the request off the Apex
    // REST root. Only the part before it is worth checking — and it
    // has to be checked, because a terminator closes the segment it
    // follows, so `..?` is still a dot segment.
    let addressed = trimmed
        .find(['?', '#'])
        .map_or(trimmed, |end| &trimmed[..end]);
    let body = addressed.strip_suffix('/').unwrap_or(addressed);
    for segment in body.split('/') {
        if segment.is_empty() || is_relative_segment(segment) {
            return Err(CirrusError::InvalidInput {
                field: "Apex REST path",
                message: format!(
                    "segment {segment:?} is not addressable under /services/apexrest/ \
                     (empty and relative segments are rejected)"
                ),
            });
        }
    }
    Ok(format!("/services/apexrest/{trimmed}"))
}

/// Whether a path segment is a dot segment that URL parsing would resolve
/// away.
///
/// WHATWG URL parsing treats a segment as `.` or `..` after
/// case-insensitively decoding `%2e`, so both spellings have to be caught.
/// Doubly-encoded forms such as `%252e` decode to the literal text `%2e`
/// and are left alone, matching the parser.
fn is_relative_segment(segment: &str) -> bool {
    let decoded = segment.to_ascii_lowercase().replace("%2e", ".");
    decoded == "." || decoded == ".."
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::auth::StaticTokenAuth;
    use serde_json::json;
    use std::sync::Arc;
    use wiremock::matchers::{body_json, header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn fixture(uri: String) -> Cirrus {
        let auth = Arc::new(StaticTokenAuth::new("tok", uri));
        Cirrus::builder().auth(auth).build().unwrap()
    }

    fn fixture_with_fast_retries(uri: String) -> Cirrus {
        // The default retry budget with zero delays, so a replay that
        // should not happen shows up as an extra request, not as a
        // slow test.
        let auth = Arc::new(StaticTokenAuth::new("tok", uri));
        Cirrus::builder()
            .auth(auth)
            .retry_policy(crate::RetryPolicy {
                base_delay: std::time::Duration::ZERO,
                max_delay: std::time::Duration::ZERO,
                jitter: false,
                ..crate::RetryPolicy::default()
            })
            .build()
            .unwrap()
    }

    #[test]
    fn apex_path_normalizes_relative_input() {
        assert_eq!(
            apex_path("MyEndpoint").unwrap(),
            "/services/apexrest/MyEndpoint"
        );
    }

    #[test]
    fn apex_path_normalizes_leading_slash_input() {
        assert_eq!(
            apex_path("/MyEndpoint").unwrap(),
            "/services/apexrest/MyEndpoint"
        );
    }

    #[test]
    fn apex_path_preserves_subpaths() {
        assert_eq!(
            apex_path("Cases/12345/comments").unwrap(),
            "/services/apexrest/Cases/12345/comments"
        );
        assert_eq!(
            apex_path("/Cases/12345/comments").unwrap(),
            "/services/apexrest/Cases/12345/comments"
        );
    }

    #[test]
    fn apex_path_keeps_documented_trailing_slash() {
        // SOURCE: https://developer.salesforce.com/docs/atlas.en-us.apexcode.meta/apexcode/apex_rest_methods.htm
        // "the URL used via REST to call these methods would be of the form
        // https://instance.salesforce.com/services/apexrest/packageNamespace/MyMethod/"
        assert_eq!(
            apex_path("packageNamespace/MyMethod/").unwrap(),
            "/services/apexrest/packageNamespace/MyMethod/"
        );
    }

    #[test]
    fn apex_path_rejects_relative_segments() {
        // `Url::parse` resolves dot segments away, so a path built from
        // untrusted input would otherwise climb out of the Apex REST root
        // and reach the data API with the caller's bearer token.
        for candidate in [
            "..",
            "../../services/data/v66.0/sobjects/Account/001xx000003DGb2",
            "Cases/../../../services/data/v66.0/limits",
            "Cases/./comments",
            // Percent-encoded spellings normalize identically.
            "%2e%2e/services/data/v66.0/limits",
            "Cases/%2E%2E/comments",
            "Cases/.%2e/comments",
            "Cases/%2e/comments",
            // A backslash is a path separator for special schemes, so the
            // whole thing would otherwise pass as one segment.
            "Cases\\..\\..\\..\\services/data/v66.0/sobjects/Account/001xx",
            // Tab, LF and CR are stripped before dot segments are
            // resolved, so they can split a `..` in half.
            "Cases/.\t./.\t./.\t./services/data/v66.0/limits",
            "Cases/.\n./.\n./.\n./services/data/v66.0/limits",
            "Cases/.\r./.\r./.\r./services/data/v66.0/limits",
            // C0 controls and spaces are trimmed off both ends of the URL
            // before dot segments resolve, so a trailing one puts a `..`
            // back after the per-segment check has seen something else.
            ".. ",
            "%2e%2e ",
            "Cases/..\u{0}",
            // `?` and `#` end the path, which closes the segment in
            // front of them — so the dot segment still resolves.
            "..?",
            "..#",
            "%2e%2e?x=1",
            "Cases/..#fragment",
        ] {
            let err = apex_path(candidate).unwrap_err();
            assert!(
                matches!(err, CirrusError::InvalidInput { .. }),
                "{candidate:?} should be rejected, got {err:?}"
            );
        }
    }

    #[test]
    fn apex_path_rejects_empty_segments() {
        for candidate in ["", "/", "Cases//comments"] {
            assert!(
                apex_path(candidate).is_err(),
                "{candidate:?} should be rejected"
            );
        }
    }

    #[test]
    fn apex_path_keeps_a_query_string_or_fragment() {
        // Only `get_with_query` takes a separate query value, so an
        // inline one is the only way to put a query on the other verbs.
        assert_eq!(
            apex_path("MyEndpoint?foo=bar").unwrap(),
            "/services/apexrest/MyEndpoint?foo=bar"
        );
        assert_eq!(
            apex_path("Cases/12345/?foo=bar").unwrap(),
            "/services/apexrest/Cases/12345/?foo=bar"
        );
        assert_eq!(
            apex_path("MyEndpoint#anchor").unwrap(),
            "/services/apexrest/MyEndpoint#anchor"
        );
    }

    #[test]
    fn accepted_paths_stay_under_the_apex_rest_root_once_parsed() {
        // The per-segment checks exist to survive URL parsing, which is
        // where dot-segment removal actually happens — so assert on the
        // parsed path rather than on the string the handler built.
        for candidate in [
            "MyEndpoint",
            "/MyEndpoint",
            "packageNamespace/MyMethod/",
            "Cases/12345/comments",
            "Cases/%252e%252e/comments",
            "MyEndpoint?foo=bar",
            "MyEndpoint#anchor",
            "Cases/..%2f..%2fadmin",
        ] {
            let resolved = apex_path(candidate).unwrap();
            let parsed = url::Url::parse(&format!("https://acme.my.salesforce.com{resolved}"))
                .unwrap_or_else(|e| panic!("{candidate:?} produced an unparseable URL: {e}"));
            assert!(
                parsed.path().starts_with("/services/apexrest/"),
                "{candidate:?} escaped to {}",
                parsed.path()
            );
        }
    }

    #[test]
    fn no_accepted_path_escapes_the_apex_rest_root() {
        // Exhaustive over the pieces WHATWG URL parsing gives special
        // treatment — dot segments in each spelling, the separators,
        // the terminators, and the characters parsing strips — because
        // the escapes that matter come from combining them, not from
        // any one of them alone.
        const ATOMS: [&str; 18] = [
            "..", ".", "%2e%2e", "%2E.", ".%2e", "%2e", "%252e", "a", "", "?", "#", "&", "\\", " ",
            "\t", "\u{0}", "%2f", "..%2f",
        ];
        let mut checked = 0usize;
        let mut confine = |candidate: &str| {
            let Ok(resolved) = apex_path(candidate) else {
                return;
            };
            checked += 1;
            let parsed = url::Url::parse(&format!("https://acme.my.salesforce.com{resolved}"))
                .unwrap_or_else(|e| panic!("{candidate:?} produced an unparseable URL: {e}"));
            assert!(
                parsed.path().starts_with("/services/apexrest/"),
                "{candidate:?} resolved to {}",
                parsed.path()
            );
        };
        for a in ATOMS {
            for b in ATOMS {
                for c in ATOMS {
                    confine(&format!("{a}{b}{c}"));
                    confine(&format!("{a}/{b}/{c}"));
                    confine(&format!("Cases/{a}{b}/{c}/comments"));
                }
            }
        }
        assert!(checked > 0, "every candidate was rejected");
    }

    #[test]
    fn apex_path_allows_doubly_encoded_dots() {
        // `%252e` decodes to the literal text `%2e`, which URL parsing
        // leaves in place — it addresses a real segment, not a parent.
        assert_eq!(
            apex_path("Cases/%252e%252e/comments").unwrap(),
            "/services/apexrest/Cases/%252e%252e/comments"
        );
    }

    #[tokio::test]
    async fn apex_traversal_path_errors_without_issuing_a_request() {
        let server = MockServer::start().await;
        // No mock is mounted: any outgoing request fails the test by
        // returning a 404 that would surface as CirrusError::Api.
        let sf = fixture(server.uri());
        for candidate in [
            "Cases/../../services/data/v66.0/sobjects/Account/001xx",
            "Cases\\..\\..\\..\\services/data/v66.0/sobjects/Account/001xx",
            "Cases/.\t./.\t./.\t./services/data/v66.0/limits",
            "Cases/..\u{0}",
            "..?",
        ] {
            let err = sf.apex().delete::<()>(candidate).await.unwrap_err();
            assert!(
                matches!(err, CirrusError::InvalidInput { .. }),
                "{candidate:?}: {err:?}"
            );
        }
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn apex_get_targets_apexrest_path_without_version() {
        let server = MockServer::start().await;

        // Note the URL: NO /services/data/v66.0/ prefix. Apex REST lives
        // outside the versioned tree.
        Mock::given(method("GET"))
            .and(path("/services/apexrest/MyEndpoint"))
            .and(header("authorization", "Bearer tok"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let v: serde_json::Value = sf.apex().get("MyEndpoint").await.unwrap();
        assert_eq!(v["ok"], true);
    }

    #[tokio::test]
    async fn apex_get_accepts_leading_slash_input() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/services/apexrest/MyEndpoint"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"hit": true})))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let v: serde_json::Value = sf.apex().get("/MyEndpoint").await.unwrap();
        assert_eq!(v["hit"], true);
    }

    #[tokio::test]
    async fn apex_get_with_query_passes_params() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/services/apexrest/Cases"))
            .and(query_param("status", "Open"))
            .and(query_param("limit", "10"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([{"id": "500xx"}])))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let v: serde_json::Value = sf
            .apex()
            .get_with_query("Cases", &[("status", "Open"), ("limit", "10")])
            .await
            .unwrap();
        assert_eq!(v[0]["id"], "500xx");
    }

    #[tokio::test]
    async fn apex_get_typed_response_deserializes_caller_struct() {
        // Demonstrates the entire reason this handler is generic over R:
        // the Apex developer defined CaseSummary, not Salesforce.
        #[derive(serde::Deserialize)]
        struct CaseSummary {
            #[serde(rename = "Id")]
            id: String,
            #[serde(rename = "Subject")]
            subject: String,
        }

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/services/apexrest/Cases/500xx"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"Id": "500xx", "Subject": "Login issue"})),
            )
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let case: CaseSummary = sf.apex().get("Cases/500xx").await.unwrap();
        assert_eq!(case.id, "500xx");
        assert_eq!(case.subject, "Login issue");
    }

    #[tokio::test]
    async fn apex_post_sends_json_body() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/services/apexrest/Cases"))
            .and(body_json(json!({
                "subject": "Login issue",
                "priority": "High"
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({"id": "500xx"})))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let v: serde_json::Value = sf
            .apex()
            .post(
                "Cases",
                &json!({"subject": "Login issue", "priority": "High"}),
            )
            .await
            .unwrap();
        assert_eq!(v["id"], "500xx");
    }

    #[tokio::test]
    async fn apex_put_sends_json_body() {
        let server = MockServer::start().await;

        Mock::given(method("PUT"))
            .and(path("/services/apexrest/Settings/SomeKey"))
            .and(body_json(json!({"value": "new"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"updated": true})))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let v: serde_json::Value = sf
            .apex()
            .put("Settings/SomeKey", &json!({"value": "new"}))
            .await
            .unwrap();
        assert_eq!(v["updated"], true);
    }

    #[tokio::test]
    async fn apex_patch_handles_204_no_content() {
        let server = MockServer::start().await;

        Mock::given(method("PATCH"))
            .and(path("/services/apexrest/Cases/500xx"))
            .and(body_json(json!({"status": "Closed"})))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        sf.apex()
            .patch::<(), _>("Cases/500xx", &json!({"status": "Closed"}))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn apex_delete_handles_204_no_content() {
        let server = MockServer::start().await;

        Mock::given(method("DELETE"))
            .and(path("/services/apexrest/Cases/500xx"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        sf.apex().delete::<()>("Cases/500xx").await.unwrap();
    }

    #[tokio::test]
    async fn apex_get_is_not_replayed_after_a_5xx() {
        // SOURCE: https://developer.salesforce.com/docs/atlas.en-us.apexcode.meta/apexcode/apex_rest_methods.htm
        // Response Status Codes: 500 is "An unhandled Apex exception
        // occurred." The Apex already ran, so a re-sent GET runs it
        // again — DML, callouts and all — before the caller sees the
        // same failure.
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/services/apexrest/Cases/500xx"))
            .respond_with(ResponseTemplate::new(500).set_body_json(json!([{
                "message": "System.QueryException: List has no rows for assignment to SObject",
                "errorCode": "APEX_ERROR"
            }])))
            .mount(&server)
            .await;

        let sf = fixture_with_fast_retries(server.uri());
        let err = sf
            .apex()
            .get::<serde_json::Value>("Cases/500xx")
            .await
            .unwrap_err();
        assert!(matches!(err, crate::CirrusError::Api { status: 500, .. }));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn apex_get_with_query_is_not_replayed_after_a_5xx() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/services/apexrest/Report"))
            .and(query_param("since", "2026-01-01"))
            .respond_with(ResponseTemplate::new(502))
            .mount(&server)
            .await;

        let sf = fixture_with_fast_retries(server.uri());
        let err = sf
            .apex()
            .get_with_query::<serde_json::Value, _>("Report", &[("since", "2026-01-01")])
            .await
            .unwrap_err();
        assert!(matches!(err, crate::CirrusError::Api { status: 502, .. }));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn apex_put_is_not_replayed_after_a_503() {
        // SOURCE: https://developer.salesforce.com/docs/atlas.en-us.apexcode.meta/apexcode/apex_classes_annotation_http_put.htm
        // "@HttpPut ... creates or updates the specified resource": the
        // method name promises nothing about idempotency of the Apex
        // behind it, so a 503 from an intermediary after the commit must
        // not be followed by a second PUT.
        let server = MockServer::start().await;

        Mock::given(method("PUT"))
            .and(path("/services/apexrest/Orders/801xx"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let sf = fixture_with_fast_retries(server.uri());
        let err = sf
            .apex()
            .put::<serde_json::Value, _>("Orders/801xx", &json!({"status": "Shipped"}))
            .await
            .unwrap_err();
        assert!(matches!(err, crate::CirrusError::Api { status: 503, .. }));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn apex_delete_is_not_replayed_after_a_503() {
        let server = MockServer::start().await;

        Mock::given(method("DELETE"))
            .and(path("/services/apexrest/Orders/801xx"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let sf = fixture_with_fast_retries(server.uri());
        let err = sf.apex().delete::<()>("Orders/801xx").await.unwrap_err();
        assert!(matches!(err, crate::CirrusError::Api { status: 503, .. }));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn apex_retries_a_429_because_the_request_was_refused() {
        // 429 means the org never ran the Apex, so the one retry class
        // that survives `Replay::Never` still applies here.
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/services/apexrest/Cases/500xx"))
            .respond_with(ResponseTemplate::new(429))
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/services/apexrest/Cases/500xx"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"Id": "500xx"})))
            .expect(1)
            .mount(&server)
            .await;

        let sf = fixture_with_fast_retries(server.uri());
        let case: serde_json::Value = sf.apex().get("Cases/500xx").await.unwrap();
        assert_eq!(case["Id"], "500xx");
    }

    #[tokio::test]
    async fn apex_surfaces_standard_salesforce_error_array() {
        // Even though the body shape is dev-defined, the platform error
        // shape is still the standard [{message, errorCode}] array.
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/services/apexrest/Missing"))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!([{
                "message": "Could not find a match for URL /Missing",
                "errorCode": "NOT_FOUND"
            }])))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let err = sf
            .apex()
            .get::<serde_json::Value>("Missing")
            .await
            .unwrap_err();
        match err {
            crate::CirrusError::Api { status, errors, .. } => {
                assert_eq!(status, 404);
                assert_eq!(errors[0].error_code, "NOT_FOUND");
            }
            other => panic!("expected Api error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn apex_handles_nested_subpath_with_record_id() {
        // A typical Apex REST pattern: urlMapping='/Cases/*', the trailing
        // segment is a record ID parsed by the Apex code.
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/services/apexrest/Cases/500xx0000000001/comments"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                {"author": "ryf", "text": "first"},
                {"author": "other", "text": "second"}
            ])))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let comments: serde_json::Value = sf
            .apex()
            .get("/Cases/500xx0000000001/comments")
            .await
            .unwrap();
        assert_eq!(comments.as_array().unwrap().len(), 2);
        assert_eq!(comments[0]["author"], "ryf");
    }
}
