//! SOSL search and parameterized search.
//!
//! Salesforce exposes two related endpoints for full-text search:
//!
//! - [`search`] — runs a SOSL string (`FIND {Acme} IN ALL FIELDS RETURNING
//!   Account(Id, Name)`). The caller writes SOSL directly.
//! - [`parameterized_search`] — POSTs a structured JSON body
//!   (`{"q": "Acme", "fields": ["Id", "Name"], "sobjects": [...]}`) and
//!   lets Salesforce assemble the SOSL. Strictly more capable than the
//!   GET form (which this SDK does not wrap).
//!
//! Both endpoints share the same response envelope ([`SearchResult`]) and
//! both expose `_as::<T>()` typed variants.
//!
//! [`search`]: Cirrus::search
//! [`parameterized_search`]: Cirrus::parameterized_search

use crate::Cirrus;
use crate::error::CirrusResult;
use crate::response::SearchResult;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

impl Cirrus {
    /// Runs a SOSL search.
    ///
    /// Calls `GET /services/data/{api_version}/search?q={sosl}`. Pass plain
    /// SOSL: the statement is percent-encoded for the URI here, which is
    /// transport encoding only. A search term that comes from outside the
    /// program goes through [`sosl::escape_term`](crate::sosl::escape_term)
    /// first, or a reserved character in it (`}` among them) rewrites the
    /// `FIND` clause. The 16,384-byte URI cap described under
    /// [Request size](crate::handlers::query#request-size) applies here
    /// too.
    ///
    /// SOSL example:
    /// `FIND {Acme} IN NAME FIELDS RETURNING Account(Id, Name), Contact(Id)`.
    /// Field labels come back on [`SearchResult::metadata`] when the
    /// statement ends in `WITH METADATA='LABELS'`.
    pub async fn search(&self, sosl: &str) -> CirrusResult<SearchResult<Value>> {
        self.search_as(sosl).await
    }

    /// Typed variant of [`search`](Self::search) — records deserialize as `R`.
    pub async fn search_as<R: DeserializeOwned>(
        &self,
        sosl: &str,
    ) -> CirrusResult<SearchResult<R>> {
        let query = [("q", sosl)];
        self.get_with_query("search", &query).await
    }

    /// Runs a parameterized search via POST.
    ///
    /// Calls `POST /services/data/{api_version}/parameterizedSearch`. The
    /// body is any `Serialize` value matching Salesforce's documented
    /// shape, e.g.
    ///
    /// ```ignore
    /// serde_json::json!({
    ///     "q": "Acme",
    ///     "fields": ["Id", "Name"],
    ///     "sobjects": [{"name": "Account"}, {"name": "Contact"}]
    /// })
    /// ```
    ///
    /// The POST form is strictly more capable than the GET form (which
    /// this SDK does not wrap). Use the open-ended client escape hatch
    /// for the GET form if you need it.
    pub async fn parameterized_search<B>(&self, body: &B) -> CirrusResult<SearchResult<Value>>
    where
        B: Serialize + ?Sized,
    {
        self.parameterized_search_as(body).await
    }

    /// Typed variant of
    /// [`parameterized_search`](Self::parameterized_search).
    pub async fn parameterized_search_as<R, B>(&self, body: &B) -> CirrusResult<SearchResult<R>>
    where
        R: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        self.post("parameterizedSearch", body).await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use crate::Cirrus;
    use crate::auth::StaticTokenAuth;
    use serde_json::json;
    use std::sync::Arc;
    use wiremock::matchers::{body_json, header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn fixture(uri: String) -> Cirrus {
        let auth = Arc::new(StaticTokenAuth::new("tok", uri));
        Cirrus::builder().auth(auth).build().unwrap()
    }

    #[tokio::test]
    async fn search_passes_sosl_in_q_param() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/search"))
            .and(query_param(
                "q",
                "FIND {Acme} IN NAME FIELDS RETURNING Account(Id, Name)",
            ))
            .and(header("authorization", "Bearer tok"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "searchRecords": [
                    {
                        "attributes": {
                            "type": "Account",
                            "url": "/services/data/v66.0/sobjects/Account/001xx"
                        },
                        "Id": "001xx",
                        "Name": "Acme"
                    }
                ]
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let result = sf
            .search("FIND {Acme} IN NAME FIELDS RETURNING Account(Id, Name)")
            .await
            .unwrap();
        assert_eq!(result.search_records.len(), 1);
        assert_eq!(result.search_records[0]["Name"], "Acme");
    }

    #[tokio::test]
    async fn search_returns_empty_when_no_hits() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/search"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"searchRecords": []})))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let result = sf
            .search("FIND {NoSuchThing} RETURNING Account(Id)")
            .await
            .unwrap();
        assert!(result.search_records.is_empty());
        assert!(result.metadata.is_none());
    }

    #[tokio::test]
    async fn search_typed_records() {
        #[derive(serde::Deserialize)]
        struct Hit {
            #[serde(rename = "Id")]
            id: String,
            #[serde(rename = "Name")]
            name: String,
        }

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/search"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "searchRecords": [
                    {"attributes": {"type": "Account"}, "Id": "001xx", "Name": "Acme"}
                ]
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let result = sf
            .search_as::<Hit>("FIND {Acme} RETURNING Account(Id, Name)")
            .await
            .unwrap();
        assert_eq!(result.search_records[0].id, "001xx");
        assert_eq!(result.search_records[0].name, "Acme");
    }

    #[tokio::test]
    async fn search_surfaces_malformed_search_error() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/search"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!([{
                "message": "unexpected token: foo",
                "errorCode": "MALFORMED_SEARCH"
            }])))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let err = sf.search("FIND foo").await.unwrap_err();
        match err {
            crate::CirrusError::Api { status, errors, .. } => {
                assert_eq!(status, 400);
                assert_eq!(errors[0].error_code, "MALFORMED_SEARCH");
            }
            other => panic!("expected Api error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn parameterized_search_posts_structured_body() {
        let server = MockServer::start().await;

        let request_body = json!({
            "q": "Acme",
            "fields": ["Id", "Name"],
            "sobjects": [{"name": "Account"}, {"name": "Contact"}]
        });

        Mock::given(method("POST"))
            .and(path("/services/data/v66.0/parameterizedSearch"))
            .and(header("authorization", "Bearer tok"))
            .and(body_json(request_body.clone()))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "searchRecords": [
                    {
                        "attributes": {
                            "type": "Account",
                            "url": "/services/data/v66.0/sobjects/Account/001xx"
                        },
                        "Id": "001xx",
                        "Name": "Acme"
                    },
                    {
                        "attributes": {
                            "type": "Contact",
                            "url": "/services/data/v66.0/sobjects/Contact/003yy"
                        },
                        "Id": "003yy",
                        "Name": "Acme Smith"
                    }
                ]
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let result = sf.parameterized_search(&request_body).await.unwrap();
        assert_eq!(result.search_records.len(), 2);
        assert_eq!(result.search_records[0]["attributes"]["type"], "Account");
        assert_eq!(result.search_records[1]["attributes"]["type"], "Contact");
    }

    #[tokio::test]
    async fn parameterized_search_returns_metadata_when_present() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/services/data/v66.0/parameterizedSearch"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "searchRecords": [],
                "metadata": {
                    "entityMetadata": [
                        {"entityName": "Account", "fieldMetadata": [
                            {"name": "Name", "label": "Account Name"}
                        ]}
                    ]
                }
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let result = sf
            .parameterized_search(&json!({"q": "x", "metadata": "LABELS"}))
            .await
            .unwrap();
        let md = result.metadata.expect("metadata present");
        assert!(md["entityMetadata"].is_array());
    }

    #[tokio::test]
    async fn parameterized_search_typed_records() {
        #[derive(serde::Deserialize)]
        struct Hit {
            #[serde(rename = "Id")]
            id: String,
        }

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/services/data/v66.0/parameterizedSearch"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "searchRecords": [
                    {"attributes": {"type": "Account"}, "Id": "001xx"}
                ]
            })))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let result = sf
            .parameterized_search_as::<Hit, _>(&json!({"q": "Acme"}))
            .await
            .unwrap();
        assert_eq!(result.search_records[0].id, "001xx");
    }

    #[tokio::test]
    async fn parameterized_search_surfaces_invalid_search_error() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/services/data/v66.0/parameterizedSearch"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!([{
                "message": "Invalid search scope",
                "errorCode": "INVALID_SEARCH_SCOPE"
            }])))
            .mount(&server)
            .await;

        let sf = fixture(server.uri());
        let err = sf
            .parameterized_search(&json!({"q": ""}))
            .await
            .unwrap_err();
        match err {
            crate::CirrusError::Api { status, errors, .. } => {
                assert_eq!(status, 400);
                assert_eq!(errors[0].error_code, "INVALID_SEARCH_SCOPE");
            }
            other => panic!("expected Api error, got {other:?}"),
        }
    }
}
