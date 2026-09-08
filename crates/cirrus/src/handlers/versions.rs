//! `GET /services/data` — list of supported Salesforce REST API versions.
//!
//! This is the simplest endpoint Salesforce exposes: it returns a JSON array
//! of [`ApiVersion`] entries describing every API version available on the
//! org. It lives outside the versioned `/services/data/{version}` tree and,
//! per the [Versions] resource reference, needs no authentication —
//! [`Cirrus::versions`] still sends the configured bearer token because it
//! shares the standard send path, so it needs a working credential like any
//! other call. To reach the endpoint before credentials are available, use
//! [`Cirrus::execute`], which sends a caller-built request untouched.
//!
//! [Versions]: https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/resources_versions.htm

use crate::Cirrus;
use crate::error::{CirrusError, CirrusResult};
use crate::response::ApiVersion;

impl Cirrus {
    /// Fetches the list of REST API versions this org supports.
    ///
    /// Calls `GET /services/data` (unversioned). Useful for discovering the
    /// latest available `vNN.N` to use with [`CirrusBuilder::api_version`].
    ///
    /// [`CirrusBuilder::api_version`]: crate::CirrusBuilder::api_version
    pub async fn versions(&self) -> CirrusResult<Vec<ApiVersion>> {
        self.get("/services/data").await
    }

    /// Fetches the version list and returns the highest available
    /// version as a `vNN.N` string suitable for
    /// [`CirrusBuilder::api_version`] (i.e., with the `v` prefix
    /// the rest of the SDK expects).
    ///
    /// Comparison is numeric — sorted by `(major, minor)`, not
    /// lexically. Entries whose `version` isn't a `major.minor` pair are
    /// skipped; if that leaves nothing, this errors with
    /// [`CirrusError::InvalidResponse`] rather than handing back a
    /// version segment the org can't resolve.
    ///
    /// For one-shot bootstrapping at client-construction time, prefer
    /// [`CirrusBuilder::build_with_latest_version`] which combines
    /// these two steps.
    ///
    /// [`CirrusBuilder::api_version`]: crate::CirrusBuilder::api_version
    /// [`CirrusBuilder::build_with_latest_version`]: crate::CirrusBuilder::build_with_latest_version
    pub async fn latest_api_version(&self) -> CirrusResult<String> {
        let list = self.versions().await?;
        let latest = ApiVersion::latest(&list).ok_or_else(|| {
            CirrusError::InvalidResponse("/services/data returned no parseable API versions".into())
        })?;
        Ok(format!("v{}", latest.version))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use crate::Cirrus;
    use crate::auth::StaticTokenAuth;
    use std::sync::Arc;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn versions_returns_parsed_array() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/services/data"))
            .and(header("authorization", "Bearer tok"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"label": "Winter '24", "url": "/services/data/v66.0", "version": "60.0"},
                {"label": "Spring '24", "url": "/services/data/v61.0", "version": "61.0"}
            ])))
            .mount(&server)
            .await;

        let auth = Arc::new(StaticTokenAuth::new("tok", server.uri()));
        let sf = Cirrus::builder().auth(auth).build().unwrap();

        let versions = sf.versions().await.unwrap();
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].version, "60.0");
        assert_eq!(versions[1].label, "Spring '24");
    }

    #[tokio::test]
    async fn versions_surfaces_api_error_array() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/services/data"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!([
                {"message": "Session expired or invalid", "errorCode": "INVALID_SESSION_ID"}
            ])))
            .mount(&server)
            .await;

        let auth = Arc::new(StaticTokenAuth::new("tok", server.uri()));
        let sf = Cirrus::builder().auth(auth).build().unwrap();

        let err = sf.versions().await.unwrap_err();
        match err {
            crate::CirrusError::Api {
                status,
                errors,
                raw,
            } => {
                assert_eq!(status, 401);
                assert_eq!(errors.len(), 1);
                assert_eq!(errors[0].error_code, "INVALID_SESSION_ID");
                assert!(raw.is_none());
            }
            other => panic!("expected Api error, got {other:?}"),
        }
    }

    #[test]
    fn api_version_number_parses_major_minor() {
        let v = crate::ApiVersion {
            label: "Spring '26".into(),
            url: "/services/data/v66.0".into(),
            version: "66.0".into(),
        };
        assert_eq!(v.version_number(), Some((66, 0)));
    }

    #[test]
    fn api_version_number_returns_none_for_malformed() {
        let v = crate::ApiVersion {
            label: "x".into(),
            url: "/services/data/vNaN".into(),
            version: "not-a-version".into(),
        };
        assert_eq!(v.version_number(), None);
    }

    #[test]
    fn latest_picks_highest_by_numeric_not_lexical_ordering() {
        // Lexical ordering would put "9.0" > "60.0" > "10.0" — wrong.
        // Numeric ordering puts 60.0 highest. This is the load-bearing
        // test that catches the most-likely future regression.
        let versions = vec![
            crate::ApiVersion {
                label: "x".into(),
                url: "/x".into(),
                version: "9.0".into(),
            },
            crate::ApiVersion {
                label: "x".into(),
                url: "/x".into(),
                version: "60.0".into(),
            },
            crate::ApiVersion {
                label: "x".into(),
                url: "/x".into(),
                version: "10.0".into(),
            },
        ];
        let latest = crate::ApiVersion::latest(&versions).unwrap();
        assert_eq!(latest.version, "60.0");
    }

    #[test]
    fn latest_returns_none_for_empty_slice() {
        assert!(crate::ApiVersion::latest(&[]).is_none());
    }

    #[test]
    fn latest_skips_unparseable_entries() {
        let versions = vec![
            crate::ApiVersion {
                label: "x".into(),
                url: "/x".into(),
                version: "not-a-version".into(),
            },
            crate::ApiVersion {
                label: "Spring '26".into(),
                url: "/services/data/v66.0".into(),
                version: "66.0".into(),
            },
            crate::ApiVersion {
                label: "y".into(),
                url: "/y".into(),
                version: "latest".into(),
            },
        ];
        let latest = crate::ApiVersion::latest(&versions).unwrap();
        assert_eq!(latest.version, "66.0");
    }

    #[test]
    fn latest_returns_none_when_nothing_parses() {
        let versions = vec![
            crate::ApiVersion {
                label: "x".into(),
                url: "/x".into(),
                version: "not-a-version".into(),
            },
            crate::ApiVersion {
                label: "y".into(),
                url: "/y".into(),
                version: "latest".into(),
            },
        ];
        assert!(crate::ApiVersion::latest(&versions).is_none());
    }

    #[tokio::test]
    async fn latest_api_version_errors_when_no_entry_parses() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/services/data"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"label": "x", "url": "/services/data/latest", "version": "latest"}
            ])))
            .mount(&server)
            .await;

        let auth = Arc::new(StaticTokenAuth::new("tok", server.uri()));
        let sf = Cirrus::builder().auth(auth).build().unwrap();

        match sf.latest_api_version().await.unwrap_err() {
            crate::CirrusError::InvalidResponse(msg) => {
                assert!(msg.contains("no parseable API versions"), "got {msg}");
            }
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn build_with_latest_version_rejects_an_unparseable_version_list() {
        // A garbage version must fail at construction rather than being
        // installed as the client's `vXX.X` path segment.
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/services/data"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"label": "x", "url": "/services/data/latest", "version": "latest"}
            ])))
            .mount(&server)
            .await;

        let auth = Arc::new(StaticTokenAuth::new("tok", server.uri()));
        let err = Cirrus::builder()
            .auth(auth)
            .build_with_latest_version()
            .await
            .unwrap_err();
        assert!(
            matches!(err, crate::CirrusError::InvalidResponse(_)),
            "expected InvalidResponse, got {err:?}"
        );
    }

    #[tokio::test]
    async fn latest_api_version_returns_v_prefixed_highest() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/services/data"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"label": "Winter '24", "url": "/services/data/v66.0", "version": "60.0"},
                {"label": "Spring '26", "url": "/services/data/v66.0", "version": "66.0"},
                {"label": "Summer '25", "url": "/services/data/v64.0", "version": "64.0"}
            ])))
            .mount(&server)
            .await;

        let auth = Arc::new(StaticTokenAuth::new("tok", server.uri()));
        let sf = Cirrus::builder().auth(auth).build().unwrap();

        let latest = sf.latest_api_version().await.unwrap();
        assert_eq!(latest, "v66.0");
    }

    #[tokio::test]
    async fn build_with_latest_version_reconfigures_client() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/services/data"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"label": "Spring '26", "url": "/services/data/v66.0", "version": "66.0"},
                {"label": "Winter '24", "url": "/services/data/v66.0", "version": "60.0"}
            ])))
            .mount(&server)
            .await;

        let auth = Arc::new(StaticTokenAuth::new("tok", server.uri()));
        let sf = Cirrus::builder()
            .auth(auth)
            .build_with_latest_version()
            .await
            .unwrap();
        assert_eq!(sf.api_version(), "v66.0");
        // URL resolution now uses the discovered version.
        let url = sf.resolve_url("limits");
        assert!(url.contains("/v66.0/limits"), "expected v66.0 in {url}");
    }
}
