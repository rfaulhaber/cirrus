//! Transport rules shared by every Cirrus crate that talks to
//! Salesforce: the security rule for bearer tokens and the bound on how
//! much of a response body a client buffers. The crates are the OAuth
//! flows in this crate, the REST client and the SOAP Metadata client.
//!
//! RFC 6750 §5.3 requires TLS for every request that carries a bearer
//! token. The one exemption is a loopback host, where the hop never
//! leaves the machine, so local mock servers work without certificates.
//! That holds only for a client that uses no proxy, which is why every
//! client the crates build is created with `no_proxy()` rather than
//! reqwest's default of obeying `HTTP_PROXY` and the system proxy; the
//! REST and Metadata clients withdraw the exemption again when a proxy
//! is configured on their builders, through [`is_secure_transport_for`].
//! Defining the rule once keeps the clients from disagreeing about which
//! URLs qualify.
//!
//! Every client the workspace builds decodes gzip responses, so a body's
//! size on the wire says nothing about the memory it needs: a few
//! megabytes of gzip inflate a thousandfold. [`collect_body`] reads a
//! body under a limit on its decoded size, and every client reads
//! responses through it for the same reason the loopback rule is shared.
//!
//! The default TLS backend trusts the operating system's roots and
//! refuses to build a client when it finds none. [`merge_bundled_roots`]
//! is where the `bundled-roots` feature adds Mozilla's set alongside
//! them, and every default client passes through it, so the feature
//! behaves the same on every crate.

use bytes::{Bytes, BytesMut};

/// Whether `url` names a loopback host: the exact name `localhost` in any
/// case, or an IPv4 / IPv6 loopback literal.
///
/// Other names under `.localhost` do not qualify. RFC 6761 only says that
/// resolvers SHOULD treat them as loopback, and common stacks (glibc
/// without nss-myhostname, macOS) forward them to DNS, where a wildcard
/// or spoofed answer could send the token off-machine.
pub fn is_loopback_host(url: &url::Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// Whether a bearer token may be sent to `url` by a client that uses no
/// proxy: the scheme is `https`, or the host is loopback (see
/// [`is_loopback_host`]). [`is_secure_transport_for`] is the same rule
/// for a client that may route through a proxy.
pub fn is_secure_transport(url: &url::Url) -> bool {
    is_secure_transport_for(url, false)
}

/// Whether a bearer token may be sent to `url` by a client that routes
/// through a proxy when `proxied`: `https` always, and a loopback host
/// only when `proxied` is false, since the hop then leaves the machine
/// for the proxy. The REST and Metadata clients apply this with the
/// proxy their builders installed.
pub fn is_secure_transport_for(url: &url::Url, proxied: bool) -> bool {
    url.scheme() == "https" || (!proxied && is_loopback_host(url))
}

/// Adds Mozilla's root certificates to the trust store of the client
/// `builder` will create, alongside whatever the platform supplies, when
/// the crate's `bundled-roots` feature is on. Without the feature the
/// builder is returned unchanged.
///
/// The default TLS backend verifies against the operating system's
/// store and refuses to build a client when that store is empty, as it
/// is in a `FROM scratch` image or a build sandbox without
/// `ca-certificates`. Every client the Cirrus crates build passes
/// through here, so enabling the feature on whichever crate is in use is
/// enough for the clients it builds. A client supplied through an
/// `http_client` setter is its owner's and gets its roots from
/// `reqwest::ClientBuilder::tls_certs_merge` instead.
pub fn merge_bundled_roots(builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
    #[cfg(feature = "bundled-roots")]
    {
        // The bundle is well-formed DER, so `from_der` can only fail
        // where a backend rejects a root it cannot use; dropping that
        // root is better than failing every client over it.
        builder.tls_certs_merge(
            webpki_root_certs::TLS_SERVER_ROOT_CERTS
                .iter()
                .filter_map(|der| reqwest::Certificate::from_der(der).ok()),
        )
    }
    #[cfg(not(feature = "bundled-roots"))]
    builder
}

/// Why [`collect_body`] did not return a body.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CollectBodyError {
    /// The body failed in transport: a connection reset, a timeout
    /// between chunks, or content that does not decode. The cause is the
    /// [`source()`](std::error::Error::source).
    #[error("failed to read the response body")]
    Transport(#[source] reqwest::Error),

    /// The decoded body is longer than the limit. Nothing past the limit
    /// was buffered.
    #[error("response body exceeded the {limit}-byte limit")]
    TooLarge {
        /// The limit that was exceeded, in decoded bytes.
        limit: usize,
    },
}

/// Collects a response body, refusing to buffer more than `limit` bytes
/// of the decoded stream.
///
/// The limit counts decoded bytes, not bytes on the wire. The clients
/// the SDK builds decode gzip transparently, and a small compressed body
/// can inflate a thousandfold, so a limit on the encoded size would not
/// bound memory. A body is refused as soon as the chunk that would push
/// it past `limit` arrives, without storing that chunk; a body of
/// exactly `limit` bytes is accepted. Pass `usize::MAX` for no limit.
///
/// The chunks are joined once at the end into a buffer of the exact
/// size, so a collected body costs one copy of its length and no
/// growth-doubling. A body that arrives as a single chunk is returned
/// without a copy.
pub async fn collect_body(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<Bytes, CollectBodyError> {
    let mut chunks: Vec<Bytes> = Vec::new();
    let mut total: usize = 0;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(CollectBodyError::Transport)?
    {
        total = match total.checked_add(chunk.len()) {
            Some(next) if next <= limit => next,
            _ => return Err(CollectBodyError::TooLarge { limit }),
        };
        chunks.push(chunk);
    }
    if chunks.len() <= 1 {
        return Ok(chunks.pop().unwrap_or_default());
    }
    let mut body = BytesMut::with_capacity(total);
    for chunk in &chunks {
        body.extend_from_slice(chunk);
    }
    Ok(body.freeze())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn parse(s: &str) -> url::Url {
        url::Url::parse(s).unwrap()
    }

    #[test]
    fn https_is_secure_for_any_host() {
        assert!(is_secure_transport(&parse(
            "https://my-org.my.salesforce.com"
        )));
        assert!(is_secure_transport(&parse("https://192.0.2.1")));
    }

    #[test]
    fn exact_localhost_and_loopback_literals_are_loopback() {
        for u in [
            "http://localhost:8080",
            "http://LOCALHOST",
            "http://127.0.0.1:1234",
            "http://127.1.2.3",
            "http://127.255.0.1",
            "http://[::1]:8080",
        ] {
            let url = parse(u);
            assert!(is_loopback_host(&url), "{u}");
            assert!(is_secure_transport(&url), "{u}");
        }
    }

    #[test]
    fn dotted_localhost_names_and_other_hosts_are_not_loopback() {
        // Names that merely start or end with `localhost`, and private or
        // documentation addresses, are off-machine as far as the rule is
        // concerned.
        for u in [
            "http://sf.localhost:8080",
            "http://api.localhost",
            "http://localhost.evil.example",
            "http://notlocalhost",
            "http://my-org.my.salesforce.com",
            "http://192.0.2.1",
            "http://203.0.113.7",
            "http://10.0.0.1",
            "http://[fe80::1]",
            "http://[2001:db8::1]",
        ] {
            let url = parse(u);
            assert!(!is_loopback_host(&url), "{u}");
            assert!(!is_secure_transport(&url), "{u}");
        }
    }

    #[test]
    fn a_proxied_client_loses_the_loopback_exemption_but_not_https() {
        assert!(is_secure_transport_for(
            &parse("http://localhost:8080"),
            false
        ));
        assert!(!is_secure_transport_for(
            &parse("http://localhost:8080"),
            true
        ));
        assert!(!is_secure_transport_for(&parse("http://[::1]"), true));
        assert!(is_secure_transport_for(&parse("https://192.0.2.1"), true));
        assert!(!is_secure_transport_for(&parse("http://192.0.2.1"), true));
    }

    #[test]
    fn a_url_without_a_host_is_not_loopback() {
        assert!(!is_loopback_host(&parse("mailto:someone@example.com")));
        assert!(!is_secure_transport(&parse("mailto:someone@example.com")));
    }

    mod collect {
        use super::super::*;
        use std::io::Write;
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        async fn fetch(template: ResponseTemplate) -> (MockServer, reqwest::Response) {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .respond_with(template)
                .mount(&server)
                .await;
            // Decodes gzip and uses no proxy, like every client the SDK
            // builds.
            let response = reqwest::Client::builder()
                .no_proxy()
                .build()
                .unwrap()
                .get(server.uri())
                .send()
                .await
                .unwrap();
            (server, response)
        }

        #[tokio::test]
        async fn a_body_one_byte_over_the_limit_is_refused() {
            let (_server, response) =
                fetch(ResponseTemplate::new(200).set_body_bytes(vec![b'x'; 1025])).await;
            let err = collect_body(response, 1024).await.unwrap_err();
            assert!(
                matches!(err, CollectBodyError::TooLarge { limit: 1024 }),
                "{err:?}"
            );
        }

        #[tokio::test]
        async fn a_body_of_exactly_the_limit_is_returned_whole() {
            let (_server, response) =
                fetch(ResponseTemplate::new(200).set_body_bytes(vec![b'x'; 1024])).await;
            let body = collect_body(response, 1024).await.unwrap();
            assert_eq!(body.as_ref(), vec![b'x'; 1024].as_slice());
        }

        #[tokio::test]
        async fn a_gzip_body_is_limited_by_its_decoded_size() {
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
            encoder.write_all(&vec![0u8; 8 << 20]).unwrap();
            let wire = encoder.finish().unwrap();
            assert!(wire.len() < 64 * 1024, "wire size {}", wire.len());

            let (_server, response) = fetch(
                ResponseTemplate::new(200)
                    .insert_header("content-encoding", "gzip")
                    .set_body_bytes(wire),
            )
            .await;
            let err = collect_body(response, 64 * 1024).await.unwrap_err();
            assert!(
                matches!(err, CollectBodyError::TooLarge { limit } if limit == 64 * 1024),
                "{err:?}"
            );
        }

        #[tokio::test]
        async fn a_multi_chunk_body_round_trips_byte_exact() {
            // Large enough that the transport delivers it in several
            // chunks, with content that makes a misordered join visible.
            let expected: Vec<u8> = (0..(2 << 20)).map(|i: usize| (i % 251) as u8).collect();
            let (_server, response) =
                fetch(ResponseTemplate::new(200).set_body_bytes(expected.clone())).await;
            let body = collect_body(response, usize::MAX).await.unwrap();
            assert_eq!(body.as_ref(), expected.as_slice());
        }

        #[tokio::test]
        async fn an_empty_body_is_an_empty_buffer() {
            let (_server, response) = fetch(ResponseTemplate::new(204)).await;
            assert!(collect_body(response, 0).await.unwrap().is_empty());
        }
    }
}
