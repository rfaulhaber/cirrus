//! Transport-security rules for bearer tokens, shared by every Cirrus
//! crate that sends one: the OAuth flows in this crate, the REST client
//! and the SOAP Metadata client.
//!
//! RFC 6750 §5.3 requires TLS for every request that carries a bearer
//! token. The one exemption is a loopback host, where the hop never
//! leaves the machine, so local mock servers work without certificates.
//! Defining the rule once keeps the clients from disagreeing about which
//! URLs qualify.

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

/// Whether a bearer token may be sent to `url`: the scheme is `https`,
/// or the host is loopback (see [`is_loopback_host`]).
pub fn is_secure_transport(url: &url::Url) -> bool {
    url.scheme() == "https" || is_loopback_host(url)
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
            "http://[::1]:8080",
        ] {
            let url = parse(u);
            assert!(is_loopback_host(&url), "{u}");
            assert!(is_secure_transport(&url), "{u}");
        }
    }

    #[test]
    fn dotted_localhost_names_and_other_hosts_are_not_loopback() {
        for u in [
            "http://sf.localhost:8080",
            "http://api.localhost",
            "http://my-org.my.salesforce.com",
            "http://192.0.2.1",
            "http://10.0.0.1",
            "http://[fe80::1]",
        ] {
            let url = parse(u);
            assert!(!is_loopback_host(&url), "{u}");
            assert!(!is_secure_transport(&url), "{u}");
        }
    }

    #[test]
    fn a_url_without_a_host_is_not_loopback() {
        assert!(!is_loopback_host(&parse("mailto:someone@example.com")));
        assert!(!is_secure_transport(&parse("mailto:someone@example.com")));
    }
}
