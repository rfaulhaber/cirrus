//! The JWT assertions this crate signs and the RSA key material behind
//! them: the RFC 7523 bearer assertion the JWT Bearer flow exchanges for
//! a token, and the `client_assertion` with which the refresh and
//! web-server grants authenticate the client without its consumer secret.

use crate::error::{AuthError, AuthResult};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use camino::Utf8Path;
use jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};

/// The one `client_assertion_type` Salesforce accepts.
pub(crate) const CLIENT_ASSERTION_TYPE_JWT_BEARER: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// Validity window of every assertion, in seconds.
///
/// A signed assertion is a bearer credential in flight, so the window is
/// deliberately short: it only has to cover one token request and its
/// bounded retries. Salesforce bounds it from above too: a
/// `client_assertion` must expire "within 5 minutes", and the JWT Bearer
/// flow's sample sets `exp` to now plus 300 seconds while the page allows
/// "a 3-minute buffer for clock skew" past `exp`. 170 seconds therefore
/// tolerates a host clock about two minutes ahead of Salesforce's, and
/// the grace period one about five and a half minutes behind.
///
/// (<https://help.salesforce.com/s/articleView?id=xcloud.remoteaccess_oauth_web_server_flow.htm&type=5>,
/// <https://help.salesforce.com/s/articleView?id=xcloud.remoteaccess_oauth_jwt_flow.htm&type=5>)
pub(crate) const ASSERTION_VALIDITY_SECS: i64 = 170;

/// The claim set Salesforce reads from both kinds of assertion
/// (RFC 7523 §3).
#[derive(Serialize)]
struct Claims {
    iss: String,
    sub: String,
    aud: String,
    exp: i64,
}

// `iss` is the connected app's consumer key (a credential identifier) and
// `sub` is either the same or the Salesforce username (PII). Redact both
// so a stray `{:?}` in error-handling code never leaks them.
impl std::fmt::Debug for Claims {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Claims")
            .field("iss", &"[redacted]")
            .field("sub", &"[redacted]")
            .field("aud", &self.aud)
            .field("exp", &self.exp)
            .finish()
    }
}

/// The RFC 7523 bearer assertion the JWT Bearer flow exchanges for a
/// token: `iss` is the consumer key, `sub` the username to act as, and
/// `aud` the login host that receives it.
pub(crate) fn bearer_assertion(
    consumer_key: &str,
    username: &str,
    login_url: &str,
    key: &EncodingKey,
) -> AuthResult<String> {
    sign(
        &Claims {
            iss: consumer_key.to_string(),
            sub: username.to_string(),
            aud: login_url.to_string(),
            exp: expiry()?,
        },
        key,
    )
}

/// The `client_assertion` that stands in for `client_secret` on the
/// refresh and authorization-code grants. The Web Server flow page fixes
/// its shape: `iss` and `sub` are both the consumer key, `aud` is the
/// token endpoint itself, and only RS256 is accepted.
pub(crate) fn client_assertion(
    consumer_key: &str,
    login_url: &str,
    key: &EncodingKey,
) -> AuthResult<String> {
    sign(
        &Claims {
            iss: consumer_key.to_string(),
            sub: consumer_key.to_string(),
            aud: format!("{login_url}/services/oauth2/token"),
            exp: expiry()?,
        },
        key,
    )
}

/// `exp` for an assertion signed now.
fn expiry() -> AuthResult<i64> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .map_err(|e| AuthError::Other(format!("system clock before UNIX epoch: {e}")))?;
    Ok(now + ASSERTION_VALIDITY_SECS)
}

/// Produces the compact JWS for `claims` with the aws-lc-rs backend
/// directly.
///
/// `jsonwebtoken::encode` resolves the process-global `CryptoProvider`,
/// and a downstream build that enables both of jsonwebtoken's backend
/// features leaves that provider unusable: its signer panics instead of
/// erroring, which would unwind out of `access_token`. Binding to the one
/// backend this crate compiles against keeps the mint independent of the
/// host application's feature set and of any provider it installs.
fn sign(claims: &Claims, key: &EncodingKey) -> AuthResult<String> {
    let signer = (DEFAULT_PROVIDER.signer_factory)(&Algorithm::RS256, key)
        .map_err(|e| AuthError::Signing(e.to_string()))?;
    let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&Header::new(Algorithm::RS256))?);
    let claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims)?);
    let message = format!("{header}.{claims}");
    let signature = signer
        .try_sign(message.as_bytes())
        .map_err(|e| AuthError::Signing(e.to_string()))?;
    Ok(format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature)))
}

/// Refuses a builder given both a consumer secret and a private key for a
/// `client_assertion`. Salesforce reads the assertion only when no
/// `client_secret` is present, so sending both would silently
/// authenticate with the secret the caller meant to keep off the host.
pub(crate) fn check_client_authentication(
    consumer_secret: Option<&str>,
    private_key: Option<&EncodingKey>,
) -> AuthResult<()> {
    if consumer_secret.is_some() && private_key.is_some() {
        return Err(invalid_private_key(
            "consumer_secret is also set; a grant authenticates the client with one or the \
             other, and Salesforce ignores a client_assertion sent alongside a client_secret",
        ));
    }
    Ok(())
}

/// Labels of the PEM blocks that hold an RSA private key: PKCS#1 and
/// PKCS#8. jsonwebtoken also reads `RSA PUBLIC KEY`, `PUBLIC KEY` and
/// `CERTIFICATE` blocks into an `EncodingKey` and only fails when that
/// key is asked to sign, which would be the first token request.
const PRIVATE_KEY_LABELS: [&str; 2] = ["RSA PRIVATE KEY", "PRIVATE KEY"];

/// Parses an RSA private key from PEM, refusing anything that is not one
/// with [`AuthError::InvalidArgument`] naming the block that was found.
///
/// Only the first block is read, as jsonwebtoken does, so a bundle must
/// put the key before its certificate.
pub(crate) fn private_key_from_pem(pem: &[u8]) -> AuthResult<EncodingKey> {
    match first_pem_label(pem) {
        None => {
            return Err(invalid_private_key(
                "no PEM block found; expected an RSA PRIVATE KEY or PRIVATE KEY block",
            ));
        }
        Some(label) if !PRIVATE_KEY_LABELS.contains(&label) => {
            return Err(invalid_private_key(format!(
                "the PEM begins with a {label} block; expected an RSA PRIVATE KEY or PRIVATE KEY \
                 block (in a bundle, the key must come first)"
            )));
        }
        Some(_) => {}
    }
    EncodingKey::from_rsa_pem(pem)
        .map_err(|e| invalid_private_key(format!("invalid RSA PEM key: {e}")))
}

/// Reads `path` and parses it with [`private_key_from_pem`]. A file that
/// cannot be read is [`AuthError::Other`] carrying the I/O error and the
/// path.
pub(crate) fn private_key_from_pem_file(path: &Utf8Path) -> AuthResult<EncodingKey> {
    let bytes = fs_err::read(path.as_std_path())
        .map_err(|e| AuthError::Other(format!("failed to read private key: {e}")))?;
    private_key_from_pem(&bytes)
}

fn invalid_private_key(reason: impl Into<String>) -> AuthError {
    AuthError::InvalidArgument {
        name: "private_key",
        reason: reason.into(),
    }
}

/// The label of the first `-----BEGIN label-----` line in `pem`.
fn first_pem_label(pem: &[u8]) -> Option<&str> {
    const BEGIN: &str = "-----BEGIN ";
    let text = std::str::from_utf8(pem).ok()?;
    let rest = &text[text.find(BEGIN)? + BEGIN.len()..];
    Some(rest[..rest.find("-----")?].trim())
}
