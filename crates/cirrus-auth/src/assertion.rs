//! RSA key material for the JWT assertions this crate signs.

use crate::error::{AuthError, AuthResult};
use jsonwebtoken::EncodingKey;

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
