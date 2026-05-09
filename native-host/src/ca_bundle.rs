//! Compile-time CA bundle for chain building.
//!
//! Indian DSC tokens (HYP2003 etc.) typically only carry the leaf certificate,
//! so Adobe can't build a trust chain from the embedded CMS alone. We embed
//! well-known intermediate and root CAs (eMudhra, etc.) at compile time and
//! resolve the chain by walking issuer→subject Distinguished Names.
//!
//! Drop CA cert files (`.der`, `.cer`, or `.crt` — DER-encoded) into
//! `native-host/bundled-cas/` and rebuild. `build.rs` discovers them and emits
//! a static slice of byte references.

use std::collections::HashSet;

use x509_parser::prelude::*;

include!(concat!(env!("OUT_DIR"), "/ca_bundle_data.rs"));

/// Walk the certificate chain starting from `leaf_der`, returning the
/// intermediates (and root, if present in the bundle) up to a self-signed
/// certificate. The leaf itself is not included. Returns owned DER copies.
pub fn build_chain(leaf_der: &[u8]) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut visited: HashSet<Vec<u8>> = HashSet::new();

    let mut current_issuer_der: Vec<u8> = match X509Certificate::from_der(leaf_der) {
        Ok((_, c)) => c.issuer().as_raw().to_vec(),
        Err(e) => {
            tracing::warn!(error = %e, "ca_bundle: leaf cert is not parseable; chain skipped");
            return out;
        }
    };

    loop {
        if !visited.insert(current_issuer_der.clone()) {
            tracing::warn!("ca_bundle: chain cycle detected; stopping");
            break;
        }

        let next = BUNDLED_CA_DERS.iter().find(|der| {
            X509Certificate::from_der(der)
                .map(|(_, c)| c.subject().as_raw() == current_issuer_der.as_slice())
                .unwrap_or(false)
        });

        let Some(der) = next else {
            tracing::debug!(
                "ca_bundle: no bundled cert matches issuer; chain ends with {} link(s)",
                out.len()
            );
            break;
        };

        let (_, parsed) = X509Certificate::from_der(der).expect("rechecked above");
        let is_self_signed = parsed.subject().as_raw() == parsed.issuer().as_raw();
        out.push(der.to_vec());

        if is_self_signed {
            break;
        }
        current_issuer_der = parsed.issuer().as_raw().to_vec();
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_bundle_returns_empty_chain_for_unknown_issuer() {
        // A clearly invalid DER yields an empty chain rather than panicking.
        assert!(build_chain(&[0u8; 16]).is_empty());
    }

    #[test]
    fn bundle_compiles_even_when_empty() {
        // BUNDLED_CA_DERS may legitimately be empty in dev environments; just
        // make sure indexing doesn't blow up.
        let _ = BUNDLED_CA_DERS.len();
    }

    /// Fixture is the leaf cert pulled from a real signed-KG.pdf signed by an
    /// eMudhra Class 3 Individual DSC. With the bundled eMudhra Sub CA, CA, and
    /// CCA India 2022 root, build_chain must return the 3-link chain ending at
    /// the self-signed root.
    #[test]
    fn resolves_emudhra_class3_chain_to_self_signed_root() {
        let leaf = include_bytes!("test_fixtures/emudhra_leaf_sample.der");
        let chain = build_chain(leaf);

        assert_eq!(
            chain.len(),
            3,
            "expected 3-link chain (sub-CA, CA, root), got {}",
            chain.len()
        );

        let last = X509Certificate::from_der(&chain[chain.len() - 1])
            .expect("root is parseable")
            .1;
        assert_eq!(
            last.subject().as_raw(),
            last.issuer().as_raw(),
            "last cert in chain must be self-signed (CCA India 2022)"
        );
    }
}
