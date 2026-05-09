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
/// intermediate CAs needed to build a path to (but not including) a
/// self-signed root. The leaf itself is not included, and the self-signed
/// root is deliberately excluded: per RFC 5652 / PAdES, the verifier always
/// anchors trust locally (Adobe AATL or the OS trust store), so embedding
/// the root just bloats the CMS without contributing to verification.
/// Returns owned DER copies.
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
        if parsed.subject().as_raw() == parsed.issuer().as_raw() {
            tracing::debug!(
                "ca_bundle: reached self-signed root; excluding it from chain ({} intermediate link(s))",
                out.len()
            );
            break;
        }

        out.push(der.to_vec());
        current_issuer_der = parsed.issuer().as_raw().to_vec();
    }

    out
}

/// Returns `true` if `der` is a parseable X.509 certificate whose Subject DN
/// equals its Issuer DN (i.e. a self-signed / root certificate). Unparseable
/// input returns `false` so we never accidentally drop something we don't
/// understand.
pub fn is_self_signed(der: &[u8]) -> bool {
    X509Certificate::from_der(der)
        .map(|(_, c)| c.subject().as_raw() == c.issuer().as_raw())
        .unwrap_or(false)
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
    /// CCA India 2022 root, build_chain must return the 2-link intermediate
    /// chain (sub-CA + CA) and stop before the self-signed root.
    #[test]
    fn resolves_emudhra_class3_chain_to_intermediates_excluding_root() {
        let leaf = include_bytes!("test_fixtures/emudhra_leaf_sample.der");
        let chain = build_chain(leaf);

        assert_eq!(
            chain.len(),
            2,
            "expected 2-link chain (sub-CA, CA) with root excluded, got {}",
            chain.len()
        );

        let last = X509Certificate::from_der(&chain[chain.len() - 1])
            .expect("last cert is parseable")
            .1;
        assert_ne!(
            last.subject().as_raw(),
            last.issuer().as_raw(),
            "last cert in chain must NOT be self-signed; the root should be excluded"
        );

        for der in &chain {
            assert!(
                !is_self_signed(der),
                "no cert in the embedded chain may be self-signed"
            );
        }
    }

    #[test]
    fn is_self_signed_detects_root_and_intermediate() {
        let intermediate = include_bytes!("../bundled-cas/emudhra-sub-ca-class3-individual-2022.der");
        let root = include_bytes!("../bundled-cas/cca-india-2022.der");
        assert!(!is_self_signed(intermediate));
        assert!(is_self_signed(root));
        assert!(!is_self_signed(b"not a cert"));
    }
}
