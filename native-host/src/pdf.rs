//! PDF signing helpers.
//!
//! Strategy:
//! 1. The web app must produce a PDF that already contains a signature
//!    placeholder: a signature dictionary with a `/ByteRange` placeholder of
//!    `[0 ********** ********** **********]` and a fixed-size hex-encoded
//!    `/Contents <00...>` placeholder. This is the standard pattern used by
//!    pdf-lib, iText, etc.
//!
//!    The host expects the placeholder to be present so it can replace exactly
//!    those bytes without re-serialising the PDF document. Re-serialising a
//!    signed PDF with a Rust PDF library round-trips poorly and risks
//!    invalidating other digests.
//!
//! 2. Compute SHA-256 over the four byte ranges (everything except the
//!    `/Contents` hex placeholder). PKCS#1 v1.5 RSA over the
//!    DigestInfo-wrapped SHA-256 digest is the typical PDF signing path; we
//!    expose the raw digest so the caller can pick the mechanism that matches
//!    the token's key.
//!
//! 3. Build a CMS SignedData with the cert chain, digest, and signing time as
//!    signed attributes, then ship the digest of the encoded signedAttrs to
//!    the token for signing.
//!
//! 4. Hex-encode the resulting CMS SignedData DER, pad to the
//!    `/Contents` placeholder length, and splice it back in.

use anyhow::{anyhow, bail, Context, Result};
use sha2::{Digest, Sha256};

/// A located `/ByteRange` and `/Contents` placeholder pair within a PDF.
#[derive(Debug)]
pub struct SignaturePlaceholder {
    /// Offset (within the PDF bytes) of the `[` for the ByteRange array.
    pub byte_range_start: usize,
    /// Offset of the `]` closing the ByteRange array (inclusive).
    pub byte_range_end: usize,
    /// Offset of the opening `<` of the `/Contents` hex string.
    pub contents_open: usize,
    /// Offset of the closing `>` of the `/Contents` hex string.
    pub contents_close: usize,
    /// Number of hex digits between the angle brackets.
    pub contents_hex_len: usize,
}

/// Find the first signature placeholder in the PDF.
///
/// Looks for `/ByteRange [` followed by an array containing zeros or `*`
/// glyphs (typical of pre-flight placeholders) and a paired `/Contents <...>`.
pub fn locate_placeholder(pdf: &[u8]) -> Result<SignaturePlaceholder> {
    let needle = b"/ByteRange";
    let br_idx = find_subsequence(pdf, needle)
        .ok_or_else(|| anyhow!("PDF does not contain a /ByteRange placeholder"))?;

    // Skip whitespace + optional `[`.
    let mut i = br_idx + needle.len();
    while i < pdf.len() && (pdf[i] == b' ' || pdf[i] == b'\r' || pdf[i] == b'\n') {
        i += 1;
    }
    if i >= pdf.len() || pdf[i] != b'[' {
        bail!("/ByteRange not followed by '['");
    }
    let byte_range_start = i;
    let byte_range_end = pdf[i..]
        .iter()
        .position(|&b| b == b']')
        .map(|p| i + p)
        .ok_or_else(|| anyhow!("/ByteRange missing closing ']'"))?;

    // /Contents must follow within a few bytes.
    let after_br = byte_range_end + 1;
    let contents_needle = b"/Contents";
    let rel = find_subsequence(&pdf[after_br..], contents_needle)
        .ok_or_else(|| anyhow!("/Contents placeholder missing"))?;
    let mut j = after_br + rel + contents_needle.len();
    while j < pdf.len() && (pdf[j] == b' ' || pdf[j] == b'\r' || pdf[j] == b'\n') {
        j += 1;
    }
    if j >= pdf.len() || pdf[j] != b'<' {
        bail!("/Contents placeholder is not a hex string");
    }
    let contents_open = j;
    let contents_close = pdf[j + 1..]
        .iter()
        .position(|&b| b == b'>')
        .map(|p| j + 1 + p)
        .ok_or_else(|| anyhow!("/Contents missing closing '>'"))?;

    let contents_hex_len = contents_close - contents_open - 1;
    if contents_hex_len < 64 {
        bail!("/Contents placeholder too small (need at least 32 bytes of signature space)");
    }
    Ok(SignaturePlaceholder {
        byte_range_start,
        byte_range_end,
        contents_open,
        contents_close,
        contents_hex_len,
    })
}

/// Build the canonical four-segment ByteRange covering everything except the
/// `/Contents` hex placeholder. Returns `[off1, len1, off2, len2]`.
pub fn compute_byte_range(pdf_len: usize, ph: &SignaturePlaceholder) -> [usize; 4] {
    let off1 = 0;
    let len1 = ph.contents_open;
    let off2 = ph.contents_close + 1;
    let len2 = pdf_len.saturating_sub(off2);
    [off1, len1, off2, len2]
}

/// Compute SHA-256 over the byte range (skipping the `/Contents` hex bytes).
pub fn digest_byte_range(pdf: &[u8], range: &[usize; 4]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(&pdf[range[0]..range[0] + range[1]]);
    hasher.update(&pdf[range[2]..range[2] + range[3]]);
    hasher.finalize().into()
}

/// Serialise the four-element ByteRange array to the same width as the
/// placeholder so total file length stays identical.
pub fn render_byte_range(range: &[usize; 4], target_width: usize) -> String {
    let raw = format!("[{} {} {} {}]", range[0], range[1], range[2], range[3]);
    if raw.len() == target_width {
        raw
    } else if raw.len() < target_width {
        // Pad with spaces inside the brackets.
        let padding = target_width - raw.len();
        let inner = format!("{} {} {} {}", range[0], range[1], range[2], range[3]);
        let padded = format!("{:<width$}", inner, width = inner.len() + padding);
        format!("[{}]", padded)
    } else {
        raw
    }
}

/// Splice the rendered ByteRange and CMS hex into the PDF, returning the
/// signed bytes.
pub fn splice_signature(
    pdf: &[u8],
    ph: &SignaturePlaceholder,
    rendered_byte_range: &str,
    cms_der: &[u8],
) -> Result<Vec<u8>> {
    let hex_sig = hex::encode_upper(cms_der);
    if hex_sig.len() > ph.contents_hex_len {
        bail!(
            "signature ({} hex bytes) exceeds /Contents placeholder ({} hex bytes); web app must reserve a larger placeholder",
            hex_sig.len(),
            ph.contents_hex_len
        );
    }
    let mut padded = hex_sig;
    padded.extend(std::iter::repeat_n('0', ph.contents_hex_len - padded.len()));

    let mut out = Vec::with_capacity(pdf.len());
    out.extend_from_slice(&pdf[..ph.byte_range_start]);
    out.extend_from_slice(rendered_byte_range.as_bytes());
    let after_br = ph.byte_range_end + 1;
    out.extend_from_slice(&pdf[after_br..ph.contents_open + 1]);
    out.extend_from_slice(padded.as_bytes());
    out.extend_from_slice(&pdf[ph.contents_close..]);
    Ok(out)
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Build a CMS SignedData detached signature.
///
/// We construct the structures by hand instead of using `cms::builder` because
/// the builder is bound to in-process [`signature::keypair::Keypair`] types
/// and we need to delegate signing to an external HSM callback.
///
/// `signer_cert_der` is the DER of the signer certificate (read from the
/// token via PKCS#11). `extra_certs` may include intermediate CA certs.
///
/// `digest_signer` is invoked with the DER of the SignedAttributes and must
/// return the raw signature bytes (RSA PKCS#1 v1.5 over a SHA-256 DigestInfo
/// when using the [`Mechanism::Sha256RsaPkcs`] mechanism).
pub fn build_cms_signature<F>(
    signed_content_digest: &[u8; 32],
    signer_cert_der: &[u8],
    extra_certs: &[Vec<u8>],
    digest_signer: F,
) -> Result<Vec<u8>>
where
    F: FnOnce(&[u8]) -> Result<Vec<u8>>,
{
    use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
    use cms::content_info::{CmsVersion, ContentInfo};
    use cms::signed_data::{
        CertificateSet, EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo,
        SignerInfos,
    };
    use const_oid::db::rfc5911::{
        ID_CONTENT_TYPE, ID_DATA, ID_MESSAGE_DIGEST, ID_SIGNED_DATA, ID_SIGNING_TIME,
    };
    use const_oid::db::rfc5912::{ID_SHA_256, RSA_ENCRYPTION};
    use der::{
        asn1::{OctetString, SetOfVec, UtcTime},
        Any, Decode, Encode,
    };
    use spki::AlgorithmIdentifierOwned;
    use std::time::{Duration, SystemTime};
    use x509_cert::attr::Attribute;
    use x509_cert::time::Time;
    use x509_cert::Certificate;

    let signer_cert =
        Certificate::from_der(signer_cert_der).context("parse signer certificate DER")?;
    let mut chain: Vec<Certificate> = vec![signer_cert.clone()];
    for c in extra_certs {
        let cert = Certificate::from_der(c).context("parse intermediate certificate")?;
        chain.push(cert);
    }

    let digest_alg = AlgorithmIdentifierOwned {
        oid: ID_SHA_256,
        parameters: None,
    };

    // For RSA keys with the Sha256RsaPkcs PKCS#11 mechanism, the token wraps
    // the digest in a DigestInfo and signs with PKCS#1 v1.5. The CMS
    // signatureAlgorithm should advertise rsaEncryption (per RFC 8933).
    let signature_alg = AlgorithmIdentifierOwned {
        oid: RSA_ENCRYPTION,
        parameters: Some(Any::null()),
    };

    let encap = EncapsulatedContentInfo {
        econtent_type: ID_DATA,
        econtent: None,
    };

    let signing_time = {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO);
        let utc = UtcTime::from_unix_duration(now)
            .map_err(|e| anyhow!("UtcTime::from_unix_duration: {e}"))?;
        Time::UtcTime(utc)
    };

    let signed_attrs: SetOfVec<Attribute> = {
        let mut v = Vec::with_capacity(3);
        v.push(make_attr(ID_CONTENT_TYPE, ID_DATA.to_der()?)?);
        v.push(make_attr(
            ID_MESSAGE_DIGEST,
            OctetString::new(signed_content_digest.as_slice())?.to_der()?,
        )?);
        v.push(make_attr(ID_SIGNING_TIME, signing_time.to_der()?)?);
        SetOfVec::try_from(v).map_err(|e| anyhow!("SignedAttributes set: {e}"))?
    };

    // RFC 5652 §5.4: the signature is computed over the DER encoding of the
    // SignedAttributes type with the IMPLICIT [0] tag replaced by SET OF.
    // SetOfVec<Attribute>::to_der() emits the universal SET tag, which is
    // exactly what we need.
    let signed_attrs_der = signed_attrs
        .to_der()
        .map_err(|e| anyhow!("encode signed attrs: {e}"))?;

    let raw_signature = digest_signer(&signed_attrs_der)?;

    let issuer_and_serial = IssuerAndSerialNumber {
        issuer: signer_cert.tbs_certificate.issuer.clone(),
        serial_number: signer_cert.tbs_certificate.serial_number.clone(),
    };

    let signer_info = SignerInfo {
        version: CmsVersion::V1,
        sid: SignerIdentifier::IssuerAndSerialNumber(issuer_and_serial),
        digest_alg: digest_alg.clone(),
        signed_attrs: Some(signed_attrs),
        signature_algorithm: signature_alg,
        signature: OctetString::new(raw_signature)?,
        unsigned_attrs: None,
    };

    let signer_infos = SignerInfos(
        SetOfVec::try_from(vec![signer_info]).map_err(|e| anyhow!("SignerInfos set: {e}"))?,
    );

    let mut cert_set: SetOfVec<CertificateChoices> = SetOfVec::new();
    for cert in chain {
        cert_set
            .insert(CertificateChoices::Certificate(cert))
            .map_err(|e| anyhow!("insert cert into CertificateSet: {e}"))?;
    }

    let digest_algorithms = SetOfVec::try_from(vec![digest_alg])
        .map_err(|e| anyhow!("DigestAlgorithmIdentifiers set: {e}"))?;

    let signed_data = SignedData {
        version: CmsVersion::V1,
        digest_algorithms,
        encap_content_info: encap,
        certificates: Some(CertificateSet(cert_set)),
        crls: None,
        signer_infos,
    };

    let signed_data_any = Any::from_der(&signed_data.to_der()?)?;
    let content_info = ContentInfo {
        content_type: ID_SIGNED_DATA,
        content: signed_data_any,
    };
    let der_bytes = content_info.to_der().context("encode CMS ContentInfo")?;
    Ok(der_bytes)
}

fn make_attr(
    oid: const_oid::ObjectIdentifier,
    value_der: Vec<u8>,
) -> Result<x509_cert::attr::Attribute> {
    use der::{asn1::SetOfVec, Any, Decode};
    use x509_cert::attr::{Attribute, AttributeValue};

    let value = Any::from_der(&value_der).map_err(|e| anyhow!("Any::from_der: {e}"))?;
    let mut values: SetOfVec<AttributeValue> = SetOfVec::new();
    values
        .insert(value)
        .map_err(|e| anyhow!("attribute value insert: {e}"))?;
    Ok(Attribute { oid, values })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locate_placeholder_finds_byte_range() {
        let pdf = b"%PDF-1.7\n/ByteRange [0 1234 5678 9012]\n/Contents <000000000000000000000000000000000000000000000000000000000000000000000000>\nrest";
        let ph = locate_placeholder(pdf).unwrap();
        assert_eq!(ph.contents_hex_len, 72);
        assert!(ph.contents_open < ph.contents_close);
    }

    #[test]
    fn render_byte_range_preserves_width() {
        let r = [0usize, 100, 200, 300];
        let s = render_byte_range(&r, 30);
        assert_eq!(s.len(), 30);
    }
}
