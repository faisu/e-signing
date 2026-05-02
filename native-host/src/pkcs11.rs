//! Thin wrapper around the `cryptoki` crate. Hides the raw PKCS#11 surface
//! from the rest of the host and presents the operations we actually need:
//!
//! - enumerate slots with present tokens
//! - enumerate certificates on a slot
//! - sign a digest with the private key matching a chosen certificate
//!
//! The vendor module path is loaded from [`crate::config::Config`].

use std::path::Path;
use std::sync::Mutex;

use anyhow::{anyhow, bail, Context, Result};
use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SlotInfo {
    pub id: u64,
    pub label: String,
    pub manufacturer: String,
    pub model: String,
    pub serial: String,
    pub token_present: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertInfo {
    /// Hex-encoded CKA_ID. Used by the extension to reference a specific cert.
    pub id: String,
    pub label: String,
    pub subject: String,
    pub issuer: String,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub serial: Option<String>,
    /// Base64-encoded DER. The extension can show fingerprint / chain info.
    pub der_base64: String,
}

/// Per-port handle. Holds the loaded PKCS#11 module and at most one cached
/// authenticated session keyed by slot id.
///
/// `cryptoki::Session` is `Send` but not `Sync`, so we store it directly
/// inside the mutex and run all PKCS#11 calls while holding the lock. The
/// host is intentionally single-threaded, so this never contends.
pub struct Pkcs11Client {
    inner: Pkcs11,
    cached_session: Mutex<Option<CachedSession>>,
}

struct CachedSession {
    slot_id: u64,
    session: Session,
}

impl Pkcs11Client {
    pub fn load(module_path: &Path) -> Result<Self> {
        if !module_path.exists() {
            bail!(
                "PKCS#11 module not found at {} (configure pkcs11_module in config.toml)",
                module_path.display()
            );
        }
        let pkcs11 = Pkcs11::new(module_path)
            .with_context(|| format!("dlopen {}", module_path.display()))?;
        pkcs11
            .initialize(CInitializeArgs::OsThreads)
            .context("C_Initialize failed")?;
        Ok(Self {
            inner: pkcs11,
            cached_session: Mutex::new(None),
        })
    }

    pub fn list_slots(&self) -> Result<Vec<SlotInfo>> {
        let slots = self.inner.get_slots_with_token().context("get_slots")?;
        let mut out = Vec::with_capacity(slots.len());
        for slot in slots {
            let info = self
                .inner
                .get_slot_info(slot)
                .with_context(|| format!("get_slot_info({})", slot.id()))?;
            let token_present = info.token_present();
            let token = self
                .inner
                .get_token_info(slot)
                .with_context(|| format!("get_token_info({})", slot.id()))?;
            out.push(SlotInfo {
                id: slot.id(),
                label: token.label().to_string(),
                manufacturer: token.manufacturer_id().to_string(),
                model: token.model().to_string(),
                serial: token.serial_number().to_string(),
                token_present,
            });
        }
        Ok(out)
    }

    pub fn list_certs(&self, slot_id: u64) -> Result<Vec<CertInfo>> {
        let slot = self.find_slot(slot_id)?;
        let session = self
            .inner
            .open_ro_session(slot)
            .context("open_ro_session for cert listing")?;

        let template = vec![Attribute::Class(ObjectClass::CERTIFICATE)];
        let handles = session
            .find_objects(&template)
            .context("find certificate objects")?;

        let mut out = Vec::with_capacity(handles.len());
        for handle in handles {
            match read_cert(&session, handle) {
                Ok(cert) => out.push(cert),
                Err(e) => tracing::warn!("skipping cert: {e:?}"),
            }
        }
        Ok(out)
    }

    /// Sign `data` with the private key paired to the certificate identified
    /// by `cert_id_hex`. The PIN is provided by [`crate::pin`].
    ///
    /// The host caches the session for the lifetime of the connection, so the
    /// PIN dialog only appears once per port.
    ///
    /// Some tokens (e.g. HYP2003) store the certificate and its private key
    /// with different `CKA_ID` values, so we accept the certificate DER and
    /// fall back to matching by public-key components when the `CKA_ID`
    /// lookup misses.
    pub fn sign_digest(
        &self,
        slot_id: u64,
        cert_id_hex: &str,
        cert_der: &[u8],
        pin: &str,
        mechanism: &Mechanism,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        self.ensure_session(slot_id, pin)?;
        let mut guard = self.cached_session.lock().unwrap();
        let session = &guard
            .as_mut()
            .expect("ensure_session populated cache")
            .session;

        let cert_id = hex::decode(cert_id_hex).context("cert_id is not valid hex")?;
        let key_handle = find_private_key_handle(session, &cert_id, cert_der)?;

        let signature = session
            .sign(mechanism, key_handle, data)
            .context("C_Sign failed")?;
        Ok(signature)
    }

    pub fn cert_der(&self, slot_id: u64, cert_id_hex: &str) -> Result<Vec<u8>> {
        let slot = self.find_slot(slot_id)?;
        let session = self.inner.open_ro_session(slot)?;
        let cert_id = hex::decode(cert_id_hex).context("cert_id is not valid hex")?;
        let template = vec![
            Attribute::Class(ObjectClass::CERTIFICATE),
            Attribute::Id(cert_id),
        ];
        let handles = session.find_objects(&template).context("find_objects")?;
        let handle = handles
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("certificate with requested CKA_ID not found"))?;
        let attrs = session
            .get_attributes(handle, &[AttributeType::Value])
            .context("read CKA_VALUE")?;
        for attr in attrs {
            if let Attribute::Value(v) = attr {
                return Ok(v);
            }
        }
        bail!("certificate object had no CKA_VALUE")
    }

    fn find_slot(&self, slot_id: u64) -> Result<Slot> {
        for slot in self.inner.get_all_slots()? {
            if slot.id() == slot_id {
                return Ok(slot);
            }
        }
        bail!("slot id {slot_id} not present")
    }

    fn ensure_session(&self, slot_id: u64, pin: &str) -> Result<()> {
        let mut cached = self.cached_session.lock().unwrap();
        if let Some(c) = cached.as_ref() {
            if c.slot_id == slot_id {
                return Ok(());
            }
        }

        let slot = self.find_slot(slot_id)?;
        let session = self
            .inner
            .open_rw_session(slot)
            .context("open_rw_session for signing")?;
        session
            .login(UserType::User, Some(&AuthPin::new(pin.into())))
            .context("C_Login (user) failed")?;
        *cached = Some(CachedSession { slot_id, session });
        Ok(())
    }
}

fn read_cert(session: &Session, handle: ObjectHandle) -> Result<CertInfo> {
    let attrs = session
        .get_attributes(
            handle,
            &[
                AttributeType::Id,
                AttributeType::Label,
                AttributeType::Value,
            ],
        )
        .context("get cert attributes")?;

    let mut id: Vec<u8> = Vec::new();
    let mut label: String = String::new();
    let mut der: Vec<u8> = Vec::new();

    for attr in attrs {
        match attr {
            Attribute::Id(v) => id = v,
            Attribute::Label(v) => label = String::from_utf8_lossy(&v).to_string(),
            Attribute::Value(v) => der = v,
            _ => {}
        }
    }

    if der.is_empty() {
        bail!("certificate object had no CKA_VALUE");
    }

    let id_hex = hex::encode(&id);
    let der_b64 = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(&der)
    };

    let (subject, issuer, not_before, not_after, serial) = parse_metadata(&der);

    Ok(CertInfo {
        id: id_hex,
        label,
        subject,
        issuer,
        not_before,
        not_after,
        serial,
        der_base64: der_b64,
    })
}

fn parse_metadata(
    der: &[u8],
) -> (
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
) {
    use x509_parser::prelude::*;
    match X509Certificate::from_der(der) {
        Ok((_, cert)) => (
            cert.subject().to_string(),
            cert.issuer().to_string(),
            Some(cert.validity().not_before.to_string()),
            Some(cert.validity().not_after.to_string()),
            Some(format!("{:x}", cert.serial)),
        ),
        Err(_) => (String::new(), String::new(), None, None, None),
    }
}

/// Resolve the private key paired with the certificate identified by
/// `cert_id`. First attempts the standard `CKA_ID` match, then falls back to
/// matching by public-key components extracted from `cert_der`.
fn find_private_key_handle(
    session: &Session,
    cert_id: &[u8],
    cert_der: &[u8],
) -> Result<ObjectHandle> {
    let by_id = session
        .find_objects(&[
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Id(cert_id.to_vec()),
        ])
        .context("find private key by CKA_ID")?;
    if let Some(handle) = by_id.into_iter().next() {
        return Ok(handle);
    }

    tracing::warn!(
        cert_id_hex = %hex::encode(cert_id),
        "private key CKA_ID does not match certificate; falling back to public-key match"
    );

    use x509_parser::prelude::*;
    use x509_parser::public_key::PublicKey;
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| anyhow!("parse certificate DER for fallback: {e}"))?;
    let parsed = cert
        .public_key()
        .parsed()
        .map_err(|e| anyhow!("parse certificate public key for fallback: {e}"))?;

    let candidates = session
        .find_objects(&[Attribute::Class(ObjectClass::PRIVATE_KEY)])
        .context("enumerate private keys for fallback match")?;
    if candidates.is_empty() {
        bail!("token has no private key objects after login");
    }

    let mut considered: Vec<String> = Vec::with_capacity(candidates.len());
    for handle in &candidates {
        let attrs = match session.get_attributes(
            *handle,
            &[
                AttributeType::KeyType,
                AttributeType::Id,
                AttributeType::Modulus,
                AttributeType::PublicExponent,
                AttributeType::EcPoint,
            ],
        ) {
            Ok(a) => a,
            Err(e) => {
                considered.push(format!("<get_attrs failed: {e}>"));
                continue;
            }
        };

        let mut key_type: Option<KeyType> = None;
        let mut modulus: Vec<u8> = Vec::new();
        let mut exponent: Vec<u8> = Vec::new();
        let mut ec_point: Vec<u8> = Vec::new();
        let mut cka_id_hex = String::new();
        for attr in attrs {
            match attr {
                Attribute::KeyType(k) => key_type = Some(k),
                Attribute::Modulus(v) => modulus = v,
                Attribute::PublicExponent(v) => exponent = v,
                Attribute::EcPoint(v) => ec_point = v,
                Attribute::Id(v) => cka_id_hex = hex::encode(&v),
                _ => {}
            }
        }
        considered.push(format!(
            "{{cka_id={cka_id_hex},key_type={:?}}}",
            key_type
        ));

        let matched = match (&parsed, key_type) {
            (PublicKey::RSA(rsa), Some(kt)) if kt == KeyType::RSA => {
                !modulus.is_empty()
                    && !exponent.is_empty()
                    && strip_leading_zero(rsa.modulus) == strip_leading_zero(&modulus)
                    && strip_leading_zero(rsa.exponent) == strip_leading_zero(&exponent)
            }
            (PublicKey::EC(point), Some(kt)) if kt == KeyType::EC => {
                let needle = point.data();
                !ec_point.is_empty()
                    && !needle.is_empty()
                    && (ec_point.as_slice() == needle
                        || ec_point.windows(needle.len()).any(|w| w == needle))
            }
            _ => false,
        };
        if matched {
            tracing::info!(
                cka_id = %cka_id_hex,
                "private key matched by public-key components"
            );
            return Ok(*handle);
        }
    }

    bail!(
        "no private key matches certificate public key (cert_id={}, considered=[{}])",
        hex::encode(cert_id),
        considered.join(", ")
    )
}

/// Drop a single leading zero byte from a big-endian unsigned integer.
/// ASN.1 INTEGER encodes magnitudes with the high bit set as `0x00 || bytes`
/// to keep them positive; PKCS#11 returns the raw magnitude. Normalize both
/// to the bare big-endian form before comparing.
fn strip_leading_zero(bytes: &[u8]) -> &[u8] {
    if bytes.len() > 1 && bytes[0] == 0 {
        &bytes[1..]
    } else {
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::strip_leading_zero;

    #[test]
    fn strip_leading_zero_removes_single_leading_zero() {
        assert_eq!(strip_leading_zero(&[0x00, 0xff, 0x01]), &[0xff, 0x01]);
    }

    #[test]
    fn strip_leading_zero_preserves_no_leading_zero() {
        assert_eq!(strip_leading_zero(&[0x7f, 0x01]), &[0x7f, 0x01]);
    }

    #[test]
    fn strip_leading_zero_preserves_lone_zero() {
        // A single 0x00 byte represents the integer zero; do not collapse to empty.
        assert_eq!(strip_leading_zero(&[0x00]), &[0x00]);
    }

    #[test]
    fn strip_leading_zero_keeps_only_one() {
        // Only the single ASN.1 INTEGER sign byte is dropped; further leading
        // zeros are part of the magnitude (rare, but handle defensively).
        assert_eq!(
            strip_leading_zero(&[0x00, 0x00, 0xab]),
            &[0x00, 0xab]
        );
    }

    #[test]
    fn strip_leading_zero_handles_empty() {
        assert_eq!(strip_leading_zero(&[]), &[] as &[u8]);
    }
}
