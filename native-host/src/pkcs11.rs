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
use cryptoki::object::{Attribute, AttributeType, ObjectClass, ObjectHandle};
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

    /// Sign `data` with the private key whose CKA_ID matches `cert_id_hex`.
    /// The PIN is provided by [`crate::pin`].
    ///
    /// The host caches the session for the lifetime of the connection, so the
    /// PIN dialog only appears once per port.
    pub fn sign_digest(
        &self,
        slot_id: u64,
        cert_id_hex: &str,
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
        let template = vec![
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Id(cert_id),
        ];
        let handles = session
            .find_objects(&template)
            .context("find private key for cert id")?;
        let key_handle = handles
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("no private key with the requested CKA_ID"))?;

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
