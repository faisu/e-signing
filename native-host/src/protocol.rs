//! Wire protocol shared with the Chrome extension.
//!
//! Mirrors the contract previously defined in `native-host/src/shared/protocol.ts`.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const PROTOCOL_VERSION: u32 = 1;

/// Per-message body cap (Chrome's documented native messaging limit).
pub const MAX_NATIVE_MESSAGE_BYTES: usize = 1024 * 1024;

/// Maximum base64 chunk size we emit when streaming PDF output back to the
/// extension. Keep well under [`MAX_NATIVE_MESSAGE_BYTES`] so envelope overhead
/// fits comfortably.
pub const MAX_CHUNK_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HostCmd {
    Ping,
    ListSlots,
    ListCerts,
    SignPdfStart,
    SignPdfChunk,
    SignPdfEnd,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HostEnvelope {
    pub v: u32,
    pub id: String,
    pub cmd: HostCmd,
    #[serde(default)]
    pub payload: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostResponse {
    pub v: u32,
    pub id: String,
    pub ok: bool,
    pub result: Option<Value>,
    pub error: Option<HostError>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostError {
    pub code: String,
    pub message: String,
}

impl HostResponse {
    pub fn success(id: impl Into<String>, result: Value) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            id: id.into(),
            ok: true,
            result: Some(result),
            error: None,
        }
    }

    pub fn failure(
        id: impl Into<String>,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            id: id.into(),
            ok: false,
            result: None,
            error: Some(HostError {
                code: code.into(),
                message: message.into(),
            }),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignPdfStartPayload {
    pub job_id: String,
    #[serde(default)]
    pub file_name: Option<String>,
    pub total_chunks: u32,
    #[serde(default)]
    pub content_type: Option<String>,
    /// Slot id selected by the user when the extension issued [`HostCmd::ListSlots`].
    #[serde(default)]
    pub slot_id: Option<u64>,
    /// Certificate id (CKA_ID, hex-encoded) of the signing key on the slot.
    #[serde(default)]
    pub cert_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignPdfChunkPayload {
    pub job_id: String,
    pub index: u32,
    pub chunk_base64: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignPdfEndPayload {
    pub job_id: String,
}

/// Common error codes emitted by the host. Strings are stable; the extension
/// surfaces them to the page.
pub mod error_code {
    pub const INVALID_JSON: &str = "INVALID_JSON";
    pub const INVALID_PAYLOAD: &str = "INVALID_PAYLOAD";
    pub const MSG_TOO_LARGE: &str = "MSG_TOO_LARGE";
    pub const UNKNOWN_CMD: &str = "UNKNOWN_CMD";
    pub const UNKNOWN_JOB: &str = "UNKNOWN_JOB";
    pub const INVALID_CHUNK_INDEX: &str = "INVALID_CHUNK_INDEX";

    pub const PKCS11_MODULE_NOT_FOUND: &str = "PKCS11_MODULE_NOT_FOUND";
    pub const PKCS11_INIT_FAILED: &str = "PKCS11_INIT_FAILED";
    pub const PKCS11_SLOT_NOT_FOUND: &str = "PKCS11_SLOT_NOT_FOUND";
    pub const PKCS11_LOGIN_FAILED: &str = "PKCS11_LOGIN_FAILED";
    pub const PKCS11_SIGN_FAILED: &str = "PKCS11_SIGN_FAILED";
    pub const CERT_NOT_FOUND: &str = "CERT_NOT_FOUND";
    pub const PIN_CANCELLED: &str = "PIN_CANCELLED";
    pub const PDF_INVALID: &str = "PDF_INVALID";
    pub const CMS_BUILD_FAILED: &str = "CMS_BUILD_FAILED";
}
