//! Command dispatcher. Mirrors the previous TypeScript `handleCommand` in
//! `native-host/src/commands.ts` and adds real PKCS#11-backed implementations
//! for `LIST_SLOTS`, `LIST_CERTS`, and `SIGN_PDF_END`.

use std::collections::HashMap;
use std::sync::Mutex;

use anyhow::Context;
use base64::Engine;
use cryptoki::mechanism::Mechanism;
use serde_json::{json, Value};

use crate::config::{discover_default_module, Config};
use crate::pdf;
use crate::pin;
use crate::pkcs11::Pkcs11Client;
use crate::protocol::{
    error_code as err, HostCmd, HostEnvelope, HostResponse, SignPdfChunkPayload, SignPdfEndPayload,
    SignPdfStartPayload, MAX_CHUNK_BYTES,
};

const HOST_VERSION: &str = env!("CARGO_PKG_VERSION");

struct SignJob {
    total_chunks: u32,
    chunks: Vec<String>,
    slot_id: Option<u64>,
    cert_id: Option<String>,
}

/// Per-port mutable state. Lives for one Chrome native port (one process).
pub struct State {
    config: Config,
    sign_jobs: Mutex<HashMap<String, SignJob>>,
    pkcs11: Mutex<Option<Pkcs11Client>>,
}

impl State {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            sign_jobs: Mutex::new(HashMap::new()),
            pkcs11: Mutex::new(None),
        }
    }

    fn pkcs11_or_load(&self) -> anyhow::Result<()> {
        let mut guard = self.pkcs11.lock().unwrap();
        if guard.is_some() {
            return Ok(());
        }
        let module = self
            .config
            .pkcs11_module
            .clone()
            .or_else(discover_default_module)
            .context("no PKCS#11 module configured and no vendor default detected")?;
        tracing::info!(module = %module.display(), "loading PKCS#11 module");
        let client = Pkcs11Client::load(&module)?;
        *guard = Some(client);
        Ok(())
    }

    fn with_pkcs11<R>(
        &self,
        f: impl FnOnce(&Pkcs11Client) -> anyhow::Result<R>,
    ) -> anyhow::Result<R> {
        self.pkcs11_or_load()?;
        let guard = self.pkcs11.lock().unwrap();
        let client = guard
            .as_ref()
            .expect("pkcs11 client must be loaded after pkcs11_or_load()");
        f(client)
    }
}

pub fn handle(state: &State, env: HostEnvelope) -> Vec<HostResponse> {
    let id = env.id.clone();
    match env.cmd {
        HostCmd::Ping => vec![HostResponse::success(
            id,
            json!({
                "hostVersion": HOST_VERSION,
                "tokenPresent": false,
                "protocolVersion": crate::protocol::PROTOCOL_VERSION,
            }),
        )],
        HostCmd::ListSlots => match state.with_pkcs11(|c| c.list_slots()) {
            Ok(slots) => vec![HostResponse::success(id, json!({ "slots": slots }))],
            Err(e) => {
                tracing::warn!("LIST_SLOTS failed: {e:?}");
                vec![HostResponse::failure(
                    id,
                    err::PKCS11_INIT_FAILED,
                    e.to_string(),
                )]
            }
        },
        HostCmd::ListCerts => {
            let slot_id = match env.payload.get("slotId").and_then(Value::as_u64) {
                Some(s) => s,
                None => {
                    return vec![HostResponse::failure(
                        id,
                        err::INVALID_PAYLOAD,
                        "LIST_CERTS requires payload.slotId",
                    )]
                }
            };
            match state.with_pkcs11(|c| c.list_certs(slot_id)) {
                Ok(certs) => vec![HostResponse::success(id, json!({ "certs": certs }))],
                Err(e) => {
                    tracing::warn!("LIST_CERTS failed: {e:?}");
                    vec![HostResponse::failure(
                        id,
                        err::CERT_NOT_FOUND,
                        e.to_string(),
                    )]
                }
            }
        }
        HostCmd::SignPdfStart => match decode::<SignPdfStartPayload>(&env.payload) {
            Ok(payload) => vec![handle_start(state, &id, payload)],
            Err(e) => vec![HostResponse::failure(id, err::INVALID_PAYLOAD, e)],
        },
        HostCmd::SignPdfChunk => match decode::<SignPdfChunkPayload>(&env.payload) {
            Ok(payload) => vec![handle_chunk(state, &id, payload)],
            Err(e) => vec![HostResponse::failure(id, err::INVALID_PAYLOAD, e)],
        },
        HostCmd::SignPdfEnd => match decode::<SignPdfEndPayload>(&env.payload) {
            Ok(payload) => handle_end(state, &id, payload),
            Err(e) => vec![HostResponse::failure(id, err::INVALID_PAYLOAD, e)],
        },
    }
}

fn decode<T: serde::de::DeserializeOwned>(value: &Value) -> Result<T, String> {
    serde_json::from_value(value.clone()).map_err(|e| e.to_string())
}

fn handle_start(state: &State, id: &str, payload: SignPdfStartPayload) -> HostResponse {
    if payload.job_id.is_empty() || payload.total_chunks == 0 {
        return HostResponse::failure(
            id,
            err::INVALID_PAYLOAD,
            "SIGN_PDF_START requires jobId and totalChunks > 0.",
        );
    }
    let job = SignJob {
        total_chunks: payload.total_chunks,
        chunks: vec![String::new(); payload.total_chunks as usize],
        slot_id: payload.slot_id,
        cert_id: payload.cert_id,
    };
    state
        .sign_jobs
        .lock()
        .unwrap()
        .insert(payload.job_id.clone(), job);

    HostResponse::success(id, json!({ "accepted": true, "jobId": payload.job_id }))
}

fn handle_chunk(state: &State, id: &str, payload: SignPdfChunkPayload) -> HostResponse {
    let mut jobs = state.sign_jobs.lock().unwrap();
    let job = match jobs.get_mut(&payload.job_id) {
        Some(j) => j,
        None => {
            return HostResponse::failure(
                id,
                err::UNKNOWN_JOB,
                "SIGN_PDF_CHUNK received before SIGN_PDF_START.",
            );
        }
    };
    if payload.index >= job.total_chunks {
        return HostResponse::failure(id, err::INVALID_CHUNK_INDEX, "Chunk index is out of range.");
    }
    job.chunks[payload.index as usize] = payload.chunk_base64;
    HostResponse::success(
        id,
        json!({
            "accepted": true,
            "jobId": payload.job_id,
            "index": payload.index,
        }),
    )
}

fn handle_end(state: &State, id: &str, payload: SignPdfEndPayload) -> Vec<HostResponse> {
    let job = state.sign_jobs.lock().unwrap().remove(&payload.job_id);
    let Some(job) = job else {
        return vec![HostResponse::failure(
            id,
            err::UNKNOWN_JOB,
            "SIGN_PDF_END received before SIGN_PDF_START.",
        )];
    };

    let assembled_b64: String = job.chunks.into_iter().collect();
    let pdf_bytes = match base64::engine::general_purpose::STANDARD.decode(&assembled_b64) {
        Ok(b) => b,
        Err(e) => {
            return vec![HostResponse::failure(
                id,
                err::INVALID_PAYLOAD,
                format!("base64 decode failed: {e}"),
            )]
        }
    };

    let signed = match sign_pdf(state, &pdf_bytes, job.slot_id, job.cert_id.as_deref()) {
        Ok(b) => b,
        Err(SignError::Cancelled) => {
            return vec![HostResponse::failure(
                id,
                err::PIN_CANCELLED,
                "User cancelled the PIN prompt.",
            )];
        }
        Err(SignError::Other(code, msg)) => {
            return vec![HostResponse::failure(id, code, msg)];
        }
    };

    let result_b64 = base64::engine::general_purpose::STANDARD.encode(&signed);
    let result_chunks = chunk_string(&result_b64, MAX_CHUNK_BYTES);
    let total = result_chunks.len();

    let mut responses = Vec::with_capacity(total + 1);
    for (i, chunk) in result_chunks.into_iter().enumerate() {
        responses.push(HostResponse::success(
            id,
            json!({
                "resultType": "chunk",
                "jobId": payload.job_id,
                "chunk": chunk,
                "index": i,
                "totalChunks": total,
            }),
        ));
    }
    responses.push(HostResponse::success(
        id,
        json!({ "resultType": "final", "jobId": payload.job_id }),
    ));
    responses
}

#[derive(Debug)]
enum SignError {
    Cancelled,
    Other(&'static str, String),
}

impl From<anyhow::Error> for SignError {
    fn from(e: anyhow::Error) -> Self {
        SignError::Other(err::PKCS11_SIGN_FAILED, e.to_string())
    }
}

fn sign_pdf(
    state: &State,
    pdf_bytes: &[u8],
    slot_id: Option<u64>,
    cert_id: Option<&str>,
) -> Result<Vec<u8>, SignError> {
    let slot_id = slot_id.ok_or_else(|| {
        SignError::Other(
            err::INVALID_PAYLOAD,
            "SIGN_PDF_START.slotId is required".into(),
        )
    })?;
    let cert_id = cert_id.ok_or_else(|| {
        SignError::Other(
            err::INVALID_PAYLOAD,
            "SIGN_PDF_START.certId is required".into(),
        )
    })?;

    let placeholder = pdf::locate_placeholder(pdf_bytes)
        .map_err(|e| SignError::Other(err::PDF_INVALID, e.to_string()))?;

    let pin = if state.config.prompt_pin {
        match pin::prompt_pin("AutoDCR token") {
            Ok(p) => p,
            Err(pin::PinError::Cancelled) => return Err(SignError::Cancelled),
            Err(e) => return Err(SignError::Other(err::PIN_CANCELLED, e.to_string())),
        }
    } else {
        return Err(SignError::Other(
            err::PIN_CANCELLED,
            "prompt_pin disabled in config and no other PIN source is implemented".into(),
        ));
    };

    let cert_der = state
        .with_pkcs11(|c| c.cert_der(slot_id, cert_id))
        .map_err(SignError::from)?;

    let byte_range = pdf::compute_byte_range(pdf_bytes.len(), &placeholder);
    let content_digest = pdf::digest_byte_range(pdf_bytes, &byte_range);

    let cms_der = pdf::build_cms_signature(&content_digest, &cert_der, &[], |signed_attrs_der| {
        state.with_pkcs11(|c| {
            c.sign_digest(
                slot_id,
                cert_id,
                &pin,
                &Mechanism::Sha256RsaPkcs,
                signed_attrs_der,
            )
        })
    })
    .map_err(|e| SignError::Other(err::CMS_BUILD_FAILED, e.to_string()))?;

    let target_width = placeholder.byte_range_end - placeholder.byte_range_start + 1;
    let rendered_byte_range = pdf::render_byte_range(&byte_range, target_width);

    pdf::splice_signature(pdf_bytes, &placeholder, &rendered_byte_range, &cms_der)
        .map_err(|e| SignError::Other(err::PDF_INVALID, e.to_string()))
}

fn chunk_string(s: &str, size: usize) -> Vec<String> {
    if s.is_empty() {
        return vec![String::new()];
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len().div_ceil(size));
    let mut i = 0;
    while i < bytes.len() {
        let end = (i + size).min(bytes.len());
        out.push(std::str::from_utf8(&bytes[i..end]).unwrap().to_string());
        i = end;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> State {
        State::new(Config::default())
    }

    #[test]
    fn ping_returns_host_version() {
        let env = HostEnvelope {
            v: 1,
            id: "abc".into(),
            cmd: HostCmd::Ping,
            payload: Value::Null,
        };
        let r = handle(&state(), env);
        assert_eq!(r.len(), 1);
        assert!(r[0].ok);
        assert_eq!(r[0].id, "abc");
        let result = r[0].result.as_ref().unwrap();
        assert_eq!(result["hostVersion"], HOST_VERSION);
        assert_eq!(result["protocolVersion"], 1);
    }

    #[test]
    fn sign_chunk_without_start_fails() {
        let s = state();
        let env = HostEnvelope {
            v: 1,
            id: "x".into(),
            cmd: HostCmd::SignPdfChunk,
            payload: json!({"jobId": "j1", "index": 0, "chunkBase64": "AA=="}),
        };
        let r = handle(&s, env);
        assert!(!r[0].ok);
        assert_eq!(r[0].error.as_ref().unwrap().code, err::UNKNOWN_JOB);
    }

    #[test]
    fn sign_start_then_chunk_succeeds() {
        let s = state();
        let start = HostEnvelope {
            v: 1,
            id: "1".into(),
            cmd: HostCmd::SignPdfStart,
            payload: json!({
                "jobId": "j1",
                "totalChunks": 2,
                "slotId": 0,
                "certId": "00",
            }),
        };
        let r = handle(&s, start);
        assert!(r[0].ok, "{:?}", r[0].error);

        let chunk = HostEnvelope {
            v: 1,
            id: "2".into(),
            cmd: HostCmd::SignPdfChunk,
            payload: json!({"jobId": "j1", "index": 0, "chunkBase64": "AA=="}),
        };
        let r = handle(&s, chunk);
        assert!(r[0].ok);
    }

    #[test]
    fn chunk_string_under_limit() {
        let parts = chunk_string("hello", 16);
        assert_eq!(parts, vec!["hello".to_string()]);
    }

    #[test]
    fn chunk_string_at_boundary() {
        let parts = chunk_string("aaaabbbb", 4);
        assert_eq!(parts, vec!["aaaa".to_string(), "bbbb".to_string()]);
    }
}
