//! Command dispatcher. Mirrors the previous TypeScript `handleCommand` in
//! `native-host/src/commands.ts` and adds real PKCS#11-backed implementations
//! for `LIST_SLOTS`, `LIST_CERTS`, and `SIGN_PDF_END`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Context;
use base64::Engine;
use cryptoki::mechanism::Mechanism;
use serde_json::{json, Value};

use crate::config::{discover_default_module, Config};
use crate::pdf;
use crate::pin;
use crate::pkcs11::{LoginError, Pkcs11Client};
use crate::protocol::{
    error_code as err, HostCmd, HostEnvelope, HostResponse, SignPdfChunkPayload, SignPdfEndPayload,
    SignPdfStartPayload, MAX_CHUNK_BYTES,
};
use crate::token_detection;

const HOST_VERSION: &str = env!("CARGO_PKG_VERSION");
const PKCS11_INIT_TIMEOUT_MARKER: &str = "PKCS11_INIT_TIMEOUT";

struct SignJob {
    total_chunks: u32,
    chunks: Vec<String>,
    slot_id: Option<u64>,
    cert_id: Option<String>,
}

struct Pkcs11LoadOutcome {
    client: Pkcs11Client,
    module: PathBuf,
}

type Pkcs11LoadSlot = Arc<Mutex<Option<Result<Pkcs11LoadOutcome, String>>>>;

/// Per-port mutable state. Lives for one Chrome native port (one process).
pub struct State {
    config: Config,
    sign_jobs: Mutex<HashMap<String, SignJob>>,
    pkcs11: Mutex<Option<Pkcs11Client>>,
    /// Path that `pkcs11_or_load` resolved to. Surfaced via LIST_SLOTS so the
    /// browser-side UI can show which driver is actually loaded.
    pkcs11_module_path: Mutex<Option<PathBuf>>,
    /// In-flight PKCS#11 load shared across concurrent commands.
    pkcs11_load_slot: Mutex<Option<Pkcs11LoadSlot>>,
}

impl State {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            sign_jobs: Mutex::new(HashMap::new()),
            pkcs11: Mutex::new(None),
            pkcs11_module_path: Mutex::new(None),
            pkcs11_load_slot: Mutex::new(None),
        }
    }

    fn resolve_pkcs11_module(&self) -> anyhow::Result<PathBuf> {
        self.config
            .pkcs11_module
            .clone()
            .or_else(discover_default_module)
            .context("no PKCS#11 module configured and no vendor default detected")
    }

    fn pkcs11_init_timeout(&self) -> Duration {
        Duration::from_secs(self.config.pkcs11_init_timeout_secs.max(1))
    }

    fn start_pkcs11_load_if_needed(&self, module: &PathBuf) -> Pkcs11LoadSlot {
        let mut slot_guard = self.pkcs11_load_slot.lock().unwrap();
        if let Some(slot) = slot_guard.as_ref() {
            return slot.clone();
        }

        let slot: Pkcs11LoadSlot = Arc::new(Mutex::new(None));
        let slot_for_thread = slot.clone();
        let module_for_thread = module.clone();
        tracing::info!(module = %module.display(), "loading PKCS#11 module");
        std::thread::spawn(move || {
            let outcome = Pkcs11Client::load(&module_for_thread)
                .map(|client| Pkcs11LoadOutcome {
                    client,
                    module: module_for_thread,
                })
                .map_err(|e| e.to_string());
            *slot_for_thread.lock().unwrap() = Some(outcome);
        });
        *slot_guard = Some(slot.clone());
        slot
    }

    fn pkcs11_or_load_with_timeout(&self, timeout: Duration) -> anyhow::Result<()> {
        if self.pkcs11.lock().unwrap().is_some() {
            tracing::debug!("pkcs11 client already initialized");
            return Ok(());
        }

        let module = self.resolve_pkcs11_module()?;
        let slot = self.start_pkcs11_load_if_needed(&module);
        let deadline = Instant::now() + timeout;

        loop {
            if self.pkcs11.lock().unwrap().is_some() {
                return Ok(());
            }

            if let Some(outcome) = slot.lock().unwrap().take() {
                return match outcome {
                    Ok(loaded) => {
                        tracing::info!(
                            module = %loaded.module.display(),
                            "PKCS#11 module loaded successfully"
                        );
                        *self.pkcs11.lock().unwrap() = Some(loaded.client);
                        *self.pkcs11_module_path.lock().unwrap() = Some(loaded.module);
                        *self.pkcs11_load_slot.lock().unwrap() = None;
                        Ok(())
                    }
                    Err(message) => {
                        *self.pkcs11_load_slot.lock().unwrap() = None;
                        Err(anyhow::anyhow!(message))
                    }
                };
            }

            if Instant::now() >= deadline {
                tracing::warn!(
                    timeout_secs = timeout.as_secs(),
                    module = %module.display(),
                    "PKCS#11 init timed out; driver may be waiting on PCSC/smart-card reader"
                );
                return Err(anyhow::anyhow!(
                    "{PKCS11_INIT_TIMEOUT_MARKER}: PKCS#11 init timed out after {}s (module {}). \
                     The driver may be waiting on the smart-card reader. Re-seat the token, open \
                     the vendor manager app, or restart the smart-card service.",
                    timeout.as_secs(),
                    module.display()
                ));
            }

            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn pkcs11_or_load(&self) -> anyhow::Result<()> {
        self.pkcs11_or_load_with_timeout(self.pkcs11_init_timeout())
    }

    fn pkcs11_load_error_code(message: &str) -> &'static str {
        if message.contains(PKCS11_INIT_TIMEOUT_MARKER) {
            err::PKCS11_INIT_TIMEOUT
        } else {
            err::PKCS11_INIT_FAILED
        }
    }

    pub fn loaded_pkcs11_module(&self) -> Option<PathBuf> {
        self.pkcs11_module_path.lock().unwrap().clone()
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

    fn verify_pin_login(&self, slot_id: u64, pin: &str) -> std::result::Result<(), LoginError> {
        self.pkcs11_or_load()
            .map_err(|e| LoginError::Other(e.to_string()))?;
        let guard = self.pkcs11.lock().unwrap();
        let client = guard
            .as_ref()
            .expect("pkcs11 client must be loaded after pkcs11_or_load()");
        client.verify_login(slot_id, pin)
    }
}

pub fn handle(state: &State, env: HostEnvelope) -> Vec<HostResponse> {
    let id = env.id.clone();
    tracing::debug!(request_id = %id, cmd = ?env.cmd, "dispatching command");
    match env.cmd {
        HostCmd::Ping => {
            let timeout = state.pkcs11_init_timeout();
            let token_present = token_detection::hybrid_token_present(
                || {
                    state.pkcs11_or_load_with_timeout(timeout)?;
                    state.with_pkcs11(|c| {
                        c.list_slots()
                            .map(|slots| slots.iter().any(|s| s.token_present))
                    })
                },
                token_detection::usb_token_hint_present,
            );
            tracing::info!(
                request_id = %id,
                token_present,
                "PING evaluated token presence"
            );
            vec![HostResponse::success(
                id,
                json!({
                    "hostVersion": HOST_VERSION,
                    "tokenPresent": token_present,
                    "protocolVersion": crate::protocol::PROTOCOL_VERSION,
                }),
            )]
        }
        HostCmd::ListUsbTokens => {
            tracing::info!(request_id = %id, "LIST_USB_TOKENS requested");
            match token_detection::list_usb_tokens() {
                Ok(tokens) => {
                    tracing::info!(
                        request_id = %id,
                        token_count = tokens.len(),
                        "LIST_USB_TOKENS succeeded"
                    );
                    vec![HostResponse::success(id, json!({ "tokens": tokens }))]
                }
                Err(e) => {
                    tracing::warn!(request_id = %id, "LIST_USB_TOKENS failed: {e:?}");
                    vec![HostResponse::failure(id, err::USB_ENUM_FAILED, e.to_string())]
                }
            }
        }
        HostCmd::ListSlots => match state.with_pkcs11(|c| c.list_slots()) {
            Ok(slots) => {
                let module_path = state
                    .loaded_pkcs11_module()
                    .map(|p| p.display().to_string());
                let with_token = slots.iter().filter(|s| s.token_present).count();
                tracing::info!(
                    request_id = %id,
                    slot_count = slots.len(),
                    slot_count_with_token = with_token,
                    module = module_path.as_deref().unwrap_or("<unknown>"),
                    "LIST_SLOTS succeeded"
                );
                let usb_hint = token_detection::usb_token_hint_present();
                vec![HostResponse::success(
                    id,
                    json!({
                        "slots": slots,
                        "pkcs11Module": module_path,
                        "usbTokenLikelyPresent": usb_hint,
                    }),
                )]
            }
            Err(e) => {
                let message = e.to_string();
                let code = State::pkcs11_load_error_code(&message);
                tracing::warn!(request_id = %id, error_code = code, "LIST_SLOTS failed: {message}");
                vec![HostResponse::failure(id, code, message)]
            }
        },
        HostCmd::ListCerts => {
            let slot_id = match env.payload.get("slotId").and_then(Value::as_u64) {
                Some(s) => s,
                None => {
                    tracing::warn!(request_id = %id, "LIST_CERTS missing payload.slotId");
                    return vec![HostResponse::failure(
                        id,
                        err::INVALID_PAYLOAD,
                        "LIST_CERTS requires payload.slotId",
                    )]
                }
            };
            tracing::debug!(request_id = %id, slot_id, "LIST_CERTS requested");
            match state.with_pkcs11(|c| c.list_certs(slot_id)) {
                Ok(certs) => {
                    tracing::info!(
                        request_id = %id,
                        slot_id,
                        cert_count = certs.len(),
                        "LIST_CERTS succeeded"
                    );
                    vec![HostResponse::success(id, json!({ "certs": certs }))]
                }
                Err(e) => {
                    tracing::warn!(request_id = %id, slot_id, "LIST_CERTS failed: {e:?}");
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
            Err(e) => {
                tracing::warn!(request_id = %id, error = %e, "SIGN_PDF_START payload decode failed");
                vec![HostResponse::failure(id, err::INVALID_PAYLOAD, e)]
            }
        },
        HostCmd::SignPdfChunk => match decode::<SignPdfChunkPayload>(&env.payload) {
            Ok(payload) => vec![handle_chunk(state, &id, payload)],
            Err(e) => {
                tracing::warn!(request_id = %id, error = %e, "SIGN_PDF_CHUNK payload decode failed");
                vec![HostResponse::failure(id, err::INVALID_PAYLOAD, e)]
            }
        },
        HostCmd::SignPdfEnd => match decode::<SignPdfEndPayload>(&env.payload) {
            Ok(payload) => handle_end(state, &id, payload),
            Err(e) => {
                tracing::warn!(request_id = %id, error = %e, "SIGN_PDF_END payload decode failed");
                vec![HostResponse::failure(id, err::INVALID_PAYLOAD, e)]
            }
        },
    }
}

fn decode<T: serde::de::DeserializeOwned>(value: &Value) -> Result<T, String> {
    serde_json::from_value(value.clone()).map_err(|e| e.to_string())
}

fn handle_start(state: &State, id: &str, payload: SignPdfStartPayload) -> HostResponse {
    if payload.job_id.is_empty() || payload.total_chunks == 0 {
        tracing::warn!(
            request_id = %id,
            job_id = %payload.job_id,
            total_chunks = payload.total_chunks,
            "SIGN_PDF_START rejected due to invalid payload"
        );
        return HostResponse::failure(
            id,
            err::INVALID_PAYLOAD,
            "SIGN_PDF_START requires jobId and totalChunks > 0.",
        );
    }
    tracing::info!(
        request_id = %id,
        job_id = %payload.job_id,
        total_chunks = payload.total_chunks,
        slot_id = ?payload.slot_id,
        cert_id_present = payload.cert_id.is_some(),
        cert_id_len = payload.cert_id.as_ref().map(|v| v.len()).unwrap_or_default(),
        cert_id_preview = payload
            .cert_id
            .as_deref()
            .map(|v| preview_head_tail(v, 8, 8))
            .unwrap_or_else(|| "none".to_string()),
        "SIGN_PDF_START accepted"
    );
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
    let active_jobs = state.sign_jobs.lock().unwrap().len();
    tracing::debug!(request_id = %id, active_jobs, "sign job registered");

    HostResponse::success(id, json!({ "accepted": true, "jobId": payload.job_id }))
}

fn handle_chunk(state: &State, id: &str, payload: SignPdfChunkPayload) -> HostResponse {
    let mut jobs = state.sign_jobs.lock().unwrap();
    let job = match jobs.get_mut(&payload.job_id) {
        Some(j) => j,
        None => {
            tracing::warn!(
                request_id = %id,
                job_id = %payload.job_id,
                index = payload.index,
                "SIGN_PDF_CHUNK received for unknown job"
            );
            return HostResponse::failure(
                id,
                err::UNKNOWN_JOB,
                "SIGN_PDF_CHUNK received before SIGN_PDF_START.",
            );
        }
    };
    if payload.index >= job.total_chunks {
        tracing::warn!(
            request_id = %id,
            job_id = %payload.job_id,
            index = payload.index,
            total_chunks = job.total_chunks,
            "SIGN_PDF_CHUNK index out of range"
        );
        return HostResponse::failure(id, err::INVALID_CHUNK_INDEX, "Chunk index is out of range.");
    }
    tracing::debug!(
        request_id = %id,
        job_id = %payload.job_id,
        index = payload.index,
        total_chunks = job.total_chunks,
        chunk_base64_len = payload.chunk_base64.len(),
        "SIGN_PDF_CHUNK accepted"
    );
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
    tracing::info!(request_id = %id, job_id = %payload.job_id, "SIGN_PDF_END received");
    let job = state.sign_jobs.lock().unwrap().remove(&payload.job_id);
    let Some(job) = job else {
        tracing::warn!(
            request_id = %id,
            job_id = %payload.job_id,
            "SIGN_PDF_END received for unknown job"
        );
        return vec![HostResponse::failure(
            id,
            err::UNKNOWN_JOB,
            "SIGN_PDF_END received before SIGN_PDF_START.",
        )];
    };
    tracing::debug!(
        request_id = %id,
        job_id = %payload.job_id,
        slot_id = ?job.slot_id,
        cert_id_present = job.cert_id.is_some(),
        cert_id_len = job.cert_id.as_ref().map(|v| v.len()).unwrap_or_default(),
        cert_id_preview = job
            .cert_id
            .as_deref()
            .map(|v| preview_head_tail(v, 8, 8))
            .unwrap_or_else(|| "none".to_string()),
        "SIGN_PDF_END using job signing context"
    );

    let missing_chunks: Vec<usize> = job
        .chunks
        .iter()
        .enumerate()
        .filter_map(|(index, chunk)| if chunk.is_empty() { Some(index) } else { None })
        .collect();
    if !missing_chunks.is_empty() {
        tracing::warn!(
            request_id = %id,
            job_id = %payload.job_id,
            total_chunks = job.total_chunks,
            missing_chunk_count = missing_chunks.len(),
            missing_chunk_preview = ?missing_chunks.iter().take(10).collect::<Vec<_>>(),
            "SIGN_PDF_END received with missing chunks; assembled payload may be invalid"
        );
    }

    let assembled_b64: String = job.chunks.into_iter().collect();
    tracing::debug!(
        request_id = %id,
        job_id = %payload.job_id,
        total_chunks = job.total_chunks,
        assembled_base64_len = assembled_b64.len(),
        "assembled SIGN_PDF_END payload"
    );
    let pdf_bytes = match base64::engine::general_purpose::STANDARD.decode(&assembled_b64) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(
                request_id = %id,
                job_id = %payload.job_id,
                error = %e,
                "SIGN_PDF_END base64 decode failed"
            );
            return vec![HostResponse::failure(
                id,
                err::INVALID_PAYLOAD,
                format!("base64 decode failed: {e}"),
            )]
        }
    };
    tracing::info!(
        request_id = %id,
        job_id = %payload.job_id,
        pdf_bytes = pdf_bytes.len(),
        "SIGN_PDF_END decoded PDF payload"
    );

    let signed = match sign_pdf(state, &pdf_bytes, job.slot_id, job.cert_id.as_deref()) {
        Ok(b) => b,
        Err(SignError::Cancelled) => {
            tracing::info!(
                request_id = %id,
                job_id = %payload.job_id,
                "SIGN_PDF_END cancelled by user"
            );
            return vec![HostResponse::failure(
                id,
                err::PIN_CANCELLED,
                "User cancelled the PIN prompt.",
            )];
        }
        Err(SignError::Other(code, msg)) => {
            tracing::warn!(
                request_id = %id,
                job_id = %payload.job_id,
                slot_id = ?job.slot_id,
                cert_id_present = job.cert_id.is_some(),
                cert_id_len = job.cert_id.as_ref().map(|v| v.len()).unwrap_or_default(),
                cert_id_preview = job
                    .cert_id
                    .as_deref()
                    .map(|v| preview_head_tail(v, 8, 8))
                    .unwrap_or_else(|| "none".to_string()),
                error_code = code,
                "SIGN_PDF_END signing failed: {msg}"
            );
            return vec![HostResponse::failure(id, code, msg)];
        }
    };

    let result_b64 = base64::engine::general_purpose::STANDARD.encode(&signed);
    let result_chunks = chunk_string(&result_b64, MAX_CHUNK_BYTES);
    let total = result_chunks.len();
    tracing::info!(
        request_id = %id,
        job_id = %payload.job_id,
        signed_pdf_bytes = signed.len(),
        result_base64_len = result_b64.len(),
        total_chunks = total,
        "SIGN_PDF_END produced signed output"
    );

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
    tracing::debug!(
        pdf_bytes = pdf_bytes.len(),
        slot_id = ?slot_id,
        cert_id_present = cert_id.is_some(),
        cert_id_len = cert_id.map(str::len).unwrap_or_default(),
        "sign_pdf started"
    );
    let slot_id = slot_id.ok_or_else(|| {
        SignError::Other(
            err::INVALID_PAYLOAD,
            "SIGN_PDF_START.slotId is required".into(),
        )
    })?;
    tracing::debug!(slot_id, "sign_pdf using slot");
    let cert_id = cert_id.ok_or_else(|| {
        SignError::Other(
            err::INVALID_PAYLOAD,
            "SIGN_PDF_START.certId is required".into(),
        )
    })?;
    tracing::debug!(slot_id, cert_id_len = cert_id.len(), "sign_pdf using certificate id");

    let pin = if state.config.prompt_pin {
        tracing::debug!("prompting user for token PIN with verification");
        match pin::prompt_and_verify_pin("AutoDCR token", 3, |p| {
            state.verify_pin_login(slot_id, p)
        }) {
            Ok(p) => p,
            Err(pin::PinError::Cancelled) => return Err(SignError::Cancelled),
            Err(pin::PinError::Incorrect) => {
                return Err(SignError::Other(
                    err::PIN_INCORRECT,
                    "Incorrect DSC PIN.".into(),
                ));
            }
            Err(pin::PinError::Locked) => {
                return Err(SignError::Other(
                    err::PIN_LOCKED,
                    "DSC token PIN is locked.".into(),
                ));
            }
            Err(e) => return Err(SignError::Other(err::PIN_CANCELLED, e.to_string())),
        }
    } else {
        return Err(SignError::Other(
            err::PIN_CANCELLED,
            "prompt_pin disabled in config and no other PIN source is implemented".into(),
        ));
    };
    tracing::debug!("PIN verified successfully");

    tracing::debug!(
        pdf_head_preview = %String::from_utf8_lossy(
            &pdf_bytes[..pdf_bytes.len().min(256)]
        ),
        contains_byte_range_token = pdf_bytes
            .windows(b"/ByteRange".len())
            .any(|window| window == b"/ByteRange"),
        contains_contents_token = pdf_bytes
            .windows(b"/Contents".len())
            .any(|window| window == b"/Contents"),
        "sign_pdf inspecting PDF placeholder markers"
    );

    let placeholder = pdf::locate_placeholder(pdf_bytes)
        .map_err(|e| SignError::Other(err::PDF_INVALID, e.to_string()))?;
    tracing::debug!(
        slot_id,
        byte_range_start = placeholder.byte_range_start,
        byte_range_end = placeholder.byte_range_end,
        "pdf placeholder located"
    );

    let cert_der = state
        .with_pkcs11(|c| c.cert_der(slot_id, cert_id))
        .map_err(SignError::from)?;
    tracing::debug!(
        slot_id,
        cert_der_bytes = cert_der.len(),
        "certificate DER loaded from token"
    );

    let from_token: Vec<Vec<u8>> = match state.with_pkcs11(|c| c.all_cert_ders(slot_id)) {
        Ok(all) => all
            .into_iter()
            .filter(|der| der.as_slice() != cert_der.as_slice())
            .collect(),
        Err(e) => {
            tracing::warn!(
                slot_id,
                error = %e,
                "could not enumerate token certificates for chain embedding; will rely on bundle only"
            );
            Vec::new()
        }
    };
    let from_bundle = crate::ca_bundle::build_chain(&cert_der);

    let mut extra_certs: Vec<Vec<u8>> = Vec::with_capacity(from_token.len() + from_bundle.len());
    let mut seen: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
    seen.insert(cert_der.clone());
    let mut dropped_roots: usize = 0;
    for der in from_token.iter().chain(from_bundle.iter()) {
        if !seen.insert(der.clone()) {
            continue;
        }
        // Self-signed roots add ~1.3 KB of CMS without affecting verification
        // (Adobe / OS trust stores anchor on the root locally), and they push
        // many real-world placeholders over their reserved size. Drop them.
        if crate::ca_bundle::is_self_signed(der) {
            dropped_roots += 1;
            continue;
        }
        extra_certs.push(der.clone());
    }
    tracing::info!(
        slot_id,
        from_token = from_token.len(),
        from_bundle = from_bundle.len(),
        extra_cert_count = extra_certs.len(),
        dropped_roots,
        "embedding intermediate certificates into CMS"
    );

    let byte_range = pdf::compute_byte_range(pdf_bytes.len(), &placeholder);

    // Render the final ByteRange and substitute it into a working buffer
    // BEFORE digesting. The digest must cover the bytes that will exist in
    // the final file; otherwise Adobe reports "Document has been altered or
    // corrupted since it was signed".
    let target_width = placeholder.byte_range_end - placeholder.byte_range_start + 1;
    let rendered_byte_range = pdf::render_byte_range(&byte_range, target_width);
    if rendered_byte_range.len() != target_width {
        return Err(SignError::Other(
            err::PDF_INVALID,
            format!(
                "rendered ByteRange width {} does not match placeholder width {}; placeholder is too narrow for the actual offsets",
                rendered_byte_range.len(),
                target_width
            ),
        ));
    }
    let mut pre_signed = pdf_bytes.to_vec();
    pre_signed[placeholder.byte_range_start..=placeholder.byte_range_end]
        .copy_from_slice(rendered_byte_range.as_bytes());
    tracing::debug!(
        slot_id,
        rendered_byte_range_len = rendered_byte_range.len(),
        target_width,
        "rendered byte range and spliced into pre-signing buffer"
    );

    let content_digest = pdf::digest_byte_range(&pre_signed, &byte_range);
    tracing::debug!(
        slot_id,
        byte_range_segments = byte_range.len(),
        digest_bytes = content_digest.len(),
        "computed PDF byte range digest"
    );

    let cms_der = pdf::build_cms_signature(&content_digest, &cert_der, &extra_certs, |signed_attrs_der| {
        tracing::debug!(
            slot_id,
            signed_attrs_der_bytes = signed_attrs_der.len(),
            "requesting PKCS#11 signature over signed attributes"
        );
        state.with_pkcs11(|c| {
            c.sign_digest(
                slot_id,
                cert_id,
                &cert_der,
                &pin,
                &Mechanism::Sha256RsaPkcs,
                signed_attrs_der,
            )
        })
    })
    .map_err(|e| SignError::Other(err::CMS_BUILD_FAILED, e.to_string()))?;
    tracing::debug!(slot_id, cms_der_bytes = cms_der.len(), "CMS signature built");

    pdf::splice_signature(&pre_signed, &placeholder, &rendered_byte_range, &cms_der)
        .map(|signed_pdf| {
            tracing::info!(
                slot_id,
                output_bytes = signed_pdf.len(),
                "sign_pdf completed successfully"
            );
            signed_pdf
        })
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

fn preview_head_tail(value: &str, head: usize, tail: usize) -> String {
    let len = value.chars().count();
    if len <= head + tail {
        return value.to_string();
    }
    let prefix: String = value.chars().take(head).collect();
    let suffix_chars: Vec<char> = value.chars().rev().take(tail).collect();
    let suffix: String = suffix_chars.into_iter().rev().collect();
    format!("{prefix}...{suffix}")
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
        assert!(
            result["tokenPresent"].is_boolean(),
            "tokenPresent must be a boolean (true when PKCS#11 sees a token)"
        );
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
    fn list_usb_tokens_returns_well_formed_response() {
        let env = HostEnvelope {
            v: 1,
            id: "usb-1".into(),
            cmd: HostCmd::ListUsbTokens,
            payload: Value::Null,
        };
        let r = handle(&state(), env);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].id, "usb-1");
        if r[0].ok {
            let tokens = &r[0].result.as_ref().unwrap()["tokens"];
            assert!(tokens.is_array(), "tokens must be an array");
        } else {
            assert_eq!(r[0].error.as_ref().unwrap().code, err::USB_ENUM_FAILED);
        }
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
