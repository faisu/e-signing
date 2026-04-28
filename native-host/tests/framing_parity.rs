//! End-to-end parity test against the previous TS framing module
//! (`native-host/src/shared/framing.ts`).
//!
//! Verifies the on-wire bytes the Rust host produces are byte-identical to
//! what the Node host produced for the same JSON payload.

use std::io::Cursor;

#[path = "../src/framing.rs"]
mod framing;

#[path = "../src/protocol.rs"]
mod protocol;

#[test]
fn ping_envelope_frames_match_node_output() {
    // What the previous TS host emitted for a PING success (formatted by
    // JSON.stringify on the Node side).
    let body = br#"{"v":1,"id":"abc","ok":true,"result":{"hostVersion":"0.1.0","tokenPresent":false,"protocolVersion":1},"error":null}"#;
    let mut buf = Vec::new();
    framing::write_frame(&mut buf, body).unwrap();

    assert_eq!(&buf[..4], &(body.len() as u32).to_le_bytes());
    assert_eq!(&buf[4..], body);
}

#[test]
fn read_then_write_roundtrip() {
    let body = br#"{"v":1,"id":"x","cmd":"PING","payload":{}}"#;
    let mut wire = Vec::new();
    framing::write_frame(&mut wire, body).unwrap();

    let mut cursor = Cursor::new(wire);
    let frame = framing::read_frame(&mut cursor).unwrap().unwrap();
    assert_eq!(frame, body);
}
