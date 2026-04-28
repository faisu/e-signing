//! Chrome native messaging framing: 4-byte little-endian length prefix
//! followed by a UTF-8 JSON body.
//!
//! Chrome's documentation specifies "native byte order" for the length, but on
//! every architecture we ship to (x86_64, aarch64) that resolves to
//! little-endian, which matches the previous TS implementation
//! (`view.setUint32(0, len, true)`).

use std::io::{self, Read, Write};

use crate::protocol::MAX_NATIVE_MESSAGE_BYTES;

const HEADER_BYTES: usize = 4;

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("frame exceeds {limit} byte cap (got {actual})")]
    TooLarge { limit: usize, actual: usize },
    #[error("eof before frame complete")]
    UnexpectedEof,
}

/// Block until a full frame is read. Returns `Ok(None)` on clean EOF
/// (the extension closed the port).
pub fn read_frame<R: Read>(reader: &mut R) -> Result<Option<Vec<u8>>, FrameError> {
    let mut header = [0u8; HEADER_BYTES];
    match reader.read_exact(&mut header) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }

    let len = u32::from_le_bytes(header) as usize;
    if len > MAX_NATIVE_MESSAGE_BYTES {
        // Drain & discard so the stream stays sync'd with subsequent frames.
        let mut sink = io::sink();
        io::copy(&mut reader.take(len as u64), &mut sink)?;
        return Err(FrameError::TooLarge {
            limit: MAX_NATIVE_MESSAGE_BYTES,
            actual: len,
        });
    }

    let mut body = vec![0u8; len];
    reader.read_exact(&mut body).map_err(|e| match e.kind() {
        io::ErrorKind::UnexpectedEof => FrameError::UnexpectedEof,
        _ => FrameError::Io(e),
    })?;
    Ok(Some(body))
}

pub fn write_frame<W: Write>(writer: &mut W, body: &[u8]) -> io::Result<()> {
    let len = body.len() as u32;
    writer.write_all(&len.to_le_bytes())?;
    writer.write_all(body)?;
    writer.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn roundtrip_small() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"hello").unwrap();
        // 5 bytes LE + body
        assert_eq!(&buf[..4], &[5, 0, 0, 0]);
        assert_eq!(&buf[4..], b"hello");

        let mut cursor = Cursor::new(buf);
        let frame = read_frame(&mut cursor).unwrap().unwrap();
        assert_eq!(frame, b"hello");
    }

    #[test]
    fn header_is_little_endian() {
        // 0x01020304 == 16909060.  LE bytes = [0x04, 0x03, 0x02, 0x01]
        let header_only = (0x01020304u32).to_le_bytes();
        assert_eq!(header_only, [0x04, 0x03, 0x02, 0x01]);
    }

    #[test]
    fn rejects_oversize_frame() {
        let mut header = ((MAX_NATIVE_MESSAGE_BYTES + 1) as u32)
            .to_le_bytes()
            .to_vec();
        // Append filler so the discard-drain has something to consume.
        header.extend(std::iter::repeat_n(0u8, 16));
        let mut cursor = Cursor::new(header);
        let err = read_frame(&mut cursor).unwrap_err();
        match err {
            FrameError::TooLarge { .. } => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn clean_eof_returns_none() {
        let mut cursor = Cursor::new(Vec::<u8>::new());
        assert!(read_frame(&mut cursor).unwrap().is_none());
    }

    #[test]
    fn truncated_body_is_unexpected_eof() {
        let mut buf = Vec::new();
        // Header says 10 bytes follow but supply only 3.
        buf.extend(10u32.to_le_bytes());
        buf.extend(b"abc");
        let mut cursor = Cursor::new(buf);
        let err = read_frame(&mut cursor).unwrap_err();
        assert!(matches!(err, FrameError::UnexpectedEof));
    }
}
