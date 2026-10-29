//! Prefetch files in raw bytes: the uncompressed `SCCA` header (versions 17, 23, 26, 30) and
//! the Windows 10/11 `MAM` container that holds an Xpress Huffman compressed one. The
//! validator only reads the header; decompression and parsing stay in the tool.

pub const MAM_MAGIC: &[u8; 4] = b"MAM\x04";
/// Uncompressed Prefetch signatures: version then `SCCA`.
pub const SCCA_SIGNATURES: [&[u8]; 4] = [b"\x1e\0\0\0SCCA", b"\x1a\0\0\0SCCA", b"\x17\0\0\0SCCA", b"\x11\0\0\0SCCA"];
/// Largest Prefetch file accepted.
pub const MAX_PREFETCH_BYTES: u32 = 64 << 20;

/// What a Prefetch header at the start of `buf` says about the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrefetchCandidate {
    /// Format version (17, 23, 26, 30) when the header is uncompressed; `None` for `MAM`.
    pub version: Option<u32>,
    /// Bytes of the file as stored: the declared size for `SCCA`, unknown for `MAM` (whose
    /// header only gives the decompressed size).
    pub stored_size: Option<u32>,
    pub decompressed_size: u32,
}

/// Validates a Prefetch header without decompressing anything.
pub fn candidate(buf: &[u8]) -> Option<PrefetchCandidate> {
    if buf.len() < 16 {
        return None;
    }
    if buf.starts_with(MAM_MAGIC) {
        let size = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        if !(0x54..=MAX_PREFETCH_BYTES).contains(&size) {
            return None;
        }
        return Some(PrefetchCandidate { version: None, stored_size: None, decompressed_size: size });
    }
    if &buf[4..8] != b"SCCA" {
        return None;
    }
    let version = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    if !matches!(version, 17 | 23 | 26 | 30) {
        return None;
    }
    let size = u32::from_le_bytes(buf[12..16].try_into().unwrap());
    if !(0x54..=MAX_PREFETCH_BYTES).contains(&size) {
        return None;
    }
    Some(PrefetchCandidate { version: Some(version), stored_size: Some(size), decompressed_size: size })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers() {
        let mut scca = vec![0u8; 32];
        scca[0] = 30;
        scca[4..8].copy_from_slice(b"SCCA");
        scca[12..16].copy_from_slice(&4096u32.to_le_bytes());
        assert_eq!(candidate(&scca), Some(PrefetchCandidate { version: Some(30), stored_size: Some(4096), decompressed_size: 4096 }));
        let mut mam = vec![0u8; 16];
        mam[..4].copy_from_slice(MAM_MAGIC);
        mam[4..8].copy_from_slice(&20000u32.to_le_bytes());
        assert_eq!(candidate(&mam).unwrap().decompressed_size, 20000);
        scca[0] = 9;
        assert!(candidate(&scca).is_none());
    }
}
