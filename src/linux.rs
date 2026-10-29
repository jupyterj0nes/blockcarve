//! Linux structures with a self-describing header: systemd journal files.

pub const JOURNAL_MAGIC: &[u8; 8] = b"LPKSHHRH";
/// Largest journal file accepted.
pub const JOURNAL_MAX: u64 = 4 << 30;

/// Size of a journal file from its header (`header_size + arena_size`), when plausible.
pub fn journal_size(buf: &[u8]) -> Option<u64> {
    if buf.len() < 0x68 || !buf.starts_with(JOURNAL_MAGIC) {
        return None;
    }
    let header_size = u64::from_le_bytes(buf[0x58..0x60].try_into().unwrap());
    let arena_size = u64::from_le_bytes(buf[0x60..0x68].try_into().unwrap());
    if !(0xf0..=4096).contains(&header_size) || arena_size == 0 || arena_size > JOURNAL_MAX {
        return None;
    }
    Some(header_size + arena_size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_header() {
        let mut j = vec![0u8; 0x100];
        j[..8].copy_from_slice(JOURNAL_MAGIC);
        j[0x58..0x60].copy_from_slice(&0xf8u64.to_le_bytes());
        j[0x60..0x68].copy_from_slice(&(8u64 << 20).to_le_bytes());
        assert_eq!(journal_size(&j), Some(0xf8 + (8 << 20)));
        j[0x60..0x68].copy_from_slice(&0u64.to_le_bytes());
        assert!(journal_size(&j).is_none());
    }
}
