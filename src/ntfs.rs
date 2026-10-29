//! NTFS metadata found in raw bytes (allymacb's carver): `FILE` records of the `$MFT` and
//! `INDX` blocks of directory indexes. Both carry update sequence arrays, so a candidate is
//! accepted only when every sector's last two bytes match the sequence number; random data
//! almost never passes. Index blocks also yield the entries left in their slack after a
//! file was deleted.

pub const FILE_MAGIC: &[u8; 4] = b"FILE";
pub const INDX_MAGIC: &[u8; 4] = b"INDX";
/// `$MFT` record sizes in use.
pub const VALID_ENTRY_SIZES: [u32; 2] = [1024, 4096];
/// `$FILE_NAME` flag for directories.
pub const FN_FLAG_DIRECTORY: u32 = 0x1000_0000;
/// FILETIME of 1970-01-01: slack entries with earlier times are treated as garbage.
pub const FILETIME_1970: u64 = 116_444_736_000_000_000;

/// Size of a valid `FILE` record at the start of `buf` (header geometry and fixups checked).
pub fn file_record_size(buf: &[u8]) -> Option<usize> {
    if buf.len() < 48 || &buf[0..4] != FILE_MAGIC {
        return None;
    }
    let usa_offset = u16::from_le_bytes([buf[4], buf[5]]) as usize;
    let usa_count = u16::from_le_bytes([buf[6], buf[7]]) as usize;
    let first_attr = u16::from_le_bytes([buf[20], buf[21]]) as usize;
    let used = u32::from_le_bytes(buf[24..28].try_into().unwrap()) as usize;
    let total = u32::from_le_bytes(buf[28..32].try_into().unwrap());
    if !VALID_ENTRY_SIZES.contains(&total) {
        return None;
    }
    let size = total as usize;
    if buf.len() < size || usa_count != size / 512 + 1 {
        return None;
    }
    if usa_offset < 0x2A || usa_offset + usa_count * 2 > first_attr || first_attr + 8 > size || used > size || used < first_attr {
        return None;
    }
    let usn = &buf[usa_offset..usa_offset + 2];
    for i in 1..usa_count {
        if &buf[i * 512 - 2..i * 512] != usn {
            return None;
        }
    }
    Some(size)
}

/// Is the `FILE` record in use (flag 0x01 of the header)?
pub fn file_record_allocated(buf: &[u8]) -> bool {
    buf.len() > 22 && buf[22] & 0x01 != 0
}

/// Record number stored in the header (NTFS 3.1+), 0 when the header is the older short form.
pub fn file_record_number(buf: &[u8]) -> u64 {
    if buf.len() < 48 {
        return 0;
    }
    let usa_offset = u16::from_le_bytes([buf[4], buf[5]]);
    if usa_offset >= 0x30 {
        u64::from(u32::from_le_bytes([buf[44], buf[45], buf[46], buf[47]]))
    } else {
        0
    }
}

/// `(entry number, sequence number)` of a file reference.
pub fn split_ref(file_ref: u64) -> (u64, u16) {
    (file_ref & 0x0000_FFFF_FFFF_FFFF, (file_ref >> 48) as u16)
}

/// Size and fixup-corrected bytes of a valid `INDX` block at the start of `buf`, plus the
/// end of the live entry chain and of the allocated area (both relative to the block).
pub fn indx_block(buf: &[u8]) -> Option<(Vec<u8>, usize, usize, usize)> {
    if buf.len() < 0x58 || &buf[0..4] != INDX_MAGIC {
        return None;
    }
    let usa_offset = u16::from_le_bytes([buf[4], buf[5]]) as usize;
    let usa_count = u16::from_le_bytes([buf[6], buf[7]]) as usize;
    if !(3..=129).contains(&usa_count) {
        return None;
    }
    let size = (usa_count - 1) * 512;
    if buf.len() < size || usa_offset < 0x28 || usa_offset + usa_count * 2 > size {
        return None;
    }
    let entries_offset = u32::from_le_bytes(buf[24..28].try_into().ok()?) as usize;
    let index_size = u32::from_le_bytes(buf[28..32].try_into().ok()?) as usize;
    let alloc_size = u32::from_le_bytes(buf[32..36].try_into().ok()?) as usize;
    if entries_offset < 0x10 || 24 + alloc_size > size || index_size > alloc_size || entries_offset > index_size {
        return None;
    }
    if usa_offset + usa_count * 2 > 24 + entries_offset {
        return None;
    }
    let mut block = buf[..size].to_vec();
    let usn = [block[usa_offset], block[usa_offset + 1]];
    for i in 1..usa_count {
        let end = i * 512;
        if block[end - 2..end] != usn {
            return None;
        }
        let fix = usa_offset + i * 2;
        block[end - 2] = block[fix];
        block[end - 1] = block[fix + 1];
    }
    Some((block, 24 + entries_offset, 24 + index_size, 24 + alloc_size))
}

#[cfg(feature = "mft")]
pub use with_mft::{parse_indx_block, IndxEntry};

#[cfg(feature = "mft")]
mod with_mft {
    use super::*;
    use mft::attribute::x30::FileNameAttr;
    use std::io::Cursor;

    /// One parsed `$I30` entry.
    pub struct IndxEntry {
        /// Offset of the entry inside the block.
        pub offset: usize,
        pub file_ref: u64,
        /// Raw `$FILE_NAME` flags (see [`FN_FLAG_DIRECTORY`]).
        pub flags: u32,
        /// Found after the live chain: a child the directory no longer lists.
        pub in_slack: bool,
        pub fname: FileNameAttr,
    }

    fn entry_header(block: &[u8], pos: usize) -> (usize, u32) {
        let len = u16::from_le_bytes([block[pos + 8], block[pos + 9]]) as usize;
        let flags = u32::from_le_bytes(block[pos + 12..pos + 16].try_into().unwrap_or([0; 4]));
        (len, flags)
    }

    /// Parses the index entry at `pos`. `strict` adds the plausibility checks needed when the
    /// entry comes from slack instead of the live chain.
    fn try_entry(block: &[u8], pos: usize, strict: bool) -> Option<IndxEntry> {
        if pos + 0x58 > block.len() {
            return None;
        }
        let file_ref = u64::from_le_bytes(block[pos..pos + 8].try_into().ok()?);
        let (len, flags) = entry_header(block, pos);
        let fn_len = u16::from_le_bytes([block[pos + 10], block[pos + 11]]) as usize;
        let fn_start = pos + 16;
        if fn_len < 0x44 || fn_start + fn_len > block.len() || len < 16 + fn_len {
            return None;
        }
        let name_len = block[fn_start + 0x40] as usize;
        let namespace = block[fn_start + 0x41];
        if name_len == 0 || namespace > 3 || fn_len != 0x42 + 2 * name_len {
            return None;
        }
        if strict {
            let expected = (16 + fn_len + 7) & !7;
            let expected = if flags & 0x01 != 0 { expected + 8 } else { expected };
            if len != expected || flags & !0x03 != 0 {
                return None;
            }
            for i in 0..4 {
                let t = u64::from_le_bytes(block[fn_start + 8 + i * 8..fn_start + 16 + i * 8].try_into().ok()?);
                if t >= 1 << 63 || (t != 0 && t < FILETIME_1970) {
                    return None;
                }
            }
        }
        let fn_flags = u32::from_le_bytes(block[fn_start + 0x38..fn_start + 0x3C].try_into().ok()?);
        let fname = FileNameAttr::from_stream(&mut Cursor::new(&block[fn_start..fn_start + fn_len])).ok()?;
        if fname.name.chars().any(|c| c.is_control() || c == '\\' || c == '/') {
            return None;
        }
        Some(IndxEntry { offset: pos, file_ref, flags: fn_flags, in_slack: strict, fname })
    }

    /// Validates an `INDX` block at the start of `buf`, applies its fixups and returns its size
    /// with every entry of the live chain and of the slack.
    pub fn parse_indx_block(buf: &[u8]) -> Option<(usize, Vec<IndxEntry>)> {
        let (block, first, live_end, block_end) = indx_block(buf)?;
        let mut out = Vec::new();
        let mut pos = first;
        while pos + 16 <= live_end {
            let (len, flags) = entry_header(&block, pos);
            if flags & 0x02 != 0 || len < 16 || !len.is_multiple_of(8) || pos + len > live_end {
                break;
            }
            if let Some(e) = try_entry(&block, pos, false) {
                out.push(e);
            }
            pos += len;
        }
        let mut pos = (live_end + 7) & !7;
        while pos + 0x58 <= block_end {
            match try_entry(&block, pos, true) {
                Some(e) => {
                    let (len, _) = entry_header(&block, pos);
                    out.push(e);
                    pos += len.max(8);
                }
                None => pos += 8,
            }
        }
        Some((block.len(), out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 1 KB `FILE` record with consistent fixups.
    pub fn synthetic_file_record(allocated: bool) -> Vec<u8> {
        let mut r = vec![0u8; 1024];
        r[0..4].copy_from_slice(FILE_MAGIC);
        r[4..6].copy_from_slice(&0x30u16.to_le_bytes()); // usa offset
        r[6..8].copy_from_slice(&3u16.to_le_bytes()); // usa count
        r[20..22].copy_from_slice(&0x38u16.to_le_bytes()); // first attribute
        r[22] = if allocated { 1 } else { 0 };
        r[24..28].copy_from_slice(&0x60u32.to_le_bytes()); // used
        r[28..32].copy_from_slice(&1024u32.to_le_bytes()); // allocated
        r[44..48].copy_from_slice(&77u32.to_le_bytes()); // record number
        r[0x30..0x32].copy_from_slice(&[0x11, 0x22]);
        r[510..512].copy_from_slice(&[0x11, 0x22]);
        r[1022..1024].copy_from_slice(&[0x11, 0x22]);
        r
    }

    #[test]
    fn file_records_need_matching_fixups() {
        let r = synthetic_file_record(true);
        assert_eq!(file_record_size(&r), Some(1024));
        assert!(file_record_allocated(&r));
        assert_eq!(file_record_number(&r), 77);
        let mut bad = r.clone();
        bad[1023] = 0;
        assert!(file_record_size(&bad).is_none());
        assert_eq!(split_ref(0x0005_0000_0000_002A), (42, 5));
        assert!(indx_block(&r).is_none());
    }
}
