//! Whole-hive carving: validate a `regf` base block found in raw bytes, pull the hive bins
//! that follow it as long as the chain is intact, and hand back bytes the normal registry
//! pipeline can open (freed cells included). Every hive bin carries its own offset relative
//! to the start of the bins region, so a contiguous hive verifies itself bin by bin and the
//! carve stops exactly where the chain breaks. The root key cell is checked before anything
//! is accepted. Faramir's registry carver.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::content_hash;
use crate::scan::BLOCK_SIZE;
use crate::source::BlockSource;

pub const BASE_BLOCK_SIZE: usize = 4096;
pub const HBIN_HEADER: usize = 32;
pub const HBIN_MAGIC: &[u8; 4] = b"hbin";
pub const REGF_MAGIC: &[u8; 4] = b"regf";
/// Bytes the scanner must present after a `regf` signature: base block + first bin header.
pub const WINDOW: usize = BASE_BLOCK_SIZE + HBIN_HEADER;
/// Largest hive accepted (SOFTWARE on a long-lived server is a few hundred MB).
pub const MAX_HIVE_BYTES: u64 = 2 << 30;
/// Smallest key cell: size + nk fixed part.
const NK_FIXED: usize = 0x50;
const NK_ROOT_FLAG: u16 = 0x04;
const DATA_SIZE_OFFSET: usize = 0x28;
const CHECKSUM_OFFSET: usize = 0x1fc;

fn u16_at(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}
fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}
fn u64_at(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}

/// The fields of a base block the carver needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HiveHeader {
    pub primary_sequence: u32,
    pub secondary_sequence: u32,
    pub timestamp_filetime: u64,
    pub major: u32,
    pub minor: u32,
    /// 0 primary, 1 legacy log, 2 new log.
    pub file_type: u32,
    pub root_cell_offset: u32,
    pub data_size: u32,
    pub embedded_name: String,
    pub checksum_stored: u32,
}

impl HiveHeader {
    pub fn parse(b: &[u8]) -> Option<Self> {
        if b.len() < 512 || &b[..4] != REGF_MAGIC {
            return None;
        }
        let name_units: Vec<u16> = b[0x30..0x70].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&u| u != 0).collect();
        Some(HiveHeader {
            primary_sequence: u32_at(b, 4),
            secondary_sequence: u32_at(b, 8),
            timestamp_filetime: u64_at(b, 0x0c),
            major: u32_at(b, 0x14),
            minor: u32_at(b, 0x18),
            file_type: u32_at(b, 0x1c),
            root_cell_offset: u32_at(b, 0x24),
            data_size: u32_at(b, 0x28),
            embedded_name: String::from_utf16_lossy(&name_units),
            checksum_stored: u32_at(b, CHECKSUM_OFFSET),
        })
    }

    pub fn is_primary(&self) -> bool {
        self.file_type == 0
    }

    /// File name to give the carved copy so a registry parser classifies it: the last
    /// component of the embedded name (`\??\C:\Windows\System32\config\SYSTEM` -> `SYSTEM`,
    /// `\??\C:\Users\bob\ntuser.dat` -> `bob_ntuser.dat`).
    pub fn file_name(&self) -> String {
        let name = self.embedded_name.replace('/', "\\");
        let parts: Vec<&str> = name.split('\\').filter(|p| !p.is_empty()).collect();
        let last = parts.last().copied().unwrap_or("").trim();
        let lower = last.to_ascii_lowercase();
        let clean = |s: &str| s.chars().map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') { c } else { '_' }).collect::<String>();
        if lower.is_empty() {
            return "UNKNOWN_HIVE".to_string();
        }
        if (lower == "ntuser.dat" || lower == "usrclass.dat") && parts.len() >= 2 {
            // keep the profile name so the user column can be filled
            let user = parts.iter().rev().find(|p| {
                !p.eq_ignore_ascii_case("ntuser.dat")
                    && !p.eq_ignore_ascii_case("usrclass.dat")
                    && !p.to_ascii_lowercase().contains("appdata")
                    && !p.eq_ignore_ascii_case("windows")
                    && !p.eq_ignore_ascii_case("microsoft")
                    && !p.eq_ignore_ascii_case("local")
            });
            if let Some(u) = user {
                return format!("{}_{}", clean(u), clean(last));
            }
        }
        clean(last)
    }
}

/// Size of the bin whose 32-byte header is `hdr`, when it is sane: `hbin` magic, offset
/// equal to its position in the chain, non-zero size in 4 KB units inside the declared
/// data size.
pub fn valid_bin_header(hdr: &[u8], expected_offset: u32, data_size: u32) -> Option<u32> {
    if hdr.len() < HBIN_HEADER || &hdr[..4] != HBIN_MAGIC {
        return None;
    }
    let offset = u32_at(hdr, 4);
    let size = u32_at(hdr, 8);
    if offset != expected_offset || size == 0 || !size.is_multiple_of(4096) {
        return None;
    }
    if (offset as u64) + (size as u64) > data_size as u64 {
        return None;
    }
    Some(size)
}

/// Is the window at a `regf` signature the base block of a primary hive worth carving?
/// `window` should hold [`WINDOW`] bytes unless the source ends earlier.
pub fn validate_base_block(window: &[u8]) -> Result<HiveHeader, String> {
    let header = HiveHeader::parse(window).ok_or("short or invalid base block")?;
    if header.file_type != 0 {
        return Err(format!("file type {} (transaction log or unknown), not a primary hive", header.file_type));
    }
    if header.major != 1 || !(3..=6).contains(&header.minor) {
        return Err(format!("unsupported hive version {}.{}", header.major, header.minor));
    }
    if header.data_size == 0 || !header.data_size.is_multiple_of(4096) || header.data_size as u64 > MAX_HIVE_BYTES {
        return Err(format!("implausible data size {}", header.data_size));
    }
    if !header.root_cell_offset.is_multiple_of(8) || header.root_cell_offset as u64 + NK_FIXED as u64 > header.data_size as u64 {
        return Err(format!("implausible root cell offset {:#x}", header.root_cell_offset));
    }
    if window.len() < WINDOW {
        return Err(format!("source ends {} bytes after the signature, no bin can follow", window.len()));
    }
    if valid_bin_header(&window[BASE_BLOCK_SIZE..WINDOW], 0, header.data_size).is_none() {
        return Err("no hive bin follows the base block".to_string());
    }
    Ok(header)
}

/// Bytes pulled out of the source for one hive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawCarve {
    pub bytes: Vec<u8>,
    pub bins: usize,
    /// `4096 + data_size` as declared by the base block.
    pub declared_len: usize,
    /// Bytes kept: base block plus every bin verified in sequence.
    pub recovered_len: usize,
    pub complete: bool,
    /// The base block was rewritten (data size / checksum) to describe the recovered prefix.
    pub header_patched: bool,
    pub content_hash: u64,
}

/// Identity of a hive copy: header fields plus a hash of the bytes kept.
pub fn fingerprint(h: &HiveHeader, hash: u64) -> String {
    format!("{}|{}|{}|{:016x}|{}|{:x}|{:016x}", h.embedded_name, h.primary_sequence, h.secondary_sequence, h.timestamp_filetime, h.data_size, h.root_cell_offset, hash)
}

/// XOR checksum of the first 508 bytes of a base block, as Windows computes it.
pub fn base_block_checksum(block: &[u8]) -> u32 {
    let mut x: u32 = 0;
    for i in (0..508).step_by(4) {
        x ^= u32_at(block, i);
    }
    if x == 0xffff_ffff {
        0xffff_fffe
    } else if x == 0 {
        1
    } else {
        x
    }
}

/// Equalises the sequence numbers and rebuilds the checksum of the base block at the start
/// of `b`: a carved copy has no transaction logs, so it is marked clean for the parser.
pub fn mark_clean(b: &mut [u8]) {
    if b.len() < 512 {
        return;
    }
    let seq = u32_at(b, 4);
    b[8..12].copy_from_slice(&seq.to_le_bytes());
    let sum = base_block_checksum(&b[..512]);
    b[CHECKSUM_OFFSET..CHECKSUM_OFFSET + 4].copy_from_slice(&sum.to_le_bytes());
}

/// Reads a hive whose base block sits at `offset`, following the bin chain until it breaks
/// or the declared size is reached. The copy comes back marked clean ([`mark_clean`]); a
/// truncated copy has its data size patched to what was recovered.
pub fn read_hive(src: &mut dyn BlockSource, offset: u64, header: &HiveHeader) -> Result<RawCarve, String> {
    read_hive_with(src, offset, header, true)
}

/// Same as [`read_hive`] with the bytes kept as found: the base block is only rewritten
/// (data size and checksum) when the copy is truncated. A dirty hive stays dirty, so a
/// parser that replays transaction logs can say so.
pub fn read_hive_raw(src: &mut dyn BlockSource, offset: u64, header: &HiveHeader) -> Result<RawCarve, String> {
    read_hive_with(src, offset, header, false)
}

fn read_hive_with(src: &mut dyn BlockSource, offset: u64, header: &HiveHeader, clean: bool) -> Result<RawCarve, String> {
    let data_size = header.data_size;
    let declared_len = BASE_BLOCK_SIZE + data_size as usize;
    let mut buf: Vec<u8> = Vec::with_capacity(declared_len.min(BLOCK_SIZE * 4));
    let mut validated = 0usize;
    let mut bins = 0usize;
    let mut broken = false;
    while buf.len() < declared_len && !broken {
        let want = BLOCK_SIZE.min(declared_len - buf.len());
        let chunk = match src.read_block(offset + buf.len() as u64, want) {
            Ok(c) if c.is_empty() => break,
            Ok(c) => c,
            Err(_) => break,
        };
        buf.extend_from_slice(&chunk);
        loop {
            let start = BASE_BLOCK_SIZE + validated;
            if start + HBIN_HEADER > buf.len() {
                break;
            }
            match valid_bin_header(&buf[start..start + HBIN_HEADER], validated as u32, data_size) {
                Some(size) => {
                    if start + size as usize > buf.len() {
                        break;
                    }
                    validated += size as usize;
                    bins += 1;
                }
                None => {
                    broken = true;
                    break;
                }
            }
        }
    }
    if bins == 0 {
        return Err("no intact hive bin after the base block".into());
    }
    let recovered_len = BASE_BLOCK_SIZE + validated;
    buf.truncate(recovered_len);
    let root = header.root_cell_offset as usize;
    let cell = BASE_BLOCK_SIZE + root;
    if cell + 4 + NK_FIXED > recovered_len {
        return Err(format!("root cell {:#x} lies beyond the {} recovered bytes", root, recovered_len));
    }
    let cell_size = i32::from_le_bytes(buf[cell..cell + 4].try_into().unwrap());
    let nk = &buf[cell + 4..];
    if cell_size >= 0 || &nk[..2] != b"nk" || u16_at(nk, 2) & NK_ROOT_FLAG == 0 {
        return Err(format!("root cell {:#x} is not an allocated root key", root));
    }
    let complete = validated == data_size as usize;
    if !complete {
        buf[DATA_SIZE_OFFSET..DATA_SIZE_OFFSET + 4].copy_from_slice(&(validated as u32).to_le_bytes());
        let sum = base_block_checksum(&buf[..512]);
        buf[CHECKSUM_OFFSET..CHECKSUM_OFFSET + 4].copy_from_slice(&sum.to_le_bytes());
    }
    if clean {
        mark_clean(&mut buf);
    }
    let hash = content_hash(&buf);
    Ok(RawCarve { bytes: buf, bins, declared_len, recovered_len, complete, header_patched: !complete, content_hash: hash })
}

/// Writes the carved hive as `<out_dir>/<header file name>`.
pub fn write_carved(out_dir: &Path, header: &HiveHeader, raw: &RawCarve) -> Result<PathBuf, String> {
    std::fs::create_dir_all(out_dir).map_err(|e| e.to_string())?;
    let path = out_dir.join(header.file_name());
    std::fs::write(&path, &raw.bytes).map_err(|e| e.to_string())?;
    Ok(path)
}

/// Fingerprint of a primary hive file on disk (what the file system or the shadow copies
/// already gave us), so an identical copy found in the raw bytes is skipped. The same
/// normalisation as [`read_hive`] is applied before hashing.
pub fn fingerprint_of_file(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    let header = HiveHeader::parse(&bytes)?;
    if !header.is_primary() {
        return None;
    }
    let keep = bytes.len().min(BASE_BLOCK_SIZE + header.data_size as usize);
    let mut b = bytes[..keep].to_vec();
    mark_clean(&mut b);
    Some(fingerprint(&header, content_hash(&b)))
}

/// Fingerprints of every primary hive under `dir`; `skip` says which paths to leave out (a
/// tool may keep hives extracted from shadow copies out, so a deleted hive found both in a
/// snapshot and in the raw bytes counts twice).
pub fn fingerprints_under(dir: &Path, skip: &dyn Fn(&Path) -> bool) -> HashSet<String> {
    let mut out = HashSet::new();
    for entry in walkdir::WalkDir::new(dir).into_iter().flatten() {
        if entry.file_type().is_file() && !skip(entry.path()) {
            if let Some(fp) = fingerprint_of_file(entry.path()) {
                out.insert(fp);
            }
        }
    }
    out
}

/// Does this file start with a hive base block?
pub fn starts_with_regf(path: &Path) -> bool {
    use std::io::Read;
    let Ok(mut f) = std::fs::File::open(path) else { return false };
    let mut magic = [0u8; 4];
    f.read_exact(&mut magic).is_ok() && &magic == REGF_MAGIC
}

/// Minimal valid hive for tests: base block + one 4 KB bin holding a root `nk`.
pub fn synthetic_hive(name: &str) -> Vec<u8> {
    let mut h = vec![0u8; 4096 + 4096];
    h[0..4].copy_from_slice(b"regf");
    h[4..8].copy_from_slice(&7u32.to_le_bytes());
    h[8..12].copy_from_slice(&7u32.to_le_bytes());
    h[0x0c..0x14].copy_from_slice(&133_552_399_310_000_000u64.to_le_bytes());
    h[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
    h[0x18..0x1c].copy_from_slice(&5u32.to_le_bytes());
    h[0x24..0x28].copy_from_slice(&0x20u32.to_le_bytes());
    h[0x28..0x2c].copy_from_slice(&4096u32.to_le_bytes());
    let n: Vec<u8> = name.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    h[0x30..0x30 + n.len()].copy_from_slice(&n);
    let sum = base_block_checksum(&h[..512]);
    h[CHECKSUM_OFFSET..CHECKSUM_OFFSET + 4].copy_from_slice(&sum.to_le_bytes());
    let bin = 4096;
    h[bin..bin + 4].copy_from_slice(b"hbin");
    h[bin + 8..bin + 12].copy_from_slice(&4096u32.to_le_bytes());
    let cell = bin + 0x20;
    h[cell..cell + 4].copy_from_slice(&(-(0x60i32)).to_le_bytes());
    h[cell + 4..cell + 6].copy_from_slice(b"nk");
    h[cell + 6..cell + 8].copy_from_slice(&0x2cu16.to_le_bytes());
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::MemorySource;

    #[test]
    fn carves_a_planted_hive_and_names_it() {
        let hive = synthetic_hive("Root\\System32\\Config\\SYSTEM");
        let mut img = vec![0u8; 512 * 10];
        img.extend_from_slice(&hive);
        img.extend(vec![0u8; 2048]);
        let mut src = MemorySource::from_bytes(img, "t");
        let window = src.read_block(5120, WINDOW).unwrap();
        let header = validate_base_block(&window).expect("valid base block");
        assert_eq!(header.file_name(), "SYSTEM");
        let raw = read_hive(&mut src, 5120, &header).unwrap();
        assert!(raw.complete);
        assert!(!raw.header_patched);
        assert_eq!(raw.bins, 1);
        assert_eq!(raw.recovered_len, 8192);
        let user = HiveHeader { embedded_name: "\\??\\C:\\Users\\bob\\ntuser.dat".into(), ..header.clone() };
        assert_eq!(user.file_name(), "bob_ntuser.dat");
        assert!(validate_base_block(&vec![0u8; WINDOW]).is_err());
    }

    #[test]
    fn a_broken_chain_yields_a_truncated_patched_copy() {
        let mut hive = synthetic_hive("SOFTWARE");
        hive[0x28..0x2c].copy_from_slice(&8192u32.to_le_bytes()); // declares two bins, has one
        let mut src = MemorySource::from_bytes(hive, "t");
        let window = src.read_block(0, WINDOW).unwrap();
        let header = validate_base_block(&window).unwrap();
        let raw = read_hive(&mut src, 0, &header).unwrap();
        assert!(!raw.complete && raw.header_patched);
        assert_eq!(raw.recovered_len, 8192);
        assert_eq!(u32::from_le_bytes(raw.bytes[0x28..0x2c].try_into().unwrap()), 4096);
    }

    #[test]
    fn raw_copies_keep_dirty_sequence_numbers() {
        let mut hive = synthetic_hive("SYSTEM");
        hive[8..12].copy_from_slice(&6u32.to_le_bytes()); // secondary behind primary: dirty
        let sum = base_block_checksum(&hive[..512]);
        hive[CHECKSUM_OFFSET..CHECKSUM_OFFSET + 4].copy_from_slice(&sum.to_le_bytes());
        let mut src = MemorySource::from_bytes(hive.clone(), "t");
        let header = HiveHeader::parse(&hive).unwrap();
        let raw = read_hive_raw(&mut src, 0, &header).unwrap();
        assert_eq!(raw.bytes, hive, "bytes as found");
        let clean = read_hive(&mut src, 0, &header).unwrap();
        assert_eq!(&clean.bytes[8..12], &7u32.to_le_bytes());
        assert_ne!(clean.content_hash, raw.content_hash);
    }
}
