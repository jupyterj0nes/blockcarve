//! Registry transaction log replay, in memory: evidence files are never modified.
//!
//! Implements the recovery rules of the registry file format specification
//! (<https://github.com/msuhanov/regf>):
//!
//! * New format (`HvLE` log entries, Windows 8.1+): every entry is authenticated with two
//!   Marvin32 hashes; entries are applied in strictly consecutive sequence order starting at the
//!   primary sequence number of the log file's own base block; both `.LOG1` / `.LOG2` are used,
//!   the one with the earlier entries first; a clean hive is never touched.
//! * Old format (`DIRT` dirty vector, up to Windows 8): a log is valid when its own sequence
//!   numbers match and applicable when its "last written" timestamp equals the hive's.
//!
//! The replayed buffer has equal sequence numbers and a rebuilt checksum, so any hive reader
//! (nt_hive2, sootmark-registry, [`crate::hive_cells`]) takes it as clean. Matched against the
//! hives Windows 10 and Windows 7 recovered themselves in the yarp test corpus.
//!
//! ```no_run
//! use std::path::Path;
//! let path = Path::new("NTUSER.DAT");
//! let raw = std::fs::read(path).unwrap();
//! let replay = blockcarve::hive_logs::replay_beside(path, &raw);
//! println!("{:?}", replay.outcome);
//! let bytes: &[u8] = &replay.data; // the hive with its logs applied, or the raw bytes
//! # let _ = bytes;
//! ```

use std::borrow::Cow;
use std::path::{Path, PathBuf};

use crate::hive::base_block_checksum;

/// Seed used by Windows for Hash-1 / Hash-2 of `HvLE` entries (bytes 82 EF 4D 88 7A 4E 55 C5).
pub const MARVIN32_SEED: u64 = 0x82EF_4D88_7A4E_55C5;
const HVLE_HEADER_LEN: usize = 40;
const SECTOR: usize = 512;
const PRIMARY_BASE_BLOCK_LEN: usize = 4096;

// -------------------------------------------------------------------------------------------------
// Marvin32 (verified against real NTUSER.DAT.LOG1/.LOG2 entries written by Windows 11)
// -------------------------------------------------------------------------------------------------

#[inline]
fn marvin_block(p0: &mut u32, p1: &mut u32) {
    *p1 ^= *p0;
    *p0 = p0.rotate_left(20);
    *p0 = p0.wrapping_add(*p1);
    *p1 = p1.rotate_left(9);
    *p1 ^= *p0;
    *p0 = p0.rotate_left(27);
    *p0 = p0.wrapping_add(*p1);
    *p1 = p1.rotate_left(19);
}

/// Microsoft Marvin32 checksum. Returns `(p1 << 32) | p0`, the layout Windows stores on disk.
pub fn marvin32(seed: u64, data: &[u8]) -> u64 {
    let mut p0 = seed as u32;
    let mut p1 = (seed >> 32) as u32;

    let mut chunks = data.chunks_exact(4);
    for c in &mut chunks {
        p0 = p0.wrapping_add(u32::from_le_bytes([c[0], c[1], c[2], c[3]]));
        marvin_block(&mut p0, &mut p1);
    }
    let rem = chunks.remainder();
    let fin: u32 = match rem.len() {
        0 => 0x80,
        1 => 0x8000 | rem[0] as u32,
        2 => 0x80_0000 | rem[0] as u32 | (rem[1] as u32) << 8,
        _ => 0x8000_0000 | rem[0] as u32 | (rem[1] as u32) << 8 | (rem[2] as u32) << 16,
    };
    p0 = p0.wrapping_add(fin);
    marvin_block(&mut p0, &mut p1);
    marvin_block(&mut p0, &mut p1);

    ((p1 as u64) << 32) | p0 as u64
}

// -------------------------------------------------------------------------------------------------
// Data structures
// -------------------------------------------------------------------------------------------------

/// A page of hive bins carried by a log, at its offset from the end of the base block.
#[derive(Debug, Clone)]
struct DirtyPage {
    offset_in_bins: usize,
    data: Vec<u8>,
}

/// A parsed, hash-verified `HvLE` log entry.
#[derive(Debug, Clone)]
struct HvLeEntry {
    sequence_number: u32,
    hive_bins_data_size: usize,
    dirty_pages: Vec<DirtyPage>,
}

/// Fields of a `regf` base block that drive recovery decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BaseBlockInfo {
    pub primary_seq: u32,
    pub secondary_seq: u32,
    pub last_written: u64,
    pub hive_bins_size: u32,
    /// 0 primary, 1 / 2 old-format log, 6 new-format log.
    pub file_type: u32,
}

/// Reads the base block of a primary or log file (`None` when the `regf` signature is missing).
pub fn base_block_info(data: &[u8]) -> Option<BaseBlockInfo> {
    if data.len() < 0x2C || &data[0..4] != b"regf" {
        return None;
    }
    let u32_at = |o: usize| u32::from_le_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]]);
    let mut lw = [0u8; 8];
    lw.copy_from_slice(&data[12..20]);
    Some(BaseBlockInfo {
        primary_seq: u32_at(4),
        secondary_seq: u32_at(8),
        last_written: u64::from_le_bytes(lw),
        hive_bins_size: u32_at(0x28),
        file_type: u32_at(0x1C),
    })
}

/// Primary and secondary sequence numbers differ: the latest changes may be in the logs.
pub fn is_dirty(hive_data: &[u8]) -> bool {
    base_block_info(hive_data).map(|b| b.primary_seq != b.secondary_seq).unwrap_or(false)
}

/// Transaction logs next to a hive file: `.LOG`, `.LOG1`, `.LOG2` in either case, each once.
pub fn logs_beside(hive_path: &Path) -> Vec<PathBuf> {
    let mut logs = Vec::new();
    let (Some(parent), Some(name)) = (hive_path.parent(), hive_path.file_name()) else {
        return logs;
    };
    let name = name.to_string_lossy();
    for ext in ["LOG", "LOG1", "LOG2", "log", "log1", "log2"] {
        let log_path = parent.join(format!("{name}.{ext}"));
        if log_path.is_file() && !logs.iter().any(|p: &PathBuf| p.to_string_lossy().eq_ignore_ascii_case(&log_path.to_string_lossy())) {
            logs.push(log_path);
        }
    }
    logs
}

/// A transaction log handed to [`replay`]: where it came from and its bytes.
#[derive(Debug, Clone)]
pub struct LogFile {
    pub path: PathBuf,
    pub data: Vec<u8>,
}

/// Why an old-format log was not applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OldLogSkip {
    /// The log's own primary and secondary sequence numbers differ: it was torn.
    InconsistentSequence,
    /// The log's "last written" timestamp is not the hive's: it belongs to another write.
    TimestampMismatch,
}

impl std::fmt::Display for OldLogSkip {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            OldLogSkip::InconsistentSequence => "inconsistent sequence numbers",
            OldLogSkip::TimestampMismatch => "last-written timestamp does not match the hive",
        })
    }
}

/// What [`replay`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// No `regf` base block: the bytes are not a hive.
    NotAHive,
    /// The hive is clean; logs are ignored, as Windows does.
    Clean,
    /// The hive is dirty and no log was given.
    NoLogs,
    /// New-format entries applied.
    NewFormat {
        entries: usize,
        pages: usize,
        logs: usize,
        from_seq: u32,
        to_seq: u32,
        /// A missing sequence number stopped the replay; later entries were not applied.
        gap: bool,
        /// Entries rejected by their Marvin32 hashes.
        rejected: usize,
    },
    /// New-format logs present, none of their entries applies.
    NoApplicableEntries { expected_seq: u32, rejected: usize },
    /// An old-format dirty vector applied.
    OldFormat { pages: usize, log: PathBuf },
    /// Dirty hive, logs present, nothing usable in them.
    NothingUsable,
}

impl Outcome {
    /// True when log data went into the returned buffer.
    pub fn applied(&self) -> bool {
        matches!(self, Outcome::NewFormat { .. } | Outcome::OldFormat { .. })
    }
}

/// The hive after replay: its bytes (borrowed when nothing was applied), what was done, and
/// the old-format logs that were passed over.
#[derive(Debug, Clone)]
pub struct Replay<'a> {
    pub data: Cow<'a, [u8]>,
    pub outcome: Outcome,
    pub skipped_old: Vec<(PathBuf, OldLogSkip)>,
}

/// Recomputes the base block checksum at 0x1FC.
fn fix_base_block_checksum(buf: &mut [u8]) {
    if buf.len() < 0x200 {
        return;
    }
    let checksum = base_block_checksum(&buf[..0x200]);
    buf[0x1FC..0x200].copy_from_slice(&checksum.to_le_bytes());
}

fn apply_pages(buffer: &mut Vec<u8>, pages: &[DirtyPage]) -> usize {
    let mut applied = 0;
    for page in pages {
        let write_offset = PRIMARY_BASE_BLOCK_LEN + page.offset_in_bins;
        let end_offset = write_offset + page.data.len();
        if buffer.len() < end_offset {
            buffer.resize(end_offset, 0);
        }
        buffer[write_offset..end_offset].copy_from_slice(&page.data);
        applied += 1;
    }
    applied
}

/// Reads the logs next to `hive_path` ([`logs_beside`]) and replays them into `hive_data`.
/// The logs are only read when the hive is dirty.
pub fn replay_beside<'a>(hive_path: &Path, hive_data: &'a [u8]) -> Replay<'a> {
    let logs = if is_dirty(hive_data) {
        logs_beside(hive_path)
            .into_iter()
            .filter_map(|path| std::fs::read(&path).ok().map(|data| LogFile { path, data }))
            .collect()
    } else {
        Vec::new()
    };
    replay(hive_data, &logs)
}

/// A transaction log after parsing.
struct ParsedLog<'l> {
    path: &'l Path,
    info: BaseBlockInfo,
    hvle: Vec<HvLeEntry>,
    hvle_rejected: usize,
    dirt: Vec<DirtyPage>,
}

/// Replays transaction logs into a primary hive buffer. Returns the hive unchanged (borrowed,
/// no copy) when nothing has to be applied, or a new in-memory buffer with the recovered data.
/// Old-format logs are tried in the order given (`.LOG` / `.LOG1` before `.LOG2`).
pub fn replay<'a>(hive_data: &'a [u8], logs: &[LogFile]) -> Replay<'a> {
    let unchanged = |outcome, skipped_old| Replay { data: Cow::Borrowed(hive_data), outcome, skipped_old };
    let Some(hive_info) = base_block_info(hive_data) else {
        return unchanged(Outcome::NotAHive, Vec::new());
    };

    // A clean hive is consistent by definition: log entries left behind are ignored (spec).
    if hive_info.primary_seq == hive_info.secondary_seq {
        return unchanged(Outcome::Clean, Vec::new());
    }
    if logs.is_empty() {
        return unchanged(Outcome::NoLogs, Vec::new());
    }

    let mut parsed: Vec<ParsedLog> = Vec::new();
    for log in logs {
        let Some(info) = base_block_info(&log.data) else { continue };
        // The file type says which format the log holds: 6 new (HvLE), 1 or 2 old (DIRT).
        let (hvle, hvle_rejected) = if info.file_type == 6 { parse_hvle_log(&log.data) } else { (Vec::new(), 0) };
        let dirt = if matches!(info.file_type, 1 | 2) { parse_dirt_log(&log.data) } else { Vec::new() };
        parsed.push(ParsedLog { path: &log.path, info, hvle, hvle_rejected, dirt });
    }

    // ---------------------------------------------------------------------------------------------
    // New format (HvLE)
    // ---------------------------------------------------------------------------------------------
    let mut new_logs: Vec<&ParsedLog> = parsed.iter().filter(|l| !l.hvle.is_empty()).collect();
    if !new_logs.is_empty() {
        // Logs written before the last successful flush of the primary file are stale.
        new_logs.retain(|l| l.info.primary_seq >= hive_info.secondary_seq);
        new_logs.sort_by_key(|l| l.info.primary_seq);

        let rejected: usize = parsed.iter().map(|l| l.hvle_rejected).sum();
        let mut expected = match new_logs.first() {
            Some(l) => l.info.primary_seq.max(hive_info.primary_seq),
            None => return unchanged(Outcome::NoApplicableEntries { expected_seq: hive_info.primary_seq, rejected }, Vec::new()),
        };
        let mut buffer = hive_data.to_vec();
        let mut applied_entries = 0usize;
        let mut applied_pages = 0usize;
        let mut last_seq = hive_info.primary_seq;
        let mut last_bins_size: Option<usize> = None;
        let mut gap = false;

        'outer: for log in &new_logs {
            for entry in &log.hvle {
                if entry.sequence_number < expected {
                    continue; // already contained in the primary file
                }
                if entry.sequence_number > expected {
                    gap = true;
                    break 'outer; // missing entry: everything after it is unreliable
                }
                applied_pages += apply_pages(&mut buffer, &entry.dirty_pages);
                applied_entries += 1;
                last_seq = entry.sequence_number;
                last_bins_size = Some(entry.hive_bins_data_size);
                expected += 1;
            }
        }

        if applied_entries == 0 {
            return unchanged(Outcome::NoApplicableEntries { expected_seq: expected, rejected }, Vec::new());
        }

        if let Some(size) = last_bins_size {
            let needed = PRIMARY_BASE_BLOCK_LEN + size;
            if buffer.len() < needed {
                buffer.resize(needed, 0);
            }
            buffer[0x28..0x2C].copy_from_slice(&(size as u32).to_le_bytes());
        }
        let seq_bytes = last_seq.to_le_bytes();
        buffer[4..8].copy_from_slice(&seq_bytes);
        buffer[8..12].copy_from_slice(&seq_bytes);
        fix_base_block_checksum(&mut buffer);

        return Replay {
            data: Cow::Owned(buffer),
            outcome: Outcome::NewFormat {
                entries: applied_entries,
                pages: applied_pages,
                logs: new_logs.len(),
                from_seq: hive_info.primary_seq,
                to_seq: last_seq,
                gap,
                rejected,
            },
            skipped_old: Vec::new(),
        };
    }

    // ---------------------------------------------------------------------------------------------
    // Old format (DIRT): first valid & applicable log wins, in the order given
    // ---------------------------------------------------------------------------------------------
    let mut skipped_old = Vec::new();
    for log in parsed.iter().filter(|l| !l.dirt.is_empty()) {
        if log.info.primary_seq != log.info.secondary_seq {
            skipped_old.push((log.path.to_path_buf(), OldLogSkip::InconsistentSequence));
            continue;
        }
        if log.info.last_written != hive_info.last_written {
            skipped_old.push((log.path.to_path_buf(), OldLogSkip::TimestampMismatch));
            continue;
        }
        let mut buffer = hive_data.to_vec();
        let pages = apply_pages(&mut buffer, &log.dirt);
        let seq_bytes = log.info.primary_seq.to_le_bytes();
        buffer[4..8].copy_from_slice(&seq_bytes);
        buffer[8..12].copy_from_slice(&seq_bytes);
        fix_base_block_checksum(&mut buffer);
        return Replay { data: Cow::Owned(buffer), outcome: Outcome::OldFormat { pages, log: log.path.to_path_buf() }, skipped_old };
    }

    unchanged(Outcome::NothingUsable, skipped_old)
}

/// Parses an incremental transaction log file (new format, `HvLE`).
/// Returns the verified entries in file order and the number of entries rejected because
/// their Marvin32 hashes did not match (parsing stops at the first invalid entry).
fn parse_hvle_log(data: &[u8]) -> (Vec<HvLeEntry>, usize) {
    let mut entries = Vec::new();
    let mut rejected = 0;

    // The first sector (512 bytes) is the base block
    if data.len() < 2 * SECTOR || &data[0..4] != b"regf" {
        return (entries, rejected);
    }

    let u32_at = |o: usize| u32::from_le_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]]);
    let u64_at = |o: usize| {
        let mut b = [0u8; 8];
        b.copy_from_slice(&data[o..o + 8]);
        u64::from_le_bytes(b)
    };

    let mut offset = SECTOR; // Log entries start at the second sector

    while offset + HVLE_HEADER_LEN <= data.len() {
        if &data[offset..offset + 4] != b"HvLE" {
            break; // not a valid entry at this 512-byte boundary: end of log
        }

        let entry_size = u32_at(offset + 4) as usize;
        if entry_size < HVLE_HEADER_LEN || offset + entry_size > data.len() {
            rejected += 1;
            break;
        }

        let sequence_number = u32_at(offset + 12);
        let hive_bins_data_size = u32_at(offset + 16) as usize;
        let dirty_pages_count = u32_at(offset + 20) as usize;
        let stored_hash1 = u64_at(offset + 24);
        let stored_hash2 = u64_at(offset + 32);

        // Hash-2 covers the first 32 bytes of the entry; Hash-1 covers everything after the header.
        let hash2 = marvin32(MARVIN32_SEED, &data[offset..offset + 32]);
        let hash1 = marvin32(MARVIN32_SEED, &data[offset + HVLE_HEADER_LEN..offset + entry_size]);
        if hash1 != stored_hash1 || hash2 != stored_hash2 {
            rejected += 1;
            break;
        }

        let refs_offset = offset + HVLE_HEADER_LEN;
        let refs_total_size = dirty_pages_count.saturating_mul(8);
        let mut raw_data_offset = refs_offset.saturating_add(refs_total_size);

        if raw_data_offset > offset + entry_size {
            rejected += 1;
            break;
        }

        let mut dirty_pages = Vec::with_capacity(dirty_pages_count);
        let mut valid = true;

        for i in 0..dirty_pages_count {
            let ref_ptr = refs_offset + (i * 8);
            let page_offset = u32_at(ref_ptr) as usize;
            let page_size = u32_at(ref_ptr + 4) as usize;

            if raw_data_offset + page_size > offset + entry_size {
                valid = false;
                break;
            }

            dirty_pages.push(DirtyPage { offset_in_bins: page_offset, data: data[raw_data_offset..raw_data_offset + page_size].to_vec() });

            raw_data_offset += page_size;
        }

        if !valid {
            rejected += 1;
            break;
        }

        entries.push(HvLeEntry { sequence_number, hive_bins_data_size, dirty_pages });

        // Align next entry offset to 512-byte boundary
        offset = (offset + entry_size + SECTOR - 1) & !(SECTOR - 1);
    }

    (entries, rejected)
}

/// Parses a legacy transaction log file (old format, `DIRT` dirty vector).
fn parse_dirt_log(data: &[u8]) -> Vec<DirtyPage> {
    let mut pages = Vec::new();

    if data.len() < 2 * SECTOR + 4 || &data[0..4] != b"regf" {
        return pages;
    }

    // "DIRT" signature at the beginning of the second sector
    if &data[SECTOR..SECTOR + 4] != b"DIRT" {
        return pages;
    }

    let hive_bins_size = u32::from_le_bytes([data[0x28], data[0x29], data[0x2A], data[0x2B]]) as usize;

    let total_pages = hive_bins_size / SECTOR;
    let bitmap_bytes_len = total_pages.div_ceil(8);
    let bitmap_start = SECTOR + 4;
    let bitmap_end = bitmap_start + bitmap_bytes_len;

    if bitmap_end > data.len() {
        return pages;
    }

    // Dirty pages start at the sector following the last sector of the dirty vector
    let pages_data_start = (bitmap_end + SECTOR - 1) & !(SECTOR - 1);
    let mut current_page_offset = pages_data_start;

    for bit_index in 0..total_pages {
        let byte_pos = bitmap_start + (bit_index / 8);
        let bit_pos = bit_index % 8;

        if byte_pos >= data.len() {
            break;
        }

        if (data[byte_pos] & (1 << bit_pos)) != 0 {
            if current_page_offset + SECTOR <= data.len() {
                pages.push(DirtyPage { offset_in_bins: bit_index * SECTOR, data: data[current_page_offset..current_page_offset + SECTOR].to_vec() });
                current_page_offset += SECTOR;
            } else {
                break;
            }
        }
    }

    pages
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_block(primary: u32, secondary: u32, hbins: u32) -> Vec<u8> {
        let mut b = vec![0u8; 4096];
        b[..4].copy_from_slice(b"regf");
        b[4..8].copy_from_slice(&primary.to_le_bytes());
        b[8..12].copy_from_slice(&secondary.to_le_bytes());
        b[0x28..0x2C].copy_from_slice(&hbins.to_le_bytes());
        b
    }

    fn log_file(name: &str, mut data: Vec<u8>) -> LogFile {
        // file type: 1 for a DIRT log, 6 for an HvLE log, as Windows writes them
        let ty: u32 = if data.len() >= SECTOR + 4 && &data[SECTOR..SECTOR + 4] == b"DIRT" { 1 } else { 6 };
        data[0x1C..0x20].copy_from_slice(&ty.to_le_bytes());
        LogFile { path: PathBuf::from(name), data }
    }

    /// Builds one HvLE entry (with valid hashes) at `offset` inside `log`.
    fn write_hvle_entry(log: &mut Vec<u8>, offset: usize, seq: u32, bins_size: u32, pages: &[(u32, &[u8])]) -> usize {
        let refs = pages.len() * 8;
        let data_len: usize = pages.iter().map(|(_, d)| d.len()).sum();
        let entry_size = HVLE_HEADER_LEN + refs + data_len;
        let padded = (entry_size + SECTOR - 1) & !(SECTOR - 1);
        if log.len() < offset + padded {
            log.resize(offset + padded, 0);
        }
        log[offset..offset + 4].copy_from_slice(b"HvLE");
        log[offset + 4..offset + 8].copy_from_slice(&(padded as u32).to_le_bytes());
        log[offset + 12..offset + 16].copy_from_slice(&seq.to_le_bytes());
        log[offset + 16..offset + 20].copy_from_slice(&bins_size.to_le_bytes());
        log[offset + 20..offset + 24].copy_from_slice(&(pages.len() as u32).to_le_bytes());
        let mut rp = offset + HVLE_HEADER_LEN;
        let mut dp = offset + HVLE_HEADER_LEN + refs;
        for (page_off, data) in pages {
            log[rp..rp + 4].copy_from_slice(&page_off.to_le_bytes());
            log[rp + 4..rp + 8].copy_from_slice(&(data.len() as u32).to_le_bytes());
            log[dp..dp + data.len()].copy_from_slice(data);
            rp += 8;
            dp += data.len();
        }
        let h1 = marvin32(MARVIN32_SEED, &log[offset + HVLE_HEADER_LEN..offset + padded]);
        log[offset + 24..offset + 32].copy_from_slice(&h1.to_le_bytes());
        let h2 = marvin32(MARVIN32_SEED, &log[offset..offset + 32]);
        log[offset + 32..offset + 40].copy_from_slice(&h2.to_le_bytes());
        offset + padded
    }

    #[test]
    fn dirty_flag() {
        let clean = base_block(100, 100, 4096);
        assert!(!is_dirty(&clean));
        let mut dirty = clean.clone();
        dirty[8..12].copy_from_slice(&99u32.to_le_bytes());
        assert!(is_dirty(&dirty));
        assert!(!is_dirty(b"not a hive"));
    }

    #[test]
    fn marvin32_is_deterministic_and_length_sensitive() {
        let a = marvin32(MARVIN32_SEED, b"abc");
        let b = marvin32(MARVIN32_SEED, b"abc");
        let c = marvin32(MARVIN32_SEED, b"abcd");
        let d = marvin32(MARVIN32_SEED, b"");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
        assert_ne!(marvin32(0, b"abc"), a);
    }

    #[test]
    fn hvle_entries_are_hash_verified_and_replayed_in_order() {
        let mut log = base_block(10, 10, 4096);
        log.truncate(SECTOR); // log files have a 512-byte base block
        let page_a = b"BLOCKCARVE_FORENSIC_RECOVERED_PAGE_DATA";
        let page_b = b"SECOND_ENTRY";
        let next = write_hvle_entry(&mut log, SECTOR, 10, 4096, &[(0x20, page_a)]);
        let next = write_hvle_entry(&mut log, next, 11, 4096, &[(0x100, page_b)]);
        // A corrupted (torn) third entry must be rejected and must not stop the first two.
        let end = write_hvle_entry(&mut log, next, 12, 4096, &[(0x200, b"GARBAGE")]);
        log[next + 50] ^= 0xFF;
        assert!(end > next);

        let (entries, rejected) = parse_hvle_log(&log);
        assert_eq!(entries.len(), 2);
        assert_eq!(rejected, 1);
        assert_eq!(entries[0].sequence_number, 10);
        assert_eq!(entries[0].dirty_pages[0].offset_in_bins, 0x20);
        assert_eq!(entries[0].dirty_pages[0].data, page_a);

        // Replay into a dirty hive (primary 10 / secondary 9)
        let mut hive = base_block(10, 9, 4096);
        hive.resize(8192, 0);
        let r = replay(&hive, &[log_file("NTUSER.DAT.LOG1", log)]);

        assert!(matches!(r.data, Cow::Owned(_)));
        assert_eq!(r.outcome, Outcome::NewFormat { entries: 2, pages: 2, logs: 1, from_seq: 10, to_seq: 11, gap: false, rejected: 1 });
        assert_eq!(&r.data[4096 + 0x20..4096 + 0x20 + page_a.len()], page_a);
        assert_eq!(&r.data[4096 + 0x100..4096 + 0x100 + page_b.len()], page_b);
        let info = base_block_info(&r.data).unwrap();
        assert_eq!((info.primary_seq, info.secondary_seq), (11, 11));
        assert_eq!(base_block_checksum(&r.data[..512]), u32::from_le_bytes(r.data[0x1FC..0x200].try_into().unwrap()));
    }

    #[test]
    fn sequence_gap_stops_replay() {
        let mut log = base_block(10, 10, 4096);
        log.truncate(SECTOR);
        let next = write_hvle_entry(&mut log, SECTOR, 10, 4096, &[(0x20, b"FIRST")]);
        write_hvle_entry(&mut log, next, 12, 4096, &[(0x40, b"AFTER_GAP")]);
        let mut hive = base_block(10, 9, 4096);
        hive.resize(8192, 0);
        let r = replay(&hive, &[log_file("X.LOG1", log)]);
        assert!(matches!(r.outcome, Outcome::NewFormat { entries: 1, to_seq: 10, gap: true, .. }));
        assert_eq!(&r.data[4096 + 0x20..4096 + 0x25], b"FIRST");
        assert_ne!(&r.data[4096 + 0x40..4096 + 0x49], b"AFTER_GAP");
    }

    #[test]
    fn two_logs_are_chained_earliest_first() {
        // .LOG2 holds the earlier entry, .LOG1 the next one: order follows the log base blocks
        let mut log1 = base_block(11, 11, 4096);
        log1.truncate(SECTOR);
        write_hvle_entry(&mut log1, SECTOR, 11, 4096, &[(0x80, b"SECOND")]);
        let mut log2 = base_block(10, 10, 4096);
        log2.truncate(SECTOR);
        write_hvle_entry(&mut log2, SECTOR, 10, 4096, &[(0x20, b"FIRST")]);
        let mut hive = base_block(10, 9, 4096);
        hive.resize(8192, 0);
        let r = replay(&hive, &[log_file("H.LOG1", log1), log_file("H.LOG2", log2)]);
        assert!(matches!(r.outcome, Outcome::NewFormat { entries: 2, logs: 2, to_seq: 11, gap: false, .. }));
        assert_eq!(&r.data[4096 + 0x20..4096 + 0x25], b"FIRST");
        assert_eq!(&r.data[4096 + 0x80..4096 + 0x86], b"SECOND");
    }

    #[test]
    fn clean_hive_is_left_untouched_and_stale_logs_are_ignored() {
        let mut hive = base_block(44, 44, 4096);
        hive.resize(8192, 0);
        let mut log = base_block(43, 43, 4096);
        log.truncate(SECTOR);
        write_hvle_entry(&mut log, SECTOR, 43, 4096, &[(0x20, b"STALE")]);
        let logs = [log_file("SYSTEM.LOG1", log)];

        let r = replay(&hive, &logs);
        assert!(matches!(r.data, Cow::Borrowed(_)));
        assert_eq!(r.outcome, Outcome::Clean);

        // Dirty hive (45/44) but the only log is older than the last flush: nothing applicable
        hive[4..8].copy_from_slice(&45u32.to_le_bytes());
        let r = replay(&hive, &logs);
        assert!(matches!(r.data, Cow::Borrowed(_)));
        assert!(matches!(r.outcome, Outcome::NoApplicableEntries { .. }));

        assert_eq!(replay(&hive, &[]).outcome, Outcome::NoLogs);
        assert_eq!(replay(b"nope", &[]).outcome, Outcome::NotAHive);
    }

    #[test]
    fn old_dirt_log_requires_matching_timestamp() {
        let mut hive = base_block(7, 6, 1024);
        hive[12..20].copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
        hive.resize(4096 + 1024, 0);

        // Log: base block (seq 7/7, same timestamp), DIRT vector marking page 1, one page of data
        let mut log = base_block(7, 7, 1024);
        log[12..20].copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
        log.truncate(SECTOR);
        log.extend_from_slice(b"DIRT");
        log.push(0b0000_0010); // page index 1 dirty
        log.resize(2 * SECTOR, 0); // pad to the next sector
        let mut page = vec![0xABu8; SECTOR];
        page[..5].copy_from_slice(b"DIRTY");
        log.extend_from_slice(&page);
        let logs = [log_file("SOFTWARE.LOG1", log)];

        let r = replay(&hive, &logs);
        assert!(matches!(r.data, Cow::Owned(_)));
        assert_eq!(r.outcome, Outcome::OldFormat { pages: 1, log: PathBuf::from("SOFTWARE.LOG1") });
        assert_eq!(&r.data[4096 + 512..4096 + 517], b"DIRTY");

        // Same log but a different "last written" timestamp in the hive: must be skipped
        hive[12..20].copy_from_slice(&0x9999u64.to_le_bytes());
        let r = replay(&hive, &logs);
        assert!(matches!(r.data, Cow::Borrowed(_)));
        assert_eq!(r.outcome, Outcome::NothingUsable);
        assert_eq!(r.skipped_old, vec![(PathBuf::from("SOFTWARE.LOG1"), OldLogSkip::TimestampMismatch)]);
    }

    #[test]
    fn log_format_follows_the_file_type() {
        let mut log = base_block(10, 10, 4096);
        log.truncate(SECTOR);
        write_hvle_entry(&mut log, SECTOR, 10, 4096, &[(0x20, b"TYPED")]);
        let mut hive = base_block(10, 9, 4096);
        hive.resize(8192, 0);
        let mut old_type = log_file("H.LOG", log.clone());
        old_type.data[0x1C..0x20].copy_from_slice(&1u32.to_le_bytes());
        assert!(!replay(&hive, &[old_type]).outcome.applied(), "HvLE entries in a type-1 log");
        assert!(replay(&hive, &[log_file("H.LOG1", log)]).outcome.applied());
    }

    #[test]
    fn logs_beside_reads_files_next_to_the_hive() {
        let dir = std::env::temp_dir().join(format!("blockcarve_hive_logs_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let hive_path = dir.join("NTUSER.DAT");
        let mut hive = base_block(10, 9, 4096);
        hive.resize(8192, 0);
        let mut log = base_block(10, 10, 4096);
        log.truncate(SECTOR);
        write_hvle_entry(&mut log, SECTOR, 10, 4096, &[(0x20, b"BESIDE")]);
        log[0x1C..0x20].copy_from_slice(&6u32.to_le_bytes());
        std::fs::write(&hive_path, &hive).unwrap();
        std::fs::write(dir.join("NTUSER.DAT.LOG1"), &log).unwrap();

        let found = logs_beside(&hive_path);
        let r = replay_beside(&hive_path, &hive);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(found.len(), 1);
        assert!(r.outcome.applied());
        assert_eq!(&r.data[4096 + 0x20..4096 + 0x26], b"BESIDE");
    }

    #[test]
    fn hostile_logs_do_not_panic() {
        let mut hive = base_block(10, 9, 4096);
        hive.resize(8192, 0);
        let mut log = base_block(10, 10, 4096);
        log.truncate(SECTOR);
        log.extend_from_slice(b"HvLE");
        log.extend_from_slice(&u32::MAX.to_le_bytes());
        log.resize(2 * SECTOR, 0xFF);
        let r = replay(&hive, &[log_file("X.LOG1", log)]);
        assert!(!r.outcome.applied());
        let mut dirt = base_block(7, 7, u32::MAX);
        dirt.truncate(SECTOR);
        dirt.extend_from_slice(b"DIRT");
        let r = replay(&hive, &[log_file("Y.LOG", dirt)]);
        assert!(!r.outcome.applied());
    }

    /// Ground-truth check against the yarp test corpus when it is available locally:
    /// `BLOCKCARVE_YARP_HIVES=<dir with NewDirtyHive1/, OldDirtyHive/>`.
    #[test]
    fn recovery_matches_yarp_reference_hives() {
        let root = match std::env::var("BLOCKCARVE_YARP_HIVES").or_else(|_| std::env::var("CAAREA_YARP_HIVES")) {
            Ok(r) => PathBuf::from(r),
            Err(_) => return,
        };
        let cases = [
            ("NewDirtyHive1/NewDirtyHive", "NewDirtyHive1/RecoveredHive_Windows10"),
            ("OldDirtyHive/OldDirtyHive", "OldDirtyHive/RecoveredHive_Windows7"),
        ];
        for (dirty, reference) in cases {
            let dirty_path = root.join(dirty);
            let dirty_data = std::fs::read(&dirty_path).expect("dirty hive fixture");
            let reference_data = std::fs::read(root.join(reference)).expect("reference fixture");
            assert!(is_dirty(&dirty_data), "{} should be dirty", dirty);
            let recovered = replay_beside(&dirty_path, &dirty_data).data;
            assert!(matches!(recovered, Cow::Owned(_)), "{}: nothing was replayed", dirty);
            let bins = base_block_info(&recovered).unwrap().hive_bins_size as usize;
            let n = (4096 + bins).min(recovered.len()).min(reference_data.len());
            assert!(n > 4096, "{}: recovered buffer too small", dirty);
            // Windows refreshes the timestamp stored in the first hbin header (bytes 20..28 of
            // the hbin) when it writes the recovered hive; that field carries no cell data.
            let first_hbin_ts = 4096 + 20..4096 + 28;
            let diffs: Vec<usize> = (4096..n).filter(|i| !first_hbin_ts.contains(i)).filter(|&i| recovered[i] != reference_data[i]).collect();
            // The old-format reference was produced by Windows 7 *loading* the recovered hive,
            // which also refreshes cached nk fields ("largest value name length"): one byte in
            // 1,109 corrected bytes. The new-format reference must match exactly.
            let tolerance = if dirty.starts_with("Old") { 4 } else { 0 };
            assert!(
                diffs.len() <= tolerance,
                "{}: {} byte(s) of recovered hive bins differ from the Windows-recovered reference, first at {:#x}",
                dirty,
                diffs.len(),
                diffs[0]
            );
        }
    }
}
