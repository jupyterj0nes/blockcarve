//! EVTX carving (masstin's design): every 64 KB `ElfChnk` chunk is self-contained, so chunks
//! found in unallocated space are accepted on their own checksums, grouped and glued behind
//! a synthetic `ElfFile` header into files the normal EVTX pipeline reads. Records outside
//! any chunk (`**\0\0` orphans) cannot be rendered without their chunk's templates, but
//! their time and record id are still a trace of a log that was cleared.
//!
//! Nothing here parses a record: parsing a corrupt chunk can ask the allocator for gigabytes
//! and that aborts the process. Tools validate the synthetic files in a child process and
//! pass that check to [`ChunkGroups::write_all`], which bisects a failing file down to the
//! chunks that pass.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use crate::content_hash;
use crate::{FILETIME_2000, FILETIME_2040};

pub const CHUNK_MAGIC: &[u8; 8] = b"ElfChnk\0";
pub const FILE_MAGIC: &[u8; 8] = b"ElfFile\0";
pub const RECORD_MAGIC: &[u8; 4] = b"\x2a\x2a\x00\x00";
pub const CHUNK_SIZE: usize = 65536;
/// Bytes of a chunk covered by the header checksum: `0..120` and `128..512`.
const CHUNK_HEADER_LEN: usize = 512;

/// CRC-32 (IEEE 802.3), the checksum EVTX uses.
pub fn crc32_ieee(data: &[u8]) -> u32 {
    crc32_update(0xFFFF_FFFF, data) ^ 0xFFFF_FFFF
}

fn crc32_update(mut crc: u32, data: &[u8]) -> u32 {
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    crc
}

/// Header fields of a chunk that the carver looks at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkHeader {
    pub first_record_number: u64,
    pub last_record_number: u64,
    pub first_record_id: u64,
    pub last_record_id: u64,
    pub last_record_offset: u32,
    pub free_space_offset: u32,
    pub records_checksum: u32,
    pub header_checksum: u32,
}

impl ChunkHeader {
    pub fn parse(chunk: &[u8]) -> Option<Self> {
        if chunk.len() < CHUNK_HEADER_LEN || !chunk.starts_with(CHUNK_MAGIC) {
            return None;
        }
        let u64_at = |o: usize| u64::from_le_bytes(chunk[o..o + 8].try_into().unwrap());
        let u32_at = |o: usize| u32::from_le_bytes(chunk[o..o + 4].try_into().unwrap());
        Some(ChunkHeader {
            first_record_number: u64_at(8),
            last_record_number: u64_at(16),
            first_record_id: u64_at(24),
            last_record_id: u64_at(32),
            last_record_offset: u32_at(44),
            free_space_offset: u32_at(48),
            records_checksum: u32_at(52),
            header_checksum: u32_at(124),
        })
    }
}

/// Is this a chunk worth keeping? Magic, a sane free-space offset, and the two CRC32s every
/// chunk carries: over the header (bytes 0..120 and 128..512) and over the record data
/// (bytes 512..free space offset).
pub fn chunk_checksums_ok(chunk: &[u8]) -> bool {
    if chunk.len() < CHUNK_SIZE {
        return false;
    }
    let Some(h) = ChunkHeader::parse(chunk) else { return false };
    let free = h.free_space_offset as usize;
    if !(CHUNK_HEADER_LEN..=CHUNK_SIZE).contains(&free) || h.first_record_number > h.last_record_number {
        return false;
    }
    let header_crc = crc32_update(crc32_update(0xFFFF_FFFF, &chunk[..120]), &chunk[128..512]) ^ 0xFFFF_FFFF;
    if header_crc != h.header_checksum {
        return false;
    }
    crc32_ieee(&chunk[512..free]) == h.records_checksum
}

/// Writes a synthetic EVTX: 4096-byte `ElfFile` header followed by the chunks.
pub fn write_synthetic_evtx(path: &Path, chunks: &[Vec<u8>]) -> Result<(), String> {
    let mut header = [0u8; 4096];
    header[0..8].copy_from_slice(FILE_MAGIC);
    let last_chunk = chunks.len().saturating_sub(1) as u64;
    header[16..24].copy_from_slice(&last_chunk.to_le_bytes());
    header[32..36].copy_from_slice(&128u32.to_le_bytes());
    header[36..38].copy_from_slice(&1u16.to_le_bytes());
    header[38..40].copy_from_slice(&3u16.to_le_bytes());
    header[40..42].copy_from_slice(&4096u16.to_le_bytes());
    header[42..44].copy_from_slice(&(chunks.len() as u16).to_le_bytes());
    let crc = crc32_ieee(&header[0..120]);
    header[124..128].copy_from_slice(&crc.to_le_bytes());
    let mut out = Vec::with_capacity(4096 + chunks.len() * CHUNK_SIZE);
    out.extend_from_slice(&header);
    for c in chunks {
        if c.len() == CHUNK_SIZE {
            out.extend_from_slice(c);
        }
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(path, out).map_err(|e| e.to_string())
}

/// Chunks collected during a scan, grouped by a key of the tool's choosing (a provider, a
/// source), with the offset of the first one. Identical chunks are kept once; seed
/// `seen_hashes` with [`chunk_hashes_under`] to drop chunks of logs already extracted.
#[derive(Default)]
pub struct ChunkGroups {
    pub groups: BTreeMap<String, (u64, Vec<Vec<u8>>)>,
    pub seen_hashes: HashSet<u64>,
}

/// One synthetic file written by [`ChunkGroups::write_all`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrittenFile {
    pub key: String,
    pub path: PathBuf,
    /// Offset of the first chunk of the group in the source.
    pub first_offset: u64,
    pub chunks_kept: usize,
    pub chunks_dropped: usize,
}

impl ChunkGroups {
    /// `true` when the chunk was new.
    pub fn add(&mut self, key: String, offset: u64, chunk: Vec<u8>) -> bool {
        let hash = content_hash(&chunk);
        if !self.seen_hashes.insert(hash) {
            return false;
        }
        let entry = self.groups.entry(key).or_insert_with(|| (offset, Vec::new()));
        entry.1.push(chunk);
        true
    }

    pub fn total_chunks(&self) -> usize {
        self.groups.values().map(|(_, c)| c.len()).sum()
    }

    /// Writes one synthetic file per group at `path_for(key)` and runs `validate` on it (a
    /// child-process parse, in the tools). A file that fails is rebuilt from the chunks that
    /// pass on their own, found by bisection (a bad chunk costs log2(n) runs, not n); the
    /// rest are dropped. Groups with nothing left produce no file.
    pub fn write_all(&self, path_for: &dyn Fn(&str) -> PathBuf, validate: &mut dyn FnMut(&Path) -> bool) -> Vec<WrittenFile> {
        let mut out = Vec::new();
        for (key, (offset, chunks)) in &self.groups {
            let path = path_for(key);
            if write_synthetic_evtx(&path, chunks).is_err() {
                continue;
            }
            if validate(&path) {
                out.push(WrittenFile { key: key.clone(), path, first_offset: *offset, chunks_kept: chunks.len(), chunks_dropped: 0 });
                continue;
            }
            let probe = path.with_extension("probe.evtx");
            let mut good: Vec<Vec<u8>> = Vec::new();
            let mut stack: Vec<&[Vec<u8>]> = vec![chunks.as_slice()];
            while let Some(part) = stack.pop() {
                if part.is_empty() {
                    continue;
                }
                if write_synthetic_evtx(&probe, part).is_ok() && validate(&probe) {
                    good.extend(part.iter().cloned());
                } else if part.len() > 1 {
                    let (a, b) = part.split_at(part.len() / 2);
                    stack.push(b);
                    stack.push(a);
                }
            }
            let _ = std::fs::remove_file(&probe);
            let dropped = chunks.len() - good.len();
            if good.is_empty() || write_synthetic_evtx(&path, &good).is_err() {
                let _ = std::fs::remove_file(&path);
                continue;
            }
            out.push(WrittenFile { key: key.clone(), path, first_offset: *offset, chunks_kept: good.len(), chunks_dropped: dropped });
        }
        out
    }
}

/// Hashes of every chunk of every EVTX file under `dir` (the logs a file-system pass already
/// extracted), so the carver can tell a live chunk from a lost one.
pub fn chunk_hashes_under(dir: &Path) -> HashSet<u64> {
    let mut out = HashSet::new();
    for entry in walkdir::WalkDir::new(dir).into_iter().flatten() {
        if !entry.file_type().is_file() || !entry.file_name().to_string_lossy().to_ascii_lowercase().ends_with(".evtx") {
            continue;
        }
        let Ok(bytes) = std::fs::read(entry.path()) else { continue };
        if !bytes.starts_with(b"ElfFile") {
            continue;
        }
        let mut pos = 4096;
        while pos + CHUNK_SIZE <= bytes.len() {
            if bytes[pos..].starts_with(CHUNK_MAGIC) {
                out.insert(content_hash(&bytes[pos..pos + CHUNK_SIZE]));
            }
            pos += CHUNK_SIZE;
        }
    }
    out
}

/// An orphan record header outside any chunk: `(record id, FILETIME, size)`. The size is
/// repeated at the record's end and the BinXML must open with a fragment header.
pub fn orphan_record(buf: &[u8]) -> Option<(u64, u64, u32)> {
    if buf.len() < 28 || !buf.starts_with(RECORD_MAGIC) {
        return None;
    }
    let size = u32::from_le_bytes(buf[4..8].try_into().unwrap());
    if !(28..=65024).contains(&size) || size as usize > buf.len() {
        return None;
    }
    let trail = size as usize - 4;
    if u32::from_le_bytes(buf[trail..trail + 4].try_into().unwrap()) != size {
        return None;
    }
    if buf[24] != 0x0F {
        return None;
    }
    let ft = u64::from_le_bytes(buf[16..24].try_into().unwrap());
    if !(FILETIME_2000..FILETIME_2040).contains(&ft) {
        return None;
    }
    let id = u64::from_le_bytes(buf[8..16].try_into().unwrap());
    Some((id, ft, size))
}

/// A chunk with valid checksums and no records, for tests.
pub fn synthetic_chunk() -> Vec<u8> {
    let mut c = vec![0u8; CHUNK_SIZE];
    c[..8].copy_from_slice(CHUNK_MAGIC);
    c[40..44].copy_from_slice(&128u32.to_le_bytes());
    c[44..48].copy_from_slice(&512u32.to_le_bytes());
    c[48..52].copy_from_slice(&512u32.to_le_bytes());
    c[52..56].copy_from_slice(&crc32_ieee(&[]).to_le_bytes());
    let header_crc = crc32_update(crc32_update(0xFFFF_FFFF, &c[..120]), &c[128..512]) ^ 0xFFFF_FFFF;
    c[124..128].copy_from_slice(&header_crc.to_le_bytes());
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_matches_the_reference_vector() {
        assert_eq!(crc32_ieee(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn checksums_accept_a_coherent_chunk_and_reject_damage() {
        let chunk = synthetic_chunk();
        assert!(chunk_checksums_ok(&chunk));
        let mut damaged = chunk.clone();
        damaged[600] = 1; // inside the free space: not covered
        assert!(chunk_checksums_ok(&damaged));
        let mut damaged = chunk.clone();
        damaged[48..52].copy_from_slice(&1024u32.to_le_bytes()); // free space grows: data CRC fails
        assert!(!chunk_checksums_ok(&damaged));
        let mut damaged = chunk;
        damaged[200] ^= 0xff; // header byte: header CRC fails
        assert!(!chunk_checksums_ok(&damaged));
        assert!(!chunk_checksums_ok(&vec![0u8; CHUNK_SIZE]));
    }

    #[test]
    fn synthetic_file_groups_and_orphans() {
        let dir = std::env::temp_dir().join(format!("blockcarve_evtx_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut groups = ChunkGroups::default();
        let a = synthetic_chunk();
        let mut b = synthetic_chunk();
        b[8..16].copy_from_slice(&1u64.to_le_bytes());
        assert!(groups.add("p".into(), 100, a.clone()));
        assert!(!groups.add("p".into(), 200, a));
        assert!(groups.add("p".into(), 300, b));
        assert_eq!(groups.total_chunks(), 2);
        // the validator rejects any file whose first chunk has record number 0
        let mut validate = |p: &Path| {
            let bytes = std::fs::read(p).unwrap();
            u64::from_le_bytes(bytes[4096 + 8..4096 + 16].try_into().unwrap()) != 0
        };
        let written = groups.write_all(&|k| dir.join(format!("{k}.evtx")), &mut validate);
        assert_eq!(written.len(), 1);
        assert_eq!((written[0].chunks_kept, written[0].chunks_dropped, written[0].first_offset), (1, 1, 100));
        let bytes = std::fs::read(&written[0].path).unwrap();
        assert_eq!(bytes.len(), 4096 + CHUNK_SIZE);
        assert_eq!(chunk_hashes_under(&dir).len(), 1);
        let _ = std::fs::remove_dir_all(&dir);

        let mut rec = vec![0u8; 64];
        rec[0..4].copy_from_slice(RECORD_MAGIC);
        rec[4..8].copy_from_slice(&64u32.to_le_bytes());
        rec[8..16].copy_from_slice(&4242u64.to_le_bytes());
        rec[16..24].copy_from_slice(&133_552_399_310_000_000u64.to_le_bytes());
        rec[24] = 0x0F;
        rec[60..64].copy_from_slice(&64u32.to_le_bytes());
        assert_eq!(orphan_record(&rec), Some((4242, 133_552_399_310_000_000, 64)));
        rec[60] = 0;
        assert!(orphan_record(&rec).is_none());
    }
}
