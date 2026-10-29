//! Deleted registry keys and values recovered from the free cells of a hive.
//!
//! When a key or value is deleted, Windows only flips the sign of its cell size: the bytes
//! stay where they were until the space is reused. [`HiveImage::scan`] walks every hive bin
//! with its own bounds-checked parser (free cells may hold garbage, so no count, size or
//! offset is trusted without checking it), rebuilds the path of each deleted key through
//! its parent chain, collects the values its list still points to, and reports the freed
//! value cells no deleted key references (orphans).
//!
//! The scan works on the bytes of any hive: one read from disk (apply its transaction logs
//! first so the free cells are the current ones), one extracted from a shadow copy, or one
//! carved from raw bytes with [`crate::hive::read_hive`]. What is evidence is the caller's
//! decision; this module only recovers. Faramir's walker, shared by faramir, caarea and
//! masstin.

use std::collections::{HashMap, HashSet};

use crate::hive::{BASE_BLOCK_SIZE, HBIN_HEADER, HBIN_MAGIC, REGF_MAGIC};

const NK_FIXED: usize = 0x4c;
const VK_FIXED: usize = 0x14;
/// Values read from one key's list at most.
pub const MAX_VALUES_PER_KEY: u32 = 4096;
/// Largest value data kept.
pub const MAX_DATA_BYTES: usize = 64 * 1024;
const MAX_NAME_BYTES: usize = 512;
/// Parent links followed at most when rebuilding a path.
pub const MAX_CHAIN: usize = 128;
/// Prefix of a path whose parent chain could not be followed to the root.
pub const BROKEN_CHAIN_PREFIX: &str = "?\\";

/// Registry value types this module decodes as text.
pub const REG_SZ: u32 = 1;
pub const REG_EXPAND_SZ: u32 = 2;
pub const REG_BINARY: u32 = 3;
pub const REG_DWORD: u32 = 4;
pub const REG_MULTI_SZ: u32 = 7;
pub const REG_QWORD: u32 = 11;

/// A key cell (`nk`), allocated or free.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawKey {
    /// Cell offset relative to the start of the hive bins.
    pub offset: u32,
    pub allocated: bool,
    pub name: String,
    pub parent: u32,
    /// Last write time of the key (FILETIME).
    pub timestamp_filetime: u64,
    pub values_count: u32,
    pub values_list: u32,
    pub is_root: bool,
}

/// A value cell (`vk`), allocated or free, with its data when it could be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawValue {
    pub offset: u32,
    pub allocated: bool,
    /// `(Default)` for the unnamed value.
    pub name: String,
    pub data_type: u32,
    /// Data bytes (inline data for up to 4 bytes, the data cell otherwise), up to
    /// [`MAX_DATA_BYTES`]. `None` when the data cell is gone or implausible.
    pub data: Option<Vec<u8>>,
}

impl RawValue {
    /// The data as text for `REG_SZ`, `REG_EXPAND_SZ` (up to the first NUL) and
    /// `REG_MULTI_SZ` (strings joined with `|`); `None` for other types.
    pub fn text(&self) -> Option<String> {
        let data = self.data.as_deref()?;
        match self.data_type {
            REG_SZ | REG_EXPAND_SZ => Some(utf16_until_nul(data)),
            REG_MULTI_SZ => {
                let units: Vec<u16> = data.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                let parts: Vec<String> = units.split(|&u| u == 0).filter(|p| !p.is_empty()).map(String::from_utf16_lossy).collect();
                Some(parts.join("|"))
            }
            _ => None,
        }
    }

    /// The data as an integer for `REG_DWORD` and `REG_QWORD`.
    pub fn number(&self) -> Option<u64> {
        let d = self.data.as_deref()?;
        match self.data_type {
            REG_DWORD if d.len() >= 4 => Some(u32::from_le_bytes(d[..4].try_into().unwrap()) as u64),
            REG_QWORD if d.len() >= 8 => Some(u64::from_le_bytes(d[..8].try_into().unwrap())),
            _ => None,
        }
    }
}

/// A free key cell with the path rebuilt through its parents and the values its list
/// still points to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletedKey {
    pub key: RawKey,
    /// Root-relative path (`Microsoft\Windows\CurrentVersion\Run`) or, when the parent
    /// chain is broken, [`BROKEN_CHAIN_PREFIX`] followed by the reachable tail.
    pub path: String,
    pub values: Vec<RawValue>,
}

impl DeletedKey {
    /// The path without the broken-chain marker.
    pub fn path_tail(&self) -> &str {
        self.path.strip_prefix(BROKEN_CHAIN_PREFIX).unwrap_or(&self.path)
    }

    /// Value by name, case-insensitively.
    pub fn value(&self, name: &str) -> Option<&RawValue> {
        self.values.iter().find(|v| v.name.eq_ignore_ascii_case(name))
    }
}

/// What a scan found.
#[derive(Debug, Default, Clone)]
pub struct DeletedScan {
    pub bins: usize,
    pub cells: usize,
    pub live_keys: usize,
    /// Sorted by path, then offset.
    pub deleted_keys: Vec<DeletedKey>,
    /// Free value cells that no deleted key references.
    pub orphan_values: Vec<RawValue>,
}

fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}
fn u16_at(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}
fn u64_at(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}

fn decode_name(raw: &[u8], ascii: bool) -> Option<String> {
    let s = if ascii {
        raw.iter().map(|&b| b as char).collect::<String>()
    } else {
        let units: Vec<u16> = raw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        String::from_utf16(&units).ok()?
    };
    if s.is_empty() || s.chars().any(|c| c.is_control()) {
        return None;
    }
    Some(s)
}

fn utf16_until_nul(raw: &[u8]) -> String {
    let units: Vec<u16> = raw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&u| u != 0).collect();
    String::from_utf16_lossy(&units)
}

/// Bounds-checked view over a hive's bytes.
pub struct HiveImage<'a> {
    bytes: &'a [u8],
    root_cell: u32,
}

impl<'a> HiveImage<'a> {
    /// `None` unless the bytes start with a `regf` base block and hold at least one bin header.
    pub fn new(bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() < BASE_BLOCK_SIZE + HBIN_HEADER || &bytes[..4] != REGF_MAGIC {
            return None;
        }
        Some(HiveImage { bytes, root_cell: u32_at(bytes, 0x24) })
    }

    /// Last write time of the hive itself (base block), the upper bound for an orphan value.
    pub fn hive_timestamp(&self) -> u64 {
        u64_at(self.bytes, 0x0c)
    }

    fn region(&self) -> &[u8] {
        &self.bytes[BASE_BLOCK_SIZE..]
    }

    /// Cell at `off` (relative to the hive bins): `(allocated, payload after the size field)`.
    pub fn cell(&self, off: u32) -> Option<(bool, &[u8])> {
        let r = self.region();
        let o = off as usize;
        if o + 4 > r.len() || !o.is_multiple_of(8) {
            return None;
        }
        let raw = i32::from_le_bytes([r[o], r[o + 1], r[o + 2], r[o + 3]]);
        let size = raw.unsigned_abs() as usize;
        if size < 8 || !size.is_multiple_of(8) || o + size > r.len() {
            return None;
        }
        Some((raw < 0, &r[o + 4..o + size]))
    }

    fn parse_nk(&self, off: u32) -> Option<RawKey> {
        let (allocated, p) = self.cell(off)?;
        if p.len() < NK_FIXED || &p[..2] != b"nk" {
            return None;
        }
        let flags = u16_at(p, 2);
        let name_len = u16_at(p, 0x48) as usize;
        if name_len == 0 || name_len > MAX_NAME_BYTES || NK_FIXED + name_len > p.len() {
            return None;
        }
        let name = decode_name(&p[NK_FIXED..NK_FIXED + name_len], flags & 0x20 != 0)?;
        Some(RawKey {
            offset: off,
            allocated,
            name,
            parent: u32_at(p, 0x10),
            timestamp_filetime: u64_at(p, 0x04),
            values_count: u32_at(p, 0x24),
            values_list: u32_at(p, 0x28),
            is_root: flags & 0x04 != 0 || off == self.root_cell,
        })
    }

    fn parse_vk(&self, off: u32) -> Option<RawValue> {
        let (allocated, p) = self.cell(off)?;
        if p.len() < VK_FIXED || &p[..2] != b"vk" {
            return None;
        }
        let name_len = u16_at(p, 2) as usize;
        let data_size = u32_at(p, 4);
        let data_field = u32_at(p, 8);
        let data_type = u32_at(p, 12);
        let flags = u16_at(p, 16);
        if name_len > MAX_NAME_BYTES || VK_FIXED + name_len > p.len() {
            return None;
        }
        let name = if name_len == 0 { "(Default)".to_string() } else { decode_name(&p[VK_FIXED..VK_FIXED + name_len], flags & 1 != 0)? };
        let data = self.raw_data(data_size, data_field);
        Some(RawValue { offset: off, allocated, name, data_type, data })
    }

    fn raw_data(&self, data_size: u32, data_field: u32) -> Option<Vec<u8>> {
        let len = (data_size & 0x7fff_ffff) as usize;
        if data_size & 0x8000_0000 != 0 {
            let bytes = data_field.to_le_bytes();
            return Some(bytes[..len.min(4)].to_vec());
        }
        if len == 0 || len > MAX_DATA_BYTES {
            return None;
        }
        let (_, p) = self.cell(data_field)?;
        if p.len() < len {
            return None;
        }
        Some(p[..len].to_vec())
    }

    fn values_of(&self, key: &RawKey, referenced: &mut HashSet<u32>) -> Vec<RawValue> {
        let count = key.values_count;
        if count == 0 || count > MAX_VALUES_PER_KEY || key.values_list == 0xffff_ffff {
            return Vec::new();
        }
        let Some((_, list)) = self.cell(key.values_list) else { return Vec::new() };
        let mut out = Vec::new();
        for i in 0..count as usize {
            if (i + 1) * 4 > list.len() {
                break;
            }
            let vk_off = u32_at(list, i * 4);
            if let Some(v) = self.parse_vk(vk_off) {
                referenced.insert(vk_off);
                out.push(v);
            }
        }
        out
    }

    /// Walks every hive bin and classifies its cells.
    pub fn scan(&self) -> DeletedScan {
        let r = self.region();
        let mut scan = DeletedScan::default();
        let mut keys: HashMap<u32, RawKey> = HashMap::new();
        let mut free_vk: Vec<u32> = Vec::new();

        let mut pos = 0usize;
        while pos + HBIN_HEADER <= r.len() {
            if &r[pos..pos + 4] != HBIN_MAGIC {
                pos += 4096;
                continue;
            }
            let size = u32_at(r, pos + 8) as usize;
            if size == 0 || !size.is_multiple_of(4096) || pos + size > r.len() {
                pos += 4096;
                continue;
            }
            scan.bins += 1;
            let end = pos + size;
            let mut c = pos + HBIN_HEADER;
            while c + 8 <= end {
                let raw = i32::from_le_bytes([r[c], r[c + 1], r[c + 2], r[c + 3]]);
                let csize = raw.unsigned_abs() as usize;
                if csize < 8 || !csize.is_multiple_of(8) || c + csize > end {
                    break;
                }
                scan.cells += 1;
                let magic = &r[c + 4..c + 6];
                let off = c as u32;
                if magic == b"nk" {
                    if let Some(k) = self.parse_nk(off) {
                        if k.allocated {
                            scan.live_keys += 1;
                        }
                        keys.insert(off, k);
                    }
                } else if magic == b"vk" && raw > 0 {
                    free_vk.push(off);
                }
                c += csize;
            }
            pos = end;
        }

        let mut referenced: HashSet<u32> = HashSet::new();
        let mut deleted: Vec<DeletedKey> = Vec::new();
        for key in keys.values().filter(|k| !k.allocated) {
            let path = self.resolve_path(key, &keys);
            let values = self.values_of(key, &mut referenced);
            deleted.push(DeletedKey { key: key.clone(), path, values });
        }
        deleted.sort_by(|a, b| a.path.cmp(&b.path).then(a.key.offset.cmp(&b.key.offset)));
        scan.deleted_keys = deleted;

        for off in free_vk {
            if referenced.contains(&off) {
                continue;
            }
            if let Some(v) = self.parse_vk(off) {
                scan.orphan_values.push(v);
            }
        }
        scan
    }

    fn resolve_path(&self, key: &RawKey, keys: &HashMap<u32, RawKey>) -> String {
        let mut parts = vec![key.name.clone()];
        let mut cur = key.parent;
        let mut hops = 0;
        loop {
            if cur == self.root_cell {
                parts.reverse();
                return parts.join("\\");
            }
            hops += 1;
            if hops > MAX_CHAIN {
                break;
            }
            match keys.get(&cur) {
                Some(p) if p.is_root => {
                    parts.reverse();
                    return parts.join("\\");
                }
                Some(p) => {
                    parts.push(p.name.clone());
                    cur = p.parent;
                }
                None => break,
            }
        }
        parts.push("?".to_string());
        parts.reverse();
        parts.join("\\")
    }
}

/// Scans `bytes` for deleted keys and orphan values; `None` when they are not a hive. A
/// panic inside the walker (it should not happen, the parser checks every bound) is caught
/// and reported as `None` too.
pub fn scan(bytes: &[u8]) -> Option<DeletedScan> {
    let image = HiveImage::new(bytes)?;
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| image.scan())).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny hive: live ROOT\ControlSet001\Services, a freed `EvilSvc` key under Services
    /// with an ImagePath, a freed key whose parent is gone, and a freed orphan value.
    fn synthetic_hive() -> Vec<u8> {
        let mut h = vec![0u8; 4096 + 8192];
        h[0..4].copy_from_slice(b"regf");
        h[0x0c..0x14].copy_from_slice(&133_552_399_310_000_000u64.to_le_bytes());
        h[0x24..0x28].copy_from_slice(&0x20u32.to_le_bytes());
        let bins = 4096;
        h[bins..bins + 4].copy_from_slice(b"hbin");
        h[bins + 8..bins + 12].copy_from_slice(&8192u32.to_le_bytes());
        let mut cursor = 0x20usize;

        #[allow(clippy::too_many_arguments)]
        fn put_nk(h: &mut [u8], cursor: &mut usize, allocated: bool, name: &str, parent: u32, root: bool, ts: u64, vcount: u32, vlist: u32) -> u32 {
            let bins = 4096;
            let size = (4 + NK_FIXED + name.len()).div_ceil(8) * 8;
            let off = *cursor;
            let abs = bins + off;
            let s = if allocated { -(size as i32) } else { size as i32 };
            h[abs..abs + 4].copy_from_slice(&s.to_le_bytes());
            let p = abs + 4;
            h[p..p + 2].copy_from_slice(b"nk");
            let flags: u16 = 0x20 | if root { 0x04 } else { 0 };
            h[p + 2..p + 4].copy_from_slice(&flags.to_le_bytes());
            h[p + 4..p + 12].copy_from_slice(&ts.to_le_bytes());
            h[p + 0x10..p + 0x14].copy_from_slice(&parent.to_le_bytes());
            h[p + 0x24..p + 0x28].copy_from_slice(&vcount.to_le_bytes());
            h[p + 0x28..p + 0x2c].copy_from_slice(&vlist.to_le_bytes());
            h[p + 0x48..p + 0x4a].copy_from_slice(&(name.len() as u16).to_le_bytes());
            h[p + NK_FIXED..p + NK_FIXED + name.len()].copy_from_slice(name.as_bytes());
            *cursor += size;
            off as u32
        }
        fn put_vk(h: &mut [u8], cursor: &mut usize, allocated: bool, name: &str, data: &[u8], dtype: u32) -> u32 {
            let bins = 4096;
            let dsize = (4 + data.len()).div_ceil(8) * 8;
            let doff = *cursor;
            h[bins + doff..bins + doff + 4].copy_from_slice(&(-(dsize as i32)).to_le_bytes());
            h[bins + doff + 4..bins + doff + 4 + data.len()].copy_from_slice(data);
            *cursor += dsize;
            let size = (4 + VK_FIXED + name.len()).div_ceil(8) * 8;
            let off = *cursor;
            let abs = bins + off;
            let s = if allocated { -(size as i32) } else { size as i32 };
            h[abs..abs + 4].copy_from_slice(&s.to_le_bytes());
            let p = abs + 4;
            h[p..p + 2].copy_from_slice(b"vk");
            h[p + 2..p + 4].copy_from_slice(&(name.len() as u16).to_le_bytes());
            h[p + 4..p + 8].copy_from_slice(&(data.len() as u32).to_le_bytes());
            h[p + 8..p + 12].copy_from_slice(&(doff as u32).to_le_bytes());
            h[p + 12..p + 16].copy_from_slice(&dtype.to_le_bytes());
            h[p + 16..p + 18].copy_from_slice(&1u16.to_le_bytes());
            h[p + VK_FIXED..p + VK_FIXED + name.len()].copy_from_slice(name.as_bytes());
            *cursor += size;
            off as u32
        }
        fn put_list(h: &mut [u8], cursor: &mut usize, offs: &[u32]) -> u32 {
            let bins = 4096;
            let size = (4 + offs.len() * 4).div_ceil(8) * 8;
            let off = *cursor;
            h[bins + off..bins + off + 4].copy_from_slice(&(-(size as i32)).to_le_bytes());
            for (i, o) in offs.iter().enumerate() {
                h[bins + off + 4 + i * 4..bins + off + 8 + i * 4].copy_from_slice(&o.to_le_bytes());
            }
            *cursor += size;
            off as u32
        }

        let ts = 133_552_399_310_000_000u64;
        let root = put_nk(&mut h, &mut cursor, true, "ROOT", 0, true, ts, 0, 0xffff_ffff);
        let cs = put_nk(&mut h, &mut cursor, true, "ControlSet001", root, false, ts, 0, 0xffff_ffff);
        let services = put_nk(&mut h, &mut cursor, true, "Services", cs, false, ts, 0, 0xffff_ffff);
        let image: Vec<u8> = "C:\\Temp\\evil.exe -svc\0".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let vk_image = put_vk(&mut h, &mut cursor, false, "ImagePath", &image, REG_EXPAND_SZ);
        let start = 3u32.to_le_bytes();
        let vk_start = put_vk(&mut h, &mut cursor, false, "Start", &start, REG_DWORD);
        let list = put_list(&mut h, &mut cursor, &[vk_image, vk_start]);
        put_nk(&mut h, &mut cursor, false, "EvilSvc", services, false, ts + 10_000_000, 2, list);
        put_nk(&mut h, &mut cursor, false, "Lost", 0x1ff8, false, ts, 0, 0xffff_ffff);
        let cmd: Vec<u8> = "cmd.exe /c evil\0".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        put_vk(&mut h, &mut cursor, false, "Updater", &cmd, REG_SZ);
        h
    }

    #[test]
    fn recovers_keys_values_and_orphans() {
        let hive = synthetic_hive();
        let image = HiveImage::new(&hive).unwrap();
        assert_eq!(image.hive_timestamp(), 133_552_399_310_000_000);
        let s = image.scan();
        assert_eq!(s.bins, 1);
        assert_eq!(s.live_keys, 3);
        assert_eq!(s.deleted_keys.len(), 2);
        let evil = s.deleted_keys.iter().find(|k| k.key.name == "EvilSvc").unwrap();
        assert_eq!(evil.path, "ControlSet001\\Services\\EvilSvc");
        assert_eq!(evil.key.timestamp_filetime, 133_552_399_320_000_000);
        assert_eq!(evil.value("imagepath").unwrap().text().as_deref(), Some("C:\\Temp\\evil.exe -svc"));
        assert_eq!(evil.value("Start").unwrap().number(), Some(3));
        let lost = s.deleted_keys.iter().find(|k| k.key.name == "Lost").unwrap();
        assert_eq!(lost.path, "?\\Lost");
        assert_eq!(lost.path_tail(), "Lost");
        assert_eq!(s.orphan_values.len(), 1);
        assert_eq!(s.orphan_values[0].name, "Updater");
        assert_eq!(s.orphan_values[0].text().as_deref(), Some("cmd.exe /c evil"));
    }

    #[test]
    fn garbage_is_rejected_or_empty() {
        assert!(HiveImage::new(&[0u8; 100]).is_none());
        assert!(scan(&vec![0u8; 8192]).is_none());
        let mut junk = vec![0xffu8; 4096 + 8192];
        junk[..4].copy_from_slice(b"regf");
        let s = scan(&junk).unwrap();
        assert!(s.deleted_keys.is_empty() && s.orphan_values.is_empty());
        let multi = RawValue {
            offset: 0,
            allocated: false,
            name: "m".into(),
            data_type: REG_MULTI_SZ,
            data: Some("a\0b\0\0".encode_utf16().flat_map(|u| u.to_le_bytes()).collect()),
        };
        assert_eq!(multi.text().as_deref(), Some("a|b"));
    }
}
