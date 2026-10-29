//! Block-wise signature carving for forensic sources.
//!
//! The engine shared by [masstin](https://github.com/jupyterj0nes/masstin) (EVTX),
//! [faramir](https://github.com/jupyterj0nes/faramir) (registry hives),
//! [allymacb](https://github.com/jupyterj0nes/allymacb) (NTFS metadata) and
//! [caarea](https://github.com/jupyterj0nes/caarea) (execution artifacts): one way of reading
//! raw bytes and one way of walking them, with validators that only accept structures that
//! prove themselves.
//!
//! * [`source`]: anything readable by absolute offset. [`source::DirectSource`] wraps a
//!   `Read + Seek`; [`source::GuardedSource`] runs every read on a helper thread with a time
//!   budget and reopens the reader after a stall (a damaged EWF segment can spin forever).
//! * [`scan`]: 4 MB blocks, sector-aligned candidates, a carry-over tail so a structure split
//!   between two reads is seen whole, every byte offered exactly once; read failures cost a
//!   skipped window, never the run.
//! * [`hive_cells`]: deleted keys and values recovered from the free cells of a hive.
//! * [`hive`], [`evtx`], [`ntfs`], [`prefetch`], [`linux`]: validators and helpers for the
//!   structures the tools carve. Each tool keeps its own emission and deduplication.
//!
//! ```
//! use blockcarve::scan::{scan_signatures, HitAction, ScanConfig};
//! use blockcarve::source::MemorySource;
//!
//! let mut data = vec![0u8; 8192];
//! data[4096..4100].copy_from_slice(b"regf");
//! let mut src = MemorySource::from_bytes(data, "demo");
//! let mut hits = Vec::new();
//! scan_signatures(&mut src, &ScanConfig::default(), b"regf", &mut |_, offset, _| {
//!     hits.push(offset);
//!     HitAction::Continue
//! }, &mut |_, _| {});
//! assert_eq!(hits, vec![4096]);
//! ```

pub mod evtx;
pub mod hive;
pub mod hive_cells;
pub mod linux;
pub mod ntfs;
pub mod prefetch;
pub mod scan;
pub mod source;

pub use scan::{scan_many, scan_signatures, BlockFn, HitAction, HitFn, MultiHitFn, ProgressFn, ScanConfig, ScanStats};
pub use source::{BlockError, BlockSource, DirectSource, GuardedSource, MemorySource};

/// FNV-1a 64 over `bytes`: cheap identity for carved structures (a chunk, a hive copy).
pub fn content_hash(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// FILETIME of 2000-01-01, the lower bound used by the validators for plausible times.
pub const FILETIME_2000: u64 = 125_911_584_000_000_000;
/// FILETIME of 2040-01-01, the upper bound used by the validators for plausible times.
pub const FILETIME_2040: u64 = 138_535_776_000_000_000;
