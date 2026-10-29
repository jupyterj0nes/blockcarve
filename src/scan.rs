//! Signature scanner over a [`BlockSource`].
//!
//! Reads the source in large blocks, keeps a carry-over so a structure that starts near the
//! end of one block is seen whole in the next, and visits every aligned signature exactly
//! once. The hit callback may read anywhere in the source (to pull a whole hive out) and may
//! ask the scanner to jump past what it consumed. Read failures never abort the scan: a bad
//! sector costs a skipped window and a note in the statistics.

use crate::source::{BlockError, BlockSource};

/// Bytes read per iteration.
pub const BLOCK_SIZE: usize = 4 << 20;
/// Signatures are only looked for at multiples of this (file-system structures are sector
/// or cluster aligned).
pub const SECTOR: usize = 512;
/// Window skipped after a stalled read.
pub const STALL_SKIP: u64 = 32 << 20;
/// Window skipped after too many consecutive read failures.
pub const ERROR_SKIP: u64 = 64 << 20;
/// Consecutive failed blocks tolerated before the larger skip kicks in.
pub const MAX_CONSECUTIVE_ERRORS: usize = 10;
/// Diagnostic notes kept per scan (the rest are only counted).
pub const MAX_NOTES: usize = 50;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanConfig {
    pub block_size: usize,
    /// Bytes after a signature the callback needs to see in one piece.
    pub window: usize,
    /// Alignment of candidate signatures.
    pub step: usize,
}

impl Default for ScanConfig {
    fn default() -> Self {
        ScanConfig { block_size: BLOCK_SIZE, window: 4096 + 32, step: SECTOR }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ScanStats {
    pub bytes_read: u64,
    pub blocks: usize,
    /// Signatures handed to the callback.
    pub signatures: usize,
    pub read_errors: usize,
    pub stalls: usize,
    /// Bytes jumped over (after errors, stalls or at the callback's request).
    pub bytes_skipped: u64,
    pub aborted: bool,
    /// Human-readable diagnostics (first [`MAX_NOTES`]).
    pub notes: Vec<String>,
}

impl ScanStats {
    fn note(&mut self, msg: String) {
        if self.notes.len() < MAX_NOTES {
            self.notes.push(msg);
        }
    }
}

/// What the hit callback wants the scanner to do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HitAction {
    Continue,
    /// Resume scanning at this absolute offset (ignored when not past the hit).
    SkipTo(u64),
}

/// Callback: `(source, absolute offset of the signature, bytes from the signature onwards)`.
pub type HitFn<'a> = dyn FnMut(&mut dyn BlockSource, u64, &[u8]) -> HitAction + 'a;
/// Same, plus the index of the signature that matched.
pub type MultiHitFn<'a> = dyn FnMut(&mut dyn BlockSource, u64, &[u8], usize) -> HitAction + 'a;
/// Progress callback: `(offset reached, total size)`.
pub type ProgressFn<'a> = dyn FnMut(u64, u64) + 'a;
/// Block callback: `(absolute offset of the block, the block's bytes)`, without the carry.
pub type BlockFn<'a> = dyn FnMut(u64, &[u8]) + 'a;

/// Visits every `signature` aligned to `cfg.step`.
pub fn scan_signatures(
    src: &mut dyn BlockSource,
    cfg: &ScanConfig,
    signature: &[u8],
    on_hit: &mut HitFn<'_>,
    progress: &mut ProgressFn<'_>,
) -> ScanStats {
    scan_many(src, cfg, &[signature], &mut |s, off, bytes, _which| on_hit(s, off, bytes), progress, None)
}

/// Visits every occurrence of any of `signatures` aligned to `cfg.step`; the callback also
/// receives the index of the signature that matched. One pass over the source serves every
/// structure type at once.
///
/// `on_block`, when given, sees every byte of the source exactly once, after the signature
/// pass over the same bytes: structures without an aligned signature (USN records, orphan
/// event records, text lines) are found there. A structure cut by a block boundary is seen
/// whole in the next call as long as it is shorter than `cfg.window`.
pub fn scan_many(
    src: &mut dyn BlockSource,
    cfg: &ScanConfig,
    signatures: &[&[u8]],
    on_hit: &mut MultiHitFn<'_>,
    progress: &mut ProgressFn<'_>,
    mut on_block: Option<&mut BlockFn<'_>>,
) -> ScanStats {
    let mut stats = ScanStats::default();
    let size = src.size();
    let label = src.label().to_string();
    if size == 0 || signatures.is_empty() {
        stats.aborted = true;
        stats.note(format!("{label}: nothing to scan"));
        return stats;
    }
    let step = cfg.step.max(1) as u64;
    let max_sig = signatures.iter().map(|s| s.len()).max().unwrap_or(0);
    let min_sig = signatures.iter().map(|s| s.len()).min().unwrap_or(0).max(1);
    let window = cfg.window.max(max_sig);

    let mut offset: u64 = 0;
    // bytes [offset - carry.len(), offset) kept from the previous block
    let mut carry: Vec<u8> = Vec::new();
    // every hit whose window ends at or before this offset has been handled
    let mut processed_until: u64 = 0;
    let mut consecutive_errors = 0usize;

    while offset < size {
        progress(offset, size);
        let want = cfg.block_size.min((size - offset) as usize);
        let block = match src.read_block(offset, want) {
            Ok(b) if b.is_empty() => break,
            Ok(b) => {
                consecutive_errors = 0;
                b
            }
            Err(BlockError::Stalled) => {
                stats.stalls += 1;
                let skip = STALL_SKIP.min(size - offset);
                stats.note(format!("{label}: read stalled at offset {offset:#x}; skipping {} MB", skip >> 20));
                offset += skip;
                stats.bytes_skipped += skip;
                carry.clear();
                processed_until = offset;
                continue;
            }
            Err(BlockError::Unavailable(e)) => {
                stats.aborted = true;
                stats.note(format!("{label}: aborted at offset {offset:#x}: {e}"));
                break;
            }
            Err(BlockError::Io(e)) => {
                stats.read_errors += 1;
                consecutive_errors += 1;
                let skip = if consecutive_errors > MAX_CONSECUTIVE_ERRORS {
                    stats.note(format!(
                        "{label}: {e} at offset {offset:#x} ({consecutive_errors} consecutive failures, skipping {} MB)",
                        ERROR_SKIP >> 20
                    ));
                    consecutive_errors = 0;
                    ERROR_SKIP
                } else {
                    stats.note(format!("{label}: {e} at offset {offset:#x}"));
                    want as u64
                };
                let skip = skip.min(size - offset);
                offset += skip;
                stats.bytes_skipped += skip;
                carry.clear();
                processed_until = offset;
                continue;
            }
        };
        stats.blocks += 1;
        stats.bytes_read += block.len() as u64;

        let base = offset - carry.len() as u64;
        let mut buf = std::mem::take(&mut carry);
        buf.extend_from_slice(&block);
        let end_abs = base + buf.len() as u64;
        let at_eof = end_abs >= size || block.len() < want;

        // first position in `buf` whose absolute offset is step-aligned
        let mut pos = (base.div_ceil(step) * step - base) as usize;
        let mut skip_to: Option<u64> = None;
        while pos + min_sig <= buf.len() {
            let abs = base + pos as u64;
            let whole_window = pos + window <= buf.len() || at_eof;
            if abs + window as u64 > processed_until && whole_window {
                if let Some(which) = signatures.iter().position(|s| buf[pos..].starts_with(s)) {
                    stats.signatures += 1;
                    match on_hit(src, abs, &buf[pos..], which) {
                        HitAction::Continue => {}
                        HitAction::SkipTo(t) if t > abs && t < end_abs => {
                            // still inside the buffer: jump within it instead of re-reading,
                            // to the next step-aligned absolute offset (the buffer itself may
                            // start unaligned when the carry is not a multiple of the step)
                            pos = (t.div_ceil(step) * step - base) as usize;
                            continue;
                        }
                        HitAction::SkipTo(t) if t > abs => {
                            skip_to = Some(t);
                            break;
                        }
                        HitAction::SkipTo(_) => {}
                    }
                }
            }
            pos += step as usize;
        }

        // The block callback runs after the signature pass over the same bytes, so structures
        // the pass accepted are known (a record inside a recovered chunk is not an orphan).
        // The tail that becomes the next carry is left out: its signatures are only handled
        // in the next iteration, and the callback sees those bytes then. Every byte is thus
        // offered exactly once, and structures cut by a block boundary are seen whole.
        if let Some(cb) = on_block.as_mut() {
            let end = if at_eof || skip_to.is_some() { buf.len() } else { buf.len() - window.min(buf.len()) };
            cb(base, &buf[..end]);
        }

        if let Some(t) = skip_to {
            let t = t.min(size);
            if t > end_abs {
                stats.bytes_skipped += t - end_abs;
            }
            offset = t;
            carry.clear();
            processed_until = t;
            continue;
        }

        if at_eof {
            offset = end_abs;
            break;
        }
        let keep = window.min(buf.len());
        carry = buf[buf.len() - keep..].to_vec();
        processed_until = end_abs;
        offset = end_abs;
    }
    progress(offset.min(size), size);
    stats
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::MemorySource;

    fn plant(buf: &mut [u8], at: usize, sig: &[u8]) {
        buf[at..at + sig.len()].copy_from_slice(sig);
    }

    #[test]
    fn finds_aligned_signatures_once_across_block_boundaries() {
        let block = 8192;
        let mut data = vec![0u8; block * 3];
        plant(&mut data, 512, b"MAGIC");
        plant(&mut data, block - 512, b"MAGIC");
        plant(&mut data, 1000, b"MAGIC"); // unaligned: ignored
        plant(&mut data, block * 3 - 512, b"MAGIC");
        let mut src = MemorySource::from_bytes(data, "t");
        let cfg = ScanConfig { block_size: block, window: 1024, step: 512 };
        let mut hits = Vec::new();
        let stats = scan_signatures(&mut src, &cfg, b"MAGIC", &mut |_, off, win| {
            hits.push((off, win.len()));
            HitAction::Continue
        }, &mut |_, _| {});
        assert_eq!(hits.iter().map(|h| h.0).collect::<Vec<_>>(), vec![512, (block - 512) as u64, (block * 3 - 512) as u64]);
        assert!(hits.iter().all(|h| h.1 >= 512));
        assert_eq!(stats.signatures, 3);
        assert_eq!(stats.bytes_read, (block * 3) as u64);
        assert!(!stats.aborted);
    }

    #[test]
    fn skip_to_jumps_past_consumed_bytes() {
        let mut data = vec![0u8; 65536];
        plant(&mut data, 0, b"HDR");
        plant(&mut data, 4096, b"HDR"); // inside the first structure: must not be reported
        plant(&mut data, 32768, b"HDR");
        let mut src = MemorySource::from_bytes(data, "t");
        let cfg = ScanConfig { block_size: 16384, window: 64, step: 512 };
        let mut hits = Vec::new();
        let stats = scan_signatures(&mut src, &cfg, b"HDR", &mut |_, off, _| {
            hits.push(off);
            HitAction::SkipTo(off + 8192)
        }, &mut |_, _| {});
        assert_eq!(hits, vec![0, 32768]);
        assert_eq!(stats.signatures, 2, "the signature inside a consumed structure is never reported");
    }

    #[test]
    fn several_signatures_in_one_pass_and_every_byte_once() {
        let mut data = vec![0u8; 8192];
        plant(&mut data, 0, b"AAAA");
        plant(&mut data, 1024, b"BB");
        plant(&mut data, 2048, b"AAAA");
        let mut src = MemorySource::from_bytes(data, "t");
        let cfg = ScanConfig { block_size: 4096, window: 16, step: 512 };
        let mut seen = Vec::new();
        let mut offered = 0usize;
        let mut bases = Vec::new();
        scan_many(&mut src, &cfg, &[b"AAAA", b"BB"], &mut |_, off, _, which| {
            seen.push((off, which));
            HitAction::Continue
        }, &mut |_, _| {}, Some(&mut |base, block| {
            bases.push(base);
            offered += block.len();
        }));
        assert_eq!(seen, vec![(0, 0), (1024, 1), (2048, 0)]);
        assert_eq!(offered, 8192);
        assert_eq!(bases, vec![0, 4096 - 16]);
    }

    #[test]
    fn in_buffer_skip_keeps_absolute_alignment_with_an_unaligned_carry() {
        // window 4128 is not a multiple of the step, so the second buffer starts unaligned;
        // a skip inside it must still land on 512-aligned absolute offsets
        let mb = 1 << 20;
        let mut data = vec![0u8; 8 * mb];
        for at in [mb, 3 * mb + 512, 5 * mb, 7 * mb] {
            plant(&mut data, at, b"regf");
        }
        let mut src = MemorySource::from_bytes(data, "t");
        let cfg = ScanConfig { block_size: 4 * mb, window: 4128, step: 512 };
        let mut hits = Vec::new();
        scan_signatures(&mut src, &cfg, b"regf", &mut |_, off, _| {
            hits.push(off);
            HitAction::SkipTo(off + 8192)
        }, &mut |_, _| {});
        assert_eq!(hits, vec![mb as u64, (3 * mb + 512) as u64, (5 * mb) as u64, (7 * mb) as u64]);
    }

    struct Flaky {
        size: u64,
        fail_at: u64,
    }

    impl BlockSource for Flaky {
        fn size(&self) -> u64 {
            self.size
        }
        fn label(&self) -> &str {
            "flaky"
        }
        fn read_block(&mut self, offset: u64, len: usize) -> Result<Vec<u8>, BlockError> {
            if offset == self.fail_at {
                return Err(BlockError::Io("bad sector".into()));
            }
            let len = len.min((self.size - offset) as usize);
            let mut v = vec![0u8; len];
            if offset == 0 {
                v[..3].copy_from_slice(b"SIG");
            }
            Ok(v)
        }
    }

    #[test]
    fn read_errors_are_skipped_not_fatal() {
        let mut src = Flaky { size: 4 * 4096, fail_at: 4096 };
        let cfg = ScanConfig { block_size: 4096, window: 8, step: 512 };
        let mut hits = 0;
        let stats = scan_signatures(&mut src, &cfg, b"SIG", &mut |_, _, _| {
            hits += 1;
            HitAction::Continue
        }, &mut |_, _| {});
        assert_eq!(hits, 1);
        assert_eq!(stats.read_errors, 1);
        assert_eq!(stats.bytes_skipped, 4096);
        assert!(!stats.aborted);
        assert_eq!(stats.notes.len(), 1);
    }
}
