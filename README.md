# blockcarve

Block-wise signature carving for forensic sources, in pure Rust. The engine shared by
[masstin](https://github.com/jupyterj0nes/masstin) (EVTX chunks and orphan records),
[faramir](https://github.com/jupyterj0nes/faramir) (registry hives),
[allymacb](https://github.com/jupyterj0nes/allymacb) (NTFS `FILE` records and `INDX`
blocks) and [caarea](https://github.com/jupyterj0nes/caarea) (all of those plus Prefetch
and systemd journals), so every tool reads raw bytes the same way and accepts a structure
for the same reasons.

## What it does

- **Sources** (`source`): anything addressed by absolute offset. `DirectSource` wraps a
  `Read + Seek` (raw image, VMDK, VHD/VHDX, a live volume). `GuardedSource` runs every read
  on a helper thread with a time budget and reopens the reader after a stall, because a
  damaged EWF segment can make a decoder spin forever. `open_file` handles plain files and
  raw devices (`\\.\PhysicalDrive0`, `/dev/sdb`), whose size the metadata does not report.
  `SourceReader` turns a source back into `Read + Seek` for file system readers.
- **Scanner** (`scan`): 4 MB blocks, candidates at sector alignment, a carry-over tail so a
  structure split between two reads is seen whole, and every byte offered exactly once to an
  optional block callback for structures without an aligned signature (USN records, orphan
  event records, text). A hit callback may read anywhere in the source and may ask the scan
  to jump past what it consumed. Read failures cost a skipped window and a note, never the run.
- **Validators**, one module per structure, accepting only what proves itself:
  - `hive`: `regf` base block, hive-bin chain followed bin by bin, root key checked; the
    copy comes back marked clean for the parser, truncated copies patched to their recovered
    size; fingerprints to skip hives the file system already gave you.
  - `evtx`: chunk header and data CRC32 (no record is ever parsed here), synthetic `ElfFile`
    writer, chunk groups with bisection against a validator you provide (a child-process
    parse), orphan record headers.
  - `ntfs`: `FILE` record geometry and fixups, `INDX` blocks with fixups applied and the
    entries of the live chain and of the slack (feature `mft`, on by default).
  - `prefetch`: `SCCA` and `MAM` headers.
  - `linux`: systemd journal header.
- **Deleted registry keys** (`hive_cells`): every hive bin walked with a bounds-checked
  parser; free `nk` cells come back with their path rebuilt through the parent chain and
  the values their list still points to, free `vk` cells nobody references come back as
  orphans. Works on a hive read from disk, from a shadow copy or carved from raw bytes.
- **Transaction log replay** (`hive_logs`): a dirty hive and its `.LOG` / `.LOG1` / `.LOG2`
  rebuilt in memory, never on disk. New-format `HvLE` entries (Windows 8.1+) are checked by
  their two Marvin32 hashes and applied in consecutive sequence order, earlier log first,
  stopping at a gap; old-format `DIRT` logs (Windows 7 / 8) are applied when their timestamp
  matches the hive. The result is marked clean, so any hive reader takes it as is. Checked
  against the hives Windows 10 and Windows 7 recovered themselves (yarp test corpus) and
  against nt_hive2's own log applier on a lab NTUSER.DAT.

Each tool keeps its own emission, deduplication and provenance; this crate never writes a
timeline row.

## Example

```rust
use blockcarve::hive;
use blockcarve::scan::{scan_signatures, HitAction, ScanConfig};
use blockcarve::source::open_file;

let mut src = open_file(std::path::Path::new("disk.dd"))?;
let cfg = ScanConfig { window: hive::WINDOW, ..Default::default() };
scan_signatures(&mut *src, &cfg, hive::REGF_MAGIC, &mut |src, offset, window| {
    let Ok(header) = hive::validate_base_block(window) else { return HitAction::Continue };
    match hive::read_hive(src, offset, &header) {
        Ok(raw) => {
            hive::write_carved(std::path::Path::new("carved"), &header, &raw).ok();
            HitAction::SkipTo(offset + raw.recovered_len as u64)
        }
        Err(_) => HitAction::Continue,
    }
}, &mut |_, _| {});
# Ok::<(), String>(())
```

## Design rules the tools follow

- Carving is opt-in (`--carve`); structural recovery from structures already parsed (freed
  hive cells, unused `$MFT` records) runs by default. Both may use this crate: the rule is
  about when a scan runs, not where its code lives.
- Only self-timestamped structures are carved.
- Identity deduplication against what the file system already provided (hive fingerprints,
  chunk hashes), never deduplication by offset.
- Provenance stays with the tool: an artifact segment or a source column, with the byte
  offset.

## License

AGPL-3.0-only. Tono Diaz (@jupyterj0nes).
