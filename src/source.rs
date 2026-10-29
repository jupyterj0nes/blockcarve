//! Block sources for carving: anything that can be read by absolute offset.
//!
//! Two flavours:
//!
//! * [`DirectSource`] wraps any `Read + Seek` (raw files, VMDK, VHD/VHDX, a live volume).
//!   Reader panics are caught and reported as read errors.
//! * [`GuardedSource`] runs every read on a helper thread with a time budget. A damaged EWF
//!   segment can make a chunk decode spin forever; when that happens the stuck reader is
//!   abandoned, a fresh one is opened and the scanner skips past the window.
//!
//! [`open_file`] opens a plain file or a raw device (`\\.\PhysicalDrive0`, `/dev/sdb`), whose
//! size the metadata does not report.

use std::io::{Read, Seek, SeekFrom};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::sync::mpsc;
use std::time::Duration;

/// Why a block could not be delivered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockError {
    /// The read failed; the caller skips the block.
    Io(String),
    /// The read exceeded the time budget; the reader was abandoned.
    Stalled,
    /// No reader is available any more (reopen failed).
    Unavailable(String),
}

impl std::fmt::Display for BlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlockError::Io(e) => write!(f, "read error: {e}"),
            BlockError::Stalled => write!(f, "read stalled"),
            BlockError::Unavailable(e) => write!(f, "source unavailable: {e}"),
        }
    }
}

impl std::error::Error for BlockError {}

/// A byte source addressed by absolute offset.
pub trait BlockSource {
    /// Total size in bytes.
    fn size(&self) -> u64;
    /// Human-readable name used in diagnostics.
    fn label(&self) -> &str;
    /// Bytes at `offset`. Shorter than `len` only at the end of the source; empty when
    /// `offset` is at or past the end.
    fn read_block(&mut self, offset: u64, len: usize) -> Result<Vec<u8>, BlockError>;
    /// Number of reads abandoned for exceeding the time budget.
    fn stalls(&self) -> usize {
        0
    }
}

/// Text of a panic payload (`&str` or `String`), or a placeholder.
pub fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "panic".to_string()
    }
}

fn read_fully<R: Read + Seek>(r: &mut R, offset: u64, len: usize) -> std::io::Result<Vec<u8>> {
    r.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; len];
    let mut got = 0usize;
    while got < len {
        match r.read(&mut buf[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    buf.truncate(got);
    Ok(buf)
}

/// Plain seekable reader.
pub struct DirectSource<R: Read + Seek> {
    inner: R,
    size: u64,
    label: String,
}

impl<R: Read + Seek> DirectSource<R> {
    pub fn new(inner: R, size: u64, label: impl Into<String>) -> Self {
        DirectSource { inner, size, label: label.into() }
    }

    /// The wrapped reader.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read + Seek> BlockSource for DirectSource<R> {
    fn size(&self) -> u64 {
        self.size
    }

    fn label(&self) -> &str {
        &self.label
    }

    fn read_block(&mut self, offset: u64, len: usize) -> Result<Vec<u8>, BlockError> {
        if offset >= self.size {
            return Ok(Vec::new());
        }
        let len = len.min((self.size - offset) as usize);
        match catch_unwind(AssertUnwindSafe(|| read_fully(&mut self.inner, offset, len))) {
            Ok(Ok(b)) => Ok(b),
            Ok(Err(e)) => Err(BlockError::Io(e.to_string())),
            Err(p) => Err(BlockError::Io(format!("reader panicked: {}", panic_message(&*p)))),
        }
    }
}

/// Reader driven from a helper thread with a per-read time budget.
pub struct GuardedSource<R: Read + Seek + Send + 'static> {
    inner: Option<R>,
    reopen: Box<dyn Fn() -> Result<R, String> + Send>,
    timeout: Duration,
    size: u64,
    label: String,
    stalls: usize,
}

impl<R: Read + Seek + Send + 'static> GuardedSource<R> {
    pub fn new(
        inner: R,
        size: u64,
        label: impl Into<String>,
        timeout: Duration,
        reopen: impl Fn() -> Result<R, String> + Send + 'static,
    ) -> Self {
        GuardedSource { inner: Some(inner), reopen: Box::new(reopen), timeout, size, label: label.into(), stalls: 0 }
    }
}

impl<R: Read + Seek + Send + 'static> BlockSource for GuardedSource<R> {
    fn size(&self) -> u64 {
        self.size
    }

    fn label(&self) -> &str {
        &self.label
    }

    fn stalls(&self) -> usize {
        self.stalls
    }

    fn read_block(&mut self, offset: u64, len: usize) -> Result<Vec<u8>, BlockError> {
        if offset >= self.size {
            return Ok(Vec::new());
        }
        let len = len.min((self.size - offset) as usize);
        let mut reader = match self.inner.take() {
            Some(r) => r,
            None => (self.reopen)().map_err(BlockError::Unavailable)?,
        };
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let result = catch_unwind(AssertUnwindSafe(|| read_fully(&mut reader, offset, len)));
            let _ = tx.send((result, reader));
        });
        match rx.recv_timeout(self.timeout) {
            Ok((Ok(Ok(buf)), reader)) => {
                self.inner = Some(reader);
                Ok(buf)
            }
            Ok((Ok(Err(e)), reader)) => {
                self.inner = Some(reader);
                Err(BlockError::Io(e.to_string()))
            }
            Ok((Err(p), _)) => Err(BlockError::Io(format!("reader panicked: {}", panic_message(&*p)))),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // The stuck thread keeps the old reader; it is dropped whenever (if ever) the
                // read returns. The next call reopens.
                self.stalls += 1;
                Err(BlockError::Stalled)
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(BlockError::Io("reader thread ended without a result".to_string())),
        }
    }
}

/// In-memory source, handy for tests and for carving small files.
pub type MemorySource = DirectSource<std::io::Cursor<Vec<u8>>>;

impl DirectSource<std::io::Cursor<Vec<u8>>> {
    pub fn from_bytes(bytes: Vec<u8>, label: impl Into<String>) -> Self {
        let size = bytes.len() as u64;
        DirectSource::new(std::io::Cursor::new(bytes), size, label)
    }
}

/// `Read + Seek` view over a block source (or a window of it starting at `base`), for file
/// system readers that need to open a file inside the scanned image.
pub struct SourceReader<'a> {
    src: &'a mut dyn BlockSource,
    pos: u64,
    base: u64,
}

impl<'a> SourceReader<'a> {
    pub fn new(src: &'a mut dyn BlockSource, base: u64) -> Self {
        SourceReader { src, pos: 0, base }
    }
}

impl Read for SourceReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let data = self.src.read_block(self.base + self.pos, buf.len()).map_err(|e| std::io::Error::other(e.to_string()))?;
        let n = data.len().min(buf.len());
        buf[..n].copy_from_slice(&data[..n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for SourceReader<'_> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let size = self.src.size().saturating_sub(self.base);
        let new = match pos {
            SeekFrom::Start(p) => p as i128,
            SeekFrom::End(d) => size as i128 + d as i128,
            SeekFrom::Current(d) => self.pos as i128 + d as i128,
        };
        if new < 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "seek before start"));
        }
        self.pos = new as u64;
        Ok(self.pos)
    }
}

/// `\\.\PhysicalDrive0`, `\\.\C:`, `/dev/sda`: a device rather than a file.
pub fn is_device_path(path: &Path) -> bool {
    let s = path.to_string_lossy();
    s.starts_with("\\\\.\\") || s.starts_with("\\\\?\\") || s.starts_with("/dev/")
}

/// Size of a raw device, which `metadata().len()` reports as zero.
#[cfg(windows)]
pub fn device_length(file: &mut std::fs::File) -> Option<u64> {
    use std::os::windows::io::AsRawHandle;
    #[repr(C)]
    struct GetLengthInformation {
        length: i64,
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn DeviceIoControl(
            device: *mut std::ffi::c_void,
            control_code: u32,
            in_buffer: *mut std::ffi::c_void,
            in_size: u32,
            out_buffer: *mut std::ffi::c_void,
            out_size: u32,
            returned: *mut u32,
            overlapped: *mut std::ffi::c_void,
        ) -> i32;
    }
    const IOCTL_DISK_GET_LENGTH_INFO: u32 = 0x0007_405C;
    let mut info = GetLengthInformation { length: 0 };
    let mut returned: u32 = 0;
    // SAFETY: the handle is open for the lifetime of `file`, the out buffer is a correctly
    // sized, writable struct and the IOCTL takes no input buffer.
    let ok = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            IOCTL_DISK_GET_LENGTH_INFO,
            std::ptr::null_mut(),
            0,
            &mut info as *mut GetLengthInformation as *mut std::ffi::c_void,
            std::mem::size_of::<GetLengthInformation>() as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    (ok != 0 && info.length > 0).then_some(info.length as u64)
}

/// Size of a raw device, which `metadata().len()` reports as zero.
#[cfg(not(windows))]
pub fn device_length(file: &mut std::fs::File) -> Option<u64> {
    let end = file.seek(SeekFrom::End(0)).ok()?;
    file.seek(SeekFrom::Start(0)).ok()?;
    (end > 0).then_some(end)
}

/// Opens a plain file (buffered) or a raw device (unbuffered, so every request stays sector
/// aligned) as a block source.
pub fn open_file(path: &Path) -> Result<Box<dyn BlockSource>, String> {
    let label = path.display().to_string();
    let mut file = std::fs::File::open(path).map_err(|e| format!("{label}: {e}"))?;
    let mut size = file.metadata().map(|m| m.len()).unwrap_or(0);
    if size == 0 && is_device_path(path) {
        size = device_length(&mut file).ok_or_else(|| format!("{label}: cannot determine the device size"))?;
        return Ok(Box::new(DirectSource::new(file, size, label)));
    }
    if size == 0 {
        return Err(format!("{label}: empty file"));
    }
    Ok(Box::new(DirectSource::new(std::io::BufReader::new(file), size, label)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A reader that blocks forever on the second read, to exercise the stall path.
    struct Sticky {
        data: std::io::Cursor<Vec<u8>>,
        reads: usize,
    }

    impl Read for Sticky {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.reads += 1;
            if self.reads == 2 {
                std::thread::sleep(Duration::from_secs(3600));
            }
            self.data.read(buf)
        }
    }

    impl Seek for Sticky {
        fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
            self.data.seek(pos)
        }
    }

    #[test]
    fn direct_source_clamps_at_the_end() {
        let mut s = MemorySource::from_bytes((0u8..100).collect(), "mem");
        assert_eq!(s.read_block(90, 50).unwrap().len(), 10);
        assert!(s.read_block(100, 10).unwrap().is_empty());
        assert_eq!(s.read_block(0, 4).unwrap(), vec![0, 1, 2, 3]);
    }

    #[test]
    fn guarded_source_reports_a_stall_and_recovers_by_reopening() {
        let make = || Sticky { data: std::io::Cursor::new(vec![7u8; 4096]), reads: 0 };
        let mut g = GuardedSource::new(make(), 4096, "sticky", Duration::from_millis(200), move || Ok(make()));
        assert_eq!(g.read_block(0, 16).unwrap(), vec![7u8; 16]);
        assert_eq!(g.read_block(16, 16), Err(BlockError::Stalled));
        assert_eq!(g.stalls(), 1);
        assert_eq!(g.read_block(32, 16).unwrap(), vec![7u8; 16]);
    }

    #[test]
    fn source_reader_windows_a_source() {
        let mut s = MemorySource::from_bytes((0u8..100).collect(), "mem");
        let mut r = SourceReader::new(&mut s, 10);
        let mut buf = [0u8; 4];
        r.seek(SeekFrom::Start(5)).unwrap();
        r.read_exact(&mut buf).unwrap();
        assert_eq!(buf, [15, 16, 17, 18]);
        assert_eq!(r.seek(SeekFrom::End(0)).unwrap(), 90);
        assert!(is_device_path(Path::new("\\\\.\\C:")));
        assert!(!is_device_path(Path::new("C:\\image.dd")));
    }
}
