//! Read-only BRU/BRU-PE legacy archive reader for Remanence.
//!
//! BRU uses 2048-byte logical blocks with per-block checksums. On physical
//! tape those logical blocks may be grouped into larger tape records, so this
//! crate keeps logical BRU parsing separate from the input source. The first
//! implementation supports dump/byte streams and the
//! [`ForeignFormatAdapter`] entry point over [`PhysicalTapeSource`].

use std::io::{self, Read, Seek, SeekFrom};

use remanence_format_driver::{
    ArchiveEventSink, ArchiveGapCause, ArchiveGapRange, ArchiveReader, DamageRange, DamageStatus,
    EntryCatalogSink, EntryKind, FileDataSink, FileId, FileStreamReport, ForeignFormatAdapter,
    FormatCapabilities, FormatDescriptor, FormatError, NormalizedEntry, ProbeConfidence,
    ProbeResult, ReadSeek, ScanIntegrityBasis, ScanReport, SourceRequirement, StreamReport,
};
use remanence_library::{
    BlockSize, PhysicalReadOutcome, PhysicalTapePosition, PhysicalTapeSource, ScsiError,
    TapeIoError,
};

/// BRU logical block size in bytes.
pub const BRU_BLOCK_SIZE: usize = 2048;

const CHKSUM_OFFSET: usize = 0x080;
const CHKSUM_SIZE: usize = 8;
const CHKSUM_PLACEHOLDER: &[u8; CHKSUM_SIZE] = b"       0";

const MAGIC_OFFSET: usize = 0x0B0;
const MAGIC_SIZE: usize = 4;
const MAGIC_ARCHIVE_HEADER: u64 = 0x1234;
const MAGIC_FILE_HEADER: u64 = 0x2345;
const MAGIC_CONTINUATION: u64 = 0x3456;
const MAGIC_ARCHIVE_TERMINATOR: u64 = 0x7890;

const ARTIME_OFFSET: usize = 0x098;
const BUFSIZE_OFFSET: usize = 0x0A0;
const RELEASE_MAJOR_OFFSET: usize = 0x0B8;
const RELEASE_MINOR_OFFSET: usize = 0x0BC;
const VARIANT_OFFSET: usize = 0x0C0;
const ARCHIVE_ID_LOW_OFFSET: usize = 0x0D8;
const LABEL_OFFSET: usize = 0x1D0;
const LABEL_SIZE: usize = 80;

const FILE_PATH_OFFSET: usize = 0x000;
const FILE_PATH_SIZE: usize = 128;
const FILE_SEQUENCE_OFFSET: usize = 0x0C4;
const INLINE_DATA_LEN_OFFSET: usize = 0x0DC;
const INLINE_DATA_OFFSET: usize = 0x400;
const ST_MODE_OFFSET: usize = 0x180;
const ST_SIZE_OFFSET: usize = 0x1B8;
const FILE_FLAGS_OFFSET: usize = 0x1D8;
const SIZE_HIGH_OFFSET: usize = 0x278;

const FILE_FLAG_EXTERNAL_COMPRESSION: u64 = 0x008;
const FILE_FLAG_BUILTIN_COMPRESSION: u64 = 0x100;
const FILE_COMPRESSION_MASK: u64 = FILE_FLAG_EXTERNAL_COMPRESSION | FILE_FLAG_BUILTIN_COMPRESSION;

const CONTINUATION_DLEN_OFFSET: usize = 0x0DC;
const CONTINUATION_DATA_OFFSET: usize = 0x100;

const S_IFMT: u64 = 0xF000;
const S_IFDIR: u64 = 0x4000;
const S_IFREG: u64 = 0x8000;
const S_IFLNK: u64 = 0xA000;

const PHYSICAL_READ_BUFFER_BYTES: usize = 0x00FF_FFFF;

/// Parsed BRU archive header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BruArchiveHeader {
    /// Composite BRU archive id.
    pub archive_id: String,
    /// Archive label.
    pub label: String,
    /// BRU I/O buffer size in bytes.
    pub buffer_size_bytes: u64,
    /// Archive creation time as a Unix timestamp.
    pub artime: u64,
    /// BRU release major component.
    pub release_major: u64,
    /// BRU release minor component.
    pub release_minor: u64,
    /// BRU archive variant.
    pub variant: u64,
}

/// Parsed BRU file header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BruFileHeader {
    /// Per-file sequence number stored in the archive header.
    pub sequence: u64,
    /// UTF-8 presentation path.
    pub path: String,
    /// Raw path bytes before UTF-8 conversion.
    pub raw_path: Vec<u8>,
    /// File size in bytes.
    pub size_bytes: u64,
    /// Entry kind.
    pub kind: EntryKind,
    /// Raw POSIX mode bits.
    pub mode: u64,
    /// Compression recorded for this member.
    pub compression: BruCompression,
}

/// Compression mode recorded in a BRU file header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BruCompression {
    /// The member payload is stored without software compression.
    None,
    /// The member uses BRU's built-in compressor.
    BuiltIn,
    /// The member uses an external compressor selected by BRU.
    External,
    /// The member sets more than one compression flag.
    Ambiguous,
}

/// BRU format driver.
#[derive(Debug, Default, Clone, Copy)]
pub struct BruFormat;

impl BruFormat {
    /// Create a BRU reader from a byte stream, such as a `.bru` dump file.
    pub fn open_dump_reader<R: Read>(&self, reader: R) -> BruDumpReader<R> {
        BruDumpReader {
            inner: BruArchiveReader::new(ByteBruBlockSource::new(reader)),
        }
    }

    /// Probe a seekable byte stream, such as a `.bru` dump file.
    ///
    /// The stream position is restored before this returns, even when the
    /// source does not contain enough bytes for a full BRU block.
    pub fn probe_dump<R: Read + Seek + ?Sized>(
        &self,
        reader: &mut R,
    ) -> Result<ProbeResult, FormatError> {
        let start = reader
            .stream_position()
            .map_err(|err| io_to_format("reading BRU dump position", err))?;
        let mut block = [0; BRU_BLOCK_SIZE];
        let mut filled = 0usize;
        let mut read_error = None;
        while filled < BRU_BLOCK_SIZE {
            match reader.read(&mut block[filled..]) {
                Ok(0) => break,
                Ok(read) => filled += read,
                Err(err) => {
                    read_error = Some(err);
                    break;
                }
            }
        }
        reader
            .seek(SeekFrom::Start(start))
            .map_err(|err| io_to_format("restoring BRU dump position", err))?;
        if let Some(err) = read_error {
            return Err(io_to_format("probing BRU dump block", err));
        }

        let confidence = if filled == BRU_BLOCK_SIZE {
            probe_block_confidence(&block)
        } else {
            ProbeConfidence::NoMatch
        };
        Ok(ProbeResult {
            format_id: self.id().to_string(),
            confidence,
            source_requirement: SourceRequirement::ByteStreamDump,
            adapter_state: Vec::new(),
        })
    }
}

impl FormatDescriptor for BruFormat {
    fn id(&self) -> &'static str {
        "remanence-bru"
    }

    fn version(&self) -> &'static str {
        "0.1"
    }

    fn source_requirement(&self) -> SourceRequirement {
        SourceRequirement::PhysicalTapeRecords
    }

    fn capabilities(&self) -> FormatCapabilities {
        FormatCapabilities {
            catalog_scan: true,
            sequential_restore: true,
            indexed_file_restore: false,
            range_read: false,
            write: false,
            verify: true,
            damage_events: true,
            metadata_preserving: false,
        }
    }
}

impl ForeignFormatAdapter for BruFormat {
    fn aliases(&self) -> &'static [&'static str] {
        &["bru"]
    }

    fn supported_sources(&self) -> &'static [SourceRequirement] {
        &[
            SourceRequirement::PhysicalTapeRecords,
            SourceRequirement::ByteStreamDump,
        ]
    }

    fn probe_dump(&self, source: &mut dyn ReadSeek) -> Result<ProbeResult, FormatError> {
        BruFormat::probe_dump(self, source)
    }

    fn open_dump_reader<'a>(
        &self,
        source: Box<dyn ReadSeek + 'a>,
        _adapter_state: &[u8],
    ) -> Result<Box<dyn ArchiveReader + 'a>, FormatError> {
        Ok(Box::new(BruFormat::open_dump_reader(self, source)))
    }

    fn probe_tape(&self, source: &mut dyn PhysicalTapeSource) -> Result<ProbeResult, FormatError> {
        source.configure_block_size(BlockSize::Variable)?;
        let start = source.position()?;
        let mut buf = vec![0; PHYSICAL_READ_BUFFER_BYTES];
        let read_result = source.read_record(&mut buf);
        let restore_result = source.locate_physical(start);
        let outcome = read_result?;
        restore_result?;

        let confidence = match outcome {
            PhysicalReadOutcome::Data { bytes, .. } if bytes >= BRU_BLOCK_SIZE => {
                let block: &[u8; BRU_BLOCK_SIZE] = buf[..BRU_BLOCK_SIZE]
                    .try_into()
                    .map_err(|_| FormatError::Parse("BRU probe block size mismatch".to_string()))?;
                probe_block_confidence(block)
            }
            _ => ProbeConfidence::NoMatch,
        };
        Ok(ProbeResult {
            format_id: self.id().to_string(),
            confidence,
            source_requirement: SourceRequirement::PhysicalTapeRecords,
            adapter_state: Vec::new(),
        })
    }

    fn open_tape_reader<'a>(
        &self,
        source: &'a mut dyn PhysicalTapeSource,
        _probe: &ProbeResult,
    ) -> Result<Box<dyn ArchiveReader + 'a>, FormatError> {
        source.configure_block_size(BlockSize::Variable)?;
        Ok(Box::new(BruPhysicalReader {
            inner: BruArchiveReader::new(PhysicalBruBlockSource::new(source)),
        }))
    }
}

/// BRU reader over a byte stream.
#[derive(Debug)]
pub struct BruDumpReader<R: Read> {
    inner: BruArchiveReader<ByteBruBlockSource<R>>,
}

impl<R: Read> BruDumpReader<R> {
    /// Read and validate the archive header from the current stream position.
    ///
    /// This consumes the header block. Use a fresh reader for `scan` or
    /// `stream_all`, which expect to start at the archive header.
    pub fn read_archive_header(&mut self) -> Result<BruArchiveHeader, FormatError> {
        self.inner.read_archive_header()
    }
}

impl<R: Read> ArchiveReader for BruDumpReader<R> {
    fn scan(&mut self, sink: &mut dyn EntryCatalogSink) -> Result<ScanReport, FormatError> {
        self.inner.scan(sink)
    }

    fn stream_all(&mut self, sink: &mut dyn ArchiveEventSink) -> Result<StreamReport, FormatError> {
        self.inner.stream_all(sink)
    }

    fn stream_file(
        &mut self,
        _file_id: &FileId,
        _sink: &mut dyn FileDataSink,
    ) -> Result<FileStreamReport, FormatError> {
        Err(FormatError::unsupported(
            "BRU indexed file restore requires a scanned index",
        ))
    }
}

/// BRU reader over a physical tape stream.
pub struct BruPhysicalReader<'a> {
    inner: BruArchiveReader<PhysicalBruBlockSource<'a>>,
}

impl ArchiveReader for BruPhysicalReader<'_> {
    fn scan(&mut self, sink: &mut dyn EntryCatalogSink) -> Result<ScanReport, FormatError> {
        self.inner.scan(sink)
    }

    fn stream_all(&mut self, sink: &mut dyn ArchiveEventSink) -> Result<StreamReport, FormatError> {
        self.inner.stream_all(sink)
    }

    fn stream_file(
        &mut self,
        _file_id: &FileId,
        _sink: &mut dyn FileDataSink,
    ) -> Result<FileStreamReport, FormatError> {
        Err(FormatError::unsupported(
            "BRU indexed file restore requires a scanned index",
        ))
    }
}

#[derive(Debug)]
struct BruArchiveReader<S> {
    source: S,
}

impl<S: BruBlockSource> BruArchiveReader<S> {
    fn new(source: S) -> Self {
        Self { source }
    }

    fn read_archive_header(&mut self) -> Result<BruArchiveHeader, FormatError> {
        let block = self
            .source
            .next_block()?
            .ok_or_else(|| FormatError::Parse("missing BRU archive header".to_string()))?;
        if !matches!(
            block.status,
            BruBlockStatus::Ok | BruBlockStatus::ReadErrorData
        ) {
            return Err(FormatError::Parse(
                "BRU archive header checksum failed".to_string(),
            ));
        }
        parse_archive_header(&block.data)
    }

    fn scan(&mut self, sink: &mut dyn EntryCatalogSink) -> Result<ScanReport, FormatError> {
        let mut visitor = ScanVisitor {
            sink,
            report: ScanReport {
                integrity_basis: ScanIntegrityBasis::FormatChecksum,
                ..ScanReport::default()
            },
        };
        walk_archive(&mut self.source, &mut visitor)?;
        Ok(visitor.report)
    }

    fn stream_all(&mut self, sink: &mut dyn ArchiveEventSink) -> Result<StreamReport, FormatError> {
        let mut visitor = StreamVisitor {
            sink,
            report: StreamReport::default(),
        };
        walk_archive(&mut self.source, &mut visitor)?;
        Ok(visitor.report)
    }
}

trait BruBlockSource {
    fn next_block(&mut self) -> Result<Option<BruBlock>, FormatError>;
}

#[derive(Debug)]
struct ByteBruBlockSource<R> {
    reader: R,
    offset: u64,
}

impl<R: Read> ByteBruBlockSource<R> {
    fn new(reader: R) -> Self {
        Self { reader, offset: 0 }
    }
}

impl<R: Read> BruBlockSource for ByteBruBlockSource<R> {
    fn next_block(&mut self) -> Result<Option<BruBlock>, FormatError> {
        let mut data = [0; BRU_BLOCK_SIZE];
        let mut filled = 0;
        while filled < BRU_BLOCK_SIZE {
            let read = self
                .reader
                .read(&mut data[filled..])
                .map_err(|err| io_to_format("reading BRU dump block", err))?;
            if read == 0 {
                if filled == 0 {
                    return Ok(None);
                }
                let offset = self.offset;
                self.offset = self
                    .offset
                    .checked_add(filled as u64)
                    .ok_or_else(|| FormatError::Parse("BRU source offset overflow".to_string()))?;
                return Ok(Some(BruBlock::partial(offset, data, filled)));
            }
            filled += read;
        }
        let offset = self.offset;
        self.offset = self
            .offset
            .checked_add(BRU_BLOCK_SIZE as u64)
            .ok_or_else(|| FormatError::Parse("BRU source offset overflow".to_string()))?;
        Ok(Some(BruBlock::new(offset, data)))
    }
}

struct PhysicalBruBlockSource<'a> {
    source: &'a mut dyn PhysicalTapeSource,
    record: Vec<u8>,
    record_pos: usize,
    record_len: usize,
    record_read_error: bool,
    record_source_state: Vec<u8>,
    logical_offset: u64,
    physical_position: Option<PhysicalTapePosition>,
    pending_read_error: Option<PendingPhysicalReadError>,
}

struct PendingPhysicalReadError {
    position_before: PhysicalTapePosition,
    position_after: PhysicalTapePosition,
    diagnostic: String,
}

impl<'a> PhysicalBruBlockSource<'a> {
    fn new(source: &'a mut dyn PhysicalTapeSource) -> Self {
        Self {
            source,
            record: vec![0; PHYSICAL_READ_BUFFER_BYTES],
            record_pos: 0,
            record_len: 0,
            record_read_error: false,
            record_source_state: Vec::new(),
            logical_offset: 0,
            physical_position: None,
            pending_read_error: None,
        }
    }
}

impl BruBlockSource for PhysicalBruBlockSource<'_> {
    fn next_block(&mut self) -> Result<Option<BruBlock>, FormatError> {
        loop {
            if self.record_len.saturating_sub(self.record_pos) >= BRU_BLOCK_SIZE {
                let mut data = [0; BRU_BLOCK_SIZE];
                data.copy_from_slice(
                    &self.record[self.record_pos..self.record_pos + BRU_BLOCK_SIZE],
                );
                self.record_pos += BRU_BLOCK_SIZE;
                let offset = self.logical_offset;
                self.logical_offset = self
                    .logical_offset
                    .checked_add(BRU_BLOCK_SIZE as u64)
                    .ok_or_else(|| FormatError::Parse("BRU logical offset overflow".to_string()))?;
                let mut block = BruBlock::new(offset, data);
                if self.record_read_error {
                    if block.status == BruBlockStatus::Ok {
                        block.status = BruBlockStatus::ReadErrorData;
                    }
                    block.source_state = self.record_source_state.clone();
                }
                return Ok(Some(block));
            }
            if self.record_pos != self.record_len {
                return Err(FormatError::Parse(format!(
                    "BRU physical record length {} is not a multiple of {}",
                    self.record_len, BRU_BLOCK_SIZE
                )));
            }
            if let Some(pending) = self.pending_read_error.take() {
                self.record_read_error = false;
                self.record_source_state.clear();
                let offset = self.logical_offset;
                self.logical_offset = self
                    .logical_offset
                    .checked_add(BRU_BLOCK_SIZE as u64)
                    .ok_or_else(|| FormatError::Parse("BRU logical offset overflow".to_string()))?;
                return Ok(Some(BruBlock::read_error(
                    offset,
                    pending.position_before,
                    pending.position_after,
                    &pending.diagnostic,
                )));
            }

            let position_before = match self.physical_position {
                Some(position) => position,
                None => {
                    let position = self.source.position()?;
                    self.physical_position = Some(position);
                    position
                }
            };
            match self.source.read_record(&mut self.record) {
                Err(error) => {
                    let Some(transferred_bytes) =
                        recoverable_transferred_bytes(&error, self.record.len())
                    else {
                        return Err(error.into());
                    };
                    let Ok(position_after) = self.source.position() else {
                        return Err(error.into());
                    };
                    if position_after.partition != position_before.partition
                        || position_after.lba <= position_before.lba
                    {
                        return Err(error.into());
                    }
                    self.physical_position = Some(position_after);
                    let complete_bru_bytes = transferred_bytes - transferred_bytes % BRU_BLOCK_SIZE;
                    let diagnostic = format!(
                        "{error}; bytes_transferred={transferred_bytes}; complete_bru_bytes={complete_bru_bytes}"
                    );
                    self.record_pos = 0;
                    self.record_len = complete_bru_bytes;
                    self.record_read_error = true;
                    self.record_source_state =
                        physical_read_state(position_before, position_after, &diagnostic);
                    self.pending_read_error = Some(PendingPhysicalReadError {
                        position_before,
                        position_after,
                        diagnostic,
                    });
                    continue;
                }
                Ok(PhysicalReadOutcome::Data { bytes: 0, .. }) => {
                    return Err(FormatError::Parse(
                        "BRU physical data record is empty".to_string(),
                    ));
                }
                Ok(PhysicalReadOutcome::Data {
                    bytes,
                    position_after,
                }) => {
                    if bytes > self.record.len() {
                        return Err(FormatError::Parse(format!(
                            "physical source returned {bytes} bytes for a {}-byte BRU buffer",
                            self.record.len()
                        )));
                    }
                    self.physical_position = Some(position_after);
                    self.record_pos = 0;
                    self.record_len = bytes;
                    self.record_read_error = false;
                    self.record_source_state.clear();
                }
                Ok(PhysicalReadOutcome::Filemark { position_after })
                | Ok(PhysicalReadOutcome::EndOfData { position_after }) => {
                    self.physical_position = Some(position_after);
                    return Ok(None);
                }
            }
        }
    }
}

fn recoverable_transferred_bytes(error: &TapeIoError, buffer_len: usize) -> Option<usize> {
    let transferred = match error {
        TapeIoError::CheckCondition(error) => check_condition_transferred_bytes(error)?,
        // `provided` is the caller's buffer capacity, not a count of bytes
        // written before the error. The tape contract does not guarantee that
        // any part of the buffer was initialized on this path.
        TapeIoError::ReadBufferTooSmall { .. } => 0,
        _ => return None,
    };
    Some(transferred.min(buffer_len))
}

fn check_condition_transferred_bytes(error: &ScsiError) -> Option<usize> {
    #[cfg(target_os = "linux")]
    {
        let ScsiError::CheckCondition {
            bytes_transferred, ..
        } = error
        else {
            return None;
        };
        Some(*bytes_transferred as usize)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = error;
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BruBlockStatus {
    Ok,
    ChecksumFailed,
    Partial,
    ReadErrorData,
    ReadError,
}

#[derive(Debug)]
struct BruBlock {
    offset: u64,
    data: [u8; BRU_BLOCK_SIZE],
    valid_len: usize,
    status: BruBlockStatus,
    source_state: Vec<u8>,
}

impl BruBlock {
    fn new(offset: u64, data: [u8; BRU_BLOCK_SIZE]) -> Self {
        let status = if verify_block(&data).is_ok() {
            BruBlockStatus::Ok
        } else {
            BruBlockStatus::ChecksumFailed
        };
        Self {
            offset,
            data,
            valid_len: BRU_BLOCK_SIZE,
            status,
            source_state: Vec::new(),
        }
    }

    fn partial(offset: u64, data: [u8; BRU_BLOCK_SIZE], valid_len: usize) -> Self {
        Self {
            offset,
            data,
            valid_len,
            status: BruBlockStatus::Partial,
            source_state: Vec::new(),
        }
    }

    fn read_error(
        offset: u64,
        position_before: PhysicalTapePosition,
        position_after: PhysicalTapePosition,
        diagnostic: &str,
    ) -> Self {
        Self {
            offset,
            data: [0; BRU_BLOCK_SIZE],
            valid_len: BRU_BLOCK_SIZE,
            status: BruBlockStatus::ReadError,
            source_state: physical_read_state(position_before, position_after, diagnostic),
        }
    }
}

fn physical_read_state(
    position_before: PhysicalTapePosition,
    position_after: PhysicalTapePosition,
    diagnostic: &str,
) -> Vec<u8> {
    let mut state = Vec::with_capacity(32 + diagnostic.len());
    state.extend_from_slice(&position_before.partition.to_le_bytes());
    state.extend_from_slice(&position_before.lba.to_le_bytes());
    state.extend_from_slice(&position_after.partition.to_le_bytes());
    state.extend_from_slice(&position_after.lba.to_le_bytes());
    state.extend_from_slice(diagnostic.as_bytes());
    state
}

trait BruVisitor {
    fn entry(&mut self, entry: &NormalizedEntry) -> Result<(), FormatError>;
    fn data(&mut self, file_offset: u64, bytes: &[u8]) -> Result<(), FormatError>;
    fn damage(&mut self, range: &DamageRange) -> Result<(), FormatError>;
    fn archive_gap(&mut self, range: &ArchiveGapRange) -> Result<(), FormatError>;
    fn end_entry(&mut self, entry: &NormalizedEntry) -> Result<(), FormatError>;
}

struct ScanVisitor<'a> {
    sink: &'a mut dyn EntryCatalogSink,
    report: ScanReport,
}

impl BruVisitor for ScanVisitor<'_> {
    fn entry(&mut self, entry: &NormalizedEntry) -> Result<(), FormatError> {
        self.report.entries += 1;
        self.sink.entry(entry)
    }

    fn data(&mut self, _file_offset: u64, _bytes: &[u8]) -> Result<(), FormatError> {
        Ok(())
    }

    fn damage(&mut self, range: &DamageRange) -> Result<(), FormatError> {
        self.report.damage_events += 1;
        self.sink.damage(range)
    }

    fn archive_gap(&mut self, range: &ArchiveGapRange) -> Result<(), FormatError> {
        self.report.archive_gaps += 1;
        self.sink.archive_gap(range)
    }

    fn end_entry(&mut self, _entry: &NormalizedEntry) -> Result<(), FormatError> {
        Ok(())
    }
}

struct StreamVisitor<'a> {
    sink: &'a mut dyn ArchiveEventSink,
    report: StreamReport,
}

impl BruVisitor for StreamVisitor<'_> {
    fn entry(&mut self, entry: &NormalizedEntry) -> Result<(), FormatError> {
        self.report.entries += 1;
        self.sink.begin_entry(entry)
    }

    fn data(&mut self, file_offset: u64, bytes: &[u8]) -> Result<(), FormatError> {
        self.report.bytes += bytes.len() as u64;
        self.sink.write_file_data(file_offset, bytes)
    }

    fn damage(&mut self, range: &DamageRange) -> Result<(), FormatError> {
        self.report.damage_events += 1;
        self.sink.report_damage(range)
    }

    fn archive_gap(&mut self, range: &ArchiveGapRange) -> Result<(), FormatError> {
        self.report.archive_gaps += 1;
        self.sink.report_archive_gap(range)
    }

    fn end_entry(&mut self, entry: &NormalizedEntry) -> Result<(), FormatError> {
        self.sink.end_entry(entry)
    }
}

fn walk_archive(
    source: &mut dyn BruBlockSource,
    visitor: &mut dyn BruVisitor,
) -> Result<(), FormatError> {
    let archive_block = source
        .next_block()?
        .ok_or_else(|| FormatError::Parse("missing BRU archive header".to_string()))?;
    if archive_block.status == BruBlockStatus::Partial {
        return Err(FormatError::TruncatedPayload);
    }
    if !matches!(
        archive_block.status,
        BruBlockStatus::Ok | BruBlockStatus::ReadErrorData
    ) {
        return Err(FormatError::Parse(
            "BRU archive header checksum failed".to_string(),
        ));
    }
    parse_archive_header(&archive_block.data)?;

    let mut pending_block: Option<BruBlock> = None;
    loop {
        let block = match pending_block.take() {
            Some(block) => Some(block),
            None => source.next_block()?,
        };
        let Some(block) = block else { break };
        let Some(block) = file_header_or_resync(source, visitor, block)? else {
            break;
        };
        let header = parse_file_header(&block.data)?;
        if header.compression != BruCompression::None {
            return Err(FormatError::unsupported(format!(
                "BRU member {} uses {:?} software compression",
                header.path, header.compression
            )));
        }
        let entry = normalized_entry(block.offset, &header);
        visitor.entry(&entry)?;
        pending_block = stream_entry_body(source, visitor, &entry, &header, &block)?;
        visitor.end_entry(&entry)?;
    }
    Ok(())
}

fn file_header_or_resync(
    source: &mut dyn BruBlockSource,
    visitor: &mut dyn BruVisitor,
    block: BruBlock,
) -> Result<Option<BruBlock>, FormatError> {
    if block.status == BruBlockStatus::Partial {
        visitor.archive_gap(&archive_gap_range(&block, ArchiveGapCause::Missing))?;
        return Ok(None);
    }
    if block.status == BruBlockStatus::ReadError {
        visitor.archive_gap(&archive_gap_range(&block, ArchiveGapCause::ReadError))?;
        return resync_to_file_header(source, visitor);
    }
    if is_archive_terminator(&block) {
        return Ok(None);
    }
    if is_resync_file_header(&block) {
        Ok(Some(block))
    } else {
        visitor.archive_gap(&archive_gap_range(
            &block,
            ArchiveGapCause::UnrecognizedData,
        ))?;
        resync_to_file_header(source, visitor)
    }
}

fn resync_to_file_header(
    source: &mut dyn BruBlockSource,
    visitor: &mut dyn BruVisitor,
) -> Result<Option<BruBlock>, FormatError> {
    while let Some(block) = source.next_block()? {
        if block.status == BruBlockStatus::Partial {
            visitor.archive_gap(&archive_gap_range(&block, ArchiveGapCause::Missing))?;
            return Ok(None);
        }
        if block.status == BruBlockStatus::ReadError {
            visitor.archive_gap(&archive_gap_range(&block, ArchiveGapCause::ReadError))?;
            continue;
        }
        if is_archive_terminator(&block) {
            return Ok(None);
        }
        if is_resync_file_header(&block) {
            return Ok(Some(block));
        }
        visitor.archive_gap(&archive_gap_range(&block, ArchiveGapCause::Resync))?;
    }
    Ok(None)
}

fn is_archive_terminator(block: &BruBlock) -> bool {
    matches!(
        block.status,
        BruBlockStatus::Ok | BruBlockStatus::ReadErrorData
    ) && read_magic(&block.data).ok() == Some(MAGIC_ARCHIVE_TERMINATOR)
}

fn is_resync_file_header(block: &BruBlock) -> bool {
    matches!(
        block.status,
        BruBlockStatus::Ok | BruBlockStatus::ReadErrorData
    ) && matches!(read_magic(&block.data), Ok(MAGIC_FILE_HEADER))
        && parse_file_header(&block.data).is_ok()
}

fn stream_entry_body(
    source: &mut dyn BruBlockSource,
    visitor: &mut dyn BruVisitor,
    entry: &NormalizedEntry,
    header: &BruFileHeader,
    header_block: &BruBlock,
) -> Result<Option<BruBlock>, FormatError> {
    if header.kind != EntryKind::RegularFile || header.size_bytes == 0 {
        return Ok(None);
    }

    let mut position = 0u64;
    let inline_len = read_hex_u64(&header_block.data, INLINE_DATA_LEN_OFFSET, 4)?;
    if inline_len > 1024 {
        return Err(FormatError::Parse(format!(
            "invalid BRU inline_data_len={inline_len} at byte offset 0x{:x}",
            header_block.offset
        )));
    }
    if inline_len > header.size_bytes {
        return Err(FormatError::Parse(format!(
            "BRU inline_data_len={inline_len} exceeds file size {} for {}",
            header.size_bytes, header.path
        )));
    }
    if inline_len > 0 {
        let end = INLINE_DATA_OFFSET + inline_len as usize;
        if let Some(status) = payload_damage_status(header_block.status) {
            visitor.damage(&damage_range(
                &entry.file_id,
                position,
                position + inline_len,
                status,
                Some(header_block.offset),
            ))?;
        }
        visitor.data(position, &header_block.data[INLINE_DATA_OFFSET..end])?;
        position += inline_len;
    }

    while position < header.size_bytes {
        let block = match source.next_block() {
            Ok(Some(block)) => block,
            Ok(None) | Err(FormatError::TruncatedPayload) => {
                visitor.damage(&damage_range(
                    &entry.file_id,
                    position,
                    header.size_bytes,
                    DamageStatus::Missing,
                    None,
                ))?;
                return Ok(None);
            }
            Err(err) => return Err(err),
        };
        if block.status == BruBlockStatus::Partial {
            return stream_partial_continuation(visitor, entry, header, position, block);
        }
        if block.status == BruBlockStatus::ReadError {
            visitor.damage(&damage_range(
                &entry.file_id,
                position,
                header.size_bytes,
                DamageStatus::ReadError,
                Some(block.offset),
            ))?;
            visitor.archive_gap(&archive_gap_range(&block, ArchiveGapCause::ReadError))?;
            return Ok(None);
        }
        let magic = match read_magic(&block.data) {
            Ok(magic) => magic,
            Err(_) => {
                return abort_entry_body_after_bad_continuation(
                    visitor, entry, header, position, block,
                );
            }
        };
        if magic != MAGIC_CONTINUATION {
            return abort_entry_body_after_bad_continuation(
                visitor, entry, header, position, block,
            );
        }
        let dlen = match read_hex_u64(&block.data, CONTINUATION_DLEN_OFFSET, 4) {
            Ok(dlen) => dlen,
            Err(_) => {
                return abort_entry_body_after_bad_continuation(
                    visitor, entry, header, position, block,
                );
            }
        };
        if dlen == 0 || dlen > 1792 {
            return abort_entry_body_after_bad_continuation(
                visitor, entry, header, position, block,
            );
        }
        let remaining = header.size_bytes - position;
        if dlen > remaining {
            return abort_entry_body_after_bad_continuation(
                visitor, entry, header, position, block,
            );
        }
        if let Some(status) = payload_damage_status(block.status) {
            visitor.damage(&damage_range(
                &entry.file_id,
                position,
                position + dlen,
                status,
                Some(block.offset),
            ))?;
        }
        let end = CONTINUATION_DATA_OFFSET + dlen as usize;
        visitor.data(position, &block.data[CONTINUATION_DATA_OFFSET..end])?;
        position += dlen;
    }
    Ok(None)
}

fn payload_damage_status(status: BruBlockStatus) -> Option<DamageStatus> {
    match status {
        BruBlockStatus::Ok => None,
        BruBlockStatus::ChecksumFailed | BruBlockStatus::Partial => {
            Some(DamageStatus::ChecksumFailed)
        }
        BruBlockStatus::ReadErrorData | BruBlockStatus::ReadError => Some(DamageStatus::ReadError),
    }
}

fn stream_partial_continuation(
    visitor: &mut dyn BruVisitor,
    entry: &NormalizedEntry,
    header: &BruFileHeader,
    mut position: u64,
    block: BruBlock,
) -> Result<Option<BruBlock>, FormatError> {
    let continuation_header_end = CONTINUATION_DLEN_OFFSET + 4;
    if block.valid_len < continuation_header_end
        || read_magic(&block.data).ok() != Some(MAGIC_CONTINUATION)
    {
        visitor.damage(&damage_range(
            &entry.file_id,
            position,
            header.size_bytes,
            DamageStatus::Missing,
            Some(block.offset),
        ))?;
        visitor.archive_gap(&archive_gap_range(&block, ArchiveGapCause::Missing))?;
        return Ok(None);
    }

    let dlen = match read_hex_u64(&block.data, CONTINUATION_DLEN_OFFSET, 4) {
        Ok(dlen) => dlen,
        Err(_) => {
            return abort_entry_body_after_bad_continuation(
                visitor, entry, header, position, block,
            );
        }
    };
    let remaining = header.size_bytes - position;
    if dlen == 0 || dlen > 1792 || dlen > remaining {
        return abort_entry_body_after_bad_continuation(visitor, entry, header, position, block);
    }

    let available = block
        .valid_len
        .saturating_sub(CONTINUATION_DATA_OFFSET)
        .min(dlen as usize);
    if available > 0 {
        let available_end = position + available as u64;
        visitor.damage(&damage_range(
            &entry.file_id,
            position,
            available_end,
            DamageStatus::ChecksumFailed,
            Some(block.offset),
        ))?;
        visitor.data(
            position,
            &block.data[CONTINUATION_DATA_OFFSET..CONTINUATION_DATA_OFFSET + available],
        )?;
        position = available_end;
    }
    if position < header.size_bytes {
        visitor.damage(&damage_range(
            &entry.file_id,
            position,
            header.size_bytes,
            DamageStatus::Missing,
            Some(block.offset + block.valid_len as u64),
        ))?;
    }
    visitor.archive_gap(&ArchiveGapRange {
        source_start: block.offset + block.valid_len as u64,
        source_end: block.offset + BRU_BLOCK_SIZE as u64,
        cause: ArchiveGapCause::Missing,
        adapter_state: block.source_state.clone(),
    })?;
    Ok(None)
}

fn abort_entry_body_after_bad_continuation(
    visitor: &mut dyn BruVisitor,
    entry: &NormalizedEntry,
    header: &BruFileHeader,
    position: u64,
    block: BruBlock,
) -> Result<Option<BruBlock>, FormatError> {
    if position < header.size_bytes {
        visitor.damage(&damage_range(
            &entry.file_id,
            position,
            header.size_bytes,
            DamageStatus::Missing,
            Some(block.offset),
        ))?;
    }
    if is_resync_file_header(&block) {
        return Ok(Some(block));
    }
    visitor.archive_gap(&archive_gap_range(
        &block,
        ArchiveGapCause::UnrecognizedData,
    ))?;
    Ok(None)
}

fn normalized_entry(header_offset: u64, header: &BruFileHeader) -> NormalizedEntry {
    let mut adapter_state = Vec::with_capacity(16 + header.raw_path.len());
    adapter_state.extend_from_slice(&header.sequence.to_le_bytes());
    adapter_state.extend_from_slice(&header_offset.to_le_bytes());
    adapter_state.extend_from_slice(&header.raw_path);
    NormalizedEntry {
        file_id: FileId(format!("bru:{}", header.sequence)),
        path: header.path.clone(),
        kind: header.kind,
        link_target: None,
        size_bytes: Some(header.size_bytes),
        adapter_state,
    }
}

fn damage_range(
    file_id: &FileId,
    start: u64,
    end: u64,
    status: DamageStatus,
    block_offset: Option<u64>,
) -> DamageRange {
    DamageRange {
        file_id: file_id.clone(),
        start,
        end,
        status,
        adapter_state: block_offset
            .map(|offset| offset.to_le_bytes().to_vec())
            .unwrap_or_default(),
    }
}

fn archive_gap_range(block: &BruBlock, cause: ArchiveGapCause) -> ArchiveGapRange {
    let mut adapter_state = block.source_state.clone();
    if adapter_state.is_empty() {
        adapter_state.reserve(16);
        adapter_state.extend_from_slice(&block.offset.to_le_bytes());
        if let Ok(magic) = read_magic(&block.data) {
            adapter_state.extend_from_slice(&magic.to_le_bytes());
        }
    }
    ArchiveGapRange {
        source_start: block.offset,
        source_end: block.offset + block.valid_len as u64,
        cause,
        adapter_state,
    }
}

/// Compute the BRU checksum for one logical block.
pub fn bru_checksum(block: &[u8; BRU_BLOCK_SIZE]) -> u32 {
    let mut sums = [0u32; 4];
    for (index, byte) in block.iter().enumerate() {
        let value = if (CHKSUM_OFFSET..CHKSUM_OFFSET + CHKSUM_SIZE).contains(&index) {
            CHKSUM_PLACEHOLDER[index - CHKSUM_OFFSET]
        } else {
            *byte
        };
        sums[index % 4] = sums[index % 4].wrapping_add(value as u32);
    }
    ((sums[0] & 0xff) << 24) | ((sums[1] & 0xff) << 16) | ((sums[2] & 0xff) << 8) | (sums[3] & 0xff)
}

/// Extract the stored BRU checksum from one logical block.
pub fn stored_checksum(block: &[u8; BRU_BLOCK_SIZE]) -> Result<u32, FormatError> {
    Ok(read_hex_u64(block, CHKSUM_OFFSET, CHKSUM_SIZE)? as u32)
}

fn verify_block(block: &[u8; BRU_BLOCK_SIZE]) -> Result<(), FormatError> {
    let stored = stored_checksum(block)?;
    let computed = bru_checksum(block);
    if stored == computed {
        Ok(())
    } else {
        Err(FormatError::Parse(format!(
            "BRU checksum mismatch: stored 0x{stored:08x}, computed 0x{computed:08x}"
        )))
    }
}

fn probe_block_confidence(block: &[u8; BRU_BLOCK_SIZE]) -> ProbeConfidence {
    match read_magic(block) {
        Ok(MAGIC_ARCHIVE_HEADER) if verify_block(block).is_ok() => ProbeConfidence::Certain,
        Ok(MAGIC_ARCHIVE_HEADER) => ProbeConfidence::Probable,
        Ok(_) | Err(_) => ProbeConfidence::NoMatch,
    }
}

fn parse_archive_header(block: &[u8; BRU_BLOCK_SIZE]) -> Result<BruArchiveHeader, FormatError> {
    let magic = read_magic(block)?;
    if magic != MAGIC_ARCHIVE_HEADER {
        return Err(FormatError::Parse(format!(
            "not a BRU archive header: magic=0x{magic:04x}"
        )));
    }
    let artime = read_hex_u64(block, ARTIME_OFFSET, 8)?;
    let archive_id_low = read_hex_u64(block, ARCHIVE_ID_LOW_OFFSET, 4)?;
    Ok(BruArchiveHeader {
        archive_id: format!("{artime:08x}{archive_id_low:04x}"),
        label: read_ascii(block, LABEL_OFFSET, LABEL_SIZE).0,
        buffer_size_bytes: read_hex_u64(block, BUFSIZE_OFFSET, 8)?,
        artime,
        release_major: read_hex_u64(block, RELEASE_MAJOR_OFFSET, 4)?,
        release_minor: read_hex_u64(block, RELEASE_MINOR_OFFSET, 4)?,
        variant: read_hex_u64(block, VARIANT_OFFSET, 4)?,
    })
}

fn parse_file_header(block: &[u8; BRU_BLOCK_SIZE]) -> Result<BruFileHeader, FormatError> {
    let magic = read_magic(block)?;
    if magic != MAGIC_FILE_HEADER {
        return Err(FormatError::Parse(format!(
            "not a BRU file header: magic=0x{magic:04x}"
        )));
    }
    let (path, raw_path) = read_ascii(block, FILE_PATH_OFFSET, FILE_PATH_SIZE);
    let mode = read_hex_u64(block, ST_MODE_OFFSET, 8)?;
    let kind = match mode & S_IFMT {
        S_IFDIR => EntryKind::Directory,
        S_IFREG => EntryKind::RegularFile,
        S_IFLNK => EntryKind::Symlink,
        _ => EntryKind::Special,
    };
    let size_low = read_hex_u64(block, ST_SIZE_OFFSET, 8)?;
    let size_high = read_hex_u64(block, SIZE_HIGH_OFFSET, 8)?;
    let compression = match read_hex_u64(block, FILE_FLAGS_OFFSET, 8)? & FILE_COMPRESSION_MASK {
        0 => BruCompression::None,
        FILE_FLAG_BUILTIN_COMPRESSION => BruCompression::BuiltIn,
        FILE_FLAG_EXTERNAL_COMPRESSION => BruCompression::External,
        _ => BruCompression::Ambiguous,
    };
    Ok(BruFileHeader {
        sequence: read_hex_u64(block, FILE_SEQUENCE_OFFSET, 8)?,
        path,
        raw_path,
        size_bytes: (size_high << 32) | size_low,
        kind,
        mode,
        compression,
    })
}

fn read_magic(block: &[u8; BRU_BLOCK_SIZE]) -> Result<u64, FormatError> {
    read_hex_u64(block, MAGIC_OFFSET, MAGIC_SIZE)
}

fn read_hex_u64(
    block: &[u8; BRU_BLOCK_SIZE],
    offset: usize,
    size: usize,
) -> Result<u64, FormatError> {
    let raw = block
        .get(offset..offset + size)
        .ok_or_else(|| FormatError::Parse("BRU field offset out of range".to_string()))?;
    let text: String = raw
        .iter()
        .map(|byte| if *byte == 0 { b' ' } else { *byte })
        .map(char::from)
        .collect();
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(trimmed, 16).map_err(|err| {
        FormatError::Parse(format!(
            "invalid BRU hex field at 0x{offset:x} ({trimmed:?}): {err}"
        ))
    })
}

fn read_ascii(block: &[u8; BRU_BLOCK_SIZE], offset: usize, size: usize) -> (String, Vec<u8>) {
    let mut raw = block[offset..offset + size].to_vec();
    if let Some(nul) = raw.iter().position(|byte| *byte == 0) {
        raw.truncate(nul);
    }
    let text = String::from_utf8_lossy(&raw).into_owned();
    (text, raw)
}

fn io_to_format(context: impl Into<String>, source: io::Error) -> FormatError {
    FormatError::SourceIo {
        context: context.into(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use remanence_library::PhysicalFilemarkSpace;

    #[derive(Default)]
    struct CatalogSink {
        entries: Vec<NormalizedEntry>,
        damages: Vec<DamageRange>,
        archive_gaps: Vec<ArchiveGapRange>,
    }

    impl EntryCatalogSink for CatalogSink {
        fn entry(&mut self, entry: &NormalizedEntry) -> Result<(), FormatError> {
            self.entries.push(entry.clone());
            Ok(())
        }

        fn damage(&mut self, range: &DamageRange) -> Result<(), FormatError> {
            self.damages.push(range.clone());
            Ok(())
        }

        fn archive_gap(&mut self, range: &ArchiveGapRange) -> Result<(), FormatError> {
            self.archive_gaps.push(range.clone());
            Ok(())
        }
    }

    #[derive(Default)]
    struct EventSink {
        entries: Vec<NormalizedEntry>,
        data: Vec<u8>,
        data_ranges: Vec<(u64, u64)>,
        damages: Vec<DamageRange>,
        archive_gaps: Vec<ArchiveGapRange>,
        ended: Vec<FileId>,
    }

    impl ArchiveEventSink for EventSink {
        fn begin_entry(&mut self, entry: &NormalizedEntry) -> Result<(), FormatError> {
            self.entries.push(entry.clone());
            Ok(())
        }

        fn write_file_data(&mut self, file_offset: u64, bytes: &[u8]) -> Result<(), FormatError> {
            self.data_ranges
                .push((file_offset, file_offset + bytes.len() as u64));
            self.data.extend_from_slice(bytes);
            Ok(())
        }

        fn report_damage(&mut self, range: &DamageRange) -> Result<(), FormatError> {
            self.damages.push(range.clone());
            Ok(())
        }

        fn report_archive_gap(&mut self, range: &ArchiveGapRange) -> Result<(), FormatError> {
            self.archive_gaps.push(range.clone());
            Ok(())
        }

        fn end_entry(&mut self, entry: &NormalizedEntry) -> Result<(), FormatError> {
            self.ended.push(entry.file_id.clone());
            Ok(())
        }
    }

    #[test]
    fn checksum_vectors_match_bru_spec() {
        assert_eq!(bru_checksum(&[0; BRU_BLOCK_SIZE]), 0x40404050);
        assert_eq!(bru_checksum(&[0xFF; BRU_BLOCK_SIZE]), 0x42424252);
    }

    #[test]
    fn reads_archive_header_from_dump_stream() {
        let archive = archive_block();
        let mut reader = BruFormat.open_dump_reader(std::io::Cursor::new(archive));

        let header = reader.read_archive_header().unwrap();

        assert_eq!(header.archive_id, "4de47d2661a8");
        assert_eq!(header.label, "TEST");
        assert_eq!(header.buffer_size_bytes, 1024 * 1024);
        assert_eq!(header.release_major, 17);
        assert_eq!(header.release_minor, 1);
    }

    #[test]
    fn streams_file_payload_and_damage_events() {
        let mut continuation = continuation_block(b"cde");
        continuation[CONTINUATION_DATA_OFFSET] ^= 0x40;
        let dump = [
            archive_block().as_slice(),
            file_header_block(1, "file.bin", 5, b"ab").as_slice(),
            continuation.as_slice(),
        ]
        .concat();
        let mut reader = BruFormat.open_dump_reader(std::io::Cursor::new(dump));
        let mut sink = EventSink::default();

        let report = reader.stream_all(&mut sink).unwrap();

        assert_eq!(report.entries, 1);
        assert_eq!(report.bytes, 5);
        assert_eq!(sink.data, b"ab#de");
        assert_eq!(sink.data_ranges, vec![(0, 2), (2, 5)]);
        assert_eq!(sink.damages.len(), 1);
        assert_eq!(sink.damages[0].start, 2);
        assert_eq!(sink.damages[0].end, 5);
        assert_eq!(sink.damages[0].status, DamageStatus::ChecksumFailed);
    }

    #[test]
    fn rejects_compressed_members_before_emitting_catalog_or_payload() {
        for (flag, expected) in [
            (FILE_FLAG_BUILTIN_COMPRESSION, "BuiltIn"),
            (FILE_FLAG_EXTERNAL_COMPRESSION, "External"),
            (FILE_COMPRESSION_MASK, "Ambiguous"),
        ] {
            let mut header = file_header_block(1, "compressed.bin", 3, b"abc");
            put_hex(&mut header, FILE_FLAGS_OFFSET, 8, flag);
            let dump = [
                archive_block().as_slice(),
                finalize_block(header).as_slice(),
            ]
            .concat();

            let mut scan_reader = BruFormat.open_dump_reader(std::io::Cursor::new(dump.clone()));
            let mut catalog = CatalogSink::default();
            let scan_error = scan_reader.scan(&mut catalog).unwrap_err();
            assert!(scan_error.to_string().contains(expected));
            assert!(catalog.entries.is_empty());

            let mut stream_reader = BruFormat.open_dump_reader(std::io::Cursor::new(dump));
            let mut events = EventSink::default();
            let stream_error = stream_reader.stream_all(&mut events).unwrap_err();
            assert!(stream_error.to_string().contains(expected));
            assert!(events.entries.is_empty());
            assert!(events.data.is_empty());
        }
    }

    #[test]
    fn accepts_a_valid_archive_terminator_without_reporting_a_gap() {
        let dump = [
            archive_block().as_slice(),
            file_header_block(1, "file.bin", 3, b"abc").as_slice(),
            archive_terminator_block().as_slice(),
        ]
        .concat();
        let mut reader = BruFormat.open_dump_reader(std::io::Cursor::new(dump));
        let mut sink = EventSink::default();

        let report = reader.stream_all(&mut sink).unwrap();

        assert_eq!(report.entries, 1);
        assert_eq!(report.bytes, 3);
        assert_eq!(report.archive_gaps, 0);
        assert_eq!(sink.data, b"abc");
    }

    #[test]
    fn streams_missing_damage_when_payload_truncates() {
        let dump = [
            archive_block().as_slice(),
            file_header_block(1, "file.bin", 5, b"ab").as_slice(),
        ]
        .concat();
        let mut reader = BruFormat.open_dump_reader(std::io::Cursor::new(dump));
        let mut sink = EventSink::default();

        let report = reader.stream_all(&mut sink).unwrap();

        assert_eq!(report.entries, 1);
        assert_eq!(report.bytes, 2);
        assert_eq!(report.damage_events, 1);
        assert_eq!(sink.data, b"ab");
        assert_eq!(sink.data_ranges, vec![(0, 2)]);
        assert_eq!(sink.damages.len(), 1);
        assert_eq!(sink.damages[0].start, 2);
        assert_eq!(sink.damages[0].end, 5);
        assert_eq!(sink.damages[0].status, DamageStatus::Missing);
        assert_eq!(sink.ended, vec![FileId("bru:1".to_string())]);
    }

    #[test]
    fn streams_complete_payload_from_a_partial_continuation_as_suspect() {
        let continuation = continuation_block(b"cde");
        let mut dump = [
            archive_block().as_slice(),
            file_header_block(1, "file.bin", 5, b"ab").as_slice(),
        ]
        .concat();
        dump.extend_from_slice(&continuation[..CONTINUATION_DATA_OFFSET + 3]);
        let mut reader = BruFormat.open_dump_reader(std::io::Cursor::new(dump));
        let mut sink = EventSink::default();

        let report = reader.stream_all(&mut sink).unwrap();

        assert_eq!(report.entries, 1);
        assert_eq!(report.bytes, 5);
        assert_eq!(report.damage_events, 1);
        assert_eq!(report.archive_gaps, 1);
        assert_eq!(sink.data, b"abcde");
        assert_eq!(sink.data_ranges, vec![(0, 2), (2, 5)]);
        assert_eq!(sink.damages[0].start, 2);
        assert_eq!(sink.damages[0].end, 5);
        assert_eq!(sink.damages[0].status, DamageStatus::ChecksumFailed);
        assert_eq!(
            sink.archive_gaps[0].source_start,
            2 * BRU_BLOCK_SIZE as u64 + CONTINUATION_DATA_OFFSET as u64 + 3
        );
        assert_eq!(sink.archive_gaps[0].source_end, 3 * BRU_BLOCK_SIZE as u64);
        assert_eq!(sink.archive_gaps[0].cause, ArchiveGapCause::Missing);
    }

    #[test]
    fn partial_continuation_marks_only_unavailable_file_bytes_missing() {
        let continuation = continuation_block(b"cde");
        let mut dump = [
            archive_block().as_slice(),
            file_header_block(1, "file.bin", 5, b"ab").as_slice(),
        ]
        .concat();
        dump.extend_from_slice(&continuation[..CONTINUATION_DATA_OFFSET + 1]);
        let mut reader = BruFormat.open_dump_reader(std::io::Cursor::new(dump));
        let mut sink = EventSink::default();

        let report = reader.stream_all(&mut sink).unwrap();

        assert_eq!(report.bytes, 3);
        assert_eq!(report.damage_events, 2);
        assert_eq!(sink.data, b"abc");
        assert_eq!(sink.damages[0].start, 2);
        assert_eq!(sink.damages[0].end, 3);
        assert_eq!(sink.damages[0].status, DamageStatus::ChecksumFailed);
        assert_eq!(sink.damages[1].start, 3);
        assert_eq!(sink.damages[1].end, 5);
        assert_eq!(sink.damages[1].status, DamageStatus::Missing);
    }

    #[test]
    fn malformed_length_in_partial_continuation_is_nonfatal() {
        let mut continuation = continuation_block(b"cde");
        continuation[CONTINUATION_DLEN_OFFSET..CONTINUATION_DLEN_OFFSET + 4]
            .copy_from_slice(b"zzzz");
        let mut dump = [
            archive_block().as_slice(),
            file_header_block(1, "file.bin", 5, b"ab").as_slice(),
        ]
        .concat();
        dump.extend_from_slice(&continuation[..CONTINUATION_DATA_OFFSET]);
        let mut reader = BruFormat.open_dump_reader(std::io::Cursor::new(dump));
        let mut sink = EventSink::default();

        let report = reader.stream_all(&mut sink).unwrap();

        assert_eq!(report.entries, 1);
        assert_eq!(report.bytes, 2);
        assert_eq!(report.damage_events, 1);
        assert_eq!(report.archive_gaps, 1);
        assert_eq!(sink.data, b"ab");
        assert_eq!(sink.damages[0].start, 2);
        assert_eq!(sink.damages[0].end, 5);
        assert_eq!(sink.damages[0].status, DamageStatus::Missing);
        assert_eq!(
            sink.archive_gaps[0].cause,
            ArchiveGapCause::UnrecognizedData
        );
        assert_eq!(sink.ended, vec![FileId("bru:1".to_string())]);
    }

    #[test]
    fn scan_reports_entries_without_materializing_payloads() {
        let dump = [
            archive_block().as_slice(),
            file_header_block(1, "dir", 0, b"").as_slice(),
            file_header_block(2, "file.bin", 3, b"abc").as_slice(),
        ]
        .concat();
        let mut reader = BruFormat.open_dump_reader(std::io::Cursor::new(dump));
        let mut sink = CatalogSink::default();

        let report = reader.scan(&mut sink).unwrap();

        assert_eq!(report.entries, 2);
        assert_eq!(sink.entries[0].path, "dir");
        assert_eq!(sink.entries[0].kind, EntryKind::Directory);
        assert_eq!(sink.entries[1].path, "file.bin");
        assert_eq!(sink.entries[1].size_bytes, Some(3));
    }

    #[test]
    fn vendor_validated_fixture_covers_utf8_long_paths_and_continuations() {
        let fixture = include_bytes!("../../../fixtures/reference-edge.bru");
        let mut reader = BruFormat.open_dump_reader(std::io::Cursor::new(fixture.as_slice()));
        let mut sink = EventSink::default();

        let report = reader.stream_all(&mut sink).unwrap();

        assert_eq!(report.entries, 2);
        assert_eq!(report.bytes, 2000);
        assert_eq!(report.damage_events, 0);
        assert_eq!(report.archive_gaps, 0);
        assert_eq!(sink.entries[0].path, "café");
        assert_eq!(sink.entries[0].kind, EntryKind::Directory);
        assert_eq!(sink.entries[1].path.len(), 121);
        assert!(sink.entries[1].path.starts_with("archive/"));
        assert!(sink.entries[1].path.ends_with(".bin"));
        assert_eq!(sink.data.len(), 2000);
        assert_eq!(
            sink.data,
            (0..2000)
                .map(|index| ((index * 37 + 11) % 256) as u8)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn probe_recognizes_archive_header_and_restores_position() {
        let mut source = FakePhysicalSource::new(vec![archive_block().to_vec()]);

        let probe = BruFormat.probe_tape(&mut source).unwrap();

        assert_eq!(probe.confidence, ProbeConfidence::Certain);
        assert_eq!(
            probe.source_requirement,
            SourceRequirement::PhysicalTapeRecords
        );
        assert_eq!(source.configured, vec![BlockSize::Variable]);
        assert_eq!(source.position, PhysicalTapePosition::new(0));
        assert_eq!(source.next_record, 0);
        assert_eq!(source.locates, vec![PhysicalTapePosition::new(0)]);
    }

    #[test]
    fn probe_returns_no_match_for_non_hex_magic_and_restores_position() {
        let mut block = [0; BRU_BLOCK_SIZE];
        block[MAGIC_OFFSET..MAGIC_OFFSET + MAGIC_SIZE].copy_from_slice(b"nope");
        let mut source = FakePhysicalSource::new(vec![block.to_vec()]);

        let probe = BruFormat.probe_tape(&mut source).unwrap();

        assert_eq!(probe.confidence, ProbeConfidence::NoMatch);
        assert_eq!(source.configured, vec![BlockSize::Variable]);
        assert_eq!(source.position, PhysicalTapePosition::new(0));
        assert_eq!(source.next_record, 0);
        assert_eq!(source.locates, vec![PhysicalTapePosition::new(0)]);
    }

    #[test]
    fn probe_dump_recognizes_archive_header_and_restores_position() {
        let mut dump = archive_block().to_vec();
        dump.extend_from_slice(&file_header_block(1, "file.bin", 3, b"abc"));
        let mut reader = std::io::Cursor::new(dump);
        reader.set_position(0);

        let probe = BruFormat.probe_dump(&mut reader).unwrap();

        assert_eq!(probe.confidence, ProbeConfidence::Certain);
        assert_eq!(probe.source_requirement, SourceRequirement::ByteStreamDump);
        assert_eq!(reader.position(), 0);
    }

    #[test]
    fn probe_dump_returns_no_match_for_short_stream_and_restores_position() {
        let mut reader = std::io::Cursor::new(vec![0; BRU_BLOCK_SIZE - 1]);
        reader.set_position(17);

        let probe = BruFormat.probe_dump(&mut reader).unwrap();

        assert_eq!(probe.confidence, ProbeConfidence::NoMatch);
        assert_eq!(probe.source_requirement, SourceRequirement::ByteStreamDump);
        assert_eq!(reader.position(), 17);
    }

    #[test]
    fn stream_resyncs_after_unattributed_top_level_block() {
        let dump = [
            archive_block().as_slice(),
            file_header_block(1, "first.bin", 3, b"one").as_slice(),
            unrecognized_block().as_slice(),
            file_header_block(2, "second.bin", 3, b"two").as_slice(),
        ]
        .concat();
        let mut reader = BruFormat.open_dump_reader(std::io::Cursor::new(dump));
        let mut sink = EventSink::default();

        let report = reader.stream_all(&mut sink).unwrap();

        assert_eq!(report.entries, 2);
        assert_eq!(report.bytes, 6);
        assert_eq!(report.archive_gaps, 1);
        assert_eq!(sink.data, b"onetwo");
        assert_eq!(sink.entries[0].path, "first.bin");
        assert_eq!(sink.entries[1].path, "second.bin");
        assert_eq!(sink.archive_gaps.len(), 1);
        assert_eq!(sink.archive_gaps[0].source_start, 2 * BRU_BLOCK_SIZE as u64);
        assert_eq!(sink.archive_gaps[0].source_end, 3 * BRU_BLOCK_SIZE as u64);
        assert_eq!(
            sink.archive_gaps[0].cause,
            ArchiveGapCause::UnrecognizedData
        );
    }

    #[test]
    fn stream_resyncs_after_invalid_top_level_file_header() {
        let mut bad_header = file_header_block(2, "bad.bin", 0, b"");
        bad_header[ST_MODE_OFFSET] = b'z';
        let bad_header = finalize_block(bad_header);
        let dump = [
            archive_block().as_slice(),
            bad_header.as_slice(),
            file_header_block(3, "after-bad.bin", 4, b"data").as_slice(),
        ]
        .concat();
        let mut reader = BruFormat.open_dump_reader(std::io::Cursor::new(dump));
        let mut sink = EventSink::default();

        let report = reader.stream_all(&mut sink).unwrap();

        assert_eq!(report.entries, 1);
        assert_eq!(report.archive_gaps, 1);
        assert_eq!(sink.entries[0].path, "after-bad.bin");
        assert_eq!(sink.entries[0].file_id, FileId("bru:3".to_string()));
        assert_eq!(sink.data, b"data");
        assert_eq!(sink.archive_gaps[0].source_start, BRU_BLOCK_SIZE as u64);
    }

    #[test]
    fn stream_marks_missing_and_resyncs_after_bad_continuation_magic() {
        let dump = [
            archive_block().as_slice(),
            file_header_block(1, "first.bin", 5, b"ab").as_slice(),
            unrecognized_block().as_slice(),
            file_header_block(2, "second.bin", 3, b"two").as_slice(),
        ]
        .concat();
        let mut reader = BruFormat.open_dump_reader(std::io::Cursor::new(dump));
        let mut sink = EventSink::default();

        let report = reader.stream_all(&mut sink).unwrap();

        assert_eq!(report.entries, 2);
        assert_eq!(report.bytes, 5);
        assert_eq!(report.damage_events, 1);
        assert_eq!(report.archive_gaps, 1);
        assert_eq!(sink.data, b"abtwo");
        assert_eq!(sink.damages[0].start, 2);
        assert_eq!(sink.damages[0].end, 5);
        assert_eq!(sink.damages[0].status, DamageStatus::Missing);
        assert_eq!(sink.entries[1].path, "second.bin");
    }

    #[test]
    fn stream_marks_missing_and_keeps_next_header_when_continuation_is_replaced_by_header() {
        let dump = [
            archive_block().as_slice(),
            file_header_block(1, "first.bin", 5, b"ab").as_slice(),
            file_header_block(2, "second.bin", 3, b"two").as_slice(),
        ]
        .concat();
        let mut reader = BruFormat.open_dump_reader(std::io::Cursor::new(dump));
        let mut sink = EventSink::default();

        let report = reader.stream_all(&mut sink).unwrap();

        assert_eq!(report.entries, 2);
        assert_eq!(report.bytes, 5);
        assert_eq!(report.damage_events, 1);
        assert_eq!(report.archive_gaps, 0);
        assert_eq!(sink.data, b"abtwo");
        assert_eq!(sink.damages[0].status, DamageStatus::Missing);
        assert_eq!(sink.entries[1].path, "second.bin");
    }

    #[test]
    fn scan_resyncs_after_unattributed_top_level_block() {
        let dump = [
            archive_block().as_slice(),
            unrecognized_block().as_slice(),
            file_header_block(1, "after-gap.bin", 4, b"data").as_slice(),
        ]
        .concat();
        let mut reader = BruFormat.open_dump_reader(std::io::Cursor::new(dump));
        let mut sink = CatalogSink::default();

        let report = reader.scan(&mut sink).unwrap();

        assert_eq!(report.entries, 1);
        assert_eq!(report.archive_gaps, 1);
        assert_eq!(sink.entries[0].path, "after-gap.bin");
        assert_eq!(sink.archive_gaps.len(), 1);
        assert_eq!(sink.archive_gaps[0].source_start, BRU_BLOCK_SIZE as u64);
    }

    #[test]
    fn scan_keeps_completed_entries_and_reports_a_partial_tail() {
        let mut dump = [
            archive_block().as_slice(),
            file_header_block(1, "file.bin", 3, b"abc").as_slice(),
        ]
        .concat();
        dump.extend_from_slice(b"partial");
        let mut reader = BruFormat.open_dump_reader(std::io::Cursor::new(dump));
        let mut sink = CatalogSink::default();

        let report = reader.scan(&mut sink).unwrap();

        assert_eq!(report.entries, 1);
        assert_eq!(report.archive_gaps, 1);
        assert_eq!(sink.entries[0].file_id, FileId("bru:1".to_string()));
        assert_eq!(sink.archive_gaps.len(), 1);
        assert_eq!(sink.archive_gaps[0].source_start, 2 * BRU_BLOCK_SIZE as u64);
        assert_eq!(
            sink.archive_gaps[0].source_end,
            2 * BRU_BLOCK_SIZE as u64 + 7
        );
        assert_eq!(sink.archive_gaps[0].cause, ArchiveGapCause::Missing);
    }

    #[test]
    fn physical_reader_splits_large_records_into_bru_blocks() {
        let record = [
            archive_block().as_slice(),
            file_header_block(1, "file.bin", 3, b"abc").as_slice(),
        ]
        .concat();
        let mut source = FakePhysicalSource::new(vec![record]);
        let mut sink = EventSink::default();
        let probe = ProbeResult {
            format_id: BruFormat.id().to_string(),
            confidence: ProbeConfidence::Certain,
            source_requirement: SourceRequirement::PhysicalTapeRecords,
            adapter_state: Vec::new(),
        };

        let report = {
            let mut reader = BruFormat.open_tape_reader(&mut source, &probe).unwrap();
            reader.stream_all(&mut sink).unwrap()
        };

        assert_eq!(source.configured, vec![BlockSize::Variable]);
        assert_eq!(report.entries, 1);
        assert_eq!(report.bytes, 3);
        assert_eq!(sink.data, b"abc");
    }

    #[test]
    fn physical_reader_reports_an_advancing_read_error_and_resynchronizes() {
        let records = vec![
            archive_block().to_vec(),
            file_header_block(1, "first.bin", 5, b"ab").to_vec(),
            vec![0; BRU_BLOCK_SIZE],
            file_header_block(2, "second.bin", 3, b"two").to_vec(),
        ];
        let mut source = AdvancingReadErrorSource {
            inner: FakePhysicalSource::new(records),
            fail_at: 2,
            failed: false,
            transferred: Vec::new(),
        };
        let mut sink = EventSink::default();
        let probe = ProbeResult {
            format_id: BruFormat.id().to_string(),
            confidence: ProbeConfidence::Certain,
            source_requirement: SourceRequirement::PhysicalTapeRecords,
            adapter_state: Vec::new(),
        };

        let report = {
            let mut reader = BruFormat.open_tape_reader(&mut source, &probe).unwrap();
            reader.stream_all(&mut sink).unwrap()
        };

        assert_eq!(report.entries, 2);
        assert_eq!(report.bytes, 5);
        assert_eq!(report.damage_events, 1);
        assert_eq!(report.archive_gaps, 1);
        assert_eq!(sink.data, b"abtwo");
        assert_eq!(sink.damages[0].start, 2);
        assert_eq!(sink.damages[0].end, 5);
        assert_eq!(sink.damages[0].status, DamageStatus::ReadError);
        assert_eq!(sink.archive_gaps[0].cause, ArchiveGapCause::ReadError);
        assert_eq!(sink.entries[1].path, "second.bin");
    }

    #[test]
    fn physical_reader_preserves_complete_blocks_transferred_before_read_error() {
        let records = vec![
            archive_block().to_vec(),
            file_header_block(1, "first.bin", 5, b"ab").to_vec(),
            vec![0; BRU_BLOCK_SIZE],
            file_header_block(2, "second.bin", 3, b"two").to_vec(),
        ];
        let mut source = AdvancingReadErrorSource {
            inner: FakePhysicalSource::new(records),
            fail_at: 2,
            failed: false,
            transferred: continuation_block(b"cde").to_vec(),
        };
        let mut sink = EventSink::default();
        let probe = ProbeResult {
            format_id: BruFormat.id().to_string(),
            confidence: ProbeConfidence::Certain,
            source_requirement: SourceRequirement::PhysicalTapeRecords,
            adapter_state: Vec::new(),
        };

        let report = {
            let mut reader = BruFormat.open_tape_reader(&mut source, &probe).unwrap();
            reader.stream_all(&mut sink).unwrap()
        };

        assert_eq!(report.entries, 2);
        assert_eq!(report.bytes, 8);
        assert_eq!(report.damage_events, 1);
        assert_eq!(report.archive_gaps, 1);
        assert_eq!(sink.data, b"abcdetwo");
        assert_eq!(sink.damages[0].start, 2);
        assert_eq!(sink.damages[0].end, 5);
        assert_eq!(sink.damages[0].status, DamageStatus::ReadError);
        assert_eq!(sink.archive_gaps[0].cause, ArchiveGapCause::ReadError);
        assert_eq!(sink.entries[1].path, "second.bin");
    }

    #[test]
    fn physical_reader_does_not_reuse_stale_bytes_after_buffer_too_small() {
        let records = vec![
            archive_block().to_vec(),
            file_header_block(1, "first.bin", 5, b"ab").to_vec(),
            vec![0; BRU_BLOCK_SIZE],
            file_header_block(2, "second.bin", 3, b"two").to_vec(),
        ];
        let mut source = AdvancingBufferTooSmallSource {
            inner: FakePhysicalSource::new(records),
            fail_at: 2,
            failed: false,
        };
        let mut sink = EventSink::default();
        let probe = ProbeResult {
            format_id: BruFormat.id().to_string(),
            confidence: ProbeConfidence::Certain,
            source_requirement: SourceRequirement::PhysicalTapeRecords,
            adapter_state: Vec::new(),
        };

        let report = {
            let mut reader = BruFormat.open_tape_reader(&mut source, &probe).unwrap();
            reader.stream_all(&mut sink).unwrap()
        };

        assert_eq!(report.entries, 2);
        assert_eq!(report.bytes, 5);
        assert_eq!(report.damage_events, 1);
        assert_eq!(report.archive_gaps, 1);
        assert_eq!(sink.data, b"abtwo");
        assert_eq!(sink.entries[0].path, "first.bin");
        assert_eq!(sink.entries[1].path, "second.bin");
        assert_eq!(sink.damages[0].status, DamageStatus::ReadError);
        assert_eq!(sink.archive_gaps[0].cause, ArchiveGapCause::ReadError);
    }

    struct FakePhysicalSource {
        records: Vec<Vec<u8>>,
        next_record: usize,
        position: PhysicalTapePosition,
        configured: Vec<BlockSize>,
        locates: Vec<PhysicalTapePosition>,
    }

    impl FakePhysicalSource {
        fn new(records: Vec<Vec<u8>>) -> Self {
            Self {
                records,
                next_record: 0,
                position: PhysicalTapePosition::new(0),
                configured: Vec::new(),
                locates: Vec::new(),
            }
        }
    }

    impl PhysicalTapeSource for FakePhysicalSource {
        fn configure_block_size(&mut self, block_size: BlockSize) -> Result<(), TapeIoError> {
            self.configured.push(block_size);
            Ok(())
        }

        fn locate_physical(
            &mut self,
            position: PhysicalTapePosition,
        ) -> Result<PhysicalTapePosition, TapeIoError> {
            let index = usize::try_from(position.lba).map_err(|_| {
                TapeIoError::OperationFailed(format!(
                    "test position {} does not fit usize",
                    position.lba
                ))
            })?;
            if index > self.records.len() {
                return Err(TapeIoError::OperationFailed(format!(
                    "test position {} is beyond {} records",
                    index,
                    self.records.len()
                )));
            }
            self.locates.push(position);
            self.next_record = index;
            self.position = position;
            Ok(self.position)
        }

        fn space_filemarks(&mut self, _count: i64) -> Result<PhysicalFilemarkSpace, TapeIoError> {
            Ok(PhysicalFilemarkSpace {
                filemarks_spaced: 0,
                position_after: self.position,
                hit_end_of_data: false,
            })
        }

        fn read_record(&mut self, buf: &mut [u8]) -> Result<PhysicalReadOutcome, TapeIoError> {
            let Some(record) = self.records.get(self.next_record) else {
                return Ok(PhysicalReadOutcome::EndOfData {
                    position_after: self.position,
                });
            };
            let actual = record.len();
            if actual > buf.len() {
                self.next_record += 1;
                self.position = PhysicalTapePosition::new(self.next_record as u64);
                return Err(TapeIoError::ReadBufferTooSmall {
                    actual: actual as u32,
                    provided: buf.len() as u32,
                });
            }
            buf[..actual].copy_from_slice(record);
            self.next_record += 1;
            self.position = PhysicalTapePosition::new(self.next_record as u64);
            Ok(PhysicalReadOutcome::Data {
                bytes: actual,
                position_after: self.position,
            })
        }

        fn position(&mut self) -> Result<PhysicalTapePosition, TapeIoError> {
            Ok(self.position)
        }
    }

    struct AdvancingReadErrorSource {
        inner: FakePhysicalSource,
        fail_at: usize,
        failed: bool,
        transferred: Vec<u8>,
    }

    struct AdvancingBufferTooSmallSource {
        inner: FakePhysicalSource,
        fail_at: usize,
        failed: bool,
    }

    impl PhysicalTapeSource for AdvancingBufferTooSmallSource {
        fn configure_block_size(&mut self, block_size: BlockSize) -> Result<(), TapeIoError> {
            self.inner.configure_block_size(block_size)
        }

        fn locate_physical(
            &mut self,
            position: PhysicalTapePosition,
        ) -> Result<PhysicalTapePosition, TapeIoError> {
            self.inner.locate_physical(position)
        }

        fn space_filemarks(&mut self, count: i64) -> Result<PhysicalFilemarkSpace, TapeIoError> {
            self.inner.space_filemarks(count)
        }

        fn read_record(&mut self, buf: &mut [u8]) -> Result<PhysicalReadOutcome, TapeIoError> {
            if !self.failed && self.inner.next_record == self.fail_at {
                self.failed = true;
                self.inner.next_record += 1;
                self.inner.position = PhysicalTapePosition::new(self.inner.next_record as u64);
                return Err(TapeIoError::ReadBufferTooSmall {
                    actual: (buf.len() + 1) as u32,
                    provided: buf.len() as u32,
                });
            }
            self.inner.read_record(buf)
        }

        fn position(&mut self) -> Result<PhysicalTapePosition, TapeIoError> {
            self.inner.position()
        }
    }

    impl PhysicalTapeSource for AdvancingReadErrorSource {
        fn configure_block_size(&mut self, block_size: BlockSize) -> Result<(), TapeIoError> {
            self.inner.configure_block_size(block_size)
        }

        fn locate_physical(
            &mut self,
            position: PhysicalTapePosition,
        ) -> Result<PhysicalTapePosition, TapeIoError> {
            self.inner.locate_physical(position)
        }

        fn space_filemarks(&mut self, count: i64) -> Result<PhysicalFilemarkSpace, TapeIoError> {
            self.inner.space_filemarks(count)
        }

        fn read_record(&mut self, buf: &mut [u8]) -> Result<PhysicalReadOutcome, TapeIoError> {
            if !self.failed && self.inner.next_record == self.fail_at {
                self.failed = true;
                assert!(self.transferred.len() <= buf.len());
                buf[..self.transferred.len()].copy_from_slice(&self.transferred);
                self.inner.next_record += 1;
                self.inner.position = PhysicalTapePosition::new(self.inner.next_record as u64);
                return Err(TapeIoError::CheckCondition(ScsiError::CheckCondition {
                    sense: vec![0x70, 0, 0x03, 0, 0, 0, 0, 0x0a],
                    bytes_transferred: self.transferred.len() as u32,
                }));
            }
            self.inner.read_record(buf)
        }

        fn position(&mut self) -> Result<PhysicalTapePosition, TapeIoError> {
            self.inner.position()
        }
    }

    fn put_ascii(block: &mut [u8; BRU_BLOCK_SIZE], offset: usize, text: &str) {
        block[offset..offset + text.len()].copy_from_slice(text.as_bytes());
    }

    fn put_hex(block: &mut [u8; BRU_BLOCK_SIZE], offset: usize, size: usize, value: u64) {
        put_ascii(block, offset, &format!("{value:0size$x}"));
    }

    fn finalize_block(mut block: [u8; BRU_BLOCK_SIZE]) -> [u8; BRU_BLOCK_SIZE] {
        let checksum = bru_checksum(&block);
        put_ascii(&mut block, CHKSUM_OFFSET, &format!("{checksum:08x}"));
        block
    }

    fn archive_block() -> [u8; BRU_BLOCK_SIZE] {
        let mut block = [0; BRU_BLOCK_SIZE];
        put_hex(&mut block, MAGIC_OFFSET, MAGIC_SIZE, MAGIC_ARCHIVE_HEADER);
        put_hex(&mut block, ARTIME_OFFSET, 8, 0x4DE47D26);
        put_hex(&mut block, BUFSIZE_OFFSET, 8, 1024 * 1024);
        put_hex(&mut block, RELEASE_MAJOR_OFFSET, 4, 17);
        put_hex(&mut block, RELEASE_MINOR_OFFSET, 4, 1);
        put_hex(&mut block, VARIANT_OFFSET, 4, 0);
        put_hex(&mut block, ARCHIVE_ID_LOW_OFFSET, 4, 0x61A8);
        put_ascii(&mut block, LABEL_OFFSET, "TEST");
        finalize_block(block)
    }

    fn unrecognized_block() -> [u8; BRU_BLOCK_SIZE] {
        let mut block = [0; BRU_BLOCK_SIZE];
        put_hex(&mut block, MAGIC_OFFSET, MAGIC_SIZE, 0x9999);
        finalize_block(block)
    }

    fn file_header_block(
        sequence: u64,
        path: &str,
        size: u64,
        inline: &[u8],
    ) -> [u8; BRU_BLOCK_SIZE] {
        let mut block = [0; BRU_BLOCK_SIZE];
        put_ascii(&mut block, FILE_PATH_OFFSET, path);
        put_hex(&mut block, MAGIC_OFFSET, MAGIC_SIZE, MAGIC_FILE_HEADER);
        put_hex(&mut block, FILE_SEQUENCE_OFFSET, 8, sequence);
        put_hex(&mut block, INLINE_DATA_LEN_OFFSET, 4, inline.len() as u64);
        let mode = if path == "dir" {
            S_IFDIR | 0o755
        } else {
            S_IFREG | 0o644
        };
        put_hex(&mut block, ST_MODE_OFFSET, 8, mode);
        put_hex(&mut block, ST_SIZE_OFFSET, 8, size);
        block[INLINE_DATA_OFFSET..INLINE_DATA_OFFSET + inline.len()].copy_from_slice(inline);
        finalize_block(block)
    }

    fn continuation_block(data: &[u8]) -> [u8; BRU_BLOCK_SIZE] {
        let mut block = [0; BRU_BLOCK_SIZE];
        put_hex(&mut block, MAGIC_OFFSET, MAGIC_SIZE, MAGIC_CONTINUATION);
        put_hex(&mut block, CONTINUATION_DLEN_OFFSET, 4, data.len() as u64);
        block[CONTINUATION_DATA_OFFSET..CONTINUATION_DATA_OFFSET + data.len()]
            .copy_from_slice(data);
        finalize_block(block)
    }

    fn archive_terminator_block() -> [u8; BRU_BLOCK_SIZE] {
        let mut block = [0; BRU_BLOCK_SIZE];
        put_hex(
            &mut block,
            MAGIC_OFFSET,
            MAGIC_SIZE,
            MAGIC_ARCHIVE_TERMINATOR,
        );
        finalize_block(block)
    }
}
