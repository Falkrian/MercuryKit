from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath
import struct
from typing import BinaryIO, Iterable
import zlib

from mercurykit.archive import ArchiveContext, ArchiveEntry, ArchiveInfo, ArchiveMatch
from mercurykit.binary import BinaryReader, EndOfStreamError
from mercurykit.progress import NullProgressReporter, ProgressReporter


RECORD_SIZE = 1032
PATH_SIZE = 1024
HEADER_SIZE = 12
ALIGNMENT = 128
COPY_BUFFER_SIZE = 1024 * 1024
FILES_TOC_PATH = "system/files.toc"
FILES_TOC_RECORD_SIZE = 8


@dataclass(frozen=True)
class MirrorOfFateState:
    entries: tuple[ArchiveEntry, ...]


@dataclass(frozen=True)
class MirrorOfFateRecord:
    path: str
    start: int
    end: int


@dataclass(frozen=True)
class MirrorOfFateTocRecord:
    path_hash: int
    file_size: int


@dataclass(frozen=True)
class MirrorOfFateRepackFile:
    source_path: Path
    archive_path: str
    encoded_path: bytes
    payload: bytes | None = None


class MirrorOfFatePackEngine:
    """Reader and writer for Mirror of Fate HD fixed-table ``.pack`` archives."""

    format_name = "Castlevania Lords of Shadow - Mirror of Fate HD Pack Archive"
    max_u32 = 0xFFFFFFFF

    def evaluate(self, path: Path, reader: BinaryReader) -> ArchiveMatch:
        if path.suffix.lower() != ".pack":
            return ArchiveMatch(0.0, self.format_name, reason="File extension is not .pack")
        try:
            self._read_pack(path, reader, validate_padding=True)
        except (OSError, UnicodeDecodeError, ValueError, EndOfStreamError) as exc:
            return ArchiveMatch(0.0, self.format_name, reason=f"Mirror of Fate table validation failed: {exc}")
        return ArchiveMatch(0.99, self.format_name, reason="Mirror of Fate fixed table structure matched")

    def read_manifest(self, path: Path, reader: BinaryReader) -> ArchiveInfo:
        pack_size, records = self._read_pack(path, reader, validate_padding=True)
        entries = tuple(
            ArchiveEntry(
                path=record.path,
                offset=record.start,
                stored_size=record.end - record.start,
                uncompressed_size=record.end - record.start,
                metadata={"table_index": index, "end_offset": record.end},
            )
            for index, record in enumerate(records)
        )
        first_payload_mod = records[0].start % ALIGNMENT if records else None
        return ArchiveInfo(
            self.format_name,
            len(entries),
            {
                "pack_size": pack_size,
                "alignment": ALIGNMENT,
                "first_payload_mod": first_payload_mod,
                "entries": entries,
            },
        )

    def open(self, path: Path) -> ArchiveContext:
        with path.open("rb") as file:
            info = self.read_manifest(path, BinaryReader(file))
        return ArchiveContext(path, self, info, MirrorOfFateState(tuple(info.metadata["entries"])))

    def iter_entries(self, context: ArchiveContext) -> Iterable[ArchiveEntry]:
        state = self._state(context)
        yield from state.entries

    def extract_entry(self, context: ArchiveContext, entry: ArchiveEntry, output_stream: BinaryIO) -> None:
        if not isinstance(entry.offset, int):
            raise ValueError(f"Entry {entry.path or entry.entry_id or '<unnamed>'} does not define an offset")
        if not isinstance(entry.stored_size, int):
            raise ValueError(f"Entry {entry.path or entry.entry_id or '<unnamed>'} does not define a stored size")

        remaining = entry.stored_size
        with context.archive_path.open("rb") as file:
            file.seek(entry.offset)
            while remaining:
                chunk = file.read(min(COPY_BUFFER_SIZE, remaining))
                if not chunk:
                    raise EndOfStreamError(f"Entry {entry.path or entry.entry_id or '<unnamed>'} extends beyond archive data")
                output_stream.write(chunk)
                remaining -= len(chunk)

    def repack(self, input_dir: Path, output_path: Path, options: dict[str, object] | None = None) -> None:
        self.repack_with_progress(input_dir, output_path, options, NullProgressReporter())

    def repack_with_progress(
        self,
        input_dir: Path,
        output_path: Path,
        options: dict[str, object] | None,
        progress: ProgressReporter,
    ) -> None:
        options = options or {}
        input_dir = input_dir.resolve()
        output_path = output_path.resolve()
        if not input_dir.is_dir():
            raise FileNotFoundError(f"Source directory does not exist: {input_dir}")
        self._reject_output_inside_source(input_dir, output_path)
        expected_pack_size = self._validate_repack_options(options)

        repack_files = self._repack_files(input_dir)
        if not repack_files:
            raise ValueError("Mirror of Fate repack source does not contain any files")
        self._check_u32(len(repack_files), "Mirror of Fate file count")
        output_path.parent.mkdir(parents=True, exist_ok=True)

        progress.start(
            f"Repacking {output_path.name}",
            total_items=len(repack_files),
            total_bytes=sum(self._repack_file_size(file) for file in repack_files),
        )
        try:
            with output_path.open("w+b") as output:
                table_end = HEADER_SIZE + len(repack_files) * RECORD_SIZE
                self._check_u32(table_end - 4, "Mirror of Fate table marker")
                output.write(struct.pack("<III", table_end - 4, 0, len(repack_files)))

                offset_positions: list[int] = []
                for repack_file in repack_files:
                    output.write(repack_file.encoded_path.ljust(PATH_SIZE, b"\x00"))
                    offset_positions.append(output.tell())
                    output.write(b"\x00" * 8)

                target_mod = table_end % ALIGNMENT
                for repack_file, offset_position in zip(repack_files, offset_positions):
                    self._pad_to_mod(output, ALIGNMENT, target_mod)
                    start = output.tell()
                    self._write_repack_payload(repack_file, output, progress)
                    end = output.tell()
                    self._check_u32(start, f"Mirror of Fate start offset for {repack_file.archive_path}")
                    self._check_u32(end, f"Mirror of Fate end offset for {repack_file.archive_path}")
                    output.seek(offset_position)
                    output.write(struct.pack("<II", start, end))
                    output.seek(0, 2)
                    progress.advance(items=1, detail=repack_file.archive_path)

                self._pad_to_mod(output, ALIGNMENT, target_mod)
                pack_size = output.tell() - table_end
                self._check_u32(pack_size, "Mirror of Fate pack size")
                if expected_pack_size is not None and expected_pack_size != pack_size:
                    raise ValueError(
                        f"Mirror of Fate option pack_size does not match computed value: "
                        f"expected 0x{expected_pack_size:x}, computed 0x{pack_size:x}"
                    )
                output.seek(4)
                output.write(struct.pack("<I", pack_size))
        finally:
            progress.finish()

    def _read_pack(
        self,
        path: Path,
        reader: BinaryReader,
        *,
        validate_padding: bool,
    ) -> tuple[int, tuple[MirrorOfFateRecord, ...]]:
        file_size = path.stat().st_size
        if file_size < HEADER_SIZE:
            raise ValueError("file is smaller than the Mirror of Fate header")

        table_marker = reader.u32()
        pack_size = reader.u32()
        file_count = reader.u32()
        if file_count == 0:
            raise ValueError("file count is zero")

        table_end = HEADER_SIZE + file_count * RECORD_SIZE
        if table_end > file_size:
            raise ValueError("file table extends beyond the archive")
        if table_marker != table_end - 4:
            raise ValueError("table marker does not match the file count")
        if pack_size != file_size - table_end:
            raise ValueError("pack size does not match the payload area")

        records: list[MirrorOfFateRecord] = []
        previous_end: int | None = None
        first_payload_mod: int | None = None
        for index in range(file_count):
            archive_path = self._decode_table_path(reader.read_exact(PATH_SIZE))
            self._validate_archive_path(archive_path)
            start = reader.u32()
            end = reader.u32()

            if index == 0 and start != table_end:
                raise ValueError("first payload does not start after the table")
            if start > end:
                raise ValueError("payload start is after payload end")
            if end > file_size:
                raise ValueError("payload end extends beyond the archive")
            if previous_end is not None and start < previous_end:
                raise ValueError("payload ranges overlap")
            if first_payload_mod is None:
                first_payload_mod = start % ALIGNMENT
            elif start % ALIGNMENT != first_payload_mod:
                raise ValueError("payload starts do not share the expected alignment")

            records.append(MirrorOfFateRecord(archive_path, start, end))
            previous_end = end

        if validate_padding:
            self._validate_padding(reader, tuple(records), file_size)
        return pack_size, tuple(records)

    def _decode_table_path(self, raw_path: bytes) -> str:
        path_bytes, separator, padding = raw_path.partition(b"\x00")
        if not path_bytes:
            raise ValueError("empty path in file table")
        if separator and any(padding):
            raise ValueError("file table path is not null-padded")
        return path_bytes.decode("utf-8")

    def _validate_padding(
        self,
        reader: BinaryReader,
        records: tuple[MirrorOfFateRecord, ...],
        file_size: int,
    ) -> None:
        for index, record in enumerate(records):
            next_start = records[index + 1].start if index + 1 < len(records) else file_size
            if next_start < record.end:
                raise ValueError("payload padding range is invalid")
            if next_start == record.end:
                continue
            reader.seek(record.end)
            if any(reader.read_exact(next_start - record.end)):
                raise ValueError("payload padding is not zero-filled")

    def _collect_payload_paths(self, input_dir: Path) -> list[str]:
        payload_paths: list[str] = []
        for file in input_dir.rglob("*"):
            if not file.is_file():
                continue
            relative_parts = file.relative_to(input_dir).parts
            if relative_parts and relative_parts[0] == ".mercurykit":
                continue
            archive_path = PurePosixPath(*relative_parts).as_posix()
            self._validate_archive_path(archive_path)
            payload_paths.append(archive_path)

        seen: set[str] = set()
        for archive_path in payload_paths:
            key = archive_path.casefold()
            if key in seen:
                raise ValueError(f"Duplicate Mirror of Fate input path: {archive_path}")
            seen.add(key)
        return sorted(payload_paths)

    def _repack_files(self, input_dir: Path) -> list[MirrorOfFateRepackFile]:
        seen: set[str] = set()
        repack_files: list[MirrorOfFateRepackFile] = []
        for archive_path in self._collect_payload_paths(input_dir):
            self._validate_archive_path(archive_path)
            key = archive_path.casefold()
            if key in seen:
                raise ValueError(f"Duplicate Mirror of Fate input path: {archive_path}")
            seen.add(key)
            repack_files.append(self._repack_file(input_dir, archive_path))
        return self._with_updated_files_toc(repack_files)

    def _repack_file(self, input_dir: Path, archive_path: str) -> MirrorOfFateRepackFile:
        encoded_path = archive_path.encode("utf-8")
        if len(encoded_path) > PATH_SIZE:
            raise ValueError(f"Mirror of Fate path is longer than {PATH_SIZE} bytes: {archive_path}")
        source_path = input_dir / PurePosixPath(archive_path)
        if not source_path.is_file():
            raise FileNotFoundError(f"Mirror of Fate input file is missing: {source_path}")
        return MirrorOfFateRepackFile(source_path, archive_path, encoded_path)

    def _with_updated_files_toc(self, repack_files: list[MirrorOfFateRepackFile]) -> list[MirrorOfFateRepackFile]:
        toc_index = next(
            (index for index, file in enumerate(repack_files) if file.archive_path.casefold() == FILES_TOC_PATH),
            None,
        )
        if toc_index is None:
            return repack_files

        toc_file = repack_files[toc_index]
        records = self._read_files_toc(toc_file.source_path)
        updated_toc = self._build_updated_files_toc(records, repack_files)
        return [
            file if index != toc_index else MirrorOfFateRepackFile(
                file.source_path,
                file.archive_path,
                file.encoded_path,
                updated_toc,
            )
            for index, file in enumerate(repack_files)
        ]

    def _build_updated_files_toc(
        self,
        records: tuple[MirrorOfFateTocRecord, ...],
        repack_files: list[MirrorOfFateRepackFile],
    ) -> bytes:
        self_hash = self._files_toc_path_hash(FILES_TOC_PATH)
        existing_hashes = {record.path_hash for record in records}
        updates: dict[int, int] = {}
        new_candidates: dict[int, tuple[str, int]] = {}
        managed_dirs: set[str] = set()

        for file in repack_files:
            path_hash = self._files_toc_path_hash(file.archive_path)
            if path_hash in existing_hashes:
                managed_dirs.add(self._files_toc_parent(file.archive_path))
                if file.archive_path.casefold() != FILES_TOC_PATH:
                    updates[path_hash] = self._repack_file_size(file)
                continue
            if file.archive_path.casefold() != FILES_TOC_PATH:
                new_candidates[path_hash] = (file.archive_path, self._repack_file_size(file))

        missing_hashes = sorted(
            path_hash
            for path_hash, (archive_path, _) in new_candidates.items()
            if self._files_toc_path_is_managed(archive_path, managed_dirs)
        )
        final_record_count = len(records) + len(missing_hashes) + (0 if self_hash in existing_hashes else 1)
        updates[self_hash] = final_record_count * FILES_TOC_RECORD_SIZE

        rebuilt = bytearray()
        for record in records:
            rebuilt += struct.pack("<II", record.path_hash, updates.get(record.path_hash, record.file_size))
        for path_hash in missing_hashes:
            rebuilt += struct.pack("<II", path_hash, new_candidates[path_hash][1])
        if self_hash not in existing_hashes:
            rebuilt += struct.pack("<II", self_hash, updates[self_hash])
        return bytes(rebuilt)

    def _read_files_toc(self, path: Path) -> tuple[MirrorOfFateTocRecord, ...]:
        data = path.read_bytes()
        if len(data) % FILES_TOC_RECORD_SIZE:
            raise ValueError(f"Mirror of Fate files.toc size is not a multiple of {FILES_TOC_RECORD_SIZE} bytes")
        return tuple(
            MirrorOfFateTocRecord(path_hash, file_size)
            for path_hash, file_size in struct.iter_unpack("<II", data)
        )

    def _files_toc_path_hash(self, archive_path: str) -> int:
        return (~zlib.crc32(archive_path.encode("utf-8"))) & self.max_u32

    def _files_toc_parent(self, archive_path: str) -> str:
        return PurePosixPath(archive_path).parent.as_posix()

    def _files_toc_path_is_managed(self, archive_path: str, managed_dirs: set[str]) -> bool:
        parent = self._files_toc_parent(archive_path)
        if parent == ".":
            return "." in managed_dirs
        current = PurePosixPath(parent)
        while True:
            if current.as_posix() in managed_dirs:
                return True
            if current.parent == current or current.parent.as_posix() == ".":
                return False
            current = current.parent

    def _repack_file_size(self, repack_file: MirrorOfFateRepackFile) -> int:
        if repack_file.payload is not None:
            return len(repack_file.payload)
        return repack_file.source_path.stat().st_size

    def _write_repack_payload(
        self,
        repack_file: MirrorOfFateRepackFile,
        output: BinaryIO,
        progress: ProgressReporter,
    ) -> None:
        if repack_file.payload is not None:
            output.write(repack_file.payload)
            progress.advance(bytes_count=len(repack_file.payload))
            return
        with repack_file.source_path.open("rb") as source:
            self._copy_with_progress(source, output, progress)

    def _validate_archive_path(self, archive_path: str) -> None:
        if "\\" in archive_path:
            raise ValueError(f"Mirror of Fate paths must use forward slashes: {archive_path}")
        pure = PurePosixPath(archive_path)
        if pure.is_absolute():
            raise ValueError(f"Mirror of Fate path is absolute: {archive_path}")
        if any(part in {"", ".", ".."} for part in pure.parts):
            raise ValueError(f"Mirror of Fate path is unsafe: {archive_path}")
        if len(archive_path.encode("utf-8")) > PATH_SIZE:
            raise ValueError(f"Mirror of Fate path is longer than {PATH_SIZE} bytes: {archive_path}")

    def _pad_to_mod(self, output: BinaryIO, alignment: int, target_mod: int) -> None:
        padding = (target_mod - (output.tell() % alignment)) % alignment
        if padding:
            output.write(b"\x00" * padding)

    def _copy_with_progress(self, source: BinaryIO, output: BinaryIO, progress: ProgressReporter) -> None:
        while chunk := source.read(COPY_BUFFER_SIZE):
            output.write(chunk)
            progress.advance(bytes_count=len(chunk))

    def _optional_int_option(self, options: dict[str, object], key: str) -> int | None:
        if key not in options:
            return None
        value = options[key]
        if isinstance(value, bool):
            raise ValueError(f"Mirror of Fate option {key} must be an integer")
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            try:
                return int(value, 0)
            except ValueError as exc:
                raise ValueError(f"Mirror of Fate option {key} must be an integer") from exc
        raise ValueError(f"Mirror of Fate option {key} must be an integer")

    def _validate_repack_options(self, options: dict[str, object]) -> int | None:
        if "unknown_header" in options:
            raise ValueError("Mirror of Fate option unknown_header is no longer supported; pack_size is computed during repack")
        unsupported = sorted(key for key in options if key != "pack_size")
        if unsupported:
            raise ValueError(f"Mirror of Fate option is not supported: {unsupported[0]}")
        return self._optional_int_option(options, "pack_size")

    def _check_u32(self, value: int, label: str) -> None:
        if not 0 <= value <= self.max_u32:
            raise ValueError(f"{label} must fit in u32")

    def _reject_output_inside_source(self, input_dir: Path, output_path: Path) -> None:
        try:
            output_path.relative_to(input_dir)
        except ValueError:
            return
        raise ValueError("Mirror of Fate output archive cannot be written inside the source directory")

    def _state(self, context: ArchiveContext) -> MirrorOfFateState:
        if isinstance(context.state, MirrorOfFateState):
            return context.state
        return MirrorOfFateState(tuple(context.info.metadata["entries"]))
