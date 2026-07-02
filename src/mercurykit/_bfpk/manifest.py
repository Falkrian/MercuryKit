from __future__ import annotations

from pathlib import PurePosixPath
import struct
import zlib

from mercurykit.binary import BinaryReader, EndOfStreamError
from mercurykit.archive import ArchiveEntry, UnsupportedOperation

from .models import BfpkChunkTable, BfpkFileRecord, BfpkHeader


class BfpkManifestMixin:
    """Manifest parser and entry normalizer for supported BFPK table layouts."""

    def _read_header(self, reader: BinaryReader) -> BfpkHeader:
        reader.seek(0)
        magic = reader.read_exact(4)
        if magic != self.archive_magic:
            raise ValueError("Magic did not match BFPK")

        archive_version = reader.u32()
        if self._has_chunked_header(archive_version):
            file_chunk_size = reader.u32()
            file_count = reader.u32()
            table_offset = 16
        elif self._has_encrypted_picture_table(archive_version):
            file_chunk_size = None
            file_count = struct.unpack("<I", self._read_spacelords_d01_encrypted(reader, 4))[0]
            table_offset = 12
        else:
            file_chunk_size = None
            file_count = reader.u32()
            table_offset = 12
        return BfpkHeader(archive_version, file_count, file_chunk_size, table_offset)

    def _read_spacelords_d01_encrypted(self, reader: BinaryReader, size: int) -> bytes:
        """Read bytes from the offset-keyed table cipher used by encrypted picture archives."""

        start_offset = reader.tell()
        return self._crypt_spacelords_d01_table(reader.read_exact(size), start_offset)

    def _read_encrypted_picture_u32(self, reader: BinaryReader) -> int:
        return struct.unpack("<I", self._read_spacelords_d01_encrypted(reader, 4))[0]

    def _read_encrypted_picture_u64(self, reader: BinaryReader) -> int:
        return struct.unpack("<Q", self._read_spacelords_d01_encrypted(reader, 8))[0]

    def _reader_size(self, reader: BinaryReader) -> int:
        old_position = reader.tell()
        try:
            reader.seek(0, 2)
            return reader.tell()
        finally:
            reader.seek(old_position)

    def _select_table_layout(
        self,
        reader: BinaryReader,
        header: BfpkHeader,
        file_size: int,
    ) -> tuple[str, tuple[BfpkFileRecord, ...]]:
        candidates: list[tuple[str, tuple[BfpkFileRecord, ...]]] = []
        for layout in self._candidate_layouts(header.archive_version):
            try:
                records = self._read_records_for_layout(reader, header, file_size, layout)
            except (EndOfStreamError, UnicodeDecodeError, ValueError):
                continue
            candidates.append((layout, records))

        if not candidates:
            raise UnsupportedOperation(f"BFPK archive version 0x{header.archive_version:x} is not supported")

        for layout, records in candidates:
            if layout == self.blades_of_fire_layout and self._records_have_blades_of_fire_markers(records):
                return layout, records
        return candidates[0]

    def _candidate_layouts(self, archive_version: int) -> tuple[str, ...]:
        layouts: list[str] = []
        if self._supports_legacy_layout(archive_version):
            layouts.append(self.legacy_layout)
        if self._supports_blades_of_fire_layout(archive_version):
            layouts.append(self.blades_of_fire_layout)
        if self._supports_spacelords_layout(archive_version):
            layouts.append(self.spacelords_layout)
        return tuple(layouts)

    def _read_records_for_layout(
        self,
        reader: BinaryReader,
        header: BfpkHeader,
        file_size: int,
        layout: str,
    ) -> tuple[BfpkFileRecord, ...]:
        if self._has_encrypted_picture_table(header.archive_version):
            expected_layout = self._encrypted_picture_layout(header.archive_version)
            if layout != expected_layout:
                raise ValueError("BFPK encrypted picture archive does not use this table layout")
            return self._read_encrypted_picture_file_records(reader, header, file_size, layout)
        return self._read_file_records(reader, header, file_size, layout)

    def _read_file_records(
        self,
        reader: BinaryReader,
        header: BfpkHeader,
        file_size: int,
        layout: str,
    ) -> tuple[BfpkFileRecord, ...]:
        if header.file_count > self.max_u32:
            raise ValueError("BFPK file count is too large")

        reader.seek(header.table_offset)
        records = []
        for _ in range(header.file_count):
            records.append(self._read_file_record(reader, layout))
        self._validate_records(records, header, file_size, layout)
        return tuple(records)

    def _read_encrypted_picture_file_records(
        self,
        reader: BinaryReader,
        header: BfpkHeader,
        file_size: int,
        layout: str,
    ) -> tuple[BfpkFileRecord, ...]:
        if header.file_count > self.max_u32:
            raise ValueError("BFPK file count is too large")

        reader.seek(header.table_offset)
        records = []
        for _ in range(header.file_count):
            records.append(self._read_encrypted_picture_file_record(reader))
        self._validate_records(records, header, file_size, layout)
        return tuple(records)

    def _read_encrypted_picture_file_record(self, reader: BinaryReader) -> BfpkFileRecord:
        """Read a `0xD01`/`0x901` row; the opaque hash field is preserved but not validated."""

        file_name_length = self._read_encrypted_picture_u32(reader)
        if file_name_length == 0 or file_name_length > 4096:
            raise ValueError("BFPK file name length is invalid")
        file_name = self._read_spacelords_d01_encrypted(reader, file_name_length).decode("utf-8")
        if not self._is_safe_archive_path(file_name):
            raise ValueError(f"BFPK file path is unsafe: {file_name!r}")

        file_uncompressed_size = self._read_encrypted_picture_u32(reader)
        file_offset = self._read_encrypted_picture_u64(reader)
        opaque_hash = self._read_encrypted_picture_u32(reader)
        aux0 = self._read_encrypted_picture_u32(reader)
        stored_size = self._read_encrypted_picture_u32(reader)
        return BfpkFileRecord(file_name, file_uncompressed_size, file_offset, opaque_hash, aux0, stored_size)

    def _read_file_record(self, reader: BinaryReader, layout: str) -> BfpkFileRecord:
        file_name_length = reader.u32()
        if file_name_length == 0 or file_name_length > 4096:
            raise ValueError("BFPK file name length is invalid")
        file_name = reader.read_string(file_name_length)
        if not self._is_safe_archive_path(file_name):
            raise ValueError(f"BFPK file path is unsafe: {file_name!r}")

        file_uncompressed_size = reader.u32()
        file_offset = reader.u64()
        if layout == self.legacy_layout:
            return BfpkFileRecord(file_name, file_uncompressed_size, file_offset)
        if layout == self.spacelords_layout:
            return BfpkFileRecord(
                file_name,
                file_uncompressed_size,
                file_offset,
                table_hash=reader.u32(),
                aux0=reader.u32(),
            )

        return BfpkFileRecord(
            file_name,
            file_uncompressed_size,
            file_offset,
            table_hash=reader.u32(),
            aux0=reader.u32(),
            aux1=reader.u32(),
        )

    def _validate_records(
        self,
        records: list[BfpkFileRecord],
        header: BfpkHeader,
        file_size: int,
        layout: str,
    ) -> None:
        if not records:
            return

        table_end = self._table_end_offset(records, header, layout)

        previous_offset = -1
        for record in records:
            if record.offset < table_end or record.offset > file_size:
                raise ValueError("BFPK payload offset is outside archive bounds")
            if record.uncompressed_size > self.max_u32:
                raise ValueError("BFPK uncompressed size is too large")
            previous_offset = self._validate_layout_record_metadata(header, layout, record, previous_offset)

        self._validate_payload_bounds(records, header, file_size, layout)

    def _table_end_offset(self, records: list[BfpkFileRecord], header: BfpkHeader, layout: str) -> int:
        row_size = sum(4 + len(record.path.encode("utf-8")) + 4 + 8 for record in records)
        if layout == self.blades_of_fire_layout:
            row_size += 12 * len(records)
        elif layout == self.spacelords_layout:
            row_size += (12 if header.archive_version == self.spacelords_d01_archive_version else 8) * len(records)
        return header.table_offset + row_size

    def _validate_layout_record_metadata(
        self,
        header: BfpkHeader,
        layout: str,
        record: BfpkFileRecord,
        previous_offset: int,
    ) -> int:
        if layout == self.blades_of_fire_layout:
            if record.aux0 not in {0, None}:
                raise ValueError("BFPK Blades of Fire aux0 field is not supported")
            if header.archive_version == self.blades_of_fire_pics_archive_version:
                self._validate_encrypted_picture_record_metadata(record, "BFPK Blades of Fire 0x901")
                if record.offset < previous_offset:
                    raise ValueError("BFPK Blades of Fire payload offsets are not monotonic")
                return record.offset

        if layout == self.spacelords_layout:
            if record.aux0 != 0:
                raise ValueError("BFPK Spacelords aux0 field is not supported")
            if record.table_hash is None:
                raise ValueError("BFPK Spacelords table metadata is missing")
            if header.archive_version == self.spacelords_d01_archive_version:
                self._validate_encrypted_picture_record_metadata(record, "BFPK Spacelords 0xD01")
            if record.offset < previous_offset:
                raise ValueError("BFPK Spacelords payload offsets are not monotonic")
            return record.offset

        return previous_offset

    def _validate_encrypted_picture_record_metadata(self, record: BfpkFileRecord, label: str) -> None:
        if record.table_hash is None:
            raise ValueError(f"{label} table metadata is missing")
        if record.aux1 is None:
            raise ValueError(f"{label} stored size is missing")

    def _validate_payload_bounds(
        self,
        records: list[BfpkFileRecord],
        header: BfpkHeader,
        file_size: int,
        layout: str,
    ) -> None:
        if layout == self.blades_of_fire_layout and header.archive_version in {0x100, 0x300}:
            self._validate_raw_payload_bounds(records, file_size, "BFPK raw")
        elif layout == self.spacelords_layout and header.archive_version == 0x500:
            self._validate_raw_payload_bounds(records, file_size, "BFPK Spacelords raw")
        elif self._has_encrypted_picture_table(header.archive_version):
            self._validate_encrypted_picture_bounds(records, header, file_size)

    def _validate_raw_payload_bounds(self, records: list[BfpkFileRecord], file_size: int, label: str) -> None:
        for record in records:
            if record.offset + record.uncompressed_size > file_size:
                raise ValueError(f"{label} payload extends beyond archive data")

    def _validate_encrypted_picture_bounds(
        self,
        records: list[BfpkFileRecord],
        header: BfpkHeader,
        file_size: int,
    ) -> None:
        label = self._encrypted_picture_label(header.archive_version)
        minimum_header_size = self._encrypted_picture_minimum_record_header_size(header.archive_version)
        for record in records:
            if record.offset % self.encrypted_picture_alignment != 0:
                raise ValueError(f"{label} payload is not aligned")
            if record.aux1 is None or record.offset + minimum_header_size + record.aux1 > file_size:
                raise ValueError(f"{label} payload extends beyond archive data")

    def _encrypted_picture_label(self, archive_version: int) -> str:
        if archive_version == self.blades_of_fire_pics_archive_version:
            return "BFPK Blades of Fire 0x901"
        if archive_version == self.spacelords_d01_archive_version:
            return "BFPK Spacelords 0xD01"
        raise ValueError(f"BFPK archive version 0x{archive_version:x} is not an encrypted picture archive")

    def _encrypted_picture_minimum_record_header_size(self, archive_version: int) -> int:
        return 10 if archive_version == self.blades_of_fire_pics_archive_version else 6

    def _records_have_blades_of_fire_markers(self, records: tuple[BfpkFileRecord, ...]) -> bool:
        return any(record.table_hash is not None or record.aux0 is not None or record.aux1 is not None for record in records)

    def _is_safe_archive_path(self, path: str) -> bool:
        if not path or "\x00" in path or "\\" in path:
            return False
        pure = PurePosixPath(path)
        return not pure.is_absolute() and ".." not in pure.parts

    def _validate_sample_payloads(
        self,
        reader: BinaryReader,
        header: BfpkHeader,
        layout: str,
        records: tuple[BfpkFileRecord, ...],
        file_size: int,
    ) -> None:
        if not records:
            return
        sample_indexes = sorted({0, len(records) // 2, len(records) - 1})
        for index in sample_indexes:
            entry = self._entry_for_version(reader, header.archive_version, header.file_chunk_size, layout, records[index])
            if layout in {self.blades_of_fire_layout, self.spacelords_layout}:
                self._validate_hashed_payload(reader, entry)
            if layout == self.spacelords_layout and header.archive_version == 0x500:
                self._validate_spacelords_raw_padding(reader, records, index, file_size)
            if layout == self.spacelords_layout and header.archive_version == self.spacelords_d01_archive_version:
                self._validate_encrypted_picture_padding(reader, entry, records, index, file_size)
            if layout == self.blades_of_fire_layout and header.archive_version == self.blades_of_fire_pics_archive_version:
                self._validate_encrypted_picture_padding(reader, entry, records, index, file_size)

    def _validate_encrypted_picture_padding(
        self,
        reader: BinaryReader,
        entry: ArchiveEntry,
        records: tuple[BfpkFileRecord, ...],
        index: int,
        file_size: int,
    ) -> None:
        """Validate zero padding using the actual parsed record header size.

        GIF/TGA records may embed the first payload byte in the flags word, so the
        payload starts one byte earlier than the nominal record header.
        """

        record = records[index]
        if record.aux1 is None:
            raise ValueError("BFPK encrypted picture stored size is missing")
        record_header_size = entry.metadata.get("record_header_size")
        if not isinstance(record_header_size, int):
            raise ValueError("BFPK encrypted picture record header size is missing")
        payload_end = record.offset + record_header_size + record.aux1
        next_offset = records[index + 1].offset if index + 1 < len(records) else file_size
        if payload_end > next_offset:
            raise ValueError("BFPK encrypted picture payload overlaps the next entry")
        padding_size = min(next_offset - payload_end, self.spacelords_default_trailing_padding)
        if padding_size:
            old_position = reader.tell()
            try:
                reader.seek(payload_end)
                padding = reader.read_exact(padding_size)
            finally:
                reader.seek(old_position)
            if any(padding):
                raise ValueError("BFPK encrypted picture padding is not zero-filled")

    def _validate_spacelords_raw_padding(
        self,
        reader: BinaryReader,
        records: tuple[BfpkFileRecord, ...],
        index: int,
        file_size: int,
    ) -> None:
        record = records[index]
        if record.offset % self.spacelords_default_trailing_padding != 0:
            raise ValueError("BFPK Spacelords raw payload is not aligned")

        payload_end = record.offset + record.uncompressed_size
        next_offset = records[index + 1].offset if index + 1 < len(records) else file_size
        if payload_end > next_offset:
            raise ValueError("BFPK Spacelords raw payload overlaps the next entry")
        padding_size = min(next_offset - payload_end, self.spacelords_default_trailing_padding)
        if padding_size:
            old_position = reader.tell()
            try:
                reader.seek(payload_end)
                padding = reader.read_exact(padding_size)
            finally:
                reader.seek(old_position)
            if any(padding):
                raise ValueError("BFPK Spacelords raw padding is not zero-filled")

    def _validate_hashed_payload(self, reader: BinaryReader, entry: ArchiveEntry) -> None:
        expected_crc = entry.metadata.get("table_hash")
        if expected_crc is None or entry.offset is None or entry.uncompressed_size is None:
            return

        old_position = reader.tell()
        try:
            if entry.metadata.get("chunked"):
                crc = self._crc32_lz4_chunks(reader, entry)
            else:
                reader.seek(entry.offset)
                payload = reader.read_exact(entry.uncompressed_size)
                crc = zlib.crc32(payload) & self.max_u32
        finally:
            reader.seek(old_position)

        if crc != expected_crc:
            layout = entry.metadata.get("table_format")
            if layout == self.spacelords_layout:
                raise ValueError("BFPK Spacelords table CRC did not match")
            raise ValueError("BFPK Blades of Fire table CRC did not match")

    def _entry_for_version(
        self,
        reader: BinaryReader,
        archive_version: int,
        file_chunk_size: int | None,
        layout: str,
        record: BfpkFileRecord,
    ) -> ArchiveEntry:
        if layout == self.spacelords_layout:
            if archive_version == self.spacelords_d01_archive_version:
                return self._spacelords_d01_entry(reader, record)
            if archive_version == 0x500:
                return self._spacelords_raw_entry(archive_version, record)
            if archive_version == 0x502:
                if file_chunk_size is None:
                    raise ValueError("BFPK Spacelords 0x502 archive does not define a file chunk size")
                return self._spacelords_502_entry(reader, record, file_chunk_size)
            raise UnsupportedOperation(f"BFPK Spacelords archive version 0x{archive_version:x} is not supported")

        if layout == self.blades_of_fire_layout:
            if archive_version == self.blades_of_fire_pics_archive_version:
                return self._blades_of_fire_pics_entry(reader, record)
            if archive_version in {0x100, 0x300}:
                return self._blades_of_fire_raw_entry(archive_version, record)
            if archive_version == 0x102:
                if file_chunk_size is None:
                    raise ValueError("BFPK 0x102 archive does not define a file chunk size")
                return self._blades_of_fire_102_entry(reader, record, file_chunk_size)
            raise UnsupportedOperation(f"BFPK Blades of Fire archive version 0x{archive_version:x} is not supported")

        if archive_version == 0x100:
            return self._entry_for_100(record)
        if archive_version == 0x101:
            return self._entry_for_101(reader, record)
        if archive_version == 0x102:
            if file_chunk_size is None:
                raise ValueError("BFPK 0x102 archive does not define a file chunk size")
            return self._entry_for_102(reader, record, file_chunk_size)
        raise UnsupportedOperation(f"BFPK archive version 0x{archive_version:x} is not supported")

    def _entry_for_100(self, record: BfpkFileRecord) -> ArchiveEntry:
        return ArchiveEntry(
            path=record.path,
            offset=record.offset,
            uncompressed_size=record.uncompressed_size,
            stored_size=record.uncompressed_size,
            metadata={"compressed": False, "archive_version": 0x100, "table_format": self.legacy_layout},
        )

    def _entry_for_101(self, reader: BinaryReader, record: BfpkFileRecord) -> ArchiveEntry:
        old_position = reader.tell()
        reader.seek(record.offset)
        file_compressed_size = reader.u32()
        reader.seek(old_position)

        return ArchiveEntry(
            path=record.path,
            offset=record.offset + 4,
            uncompressed_size=record.uncompressed_size,
            compressed_size=file_compressed_size,
            stored_size=4 + file_compressed_size,
            compression="zlib",
            metadata={"compressed": True, "chunked": False, "archive_version": 0x101, "table_format": self.legacy_layout},
        )

    def _entry_for_102(self, reader: BinaryReader, record: BfpkFileRecord, file_chunk_size: int) -> ArchiveEntry:
        old_position = reader.tell()
        chunk_table = self._read_chunk_table(reader, record.offset, record.uncompressed_size, file_chunk_size)
        reader.seek(old_position)

        return ArchiveEntry(
            path=record.path,
            offset=record.offset,
            uncompressed_size=record.uncompressed_size,
            compressed_size=sum(chunk_table.chunk_compressed_sizes),
            stored_size=4 + chunk_table.stored_block_size,
            compression="zlib",
            metadata={
                "compressed": True,
                "chunked": True,
                "archive_version": 0x102,
                "table_format": self.legacy_layout,
                "file_chunk_size": file_chunk_size,
                "chunk_offsets": chunk_table.chunk_offsets,
                "chunk_compressed_sizes": chunk_table.chunk_compressed_sizes,
                "chunk_uncompressed_sizes": chunk_table.chunk_uncompressed_sizes,
            },
        )

    def _blades_of_fire_raw_entry(self, archive_version: int, record: BfpkFileRecord) -> ArchiveEntry:
        return ArchiveEntry(
            path=record.path,
            offset=record.offset,
            uncompressed_size=record.uncompressed_size,
            stored_size=record.uncompressed_size,
            metadata={
                "compressed": False,
                "archive_version": archive_version,
                "table_format": self.blades_of_fire_layout,
                "table_hash": record.table_hash,
                "aux0": record.aux0,
                "aux1": record.aux1,
            },
        )

    def _blades_of_fire_102_entry(
        self,
        reader: BinaryReader,
        record: BfpkFileRecord,
        file_chunk_size: int,
    ) -> ArchiveEntry:
        old_position = reader.tell()
        chunk_table = self._read_blades_of_fire_chunk_table(
            reader,
            record.offset,
            record.uncompressed_size,
            file_chunk_size,
            record.aux1,
        )
        reader.seek(old_position)

        return ArchiveEntry(
            path=record.path,
            offset=record.offset,
            uncompressed_size=record.uncompressed_size,
            compressed_size=sum(chunk_table.chunk_compressed_sizes),
            stored_size=chunk_table.stored_block_size,
            compression="lz4-block",
            metadata={
                "compressed": True,
                "chunked": True,
                "archive_version": 0x102,
                "table_format": self.blades_of_fire_layout,
                "file_chunk_size": file_chunk_size,
                "chunk_offsets": chunk_table.chunk_offsets,
                "chunk_compressed_sizes": chunk_table.chunk_compressed_sizes,
                "chunk_uncompressed_sizes": chunk_table.chunk_uncompressed_sizes,
                "chunk_hashes": chunk_table.chunk_hashes,
                "block_flag": chunk_table.block_flag,
                "table_hash": record.table_hash,
                "aux0": record.aux0,
                "aux1": record.aux1,
            },
        )

    def _blades_of_fire_pics_entry(self, reader: BinaryReader, record: BfpkFileRecord) -> ArchiveEntry:
        """Build an entry for Blades of Fire `Pics.packed` records (`0x901`)."""

        if record.aux1 is None:
            raise ValueError("BFPK Blades of Fire 0x901 stored size is missing")

        old_position = reader.tell()
        try:
            reader.seek(record.offset)
            stored_size = reader.u32()
            zero_field = reader.u32()
            flags = reader.u16()
            probe = reader.read_exact(min(max(record.aux1, 6), 18))
        finally:
            reader.seek(old_position)

        if stored_size != record.aux1:
            raise ValueError("BFPK Blades of Fire 0x901 stored size does not match the table")
        if zero_field != 0:
            raise ValueError("BFPK Blades of Fire 0x901 record zero field is not supported")

        payload_header_size = self._blades_of_fire_pics_payload_header_size(record.path, flags, probe)
        metadata = {
            "compressed": False,
            "archive_version": self.blades_of_fire_pics_archive_version,
            "table_format": self.blades_of_fire_layout,
            "record_offset": record.offset,
            "record_header_size": payload_header_size,
            "declared_size": record.uncompressed_size,
            "opaque_hash": record.table_hash,
            "aux0": record.aux0,
        }
        if self._blades_of_fire_pics_is_packed_jpeg(record.path):
            metadata.update(
                {
                    "packed_format": "blades_of_fire_jpeg",
                    "restored": False,
                    "embedded_first_payload_byte": payload_header_size == 9,
                }
            )
        return ArchiveEntry(
            path=record.path,
            offset=record.offset + payload_header_size,
            uncompressed_size=record.aux1,
            stored_size=record.aux1,
            flags=flags,
            metadata=metadata,
        )

    def _blades_of_fire_pics_payload_header_size(self, path: str, flags: int, probe: bytes) -> int:
        suffix = PurePosixPath(path).suffix.lower()
        first_flag_payload_byte = bytes([(flags >> 8) & 0xFF])
        payload_from_9 = first_flag_payload_byte + probe
        if suffix == ".gif" and payload_from_9.startswith((b"GIF87a", b"GIF89a")):
            return 9
        if suffix in {".jpg", ".jpeg"} and payload_from_9.startswith(b"\xFF\xD8"):
            return 9
        return 10

    def _blades_of_fire_pics_is_packed_jpeg(self, path: str) -> bool:
        return PurePosixPath(path).suffix.lower() in {".jpg", ".jpeg"}

    def _spacelords_raw_entry(self, archive_version: int, record: BfpkFileRecord) -> ArchiveEntry:
        return ArchiveEntry(
            path=record.path,
            offset=record.offset,
            uncompressed_size=record.uncompressed_size,
            stored_size=record.uncompressed_size,
            metadata={
                "compressed": False,
                "archive_version": archive_version,
                "table_format": self.spacelords_layout,
                "table_hash": record.table_hash,
                "aux0": record.aux0,
            },
        )

    def _spacelords_d01_entry(self, reader: BinaryReader, record: BfpkFileRecord) -> ArchiveEntry:
        """Build an entry for Spacelords encrypted picture records (`0xD01`)."""

        if record.aux1 is None:
            raise ValueError("BFPK Spacelords 0xD01 stored size is missing")

        old_position = reader.tell()
        try:
            reader.seek(record.offset)
            stored_size = reader.u32()
            flags = reader.u16()
            probe = reader.read_exact(min(max(record.aux1, 6), 18))
        finally:
            reader.seek(old_position)

        if stored_size != record.aux1:
            raise ValueError("BFPK Spacelords 0xD01 stored size does not match the table")

        payload_header_size = self._spacelords_d01_payload_header_size(record.path, flags, probe)
        return ArchiveEntry(
            path=record.path,
            offset=record.offset + payload_header_size,
            uncompressed_size=record.aux1,
            stored_size=record.aux1,
            flags=flags,
            metadata={
                "compressed": False,
                "archive_version": self.spacelords_d01_archive_version,
                "table_format": self.spacelords_layout,
                "record_offset": record.offset,
                "record_header_size": payload_header_size,
                "declared_size": record.uncompressed_size,
                "opaque_hash": record.table_hash,
                "aux0": record.aux0,
            },
        )

    def _spacelords_d01_payload_header_size(self, path: str, flags: int, probe: bytes) -> int:
        suffix = PurePosixPath(path).suffix.lower()
        first_flag_payload_byte = bytes([(flags >> 8) & 0xFF])
        payload_from_5 = first_flag_payload_byte + probe
        if suffix == ".gif" and payload_from_5.startswith((b"GIF87a", b"GIF89a")):
            return 5
        if suffix == ".tga" and self._looks_like_tga_header(payload_from_5):
            return 5
        return 6

    def _looks_like_tga_header(self, header: bytes) -> bool:
        if len(header) < 18:
            return False
        color_map_type = header[1]
        image_type = header[2]
        return color_map_type in {0, 1} and image_type in {1, 2, 3, 9, 10, 11}

    def _spacelords_502_entry(
        self,
        reader: BinaryReader,
        record: BfpkFileRecord,
        file_chunk_size: int,
    ) -> ArchiveEntry:
        old_position = reader.tell()
        chunk_table = self._read_spacelords_chunk_table(
            reader,
            record.offset,
            record.uncompressed_size,
            file_chunk_size,
        )
        reader.seek(old_position)

        return ArchiveEntry(
            path=record.path,
            offset=record.offset,
            uncompressed_size=record.uncompressed_size,
            compressed_size=sum(chunk_table.chunk_compressed_sizes),
            stored_size=4 + chunk_table.stored_block_size,
            compression="lz4-block",
            metadata={
                "compressed": True,
                "chunked": True,
                "archive_version": 0x502,
                "table_format": self.spacelords_layout,
                "file_chunk_size": file_chunk_size,
                "chunk_offsets": chunk_table.chunk_offsets,
                "chunk_compressed_sizes": chunk_table.chunk_compressed_sizes,
                "chunk_uncompressed_sizes": chunk_table.chunk_uncompressed_sizes,
                "chunk_hashes": chunk_table.chunk_hashes,
                "table_hash": record.table_hash,
                "aux0": record.aux0,
            },
        )

    def _read_chunk_table(
        self,
        reader: BinaryReader,
        file_offset: int,
        file_uncompressed_size: int,
        file_chunk_size: int,
    ) -> BfpkChunkTable:
        return self._read_compressed_chunk_table(
            reader,
            file_offset,
            file_uncompressed_size,
            file_chunk_size,
            label="BFPK 0x102",
        )

    def _read_blades_of_fire_chunk_table(
        self,
        reader: BinaryReader,
        file_offset: int,
        file_uncompressed_size: int,
        file_chunk_size: int,
        expected_stored_block_size: int | None,
    ) -> BfpkChunkTable:
        return self._read_compressed_chunk_table(
            reader,
            file_offset,
            file_uncompressed_size,
            file_chunk_size,
            label="BFPK Blades of Fire",
            has_chunk_hashes=True,
            has_block_flag=True,
            stored_size_includes_header=True,
            expected_stored_block_size=expected_stored_block_size,
        )

    def _read_spacelords_chunk_table(
        self,
        reader: BinaryReader,
        file_offset: int,
        file_uncompressed_size: int,
        file_chunk_size: int,
    ) -> BfpkChunkTable:
        return self._read_compressed_chunk_table(
            reader,
            file_offset,
            file_uncompressed_size,
            file_chunk_size,
            label="BFPK Spacelords",
            has_chunk_hashes=True,
        )

    def _read_compressed_chunk_table(
        self,
        reader: BinaryReader,
        file_offset: int,
        file_uncompressed_size: int,
        file_chunk_size: int,
        *,
        label: str,
        has_chunk_hashes: bool = False,
        has_block_flag: bool = False,
        stored_size_includes_header: bool = False,
        expected_stored_block_size: int | None = None,
    ) -> BfpkChunkTable:
        """Read the common BFPK chunk table shape used by zlib and LZ4 variants."""

        reader.seek(file_offset)
        stored_block_size = reader.u32()
        if expected_stored_block_size is not None and stored_block_size != expected_stored_block_size:
            raise ValueError(f"{label} stored block size does not match the table")

        block_flag = reader.u32() if has_block_flag else None
        consumed = 4 if stored_size_includes_header else 0
        if has_block_flag:
            consumed += 4
        remaining_uncompressed = file_uncompressed_size
        chunk_offsets: list[int] = []
        chunk_compressed_sizes: list[int] = []
        chunk_uncompressed_sizes: list[int] = []
        chunk_hashes: list[int] = []
        chunk_header_size = 8 if has_chunk_hashes else 4

        while consumed < stored_block_size:
            if remaining_uncompressed <= 0:
                raise ValueError(f"{label} chunk table has more chunks than the declared uncompressed size")
            if stored_block_size - consumed < chunk_header_size:
                raise ValueError(f"{label} chunk table ended inside a chunk header")
            chunk_compressed_size = reader.u32()
            if has_chunk_hashes:
                chunk_hashes.append(reader.u32())
            consumed += chunk_header_size
            if chunk_compressed_size > stored_block_size - consumed:
                raise ValueError(f"{label} chunk payload extends beyond the stored block")

            expected_uncompressed_size = min(file_chunk_size, remaining_uncompressed)
            chunk_offsets.append(reader.tell())
            chunk_compressed_sizes.append(chunk_compressed_size)
            chunk_uncompressed_sizes.append(expected_uncompressed_size)
            reader.seek(chunk_compressed_size, 1)
            consumed += chunk_compressed_size
            remaining_uncompressed -= expected_uncompressed_size

        if consumed != stored_block_size:
            raise ValueError(f"{label} chunk table did not consume the stored block")
        if remaining_uncompressed != 0:
            raise ValueError(f"{label} chunks do not cover the declared uncompressed size")

        return BfpkChunkTable(
            stored_block_size,
            tuple(chunk_offsets),
            tuple(chunk_compressed_sizes),
            tuple(chunk_uncompressed_sizes),
            tuple(chunk_hashes),
            block_flag,
        )

