from __future__ import annotations

from pathlib import Path

from typing import Iterable

from mercurykit.archive import ArchiveContext, ArchiveEntry, ArchiveInfo, ArchiveMatch, UnsupportedOperation
from mercurykit.binary import BinaryReader, EndOfStreamError

from .codecs import BfpkCodecMixin
from .extraction import BfpkExtractionMixin
from .manifest import BfpkManifestMixin
from .models import BfpkState
from .repack import BfpkRepackMixin


class BfpkEngine(BfpkManifestMixin, BfpkExtractionMixin, BfpkRepackMixin, BfpkCodecMixin):
    """Engine for MercurySteam BFPK game archives."""

    format_name = "MercurySteam BFPK Archive"

    archive_magic = b"BFPK"
    legacy_layout = "legacy"
    blades_of_fire_layout = "blades_of_fire"
    spacelords_layout = "spacelords"
    lords_of_shadow_ultimate_layout = "lords_of_shadow_ultimate"
    legacy_archive_versions = frozenset({0x100, 0x101, 0x102})
    blades_of_fire_archive_versions = frozenset({0x100, 0x102, 0x300})
    spacelords_archive_versions = frozenset({0x500, 0x502})
    lords_of_shadow_ultimate_archive_versions = frozenset({0x2, 0x3})
    chunked_header_archive_versions = frozenset({0x102, 0x502})
    default_file_chunk_size = 0x10000
    blades_of_fire_default_file_chunk_size = 0x40000
    spacelords_default_file_chunk_size = 0x40000
    spacelords_default_trailing_padding = 0x10000
    encrypted_picture_alignment = 0x10000
    spacelords_d01_archive_version = 0xD01
    blades_of_fire_pics_archive_version = 0x901
    blades_of_fire_pics_default_record_flags = 0x09FF
    blades_of_fire_pics_gif_record_flag_low = 0xC0
    spacelords_d01_default_record_flags = 0x00F1
    spacelords_d01_gif_record_flag_low = 0xDF
    spacelords_d01_tga_record_flag_low = 0x44
    default_trailing_padding = 0x8000
    default_compression_level = -1
    lords_of_shadow_ultimate_table_prefix = b"MercuryKitLoSUE!"
    lords_of_shadow_ultimate_aes_key = bytes.fromhex(
        "50 43 56 80 72 73 EE 6F F1 44 F3 6E EA DF 79 43 "
        "6C 69 6D 61 78 53 74 75 64 69 6F 73 32 30 31 33"
    )
    max_u32 = 0xFFFFFFFF
    max_u64 = 0xFFFFFFFFFFFFFFFF

    def _spacelords_d01_xor_key(self, offset: int) -> int:
        return (((offset * offset * 0x343FD) + 0x269EC3) >> 16) & 0xFF

    def _crypt_spacelords_d01_table(self, data: bytes, start_offset: int) -> bytes:
        return bytes(byte ^ self._spacelords_d01_xor_key(start_offset + index) for index, byte in enumerate(data))

    def _has_encrypted_picture_table(self, archive_version: int) -> bool:
        return archive_version in {self.spacelords_d01_archive_version, self.blades_of_fire_pics_archive_version}

    def _has_chunked_header(self, archive_version: int) -> bool:
        return archive_version in self.chunked_header_archive_versions

    def _has_lords_of_shadow_ultimate_table(self, archive_version: int) -> bool:
        return archive_version in self.lords_of_shadow_ultimate_archive_versions

    def _supports_legacy_layout(self, archive_version: int) -> bool:
        return archive_version in self.legacy_archive_versions

    def _supports_lords_of_shadow_ultimate_layout(self, archive_version: int) -> bool:
        return archive_version in self.lords_of_shadow_ultimate_archive_versions

    def _supports_blades_of_fire_layout(self, archive_version: int) -> bool:
        return archive_version in self.blades_of_fire_archive_versions or archive_version == self.blades_of_fire_pics_archive_version

    def _supports_spacelords_layout(self, archive_version: int) -> bool:
        return archive_version in self.spacelords_archive_versions or archive_version == self.spacelords_d01_archive_version

    def _encrypted_picture_layout(self, archive_version: int) -> str:
        if archive_version == self.blades_of_fire_pics_archive_version:
            return self.blades_of_fire_layout
        if archive_version == self.spacelords_d01_archive_version:
            return self.spacelords_layout
        raise ValueError(f"BFPK archive version 0x{archive_version:x} is not an encrypted picture archive")

    def evaluate(self, path: Path, reader: BinaryReader) -> ArchiveMatch:
        try:
            header = self._read_header(reader)
            file_size = self._reader_size(reader)
            layout, records = self._select_table_layout(reader, header, file_size)
            self._validate_sample_payloads(reader, header, layout, records, file_size)
        except (EndOfStreamError, UnicodeDecodeError, ValueError, UnsupportedOperation) as exc:
            return ArchiveMatch(0.0, self.format_name, reason=str(exc))

        reason = f"BFPK {layout} layout matched"
        return ArchiveMatch(0.99, self.format_name, reason=reason)

    def read_manifest(self, path: Path, reader: BinaryReader) -> ArchiveInfo:
        header = self._read_header(reader)
        file_size = self._reader_size(reader)
        layout, records = self._select_table_layout(reader, header, file_size)
        entries = [
            self._entry_for_version(reader, header.archive_version, header.file_chunk_size, layout, record)
            for record in records
        ]

        return ArchiveInfo(
            self.format_name,
            len(entries),
            {
                "archive_version": header.archive_version,
                "file_chunk_size": header.file_chunk_size,
                "table_format": layout,
                "encrypted_table_size": header.encrypted_table_size,
                "table_prefix": header.table_prefix,
                "entries": tuple(entries),
            },
        )

    def open(self, path: Path) -> ArchiveContext:
        with path.open("rb") as file:
            info = self.read_manifest(path, BinaryReader(file))
        return ArchiveContext(path, self, info, BfpkState(tuple(info.metadata["entries"])))

    def iter_entries(self, context: ArchiveContext) -> Iterable[ArchiveEntry]:
        state = self._state(context)
        yield from state.entries

    def _state(self, context: ArchiveContext) -> BfpkState:
        if isinstance(context.state, BfpkState):
            return context.state
        return BfpkState(tuple(context.info.metadata["entries"]))


