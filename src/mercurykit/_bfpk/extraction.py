from __future__ import annotations

import zlib
from typing import BinaryIO

from mercurykit.binary import BinaryReader, EndOfStreamError
from mercurykit.codecs import compression_registry
from mercurykit.archive import ArchiveContext, ArchiveEntry
from mercurykit._bfpk.blades_restore import try_restore_blades_picture


class BfpkExtractionMixin:
    def try_extract_restored_entry(
        self,
        context: ArchiveContext,
        entry: ArchiveEntry,
        output_stream: BinaryIO,
    ) -> bool:
        """Write a viewer-ready form for entries with a known restore transform.

        Spacelords `Pics.packed` stores picture resources as an LZ4 block
        prefixed by the record's `stored_size`. The raw extractor intentionally
        skips the first one or two LZ4 bytes so current repack workflows stay
        compatible with the historical raw output. Restore mode reads the full
        block instead.
        """

        if self._can_restore_spacelords_d01_picture(entry):
            self._extract_spacelords_d01_picture(context, entry, output_stream)
            return True

        if self._can_restore_blades_of_fire_pics(entry):
            return try_restore_blades_picture(context, entry, output_stream)

        return False

    def extract_entry(self, context: ArchiveContext, entry: ArchiveEntry, output_stream: BinaryIO) -> None:
        if entry.offset is None:
            raise ValueError(f"Entry {entry.path or entry.entry_id or '<unnamed>'} does not define an offset")
        if entry.uncompressed_size is None:
            raise ValueError(f"Entry {entry.path or entry.entry_id or '<unnamed>'} does not define an uncompressed size")

        if entry.metadata.get("chunked"):
            self._extract_chunked_entry(context, entry, output_stream)
            return

        if entry.compression is not None:
            if entry.compressed_size is None:
                raise ValueError(f"Entry {entry.path or entry.entry_id or '<unnamed>'} does not define a stored size")
            with context.archive_path.open("rb") as file:
                file.seek(entry.offset)
                payload = file.read(entry.compressed_size)
            if len(payload) != entry.compressed_size:
                raise EndOfStreamError(f"Entry {entry.path or entry.entry_id or '<unnamed>'} extends beyond archive data")
            payload = compression_registry.decompress(entry.compression, payload)
            if len(payload) != entry.uncompressed_size:
                raise ValueError(f"Entry {entry.path or entry.entry_id or '<unnamed>'} decompressed to unexpected size")
            output_stream.write(payload)
            return

        with context.archive_path.open("rb") as file:
            file.seek(entry.offset)
            payload = file.read(entry.uncompressed_size)
        if len(payload) != entry.uncompressed_size:
            raise EndOfStreamError(f"Entry {entry.path or entry.entry_id or '<unnamed>'} extends beyond archive data")
        expected_crc = entry.metadata.get("table_hash")
        if expected_crc is not None and (zlib.crc32(payload) & self.max_u32) != expected_crc:
            raise ValueError(f"Entry {entry.path or entry.entry_id or '<unnamed>'} CRC did not match")
        output_stream.write(payload)

    def _can_restore_spacelords_d01_picture(self, entry: ArchiveEntry) -> bool:
        return (
            isinstance(entry.path, str)
            and self._spacelords_d01_picture_suffix(entry.path) is not None
            and entry.metadata.get("archive_version") == self.spacelords_d01_archive_version
            and entry.metadata.get("table_format") == self.spacelords_layout
            and entry.metadata.get("restore_compression") == "lz4-block"
        )

    def _spacelords_d01_picture_suffix(self, path: str) -> str | None:
        suffix = path.lower().rsplit(".", 1)[-1]
        if suffix in {"dds", "gif", "tga"}:
            return suffix
        return None

    def _can_restore_blades_of_fire_pics(self, entry: ArchiveEntry) -> bool:
        return (
            isinstance(entry.path, str)
            and entry.metadata.get("archive_version") == self.blades_of_fire_pics_archive_version
            and entry.metadata.get("table_format") == self.blades_of_fire_layout
        )

    def _extract_spacelords_d01_picture(
        self,
        context: ArchiveContext,
        entry: ArchiveEntry,
        output_stream: BinaryIO,
    ) -> None:
        record_offset = entry.metadata.get("record_offset")
        block_size = entry.metadata.get("payload_block_size")
        declared_size = entry.metadata.get("declared_size")
        if not isinstance(record_offset, int) or not isinstance(block_size, int) or not isinstance(declared_size, int):
            raise ValueError(f"Entry {entry.path or entry.entry_id or '<unnamed>'} does not define restore metadata")

        with context.archive_path.open("rb") as file:
            file.seek(record_offset)
            stored_size = int.from_bytes(file.read(4), "little")
            if stored_size != block_size:
                raise ValueError(f"Entry {entry.path or entry.entry_id or '<unnamed>'} stored size changed")
            block = file.read(block_size)

        if len(block) != block_size:
            raise EndOfStreamError(f"Entry {entry.path or entry.entry_id or '<unnamed>'} restore block extends beyond archive data")
        restored = self._decompress_lz4_block(block, declared_size)
        self._validate_spacelords_d01_restored_picture(entry, restored)
        output_stream.write(restored)

    def _validate_spacelords_d01_restored_picture(self, entry: ArchiveEntry, data: bytes) -> None:
        suffix = self._spacelords_d01_picture_suffix(entry.path or "")
        if suffix == "dds" and data.startswith(b"DDS "):
            return
        if suffix == "gif" and data.startswith((b"GIF87a", b"GIF89a")) and data.rstrip(b"\x00").endswith(b"\x3b"):
            return
        if suffix == "tga" and self._looks_like_restored_tga_header(data):
            return
        raise ValueError(f"Entry {entry.path or entry.entry_id or '<unnamed>'} did not restore to a valid {suffix or 'picture'} file")

    def _looks_like_restored_tga_header(self, data: bytes) -> bool:
        if len(data) < 18:
            return False
        color_map_type = data[1]
        image_type = data[2]
        color_map_length = int.from_bytes(data[5:7], "little")
        width = int.from_bytes(data[12:14], "little")
        height = int.from_bytes(data[14:16], "little")
        pixel_depth = data[16]
        if color_map_type not in {0, 1} or image_type not in {1, 2, 3, 9, 10, 11}:
            return False
        if color_map_type == 0 and color_map_length != 0:
            return False
        return width > 0 and height > 0 and pixel_depth in {8, 15, 16, 24, 32}

    def _extract_chunked_entry(self, context: ArchiveContext, entry: ArchiveEntry, output_stream: BinaryIO) -> None:
        chunk_offsets = tuple(entry.metadata.get("chunk_offsets") or ())
        chunk_compressed_sizes = tuple(entry.metadata.get("chunk_compressed_sizes") or ())
        chunk_uncompressed_sizes = tuple(entry.metadata.get("chunk_uncompressed_sizes") or ())
        chunk_hashes = tuple(entry.metadata.get("chunk_hashes") or ())
        if not (len(chunk_offsets) == len(chunk_compressed_sizes) == len(chunk_uncompressed_sizes)):
            raise ValueError(f"Entry {entry.path or entry.entry_id or '<unnamed>'} has inconsistent chunk metadata")
        if chunk_hashes and len(chunk_hashes) != len(chunk_offsets):
            raise ValueError(f"Entry {entry.path or entry.entry_id or '<unnamed>'} has inconsistent chunk hash metadata")

        total_uncompressed_size = 0
        crc = 0
        with context.archive_path.open("rb") as file:
            for index, (chunk_offset, chunk_compressed_size, chunk_uncompressed_size) in enumerate(
                zip(chunk_offsets, chunk_compressed_sizes, chunk_uncompressed_sizes)
            ):
                file.seek(chunk_offset)
                payload = file.read(chunk_compressed_size)
                if len(payload) != chunk_compressed_size:
                    raise EndOfStreamError(
                        f"Entry {entry.path or entry.entry_id or '<unnamed>'} chunk extends beyond archive data"
                    )
                if chunk_hashes and self._xxh32(payload) != chunk_hashes[index]:
                    raise ValueError(f"Entry {entry.path or entry.entry_id or '<unnamed>'} chunk hash did not match")

                if entry.compression == "lz4-block":
                    payload = self._decompress_lz4_block(payload, chunk_uncompressed_size)
                else:
                    payload = compression_registry.decompress("zlib", payload)
                if len(payload) != chunk_uncompressed_size:
                    raise ValueError(
                        f"Entry {entry.path or entry.entry_id or '<unnamed>'} chunk decompressed to unexpected size"
                    )
                output_stream.write(payload)
                crc = zlib.crc32(payload, crc)
                total_uncompressed_size += len(payload)

        if total_uncompressed_size != entry.uncompressed_size:
            raise ValueError(f"Entry {entry.path or entry.entry_id or '<unnamed>'} decompressed to unexpected size")
        expected_crc = entry.metadata.get("table_hash")
        if expected_crc is not None and (crc & self.max_u32) != expected_crc:
            raise ValueError(f"Entry {entry.path or entry.entry_id or '<unnamed>'} CRC did not match")

    def _crc32_lz4_chunks(self, reader: BinaryReader, entry: ArchiveEntry) -> int:
        chunk_offsets = tuple(entry.metadata.get("chunk_offsets") or ())
        chunk_compressed_sizes = tuple(entry.metadata.get("chunk_compressed_sizes") or ())
        chunk_uncompressed_sizes = tuple(entry.metadata.get("chunk_uncompressed_sizes") or ())
        chunk_hashes = tuple(entry.metadata.get("chunk_hashes") or ())
        layout = entry.metadata.get("table_format")
        crc = 0
        for index, (chunk_offset, chunk_compressed_size, chunk_uncompressed_size) in enumerate(
            zip(chunk_offsets, chunk_compressed_sizes, chunk_uncompressed_sizes)
        ):
            reader.seek(chunk_offset)
            payload = reader.read_exact(chunk_compressed_size)
            if chunk_hashes and self._xxh32(payload) != chunk_hashes[index]:
                if layout == self.spacelords_layout:
                    raise ValueError("BFPK Spacelords chunk hash did not match")
                raise ValueError("BFPK Blades of Fire chunk hash did not match")
            decompressed = self._decompress_lz4_block(payload, chunk_uncompressed_size)
            crc = zlib.crc32(decompressed, crc)
        return crc & self.max_u32

