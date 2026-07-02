from __future__ import annotations

import zlib
from typing import BinaryIO

from mercurykit.binary import BinaryReader, EndOfStreamError
from mercurykit.codecs import compression_registry
from mercurykit.archive import ArchiveContext, ArchiveEntry


class BfpkExtractionMixin:
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

