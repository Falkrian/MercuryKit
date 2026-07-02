from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from mercurykit.archive import ArchiveEntry


@dataclass(frozen=True)
class BfpkState:
    entries: tuple[ArchiveEntry, ...]


@dataclass(frozen=True)
class BfpkHeader:
    archive_version: int
    file_count: int
    file_chunk_size: int | None
    table_offset: int
    encrypted_table_size: int | None = None
    table_prefix: bytes | None = None


@dataclass(frozen=True)
class BfpkFileRecord:
    path: str
    uncompressed_size: int
    offset: int
    table_hash: int | None = None
    aux0: int | None = None
    aux1: int | None = None


@dataclass(frozen=True)
class BfpkChunkTable:
    stored_block_size: int
    chunk_offsets: tuple[int, ...]
    chunk_compressed_sizes: tuple[int, ...]
    chunk_uncompressed_sizes: tuple[int, ...]
    chunk_hashes: tuple[int, ...] = ()
    block_flag: int | None = None


@dataclass(frozen=True)
class BfpkRepackFile:
    source_path: Path
    path: str
    encoded_path: bytes
    uncompressed_size: int
    table_hash: int
