from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class UnsupportedOperation(Exception):
    """Raised when an archive operation is not supported."""


@dataclass(frozen=True)
class ArchiveEntry:
    """A normalized entry description used by scanners, extractors, and the CLI."""

    path: str | None = None
    offset: int | list | None = None
    compressed_size: int | list | None = None
    uncompressed_size: int | list | None = None
    flags: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    entry_id: str | int | None = None
    stored_size: int | None = None
    compression: str | None = None
    encryption: str | None = None


@dataclass(frozen=True)
class ArchiveInfo:
    """Manifest-level information returned after an archive has been identified."""

    format_name: str
    entry_count: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ArchiveMatch:
    confidence: float
    format_name: str
    reason: str = ""

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")


@dataclass(frozen=True)
class ArchiveContext:
    """Opened archive state passed back to an engine for iteration and extraction."""

    archive_path: Path
    engine: Any
    info: ArchiveInfo
    state: Any = None
