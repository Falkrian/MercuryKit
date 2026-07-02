from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from mercurykit.archive import ArchiveInfo, ArchiveMatch
from mercurykit.bfpk import BfpkEngine
from mercurykit.binary import BinaryReader


class ScannerError(Exception):
    """Base exception for scanner failures."""


class NoArchiveError(ScannerError):
    """Raised when a file is not a compatible BFPK archive."""


@dataclass(frozen=True)
class ScanOutcome:
    path: Path
    engine: BfpkEngine | None
    selected: ArchiveMatch | None
    info: ArchiveInfo | None = None
    message: str = ""


class ArchiveScanner:
    """Small scanner wrapper for MercuryKit's single built-in BFPK engine."""

    def __init__(self, engine: BfpkEngine | None = None, *, min_confidence: float = 0.65) -> None:
        self.engine = engine or BfpkEngine()
        self.min_confidence = min_confidence

    def scan(self, path: Path, *, read_manifest: bool = False) -> ScanOutcome:
        path = Path(path)
        with path.open("rb") as file:
            match = self.engine.evaluate(path, BinaryReader(file))
        if match.confidence < self.min_confidence:
            return ScanOutcome(path, None, None, message="No compatible BFPK archive found")
        info = self._read_info(path) if read_manifest else None
        return ScanOutcome(path, self.engine, match, info=info)

    def require_archive(self, path: Path, *, read_manifest: bool = True) -> ScanOutcome:
        outcome = self.scan(path, read_manifest=read_manifest)
        if outcome.engine is None:
            raise NoArchiveError(f"No compatible BFPK archive found for {path}")
        return outcome

    def _read_info(self, path: Path) -> ArchiveInfo:
        with path.open("rb") as file:
            return self.engine.read_manifest(path, BinaryReader(file))
