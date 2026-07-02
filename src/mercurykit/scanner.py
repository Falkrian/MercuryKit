from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Protocol

from mercurykit.archive import ArchiveContext, ArchiveEntry, ArchiveInfo, ArchiveMatch
from mercurykit.bfpk import BfpkEngine
from mercurykit.binary import BinaryReader
from mercurykit.mirror_of_fate import MirrorOfFatePackEngine


class ArchiveEngine(Protocol):
    format_name: str

    def evaluate(self, path: Path, reader: BinaryReader) -> ArchiveMatch:
        ...

    def read_manifest(self, path: Path, reader: BinaryReader) -> ArchiveInfo:
        ...

    def open(self, path: Path) -> ArchiveContext:
        ...

    def iter_entries(self, context: ArchiveContext) -> Iterable[ArchiveEntry]:
        ...


class ScannerError(Exception):
    """Base exception for scanner failures."""


class NoArchiveError(ScannerError):
    """Raised when a file is not a compatible archive."""


@dataclass(frozen=True)
class ScanOutcome:
    path: Path
    engine: ArchiveEngine | None
    selected: ArchiveMatch | None
    info: ArchiveInfo | None = None
    message: str = ""


class ArchiveScanner:
    """Scanner wrapper for MercuryKit's built-in archive engines."""

    def __init__(
        self,
        engine: ArchiveEngine | Iterable[ArchiveEngine] | None = None,
        *,
        min_confidence: float = 0.65,
    ) -> None:
        if engine is None:
            self.engines = (BfpkEngine(), MirrorOfFatePackEngine())
        elif isinstance(engine, Iterable):
            self.engines = tuple(engine)
        else:
            self.engines = (engine,)
        self.min_confidence = min_confidence

    def scan(self, path: Path, *, read_manifest: bool = False) -> ScanOutcome:
        path = Path(path)
        selected_engine: ArchiveEngine | None = None
        selected_match: ArchiveMatch | None = None
        for engine in self.engines:
            with path.open("rb") as file:
                match = engine.evaluate(path, BinaryReader(file))
            if selected_match is None or match.confidence > selected_match.confidence:
                selected_engine = engine
                selected_match = match

        if selected_engine is None or selected_match is None or selected_match.confidence < self.min_confidence:
            return ScanOutcome(path, None, None, message="No compatible archive found")

        info = self._read_info(path, selected_engine) if read_manifest else None
        return ScanOutcome(path, selected_engine, selected_match, info=info)

    def require_archive(self, path: Path, *, read_manifest: bool = True) -> ScanOutcome:
        outcome = self.scan(path, read_manifest=read_manifest)
        if outcome.engine is None:
            raise NoArchiveError(f"No compatible archive found for {path}")
        return outcome

    def _read_info(self, path: Path, engine: ArchiveEngine) -> ArchiveInfo:
        with path.open("rb") as file:
            return engine.read_manifest(path, BinaryReader(file))
