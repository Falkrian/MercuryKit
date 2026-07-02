from __future__ import annotations

from dataclasses import dataclass
import sys
from typing import BinaryIO, Protocol, TextIO


class ProgressReporter(Protocol):
    def start(
        self,
        label: str,
        *,
        total_items: int | None = None,
        total_bytes: int | None = None,
    ) -> None:
        """Start reporting a task."""

    def advance(self, *, items: int = 0, bytes_count: int = 0, detail: str | None = None) -> None:
        """Advance the active task."""

    def finish(self, detail: str | None = None) -> None:
        """Finish the active task."""


class NullProgressReporter:
    """Progress reporter used when output should stay completely silent."""

    def start(
        self,
        label: str,
        *,
        total_items: int | None = None,
        total_bytes: int | None = None,
    ) -> None:
        pass

    def advance(self, *, items: int = 0, bytes_count: int = 0, detail: str | None = None) -> None:
        pass

    def finish(self, detail: str | None = None) -> None:
        pass


@dataclass
class TerminalProgressReporter:
    """Single-line terminal progress renderer for unpacking and repacking."""

    stream: TextIO = sys.stderr
    width: int = 28

    def __post_init__(self) -> None:
        self._label = ""
        self._total_items: int | None = None
        self._total_bytes: int | None = None
        self._current_items = 0
        self._current_bytes = 0
        self._last_length = 0
        self._active = False

    def start(
        self,
        label: str,
        *,
        total_items: int | None = None,
        total_bytes: int | None = None,
    ) -> None:
        self._label = label
        self._total_items = total_items
        self._total_bytes = total_bytes
        self._current_items = 0
        self._current_bytes = 0
        self._last_length = 0
        self._active = True
        self._render()

    def advance(self, *, items: int = 0, bytes_count: int = 0, detail: str | None = None) -> None:
        if not self._active:
            return
        self._current_items += items
        self._current_bytes += bytes_count
        self._render(detail)

    def finish(self, detail: str | None = None) -> None:
        if not self._active:
            return
        if self._total_items is not None:
            self._current_items = max(self._current_items, self._total_items)
        if self._total_bytes is not None:
            self._current_bytes = max(self._current_bytes, self._total_bytes)
        self._render(detail or "done")
        self.stream.write("\n")
        self.stream.flush()
        self._active = False
        self._last_length = 0

    def _render(self, detail: str | None = None) -> None:
        line = self._line(detail)
        padding = " " * max(0, self._last_length - len(line))
        self.stream.write(f"\r{line}{padding}")
        self.stream.flush()
        self._last_length = len(line)

    def _line(self, detail: str | None = None) -> str:
        percent = self._percent()
        bar = self._bar(percent)
        parts = [f"{self._label}: [{bar}]"]
        if percent is not None:
            parts.append(f"{percent:3.0f}%")
        if self._total_items is not None:
            parts.append(f"{self._current_items}/{self._total_items} files")
        elif self._current_items:
            parts.append(f"{self._current_items} files")
        if self._total_bytes is not None:
            parts.append(f"{_format_bytes(self._current_bytes)}/{_format_bytes(self._total_bytes)}")
        elif self._current_bytes:
            parts.append(_format_bytes(self._current_bytes))
        if detail:
            parts.append(str(detail))
        return " ".join(parts)

    def _percent(self) -> float | None:
        if self._total_bytes:
            return min(100.0, (self._current_bytes / self._total_bytes) * 100.0)
        if self._total_items:
            return min(100.0, (self._current_items / self._total_items) * 100.0)
        return None

    def _bar(self, percent: float | None) -> str:
        if percent is None:
            return "." * self.width
        filled = round((percent / 100.0) * self.width)
        return "#" * filled + "-" * (self.width - filled)


class ProgressWriter:
    """Binary stream proxy that reports written byte counts as progress."""

    def __init__(self, wrapped: BinaryIO, progress: ProgressReporter) -> None:
        self._wrapped = wrapped
        self._progress = progress

    def write(self, data: bytes) -> int:
        written = self._wrapped.write(data)
        self._progress.advance(bytes_count=written)
        return written

    def flush(self) -> None:
        self._wrapped.flush()

    def __getattr__(self, name: str) -> object:
        return getattr(self._wrapped, name)


def _format_bytes(value: int) -> str:
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    amount = float(value)
    for unit in units:
        if amount < 1024.0 or unit == units[-1]:
            if unit == "B":
                return f"{int(amount)} {unit}"
            return f"{amount:.1f} {unit}"
        amount /= 1024.0
