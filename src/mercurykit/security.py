from __future__ import annotations

from pathlib import Path, PurePosixPath, PureWindowsPath


class UnsafeArchivePathError(ValueError):
    """Raised when an archive entry path would escape the destination."""


def safe_output_path(root: Path, entry_path: str) -> Path:
    """Resolve an archive entry path while preventing traversal outside ``root``."""

    if not entry_path or "\x00" in entry_path:
        raise UnsafeArchivePathError("Archive entry path is empty or contains a null byte")

    normalized = entry_path.replace("\\", "/")
    posix = PurePosixPath(normalized)
    windows = PureWindowsPath(entry_path)

    if posix.is_absolute() or windows.is_absolute() or windows.drive:
        raise UnsafeArchivePathError(f"Archive entry path is absolute: {entry_path}")
    if any(part in ("", ".", "..") for part in posix.parts):
        raise UnsafeArchivePathError(f"Archive entry path contains an unsafe segment: {entry_path}")

    destination = (root / Path(*posix.parts)).resolve()
    resolved_root = root.resolve()
    if resolved_root != destination and resolved_root not in destination.parents:
        raise UnsafeArchivePathError(f"Archive entry path escapes destination: {entry_path}")
    return destination
