from __future__ import annotations

import argparse
from dataclasses import dataclass, fields
from pathlib import Path
import re
import sys

from mercurykit.archive import ArchiveContext, ArchiveEntry, UnsupportedOperation
from mercurykit.bfpk import BfpkEngine
from mercurykit.mirror_of_fate import MirrorOfFatePackEngine
from mercurykit.progress import NullProgressReporter, ProgressReporter, ProgressWriter, TerminalProgressReporter
from mercurykit.scanner import ArchiveScanner, NoArchiveError
from mercurykit.security import UnsafeArchivePathError, safe_output_path


@dataclass(frozen=True)
class ScanInputs:
    files: list[Path]
    empty_files: list[Path]
    directory_mode: bool


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mercurykit")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan archive files")
    scan_parser.add_argument("paths", nargs="+", type=Path)
    scan_parser.add_argument("--verbose", action="store_true")
    scan_parser.add_argument("-r", "--recursive", action="store_true")

    unpack_parser = subparsers.add_parser("unpack", help="Unpack archive files")
    unpack_parser.add_argument("files", nargs="+", type=Path)
    unpack_parser.add_argument("--dest", type=Path)
    unpack_parser.add_argument("--overwrite", action="store_true")
    _add_progress_args(unpack_parser)

    repack_parser = subparsers.add_parser("repack", help="Repack a directory into an archive")
    repack_parser.add_argument("source_dir", type=Path)
    repack_parser.add_argument("--output", required=True, type=Path)
    repack_parser.add_argument("--option", action="append", default=[], metavar="KEY=VALUE")
    _add_progress_args(repack_parser)

    return parser


def _add_progress_args(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--progress", action="store_true", help="Show progress even when stderr is not interactive")
    group.add_argument("--no-progress", action="store_true", help="Disable progress output")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    bfpk_engine = BfpkEngine()
    mirror_of_fate_engine = MirrorOfFatePackEngine()
    scanner = ArchiveScanner((bfpk_engine, mirror_of_fate_engine))

    try:
        if args.command == "scan":
            return _scan(args, scanner)
        if args.command == "unpack":
            return _unpack(args, scanner)
        if args.command == "repack":
            return _repack(args, bfpk_engine, mirror_of_fate_engine)
    except (
        NoArchiveError,
        UnsafeArchivePathError,
        UnsupportedOperation,
        FileExistsError,
        FileNotFoundError,
        ValueError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


def _scan(args: argparse.Namespace, scanner: ArchiveScanner) -> int:
    exit_code = 0
    scan_inputs = _scan_inputs(args.paths, recursive=args.recursive)
    files = scan_inputs.files
    empty_files = scan_inputs.empty_files
    directory_mode = scan_inputs.directory_mode
    supported_count = 0
    unsupported_count = 0

    if args.verbose or (not directory_mode and not files):
        for file in empty_files:
            print(f"Skipped empty file: {file}")

    for file in files:
        outcome = scanner.scan(file, read_manifest=True)
        if outcome.engine is None or outcome.selected is None:
            unsupported_count += 1
            if not directory_mode:
                exit_code = 1
            print(f"{file}: {outcome.message}")
            continue

        supported_count += 1
        match = outcome.selected
        entry_count = "unknown" if outcome.info is None or outcome.info.entry_count is None else str(outcome.info.entry_count)
        print(f"File: {file}\n\n{match.format_name}\nConfidence = {match.confidence:.2f} \nEntries = {entry_count}\n")

        if args.verbose:
            if match.reason:
                print(f"  {match.reason}")
            context = outcome.engine.open(file)
            entries = list(outcome.engine.iter_entries(context))
            if entries:
                print("Entries:")
                for index, entry in enumerate(entries, start=1):
                    print(f"  {index:06d}: {_format_entry(entry)}")

    if directory_mode:
        print(
            f"Scan summary: scanned={len(files)} supported={supported_count} "
            f"unsupported={unsupported_count} empty={len(empty_files)}"
        )

    return exit_code


def _scan_inputs(paths: list[Path], *, recursive: bool) -> ScanInputs:
    files: list[Path] = []
    empty_files: list[Path] = []
    directory_mode = False
    for path in paths:
        if not path.exists():
            raise FileNotFoundError(f"Scan input does not exist: {path}")
        if path.is_file():
            _append_scan_file(path, files, empty_files)
            continue
        if path.is_dir():
            directory_mode = True
            for file in _scan_directory_files(path, recursive=recursive):
                _append_scan_file(file, files, empty_files)
            continue
        raise FileNotFoundError(f"Scan input is not a regular file or directory: {path}")
    return ScanInputs(files, empty_files, directory_mode)


def _scan_directory_files(directory: Path, *, recursive: bool) -> list[Path]:
    candidates = directory.rglob("*") if recursive else directory.iterdir()
    return sorted((path for path in candidates if path.is_file()), key=lambda path: path.as_posix())


def _append_scan_file(path: Path, files: list[Path], empty_files: list[Path]) -> None:
    if path.stat().st_size == 0:
        empty_files.append(path)
        return
    files.append(path)


def _format_entry(entry: ArchiveEntry) -> str:
    parts: list[str] = []
    for field in fields(entry):
        value = getattr(entry, field.name)
        if value is None:
            continue
        if field.name == "metadata" and not value:
            continue
        parts.append(f"{field.name}={value!r}")
    return " ".join(parts)


def _unpack(args: argparse.Namespace, scanner: ArchiveScanner) -> int:
    for file in args.files:
        outcome = scanner.require_archive(file, read_manifest=True)
        assert outcome.engine is not None
        context = outcome.engine.open(file)
        output_root = _output_root(args.dest, file, multiple=len(args.files) > 1)
        progress = _progress_reporter(args)
        _extract_context(context, output_root, overwrite=args.overwrite, progress=progress)
        print(f"{file}: extracted to {output_root}")
    return 0


def _output_root(dest: Path | None, archive_path: Path, *, multiple: bool) -> Path:
    archive_folder = archive_path.stem
    if dest is None:
        return Path.cwd() / archive_folder
    if multiple:
        return dest / archive_folder
    if dest.exists() and dest.is_dir() and not any(dest.iterdir()):
        return dest
    if not dest.exists():
        return dest
    return dest / archive_folder


def _extract_context(
    context: ArchiveContext,
    output_root: Path,
    *,
    overwrite: bool,
    progress: ProgressReporter | None = None,
) -> None:
    progress = progress or NullProgressReporter()
    output_root.mkdir(parents=True, exist_ok=True)
    seen: set[Path] = set()
    entries = list(context.engine.iter_entries(context))
    progress.start(
        f"Extracting {context.archive_path.name}",
        total_items=len(entries),
        total_bytes=_entries_total_uncompressed_size(entries),
    )
    try:
        for index, entry in enumerate(entries, start=1):
            destination = _entry_output_path(output_root, entry, index)
            key = Path(str(destination).casefold())
            if key in seen:
                raise FileExistsError(f"Duplicate archive entry path: {entry.path or destination.name}")
            seen.add(key)
            if destination.exists() and not overwrite:
                raise FileExistsError(f"Refusing to overwrite existing file: {destination}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open("wb") as output:
                context.engine.extract_entry(context, entry, ProgressWriter(output, progress))
            progress.advance(items=1, detail=entry.path or destination.name)
    finally:
        progress.finish()
    _write_unpacked_metadata(context, output_root, entries)


def _write_unpacked_metadata(context: ArchiveContext, output_root: Path, entries: list[ArchiveEntry]) -> None:
    writer = getattr(context.engine, "write_unpacked_metadata", None)
    if callable(writer):
        writer(context, output_root, entries)


def _entries_total_uncompressed_size(entries: list[ArchiveEntry]) -> int | None:
    total = 0
    for entry in entries:
        size = entry.uncompressed_size
        if not isinstance(size, int):
            return None
        total += size
    return total


def _progress_reporter(args: argparse.Namespace) -> ProgressReporter:
    if getattr(args, "no_progress", False):
        return NullProgressReporter()
    if getattr(args, "progress", False) or sys.stderr.isatty():
        return TerminalProgressReporter(sys.stderr)
    return NullProgressReporter()


def _entry_output_path(output_root: Path, entry: ArchiveEntry, index: int) -> Path:
    if entry.path:
        return safe_output_path(output_root, entry.path)

    suffix = _sanitize_entry_id(entry.entry_id)
    name = f"entry_{index:06d}{suffix}.bin"
    return safe_output_path(output_root, name)


def _sanitize_entry_id(entry_id: str | int | None) -> str:
    if entry_id is None:
        return ""
    sanitized = re.sub(r"[^A-Za-z0-9._-]+", "_", str(entry_id)).strip("._-")
    return f"_{sanitized}" if sanitized else ""


def _parse_archive_options(raw_options: list[str]) -> dict[str, object]:
    options: dict[str, object] = {}
    for raw_option in raw_options:
        if "=" not in raw_option:
            raise ValueError(f"Archive option must use KEY=VALUE syntax: {raw_option}")
        key, raw_value = raw_option.split("=", 1)
        key = key.strip()
        if not key:
            raise ValueError(f"Archive option must include a key: {raw_option}")
        options[key] = _parse_archive_option_value(raw_value.strip())
    return options


def _parse_archive_option_value(value: str) -> object:
    lowered = value.lower()
    if lowered in {"true", "yes", "on"}:
        return True
    if lowered in {"false", "no", "off"}:
        return False
    try:
        return int(value, 0)
    except ValueError:
        return value


def _repack(args: argparse.Namespace, bfpk_engine: BfpkEngine, mirror_of_fate_engine: MirrorOfFatePackEngine) -> int:
    if not args.source_dir.is_dir():
        raise FileNotFoundError(f"Source directory does not exist: {args.source_dir}")
    options = _parse_archive_options(args.option)
    engine = _repack_engine(args.output, options, bfpk_engine, mirror_of_fate_engine)
    engine.repack_with_progress(args.source_dir, args.output, options, _progress_reporter(args))
    print(f"{args.source_dir}: repacked to {args.output}")
    return 0


def _repack_engine(
    output_path: Path,
    options: dict[str, object],
    bfpk_engine: BfpkEngine,
    mirror_of_fate_engine: MirrorOfFatePackEngine,
) -> BfpkEngine | MirrorOfFatePackEngine:
    if output_path.suffix.lower() == ".pack" and "archive_version" not in options and "layout" not in options:
        return mirror_of_fate_engine
    return bfpk_engine
