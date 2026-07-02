from __future__ import annotations

from pathlib import Path
import struct
import zlib
from typing import BinaryIO, Callable

from mercurykit.archive import UnsupportedOperation
from mercurykit.progress import NullProgressReporter, ProgressReporter

from .models import BfpkRepackFile


class BfpkRepackMixin:
    """Repack directory trees into the supported BFPK archive layouts."""

    def repack(self, input_dir: Path, output_path: Path, options: dict[str, object] | None = None) -> None:
        self.repack_with_progress(input_dir, output_path, options, NullProgressReporter())

    def repack_with_progress(
        self,
        input_dir: Path,
        output_path: Path,
        options: dict[str, object] | None,
        progress: ProgressReporter,
    ) -> None:
        options = options or {}
        layout = self._layout_option(options)
        if layout == self.spacelords_layout:
            self._repack_spacelords(input_dir, output_path, options, progress)
            return
        if layout == self.blades_of_fire_layout:
            self._repack_blades_of_fire(input_dir, output_path, options, progress)
            return
        if layout == self.lords_of_shadow_ultimate_layout:
            self._repack_lords_of_shadow_ultimate(input_dir, output_path, options, progress)
            return
        if layout == self.scrapland_layout:
            self._repack_scrapland(input_dir, output_path, options, progress)
            return
        self._repack_legacy(input_dir, output_path, options, progress)

    def _repack_legacy(
        self,
        input_dir: Path,
        output_path: Path,
        options: dict[str, object],
        progress: ProgressReporter,
    ) -> None:
        archive_version = self._required_int_option(options, "archive_version")
        if not self._supports_legacy_layout(archive_version):
            raise UnsupportedOperation(f"BFPK archive version 0x{archive_version:x} is not supported for repacking")

        file_chunk_size = self._int_option(options, "file_chunk_size", self.default_file_chunk_size)
        trailing_padding = self._int_option(options, "trailing_padding", self.default_trailing_padding)
        compression_level = self._int_option(options, "compression_level", self.default_compression_level)
        self._validate_repack_options(file_chunk_size, trailing_padding)

        input_dir = input_dir.resolve()
        output_path = output_path.resolve()
        self._validate_repack_paths(input_dir, output_path)

        files = self._collect_repack_files(input_dir)
        self._check_u32(len(files), "BFPK file count")
        output_path.parent.mkdir(parents=True, exist_ok=True)

        repack_files = self._prepare_repack_files(
            input_dir,
            files,
            output_path.name,
            compute_hash=False,
            include_total_bytes=False,
            progress=progress,
        )
        offset_field_positions: list[int] = []
        progress.start(
            f"Repacking {output_path.name}",
            total_items=len(repack_files),
            total_bytes=sum(file.uncompressed_size for file in repack_files),
        )
        with output_path.open("w+b") as output:
            try:
                self._write_repack_header(output, archive_version, len(repack_files), file_chunk_size)
                for repack_file in repack_files:
                    output.write(struct.pack("<I", len(repack_file.encoded_path)))
                    output.write(repack_file.encoded_path)
                    output.write(struct.pack("<I", repack_file.uncompressed_size))
                    offset_field_positions.append(output.tell())
                    output.write(b"\x00" * 8)

                for repack_file, offset_field_position in zip(repack_files, offset_field_positions):
                    file_offset = output.tell()
                    self._check_u64(file_offset, f"BFPK payload offset for {repack_file.path}")
                    output.seek(offset_field_position)
                    output.write(struct.pack("<Q", file_offset))
                    output.seek(0, 2)
                    self._write_legacy_repack_payload(
                        output,
                        repack_file,
                        archive_version,
                        file_chunk_size,
                        compression_level,
                        progress,
                    )
                    progress.advance(items=1, detail=repack_file.path)

                if trailing_padding:
                    output.write(b"\x00" * trailing_padding)
            finally:
                progress.finish()

    def _repack_blades_of_fire(
        self,
        input_dir: Path,
        output_path: Path,
        options: dict[str, object],
        progress: ProgressReporter,
    ) -> None:
        archive_version = self._required_int_option(options, "archive_version")
        if archive_version == self.blades_of_fire_pics_archive_version:
            self._repack_blades_of_fire_pics(input_dir, output_path, options, progress)
            return
        if archive_version not in self.blades_of_fire_archive_versions:
            raise UnsupportedOperation(
                f"BFPK Blades of Fire archive version 0x{archive_version:x} is not supported for repacking"
            )

        default_chunk_size = self.blades_of_fire_default_file_chunk_size if archive_version == 0x102 else self.default_file_chunk_size
        file_chunk_size = self._int_option(options, "file_chunk_size", default_chunk_size)
        trailing_padding = self._int_option(options, "trailing_padding", self.default_trailing_padding)
        self._validate_repack_options(file_chunk_size, trailing_padding)

        input_dir = input_dir.resolve()
        output_path = output_path.resolve()
        self._validate_repack_paths(input_dir, output_path)
        if archive_version == 0x102:
            self._require_lz4_block()

        files = self._collect_repack_files(input_dir)
        self._check_u32(len(files), "BFPK file count")
        output_path.parent.mkdir(parents=True, exist_ok=True)

        repack_files = self._prepare_repack_files(
            input_dir,
            files,
            output_path.name,
            compute_hash=True,
            include_total_bytes=True,
            progress=progress,
        )
        offset_field_positions: list[int] = []
        aux1_field_positions: list[int] = []
        progress.start(
            f"Repacking {output_path.name}",
            total_items=len(repack_files),
            total_bytes=sum(file.uncompressed_size for file in repack_files),
        )
        with output_path.open("w+b") as output:
            try:
                self._write_repack_header(output, archive_version, len(repack_files), file_chunk_size)
                for repack_file in repack_files:
                    output.write(struct.pack("<I", len(repack_file.encoded_path)))
                    output.write(repack_file.encoded_path)
                    output.write(struct.pack("<I", repack_file.uncompressed_size))
                    offset_field_positions.append(output.tell())
                    output.write(b"\x00" * 8)
                    output.write(struct.pack("<I", repack_file.table_hash))
                    output.write(struct.pack("<I", 0))
                    aux1_field_positions.append(output.tell())
                    output.write(b"\x00" * 4)

                for repack_file, offset_position, aux1_position in zip(
                    repack_files,
                    offset_field_positions,
                    aux1_field_positions,
                ):
                    file_offset = output.tell()
                    self._check_u64(file_offset, f"BFPK Blades of Fire payload offset for {repack_file.path}")
                    output.seek(offset_position)
                    output.write(struct.pack("<Q", file_offset))
                    output.seek(0, 2)
                    stored_size = self._write_blades_of_fire_payload(
                        output,
                        repack_file,
                        archive_version,
                        file_chunk_size,
                        progress,
                    )
                    aux1 = stored_size if archive_version == 0x102 else 0
                    output.seek(aux1_position)
                    output.write(struct.pack("<I", aux1))
                    output.seek(0, 2)
                    progress.advance(items=1, detail=repack_file.path)

                if trailing_padding:
                    output.write(b"\x00" * trailing_padding)
            finally:
                progress.finish()

    def _repack_blades_of_fire_pics(
        self,
        input_dir: Path,
        output_path: Path,
        options: dict[str, object],
        progress: ProgressReporter,
    ) -> None:
        self._repack_encrypted_picture_archive(
            input_dir,
            output_path,
            options,
            progress,
            archive_version=self.blades_of_fire_pics_archive_version,
            label="BFPK Blades of Fire 0x901",
            record_size=self._blades_of_fire_pics_record_size,
            write_payload=self._write_blades_of_fire_pics_payload,
        )

    def _blades_of_fire_pics_record_size(self, repack_file: BfpkRepackFile) -> int:
        if self._blades_of_fire_pics_uses_embedded_first_payload_byte(repack_file):
            return 9 + repack_file.uncompressed_size
        return 10 + repack_file.uncompressed_size

    def _blades_of_fire_pics_uses_embedded_first_payload_byte(self, repack_file: BfpkRepackFile) -> bool:
        return repack_file.path.lower().endswith(".gif") and repack_file.uncompressed_size > 0

    def _write_blades_of_fire_pics_payload(
        self,
        output: BinaryIO,
        repack_file: BfpkRepackFile,
        progress: ProgressReporter,
    ) -> int:
        data = repack_file.source_path.read_bytes()
        stored_size = len(data)
        self._check_u32(stored_size, f"BFPK Blades of Fire 0x901 stored size for {repack_file.path}")
        output.write(struct.pack("<I", stored_size))
        output.write(struct.pack("<I", 0))

        if self._blades_of_fire_pics_uses_embedded_first_payload_byte(repack_file):
            flags = self.blades_of_fire_pics_gif_record_flag_low | (data[0] << 8)
            output.write(struct.pack("<H", flags))
            output.write(data[1:])
        else:
            output.write(struct.pack("<H", self.blades_of_fire_pics_default_record_flags))
            output.write(data)

        progress.advance(bytes_count=stored_size)
        return self._blades_of_fire_pics_record_size(repack_file)

    def _repack_spacelords(
        self,
        input_dir: Path,
        output_path: Path,
        options: dict[str, object],
        progress: ProgressReporter,
    ) -> None:
        archive_version = self._required_int_option(options, "archive_version")
        if archive_version == self.spacelords_d01_archive_version:
            self._repack_spacelords_d01(input_dir, output_path, options, progress)
            return
        if archive_version not in self.spacelords_archive_versions:
            raise UnsupportedOperation(
                f"BFPK Spacelords archive version 0x{archive_version:x} is not supported for repacking"
            )

        default_chunk_size = self.spacelords_default_file_chunk_size if archive_version == 0x502 else self.default_file_chunk_size
        file_chunk_size = self._int_option(options, "file_chunk_size", default_chunk_size)
        trailing_padding = self._int_option(options, "trailing_padding", self.spacelords_default_trailing_padding)
        self._validate_repack_options(file_chunk_size, trailing_padding)

        input_dir = input_dir.resolve()
        output_path = output_path.resolve()
        self._validate_repack_paths(input_dir, output_path)
        if archive_version == 0x502:
            self._require_lz4_block()

        files = self._collect_repack_files(input_dir)
        self._check_u32(len(files), "BFPK Spacelords file count")
        output_path.parent.mkdir(parents=True, exist_ok=True)

        repack_files = self._prepare_repack_files(
            input_dir,
            files,
            output_path.name,
            compute_hash=True,
            include_total_bytes=True,
            progress=progress,
        )

        offset_field_positions: list[int] = []
        progress.start(
            f"Repacking {output_path.name}",
            total_items=len(repack_files),
            total_bytes=sum(file.uncompressed_size for file in repack_files),
        )
        with output_path.open("w+b") as output:
            try:
                self._write_repack_header(output, archive_version, len(repack_files), file_chunk_size)
                for repack_file in repack_files:
                    output.write(struct.pack("<I", len(repack_file.encoded_path)))
                    output.write(repack_file.encoded_path)
                    output.write(struct.pack("<I", repack_file.uncompressed_size))
                    offset_field_positions.append(output.tell())
                    output.write(b"\x00" * 8)
                    output.write(struct.pack("<I", repack_file.table_hash))
                    output.write(struct.pack("<I", 0))

                for repack_file, offset_position in zip(repack_files, offset_field_positions):
                    if archive_version == 0x500:
                        self._pad_output_to_alignment(output, self.spacelords_default_trailing_padding)
                    file_offset = output.tell()
                    self._check_u64(file_offset, f"BFPK Spacelords payload offset for {repack_file.path}")
                    output.seek(offset_position)
                    output.write(struct.pack("<Q", file_offset))
                    output.seek(0, 2)
                    self._write_spacelords_payload(output, repack_file, archive_version, file_chunk_size, progress)
                    progress.advance(items=1, detail=repack_file.path)

                if trailing_padding:
                    output.write(b"\x00" * trailing_padding)
            finally:
                progress.finish()

    def _repack_spacelords_d01(
        self,
        input_dir: Path,
        output_path: Path,
        options: dict[str, object],
        progress: ProgressReporter,
    ) -> None:
        self._repack_encrypted_picture_archive(
            input_dir,
            output_path,
            options,
            progress,
            archive_version=self.spacelords_d01_archive_version,
            label="BFPK Spacelords 0xD01",
            record_size=self._spacelords_d01_record_size,
            write_payload=self._write_spacelords_d01_payload,
        )

    def _repack_lords_of_shadow_ultimate(
        self,
        input_dir: Path,
        output_path: Path,
        options: dict[str, object],
        progress: ProgressReporter,
    ) -> None:
        archive_version = self._required_int_option(options, "archive_version")
        if archive_version not in self.lords_of_shadow_ultimate_archive_versions:
            raise UnsupportedOperation(
                "BFPK Lords of Shadow Ultimate Edition repack supports archive_version=0x2 or 0x3"
            )

        trailing_padding = self._int_option(options, "trailing_padding", 0)
        compression_level = self._int_option(options, "compression_level", self.default_compression_level)
        if trailing_padding < 0:
            raise ValueError("BFPK trailing_padding must be non-negative")

        input_dir = input_dir.resolve()
        output_path = output_path.resolve()
        self._validate_repack_paths(input_dir, output_path)

        files = self._collect_repack_files(input_dir)
        self._check_u32(len(files), "BFPK Lords of Shadow Ultimate Edition file count")
        output_path.parent.mkdir(parents=True, exist_ok=True)

        repack_files = self._prepare_repack_files(
            input_dir,
            files,
            output_path.name,
            compute_hash=False,
            include_total_bytes=True,
            progress=progress,
        )

        placeholder_offsets = [0] * len(repack_files)
        placeholder_table = self._build_lords_of_shadow_ultimate_table(repack_files, placeholder_offsets)
        encrypted_table_size = len(placeholder_table) - 16
        self._check_u32(encrypted_table_size, "BFPK Lords of Shadow Ultimate Edition encrypted table size")

        payload_offsets: list[int] = []
        progress.start(
            f"Repacking {output_path.name}",
            total_items=len(repack_files),
            total_bytes=sum(file.uncompressed_size for file in repack_files),
        )
        with output_path.open("w+b") as output:
            try:
                output.write(self.archive_magic)
                output.write(struct.pack("<I", archive_version))
                output.write(struct.pack("<I", encrypted_table_size))
                output.write(self._encrypt_lords_of_shadow_ultimate_table(placeholder_table))

                for repack_file in repack_files:
                    file_offset = output.tell()
                    self._check_u32(file_offset, f"BFPK Lords of Shadow Ultimate Edition payload offset for {repack_file.path}")
                    payload_offsets.append(file_offset)
                    if archive_version == 0x2:
                        self._write_raw_payload(output, repack_file.source_path, progress)
                    else:
                        self._write_lords_of_shadow_ultimate_zlib_payload(
                            output,
                            repack_file,
                            compression_level,
                            progress,
                        )
                    progress.advance(items=1, detail=repack_file.path)

                if trailing_padding:
                    output.write(b"\x00" * trailing_padding)

                table = self._build_lords_of_shadow_ultimate_table(repack_files, payload_offsets)
                if len(table) != len(placeholder_table):
                    raise ValueError("BFPK Lords of Shadow Ultimate Edition table size changed during repack")
                output.seek(12)
                output.write(self._encrypt_lords_of_shadow_ultimate_table(table))
            finally:
                progress.finish()

    def _build_lords_of_shadow_ultimate_table(
        self,
        repack_files: list[BfpkRepackFile],
        payload_offsets: list[int],
    ) -> bytes:
        if len(repack_files) != len(payload_offsets):
            raise ValueError("BFPK Lords of Shadow Ultimate Edition table offset count mismatch")

        table = bytearray(self.lords_of_shadow_ultimate_table_prefix)
        if len(table) != 16:
            raise ValueError("BFPK Lords of Shadow Ultimate Edition table prefix must be 16 bytes")
        table += struct.pack("<I", len(repack_files))
        for repack_file, payload_offset in zip(repack_files, payload_offsets):
            self._check_u32(payload_offset, f"BFPK Lords of Shadow Ultimate Edition payload offset for {repack_file.path}")
            table += struct.pack("<I", len(repack_file.encoded_path))
            table += repack_file.encoded_path
            table += struct.pack("<I", repack_file.uncompressed_size)
            table += struct.pack("<I", payload_offset)
        table += b"\x00" * ((-len(table)) % 16)
        return bytes(table)

    def _write_lords_of_shadow_ultimate_zlib_payload(
        self,
        output: BinaryIO,
        repack_file: BfpkRepackFile,
        compression_level: int,
        progress: ProgressReporter,
    ) -> int:
        data = repack_file.source_path.read_bytes()
        compressed = zlib.compress(data, compression_level)
        payload = data if len(compressed) == len(data) else compressed
        self._check_u32(len(payload), f"BFPK Lords of Shadow Ultimate Edition stored size for {repack_file.path}")
        output.write(struct.pack("<I", len(payload)))
        output.write(payload)
        progress.advance(bytes_count=len(data))
        return 4 + len(payload)

    def _repack_scrapland(
        self,
        input_dir: Path,
        output_path: Path,
        options: dict[str, object],
        progress: ProgressReporter,
    ) -> None:
        unsupported_options = set(options) - {"layout", "archive_version"}
        if unsupported_options:
            unsupported = ", ".join(sorted(unsupported_options))
            raise ValueError(f"BFPK Scrapland option is not supported: {unsupported}")
        archive_version = self._int_option(options, "archive_version", self.scrapland_archive_version)
        if archive_version != self.scrapland_archive_version:
            raise UnsupportedOperation("BFPK Scrapland repack supports only archive_version=0")

        input_dir = input_dir.resolve()
        output_path = output_path.resolve()
        self._validate_repack_paths(input_dir, output_path)

        files = self._collect_repack_files(input_dir)
        self._check_u32(len(files), "BFPK Scrapland file count")
        output_path.parent.mkdir(parents=True, exist_ok=True)

        repack_files = self._prepare_repack_files(
            input_dir,
            files,
            output_path.name,
            compute_hash=False,
            include_total_bytes=True,
            path_encoding=self.scrapland_path_encoding,
            progress=progress,
        )
        self._validate_scrapland_repack_paths(repack_files)

        table_size = sum(4 + len(file.encoded_path) + 4 + 4 for file in repack_files)
        current_offset = 12 + table_size
        payload_offsets: list[int] = []
        for repack_file in repack_files:
            self._check_u32(current_offset, f"BFPK Scrapland payload offset for {repack_file.path}")
            payload_offsets.append(current_offset)
            current_offset += repack_file.uncompressed_size
        self._check_u32(current_offset, "BFPK Scrapland archive size")

        progress.start(
            f"Repacking {output_path.name}",
            total_items=len(repack_files),
            total_bytes=sum(file.uncompressed_size for file in repack_files),
        )
        with output_path.open("w+b") as output:
            try:
                output.write(self.archive_magic)
                output.write(struct.pack("<I", self.scrapland_archive_version))
                output.write(struct.pack("<I", len(repack_files)))
                for repack_file, payload_offset in zip(repack_files, payload_offsets):
                    output.write(struct.pack("<I", len(repack_file.encoded_path)))
                    output.write(repack_file.encoded_path)
                    output.write(struct.pack("<I", repack_file.uncompressed_size))
                    output.write(struct.pack("<I", payload_offset))

                if output.tell() != (payload_offsets[0] if payload_offsets else 12):
                    raise ValueError("BFPK Scrapland repack offset calculation drifted")

                for repack_file in repack_files:
                    self._write_raw_payload(output, repack_file.source_path, progress)
                    progress.advance(items=1, detail=repack_file.path)
            finally:
                progress.finish()

    def _validate_scrapland_repack_paths(self, repack_files: list[BfpkRepackFile]) -> None:
        seen_paths: set[str] = set()
        for repack_file in repack_files:
            key = repack_file.path.casefold()
            if key in seen_paths:
                raise ValueError(f"BFPK Scrapland duplicate source path: {repack_file.path}")
            seen_paths.add(key)

    def _repack_encrypted_picture_archive(
        self,
        input_dir: Path,
        output_path: Path,
        options: dict[str, object],
        progress: ProgressReporter,
        *,
        archive_version: int,
        label: str,
        record_size: Callable[[BfpkRepackFile], int],
        write_payload: Callable[[BinaryIO, BfpkRepackFile, ProgressReporter], int],
    ) -> None:
        """Write the shared encrypted-table picture archive structure.

        Spacelords `0xD01` and Blades of Fire `0x901` use the same table cipher
        and alignment rules, but their per-record payload headers differ.
        """

        trailing_padding = self._int_option(options, "trailing_padding", self.spacelords_default_trailing_padding)
        if trailing_padding < 0:
            raise ValueError("BFPK trailing_padding must be non-negative")

        input_dir = input_dir.resolve()
        output_path = output_path.resolve()
        self._validate_repack_paths(input_dir, output_path)

        files = self._collect_repack_files(input_dir)
        self._check_u32(len(files), f"{label} file count")
        output_path.parent.mkdir(parents=True, exist_ok=True)

        repack_files = self._prepare_repack_files(
            input_dir,
            files,
            output_path.name,
            compute_hash=False,
            include_total_bytes=True,
            progress=progress,
        )

        table_size = 4 + sum(4 + len(file.encoded_path) + 4 + 8 + 4 + 4 + 4 for file in repack_files)
        current_offset = 8 + table_size
        current_offset += (-current_offset) % self.spacelords_default_trailing_padding
        record_offsets: list[int] = []
        for repack_file in repack_files:
            record_offsets.append(current_offset)
            current_offset += record_size(repack_file)
            current_offset += (-current_offset) % self.spacelords_default_trailing_padding

        table = self._build_encrypted_picture_table(repack_files, record_offsets, label)

        progress.start(
            f"Repacking {output_path.name}",
            total_items=len(repack_files),
            total_bytes=sum(file.uncompressed_size for file in repack_files),
        )
        with output_path.open("w+b") as output:
            try:
                output.write(self.archive_magic)
                output.write(struct.pack("<I", archive_version))
                output.write(self._crypt_spacelords_d01_table(table, 8))
                self._pad_output_to_alignment(output, self.spacelords_default_trailing_padding)

                for repack_file, record_offset in zip(repack_files, record_offsets):
                    if output.tell() != record_offset:
                        raise ValueError(f"{label} repack offset calculation drifted")
                    write_payload(output, repack_file, progress)
                    progress.advance(items=1, detail=repack_file.path)
                    self._pad_output_to_alignment(output, self.spacelords_default_trailing_padding)

                if trailing_padding:
                    output.write(b"\x00" * trailing_padding)
            finally:
                progress.finish()

    def _build_encrypted_picture_table(
        self,
        repack_files: list[BfpkRepackFile],
        record_offsets: list[int],
        label: str,
    ) -> bytes:
        table = bytearray()
        table += struct.pack("<I", len(repack_files))
        for repack_file, record_offset in zip(repack_files, record_offsets):
            self._check_u64(record_offset, f"{label} payload offset for {repack_file.path}")
            table += struct.pack("<I", len(repack_file.encoded_path))
            table += repack_file.encoded_path
            table += struct.pack("<I", repack_file.uncompressed_size)
            table += struct.pack("<Q", record_offset)
            # The games read this opaque table field but do not use it as a CRC during resource lookup.
            table += struct.pack("<I", repack_file.table_hash)
            table += struct.pack("<I", 0)
            table += struct.pack("<I", repack_file.uncompressed_size)
        return bytes(table)

    def _spacelords_d01_record_size(self, repack_file: BfpkRepackFile) -> int:
        if self._spacelords_d01_uses_embedded_first_payload_byte(repack_file):
            return 5 + repack_file.uncompressed_size
        return 6 + repack_file.uncompressed_size

    def _spacelords_d01_uses_embedded_first_payload_byte(self, repack_file: BfpkRepackFile) -> bool:
        suffix = repack_file.path.rsplit(".", 1)[-1].lower() if "." in repack_file.path else ""
        return suffix in {"gif", "tga"} and repack_file.uncompressed_size > 0

    def _write_spacelords_d01_payload(
        self,
        output: BinaryIO,
        repack_file: BfpkRepackFile,
        progress: ProgressReporter,
    ) -> int:
        data = repack_file.source_path.read_bytes()
        stored_size = len(data)
        self._check_u32(stored_size, f"BFPK Spacelords 0xD01 stored size for {repack_file.path}")
        output.write(struct.pack("<I", stored_size))

        if self._spacelords_d01_uses_embedded_first_payload_byte(repack_file):
            flag_low = (
                self.spacelords_d01_gif_record_flag_low
                if repack_file.path.lower().endswith(".gif")
                else self.spacelords_d01_tga_record_flag_low
            )
            flags = flag_low | (data[0] << 8)
            output.write(struct.pack("<H", flags))
            output.write(data[1:])
        else:
            output.write(struct.pack("<H", self.spacelords_d01_default_record_flags))
            output.write(data)

        progress.advance(bytes_count=stored_size)
        return self._spacelords_d01_record_size(repack_file)

    def _repack_file(
        self,
        input_dir: Path,
        file: Path,
        *,
        compute_hash: bool,
        path_encoding: str = "utf-8",
        progress: ProgressReporter,
    ) -> BfpkRepackFile:
        relative_path = file.relative_to(input_dir).as_posix()
        if not self._is_safe_archive_path(relative_path):
            raise ValueError(f"BFPK source path is unsafe: {relative_path}")
        try:
            encoded_path = relative_path.encode(path_encoding)
        except UnicodeEncodeError as exc:
            raise ValueError(f"BFPK source path cannot be encoded as {path_encoding}: {relative_path}") from exc
        self._check_u32(len(encoded_path), f"BFPK path length for {relative_path}")
        uncompressed_size = file.stat().st_size
        self._check_u32(uncompressed_size, f"BFPK uncompressed size for {relative_path}")
        table_hash = self._crc32_file(file, progress) if compute_hash else 0
        progress.advance(items=1, detail=relative_path)
        return BfpkRepackFile(file, relative_path, encoded_path, uncompressed_size, table_hash)

    def _prepare_repack_files(
        self,
        input_dir: Path,
        files: list[Path],
        output_name: str,
        *,
        compute_hash: bool,
        include_total_bytes: bool,
        path_encoding: str = "utf-8",
        progress: ProgressReporter,
    ) -> list[BfpkRepackFile]:
        total_bytes = sum(file.stat().st_size for file in files) if include_total_bytes else None
        progress.start(f"Preparing {output_name}", total_items=len(files), total_bytes=total_bytes)
        try:
            return [
                self._repack_file(input_dir, file, compute_hash=compute_hash, path_encoding=path_encoding, progress=progress)
                for file in files
            ]
        finally:
            progress.finish()

    def _write_repack_header(
        self,
        output: BinaryIO,
        archive_version: int,
        file_count: int,
        file_chunk_size: int,
    ) -> None:
        output.write(self.archive_magic)
        output.write(struct.pack("<I", archive_version))
        if self._has_chunked_header(archive_version):
            output.write(struct.pack("<I", file_chunk_size))
        output.write(struct.pack("<I", file_count))

    def _write_legacy_repack_payload(
        self,
        output: BinaryIO,
        repack_file: BfpkRepackFile,
        archive_version: int,
        file_chunk_size: int,
        compression_level: int,
        progress: ProgressReporter,
    ) -> int:
        if archive_version == 0x100:
            stored_size = self._write_raw_payload(output, repack_file.source_path, progress)
        elif archive_version == 0x101:
            stored_size = self._write_single_zlib_payload(
                output,
                repack_file.source_path,
                compression_level,
                progress,
            )
        elif archive_version == 0x102:
            stored_size = self._write_chunked_zlib_payload(
                output,
                repack_file.source_path,
                file_chunk_size,
                compression_level,
                progress,
            )
        else:
            raise UnsupportedOperation(f"BFPK archive version 0x{archive_version:x} is not supported for repacking")
        self._check_u32(stored_size, f"BFPK stored size for {repack_file.path}")
        self._check_u64(output.tell(), "BFPK archive size")
        return stored_size

    def _write_blades_of_fire_payload(
        self,
        output: BinaryIO,
        repack_file: BfpkRepackFile,
        archive_version: int,
        file_chunk_size: int,
        progress: ProgressReporter,
    ) -> int:
        if archive_version in {0x100, 0x300}:
            stored_size = self._write_raw_payload(output, repack_file.source_path, progress)
        elif archive_version == 0x102:
            stored_size = self._write_blades_of_fire_lz4_payload(
                output,
                repack_file.source_path,
                file_chunk_size,
                progress,
            )
        else:
            raise UnsupportedOperation(
                f"BFPK Blades of Fire archive version 0x{archive_version:x} is not supported for repacking"
            )
        self._check_u32(stored_size, f"BFPK Blades of Fire stored size for {repack_file.path}")
        self._check_u64(output.tell(), "BFPK Blades of Fire archive size")
        return stored_size

    def _write_spacelords_payload(
        self,
        output: BinaryIO,
        repack_file: BfpkRepackFile,
        archive_version: int,
        file_chunk_size: int,
        progress: ProgressReporter,
    ) -> int:
        if archive_version == 0x500:
            stored_size = self._write_raw_payload(output, repack_file.source_path, progress)
        elif archive_version == 0x502:
            stored_size = self._write_spacelords_lz4_payload(
                output,
                repack_file.source_path,
                file_chunk_size,
                progress,
            )
        else:
            raise UnsupportedOperation(
                f"BFPK Spacelords archive version 0x{archive_version:x} is not supported for repacking"
            )
        self._check_u32(stored_size, f"BFPK Spacelords stored size for {repack_file.path}")
        self._check_u64(output.tell(), "BFPK Spacelords archive size")
        return stored_size

    def _write_raw_payload(self, output: BinaryIO, file: Path, progress: ProgressReporter) -> int:
        start = output.tell()
        with file.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                output.write(chunk)
                progress.advance(bytes_count=len(chunk))
        return output.tell() - start

    def _write_single_zlib_payload(
        self,
        output: BinaryIO,
        file: Path,
        compression_level: int,
        progress: ProgressReporter,
    ) -> int:
        block_start = output.tell()
        output.write(b"\x00\x00\x00\x00")
        payload_start = output.tell()
        compressor = zlib.compressobj(compression_level)
        with file.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                compressed = compressor.compress(chunk)
                if compressed:
                    output.write(compressed)
                progress.advance(bytes_count=len(chunk))
        flushed = compressor.flush()
        if flushed:
            output.write(flushed)

        payload_end = output.tell()
        compressed_size = payload_end - payload_start
        self._check_u32(compressed_size, f"BFPK compressed size for {file}")
        output.seek(block_start)
        output.write(struct.pack("<I", compressed_size))
        output.seek(payload_end)
        return 4 + compressed_size

    def _write_chunked_zlib_payload(
        self,
        output: BinaryIO,
        file: Path,
        file_chunk_size: int,
        compression_level: int,
        progress: ProgressReporter,
    ) -> int:
        block_start = output.tell()
        output.write(b"\x00\x00\x00\x00")
        payload_start = output.tell()
        with file.open("rb") as source:
            while chunk := source.read(file_chunk_size):
                compressed = zlib.compress(chunk, compression_level)
                self._check_u32(len(compressed), f"BFPK chunk compressed size for {file}")
                output.write(struct.pack("<I", len(compressed)))
                output.write(compressed)
                progress.advance(bytes_count=len(chunk))

        payload_end = output.tell()
        stored_block_size = payload_end - payload_start
        self._check_u32(stored_block_size, f"BFPK stored block size for {file}")
        output.seek(block_start)
        output.write(struct.pack("<I", stored_block_size))
        output.seek(payload_end)
        return 4 + stored_block_size

    def _write_blades_of_fire_lz4_payload(
        self,
        output: BinaryIO,
        file: Path,
        file_chunk_size: int,
        progress: ProgressReporter,
    ) -> int:
        lz4_block = self._require_lz4_block()
        block_start = output.tell()
        output.write(b"\x00\x00\x00\x00")
        output.write(struct.pack("<I", 1))
        with file.open("rb") as source:
            while chunk := source.read(file_chunk_size):
                compressed = lz4_block.compress(chunk, store_size=False)
                self._check_u32(len(compressed), f"BFPK Blades of Fire chunk compressed size for {file}")
                output.write(struct.pack("<I", len(compressed)))
                output.write(struct.pack("<I", self._xxh32(compressed)))
                output.write(compressed)
                progress.advance(bytes_count=len(chunk))

        payload_end = output.tell()
        stored_block_size = payload_end - block_start
        self._check_u32(stored_block_size, f"BFPK Blades of Fire stored block size for {file}")
        output.seek(block_start)
        output.write(struct.pack("<I", stored_block_size))
        output.seek(payload_end)
        return stored_block_size

    def _write_spacelords_lz4_payload(
        self,
        output: BinaryIO,
        file: Path,
        file_chunk_size: int,
        progress: ProgressReporter,
    ) -> int:
        lz4_block = self._require_lz4_block()
        block_start = output.tell()
        output.write(b"\x00\x00\x00\x00")
        payload_start = output.tell()
        with file.open("rb") as source:
            while chunk := source.read(file_chunk_size):
                compressed = lz4_block.compress(chunk, store_size=False)
                self._check_u32(len(compressed), f"BFPK Spacelords chunk compressed size for {file}")
                output.write(struct.pack("<I", len(compressed)))
                output.write(struct.pack("<I", self._xxh32(compressed)))
                output.write(compressed)
                progress.advance(bytes_count=len(chunk))

        payload_end = output.tell()
        stored_block_size = payload_end - payload_start
        self._check_u32(stored_block_size, f"BFPK Spacelords stored block size for {file}")
        output.seek(block_start)
        output.write(struct.pack("<I", stored_block_size))
        output.seek(payload_end)
        return 4 + stored_block_size

    def _pad_output_to_alignment(self, output: BinaryIO, alignment: int) -> None:
        padding = (-output.tell()) % alignment
        if padding:
            output.write(b"\x00" * padding)

    def _collect_repack_files(self, input_dir: Path) -> list[Path]:
        files = (path for path in input_dir.rglob("*") if path.is_file())
        return sorted(files, key=lambda path: path.relative_to(input_dir).as_posix())

    def _validate_repack_paths(self, input_dir: Path, output_path: Path) -> None:
        if not input_dir.is_dir():
            raise FileNotFoundError(f"Source directory does not exist: {input_dir}")
        self._reject_output_inside_source(input_dir, output_path)

    def _validate_repack_options(self, file_chunk_size: int, trailing_padding: int) -> None:
        if file_chunk_size <= 0:
            raise ValueError("BFPK file_chunk_size must be positive")
        if trailing_padding < 0:
            raise ValueError("BFPK trailing_padding must be non-negative")

    def _reject_output_inside_source(self, input_dir: Path, output_path: Path) -> None:
        try:
            output_path.relative_to(input_dir)
        except ValueError:
            return
        raise ValueError("BFPK output archive cannot be written inside the source directory")

    def _layout_option(self, options: dict[str, object]) -> str:
        raw_layout = options.get("layout", self.legacy_layout)
        if not isinstance(raw_layout, str):
            raise ValueError("BFPK option layout must be a string")
        layout = raw_layout.strip().lower().replace("-", "_")
        if layout in {"legacy", "los2"}:
            return self.legacy_layout
        if layout in {"blades_of_fire", "bladesoffire"}:
            return self.blades_of_fire_layout
        if layout in {"spacelords", "spacelord", "raiders_of_the_broken_planet", "raidersofthebrokenplanet"}:
            return self.spacelords_layout
        if layout in {
            "lords_of_shadow_ultimate",
            "lords_of_shadow_ultimate_edition",
            "losue",
            "los_ultimate",
            "castlevania_lords_of_shadow_ultimate_edition",
        }:
            return self.lords_of_shadow_ultimate_layout
        if layout in {"scrapland", "scrapland_remastered"}:
            return self.scrapland_layout
        raise ValueError(f"BFPK layout is not supported: {raw_layout}")

    def _required_int_option(self, options: dict[str, object], key: str) -> int:
        if key not in options:
            raise ValueError(f"BFPK repack requires option {key}")
        return self._coerce_int_option(options[key], key)

    def _int_option(self, options: dict[str, object], key: str, default: int) -> int:
        if key not in options:
            return default
        return self._coerce_int_option(options[key], key)

    def _coerce_int_option(self, value: object, key: str) -> int:
        if isinstance(value, bool):
            raise ValueError(f"BFPK option {key} must be an integer")
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            try:
                return int(value, 0)
            except ValueError as exc:
                raise ValueError(f"BFPK option {key} must be an integer") from exc
        raise ValueError(f"BFPK option {key} must be an integer")

    def _crc32_file(self, file: Path, progress: ProgressReporter) -> int:
        crc = 0
        with file.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                crc = zlib.crc32(chunk, crc)
                progress.advance(bytes_count=len(chunk))
        return crc & self.max_u32

