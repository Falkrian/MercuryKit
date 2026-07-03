from __future__ import annotations

import struct
import zlib
from pathlib import PurePosixPath
from typing import BinaryIO

from mercurykit.archive import ArchiveContext, ArchiveEntry
from mercurykit.binary import EndOfStreamError

_PACKED_LZ4_TRANSFORM = "blades-packed-lz4"


def try_restore_blades_picture(
    context: ArchiveContext,
    entry: ArchiveEntry,
    output_stream: BinaryIO,
) -> bool:
    """Write a viewer-ready Blades of Fire picture when a transform is proven.

    Blades of Fire `Pics.packed` records keep the raw packed bytes as the
    repack source of truth. Restore mode follows the game loader's
    `CTexture::LoadImagePacked` path: the record starts with a packed-size
    DWORD, a mode DWORD, then an LZ4 block that expands to the table's declared
    picture size.
    """

    if _can_restore_packed_lz4(entry):
        return _try_restore_packed_lz4(context, entry, output_stream)
    return False


def _can_restore_packed_lz4(entry: ArchiveEntry) -> bool:
    return (
        isinstance(entry.path, str)
        and _picture_suffix(entry.path) in {".dds", ".gif", ".jpg", ".jpeg", ".png"}
        and entry.metadata.get("restore_transform") == _PACKED_LZ4_TRANSFORM
    )


def _try_restore_packed_lz4(
    context: ArchiveContext,
    entry: ArchiveEntry,
    output_stream: BinaryIO,
) -> bool:
    try:
        restored = _restore_packed_lz4_record(context, entry)
    except (EndOfStreamError, ValueError):
        return False
    if not _valid_restored_picture(entry, restored):
        return False
    output_stream.write(restored)
    return True


def _restore_packed_lz4_record(context: ArchiveContext, entry: ArchiveEntry) -> bytes:
    record_offset = entry.metadata.get("record_offset")
    packed_size = entry.metadata.get("raw_payload_size")
    declared_size = entry.metadata.get("declared_size")
    if not isinstance(record_offset, int) or not isinstance(packed_size, int) or not isinstance(declared_size, int):
        raise ValueError(f"Entry {entry.path or entry.entry_id or '<unnamed>'} does not define restore metadata")

    with context.archive_path.open("rb") as file:
        file.seek(record_offset)
        record = file.read(packed_size)
    if len(record) != packed_size:
        raise EndOfStreamError(f"Entry {entry.path or entry.entry_id or '<unnamed>'} restore record extends beyond archive data")

    return _decode_packed_lz4_record(record, declared_size)


def _decode_packed_lz4_record(record: bytes, expected_size: int) -> bytes:
    if len(record) < 8:
        raise EndOfStreamError("Blades packed picture record is too small")
    packed_size, mode = struct.unpack_from("<II", record, 0)
    if packed_size != len(record):
        raise ValueError("Blades packed picture record size does not match")

    if mode == 0:
        return _decompress_lz4_block(record[8:], expected_size)

    output = bytearray()
    offset = 8
    while offset < len(record):
        if offset + 8 > len(record):
            raise EndOfStreamError("Blades packed picture chunk header extends beyond record")
        chunk_size, _chunk_hash = struct.unpack_from("<II", record, offset)
        offset += 8
        if offset + chunk_size > len(record):
            raise EndOfStreamError("Blades packed picture chunk extends beyond record")
        remaining = expected_size - len(output)
        output.extend(_decompress_lz4_block(record[offset : offset + chunk_size], remaining))
        offset += chunk_size

    if len(output) != expected_size:
        raise ValueError("Blades packed picture chunks decompressed to unexpected size")
    return bytes(output)


def _decompress_lz4_block(data: bytes, expected_size: int) -> bytes:
    output = bytearray()
    index = 0
    while index < len(data):
        token = data[index]
        index += 1
        literal_length = token >> 4
        if literal_length == 15:
            while True:
                if index >= len(data):
                    raise EndOfStreamError("Blades LZ4 literal length extends beyond chunk")
                value = data[index]
                index += 1
                literal_length += value
                if value != 255:
                    break

        if index + literal_length > len(data):
            raise EndOfStreamError("Blades LZ4 literal data extends beyond chunk")
        output.extend(data[index : index + literal_length])
        index += literal_length
        if index >= len(data):
            break

        if index + 2 > len(data):
            raise EndOfStreamError("Blades LZ4 match offset extends beyond chunk")
        offset = data[index] | (data[index + 1] << 8)
        index += 2
        if offset == 0 or offset > len(output):
            raise ValueError("Blades LZ4 match offset is invalid")

        match_length = (token & 0x0F) + 4
        if (token & 0x0F) == 15:
            while True:
                if index >= len(data):
                    raise EndOfStreamError("Blades LZ4 match length extends beyond chunk")
                value = data[index]
                index += 1
                match_length += value
                if value != 255:
                    break

        start = len(output) - offset
        for offset_index in range(match_length):
            output.append(output[start + offset_index])

    if len(output) != expected_size:
        raise ValueError("Blades LZ4 chunk decompressed to unexpected size")
    return bytes(output)


def _valid_restored_picture(entry: ArchiveEntry, data: bytes) -> bool:
    suffix = _picture_suffix(entry.path or "")
    if suffix == ".dds":
        return _valid_dds(data)
    if suffix == ".gif":
        return gif_stream_end(data) == len(data)
    if suffix == ".png":
        return _valid_png(data)
    if suffix in {".jpg", ".jpeg"}:
        return _valid_jpeg(data)
    return False


def _picture_suffix(path: str) -> str:
    return PurePosixPath(path).suffix.lower()


def _valid_dds(data: bytes) -> bool:
    return len(data) >= 128 and data.startswith(b"DDS ") and data[4:8] == b"\x7c\x00\x00\x00"


def _valid_png(data: bytes) -> bool:
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return False

    offset = 8
    while offset + 12 <= len(data):
        chunk_size = int.from_bytes(data[offset : offset + 4], "big")
        chunk_type = data[offset + 4 : offset + 8]
        chunk_start = offset + 8
        chunk_end = chunk_start + chunk_size
        crc_end = chunk_end + 4
        if crc_end > len(data):
            return False
        expected_crc = int.from_bytes(data[chunk_end:crc_end], "big")
        actual_crc = zlib.crc32(chunk_type + data[chunk_start:chunk_end]) & 0xFFFFFFFF
        if actual_crc != expected_crc:
            return False
        offset = crc_end
        if chunk_type == b"IEND":
            return offset == len(data)
    return False


def _valid_jpeg(data: bytes) -> bool:
    if not data.startswith(b"\xff\xd8"):
        return False

    offset = 2
    while offset < len(data):
        if data[offset] != 0xFF:
            marker_offset = data.find(b"\xff", offset)
            if marker_offset < 0:
                return False
            offset = marker_offset

        while offset < len(data) and data[offset] == 0xFF:
            offset += 1
        if offset >= len(data):
            return False

        marker = data[offset]
        offset += 1
        if marker == 0xD9:
            return offset == len(data)
        if marker == 0x00 or marker == 0x01 or 0xD0 <= marker <= 0xD7:
            continue

        if offset + 2 > len(data):
            return False
        segment_size = int.from_bytes(data[offset : offset + 2], "big")
        if segment_size < 2 or offset + segment_size > len(data):
            return False
        offset += segment_size

    return False


def gif_stream_end(data: bytes) -> int | None:
    """Return the end offset of a complete GIF stream, ignoring trailing bytes."""

    if len(data) < 13 or not data.startswith((b"GIF87a", b"GIF89a")):
        return None

    offset = 13
    packed = data[10]
    if packed & 0x80:
        offset += 3 * (1 << ((packed & 0x07) + 1))
    if offset > len(data):
        return None

    while offset < len(data):
        block_type = data[offset]
        offset += 1
        if block_type == 0x3B:
            return offset

        if block_type == 0x21:
            if offset >= len(data):
                return None
            offset += 1
            offset = _skip_gif_sub_blocks(data, offset)
            if offset is None:
                return None
            continue

        if block_type == 0x2C:
            if offset + 9 > len(data):
                return None
            image_packed = data[offset + 8]
            offset += 9
            if image_packed & 0x80:
                offset += 3 * (1 << ((image_packed & 0x07) + 1))
            if offset >= len(data):
                return None
            offset += 1
            offset = _skip_gif_sub_blocks(data, offset)
            if offset is None:
                return None
            continue

        return None

    return None


def _skip_gif_sub_blocks(data: bytes, offset: int) -> int | None:
    while offset < len(data):
        block_size = data[offset]
        offset += 1
        if block_size == 0:
            return offset
        offset += block_size
        if offset > len(data):
            return None
    return None
