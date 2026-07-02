from __future__ import annotations

import builtins
from io import BytesIO, StringIO
import importlib.util
from pathlib import Path
import struct
import zlib

import pytest

from mercurykit.archive import ArchiveContext, ArchiveEntry, ArchiveInfo, UnsupportedOperation
from mercurykit.bfpk import BfpkEngine
from mercurykit.binary import BinaryReader
from mercurykit.cli import _extract_context, _format_entry, _parse_archive_options, main
from mercurykit.mirror_of_fate import MirrorOfFatePackEngine
from mercurykit.progress import TerminalProgressReporter
from mercurykit.scanner import ArchiveScanner, NoArchiveError


# Archive builders


def _build_bfpk_100_archive(path: Path, files: dict[str, bytes], *, padding_size: int = 0x20) -> None:
    header_size = 12
    table_size = sum(4 + len(name.encode("utf-8")) + 4 + 8 for name in files)
    current_offset = header_size + table_size
    table = bytearray()
    payloads: list[bytes] = []

    for name, data in files.items():
        encoded_name = name.encode("utf-8")
        table += len(encoded_name).to_bytes(4, "little")
        table += encoded_name
        table += len(data).to_bytes(4, "little")
        table += current_offset.to_bytes(8, "little")
        payloads.append(data)
        current_offset += len(data)

    archive = bytearray()
    archive += b"BFPK"
    archive += (0x100).to_bytes(4, "little")
    archive += len(files).to_bytes(4, "little")
    archive += table
    archive += b"".join(payloads)
    archive += b"\x00" * padding_size
    path.write_bytes(bytes(archive))


def _build_bfpk_101_archive(path: Path, files: dict[str, bytes], *, padding_size: int = 0x20) -> None:
    header_size = 12
    table_size = sum(4 + len(name.encode("utf-8")) + 4 + 8 for name in files)
    current_offset = header_size + table_size
    table = bytearray()
    payloads: list[bytes] = []

    for name, data in files.items():
        encoded_name = name.encode("utf-8")
        compressed = zlib.compress(data)
        payload = len(compressed).to_bytes(4, "little") + compressed
        table += len(encoded_name).to_bytes(4, "little")
        table += encoded_name
        table += len(data).to_bytes(4, "little")
        table += current_offset.to_bytes(8, "little")
        payloads.append(payload)
        current_offset += len(payload)

    archive = bytearray()
    archive += b"BFPK"
    archive += (0x101).to_bytes(4, "little")
    archive += len(files).to_bytes(4, "little")
    archive += table
    archive += b"".join(payloads)
    archive += b"\x00" * padding_size
    path.write_bytes(bytes(archive))


def _build_bfpk_102_archive(path: Path, files: dict[str, bytes], *, chunk_size: int = 5) -> None:
    header_size = 16
    table_size = sum(4 + len(name.encode("utf-8")) + 4 + 8 for name in files)
    current_offset = header_size + table_size
    table = bytearray()
    payloads: list[bytes] = []

    for name, data in files.items():
        encoded_name = name.encode("utf-8")
        block = bytearray()
        for start in range(0, len(data), chunk_size):
            compressed = zlib.compress(data[start : start + chunk_size])
            block += len(compressed).to_bytes(4, "little")
            block += compressed

        payload = len(block).to_bytes(4, "little") + block
        table += len(encoded_name).to_bytes(4, "little")
        table += encoded_name
        table += len(data).to_bytes(4, "little")
        table += current_offset.to_bytes(8, "little")
        payloads.append(bytes(payload))
        current_offset += len(payload)

    archive = bytearray()
    archive += b"BFPK"
    archive += (0x102).to_bytes(4, "little")
    archive += chunk_size.to_bytes(4, "little")
    archive += len(files).to_bytes(4, "little")
    archive += table
    archive += b"".join(payloads)
    path.write_bytes(bytes(archive))


def _lz4_literal_block(data: bytes) -> bytes:
    block = bytearray()
    literal_length = len(data)
    if literal_length < 15:
        block.append(literal_length << 4)
    else:
        block.append(0xF0)
        remaining = literal_length - 15
        while remaining >= 255:
            block.append(255)
            remaining -= 255
        block.append(remaining)
    block += data
    return bytes(block)


def _build_blades_of_fire_bfpk_archive(
    path: Path,
    files: dict[str, bytes],
    archive_version: int,
    *,
    chunk_size: int = 4,
    padding_size: int = 0x20,
) -> None:
    header_size = 16 if archive_version == 0x102 else 12
    table_size = sum(4 + len(name.encode("utf-8")) + 4 + 8 + 4 + 4 + 4 for name in files)
    current_offset = header_size + table_size
    table = bytearray()
    payloads: list[bytes] = []
    engine = BfpkEngine()

    for name, data in files.items():
        encoded_name = name.encode("utf-8")
        table_hash = zlib.crc32(data) & 0xFFFFFFFF
        if archive_version == 0x102:
            payload = bytearray(b"\x00\x00\x00\x00")
            payload += (1).to_bytes(4, "little")
            for start in range(0, len(data), chunk_size):
                compressed = _lz4_literal_block(data[start : start + chunk_size])
                payload += len(compressed).to_bytes(4, "little")
                payload += engine._xxh32(compressed).to_bytes(4, "little")
                payload += compressed
            payload[0:4] = len(payload).to_bytes(4, "little")
            aux1 = len(payload)
        else:
            payload = bytearray(data)
            aux1 = 0

        table += len(encoded_name).to_bytes(4, "little")
        table += encoded_name
        table += len(data).to_bytes(4, "little")
        table += current_offset.to_bytes(8, "little")
        table += table_hash.to_bytes(4, "little")
        table += (0).to_bytes(4, "little")
        table += aux1.to_bytes(4, "little")
        payloads.append(bytes(payload))
        current_offset += len(payload)

    archive = bytearray()
    archive += b"BFPK"
    archive += archive_version.to_bytes(4, "little")
    if archive_version == 0x102:
        archive += chunk_size.to_bytes(4, "little")
    archive += len(files).to_bytes(4, "little")
    archive += table
    archive += b"".join(payloads)
    archive += b"\x00" * padding_size
    path.write_bytes(bytes(archive))


def _build_spacelords_bfpk_archive(
    path: Path,
    files: dict[str, bytes],
    archive_version: int,
    *,
    chunk_size: int = 4,
    alignment: int = 0x10000,
) -> None:
    header_size = 16 if archive_version == 0x502 else 12
    table_size = sum(4 + len(name.encode("utf-8")) + 4 + 8 + 4 + 4 for name in files)
    current_offset = header_size + table_size
    if archive_version == 0x500:
        current_offset += (-current_offset) % alignment

    table = bytearray()
    payloads: list[bytes] = []
    engine = BfpkEngine()

    for name, data in files.items():
        encoded_name = name.encode("utf-8")
        table_hash = zlib.crc32(data) & 0xFFFFFFFF
        if archive_version == 0x500:
            payload = data
        else:
            block = bytearray()
            for start in range(0, len(data), chunk_size):
                compressed = _lz4_literal_block(data[start : start + chunk_size])
                block += len(compressed).to_bytes(4, "little")
                block += engine._xxh32(compressed).to_bytes(4, "little")
                block += compressed
            payload = len(block).to_bytes(4, "little") + bytes(block)

        table += len(encoded_name).to_bytes(4, "little")
        table += encoded_name
        table += len(data).to_bytes(4, "little")
        table += current_offset.to_bytes(8, "little")
        table += table_hash.to_bytes(4, "little")
        table += (0).to_bytes(4, "little")
        payloads.append(payload)
        current_offset += len(payload)
        if archive_version == 0x500:
            padding = b"\x00" * ((-current_offset) % alignment)
            payloads.append(padding)
            current_offset += len(padding)

    archive = bytearray()
    archive += b"BFPK"
    archive += archive_version.to_bytes(4, "little")
    if archive_version == 0x502:
        archive += chunk_size.to_bytes(4, "little")
    archive += len(files).to_bytes(4, "little")
    archive += table
    if archive_version == 0x500:
        archive += b"\x00" * ((-len(archive)) % alignment)
    archive += b"".join(payloads)
    archive += b"\x00" * alignment
    path.write_bytes(bytes(archive))


def _spacelords_d01_record_payload(name: str, data: bytes) -> bytes:
    record = bytearray()
    record += len(data).to_bytes(4, "little")
    lower_name = name.lower()
    if lower_name.endswith(".gif") or lower_name.endswith(".tga"):
        flag_low = 0xDF if lower_name.endswith(".gif") else 0x44
        first_byte = data[0] if data else 0
        record += (flag_low | (first_byte << 8)).to_bytes(2, "little")
        record += data[1:]
    else:
        record += (0x00F1).to_bytes(2, "little")
        record += data
    return bytes(record)


def _blades_of_fire_pics_record_payload(name: str, data: bytes, *, embed_jpg_first_byte: bool = False) -> bytes:
    record = bytearray()
    record += len(data).to_bytes(4, "little")
    record += (0).to_bytes(4, "little")
    lower_name = name.lower()
    if lower_name.endswith(".gif"):
        first_byte = data[0] if data else 0
        record += (0xC0 | (first_byte << 8)).to_bytes(2, "little")
        record += data[1:]
    elif embed_jpg_first_byte and (lower_name.endswith(".jpg") or lower_name.endswith(".jpeg")):
        first_byte = data[0] if data else 0
        record += (0x8F | (first_byte << 8)).to_bytes(2, "little")
        record += data[1:]
    else:
        record += (0x09FF).to_bytes(2, "little")
        record += data
    return bytes(record)


def _build_blades_of_fire_pics_archive(
    path: Path,
    files: dict[str, bytes],
    *,
    alignment: int = 0x10000,
    opaque_hash: int = 0xA1B2C3D4,
    embedded_jpgs: set[str] | None = None,
) -> None:
    engine = BfpkEngine()
    embedded_jpgs = embedded_jpgs or set()
    table_size = 4 + sum(4 + len(name.encode("utf-8")) + 4 + 8 + 4 + 4 + 4 for name in files)
    current_offset = 8 + table_size
    current_offset += (-current_offset) % alignment
    table = bytearray()
    payloads: list[bytes] = []

    table += len(files).to_bytes(4, "little")
    for name, data in files.items():
        encoded_name = name.encode("utf-8")
        payload = _blades_of_fire_pics_record_payload(name, data, embed_jpg_first_byte=name in embedded_jpgs)
        table += len(encoded_name).to_bytes(4, "little")
        table += encoded_name
        table += (len(data) + 3).to_bytes(4, "little")
        table += current_offset.to_bytes(8, "little")
        table += opaque_hash.to_bytes(4, "little")
        table += (0).to_bytes(4, "little")
        table += len(data).to_bytes(4, "little")
        payloads.append(payload)
        current_offset += len(payload)
        payloads.append(b"\x00" * ((-current_offset) % alignment))
        current_offset += len(payloads[-1])

    archive = bytearray()
    archive += b"BFPK"
    archive += (0x901).to_bytes(4, "little")
    archive += engine._crypt_spacelords_d01_table(bytes(table), 8)
    archive += b"\x00" * ((-len(archive)) % alignment)
    archive += b"".join(payloads)
    archive += b"\x00" * alignment
    path.write_bytes(bytes(archive))


def _build_spacelords_d01_archive(
    path: Path,
    files: dict[str, bytes],
    *,
    alignment: int = 0x10000,
    opaque_hash: int = 0x12345678,
) -> None:
    engine = BfpkEngine()
    table_size = 4 + sum(4 + len(name.encode("utf-8")) + 4 + 8 + 4 + 4 + 4 for name in files)
    current_offset = 8 + table_size
    current_offset += (-current_offset) % alignment
    table = bytearray()
    payloads: list[bytes] = []

    table += len(files).to_bytes(4, "little")
    for name, data in files.items():
        encoded_name = name.encode("utf-8")
        payload = _spacelords_d01_record_payload(name, data)
        table += len(encoded_name).to_bytes(4, "little")
        table += encoded_name
        table += (len(data) + 7).to_bytes(4, "little")
        table += current_offset.to_bytes(8, "little")
        table += opaque_hash.to_bytes(4, "little")
        table += (0).to_bytes(4, "little")
        table += len(data).to_bytes(4, "little")
        payloads.append(payload)
        current_offset += len(payload)
        payloads.append(b"\x00" * ((-current_offset) % alignment))
        current_offset += len(payloads[-1])

    archive = bytearray()
    archive += b"BFPK"
    archive += (0xD01).to_bytes(4, "little")
    archive += engine._crypt_spacelords_d01_table(bytes(table), 8)
    archive += b"\x00" * ((-len(archive)) % alignment)
    archive += b"".join(payloads)
    archive += b"\x00" * alignment
    path.write_bytes(bytes(archive))


def _build_lords_of_shadow_ultimate_dat_archive(
    path: Path,
    files: dict[str, bytes],
    archive_version: int,
    *,
    table_prefix: bytes = b"\x82\xa0\xf1\x30\xaf\x30\x2f\xe6\x7a\xe8\x5b\xb0\x54\xc3\xb7\x1f",
    raw_zlib_records: set[str] | None = None,
) -> None:
    if archive_version not in {0x2, 0x3}:
        raise ValueError("LoS UE test archives support only 0x2 and 0x3")
    if len(table_prefix) != 16:
        raise ValueError("LoS UE table prefix must be 16 bytes")

    engine = BfpkEngine()
    raw_zlib_records = raw_zlib_records or set()

    def payload_for(name: str, data: bytes) -> bytes:
        if archive_version == 0x2:
            return data
        if name in raw_zlib_records:
            return len(data).to_bytes(4, "little") + data
        compressed = zlib.compress(data)
        return len(compressed).to_bytes(4, "little") + compressed

    payloads = [(name, payload_for(name, data)) for name, data in files.items()]

    def table_for(offsets: list[int]) -> bytes:
        table = bytearray(table_prefix)
        table += len(files).to_bytes(4, "little")
        for (name, data), offset in zip(files.items(), offsets):
            encoded_name = name.encode("utf-8")
            table += len(encoded_name).to_bytes(4, "little")
            table += encoded_name
            table += len(data).to_bytes(4, "little")
            table += offset.to_bytes(4, "little")
        table += b"\x00" * ((-len(table)) % 16)
        return bytes(table)

    placeholder_table = table_for([0] * len(files))
    current_offset = 12 + len(placeholder_table)
    offsets = []
    for _, payload in payloads:
        offsets.append(current_offset)
        current_offset += len(payload)

    table = table_for(offsets)
    assert len(table) == len(placeholder_table)
    archive = bytearray()
    archive += b"BFPK"
    archive += archive_version.to_bytes(4, "little")
    archive += (len(table) - 16).to_bytes(4, "little")
    archive += engine._encrypt_lords_of_shadow_ultimate_table(table)
    for _, payload in payloads:
        archive += payload
    path.write_bytes(bytes(archive))


def _build_mirror_of_fate_pack(
    path: Path,
    files: list[tuple[str, bytes]],
    *,
    pack_size: int | None = None,
    alignment: int = 128,
) -> None:
    table_end = 12 + len(files) * 1032
    target_mod = table_end % alignment
    table = bytearray()
    payload = bytearray()
    records: list[tuple[bytes, int, int]] = []

    for archive_path, data in files:
        padding = (target_mod - ((table_end + len(payload)) % alignment)) % alignment
        payload += b"\x00" * padding
        start = table_end + len(payload)
        payload += data
        end = table_end + len(payload)
        records.append((archive_path.encode("utf-8"), start, end))

    payload += b"\x00" * ((target_mod - ((table_end + len(payload)) % alignment)) % alignment)

    actual_pack_size = len(payload)
    archive = bytearray(struct.pack("<III", table_end - 4, actual_pack_size if pack_size is None else pack_size, len(files)))
    for encoded_path, start, end in records:
        archive += encoded_path.ljust(1024, b"\x00")
        archive += struct.pack("<II", start, end)
    archive += payload
    path.write_bytes(bytes(archive))


# Shared extraction helpers


def _write_source_files(source: Path, files: dict[str, bytes]) -> None:
    for name, data in files.items():
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


def _extract_all(archive: Path) -> dict[str, bytes]:
    engine = BfpkEngine()
    context = engine.open(archive)
    extracted = {}
    for entry in engine.iter_entries(context):
        output = BytesIO()
        engine.extract_entry(context, entry, output)
        assert entry.path is not None
        extracted[entry.path] = output.getvalue()
    return extracted


def _extract_all_mirror_of_fate(archive: Path) -> dict[str, bytes]:
    engine = MirrorOfFatePackEngine()
    context = engine.open(archive)
    extracted = {}
    for entry in engine.iter_entries(context):
        output = BytesIO()
        engine.extract_entry(context, entry, output)
        assert entry.path is not None
        extracted[entry.path] = output.getvalue()
    return extracted


def _mirror_of_fate_toc_pairs(data: bytes) -> dict[int, int]:
    return dict(struct.iter_unpack("<II", data))


def _bfpk_entry_end(entry: ArchiveEntry) -> int:
    assert entry.offset is not None
    assert entry.stored_size is not None
    if entry.metadata["archive_version"] == 0x101:
        return entry.offset - 4 + entry.stored_size
    return entry.offset + entry.stored_size


def _has_strict_jpeg_marker_sequence(data: bytes) -> bool:
    if not data.startswith(b"\xFF\xD8"):
        return False
    index = 2
    while index < len(data):
        if data[index] != 0xFF:
            return False
        while index < len(data) and data[index] == 0xFF:
            index += 1
        if index >= len(data):
            return False
        marker = data[index]
        index += 1
        if marker == 0xD9:
            return True
        if marker == 0x01 or 0xD0 <= marker <= 0xD7:
            continue
        if index + 2 > len(data):
            return False
        segment_length = int.from_bytes(data[index:index + 2], "big")
        if segment_length < 2:
            return False
        if marker == 0xDA:
            return b"\xFF\xD9" in data[index + segment_length :]
        index += segment_length
    return False


# Manifest and extraction behavior


def test_bfpk_engine_public_import_and_sparse_manifest(tmp_path: Path) -> None:
    archive = tmp_path / "empty.bfpk"
    archive.write_bytes(b"BFPK" + (0x100).to_bytes(4, "little") + (0).to_bytes(4, "little"))

    with archive.open("rb") as file:
        info = BfpkEngine().read_manifest(archive, BinaryReader(file))

    assert info.format_name == "MercurySteam BFPK Archive"
    assert info.entry_count == 0


def test_bfpk_legacy_manifest_extract_and_verbose_scan(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    archive = tmp_path / "raw.bfpk"
    files = {"voice/a.ogg": b"OggSvoice-a", "voice/b.ogg": b"OggSvoice-b-longer"}
    _build_bfpk_100_archive(archive, files, padding_size=0x8000)

    with archive.open("rb") as file:
        info = BfpkEngine().read_manifest(archive, BinaryReader(file))
    entries = info.metadata["entries"]
    assert info.entry_count == 2
    assert entries[0].path == "voice/a.ogg"
    assert entries[0].stored_size == entries[0].uncompressed_size
    assert entries[0].metadata["archive_version"] == 0x100
    assert _extract_all(archive) == files

    assert main(["scan", str(archive), "--verbose"]) == 0
    output = capsys.readouterr().out
    assert "MercurySteam BFPK Archive" in output
    assert "BFPK legacy layout matched" in output
    assert "Entries = 2" in output
    assert "path='voice/a.ogg'" in output
    assert "stored_size=11" in output


def test_bfpk_zlib_layouts_manifest_and_extract(tmp_path: Path) -> None:
    single = tmp_path / "single.bfpk"
    chunked = tmp_path / "chunked.bfpk"
    files = {"data/a.bin": b"alpha" * 20, "data/b.bin": b"beta" * 30}
    _build_bfpk_101_archive(single, files, padding_size=0x8000)
    _build_bfpk_102_archive(chunked, {"a.bin": b"abcdefghijk"}, chunk_size=4)

    assert _extract_all(single) == files
    with single.open("rb") as file:
        entry = BfpkEngine().read_manifest(single, BinaryReader(file)).metadata["entries"][0]
    assert entry.compression == "zlib"
    assert entry.metadata["chunked"] is False

    assert _extract_all(chunked) == {"a.bin": b"abcdefghijk"}
    with chunked.open("rb") as file:
        entry = BfpkEngine().read_manifest(chunked, BinaryReader(file)).metadata["entries"][0]
    assert entry.metadata["archive_version"] == 0x102
    assert entry.metadata["chunk_uncompressed_sizes"] == (4, 4, 3)


def test_blades_of_fire_variants_manifest_and_extract(tmp_path: Path) -> None:
    raw_100 = tmp_path / "english.packed"
    raw_300 = tmp_path / "hud.packed"
    lz4_102 = tmp_path / "data00.packed"
    _build_blades_of_fire_bfpk_archive(raw_100, {"voices/a.ogg": b"OggSvoice-a"}, 0x100)
    _build_blades_of_fire_bfpk_archive(raw_300, {"hud/a.mpg": b"\x00\x00\x01\xbaone"}, 0x300)
    _build_blades_of_fire_bfpk_archive(lz4_102, {"language/texts.txt": b"abcdefghi"}, 0x102, chunk_size=4)

    for archive in (raw_100, raw_300, lz4_102):
        context = BfpkEngine().open(archive)
        entry = tuple(BfpkEngine().iter_entries(context))[0]
        assert entry.metadata["table_format"] == "blades_of_fire"

    assert _extract_all(raw_100) == {"voices/a.ogg": b"OggSvoice-a"}
    assert _extract_all(raw_300) == {"hud/a.mpg": b"\x00\x00\x01\xbaone"}
    assert _extract_all(lz4_102) == {"language/texts.txt": b"abcdefghi"}


def test_blades_of_fire_pics_manifest_extract_and_encrypted_table(tmp_path: Path) -> None:
    archive = tmp_path / "Pics.packed"
    files = {
        "pic/artbook/sample.jpg": b"\xff\xd8\xff\xe1" + b"j" * 20,
        "pic/icon/sample.png": b"\x89PNG\r\n\x1a\n" + b"p" * 20,
        "pic/face/sample.dds": b"DDS " + b"\x7c\x00\x00\x00" + b"d" * 20,
        "pic/misc/loading.gif": b"GIF89a" + b"g" * 20 + b"\x3b",
    }
    _build_blades_of_fire_pics_archive(archive, files, opaque_hash=0xBF4068DE)

    data = archive.read_bytes()
    assert data[8:12] != len(files).to_bytes(4, "little")

    context = BfpkEngine().open(archive)
    entries = tuple(BfpkEngine().iter_entries(context))
    assert [entry.path for entry in entries] == list(files)
    assert entries[0].offset == 0x10000 + 10
    assert entries[1].offset == 0x20000 + 10
    assert entries[2].offset == 0x30000 + 10
    assert entries[3].offset == 0x40000 + 9
    assert entries[0].metadata["archive_version"] == 0x901
    assert entries[0].metadata["table_format"] == "blades_of_fire"
    assert entries[0].metadata["packed_format"] == "blades_of_fire_jpeg"
    assert entries[0].metadata["restored"] is False
    assert entries[0].metadata["embedded_first_payload_byte"] is False
    assert entries[0].metadata["declared_size"] == len(files["pic/artbook/sample.jpg"]) + 3
    assert entries[0].metadata["opaque_hash"] == 0xBF4068DE
    assert "table_hash" not in entries[0].metadata
    assert _extract_all(archive) == files


def test_blades_of_fire_pics_jpg_embedded_first_byte_and_packed_metadata(tmp_path: Path) -> None:
    archive = tmp_path / "Pics.packed"
    normal_jpg = b"\xff\xd8\xff\xe1\x00\x18Exif\x00\x00" + b"n" * 24
    embedded_jpg = b"\xff\xd8\xff\xdb\x00\x84" + b"e" * 24
    files = {
        "pic/artbook/normal.jpg": normal_jpg,
        "pic/artbook/embedded.jpg": embedded_jpg,
    }
    _build_blades_of_fire_pics_archive(archive, files, embedded_jpgs={"pic/artbook/embedded.jpg"})

    entries = tuple(BfpkEngine().iter_entries(BfpkEngine().open(archive)))
    assert [entry.path for entry in entries] == list(files)
    assert [entry.offset for entry in entries] == [0x10000 + 10, 0x20000 + 9]
    assert [entry.metadata["record_header_size"] for entry in entries] == [10, 9]
    assert [entry.metadata["embedded_first_payload_byte"] for entry in entries] == [False, True]
    assert all(entry.metadata["packed_format"] == "blades_of_fire_jpeg" for entry in entries)
    assert all(entry.metadata["restored"] is False for entry in entries)
    assert _extract_all(archive) == files


def test_blades_of_fire_pics_packed_jpg_is_not_marked_restored(tmp_path: Path) -> None:
    archive = tmp_path / "Pics.packed"
    packed_jpg = b"\xff\xd8\xff\xe1\x00\x18Exif\x00\x00II*\x00\x08\x00\x01\x00\xf1\x6f\xff\xec\x00\x11Ducky\x00"
    _build_blades_of_fire_pics_archive(archive, {"pic/artbook/packed.jpg": packed_jpg})

    entry = tuple(BfpkEngine().iter_entries(BfpkEngine().open(archive)))[0]
    assert entry.metadata["packed_format"] == "blades_of_fire_jpeg"
    assert entry.metadata["restored"] is False
    assert _extract_all(archive) == {"pic/artbook/packed.jpg": packed_jpg}
    assert not _has_strict_jpeg_marker_sequence(packed_jpg)


def test_blades_of_fire_pics_rejects_bad_record_size_zero_field_and_padding(tmp_path: Path) -> None:
    files = {"pic/artbook/sample.jpg": b"\xff\xd8" + b"j" * 20}
    bad_size = tmp_path / "bad_size.packed"
    _build_blades_of_fire_pics_archive(bad_size, files)
    data = bytearray(bad_size.read_bytes())
    data[0x10000 : 0x10004] = (len(next(iter(files.values()))) + 1).to_bytes(4, "little")
    bad_size.write_bytes(data)
    with pytest.raises(ValueError, match="stored size"):
        BfpkEngine().open(bad_size)

    bad_zero = tmp_path / "bad_zero.packed"
    _build_blades_of_fire_pics_archive(bad_zero, files)
    data = bytearray(bad_zero.read_bytes())
    data[0x10004 : 0x10008] = (1).to_bytes(4, "little")
    bad_zero.write_bytes(data)
    with pytest.raises(ValueError, match="zero field"):
        BfpkEngine().open(bad_zero)

    bad_padding = tmp_path / "bad_padding.packed"
    _build_blades_of_fire_pics_archive(bad_padding, files)
    data = bytearray(bad_padding.read_bytes())
    padding_offset = 0x10000 + 10 + len(next(iter(files.values())))
    data[padding_offset] = 1
    bad_padding.write_bytes(data)
    assert ArchiveScanner().scan(bad_padding, read_manifest=True).selected is None


def test_blades_of_fire_pics_repack_round_trip_and_modified_file(tmp_path: Path) -> None:
    files = {
        "pic/artbook/sample.jpg": b"\xff\xd8\xff\xe1" + b"j" * 12,
        "pic/misc/loading.gif": b"GIF89a" + b"g" * 12 + b"\x3b",
    }
    source_archive = tmp_path / "source.packed"
    _build_blades_of_fire_pics_archive(source_archive, files)
    source = tmp_path / "source"
    source.mkdir()
    _write_source_files(source, _extract_all(source_archive))

    repacked = tmp_path / "repacked.packed"
    BfpkEngine().repack(source, repacked, {"layout": "blades_of_fire", "archive_version": 0x901, "trailing_padding": 16})
    assert repacked.read_bytes()[8:12] != (2).to_bytes(4, "little")
    assert _extract_all(repacked) == files
    entries = tuple(BfpkEngine().iter_entries(BfpkEngine().open(repacked)))
    assert [entry.metadata["record_offset"] for entry in entries] == [0x10000, 0x20000]
    assert [entry.metadata["record_header_size"] for entry in entries] == [10, 9]
    assert [entry.metadata["opaque_hash"] for entry in entries] == [0, 0]

    modified = dict(files)
    modified["pic/artbook/sample.jpg"] = b"\xff\xd8\xff\xe1" + b"changed" * 4
    _write_source_files(source, {"pic/artbook/sample.jpg": modified["pic/artbook/sample.jpg"]})
    modified_repacked = tmp_path / "modified.packed"
    BfpkEngine().repack(
        source,
        modified_repacked,
        {"layout": "blades_of_fire", "archive_version": "0x901", "trailing_padding": 16},
    )
    assert _extract_all(modified_repacked) == modified
    modified_entries = tuple(BfpkEngine().iter_entries(BfpkEngine().open(modified_repacked)))
    assert modified_entries[0].stored_size == len(modified["pic/artbook/sample.jpg"])
    assert modified_entries[0].metadata["record_offset"] % 0x10000 == 0


def test_blades_of_fire_pics_rejects_unsafe_paths(tmp_path: Path) -> None:
    archive = tmp_path / "unsafe.packed"
    engine = BfpkEngine()
    name = b"../escape.jpg"
    table = bytearray()
    table += (1).to_bytes(4, "little")
    table += len(name).to_bytes(4, "little")
    table += name
    table += (4).to_bytes(4, "little")
    table += (0x10000).to_bytes(8, "little")
    table += (0).to_bytes(4, "little")
    table += (0).to_bytes(4, "little")
    table += (4).to_bytes(4, "little")
    archive.write_bytes(b"BFPK" + (0x901).to_bytes(4, "little") + engine._crypt_spacelords_d01_table(bytes(table), 8))

    assert ArchiveScanner().scan(archive, read_manifest=True).selected is None


def test_spacelords_variants_manifest_and_extract(tmp_path: Path) -> None:
    raw_500 = tmp_path / "english.packed"
    lz4_502 = tmp_path / "data00.packed"
    _build_spacelords_bfpk_archive(raw_500, {"voices/a.ogg": b"OggSvoice-a"}, 0x500)
    _build_spacelords_bfpk_archive(lz4_502, {"language/default.txt": b"NO_BORRAR"}, 0x502, chunk_size=4)

    raw_context = BfpkEngine().open(raw_500)
    raw_entry = tuple(BfpkEngine().iter_entries(raw_context))[0]
    assert raw_entry.offset == 0x10000
    assert raw_entry.metadata["table_format"] == "spacelords"
    assert _extract_all(raw_500) == {"voices/a.ogg": b"OggSvoice-a"}

    lz4_context = BfpkEngine().open(lz4_502)
    lz4_entry = tuple(BfpkEngine().iter_entries(lz4_context))[0]
    assert lz4_entry.compression == "lz4-block"
    assert lz4_entry.metadata["archive_version"] == 0x502
    assert _extract_all(lz4_502) == {"language/default.txt": b"NO_BORRAR"}


def test_spacelords_d01_manifest_extract_and_encrypted_table(tmp_path: Path) -> None:
    archive = tmp_path / "Pics.packed"
    files = {
        "pic/face/sample.dds": b"DDS " + b"\x7c\x00\x00\x00" + b"d" * 20,
        "pic/misc/loading.gif": b"GIF89a" + b"g" * 20 + b"\x3b",
        "pic/logo/main_logo_requiem.tga": b"\x00\x00\x0a\x00\x01\x00" + b"t" * 24,
    }
    _build_spacelords_d01_archive(archive, files, opaque_hash=0xB38F3442)

    data = archive.read_bytes()
    assert data[8:12] != len(files).to_bytes(4, "little")

    context = BfpkEngine().open(archive)
    entries = tuple(BfpkEngine().iter_entries(context))
    assert [entry.path for entry in entries] == list(files)
    assert entries[0].offset == 0x10000 + 6
    assert entries[1].offset == 0x20000 + 5
    assert entries[2].offset == 0x30000 + 5
    assert entries[0].metadata["declared_size"] == len(files["pic/face/sample.dds"]) + 7
    assert entries[0].metadata["opaque_hash"] == 0xB38F3442
    assert "table_hash" not in entries[0].metadata
    assert _extract_all(archive) == files


def test_spacelords_d01_rejects_bad_record_size_and_padding(tmp_path: Path) -> None:
    files = {"pic/face/sample.dds": b"DDS " + b"d" * 20}
    bad_size = tmp_path / "bad_size.packed"
    _build_spacelords_d01_archive(bad_size, files)
    data = bytearray(bad_size.read_bytes())
    data[0x10000 : 0x10004] = (len(next(iter(files.values()))) + 1).to_bytes(4, "little")
    bad_size.write_bytes(data)
    with pytest.raises(ValueError, match="stored size"):
        BfpkEngine().open(bad_size)

    bad_padding = tmp_path / "bad_padding.packed"
    _build_spacelords_d01_archive(bad_padding, files)
    data = bytearray(bad_padding.read_bytes())
    padding_offset = 0x10000 + 6 + len(next(iter(files.values())))
    data[padding_offset] = 1
    bad_padding.write_bytes(data)
    assert ArchiveScanner().scan(bad_padding, read_manifest=True).selected is None


def test_spacelords_d01_repack_round_trip_and_modified_file(tmp_path: Path) -> None:
    files = {
        "pic/face/sample.dds": b"DDS " + b"d" * 20,
        "pic/misc/loading.gif": b"GIF89a" + b"g" * 12 + b"\x3b",
    }
    source_archive = tmp_path / "source.packed"
    _build_spacelords_d01_archive(source_archive, files)
    source = tmp_path / "source"
    source.mkdir()
    _write_source_files(source, _extract_all(source_archive))

    repacked = tmp_path / "repacked.packed"
    BfpkEngine().repack(source, repacked, {"layout": "spacelords", "archive_version": 0xD01, "trailing_padding": 16})
    assert _extract_all(repacked) == files

    modified = dict(files)
    modified["pic/face/sample.dds"] = b"DDS " + b"changed" * 4
    _write_source_files(source, {"pic/face/sample.dds": modified["pic/face/sample.dds"]})
    modified_repacked = tmp_path / "modified.packed"
    BfpkEngine().repack(
        source,
        modified_repacked,
        {"layout": "spacelords", "archive_version": "0xd01", "trailing_padding": 16},
    )
    assert modified_repacked.read_bytes()[8:12] != (2).to_bytes(4, "little")
    assert _extract_all(modified_repacked) == modified


def test_spacelords_d01_rejects_unsafe_paths(tmp_path: Path) -> None:
    archive = tmp_path / "unsafe.packed"
    engine = BfpkEngine()
    name = b"../escape.dds"
    table = bytearray()
    table += (1).to_bytes(4, "little")
    table += len(name).to_bytes(4, "little")
    table += name
    table += (4).to_bytes(4, "little")
    table += (0x10000).to_bytes(8, "little")
    table += (0).to_bytes(4, "little")
    table += (0).to_bytes(4, "little")
    table += (4).to_bytes(4, "little")
    archive.write_bytes(b"BFPK" + (0xD01).to_bytes(4, "little") + engine._crypt_spacelords_d01_table(bytes(table), 8))

    assert ArchiveScanner().scan(archive, read_manifest=True).selected is None


def test_lords_of_shadow_ultimate_aes_table_round_trip() -> None:
    engine = BfpkEngine()
    plaintext = b"\x11" * 16 + (0).to_bytes(4, "little") + b"\x00" * 12

    encrypted = engine._encrypt_lords_of_shadow_ultimate_table(plaintext)

    assert encrypted != plaintext
    assert engine._decrypt_lords_of_shadow_ultimate_table(encrypted) == plaintext


def test_lords_of_shadow_ultimate_raw_manifest_extract_and_scan(tmp_path: Path) -> None:
    archive = tmp_path / "Data03.dat"
    files = {
        "music/intro.ogg": b"OggSintro",
        "system/readme.txt": b"plain text",
    }
    _build_lords_of_shadow_ultimate_dat_archive(archive, files, 0x2)

    outcome = ArchiveScanner().require_archive(archive, read_manifest=True)
    assert outcome.info is not None
    assert outcome.selected is not None
    assert outcome.selected.reason == "BFPK lords_of_shadow_ultimate layout matched"
    assert outcome.info.metadata["archive_version"] == 0x2
    assert outcome.info.metadata["table_format"] == "lords_of_shadow_ultimate"
    assert outcome.info.metadata["encrypted_table_size"] is not None
    assert outcome.info.metadata["table_prefix"] == b"\x82\xa0\xf1\x30\xaf\x30\x2f\xe6\x7a\xe8\x5b\xb0\x54\xc3\xb7\x1f"
    assert _extract_all(archive) == files


def test_lords_of_shadow_ultimate_zlib_manifest_extract_and_raw_record(tmp_path: Path) -> None:
    archive = tmp_path / "Data00.dat"
    files = {
        "bmp/lights/lights.ini": b"light=1\n" * 20,
        "bmp/lights/raw.bin": b"raw-payload",
    }
    _build_lords_of_shadow_ultimate_dat_archive(archive, files, 0x3, raw_zlib_records={"bmp/lights/raw.bin"})

    context = BfpkEngine().open(archive)
    entries = tuple(BfpkEngine().iter_entries(context))

    assert entries[0].compression == "zlib"
    assert entries[0].metadata["compressed"] is True
    assert entries[1].compression is None
    assert entries[1].metadata["compressed"] is False
    assert _extract_all(archive) == files


def test_lords_of_shadow_ultimate_rejects_malformed_tables_paths_and_payloads(tmp_path: Path) -> None:
    engine = BfpkEngine()

    invalid_length = tmp_path / "invalid_length.dat"
    invalid_length.write_bytes(b"BFPK" + (0x2).to_bytes(4, "little") + (5).to_bytes(4, "little") + b"\x00" * 21)
    assert ArchiveScanner().scan(invalid_length, read_manifest=True).selected is None

    malformed_row = tmp_path / "malformed_row.dat"
    table = b"\x00" * 16 + (1).to_bytes(4, "little") + b"\x00" * 12
    malformed_row.write_bytes(
        b"BFPK"
        + (0x2).to_bytes(4, "little")
        + (len(table) - 16).to_bytes(4, "little")
        + engine._encrypt_lords_of_shadow_ultimate_table(table)
    )
    assert ArchiveScanner().scan(malformed_row, read_manifest=True).selected is None

    unsafe = tmp_path / "unsafe.dat"
    _build_lords_of_shadow_ultimate_dat_archive(unsafe, {"../escape.bin": b"payload"}, 0x2)
    assert ArchiveScanner().scan(unsafe, read_manifest=True).selected is None

    beyond_eof = tmp_path / "beyond_eof.dat"
    _build_lords_of_shadow_ultimate_dat_archive(beyond_eof, {"file.bin": b"payload"}, 0x3)
    beyond_eof.write_bytes(beyond_eof.read_bytes()[:-2])
    assert ArchiveScanner().scan(beyond_eof, read_manifest=True).selected is None


def test_lords_of_shadow_ultimate_repack_round_trips_raw_and_zlib(tmp_path: Path) -> None:
    files = {
        "system/config.ini": b"quality=high\n" * 8,
        "video/subtitles.txt": b"subtitle text",
    }
    source = tmp_path / "source"
    source.mkdir()
    _write_source_files(source, files)

    for archive_version in (0x2, 0x3):
        archive = tmp_path / f"Data{archive_version}.dat"
        BfpkEngine().repack(
            source,
            archive,
            {
                "layout": "lords_of_shadow_ultimate",
                "archive_version": archive_version,
                "compression_level": 9,
            },
        )
        assert _extract_all(archive) == files
        with archive.open("rb") as file:
            reader = BinaryReader(file)
            assert reader.read_exact(4) == b"BFPK"
            assert reader.u32() == archive_version
            encrypted_table_size = reader.u32()
            decrypted = BfpkEngine()._decrypt_lords_of_shadow_ultimate_table(reader.read_exact(encrypted_table_size + 16))
            assert decrypted.startswith(BfpkEngine().lords_of_shadow_ultimate_table_prefix)


def test_lords_of_shadow_ultimate_real_archives_when_available(tmp_path: Path) -> None:
    root = Path(r"D:\Steam\steamapps\common\CastlevaniaLoS")
    cases = [
        ("Data00.dat", 0x3, 3511),
        ("Data01.dat", 0x3, 2079),
        ("Data02.dat", 0x3, 1797),
        ("Data03.dat", 0x2, 856),
        ("Data04.dat", 0x3, 6825),
        ("Data05.dat", 0x3, 4753),
        ("Data06.dat", 0x3, 5208),
        ("Data07.dat", 0x3, 1270),
        ("Data08.dat", 0x3, 793),
        ("Data09.dat", 0x3, 1196),
        ("Data10.dat", 0x3, 1477),
        ("Data11.dat", 0x3, 747),
        ("Data12.dat", 0x3, 1532),
        ("Data13.dat", 0x3, 1665),
        ("Data14.dat", 0x3, 922),
        ("Data15.dat", 0x3, 1010),
        ("Data16.dat", 0x3, 1102),
        ("Data17.dat", 0x3, 1330),
    ]
    if not all((root / name).is_file() for name, _, _ in cases):
        pytest.skip("Castlevania: Lords of Shadow - Ultimate Edition Steam archives are not available")

    engine = BfpkEngine()
    for name, archive_version, entry_count in cases:
        archive = root / name
        outcome = ArchiveScanner().require_archive(archive, read_manifest=True)
        assert outcome.info is not None
        assert outcome.info.metadata["table_format"] == "lords_of_shadow_ultimate"
        assert outcome.info.metadata["archive_version"] == archive_version
        assert outcome.info.entry_count == entry_count

    for name, _, _ in (cases[0], cases[3]):
        archive = root / name

        context = engine.open(archive)
        entries = tuple(engine.iter_entries(context))
        for entry in (entries[0], entries[len(entries) // 2], entries[-1]):
            output = BytesIO()
            engine.extract_entry(context, entry, output)
            assert len(output.getvalue()) == entry.uncompressed_size


def test_malformed_archives_do_not_match(tmp_path: Path) -> None:
    unknown = tmp_path / "unknown.packed"
    unknown.write_bytes(b"BFPK" + (0x999).to_bytes(4, "little") + (0).to_bytes(4, "little"))
    outcome = ArchiveScanner().scan(unknown, read_manifest=True)
    assert outcome.engine is None
    assert outcome.selected is None
    assert outcome.message == "No compatible archive found"

    bad_aux = tmp_path / "bad_aux.packed"
    _build_spacelords_bfpk_archive(bad_aux, {"voices/a.ogg": b"OggSvoice-a"}, 0x500)
    data = bytearray(bad_aux.read_bytes())
    aux_offset = 12 + 4 + len("voices/a.ogg".encode("utf-8")) + 4 + 8 + 4
    data[aux_offset : aux_offset + 4] = (1).to_bytes(4, "little")
    bad_aux.write_bytes(data)
    assert ArchiveScanner().scan(bad_aux, read_manifest=True).selected is None


def test_mirror_of_fate_scan_and_manifest_reports_entries(tmp_path: Path) -> None:
    archive = tmp_path / "data.pack"
    files = [
        ("z/last.bin", b"last"),
        ("a/first.bin", b"first-data"),
        ("nested/raw.dat", b"\x00\x01payload"),
    ]
    _build_mirror_of_fate_pack(archive, files)

    outcome = ArchiveScanner().require_archive(archive, read_manifest=True)
    assert outcome.selected is not None
    assert outcome.selected.confidence == pytest.approx(0.99)
    assert outcome.selected.format_name == "Castlevania Lords of Shadow - Mirror of Fate HD Pack Archive"
    assert outcome.info is not None
    assert outcome.info.entry_count == 3
    table_end = 12 + 3 * 1032
    assert outcome.info.metadata["pack_size"] == archive.stat().st_size - table_end
    assert outcome.info.metadata["alignment"] == 128
    assert outcome.info.metadata["first_payload_mod"] == 36
    entries = outcome.info.metadata["entries"]
    assert [entry.path for entry in entries] == [name for name, _ in files]
    assert entries[0].offset == 12 + 3 * 1032
    assert entries[0].stored_size == len(files[0][1])
    assert entries[0].uncompressed_size == len(files[0][1])
    assert entries[0].metadata["table_index"] == 0
    assert entries[0].metadata["end_offset"] == entries[0].offset + len(files[0][1])


def test_mirror_of_fate_random_pack_does_not_match(tmp_path: Path) -> None:
    archive = tmp_path / "random.pack"
    archive.write_bytes(b"not a mirror of fate archive")

    outcome = ArchiveScanner().scan(archive)
    assert outcome.selected is None
    assert outcome.engine is None
    assert outcome.message == "No compatible archive found"


def test_mirror_of_fate_unpack_writes_only_exact_payloads(tmp_path: Path) -> None:
    archive = tmp_path / "data.pack"
    files = [
        ("z/last.bin", b"last"),
        ("a/first.bin", b"first-data"),
    ]
    _build_mirror_of_fate_pack(archive, files)

    output = tmp_path / "out"
    assert main(["unpack", str(archive), "--dest", str(output)]) == 0
    for name, data in files:
        assert (output / name).read_bytes() == data

    assert not (output / ".mercurykit").exists()


def test_mirror_of_fate_repack_from_directory_sorts_files_and_reports_progress(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    archive = tmp_path / "data.pack"
    files = [
        ("z/last.bin", b"last"),
        ("a/first.bin", b"first-data"),
    ]
    _build_mirror_of_fate_pack(archive, files)

    output = tmp_path / "out"
    assert main(["unpack", str(archive), "--dest", str(output)]) == 0
    (output / "new").mkdir()
    (output / "new" / "bonus.bin").write_bytes(b"bonus")
    repacked = tmp_path / "repacked.pack"

    assert main(["repack", str(output), "--output", str(repacked), "--progress"]) == 0
    captured = capsys.readouterr()
    assert "Repacking repacked.pack" in captured.err
    assert "100%" in captured.err

    engine = MirrorOfFatePackEngine()
    context = engine.open(repacked)
    entries = tuple(engine.iter_entries(context))
    assert [entry.path for entry in entries] == ["a/first.bin", "new/bonus.bin", "z/last.bin"]
    table_end = 12 + 3 * 1032
    assert context.info.metadata["pack_size"] == repacked.stat().st_size - table_end
    assert _extract_all_mirror_of_fate(repacked) == {
        "z/last.bin": b"last",
        "a/first.bin": b"first-data",
        "new/bonus.bin": b"bonus",
    }


def test_mirror_of_fate_files_toc_hash_formula() -> None:
    engine = MirrorOfFatePackEngine()
    assert engine._files_toc_path_hash("system/cameras/armourintro.bccam") == 0x58102DE2
    assert engine._files_toc_path_hash("system/files.toc") == 0x832B58A6


def test_mirror_of_fate_repack_updates_files_toc_without_touching_source(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    engine = MirrorOfFatePackEngine()
    old_hash = engine._files_toc_path_hash("system/old.bin")
    root_existing_hash = engine._files_toc_path_hash("root_existing.bin")
    self_hash = engine._files_toc_path_hash("system/files.toc")
    unknown_hash = 0x11111111
    original_toc = (
        struct.pack("<II", unknown_hash, 0x22222222)
        + struct.pack("<II", old_hash, 3)
        + struct.pack("<II", root_existing_hash, 4)
        + struct.pack("<II", self_hash, 32)
    )
    _write_source_files(
        source,
        {
            "system/files.toc": original_toc,
            "system/old.bin": b"changed-size",
            "system/new.bin": b"new",
            "root_existing.bin": b"root-changed",
            "root_added.bin": b"root",
            "presaveddata/ignored.bin": b"ignore-me",
        },
    )

    repacked = tmp_path / "repacked.pack"
    engine.repack(source, repacked, {})

    assert (source / "system" / "files.toc").read_bytes() == original_toc
    extracted = _extract_all_mirror_of_fate(repacked)
    toc_pairs = _mirror_of_fate_toc_pairs(extracted["system/files.toc"])
    assert extracted["system/old.bin"] == b"changed-size"
    assert extracted["system/new.bin"] == b"new"
    assert extracted["root_existing.bin"] == b"root-changed"
    assert extracted["root_added.bin"] == b"root"
    assert extracted["presaveddata/ignored.bin"] == b"ignore-me"
    assert toc_pairs[unknown_hash] == 0x22222222
    assert toc_pairs[old_hash] == len(b"changed-size")
    assert toc_pairs[root_existing_hash] == len(b"root-changed")
    assert toc_pairs[engine._files_toc_path_hash("system/new.bin")] == len(b"new")
    assert toc_pairs[engine._files_toc_path_hash("root_added.bin")] == len(b"root")
    assert engine._files_toc_path_hash("presaveddata/ignored.bin") not in toc_pairs
    assert toc_pairs[self_hash] == len(extracted["system/files.toc"])
    assert len(extracted["system/files.toc"]) == 6 * 8


def test_mirror_of_fate_repack_rejects_malformed_files_toc(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_source_files(source, {"system/files.toc": b"bad", "file.bin": b"payload"})

    with pytest.raises(ValueError, match="files.toc size"):
        MirrorOfFatePackEngine().repack(source, tmp_path / "bad_toc.pack", {})


def test_mirror_of_fate_repack_validates_computed_pack_size_option(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "file.bin").write_bytes(b"payload")

    repacked = tmp_path / "valid.pack"
    MirrorOfFatePackEngine().repack(source, repacked, {})
    context = MirrorOfFatePackEngine().open(repacked)
    pack_size = int(context.info.metadata["pack_size"])
    MirrorOfFatePackEngine().repack(source, tmp_path / "valid_again.pack", {"pack_size": pack_size})

    with pytest.raises(ValueError, match="pack_size does not match computed"):
        MirrorOfFatePackEngine().repack(source, tmp_path / "invalid.pack", {"pack_size": pack_size + 1})
    with pytest.raises(ValueError, match="unknown_header is no longer supported"):
        MirrorOfFatePackEngine().repack(source, tmp_path / "unknown.pack", {"unknown_header": pack_size})
    with pytest.raises(ValueError, match="option is not supported"):
        MirrorOfFatePackEngine().repack(source, tmp_path / "unsupported.pack", {"compression_level": 6})


def test_mirror_of_fate_repack_rejects_output_inside_source(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "file.bin").write_bytes(b"payload")
    engine = MirrorOfFatePackEngine()
    with pytest.raises(ValueError, match="inside the source directory"):
        engine.repack(source, source / "inside.pack", {})

    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(ValueError, match="does not contain any files"):
        engine.repack(empty, tmp_path / "empty.pack", {})


def test_mirror_of_fate_repack_rejects_invalid_input_paths_long_paths_and_duplicates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "file.bin").write_bytes(b"payload")
    engine = MirrorOfFatePackEngine()

    monkeypatch.setattr(engine, "_collect_payload_paths", lambda input_dir: ["../file.bin"])
    with pytest.raises(ValueError, match="unsafe"):
        engine.repack(source, tmp_path / "bad_path.pack", {})

    monkeypatch.setattr(engine, "_collect_payload_paths", lambda input_dir: ["a" * 1025])
    with pytest.raises(ValueError, match="longer"):
        engine.repack(source, tmp_path / "long_path.pack", {})

    monkeypatch.setattr(engine, "_collect_payload_paths", lambda input_dir: ["file.bin", "FILE.bin"])
    with pytest.raises(ValueError, match="Duplicate"):
        engine.repack(source, tmp_path / "duplicate.pack", {})


def test_mirror_of_fate_rejects_bad_table_ranges_paths_and_padding(tmp_path: Path) -> None:
    archive = tmp_path / "data.pack"
    _build_mirror_of_fate_pack(archive, [("file.bin", b"payload"), ("next.bin", b"next")])

    bad_marker = tmp_path / "bad_marker.pack"
    bad_marker.write_bytes(archive.read_bytes())
    data = bytearray(bad_marker.read_bytes())
    data[0:4] = (0).to_bytes(4, "little")
    bad_marker.write_bytes(data)
    assert ArchiveScanner().scan(bad_marker, read_manifest=True).selected is None

    bad_overlap = tmp_path / "bad_overlap.pack"
    bad_overlap.write_bytes(archive.read_bytes())
    data = bytearray(bad_overlap.read_bytes())
    second_start_offset = 12 + 1032 + 1024
    data[second_start_offset: second_start_offset + 4] = (12 + 2 * 1032).to_bytes(4, "little")
    bad_overlap.write_bytes(data)
    assert ArchiveScanner().scan(bad_overlap, read_manifest=True).selected is None

    bad_path = tmp_path / "bad_path.pack"
    _build_mirror_of_fate_pack(bad_path, [("../escape.bin", b"payload")])
    assert ArchiveScanner().scan(bad_path, read_manifest=True).selected is None

    bad_padding = tmp_path / "bad_padding.pack"
    bad_padding.write_bytes(archive.read_bytes())
    data = bytearray(bad_padding.read_bytes())
    first_end = struct.unpack_from("<I", data, 12 + 1024 + 4)[0]
    data[first_end] = 1
    bad_padding.write_bytes(data)
    assert ArchiveScanner().scan(bad_padding, read_manifest=True).selected is None


def test_scan_directory_counts_bfpk_and_mirror_of_fate_archives(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    scan_root = tmp_path / "scan"
    scan_root.mkdir()
    _build_bfpk_100_archive(scan_root / "sample.bfpk", {"file.txt": b"content"})
    _build_mirror_of_fate_pack(scan_root / "data.pack", [("file.bin", b"payload")])
    (scan_root / "unknown.bin").write_bytes(b"nope")

    assert main(["scan", str(scan_root)]) == 0
    output = capsys.readouterr().out
    assert "MercurySteam BFPK Archive" in output
    assert "Castlevania Lords of Shadow - Mirror of Fate HD Pack Archive" in output
    assert "Scan summary: scanned=3 supported=2 unsupported=1 empty=0" in output


def test_mirror_of_fate_real_archives_when_available(tmp_path: Path) -> None:
    root = Path(r"D:\Steam\steamapps\common\Castlevania Lords of Shadow - Mirror of Fate HD")
    cases = [
        ("data.pack", 3044, 0x6EB5FF80, 44),
        ("strmdata.pack", 323, 0x081A8000, 36),
    ]
    if not all((root / name).is_file() for name, _, _, _ in cases):
        pytest.skip("Mirror of Fate HD Steam archives are not available")

    engine = MirrorOfFatePackEngine()
    for name, entry_count, pack_size, first_payload_mod in cases:
        archive = root / name
        outcome = ArchiveScanner().require_archive(archive, read_manifest=True)
        assert outcome.info is not None
        assert outcome.info.entry_count == entry_count
        assert outcome.info.metadata["pack_size"] == pack_size
        assert outcome.info.metadata["first_payload_mod"] == first_payload_mod

        context = engine.open(archive)
        entries = tuple(engine.iter_entries(context))
        for entry in (entries[0], entries[len(entries) // 2], entries[-1]):
            output = BytesIO()
            engine.extract_entry(context, entry, output)
            assert isinstance(entry.offset, int)
            assert isinstance(entry.stored_size, int)
            with archive.open("rb") as file:
                file.seek(entry.offset)
                assert output.getvalue() == file.read(entry.stored_size)


# Repack behavior


def test_repack_legacy_round_trips(tmp_path: Path) -> None:
    files = {"a.bin": b"abcdefghijk", "folder/b.bin": b"0123456789abcdef"}
    source = tmp_path / "source"
    source.mkdir()
    _write_source_files(source, files)

    for archive_version, options in [
        (0x100, {}),
        (0x101, {"compression_level": 9}),
        (0x102, {"file_chunk_size": 4, "compression_level": 1}),
    ]:
        archive = tmp_path / f"repacked_{archive_version:x}.packed"
        repack_options = {"archive_version": archive_version, "trailing_padding": 16, **options}
        BfpkEngine().repack(source, archive, repack_options)
        assert _extract_all(archive) == files
        entries = tuple(BfpkEngine().iter_entries(BfpkEngine().open(archive)))
        assert [entry.path for entry in entries] == sorted(files)
        assert archive.stat().st_size - max(_bfpk_entry_end(entry) for entry in entries) == 16


def test_repack_blades_of_fire_and_spacelords_raw_round_trip(tmp_path: Path) -> None:
    files = {"voices/a.ogg": b"OggSvoice-a", "voices/b.ogg": b"OggSvoice-b-longer"}
    source = tmp_path / "source"
    source.mkdir()
    _write_source_files(source, files)

    cases = [
        ("blades_of_fire", 0x100),
        ("blades_of_fire", 0x300),
        ("spacelords", 0x500),
    ]
    for layout, archive_version in cases:
        archive = tmp_path / f"{layout}_{archive_version:x}.packed"
        BfpkEngine().repack(source, archive, {"layout": layout, "archive_version": archive_version, "trailing_padding": 16})
        assert _extract_all(archive) == files


def test_repack_lz4_variants_when_installed(tmp_path: Path) -> None:
    if importlib.util.find_spec("lz4") is None:
        pytest.skip("optional lz4 package is not installed")

    files = {"language/texts.txt": b"abcdefghi", "textures/hud.dds": b"DDS " + b"x" * 32}
    source = tmp_path / "source"
    source.mkdir()
    _write_source_files(source, files)

    for layout, archive_version in [("blades_of_fire", 0x102), ("spacelords", 0x502)]:
        archive = tmp_path / f"{layout}_{archive_version:x}.packed"
        BfpkEngine().repack(
            source,
            archive,
            {"layout": layout, "archive_version": archive_version, "file_chunk_size": 4, "trailing_padding": 16},
        )
        assert _extract_all(archive) == files


def test_lz4_repack_reports_missing_optional_dependency(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_source_files(source, {"language/texts.txt": b"abcdefghi"})
    original_import = builtins.__import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "lz4.block" or name == "lz4":
            raise ImportError(name)
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(UnsupportedOperation, match="optional lz4 package"):
        BfpkEngine().repack(
            source,
            tmp_path / "data00.packed",
            {"layout": "blades_of_fire", "archive_version": 0x102, "file_chunk_size": 4},
        )


def test_cli_repack_accepts_options_and_progress(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_source_files(source, {"voice/a.ogg": b"OggSvoice-a"})
    archive = tmp_path / "cli.packed"

    assert main(
        [
            "repack",
            str(source),
            "--output",
            str(archive),
            "--option",
            "archive_version=0x100",
            "--option",
            "trailing_padding=0x10",
            "--progress",
        ]
    ) == 0
    captured = capsys.readouterr()
    assert "Repacking cli.packed" in captured.err
    assert "100%" in captured.err
    assert _extract_all(archive) == {"voice/a.ogg": b"OggSvoice-a"}


# CLI, scanner, progress, and safety behavior


def test_cli_unpack_progress_can_be_forced_and_disabled(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    archive = tmp_path / "raw.bfpk"
    _build_bfpk_100_archive(archive, {"hello.txt": b"hello"})

    assert main(["unpack", str(archive), "--dest", str(tmp_path / "out"), "--progress"]) == 0
    captured = capsys.readouterr()
    assert "extracted to" in captured.out
    assert "Extracting raw.bfpk" in captured.err
    assert "100%" in captured.err

    assert main(["unpack", str(archive), "--dest", str(tmp_path / "out2"), "--no-progress"]) == 0
    captured = capsys.readouterr()
    assert captured.err == ""


def test_scan_directory_modes_and_empty_files(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    scan_root = tmp_path / "scan"
    nested = scan_root / "nested"
    nested.mkdir(parents=True)
    _build_bfpk_100_archive(scan_root / "sample.bfpk", {"file.txt": b"content"})
    _build_bfpk_100_archive(nested / "nested.bfpk", {"file.txt": b"content"})
    (scan_root / "unknown.bin").write_bytes(b"nope")
    (scan_root / "empty.bin").write_bytes(b"")

    assert main(["scan", str(scan_root)]) == 0
    output = capsys.readouterr().out
    assert "sample.bfpk" in output
    assert "nested.bfpk" not in output
    assert "unknown.bin: No compatible archive found" in output
    assert "Scan summary: scanned=2 supported=1 unsupported=1 empty=1" in output

    assert main(["scan", str(scan_root), "--recursive", "--verbose"]) == 0
    output = capsys.readouterr().out
    assert "nested.bfpk" in output
    assert "Skipped empty file:" in output
    assert "Entries:" in output


def test_single_unsupported_file_fails_and_empty_file_is_skipped(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    unknown = tmp_path / "unknown.bin"
    unknown.write_bytes(b"nope")
    assert main(["scan", str(unknown)]) == 1
    assert "No compatible archive found" in capsys.readouterr().out

    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    assert main(["scan", str(empty)]) == 0
    assert f"Skipped empty file: {empty}" in capsys.readouterr().out

    with pytest.raises(NoArchiveError):
        ArchiveScanner().require_archive(unknown)


def test_terminal_progress_reporter_renders_final_line() -> None:
    stream = StringIO()
    progress = TerminalProgressReporter(stream=stream, width=10)

    progress.start("Working", total_items=2, total_bytes=10)
    progress.advance(items=1, bytes_count=5, detail="one.bin")
    progress.advance(items=1, bytes_count=5, detail="two.bin")
    progress.finish()

    output = stream.getvalue()
    assert "Working" in output
    assert "100%" in output
    assert "2/2 files" in output
    assert output.endswith("\n")


def test_parse_archive_options_and_format_entry() -> None:
    assert _parse_archive_options(["archive_version=0x102", "enabled=true", "name=bfpk"]) == {
        "archive_version": 0x102,
        "enabled": True,
        "name": "bfpk",
    }
    with pytest.raises(ValueError):
        _parse_archive_options(["archive_version"])

    assert _format_entry(ArchiveEntry(entry_id="abc123", stored_size=4096)) == "entry_id='abc123' stored_size=4096"
    assert _format_entry(ArchiveEntry(path="file.bin", metadata={"hash": "abc"})) == "path='file.bin' metadata={'hash': 'abc'}"


def test_security_rejects_path_traversal_and_duplicates(tmp_path: Path) -> None:
    class BadEngine:
        def iter_entries(self, context):
            return iter([ArchiveEntry("../escape.txt"), ArchiveEntry("safe.txt")])

        def extract_entry(self, context, entry, output_stream):
            output_stream.write(b"x")

    context = ArchiveContext(tmp_path / "bad.bfpk", BadEngine(), ArchiveInfo("Bad", 2))
    with pytest.raises(ValueError):
        _extract_context(context, tmp_path / "out", overwrite=False)

    class DuplicateEngine(BadEngine):
        def iter_entries(self, context):
            return iter([ArchiveEntry("same.txt"), ArchiveEntry("same.txt")])

    context = ArchiveContext(tmp_path / "dup.bfpk", DuplicateEngine(), ArchiveInfo("Duplicate", 2))
    with pytest.raises(FileExistsError):
        _extract_context(context, tmp_path / "dup_out", overwrite=False)
