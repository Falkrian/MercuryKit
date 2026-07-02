from __future__ import annotations

from io import BytesIO

import pytest

from mercurykit.binary import BinaryReader, EndOfStreamError, Endian
from mercurykit.bits import BitReader, BitWriter


def test_binary_reader_primitives_and_endianness() -> None:
    reader = BinaryReader.from_bytes(bytes.fromhex("01 02 00 00 00 80 3f"))
    assert reader.u8() == 1
    assert reader.u16() == 2
    assert reader.f32() == pytest.approx(1.0)

    reader = BinaryReader.from_bytes(bytes.fromhex("01 02"), endian=Endian.BIG)
    assert reader.u16() == 0x0102
    reader.seek(0)
    with reader.use_endian(Endian.LITTLE):
        assert reader.u16() == 0x0201


def test_string_seek_align_and_bounds() -> None:
    reader = BinaryReader.from_bytes(b"abc\x00xx")
    assert reader.read_cstring() == "abc"
    assert reader.tell() == 4
    assert reader.read_string(2) == "xx"
    with pytest.raises(EndOfStreamError):
        reader.read_exact(1)

    reader = BinaryReader(BytesIO(b"0123456789"))
    subreader = reader.subreader(2, 3)
    assert subreader.read_exact(3) == b"234"
    with pytest.raises(EndOfStreamError):
        subreader.read_exact(1)


def test_bit_reader_and_writer() -> None:
    reader = BitReader(b"\xb0")
    assert reader.read_bits(3) == 0b101
    assert reader.read_bits(5) == 0b10000
    with pytest.raises(EOFError):
        reader.read_bits(1)

    writer = BitWriter()
    writer.write_bits(0b101, 3)
    writer.write_bits(0b10000, 5)
    assert writer.to_bytes() == b"\xb0"
