from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from io import BytesIO
import struct
from typing import BinaryIO, Iterator


class Endian(str, Enum):
    LITTLE = "little"
    BIG = "big"

    @property
    def struct_prefix(self) -> str:
        return "<" if self is Endian.LITTLE else ">"


class BinaryReaderError(Exception):
    """Base exception for binary reader failures."""


class EndOfStreamError(BinaryReaderError):
    """Raised when a read would move beyond the readable region."""


@dataclass(frozen=True)
class ReaderBounds:
    """Logical view over a stream, used to keep subreaders inside their slice."""

    base_offset: int = 0
    size: int | None = None

    def contains(self, position: int, length: int = 0) -> bool:
        if position < 0 or length < 0:
            return False
        if self.size is None:
            return True
        return position + length <= self.size


class BinaryReader:
    """Seekable binary reader with endian-aware primitive helpers."""

    def __init__(
        self,
        stream: BinaryIO,
        endian: Endian | str = Endian.LITTLE,
        *,
        bounds: ReaderBounds | None = None,
    ) -> None:
        self.stream = stream
        self.endian = Endian(endian)
        self.bounds = bounds or ReaderBounds()
        self.seek(0)

    @classmethod
    def from_bytes(cls, data: bytes, endian: Endian | str = Endian.LITTLE) -> "BinaryReader":
        return cls(BytesIO(data), endian=endian)

    def tell(self) -> int:
        return self.stream.tell() - self.bounds.base_offset

    def seek(self, offset: int, whence: int = 0) -> int:
        if whence == 0:
            new_position = offset
        elif whence == 1:
            new_position = self.tell() + offset
        elif whence == 2:
            if self.bounds.size is None:
                self.stream.seek(0, 2)
                end = self.stream.tell() - self.bounds.base_offset
            else:
                end = self.bounds.size
            new_position = end + offset
        else:
            raise ValueError(f"Unsupported whence value: {whence}")

        if not self.bounds.contains(new_position):
            raise EndOfStreamError("Seek moved outside the reader bounds")

        self.stream.seek(self.bounds.base_offset + new_position)
        return new_position

    def align(self, alignment: int) -> int:
        if alignment <= 0:
            raise ValueError("alignment must be positive")
        position = self.tell()
        padding = (-position) % alignment
        if padding:
            self.seek(padding, 1)
        return self.tell()

    def read_exact(self, length: int) -> bytes:
        if length < 0:
            raise ValueError("length must be non-negative")
        if not self.bounds.contains(self.tell(), length):
            raise EndOfStreamError("Read moved outside the reader bounds")
        data = self.stream.read(length)
        if len(data) != length:
            raise EndOfStreamError(f"Expected {length} bytes, got {len(data)}")
        return data

    def read_bytes(self, length: int) -> bytes:
        return self.read_exact(length)

    def read_cstring(self, *, encoding: str = "utf-8", max_length: int | None = None) -> str:
        data = bytearray()
        while True:
            if max_length is not None and len(data) >= max_length:
                raise EndOfStreamError("Null terminator not found before max_length")
            byte = self.read_exact(1)
            if byte == b"\x00":
                return data.decode(encoding)
            data.extend(byte)

    def read_string(self, length: int, *, encoding: str = "utf-8", strip_nulls: bool = True) -> str:
        data = self.read_exact(length)
        if strip_nulls:
            data = data.rstrip(b"\x00")
        return data.decode(encoding)

    def subreader(self, offset: int, size: int, endian: Endian | str | None = None) -> "BinaryReader":
        """Return a bounded reader over the same stream without copying bytes."""

        if offset < 0 or size < 0:
            raise ValueError("offset and size must be non-negative")
        if not self.bounds.contains(offset, size):
            raise EndOfStreamError("Subreader would exceed parent reader bounds")
        return BinaryReader(
            self.stream,
            endian=endian or self.endian,
            bounds=ReaderBounds(self.bounds.base_offset + offset, size),
        )

    @contextmanager
    def use_endian(self, endian: Endian | str) -> Iterator[None]:
        old = self.endian
        self.endian = Endian(endian)
        try:
            yield
        finally:
            self.endian = old

    def _unpack(self, fmt: str) -> int | float:
        full_format = self.endian.struct_prefix + fmt
        return struct.unpack(full_format, self.read_exact(struct.calcsize(full_format)))[0]

    def u8(self) -> int:
        return int(self._unpack("B"))

    def i8(self) -> int:
        return int(self._unpack("b"))

    def u16(self) -> int:
        return int(self._unpack("H"))

    def i16(self) -> int:
        return int(self._unpack("h"))

    def u32(self) -> int:
        return int(self._unpack("I"))

    def i32(self) -> int:
        return int(self._unpack("i"))

    def u64(self) -> int:
        return int(self._unpack("Q"))

    def i64(self) -> int:
        return int(self._unpack("q"))

    def f32(self) -> float:
        return float(self._unpack("f"))

    def f64(self) -> float:
        return float(self._unpack("d"))
