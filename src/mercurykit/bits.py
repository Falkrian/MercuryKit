from __future__ import annotations


class BitReader:
    """Read individual bits from a bytes object."""

    def __init__(self, data: bytes, *, msb_first: bool = True) -> None:
        self.data = data
        self.msb_first = msb_first
        self.bit_position = 0

    def read_bits(self, count: int) -> int:
        if count < 0:
            raise ValueError("count must be non-negative")
        if self.bit_position + count > len(self.data) * 8:
            raise EOFError("Not enough bits remaining")

        value = 0
        for _ in range(count):
            byte_index, bit_index = divmod(self.bit_position, 8)
            shift = 7 - bit_index if self.msb_first else bit_index
            bit = (self.data[byte_index] >> shift) & 1
            value = (value << 1) | bit
            self.bit_position += 1
        return value


class BitWriter:
    """Write individual bits to a bytes object."""

    def __init__(self, *, msb_first: bool = True) -> None:
        self.msb_first = msb_first
        self._bytes = bytearray()
        self._bit_position = 0

    def write_bits(self, value: int, count: int) -> None:
        if value < 0 or count < 0:
            raise ValueError("value and count must be non-negative")
        if count and value >= (1 << count):
            raise ValueError("value does not fit in count bits")

        for bit_offset in reversed(range(count)):
            bit = (value >> bit_offset) & 1
            byte_index, bit_index = divmod(self._bit_position, 8)
            if byte_index == len(self._bytes):
                self._bytes.append(0)
            shift = 7 - bit_index if self.msb_first else bit_index
            self._bytes[byte_index] |= bit << shift
            self._bit_position += 1

    def to_bytes(self) -> bytes:
        return bytes(self._bytes)
