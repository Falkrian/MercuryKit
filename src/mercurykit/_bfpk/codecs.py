from __future__ import annotations

from mercurykit.binary import EndOfStreamError
from mercurykit.archive import UnsupportedOperation


class BfpkCodecMixin:
    def _aes_256_cbc_crypt(self, data: bytes, *, decrypt: bool) -> bytes:
        if len(data) % 16 != 0:
            raise ValueError("BFPK AES table data must be 16-byte aligned")
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        except ImportError as exc:
            raise UnsupportedOperation("BFPK AES table support requires the cryptography package") from exc

        cipher = Cipher(algorithms.AES(self.lords_of_shadow_ultimate_aes_key), modes.CBC(bytes(16)))
        transform = cipher.decryptor() if decrypt else cipher.encryptor()
        return transform.update(data) + transform.finalize()

    def _decrypt_lords_of_shadow_ultimate_table(self, data: bytes) -> bytes:
        return self._aes_256_cbc_crypt(data, decrypt=True)

    def _encrypt_lords_of_shadow_ultimate_table(self, data: bytes) -> bytes:
        return self._aes_256_cbc_crypt(data, decrypt=False)

    def _require_lz4_block(self):
        try:
            import lz4.block as lz4_block
        except ImportError as exc:
            raise UnsupportedOperation("BFPK LZ4 repack requires the optional lz4 package") from exc
        return lz4_block

    def _decompress_lz4_block(self, data: bytes, expected_size: int) -> bytes:
        output = bytearray()
        index = 0
        while index < len(data):
            token = data[index]
            index += 1
            literal_length = token >> 4
            if literal_length == 15:
                while True:
                    if index >= len(data):
                        raise EndOfStreamError("BFPK LZ4 literal length extends beyond chunk")
                    value = data[index]
                    index += 1
                    literal_length += value
                    if value != 255:
                        break

            if index + literal_length > len(data):
                raise EndOfStreamError("BFPK LZ4 literal data extends beyond chunk")
            output.extend(data[index:index + literal_length])
            index += literal_length
            if index >= len(data):
                break

            if index + 2 > len(data):
                raise EndOfStreamError("BFPK LZ4 match offset extends beyond chunk")
            offset = data[index] | (data[index + 1] << 8)
            index += 2
            if offset == 0 or offset > len(output):
                raise ValueError("BFPK LZ4 match offset is invalid")

            match_length = (token & 0x0F) + 4
            if (token & 0x0F) == 15:
                while True:
                    if index >= len(data):
                        raise EndOfStreamError("BFPK LZ4 match length extends beyond chunk")
                    value = data[index]
                    index += 1
                    match_length += value
                    if value != 255:
                        break

            start = len(output) - offset
            for offset_index in range(match_length):
                output.append(output[start + offset_index])

        if len(output) != expected_size:
            raise ValueError("BFPK LZ4 chunk decompressed to unexpected size")
        return bytes(output)

    def _xxh32(self, data: bytes, seed: int = 0) -> int:
        prime1 = 0x9E3779B1
        prime2 = 0x85EBCA77
        prime3 = 0xC2B2AE3D
        prime4 = 0x27D4EB2F
        prime5 = 0x165667B1

        def rotate_left(value: int, amount: int) -> int:
            return ((value << amount) | (value >> (32 - amount))) & self.max_u32

        index = 0
        length = len(data)
        if length >= 16:
            v1 = (seed + prime1 + prime2) & self.max_u32
            v2 = (seed + prime2) & self.max_u32
            v3 = seed & self.max_u32
            v4 = (seed - prime1) & self.max_u32
            while index <= length - 16:
                lane = int.from_bytes(data[index:index + 4], "little")
                index += 4
                v1 = (rotate_left((v1 + lane * prime2) & self.max_u32, 13) * prime1) & self.max_u32
                lane = int.from_bytes(data[index:index + 4], "little")
                index += 4
                v2 = (rotate_left((v2 + lane * prime2) & self.max_u32, 13) * prime1) & self.max_u32
                lane = int.from_bytes(data[index:index + 4], "little")
                index += 4
                v3 = (rotate_left((v3 + lane * prime2) & self.max_u32, 13) * prime1) & self.max_u32
                lane = int.from_bytes(data[index:index + 4], "little")
                index += 4
                v4 = (rotate_left((v4 + lane * prime2) & self.max_u32, 13) * prime1) & self.max_u32
            h32 = (rotate_left(v1, 1) + rotate_left(v2, 7) + rotate_left(v3, 12) + rotate_left(v4, 18)) & self.max_u32
        else:
            h32 = (seed + prime5) & self.max_u32

        h32 = (h32 + length) & self.max_u32
        while index <= length - 4:
            lane = int.from_bytes(data[index:index + 4], "little")
            index += 4
            h32 = (rotate_left((h32 + lane * prime3) & self.max_u32, 17) * prime4) & self.max_u32
        while index < length:
            h32 = (rotate_left((h32 + data[index] * prime5) & self.max_u32, 11) * prime1) & self.max_u32
            index += 1

        h32 ^= h32 >> 15
        h32 = (h32 * prime2) & self.max_u32
        h32 ^= h32 >> 13
        h32 = (h32 * prime3) & self.max_u32
        h32 ^= h32 >> 16
        return h32 & self.max_u32

    def _check_u32(self, value: int, label: str) -> None:
        if not 0 <= value <= self.max_u32:
            raise ValueError(f"{label} must fit in u32")

    def _check_u64(self, value: int, label: str) -> None:
        if not 0 <= value <= self.max_u64:
            raise ValueError(f"{label} must fit in u64")

