from __future__ import annotations

from dataclasses import dataclass
import bz2
import lzma
import zlib
from typing import Callable


class UnsupportedCodecError(KeyError):
    """Raised when a requested codec has not been registered."""


Compressor = Callable[[bytes], bytes]
Decompressor = Callable[[bytes], bytes]
Encryptor = Callable[[bytes, dict], bytes]
Decryptor = Callable[[bytes, dict], bytes]


@dataclass(frozen=True)
class CompressionCodec:
    name: str
    compress: Compressor
    decompress: Decompressor


class CompressionRegistry:
    def __init__(self) -> None:
        self._codecs: dict[str, CompressionCodec] = {}

    def register(self, name: str, compress: Compressor, decompress: Decompressor) -> None:
        normalized = name.lower()
        self._codecs[normalized] = CompressionCodec(normalized, compress, decompress)

    def get(self, name: str) -> CompressionCodec:
        try:
            return self._codecs[name.lower()]
        except KeyError as exc:
            raise UnsupportedCodecError(name) from exc

    def names(self) -> list[str]:
        return sorted(self._codecs)

    def compress(self, name: str, data: bytes) -> bytes:
        return self.get(name).compress(data)

    def decompress(self, name: str, data: bytes) -> bytes:
        return self.get(name).decompress(data)


@dataclass(frozen=True)
class CryptoCodec:
    name: str
    encrypt: Encryptor
    decrypt: Decryptor


class CryptoRegistry:
    def __init__(self) -> None:
        self._codecs: dict[str, CryptoCodec] = {}

    def register(self, name: str, encrypt: Encryptor, decrypt: Decryptor) -> None:
        normalized = name.lower()
        self._codecs[normalized] = CryptoCodec(normalized, encrypt, decrypt)

    def get(self, name: str) -> CryptoCodec:
        try:
            return self._codecs[name.lower()]
        except KeyError as exc:
            raise UnsupportedCodecError(name) from exc

    def names(self) -> list[str]:
        return sorted(self._codecs)

    def encrypt(self, name: str, data: bytes, **options: object) -> bytes:
        return self.get(name).encrypt(data, dict(options))

    def decrypt(self, name: str, data: bytes, **options: object) -> bytes:
        return self.get(name).decrypt(data, dict(options))


def _deflate_compress(data: bytes) -> bytes:
    compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    return compressor.compress(data) + compressor.flush()


def _deflate_decompress(data: bytes) -> bytes:
    return zlib.decompress(data, wbits=-zlib.MAX_WBITS)


compression_registry = CompressionRegistry()
compression_registry.register("zlib", zlib.compress, zlib.decompress)
compression_registry.register("deflate", _deflate_compress, _deflate_decompress)
compression_registry.register("bz2", bz2.compress, bz2.decompress)
compression_registry.register("lzma", lzma.compress, lzma.decompress)

try:
    import lz4.frame as _lz4_frame
except ImportError:
    pass
else:
    compression_registry.register("lz4", _lz4_frame.compress, _lz4_frame.decompress)

crypto_registry = CryptoRegistry()
