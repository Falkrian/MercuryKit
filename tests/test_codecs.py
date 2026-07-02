from __future__ import annotations

import pytest

from mercurykit.codecs import UnsupportedCodecError, compression_registry, crypto_registry


@pytest.mark.parametrize("codec", ["zlib", "deflate", "bz2", "lzma"])
def test_compression_round_trip(codec: str) -> None:
    data = b"hello archive" * 20
    assert compression_registry.decompress(codec, compression_registry.compress(codec, data)) == data


def test_unsupported_codec() -> None:
    with pytest.raises(UnsupportedCodecError):
        compression_registry.decompress("missing", b"")
    with pytest.raises(UnsupportedCodecError):
        crypto_registry.decrypt("aes", b"", key=b"")
