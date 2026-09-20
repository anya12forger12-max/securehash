"""Streaming file hashing for the supported algorithms."""

import hashlib
from collections.abc import Iterator
from pathlib import Path

SUPPORTED_ALGORITHMS = ("md5", "sha1", "sha256")
"""Algorithms offered by SecureHash (MD5/SHA1 kept for legacy integrity checks)."""

_DEFAULT_CHUNK_SIZE = 1024 * 1024


def _iter_chunks(path: Path, chunk_size: int) -> Iterator[bytes]:
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            yield chunk


def hash_file(
    path: str | Path,
    algorithm: str = "sha256",
    chunk_size: int = _DEFAULT_CHUNK_SIZE,
) -> str:
    """Return the hex digest of ``path`` using ``algorithm``.

    Raises ``ValueError`` for an unsupported algorithm or a non-positive
    ``chunk_size``, and ``FileNotFoundError`` when the file does not exist.
    """
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(
            f"unsupported algorithm {algorithm!r}; choose from {', '.join(SUPPORTED_ALGORITHMS)}"
        )
    if chunk_size <= 0:
        raise ValueError("chunk_size must be > 0")

    # MD5/SHA1 are intentionally available here for legacy integrity checks.
    digest = hashlib.new(algorithm)
    for chunk in _iter_chunks(Path(path), chunk_size):
        digest.update(chunk)
    return digest.hexdigest()
