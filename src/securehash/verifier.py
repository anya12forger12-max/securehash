"""File integrity verification against an expected digest."""

from pathlib import Path

from securehash.hasher import SUPPORTED_ALGORITHMS, hash_file


def verify_file(
    path: str | Path,
    expected: str,
    algorithm: str = "sha256",
    chunk_size: int = 1024 * 1024,
) -> bool:
    """Return ``True`` when ``path`` hashes to ``expected``.

    The comparison is case- and whitespace-insensitive so pasted digests
    from any source match.
    """
    actual = hash_file(path, algorithm, chunk_size)
    return actual.lower() == expected.strip().lower()


__all__ = ["SUPPORTED_ALGORITHMS", "verify_file"]
