"""Tests for securehash.hasher."""

import hashlib

import pytest

from securehash.hasher import SUPPORTED_ALGORITHMS, hash_file

SAMPLE = b"hello securehash\n"


def test_supported_algorithms_listed():
    assert SUPPORTED_ALGORITHMS == ("md5", "sha1", "sha256")


@pytest.mark.parametrize("algorithm", SUPPORTED_ALGORITHMS)
def test_hash_matches_hashlib_reference(tmp_path, algorithm):
    path = tmp_path / "sample.bin"
    path.write_bytes(SAMPLE)
    expected = hashlib.new(algorithm, SAMPLE).hexdigest()
    assert hash_file(path, algorithm) == expected


def test_hash_accepts_string_path(tmp_path):
    path = tmp_path / "sample.bin"
    path.write_bytes(SAMPLE)
    assert hash_file(str(path)) == hashlib.sha256(SAMPLE).hexdigest()


def test_hash_defaults_to_sha256(tmp_path):
    path = tmp_path / "sample.bin"
    path.write_bytes(SAMPLE)
    assert hash_file(path) == hashlib.sha256(SAMPLE).hexdigest()


def test_hash_empty_file(tmp_path):
    path = tmp_path / "empty.bin"
    path.write_bytes(b"")
    assert hash_file(path) == hashlib.sha256(b"").hexdigest()


def test_hash_streams_with_small_chunk(tmp_path):
    data = b"abc123" * (1024 * 1024 // 6)
    path = tmp_path / "large.bin"
    path.write_bytes(data)
    assert hash_file(path, chunk_size=4096) == hashlib.sha256(data).hexdigest()


def test_hash_unsupported_algorithm_raises(tmp_path):
    with pytest.raises(ValueError, match="unsupported algorithm"):
        hash_file(tmp_path / "x.bin", "md6")


def test_hash_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        hash_file(tmp_path / "does-not-exist.bin")


def test_hash_non_positive_chunk_size_raises(tmp_path):
    path = tmp_path / "sample.bin"
    path.write_bytes(SAMPLE)
    with pytest.raises(ValueError, match="chunk_size"):
        hash_file(path, chunk_size=0)
