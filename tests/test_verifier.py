"""Tests for securehash.verifier."""

import hashlib

import pytest

from securehash.verifier import verify_file

SAMPLE = b"integrity check payload\n"


def _write_sample(tmp_path):
    path = tmp_path / "data.bin"
    path.write_bytes(SAMPLE)
    return path


def test_verify_correct_digest(tmp_path):
    path = _write_sample(tmp_path)
    assert verify_file(path, hashlib.sha256(SAMPLE).hexdigest()) is True


def test_verify_wrong_digest(tmp_path):
    path = _write_sample(tmp_path)
    assert verify_file(path, "0" * 64) is False


def test_verify_is_case_insensitive(tmp_path):
    path = _write_sample(tmp_path)
    digest = hashlib.sha256(SAMPLE).hexdigest().upper()
    assert verify_file(path, digest) is True


def test_verify_is_whitespace_tolerant(tmp_path):
    path = _write_sample(tmp_path)
    digest = hashlib.sha256(SAMPLE).hexdigest()
    assert verify_file(path, f"  {digest}\n") is True


def test_verify_explicit_algorithm(tmp_path):
    path = _write_sample(tmp_path)
    expected = hashlib.md5(SAMPLE).hexdigest()  # noqa: S324 (reference only)
    assert verify_file(path, expected, algorithm="md5") is True


def test_verify_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        verify_file(tmp_path / "missing.bin", "0" * 64)


def test_verify_unsupported_algorithm_raises(tmp_path):
    path = _write_sample(tmp_path)
    with pytest.raises(ValueError, match="unsupported algorithm"):
        verify_file(path, "0" * 64, algorithm="whirlpool")
