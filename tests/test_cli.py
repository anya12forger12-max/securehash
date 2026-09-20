"""Tests for the securehash CLI."""

import hashlib

from securehash.cli import main

SAMPLE = b"cli payload\n"


def _sample_file(tmp_path):
    path = tmp_path / "cli.bin"
    path.write_bytes(SAMPLE)
    return path


def test_hash_subcommand_prints_digest(tmp_path, capsys):
    path = _sample_file(tmp_path)
    rc = main(["hash", str(path)])
    captured = capsys.readouterr().out
    assert rc == 0
    assert f"sha256: {hashlib.sha256(SAMPLE).hexdigest()}" in captured


def test_hash_subcommand_honors_algorithm_flag(tmp_path, capsys):
    path = _sample_file(tmp_path)
    rc = main(["hash", str(path), "--algorithm", "sha1"])
    captured = capsys.readouterr().out
    assert rc == 0
    assert captured.startswith(
        f"sha1: {hashlib.sha1(SAMPLE).hexdigest()}"  # noqa: S324 (reference only)
    )


def test_hash_subcommand_rejects_unknown_algorithm(tmp_path):
    path = _sample_file(tmp_path)
    import pytest

    with pytest.raises(SystemExit) as exc:
        main(["hash", str(path), "--algorithm", "md6"])
    assert exc.value.code == 2


def test_verify_ok_returns_zero(tmp_path, capsys):
    path = _sample_file(tmp_path)
    rc = main(["verify", str(path), "--expect", hashlib.sha256(SAMPLE).hexdigest()])
    capture = capsys.readouterr()
    assert rc == 0
    assert "OK" in capture.out


def test_verify_mismatch_returns_one(tmp_path, capsys):
    path = _sample_file(tmp_path)
    rc = main(["verify", str(path), "--expect", "0" * 64])
    capture = capsys.readouterr()
    assert rc == 1
    assert "MISMATCH" in capture.out


def test_verify_accepts_uppercase_digest(tmp_path):
    path = _sample_file(tmp_path)
    digest = hashlib.sha256(SAMPLE).hexdigest().upper()
    assert main(["verify", str(path), "--expect", digest]) == 0
