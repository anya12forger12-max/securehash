# SecureHash

File Hash Generator — generate MD5, SHA1, and SHA256 hashes of files and
verify file integrity.

## Features

- Hash any file with MD5, SHA1, or SHA256 (streamed in chunks, low memory).
- Verify a file against an expected digest (case- and whitespace-insensitive).
- Pure Python standard library — no runtime dependencies.

## Install

```bash
pip install .
```

## Usage

```bash
# Hash a file (defaults to sha256)
securehash hash ./archive.zip
securehash hash ./archive.zip --algorithm sha1

# Verify integrity
securehash verify ./archive.zip --expect <hex-digest>
```

Exit code is `0` on a verified match, `1` on mismatch, `2` on bad input.

## Development

```bash
pip install -r requirements-dev.txt
ruff check src/ tests/
black --check src/ tests/
isort --check-only src/ tests/
mypy src/
pytest
```