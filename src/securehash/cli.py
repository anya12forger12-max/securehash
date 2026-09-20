"""Command-line interface for SecureHash."""

import argparse
from collections.abc import Sequence

from securehash.hasher import SUPPORTED_ALGORITHMS, hash_file
from securehash.verifier import verify_file


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="securehash",
        description="Generate MD5, SHA1, or SHA256 hashes of files and verify file integrity.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    hash_parser = subparsers.add_parser("hash", help="print the hash of a file")
    hash_parser.add_argument("file", help="path to the file to hash")
    hash_parser.add_argument(
        "-a",
        "--algorithm",
        choices=SUPPORTED_ALGORITHMS,
        default="sha256",
        help="hash algorithm (default: sha256)",
    )

    verify_parser = subparsers.add_parser("verify", help="check a file against an expected digest")
    verify_parser.add_argument("file", help="path to the file to verify")
    verify_parser.add_argument(
        "-a",
        "--algorithm",
        choices=SUPPORTED_ALGORITHMS,
        default="sha256",
        help="hash algorithm (default: sha256)",
    )
    verify_parser.add_argument("--expect", required=True, help="expected hex digest")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI; returns the process exit code."""
    args = _build_parser().parse_args(argv)

    if args.command == "hash":
        digest = hash_file(args.file, args.algorithm)
        print(f"{args.algorithm}: {digest}  {args.file}")
        return 0

    if args.command == "verify":
        if verify_file(args.file, args.expect, args.algorithm):
            print(f"OK: {args.file} matches {args.algorithm}:{args.expect}")
            return 0

        actual = hash_file(args.file, args.algorithm)
        print(f"MISMATCH: {args.file} expected {args.algorithm}:{args.expect}")
        print(f"          actual   {args.algorithm}:{actual}")
        return 1

    # Unreachable in practice: argparse enforces one of the subcommands.
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
