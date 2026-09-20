"""Allow ``python -m securehash`` and ``pipx run`` entry points."""

from securehash.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
