"""SecureHash - File Hash Generator.

Generate MD5, SHA1, and SHA256 hashes of files and verify file integrity.
"""

__version__ = "0.1.0"

from securehash.hasher import SUPPORTED_ALGORITHMS, hash_file
from securehash.verifier import verify_file

__all__ = [
    "SUPPORTED_ALGORITHMS",
    "__version__",
    "hash_file",
    "verify_file",
]
