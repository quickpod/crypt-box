"""CryptBox -- fast, offline, open-source file & folder encryption.

A small, permissively-licensed library on top of `cryptography`: passphrase
based AES-256-GCM encryption (scrypt key derivation) for single files and whole
folders, plus best-effort secure deletion.  Every public function raises
:class:`CryptBoxError` (and only that) on failure::

    from cryptbox import encrypt_file, decrypt_file
    encrypt_file("secret.pdf", "secret.pdf.cbox", "pass phrase")
    decrypt_file("secret.pdf.cbox", "secret.pdf", "pass phrase")

The GUI (:mod:`cryptbox.gui`) and CLI (``python -m cryptbox``) build on this
module.  Nothing is ever uploaded anywhere.

100% AI-built, open source, published on QuickOpen (quickopen.ai).
"""

from __future__ import annotations

from .errors import CryptBoxError
from .crypto import encrypt_file, decrypt_file
from .folder import encrypt_folder, decrypt_folder
from .shred import secure_delete
from .selfextract import make_self_decrypting

__version__ = "1.0.0"

__all__ = [
    "CryptBoxError",
    "encrypt_file",
    "decrypt_file",
    "encrypt_folder",
    "decrypt_folder",
    "secure_delete",
    "make_self_decrypting",
    "__version__",
]
