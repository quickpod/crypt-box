r"""Write a tiny companion decryptor next to a ``.cbox`` file (optional feature).

``make_self_decrypting`` emits a small standalone Python script that, when run,
prompts for the passphrase and decrypts the named ``.cbox`` back to its original
bytes.  The script is intentionally minimal and self-contained: it reproduces
the CryptBox container format inline so the recipient needs only **Python 3 with
the `cryptography` package** (or a CryptBox install) -- no copy of this repo.

This does NOT bundle the ciphertext into an executable; it is a convenience
opener that lives beside the ``.cbox`` (which you send too).  The passphrase is
never written into the script.

100% AI-built, open source, published on QuickOpen (quickopen.ai).
"""

from __future__ import annotations

import os

from .errors import CryptBoxError

_TEMPLATE = r'''#!/usr/bin/env python3
"""Self-decrypting companion for {name!r} (a CryptBox .cbox file).

Run this next to {name!r}; it will prompt for the passphrase and write the
decrypted output. Requires Python 3 and the `cryptography` package
(pip install cryptography), OR a CryptBox install.
"""
import getpass
import os
import struct
import sys

CBOX = {name!r}
HEADER = struct.Struct(">4sBBIIIB16sB4sI")
MAGIC = b"CBOX"


def _open(cbox, out, passphrase):
    try:
        from cryptbox.crypto import decrypt_file
        decrypt_file(cbox, out, passphrase)
        return
    except Exception:
        pass  # no CryptBox install -- fall back to the inline decryptor
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.exceptions import InvalidTag
    with open(cbox, "rb") as fin, open(out, "wb") as fout:
        head = fin.read(HEADER.size)
        (magic, ver, kdf, n, r, p, sl, salt, npl, npref, chunk) = HEADER.unpack(head)
        if magic != MAGIC:
            raise SystemExit("Not a CryptBox file.")
        key = Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(
            passphrase.encode("utf-8"))
        aead = AESGCM(key)
        idx = 0
        while True:
            lb = fin.read(4)
            if not lb:
                break
            (clen,) = struct.unpack(">I", lb)
            ct = fin.read(clen)
            nonce = npref + struct.pack(">Q", idx)
            done = False
            for last in (False, True):
                try:
                    aad = head + struct.pack(">Q", idx) + (b"\x01" if last else b"\x00")
                    fout.write(aead.decrypt(nonce, ct, aad))
                    done = last
                    break
                except InvalidTag:
                    continue
            else:
                raise SystemExit("Wrong passphrase or corrupted file.")
            idx += 1
            if done:
                break


def main():
    if not os.path.isfile(CBOX):
        raise SystemExit("Cannot find %s next to this script." % CBOX)
    out = CBOX[:-5] if CBOX.endswith(".cbox") else CBOX + ".out"
    if os.path.exists(out):
        out = out + ".decrypted"
    pw = getpass.getpass("Passphrase: ")
    _open(CBOX, out, pw)
    print("Decrypted -> %s" % out)


if __name__ == "__main__":
    main()
'''


def make_self_decrypting(cbox, out):
    """Write a companion decryptor *out* (.py) for the container *cbox*.

    *out* is a Python script that opens the ``.cbox`` beside it after prompting
    for the passphrase.  Returns *out*.  Raises :class:`CryptBoxError` on error.
    """
    if not str(out).lower().endswith(".py"):
        raise CryptBoxError("Self-decrypting companion must be a .py file.")
    name = os.path.basename(cbox)
    script = _TEMPLATE.format(name=name)
    try:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(script)
        try:
            os.chmod(out, 0o755)
        except OSError:
            pass
    except OSError as exc:
        raise CryptBoxError(f"Could not write companion script: {exc}") from exc
    return out
