r"""Passphrase-based authenticated file encryption for CryptBox.

This module encrypts a single file to the CryptBox container format (``.cbox``)
and decrypts it back to the exact original bytes.  It uses **scrypt** to derive a
256-bit key from the passphrase and **AES-256-GCM** to encrypt the payload as a
sequence of independently authenticated chunks, so arbitrarily large files are
processed with bounded memory (nothing is ever loaded whole).

Security properties
-------------------
* Confidentiality + integrity via AES-256-GCM (a 128-bit tag per chunk).
* A wrong passphrase, a bit-flip anywhere in the ciphertext, a reordered chunk,
  or a *truncated* file are all detected: decryption raises
  :class:`CryptBoxError` and never emits a partial or garbage output file.
  Output is written to a sibling temp file and atomically moved into place only
  after the whole stream authenticates.
* The full header is bound into every chunk as GCM associated data (AAD), so the
  KDF parameters and salt cannot be tampered with either.

Container format (all multi-byte integers big-endian)
------------------------------------------------------
The file is ``HEADER`` followed by one or more ``CHUNK`` records::

    HEADER (44 bytes, used verbatim as AAD for every chunk)
      off size field
      0   4    magic            b"CBOX"
      4   1    format version   = 1
      5   1    kdf id           = 1 (scrypt)
      6   4    scrypt N         cost parameter (power of two, e.g. 16384)
      10  4    scrypt r         block size (e.g. 8)
      14  4    scrypt p         parallelisation (e.g. 1)
      18  1    salt length      = 16
      19  16   salt             random per-file
      35  1    nonce prefix len = 4
      36  4    nonce prefix     random per-file
      40  4    chunk size       plaintext bytes per chunk (e.g. 65536)

    CHUNK (repeated; the final chunk carries the "last" flag)
      4 bytes  ciphertext length L (uint32)
      L bytes  AES-256-GCM ciphertext+tag for this chunk

    For chunk index i (0-based):
      nonce = nonce_prefix (4 bytes) || i (8-byte uint64)
      aad   = HEADER || i (8-byte uint64) || last_flag (1 byte: 0x01 last else 0x00)

    An empty plaintext still produces exactly one (empty) final chunk, so every
    valid container has at least one chunk and the "last" flag is mandatory --
    dropping trailing chunks is therefore always detected.

100% AI-built, open source, published on QuickOpen (quickopen.ai).
"""

from __future__ import annotations

import os
import struct

from .errors import CryptBoxError

# --- format constants -------------------------------------------------------
MAGIC = b"CBOX"
VERSION = 1
KDF_SCRYPT = 1
SALT_LEN = 16
NONCE_PREFIX_LEN = 4
KEY_LEN = 32                     # AES-256
TAG_LEN = 16                     # GCM tag
DEFAULT_CHUNK = 64 * 1024        # plaintext bytes per chunk

# scrypt cost parameters (interactive-strength; ~tens of MB, sub-second).
SCRYPT_N = 1 << 14               # 16384
SCRYPT_R = 8
SCRYPT_P = 1

_HEADER_STRUCT = struct.Struct(">4sBBIIIB16sB4sI")
HEADER_LEN = _HEADER_STRUCT.size  # 44


def _derive_key(passphrase, salt, n, r, p):
    """Derive a 32-byte key from *passphrase* via scrypt (raises on bad params)."""
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    if isinstance(passphrase, str):
        passphrase = passphrase.encode("utf-8")
    if not isinstance(passphrase, (bytes, bytearray)):
        raise CryptBoxError("Passphrase must be text.")
    try:
        kdf = Scrypt(salt=salt, length=KEY_LEN, n=n, r=r, p=p)
        return kdf.derive(bytes(passphrase))
    except Exception as exc:  # invalid/hostile KDF parameters
        raise CryptBoxError(f"Could not derive key: {exc}") from exc


def _pack_header(salt, nonce_prefix, chunk_size):
    return _HEADER_STRUCT.pack(
        MAGIC, VERSION, KDF_SCRYPT, SCRYPT_N, SCRYPT_R, SCRYPT_P,
        SALT_LEN, salt, NONCE_PREFIX_LEN, nonce_prefix, chunk_size)


def _parse_header(data):
    if len(data) < HEADER_LEN:
        raise CryptBoxError("Not a CryptBox file (truncated header).")
    (magic, version, kdf_id, n, r, p, salt_len, salt,
     npref_len, nonce_prefix, chunk_size) = _HEADER_STRUCT.unpack(data[:HEADER_LEN])
    if magic != MAGIC:
        raise CryptBoxError("Not a CryptBox file (bad magic).")
    if version != VERSION:
        raise CryptBoxError(f"Unsupported CryptBox format version {version}.")
    if kdf_id != KDF_SCRYPT:
        raise CryptBoxError(f"Unsupported key-derivation id {kdf_id}.")
    if salt_len != SALT_LEN or npref_len != NONCE_PREFIX_LEN:
        raise CryptBoxError("Corrupt CryptBox header (field sizes).")
    if not (1 <= chunk_size <= 1 << 30):
        raise CryptBoxError("Corrupt CryptBox header (chunk size).")
    return {"n": n, "r": r, "p": p, "salt": salt,
            "nonce_prefix": nonce_prefix, "chunk_size": chunk_size}


def _nonce(prefix, index):
    return prefix + struct.pack(">Q", index)


def _aad(header, index, last):
    return header + struct.pack(">Q", index) + (b"\x01" if last else b"\x00")


def _read_exact(fh, size):
    """Read exactly *size* bytes or raise (partial read => corrupt/truncated)."""
    buf = fh.read(size)
    if len(buf) != size:
        raise CryptBoxError("CryptBox file is truncated or corrupt.")
    return buf


def _chunks_with_last(fh, chunk_size):
    """Yield ``(plaintext, is_last)`` reading *fh* in ``chunk_size`` blocks.

    Always yields at least one item (an empty final chunk for empty input), and
    reads one block ahead so the final chunk is correctly flagged even when the
    input size is an exact multiple of ``chunk_size``.
    """
    prev = fh.read(chunk_size)
    while True:
        nxt = fh.read(chunk_size)
        if not nxt:
            yield prev, True   # empty input still yields one empty final chunk
            return
        yield prev, False
        prev = nxt


def encrypt_file(src, dst, passphrase):
    """Encrypt *src* to *dst* (CryptBox container) using *passphrase*.

    Streams the input in chunks (bounded memory).  Writes to a temp file next to
    *dst* and atomically renames on success, so a failure never leaves a partial
    output.  Raises :class:`CryptBoxError` on any problem.  Returns *dst*.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if not passphrase:
        raise CryptBoxError("A passphrase is required.")
    if not os.path.isfile(src):
        raise CryptBoxError(f"Input file not found: {src}")

    salt = os.urandom(SALT_LEN)
    nonce_prefix = os.urandom(NONCE_PREFIX_LEN)
    header = _pack_header(salt, nonce_prefix, DEFAULT_CHUNK)
    key = _derive_key(passphrase, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
    aead = AESGCM(key)

    tmp = dst + ".cbox-tmp"
    try:
        with open(src, "rb") as fin, open(tmp, "wb") as fout:
            fout.write(header)
            index = 0
            for plain, last in _chunks_with_last(fin, DEFAULT_CHUNK):
                ct = aead.encrypt(_nonce(nonce_prefix, index), plain,
                                  _aad(header, index, last))
                fout.write(struct.pack(">I", len(ct)))
                fout.write(ct)
                index += 1
            fout.flush()
            os.fsync(fout.fileno())
        os.replace(tmp, dst)
    except CryptBoxError:
        _cleanup(tmp)
        raise
    except OSError as exc:
        _cleanup(tmp)
        raise CryptBoxError(f"Encryption failed: {exc}") from exc
    except Exception as exc:
        _cleanup(tmp)
        raise CryptBoxError(f"Encryption failed: {exc}") from exc
    return dst


def decrypt_file(src, dst, passphrase):
    """Decrypt a CryptBox container *src* to *dst* using *passphrase*.

    A wrong passphrase, tampered ciphertext, reordered or truncated stream all
    raise :class:`CryptBoxError` -- and because output goes to a temp file that
    is only moved into place after the entire stream authenticates, *dst* is
    never left holding partial or garbage bytes.  Returns *dst*.
    """
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if not passphrase:
        raise CryptBoxError("A passphrase is required.")
    if not os.path.isfile(src):
        raise CryptBoxError(f"Input file not found: {src}")

    tmp = dst + ".cbox-tmp"
    try:
        with open(src, "rb") as fin, open(tmp, "wb") as fout:
            header = _read_exact(fin, HEADER_LEN)
            meta = _parse_header(header)
            key = _derive_key(passphrase, meta["salt"], meta["n"],
                              meta["r"], meta["p"])
            aead = AESGCM(key)
            index = 0
            seen_last = False
            while True:
                length_bytes = fin.read(4)
                if len(length_bytes) == 0:
                    break  # clean EOF between records
                if len(length_bytes) != 4:
                    raise CryptBoxError("CryptBox file is truncated or corrupt.")
                (clen,) = struct.unpack(">I", length_bytes)
                if clen < TAG_LEN or clen > meta["chunk_size"] + TAG_LEN:
                    raise CryptBoxError("CryptBox file is corrupt (bad chunk).")
                ct = _read_exact(fin, clen)
                nonce = _nonce(meta["nonce_prefix"], index)
                # Try as a non-final then final chunk (the flag is in the AAD).
                plain = _open_chunk(aead, nonce, ct, header, index)
                if plain is None:
                    raise CryptBoxError(
                        "Wrong passphrase, or the file has been corrupted or "
                        "tampered with.")
                data, last = plain
                fout.write(data)
                index += 1
                if last:
                    seen_last = True
                    break
            if not seen_last:
                raise CryptBoxError(
                    "CryptBox file is truncated (missing final chunk).")
            fout.flush()
            os.fsync(fout.fileno())
        os.replace(tmp, dst)
    except CryptBoxError:
        _cleanup(tmp)
        raise
    except InvalidTag:
        _cleanup(tmp)
        raise CryptBoxError(
            "Wrong passphrase, or the file has been corrupted or tampered with.")
    except OSError as exc:
        _cleanup(tmp)
        raise CryptBoxError(f"Decryption failed: {exc}") from exc
    except Exception as exc:
        _cleanup(tmp)
        raise CryptBoxError(f"Decryption failed: {exc}") from exc
    return dst


def _open_chunk(aead, nonce, ct, header, index):
    """Return ``(plaintext, is_last)`` for a chunk, or ``None`` if it won't auth.

    The last-flag lives in the AAD, so we try the non-final AAD first and the
    final AAD second; exactly one authenticates for an untampered chunk.
    """
    from cryptography.exceptions import InvalidTag

    for last in (False, True):
        try:
            data = aead.decrypt(nonce, ct, _aad(header, index, last))
            return data, last
        except InvalidTag:
            continue
    return None


def _cleanup(path):
    try:
        if os.path.exists(path):
            os.remove(path)
    except OSError:
        pass
