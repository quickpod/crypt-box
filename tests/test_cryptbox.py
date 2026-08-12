"""Deterministic tests for the cryptbox core (run headless on Linux, tmp dirs)."""

from __future__ import annotations

import os
import struct
import tarfile

import pytest

from cryptbox import (
    CryptBoxError,
    decrypt_file,
    decrypt_folder,
    encrypt_file,
    encrypt_folder,
    secure_delete,
)
from cryptbox import crypto

PASS = "correct horse battery staple"


def _write(path, data):
    with open(path, "wb") as fh:
        fh.write(data)


def _read(path):
    with open(path, "rb") as fh:
        return fh.read()


# --- single-file round trip -------------------------------------------------
def test_encrypt_decrypt_roundtrip_exact_bytes(tmp_path):
    src = tmp_path / "plain.bin"
    payload = b"CryptBox secret payload \x00\x01\x02 with bytes \xff\xfe" * 100
    _write(src, payload)
    enc = tmp_path / "plain.cbox"
    dec = tmp_path / "plain.out"
    encrypt_file(str(src), str(enc), PASS)
    decrypt_file(str(enc), str(dec), PASS)
    assert _read(dec) == payload


def test_empty_file_roundtrip(tmp_path):
    src = tmp_path / "empty.bin"
    _write(src, b"")
    enc = tmp_path / "empty.cbox"
    dec = tmp_path / "empty.out"
    encrypt_file(str(src), str(enc), PASS)
    decrypt_file(str(enc), str(dec), PASS)
    assert _read(dec) == b""


def test_ciphertext_does_not_contain_plaintext(tmp_path):
    src = tmp_path / "p.txt"
    marker = b"TOPSECRET_MARKER_STRING_1234567890"
    _write(src, marker * 50)
    enc = tmp_path / "p.cbox"
    encrypt_file(str(src), str(enc), PASS)
    blob = _read(enc)
    assert marker not in blob
    # even a single occurrence of the repeated unit must not survive
    assert b"TOPSECRET_MARKER" not in blob


def test_wrong_passphrase_raises_and_no_valid_output(tmp_path):
    src = tmp_path / "p.bin"
    payload = b"payload-bytes-here" * 20
    _write(src, payload)
    enc = tmp_path / "p.cbox"
    dec = tmp_path / "p.out"
    encrypt_file(str(src), str(enc), PASS)
    with pytest.raises(CryptBoxError):
        decrypt_file(str(enc), str(dec), "the wrong passphrase")
    # must NOT have produced a valid output equal to the plaintext
    if dec.exists():
        assert _read(dec) != payload
    # and the temp file must be gone
    assert not (tmp_path / "p.out.cbox-tmp").exists()


def test_tampered_ciphertext_detected(tmp_path):
    src = tmp_path / "p.bin"
    payload = b"tamper-me" * 100
    _write(src, payload)
    enc = tmp_path / "p.cbox"
    dec = tmp_path / "p.out"
    encrypt_file(str(src), str(enc), PASS)
    blob = bytearray(_read(enc))
    # flip a bit well past the header, inside the ciphertext body
    idx = crypto.HEADER_LEN + 8
    blob[idx] ^= 0x01
    _write(enc, bytes(blob))
    with pytest.raises(CryptBoxError):
        decrypt_file(str(enc), str(dec), PASS)
    assert not dec.exists() or _read(dec) != payload


def test_truncated_stream_detected(tmp_path):
    src = tmp_path / "big.bin"
    # a few MB so there are multiple chunks; drop the tail
    _write(src, os.urandom(3 * 1024 * 1024))
    enc = tmp_path / "big.cbox"
    dec = tmp_path / "big.out"
    encrypt_file(str(src), str(enc), PASS)
    blob = _read(enc)
    _write(enc, blob[: len(blob) - 5000])  # chop the final chunk(s)
    with pytest.raises(CryptBoxError):
        decrypt_file(str(enc), str(dec), PASS)


def test_large_file_chunked_roundtrip(tmp_path):
    src = tmp_path / "large.bin"
    payload = os.urandom(5 * 1024 * 1024 + 12345)  # ~5MB, not a chunk multiple
    _write(src, payload)
    enc = tmp_path / "large.cbox"
    dec = tmp_path / "large.out"
    encrypt_file(str(src), str(enc), PASS)
    decrypt_file(str(enc), str(dec), PASS)
    assert _read(dec) == payload


def test_exact_chunk_multiple_roundtrip(tmp_path):
    src = tmp_path / "aligned.bin"
    payload = b"A" * (crypto.DEFAULT_CHUNK * 2)  # exact multiple of chunk size
    _write(src, payload)
    enc = tmp_path / "aligned.cbox"
    dec = tmp_path / "aligned.out"
    encrypt_file(str(src), str(enc), PASS)
    decrypt_file(str(enc), str(dec), PASS)
    assert _read(dec) == payload


def test_not_a_cbox_file(tmp_path):
    junk = tmp_path / "junk.cbox"
    _write(junk, b"this is not a cryptbox container at all, no magic here")
    with pytest.raises(CryptBoxError):
        decrypt_file(str(junk), str(tmp_path / "out"), PASS)


# --- folder round trip ------------------------------------------------------
def _make_tree(root):
    os.makedirs(os.path.join(root, "sub", "deep"))
    _write(os.path.join(root, "a.txt"), b"file a contents")
    _write(os.path.join(root, "sub", "b.bin"), os.urandom(2048))
    _write(os.path.join(root, "sub", "deep", "c.dat"), b"c" * 500)


def test_encrypt_decrypt_folder_roundtrip(tmp_path):
    tree = tmp_path / "tree"
    _make_tree(str(tree))
    cbox = tmp_path / "tree.cbox"
    outdir = tmp_path / "restored"
    encrypt_folder(str(tree), str(cbox), PASS)
    decrypt_folder(str(cbox), str(outdir), PASS)
    base = outdir / "tree"
    assert _read(str(base / "a.txt")) == b"file a contents"
    assert _read(str(base / "sub" / "deep" / "c.dat")) == b"c" * 500
    assert (base / "sub" / "b.bin").exists()


def test_folder_wrong_passphrase(tmp_path):
    tree = tmp_path / "tree"
    _make_tree(str(tree))
    cbox = tmp_path / "tree.cbox"
    encrypt_folder(str(tree), str(cbox), PASS)
    with pytest.raises(CryptBoxError):
        decrypt_folder(str(cbox), str(tmp_path / "out"), "nope nope nope")


def test_folder_blocks_path_traversal(tmp_path):
    # Build a malicious tar with a '../escape.txt' member, encrypt it as a cbox,
    # then confirm decrypt_folder refuses to extract it.
    evil_tar = tmp_path / "evil.tar"
    payload = tmp_path / "payload.txt"
    _write(payload, b"escaped!")
    with tarfile.open(str(evil_tar), "w") as tar:
        tar.add(str(payload), arcname="../escape.txt")
    cbox = tmp_path / "evil.cbox"
    encrypt_file(str(evil_tar), str(cbox), PASS)  # cbox whose plaintext is the tar
    outdir = tmp_path / "dest"
    with pytest.raises(CryptBoxError):
        decrypt_folder(str(cbox), str(outdir), PASS)
    # nothing escaped to the parent
    assert not (tmp_path / "escape.txt").exists()


def test_folder_blocks_absolute_member(tmp_path):
    evil_tar = tmp_path / "evil2.tar"
    payload = tmp_path / "payload2.txt"
    _write(payload, b"abs!")
    ti = tarfile.TarInfo(name="/tmp/cryptbox_abs_escape.txt")
    data = b"abs!"
    ti.size = len(data)
    with tarfile.open(str(evil_tar), "w") as tar:
        import io
        tar.addfile(ti, io.BytesIO(data))
    cbox = tmp_path / "evil2.cbox"
    encrypt_file(str(evil_tar), str(cbox), PASS)
    with pytest.raises(CryptBoxError):
        decrypt_folder(str(cbox), str(tmp_path / "dest2"), PASS)


# --- shred ------------------------------------------------------------------
def test_secure_delete_removes_file(tmp_path):
    target = tmp_path / "to_shred.bin"
    _write(target, os.urandom(4096))
    assert target.exists()
    assert secure_delete(str(target)) is True
    assert not target.exists()


def test_secure_delete_missing_file(tmp_path):
    with pytest.raises(CryptBoxError):
        secure_delete(str(tmp_path / "does_not_exist"))


def test_secure_delete_multi_pass(tmp_path):
    target = tmp_path / "multi.bin"
    _write(target, b"x" * 10000)
    assert secure_delete(str(target), passes=3) is True
    assert not target.exists()


# --- header sanity ----------------------------------------------------------
def test_header_magic_and_version(tmp_path):
    src = tmp_path / "h.bin"
    _write(src, b"hello")
    enc = tmp_path / "h.cbox"
    encrypt_file(str(src), str(enc), PASS)
    head = _read(enc)[: crypto.HEADER_LEN]
    magic = head[:4]
    version = head[4]
    assert magic == b"CBOX"
    assert version == crypto.VERSION
    assert struct.calcsize(crypto._HEADER_STRUCT.format) == crypto.HEADER_LEN
