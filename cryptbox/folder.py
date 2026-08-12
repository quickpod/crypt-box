r"""Encrypt / decrypt whole folders as a single CryptBox archive.

A folder is packaged by streaming it into a ``tar`` archive (in a temp file),
then encrypting that tar with :mod:`cryptbox.crypto` into one ``.cbox`` file.
Decryption reverses it: decrypt to a temp tar, then extract with strict
**path-traversal protection** so a malicious archive can never write outside the
chosen destination directory (no absolute paths, no ``..`` escapes, no symlink
or device members).

100% AI-built, open source, published on QuickOpen (quickopen.ai).
"""

from __future__ import annotations

import os
import tarfile
import tempfile

from .crypto import decrypt_file, encrypt_file
from .errors import CryptBoxError


def encrypt_folder(src_dir, dst_archive, passphrase):
    """Tar *src_dir* and encrypt it to *dst_archive* (a ``.cbox`` file).

    Returns *dst_archive*.  Raises :class:`CryptBoxError` on any problem.  The
    intermediate tar is written to a temp file and always removed.
    """
    if not passphrase:
        raise CryptBoxError("A passphrase is required.")
    if not os.path.isdir(src_dir):
        raise CryptBoxError(f"Folder not found: {src_dir}")

    handle, tmp_tar = tempfile.mkstemp(suffix=".tar", prefix="cryptbox_")
    os.close(handle)
    try:
        arc_root = os.path.basename(os.path.normpath(src_dir)) or "folder"
        try:
            with tarfile.open(tmp_tar, "w") as tar:
                tar.add(src_dir, arcname=arc_root, recursive=True)
        except (OSError, tarfile.TarError) as exc:
            raise CryptBoxError(f"Could not archive folder: {exc}") from exc
        encrypt_file(tmp_tar, dst_archive, passphrase)
    finally:
        _quiet_remove(tmp_tar)
    return dst_archive


def decrypt_folder(cbox, dst_dir, passphrase):
    """Decrypt *cbox* and extract its tar into *dst_dir* (created if needed).

    Blocks path traversal: absolute paths, ``..`` components, and non-file/dir
    members (symlinks, hardlinks, devices) are rejected before extraction.
    Returns *dst_dir*.  Raises :class:`CryptBoxError` on any problem.
    """
    if not passphrase:
        raise CryptBoxError("A passphrase is required.")
    if not os.path.isfile(cbox):
        raise CryptBoxError(f"Input file not found: {cbox}")

    handle, tmp_tar = tempfile.mkstemp(suffix=".tar", prefix="cryptbox_")
    os.close(handle)
    try:
        decrypt_file(cbox, tmp_tar, passphrase)  # authenticates first
        try:
            os.makedirs(dst_dir, exist_ok=True)
        except OSError as exc:
            raise CryptBoxError(f"Could not create output folder: {exc}") from exc
        dest_root = os.path.realpath(dst_dir)
        try:
            with tarfile.open(tmp_tar, "r") as tar:
                members = tar.getmembers()
                for m in members:
                    _check_member(m, dest_root)
                _extract_all(tar, members, dest_root)
        except tarfile.TarError as exc:
            raise CryptBoxError(f"Archive is corrupt: {exc}") from exc
    finally:
        _quiet_remove(tmp_tar)
    return dst_dir


def _check_member(member, dest_root):
    """Reject any tar member that would escape *dest_root* or is not a file/dir."""
    name = member.name
    if not name or name.startswith("/") or os.path.isabs(name):
        raise CryptBoxError(f"Blocked unsafe archive path: {name!r}")
    if member.issym() or member.islnk():
        raise CryptBoxError(f"Blocked link member in archive: {name!r}")
    if member.isdev() or member.ischr() or member.isblk() or member.isfifo():
        raise CryptBoxError(f"Blocked special member in archive: {name!r}")
    target = os.path.realpath(os.path.join(dest_root, name))
    if target != dest_root and not target.startswith(dest_root + os.sep):
        raise CryptBoxError(f"Blocked path-traversal member: {name!r}")


def _extract_all(tar, members, dest_root):
    # Python 3.12+ warns unless a filter is given; "data" is the safe filter and
    # our _check_member has already vetted every member for older versions.
    try:
        tar.extractall(dest_root, members=members, filter="data")
    except TypeError:
        tar.extractall(dest_root, members=members)
    except (OSError, tarfile.TarError) as exc:
        raise CryptBoxError(f"Could not extract archive: {exc}") from exc


def _quiet_remove(path):
    try:
        if os.path.exists(path):
            os.remove(path)
    except OSError:
        pass
