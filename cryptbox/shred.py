r"""Best-effort secure deletion of files.

``secure_delete`` overwrites a file's bytes (one or more passes) and then
removes it.  This is a *best-effort* shred with real, honest limits.

Honest caveat -- please read
----------------------------
On modern storage, overwriting a file's logical bytes does **not** reliably
destroy the original data:

* **SSDs / flash / NVMe** use wear-levelling and over-provisioning, so an
  overwrite is usually redirected to a *different* physical block; the old block
  still holds your data until the controller happens to erase it.
* **Copy-on-write / journaling filesystems** (Btrfs, ZFS, APFS, NTFS with
  journaling, any snapshotting layer) may keep older versions of the blocks.
* **Wear on the drive** is the reason flash does this -- you cannot defeat it
  from user space.

For genuine assurance use **full-disk encryption** (so deleted data is already
ciphertext) or physically destroy the drive.  On a plain magnetic HDD without
snapshots, a single overwrite pass is effectively unrecoverable in practice.

100% AI-built, open source, published on QuickOpen (quickopen.ai).
"""

from __future__ import annotations

import os

from .errors import CryptBoxError

_BLOCK = 1024 * 1024  # 1 MiB overwrite buffer


def secure_delete(path, passes=1):
    """Overwrite *path* with random bytes *passes* times, then remove it.

    Only regular files are shredded (directories, symlinks and special files are
    rejected).  Returns ``True`` on success; raises :class:`CryptBoxError` on any
    problem.  See the module docstring for the SSD/CoW caveat -- this is
    best-effort, not a guarantee on flash or snapshotting storage.
    """
    if passes < 1:
        raise CryptBoxError("passes must be at least 1.")
    if not os.path.exists(path):
        raise CryptBoxError(f"File not found: {path}")
    if os.path.islink(path):
        raise CryptBoxError("Refusing to shred a symlink.")
    if not os.path.isfile(path):
        raise CryptBoxError("secure_delete only shreds regular files.")

    try:
        size = os.path.getsize(path)
        with open(path, "r+b", buffering=0) as fh:
            for _ in range(passes):
                fh.seek(0)
                remaining = size
                while remaining > 0:
                    n = min(_BLOCK, remaining)
                    fh.write(os.urandom(n))
                    remaining -= n
                fh.flush()
                os.fsync(fh.fileno())
        os.remove(path)
    except OSError as exc:
        raise CryptBoxError(f"Could not shred file: {exc}") from exc
    return True
