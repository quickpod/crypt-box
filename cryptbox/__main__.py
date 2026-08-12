"""Command-line interface: ``python -m cryptbox <command> ...``.

Commands
--------
    encrypt <src> [dst] [-p PASS]         encrypt a file  (default dst: src.cbox)
    decrypt <src> [dst] [-p PASS]         decrypt a .cbox (default dst: strips .cbox)
    encrypt-folder <dir> [out.cbox] [-p]  tar+encrypt a folder
    decrypt-folder <cbox> [dir] [-p]      decrypt+extract a folder
    shred <path> --yes [-n PASSES]        overwrite + remove a file

If ``-p/--passphrase`` is omitted, the passphrase is prompted for (twice, to
confirm, when encrypting).  Exits non-zero with a clean ``error: ...`` message
on any :class:`CryptBoxError` -- never a traceback.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys

from . import (
    CryptBoxError,
    decrypt_file,
    decrypt_folder,
    encrypt_file,
    encrypt_folder,
    make_self_decrypting,
    secure_delete,
)


# --- passphrase helpers -----------------------------------------------------
def _get_passphrase(args, confirm):
    if args.passphrase:
        return args.passphrase
    if not sys.stdin or not sys.stdin.isatty():
        # Non-interactive and none supplied: fail cleanly rather than hang.
        raise CryptBoxError(
            "No passphrase supplied (use -p/--passphrase in non-interactive use).")
    while True:
        pw = getpass.getpass("Passphrase: ")
        if not pw:
            print("Passphrase cannot be empty.", file=sys.stderr)
            continue
        if not confirm:
            return pw
        again = getpass.getpass("Confirm passphrase: ")
        if pw == again:
            return pw
        print("Passphrases did not match; try again.", file=sys.stderr)


def _default_encrypt_dst(src):
    return src + ".cbox"


def _default_decrypt_dst(src):
    if src.lower().endswith(".cbox"):
        return src[:-5]
    return src + ".out"


# --- command handlers -------------------------------------------------------
def cmd_encrypt(a):
    dst = a.dst or _default_encrypt_dst(a.src)
    pw = _get_passphrase(a, confirm=True)
    encrypt_file(a.src, dst, pw)
    print(f"Encrypted {a.src} -> {dst}")
    if a.self_extract:
        companion = dst + ".open.py"
        make_self_decrypting(dst, companion)
        print(f"Wrote self-decrypting companion -> {companion}")


def cmd_decrypt(a):
    dst = a.dst or _default_decrypt_dst(a.src)
    pw = _get_passphrase(a, confirm=False)
    decrypt_file(a.src, dst, pw)
    print(f"Decrypted {a.src} -> {dst}")


def cmd_encrypt_folder(a):
    dst = a.dst or (os.path.normpath(a.src) + ".cbox")
    pw = _get_passphrase(a, confirm=True)
    encrypt_folder(a.src, dst, pw)
    print(f"Encrypted folder {a.src} -> {dst}")
    if a.self_extract:
        companion = dst + ".open.py"
        make_self_decrypting(dst, companion)
        print(f"Wrote self-decrypting companion -> {companion}")


def cmd_decrypt_folder(a):
    dst = a.dst or _folder_default_out(a.src)
    pw = _get_passphrase(a, confirm=False)
    decrypt_folder(a.src, dst, pw)
    print(f"Decrypted folder {a.src} -> {dst}")


def _folder_default_out(src):
    base = src[:-5] if src.lower().endswith(".cbox") else src + "_out"
    return base or "cryptbox_out"


def cmd_shred(a):
    if not a.yes:
        raise CryptBoxError(
            "Refusing to shred without --yes (this permanently destroys data).")
    secure_delete(a.path, passes=a.passes)
    print(f"Shredded {a.path} ({a.passes} pass(es)).")


# --- parser -----------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(
        prog="cryptbox",
        description="CryptBox -- offline file & folder encryption "
                    "(AES-256-GCM, scrypt).")

    def _pass_arg(sp):
        sp.add_argument("-p", "--passphrase",
                        help="passphrase (prompted if omitted)")

    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("encrypt", help="Encrypt a single file")
    s.add_argument("src")
    s.add_argument("dst", nargs="?")
    _pass_arg(s)
    s.add_argument("--self-extract", action="store_true",
                   help="also write a companion .py that decrypts the output")
    s.set_defaults(func=cmd_encrypt)

    s = sub.add_parser("decrypt", help="Decrypt a .cbox file")
    s.add_argument("src")
    s.add_argument("dst", nargs="?")
    _pass_arg(s)
    s.set_defaults(func=cmd_decrypt)

    s = sub.add_parser("encrypt-folder", help="Tar and encrypt a folder")
    s.add_argument("src")
    s.add_argument("dst", nargs="?")
    _pass_arg(s)
    s.add_argument("--self-extract", action="store_true",
                   help="also write a companion .py that decrypts the output")
    s.set_defaults(func=cmd_encrypt_folder)

    s = sub.add_parser("decrypt-folder", help="Decrypt and extract a folder")
    s.add_argument("src")
    s.add_argument("dst", nargs="?")
    _pass_arg(s)
    s.set_defaults(func=cmd_decrypt_folder)

    s = sub.add_parser("shred", help="Overwrite and delete a file (best-effort)")
    s.add_argument("path")
    s.add_argument("--yes", action="store_true",
                   help="required: confirm permanent destruction")
    s.add_argument("-n", "--passes", type=int, default=1,
                   help="overwrite passes (default 1)")
    s.set_defaults(func=cmd_shred)

    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except CryptBoxError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
