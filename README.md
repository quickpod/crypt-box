# CryptBox

A fast, **offline**, **100% open-source** file & folder encryption tool for Windows. Nothing is uploaded anywhere. Built entirely by AI with human testing and guidance, and published on [QuickOpen](https://quickopen.ai/projects/crypt-box).

> **100% AI-built and open source.** Apache-2.0.

## What it does

Encrypt and decrypt files and whole folders with AES-256-GCM and a passphrase (scrypt key derivation), create self-describing encrypted archives, and securely shred originals. Simple drag-in workflow with a clear security model. SecureVault's lightweight sibling — nothing is uploaded.

## Install

Download **`CryptBox-Setup.exe`** from the [QuickOpen page](https://quickopen.ai/projects/crypt-box) or the [GitHub release](https://github.com/quickpod/crypt-box/releases/latest) and double-click it. It installs per-user, adds Desktop and Start Menu shortcuts, and can optionally trust the QuickOpen Root CA. Authenticode-signed by the QuickOpen Code Signing CA — verify at [quickopen.ai/trust](https://quickopen.ai/trust).

## Run from source

```sh
pip install -r requirements.txt
python crypt_box_app.py          # GUI
python -m cryptbox --help    # CLI
```


## Features

- **File encryption** — passphrase-based **AES-256-GCM** with a **scrypt**-derived key. Output is a single self-describing `.cbox` container (documented header: magic, version, KDF parameters, salt, nonce).
- **Streaming / large files** — the payload is encrypted as independently authenticated chunks, so multi-gigabyte files are processed with bounded memory (nothing is ever loaded whole).
- **Tamper-evident** — a wrong passphrase, a bit-flip anywhere in the ciphertext, a reordered chunk, or a truncated file are all detected. Decryption raises a clean error and **never writes a partial or garbage output** (output goes to a temp file and is atomically moved into place only after the whole stream authenticates).
- **Folder encryption** — a folder is tarred and encrypted into one `.cbox`; decryption extracts it back with strict **path-traversal protection** (absolute paths, `..` escapes, symlinks and special members are refused).
- **Self-decrypting companion** *(optional)* — write a small `.py` next to a `.cbox` that prompts for the passphrase and decrypts it (recipient needs Python + `cryptography`, or a CryptBox install).
- **Secure shred** — overwrite and delete a file. Best-effort only, with an honest caveat: on SSDs/flash (wear-levelling) and copy-on-write/snapshotting filesystems, overwriting may not destroy the original blocks — use full-disk encryption or physically destroy the drive for real assurance.
- **Desktop GUI** — dark-mode sidebar app (Encrypt / Decrypt / Shred) with threaded operations, live progress, and clear inline success/error reporting. Fully offline; nothing is uploaded.

## CLI examples

```sh
# Encrypt a file (prompts for the passphrase if -p is omitted)
python -m cryptbox encrypt secret.pdf secret.pdf.cbox -p "my passphrase"

# Decrypt it back (default output strips the .cbox extension)
python -m cryptbox decrypt secret.pdf.cbox secret.pdf -p "my passphrase"

# Encrypt a whole folder into one .cbox, plus a self-decrypting companion
python -m cryptbox encrypt-folder ./project project.cbox --self-extract

# Decrypt and extract a folder archive
python -m cryptbox decrypt-folder project.cbox ./restored

# Securely shred a file (destructive — --yes is required)
python -m cryptbox shred old-secret.bin --yes -n 3
```

Every command exits non-zero with a clean `error: ...` message (never a traceback) on failure.

## License

Apache-2.0 — see [LICENSE](LICENSE). A 100% AI-built project published on QuickOpen.
