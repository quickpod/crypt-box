"""Error type for CryptBox."""


class CryptBoxError(Exception):
    """Raised for any recoverable failure in a CryptBox operation.

    Every public function raises this (and only this) on failure -- a wrong
    passphrase, a tampered/corrupt file, a bad path, an unreadable input -- so
    callers (the CLI and the GUI) have a single exception to catch and can show
    a clean message instead of a traceback.
    """
