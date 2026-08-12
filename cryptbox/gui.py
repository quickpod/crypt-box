#!/usr/bin/env python3
r"""CryptBox -- an Aura (QuickOpen design system) GUI on top of the ``cryptbox`` API.

A single Aura window with a sidebar of sections -- **Encrypt**, **Decrypt** and
**Shred** (plus **About**) -- each swapping into the content area.  Every
operation calls the tested core library (never re-implements crypto) and runs on
a background thread so the UI stays responsive; results are marshalled back with
``self.after`` and reported in the Aura status bar -- a success message plus an
"Open folder" button, or the :class:`CryptBoxError` message (never a traceback)
on failure.

Design goals baked in here (mirrors the QuickOpen house style):
  * built on the vendored ``cryptbox/aura.py`` design system, which layers the
    quickopen.ai look (deep space + light) over CustomTkinter.  Runtime deps:
    ``customtkinter`` (+ ``darkdetect``) -- declared in requirements.txt; the
    PyInstaller build adds ``--collect-all customtkinter``.
  * Importing this module does nothing.  Only :func:`main` builds a root window,
    and it degrades gracefully (prints a note, returns 0) with no display or
    with customtkinter missing.
  * Frozen-exe safe: bundled assets resolve via ``sys._MEIPASS`` / the exe
    directory when ``sys.frozen`` is set -- never ``__file__``.
  * Passphrases are masked in the UI and are NEVER logged, printed or persisted.

100% AI-built, open source, published on QuickOpen (quickopen.ai).
"""

from __future__ import annotations

import os
import sys
import threading

# NOTE: tkinter/customtkinter are imported lazily inside main()/build_app so that
# merely importing this module (e.g. during packaging or on a headless CI box)
# never fails.

APP_NAME = "CryptBox"
APP_VERSION = "1.0.0"
WINDOW_TITLE = "CryptBox — by QuickOpen (quickopen.ai)"
PROJECT_URL = "https://quickopen.ai/projects/crypt-box"
ACCENT = "#cf2d3a"      # publish/specs/crypt-box.json "accent": [207, 45, 58]

# Passphrase field mask (a filled circle; present in DejaVu Sans / Segoe UI).
MASK = "●"

CBOX_TYPES = [("CryptBox files", "*.cbox"), ("All files", "*.*")]
ANY_TYPES = [("All files", "*.*")]

# (tool_id, label) -- tool_id maps to a _build_<id> section builder.  Kept as a
# module-level table so the automated GUI crawler can enumerate the sections.
TOOLS = [
    ("encrypt", "Encrypt"),
    ("decrypt", "Decrypt"),
    ("shred", "Shred"),
]

TOOL_DESCRIPTIONS = {
    "encrypt": "Encrypt a file or a whole folder with a passphrase "
               "(AES-256-GCM, scrypt). Output is a single .cbox file.",
    "decrypt": "Decrypt a .cbox back to the original file, or extract it back "
               "into a folder. A wrong passphrase or a tampered file is refused.",
    "shred": "Overwrite and delete a file. Best-effort only — see the caveat "
             "about SSDs and copy-on-write filesystems below.",
}


# ---------------------------------------------------------------------------
# Asset / frozen handling  +  small OS helpers
# ---------------------------------------------------------------------------
def asset_path(name):
    """Locate a bundled asset from source OR a PyInstaller one-file build.

    For a frozen exe we look only at ``sys._MEIPASS`` and the executable's own
    directory (never ``__file__``).  From source we also consult the package
    dir, the repo root and the CWD.  Returns an absolute path or ``None``.
    """
    roots = []
    if getattr(sys, "frozen", False):
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            roots.append(meipass)
        roots.append(os.path.dirname(os.path.abspath(sys.executable)))
    else:
        here = os.path.dirname(os.path.abspath(__file__))
        roots += [here, os.path.dirname(here), os.getcwd()]
    for root in roots:
        candidate = os.path.join(root, name)
        if os.path.exists(candidate):
            return candidate
    return None


def open_in_file_manager(path):
    """Best-effort 'reveal in file manager', guarded on every platform."""
    try:
        folder = path if os.path.isdir(path) else os.path.dirname(os.path.abspath(path))
        if hasattr(os, "startfile"):          # Windows
            os.startfile(folder)              # noqa: S606 - intended
        elif sys.platform == "darwin":
            import subprocess
            subprocess.Popen(["open", folder])
        else:
            import subprocess
            subprocess.Popen(["xdg-open", folder])
        return True
    except Exception:
        return False


def open_with_default_app(path):
    """Open a file/URL with the OS default application, guarded."""
    try:
        if hasattr(os, "startfile"):
            os.startfile(path)                # noqa: S606
        elif sys.platform == "darwin":
            import subprocess
            subprocess.Popen(["open", path])
        else:
            import subprocess
            subprocess.Popen(["xdg-open", path])
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# The app (built lazily; tkinter/customtkinter imported only inside build_app)
# ---------------------------------------------------------------------------
def build_app():
    """Construct and return the App class bound to live GUI imports.

    Kept inside a function so this module imports cleanly without a display
    (and without customtkinter installed).
    """
    import tkinter as tk
    from tkinter import filedialog, ttk
    import customtkinter as ctk

    from . import aura, guiconfig
    from .crypto import decrypt_file, encrypt_file
    from .errors import CryptBoxError
    from .folder import decrypt_folder, encrypt_folder
    from .selfextract import make_self_decrypting
    from .shred import secure_delete

    # -- small reusable widgets ------------------------------------------
    class FileRow(ctk.CTkFrame):
        """A labelled path field + Browse button. ``mode`` picks the dialog.

        The old house version used a ``textvariable``; Aura entries reserve that
        for their placeholder, so we read/write with ``get``/``set`` and fire
        ``on_change`` explicitly (on typing and on a Browse pick).
        """

        def __init__(self, master, label, mode="open_any", filetypes=None,
                     placeholder="", on_change=None):
            super().__init__(master, fg_color="transparent")
            self.mode = mode
            self.filetypes = filetypes
            self._on_change = on_change
            ctk.CTkLabel(self, text=label, width=118, anchor="w",
                         font=aura.font()).pack(side="left")
            self.entry = aura.AuraEntry(self, placeholder=placeholder)
            self.entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
            aura.AuraButton(self, "Browse…", kind="secondary",
                            command=self._browse).pack(side="left")
            if on_change:
                self.entry.bind("<KeyRelease>",
                                lambda _e: on_change(self.get()))

        def _browse(self):
            ft = self.filetypes or ANY_TYPES
            if self.mode == "dir":
                p = filedialog.askdirectory(title="Choose a folder")
            elif self.mode == "save_cbox":
                p = filedialog.asksaveasfilename(
                    title="Save as", defaultextension=".cbox", filetypes=CBOX_TYPES)
            elif self.mode == "save_any":
                p = filedialog.asksaveasfilename(title="Save as", filetypes=ft)
            elif self.mode == "open_cbox":
                p = filedialog.askopenfilename(title="Choose a .cbox file",
                                               filetypes=CBOX_TYPES)
            else:
                p = filedialog.askopenfilename(title="Choose a file", filetypes=ft)
            if p:
                self.set(p)
                if self._on_change:
                    self._on_change(self.get())

        def get(self):
            return self.entry.get().strip()

        def set(self, value):
            self.entry.delete(0, "end")
            if value:
                self.entry.insert(0, value)

    class PassRow(ctk.CTkFrame):
        """A passphrase entry (masked) with a show/hide toggle.

        The value is never logged; ``show`` masks the display while ``get``
        returns the real text for the core library only.
        """

        def __init__(self, master, label="Passphrase"):
            super().__init__(master, fg_color="transparent")
            ctk.CTkLabel(self, text=label, width=118, anchor="w",
                         font=aura.font()).pack(side="left")
            self.entry = aura.AuraEntry(self, placeholder=label, show=MASK)
            self.entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
            self._shown = False
            self.btn = aura.AuraButton(self, "Show", kind="secondary", width=64,
                                       command=self._toggle)
            self.btn.pack(side="left")

        def _toggle(self):
            self._shown = not self._shown
            self.entry.configure(show="" if self._shown else MASK)
            self.btn.configure(text="Hide" if self._shown else "Show")

        def get(self):
            return self.entry.get()

    # -- the main window --------------------------------------------------
    class App(aura.AuraApp):
        def __init__(self):
            super().__init__(
                title=WINDOW_TITLE, app_name=APP_NAME, accent=ACCENT,
                theme=guiconfig.get_theme(),
                icon_png=asset_path("crypt-box.png"), version=APP_VERSION,
                tagline="offline · nothing uploaded",
                on_theme_change=guiconfig.set_theme,
                size=(980, 660), min_size=(820, 560))

            self._busy = False
            self._last_output_dir = None
            self._img_refs = []          # keep PhotoImage refs alive

            # Shared status-bar widgets (created before the first show()).
            self._prog = aura.ProgressBar(self.header_actions,
                                          mode="indeterminate", width=150)
            self._openfolder_btn = aura.AuraButton(
                self.statusbar.actions, "Open folder", kind="secondary",
                height=30, command=self._open_last_folder)

            self._set_icon()
            self._build_menu()
            self.add_section("encrypt", "Encrypt", "◈", self._build_encrypt)
            self.add_section("decrypt", "Decrypt", "⇄", self._build_decrypt)
            self.add_section("shred", "Shred", "✳", self._build_shred)
            self.add_section("about", "About", "◉", self._build_about)
            self.show("encrypt")
            self.set_status("Ready")
            self.protocol("WM_DELETE_WINDOW", self.destroy)

        # ---- assets / icon (window/taskbar icon; sidebar icon handled by Aura)
        def _set_icon(self):
            try:
                ico = asset_path("crypt-box.ico")
                if ico and os.name == "nt":
                    self.iconbitmap(ico)
                    return
            except Exception:
                pass
            try:
                png = asset_path("crypt-box.png")
                if png:
                    img = tk.PhotoImage(file=png)
                    self._img_refs.append(img)
                    self.iconphoto(True, img)
            except Exception:
                pass  # icon is cosmetic; never block launch

        # ---- menu (native menus stay; theme also lives in the sidebar toggle)
        def _build_menu(self):
            bar = tk.Menu(self)
            filem = tk.Menu(bar, tearoff=0)
            filem.add_command(label="Exit", command=self.destroy)
            bar.add_cascade(label="File", menu=filem)

            viewm = tk.Menu(bar, tearoff=0)
            viewm.add_command(
                label="Toggle dark mode",
                command=lambda: self.set_theme(
                    "light" if self.theme == "dark" else "dark"))
            bar.add_cascade(label="View", menu=viewm)

            helpm = tk.Menu(bar, tearoff=0)
            helpm.add_command(label="About", command=lambda: self.show("about"))
            helpm.add_command(label="Open project page (quickopen.ai)",
                              command=lambda: open_with_default_app(PROJECT_URL))
            bar.add_cascade(label="Help", menu=helpm)
            self.configure(menu=bar)

        # ---- section switch: clear the result bar (crawler-visible alias too)
        def show(self, sid):
            super().show(sid)
            self._clear_result()

        def _show_tool(self, tool_id):
            """House-style alias kept so the GUI crawler can drive the sections."""
            self.show(tool_id)

        # ---- background operation runner
        def _bg(self, work, on_ok, button=None, busy="Working…"):
            """Run ``work()`` off the UI thread; call ``on_ok(result)`` back on it.

            Errors are shown inline (CryptBoxError message, or a generic note),
            never as a traceback.  ``button`` is disabled while running.  Refuses
            a second op while one is in flight.
            """
            if self._busy:
                self.set_error("Please wait — an operation is already running.")
                return
            self._busy = True
            if button is not None:
                try:
                    button.state(["disabled"])
                except Exception:
                    pass
            self._clear_result(keep_status=True)
            self.set_status(busy, kind="working")
            try:
                self._prog.pack(side="right")
                self._prog.start()
            except Exception:
                pass

            def run():
                try:
                    res, err = work(), None
                except CryptBoxError as ex:
                    res, err = None, str(ex)
                except Exception as ex:  # never leak a traceback to the user
                    res, err = None, f"Unexpected error: {ex}"
                self.after(0, lambda: finish(res, err))

            def finish(res, err):
                self._busy = False
                try:
                    self._prog.stop()
                    self._prog.pack_forget()
                except Exception:
                    pass
                if button is not None:
                    try:
                        button.state(["!disabled"])
                    except Exception:
                        pass
                if err is not None:
                    self.set_error(err)
                    return
                try:
                    on_ok(res)
                except Exception as ex:
                    self.set_error(f"Post-processing error: {ex}")

            threading.Thread(target=run, daemon=True).start()

        # ---- result / status bar helpers
        def _clear_result(self, keep_status=False):
            try:
                self._openfolder_btn.pack_forget()
            except Exception:
                pass
            if not keep_status:
                self.set_status("Ready")

        def report_success(self, message, outputs=None):
            outputs = outputs or []
            for o in outputs:
                if o:
                    guiconfig.add_recent(o)
            if outputs:
                first = outputs[0]
                self._last_output_dir = (
                    first if os.path.isdir(first)
                    else os.path.dirname(os.path.abspath(first)))
                self._openfolder_btn.pack(side="left")
            else:
                self._openfolder_btn.pack_forget()
            self.set_success(message)

        def _open_last_folder(self):
            if self._last_output_dir:
                open_in_file_manager(self._last_output_dir)

        # ---- shared: a mode segmented control returning "file"/"folder"
        @staticmethod
        def _mode_getter(seg, file_label):
            return lambda: "file" if seg.get() == file_label else "folder"

        # =====================================================================
        # Encrypt section
        # =====================================================================
        def _build_encrypt(self, frame):
            aura.Caption(frame, TOOL_DESCRIPTIONS["encrypt"]).pack(
                anchor="w", pady=(0, 12))
            card = aura.Card(frame, title="Encrypt a file or folder")
            card.pack(fill="x")
            body = card.body

            FILE_LBL = "Single file"
            seg = aura.SegmentedControl(
                body, values=[FILE_LBL, "Whole folder"],
                command=lambda _v: _sync(), dynamic_resizing=True)
            seg.set(FILE_LBL)
            seg.pack(anchor="w", pady=(0, 10))
            mode = self._mode_getter(seg, FILE_LBL)

            src = FileRow(body, "Input", placeholder="File or folder to encrypt…",
                          on_change=lambda v: out.set(_suggest(v)))
            src.pack(fill="x", pady=4)
            out = FileRow(body, "Save as (.cbox)", mode="save_cbox",
                          placeholder="Encrypted output (.cbox)…",
                          filetypes=CBOX_TYPES)
            out.pack(fill="x", pady=4)
            pw = PassRow(body, "Passphrase")
            pw.pack(fill="x", pady=4)
            pw2 = PassRow(body, "Confirm")
            pw2.pack(fill="x", pady=4)

            selfx = tk.BooleanVar(value=False)
            ctk.CTkCheckBox(
                body, variable=selfx, font=aura.font(),
                text="Also write a self-decrypting companion .py "
                     "(recipient needs Python)").pack(anchor="w", pady=(8, 4))
            aura.Caption(
                body,
                "AES-256-GCM with a scrypt-derived key. Keep the passphrase "
                "safe — without it the data cannot be recovered.").pack(
                anchor="w", pady=(0, 6))
            run = aura.AuraButton(body, "Encrypt", kind="primary")
            run.pack(anchor="w", pady=(6, 0))

            def _suggest(v):
                if not v:
                    return ""
                return os.path.normpath(v) + ".cbox"

            def _sync():
                src.mode = "dir" if mode() == "folder" else "open_any"

            def go():
                inp, dest = src.get(), out.get()
                p1, p2 = pw.get(), pw2.get()
                if not inp:
                    self.set_error("Choose an input file or folder.")
                    return
                if not dest:
                    self.set_error("Choose an output .cbox file.")
                    return
                if not p1:
                    self.set_error("Enter a passphrase.")
                    return
                if p1 != p2:
                    self.set_error("The two passphrases do not match.")
                    return
                is_folder = mode() == "folder"
                do_selfx = selfx.get()

                def work():
                    if is_folder:
                        encrypt_folder(inp, dest, p1)
                    else:
                        encrypt_file(inp, dest, p1)
                    if do_selfx:
                        make_self_decrypting(dest, dest + ".open.py")
                    return dest

                self._bg(work, lambda d: self.report_success(
                    f"Encrypted → {d}", [d]), button=run, busy="Encrypting…")

            run.configure(command=go)

        # =====================================================================
        # Decrypt section
        # =====================================================================
        def _build_decrypt(self, frame):
            aura.Caption(frame, TOOL_DESCRIPTIONS["decrypt"]).pack(
                anchor="w", pady=(0, 12))
            card = aura.Card(frame, title="Decrypt a .cbox archive")
            card.pack(fill="x")
            body = card.body

            FILE_LBL = "To a file"
            seg = aura.SegmentedControl(
                body, values=[FILE_LBL, "To a folder"],
                command=lambda _v: _sync(), dynamic_resizing=True)
            seg.set(FILE_LBL)
            seg.pack(anchor="w", pady=(0, 10))
            mode = self._mode_getter(seg, FILE_LBL)

            src = FileRow(body, "Input (.cbox)", mode="open_cbox",
                          placeholder="Encrypted .cbox file…",
                          filetypes=CBOX_TYPES,
                          on_change=lambda v: out.set(_suggest(v)))
            src.pack(fill="x", pady=4)
            out = FileRow(body, "Output", mode="save_any",
                          placeholder="Where to restore…")
            out.pack(fill="x", pady=4)
            pw = PassRow(body, "Passphrase")
            pw.pack(fill="x", pady=4)
            aura.Caption(
                body,
                "A wrong passphrase or a tampered/corrupt file is detected and "
                "refused — no partial output is written.").pack(
                anchor="w", pady=(6, 6))
            run = aura.AuraButton(body, "Decrypt", kind="primary")
            run.pack(anchor="w", pady=(6, 0))

            def _suggest(v):
                if not v:
                    return ""
                if v.lower().endswith(".cbox"):
                    return v[:-5]
                return v + ".out"

            def _sync():
                out.mode = "dir" if mode() == "folder" else "save_any"

            def go():
                inp, dest, p1 = src.get(), out.get(), pw.get()
                if not inp:
                    self.set_error("Choose a .cbox file.")
                    return
                if not dest:
                    self.set_error("Choose an output location.")
                    return
                if not p1:
                    self.set_error("Enter the passphrase.")
                    return
                is_folder = mode() == "folder"

                def work():
                    if is_folder:
                        decrypt_folder(inp, dest, p1)
                    else:
                        decrypt_file(inp, dest, p1)
                    return dest

                self._bg(work, lambda d: self.report_success(
                    f"Decrypted → {d}", [d]), button=run, busy="Decrypting…")

            run.configure(command=go)

        # =====================================================================
        # Shred section
        # =====================================================================
        def _build_shred(self, frame):
            aura.Caption(frame, TOOL_DESCRIPTIONS["shred"]).pack(
                anchor="w", pady=(0, 12))
            card = aura.Card(frame, title="Securely shred a file")
            card.pack(fill="x")
            body = card.body

            src = FileRow(body, "File to shred",
                          placeholder="File to overwrite and delete…")
            src.pack(fill="x", pady=4)

            row = ctk.CTkFrame(body, fg_color="transparent")
            row.pack(fill="x", pady=4)
            ctk.CTkLabel(row, text="Passes", width=118, anchor="w",
                         font=aura.font()).pack(side="left")
            passes = tk.StringVar(value="1")
            ttk.Spinbox(row, from_=1, to=35, textvariable=passes,
                        width=6).pack(side="left")

            confirm = tk.BooleanVar(value=False)
            ctk.CTkCheckBox(
                body, variable=confirm, font=aura.font(),
                text="I understand this permanently destroys the file").pack(
                anchor="w", pady=(8, 4))
            aura.Caption(
                body,
                "Best-effort only. On SSDs/flash (wear-levelling) and "
                "copy-on-write or snapshotting filesystems, overwriting may NOT "
                "destroy the original blocks. For real assurance use full-disk "
                "encryption or destroy the drive.").pack(anchor="w", pady=(0, 6))
            run = aura.AuraButton(body, "Shred file", kind="danger")
            run.pack(anchor="w", pady=(6, 0))

            def go():
                path = src.get()
                if not path:
                    self.set_error("Choose a file to shred.")
                    return
                if not confirm.get():
                    self.set_error("Tick the confirmation box first.")
                    return
                try:
                    n = int(passes.get())
                except ValueError:
                    self.set_error("Passes must be a whole number.")
                    return
                self._bg(lambda: secure_delete(path, passes=n),
                         lambda _r: self.report_success(
                             f"Shredded {path} ({n} pass(es))."),
                         button=run, busy="Shredding…")

            run.configure(command=go)

        # =====================================================================
        # About section
        # =====================================================================
        def _build_about(self, frame):
            card = aura.Card(frame, title="About CryptBox")
            card.pack(fill="x")
            aura.Heading(card.body, APP_NAME).pack(anchor="w")
            aura.Caption(card.body, f"Version {APP_VERSION}").pack(
                anchor="w", pady=(0, 10))
            ctk.CTkLabel(
                card.body, font=aura.font(), justify="left", anchor="w",
                wraplength=520,
                text="Fast, fully-offline file & folder encryption — "
                     "AES-256-GCM with a scrypt-derived key. Create self-"
                     "describing encrypted archives and securely shred "
                     "originals.\n\n"
                     "100% AI-built, open source, published on QuickOpen. "
                     "Nothing is ever uploaded anywhere.").pack(anchor="w")
            aura.Caption(
                card.body,
                "Licensed under Apache-2.0. Built on the permissively licensed "
                "`cryptography` library and CustomTkinter (MIT).").pack(
                anchor="w", pady=(10, 4))
            link = aura.AuraButton(card.body, "Project page: quickopen.ai",
                                   kind="ghost",
                                   command=lambda: open_with_default_app(
                                       PROJECT_URL))
            link.pack(anchor="w", pady=(6, 0))

    return App


def main():
    """Entry point: build the root window and run.  Degrades on headless hosts.

    Importing this module does nothing; only this function creates a Tk root.
    With no display (e.g. a server) or without customtkinter installed, it
    prints a friendly note and returns 0 instead of raising.
    """
    try:
        import tkinter as tk
    except Exception as exc:  # tkinter missing entirely
        print(f"{APP_NAME}: a graphical environment with tkinter is required "
              f"to run the GUI ({exc}).")
        return 0

    try:
        App = build_app()
        app = App()
    except ImportError as exc:
        print(f"{APP_NAME}: the GUI needs the 'customtkinter' package "
              f"({exc}). Install it with:  pip install customtkinter")
        return 0
    except tk.TclError as exc:
        print(f"{APP_NAME}: no graphical display available — cannot start the "
              f"GUI here ({exc}). This app is intended for the Windows desktop.")
        return 0
    except Exception as exc:
        print(f"{APP_NAME}: could not start the GUI ({exc}).")
        return 1

    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
