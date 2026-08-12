#!/usr/bin/env python3
r"""CryptBox -- a pure-stdlib tkinter GUI on top of the ``cryptbox`` API.

A single main window: a left sidebar (Encrypt, Decrypt, Shred) and a main panel
that swaps to the selected tool.  Every operation calls the tested core library
(never re-implements crypto) and runs on a background thread so the UI stays
responsive; results are marshalled back with ``self.after`` and reported in a
clear inline bar -- an output path plus an "Open folder" button on success, or
the :class:`CryptBoxError` message (never a traceback) on failure.

Design goals baked in here:
  * pure standard-library tkinter/ttk -- NO third-party GUI deps.  Dark mode is a
    ttk-style + palette swap (the QuickOpen palette); "drag and drop" is an
    explicit "Browse..." button (real OS DnD would need a dependency we avoid).
  * Importing this module does nothing.  Only :func:`main` builds a root window,
    and it degrades gracefully (prints a note, returns 0) with no display.
  * Frozen-exe safe: bundled assets resolve via ``sys._MEIPASS`` / the exe
    directory when ``sys.frozen`` is set -- never ``__file__``.

100% AI-built, open source, published on QuickOpen (quickopen.ai).
"""

from __future__ import annotations

import os
import sys
import threading

# NOTE: tkinter is imported lazily inside main()/build_app so that merely
# importing this module (e.g. during packaging or on a headless CI box) never
# fails.

APP_NAME = "CryptBox"
APP_VERSION = "1.0.0"
WINDOW_TITLE = "CryptBox — by QuickOpen (quickopen.ai)"
PROJECT_URL = "https://quickopen.ai/projects/crypt-box"

CBOX_TYPES = [("CryptBox files", "*.cbox"), ("All files", "*.*")]
ANY_TYPES = [("All files", "*.*")]

# (tool_id, label) -- tool_id maps to a _panel_<id> method.
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

# ---- colour palettes (mirror the QuickOpen palette) -------------------------
PALETTES = {
    "light": {
        "bg": "#f5f7fa", "surface": "#ffffff", "text": "#141820",
        "muted": "#5b6472", "primary": "#2f5fe0", "primary_hi": "#2450c8",
        "entry": "#ffffff", "border": "#d5dae2", "sel": "#2f5fe0",
        "sel_fg": "#ffffff", "trough": "#e2e7ef", "ok": "#1f7a3d",
        "err": "#c0392b",
    },
    "dark": {
        "bg": "#0f1115", "surface": "#1a1e24", "text": "#f1f3f7",
        "muted": "#9aa4b2", "primary": "#5b86f7", "primary_hi": "#7098ff",
        "entry": "#1a1e24", "border": "#2a2f38", "sel": "#5b86f7",
        "sel_fg": "#0f1115", "trough": "#2a2f38", "ok": "#5bd68a",
        "err": "#ff6b5e",
    },
}


# ---------------------------------------------------------------------------
# Asset / frozen handling
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
# The app (built lazily; tkinter imported only inside build_app/main)
# ---------------------------------------------------------------------------
def build_app():
    """Construct and return the App class bound to a live tkinter import.

    Kept inside a function so this module imports cleanly without a display.
    """
    import tkinter as tk
    from tkinter import filedialog, ttk

    from . import guiconfig
    from .crypto import decrypt_file, encrypt_file
    from .errors import CryptBoxError
    from .folder import decrypt_folder, encrypt_folder
    from .selfextract import make_self_decrypting
    from .shred import secure_delete

    FONT = "Segoe UI"

    # -- small reusable widgets ------------------------------------------
    class FileRow(ttk.Frame):
        """A labelled path field + Browse button. ``mode`` picks the dialog."""

        def __init__(self, master, app, label, mode="open_any",
                     filetypes=None, on_change=None):
            super().__init__(master, style="TFrame")
            self.app = app
            self.mode = mode
            self.filetypes = filetypes
            self.var = tk.StringVar()
            ttk.Label(self, text=label, width=14, anchor="w").pack(side="left")
            ent = ttk.Entry(self, textvariable=self.var)
            ent.pack(side="left", fill="x", expand=True, padx=(0, 6))
            ttk.Button(self, text="Browse…", command=self._browse,
                       width=10).pack(side="left")
            if on_change:
                self.var.trace_add("write", lambda *_: on_change(self.var.get()))

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
                self.var.set(p)

        def get(self):
            return self.var.get().strip()

        def set(self, value):
            self.var.set(value or "")

    class PassRow(ttk.Frame):
        """A passphrase entry with a show/hide toggle."""

        def __init__(self, master, label="Passphrase"):
            super().__init__(master, style="TFrame")
            self.var = tk.StringVar()
            ttk.Label(self, text=label, width=14, anchor="w").pack(side="left")
            self.entry = ttk.Entry(self, textvariable=self.var, show="•")
            self.entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
            self._shown = False
            self.btn = ttk.Button(self, text="Show", width=6, command=self._toggle)
            self.btn.pack(side="left")

        def _toggle(self):
            self._shown = not self._shown
            self.entry.configure(show="" if self._shown else "•")
            self.btn.configure(text="Hide" if self._shown else "Show")

        def get(self):
            return self.var.get()

    # -- the main window --------------------------------------------------
    class App(tk.Tk):
        def __init__(self):
            super().__init__()
            self.title(WINDOW_TITLE)
            self.geometry("860x600")
            self.minsize(720, 520)

            self.theme = guiconfig.get_theme()
            self._busy = False
            self._panels = {}          # tool_id -> built frame (lazy)
            self._current = None
            self._tracked = []         # (tk_widget, role) for manual re-theming
            self._img_refs = []        # keep PhotoImage refs alive
            self._last_output_dir = None

            self._set_icon()
            self._build_menu()
            self._build_layout()
            self._apply_theme()
            self.protocol("WM_DELETE_WINDOW", self.destroy)
            self.after(50, self._select_first_tool)

        # ---- assets / icon
        def _set_icon(self):
            try:
                ico = asset_path("crypt-box.ico")
                if ico:
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

        # ---- theming
        def track(self, widget, role):
            self._tracked.append((widget, role))

        def _pal(self):
            return PALETTES[self.theme]

        def _apply_theme(self):
            p = self._pal()
            style = ttk.Style(self)
            try:
                style.theme_use("clam")
            except Exception:
                pass
            self.configure(bg=p["bg"])
            style.configure(".", background=p["bg"], foreground=p["text"],
                            fieldbackground=p["entry"], bordercolor=p["border"],
                            font=(FONT, 10))
            style.configure("TFrame", background=p["bg"])
            style.configure("Sidebar.TFrame", background=p["surface"])
            style.configure("TLabel", background=p["bg"], foreground=p["text"])
            style.configure("Muted.TLabel", background=p["bg"], foreground=p["muted"])
            style.configure("Header.TLabel", background=p["bg"], foreground=p["text"],
                            font=(FONT, 15, "bold"))
            style.configure("Sub.TLabel", background=p["bg"], foreground=p["muted"],
                            font=(FONT, 10))
            style.configure("Brand.TLabel", background=p["surface"],
                            foreground=p["text"], font=(FONT, 12, "bold"))
            style.configure("Ok.TLabel", background=p["bg"], foreground=p["ok"])
            style.configure("Err.TLabel", background=p["bg"], foreground=p["err"])
            style.configure("Status.TLabel", background=p["surface"],
                            foreground=p["muted"])
            style.configure("Nav.TButton", background=p["surface"],
                            foreground=p["text"], anchor="w", padding=(12, 8),
                            borderwidth=0, focuscolor=p["surface"])
            style.map("Nav.TButton",
                      background=[("active", p["trough"])])
            style.configure("NavActive.TButton", background=p["primary"],
                            foreground="#ffffff", anchor="w", padding=(12, 8),
                            borderwidth=0, focuscolor=p["primary"])
            style.map("NavActive.TButton",
                      background=[("active", p["primary_hi"])])
            style.configure("TButton", background=p["surface"], foreground=p["text"],
                            bordercolor=p["border"], focuscolor=p["surface"],
                            padding=(10, 5))
            style.map("TButton",
                      background=[("active", p["trough"]), ("disabled", p["bg"])],
                      foreground=[("disabled", p["muted"])])
            style.configure("Accent.TButton", background=p["primary"],
                            foreground="#ffffff", padding=(12, 6))
            style.map("Accent.TButton",
                      background=[("active", p["primary_hi"]),
                                  ("disabled", p["border"])],
                      foreground=[("disabled", p["muted"])])
            style.configure("Toggle.TButton", background=p["surface"],
                            foreground=p["text"], padding=(8, 4))
            for name in ("TEntry", "TSpinbox"):
                style.configure(name, fieldbackground=p["entry"], foreground=p["text"],
                                insertcolor=p["text"], bordercolor=p["border"])
            style.configure("TCheckbutton", background=p["bg"], foreground=p["text"])
            style.map("TCheckbutton", background=[("active", p["bg"])])
            style.configure("TRadiobutton", background=p["bg"], foreground=p["text"])
            style.map("TRadiobutton", background=[("active", p["bg"])])
            style.configure("TLabelframe", background=p["bg"], foreground=p["text"],
                            bordercolor=p["border"])
            style.configure("TLabelframe.Label", background=p["bg"],
                            foreground=p["muted"])
            style.configure("Horizontal.TProgressbar", background=p["primary"],
                            troughcolor=p["trough"], bordercolor=p["border"])
            style.configure("TScrollbar", background=p["surface"],
                            troughcolor=p["bg"], bordercolor=p["border"],
                            arrowcolor=p["text"])
            style.configure("TSeparator", background=p["border"])

            # manually re-colour raw tk widgets (Text)
            for widget, role in list(self._tracked):
                try:
                    if role == "text":
                        widget.configure(bg=p["surface"], fg=p["text"],
                                         insertbackground=p["text"],
                                         highlightthickness=1,
                                         highlightbackground=p["border"],
                                         borderwidth=0)
                except Exception:
                    pass
            # re-mark the active nav button
            if hasattr(self, "_nav_btns"):
                self._highlight_nav()

        def toggle_theme(self):
            self.theme = "dark" if self.theme == "light" else "light"
            guiconfig.set_theme(self.theme)
            self._apply_theme()
            self._theme_btn.configure(
                text="☀ Light mode" if self.theme == "dark" else "🌙 Dark mode")

        # ---- menu
        def _build_menu(self):
            bar = tk.Menu(self)
            filem = tk.Menu(bar, tearoff=0)
            filem.add_command(label="Exit", command=self.destroy)
            bar.add_cascade(label="File", menu=filem)
            viewm = tk.Menu(bar, tearoff=0)
            viewm.add_command(label="Toggle dark mode", command=self.toggle_theme)
            bar.add_cascade(label="View", menu=viewm)
            helpm = tk.Menu(bar, tearoff=0)
            helpm.add_command(label="About", command=self._about)
            helpm.add_command(label="Open project page (quickopen.ai)",
                              command=lambda: open_with_default_app(PROJECT_URL))
            bar.add_cascade(label="Help", menu=helpm)
            self.configure(menu=bar)

        # ---- layout
        def _build_layout(self):
            top = ttk.Frame(self, style="Sidebar.TFrame", padding=(12, 8))
            top.pack(fill="x", side="top")
            ttk.Label(top, text="🔒 CryptBox", style="Brand.TLabel").pack(side="left")
            ttk.Label(top, style="Status.TLabel",
                      text="  offline · open source · nothing is uploaded").pack(
                side="left")
            self._theme_btn = ttk.Button(
                top, style="Toggle.TButton", command=self.toggle_theme,
                text="☀ Light mode" if self.theme == "dark" else "🌙 Dark mode")
            self._theme_btn.pack(side="right")

            body = ttk.Frame(self, style="TFrame")
            body.pack(fill="both", expand=True)

            side = ttk.Frame(body, style="Sidebar.TFrame", width=190)
            side.pack(side="left", fill="y")
            side.pack_propagate(False)
            self._nav_btns = {}
            for tid, label in TOOLS:
                b = ttk.Button(side, text=label, style="Nav.TButton",
                               command=lambda t=tid: self._show_tool(t))
                b.pack(fill="x", padx=6, pady=(6, 0))
                self._nav_btns[tid] = b

            main = ttk.Frame(body, style="TFrame", padding=(16, 12))
            main.pack(side="left", fill="both", expand=True)
            head = ttk.Frame(main, style="TFrame")
            head.pack(fill="x")
            self.title_lbl = ttk.Label(head, text="Welcome", style="Header.TLabel")
            self.title_lbl.pack(anchor="w")
            self.desc_lbl = ttk.Label(head, text="", style="Sub.TLabel",
                                      wraplength=560, justify="left")
            self.desc_lbl.pack(anchor="w", pady=(2, 8))
            ttk.Separator(main).pack(fill="x")
            self.container = ttk.Frame(main, style="TFrame")
            self.container.pack(fill="both", expand=True, pady=(10, 8))

            # result / status bar (shared, inline)
            bar = ttk.Frame(self, style="Sidebar.TFrame", padding=(12, 6))
            bar.pack(fill="x", side="bottom")
            self.status_lbl = ttk.Label(bar, text="Ready", style="Status.TLabel",
                                        width=14, anchor="w")
            self.status_lbl.pack(side="left")
            self.progress = ttk.Progressbar(bar, mode="indeterminate", length=120)
            self.openfolder_btn = ttk.Button(bar, text="Open folder",
                                             command=self._open_last_folder)
            self.result_lbl = ttk.Label(bar, text="", style="Status.TLabel",
                                        anchor="w", wraplength=520, justify="left")
            self.result_lbl.pack(side="left", fill="x", expand=True, padx=8)

        def _highlight_nav(self):
            for tid, b in self._nav_btns.items():
                b.configure(style="NavActive.TButton" if tid == self._current
                            else "Nav.TButton")

        def _select_first_tool(self):
            self._show_tool(TOOLS[0][0])

        def _show_tool(self, tool_id):
            if self._current == tool_id:
                return
            for child in self.container.winfo_children():
                child.pack_forget()
            panel = self._panels.get(tool_id)
            if panel is None:
                panel = ttk.Frame(self.container, style="TFrame")
                builder = getattr(self, "_panel_" + tool_id, None)
                if builder:
                    builder(panel)
                else:
                    ttk.Label(panel, text="Not implemented.").pack()
                self._panels[tool_id] = panel
            panel.pack(fill="both", expand=True)
            self._current = tool_id
            label = dict(TOOLS).get(tool_id, tool_id)
            self.title_lbl.configure(text=label)
            self.desc_lbl.configure(text=TOOL_DESCRIPTIONS.get(tool_id, ""))
            self._apply_theme()
            self._clear_result()

        # ---- background operation runner
        def _bg(self, work, on_ok, button=None, busy="Working…"):
            """Run ``work()`` off the UI thread; call ``on_ok(result)`` back on it.

            Errors are shown inline (CryptBoxError message, or a generic note),
            never as a traceback.  ``button`` is disabled while running.  Refuses
            a second op while one is in flight.
            """
            if self._busy:
                self._show_error("Please wait — an operation is already running.")
                return
            self._busy = True
            if button is not None:
                try:
                    button.state(["disabled"])
                except Exception:
                    pass
            self._set_status(busy, kind="working")
            self._clear_result(keep_status=True)
            try:
                self.progress.pack(side="right", padx=(6, 0))
                self.progress.start(12)
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
                    self.progress.stop()
                    self.progress.pack_forget()
                except Exception:
                    pass
                if button is not None:
                    try:
                        button.state(["!disabled"])
                    except Exception:
                        pass
                if err is not None:
                    self._set_status("error", kind="err")
                    self._show_error(err)
                    return
                self._set_status("done", kind="ok")
                try:
                    on_ok(res)
                except Exception as ex:
                    self._show_error(f"Post-processing error: {ex}")

            threading.Thread(target=run, daemon=True).start()

        # ---- result bar helpers
        def _set_status(self, text, kind="idle"):
            p = self._pal()
            color = {"working": p["primary"], "ok": p["ok"], "err": p["err"]}.get(
                kind, p["muted"])
            self.status_lbl.configure(text=text, foreground=color)

        def _clear_result(self, keep_status=False):
            self.result_lbl.configure(text="")
            self.openfolder_btn.pack_forget()
            if not keep_status:
                self._set_status("Ready")

        def _show_error(self, message):
            self.result_lbl.configure(text="✕ " + message,
                                      foreground=self._pal()["err"])
            self.openfolder_btn.pack_forget()

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
                self.openfolder_btn.pack(side="right")
            self.result_lbl.configure(text="✓ " + message,
                                      foreground=self._pal()["ok"])
            self._set_status("done", kind="ok")

        def _open_last_folder(self):
            if self._last_output_dir:
                open_in_file_manager(self._last_output_dir)

        # ---- About
        def _about(self):
            win = tk.Toplevel(self)
            win.title("About CryptBox")
            win.configure(bg=self._pal()["bg"])
            win.resizable(False, False)
            frm = ttk.Frame(win, style="TFrame", padding=18)
            frm.pack(fill="both", expand=True)
            ttk.Label(frm, text="🔒 CryptBox", style="Header.TLabel").pack(anchor="w")
            ttk.Label(frm, text=f"Version {APP_VERSION}",
                      style="Sub.TLabel").pack(anchor="w", pady=(0, 8))
            ttk.Label(frm, style="TLabel", justify="left", wraplength=380,
                      text="Fast, fully-offline file & folder encryption — "
                           "AES-256-GCM with a scrypt-derived key.\n\n"
                           "100% AI-built, open source, published on QuickOpen.\n"
                           "Nothing is ever uploaded anywhere.").pack(anchor="w")
            ttk.Label(frm, style="Sub.TLabel", justify="left", wraplength=380,
                      text="Licensed under Apache-2.0. Built on the permissively "
                           "licensed `cryptography` library.").pack(
                anchor="w", pady=(8, 4))
            link = ttk.Label(frm, text="Project page: quickopen.ai",
                             style="Ok.TLabel", cursor="hand2")
            link.pack(anchor="w", pady=(4, 10))
            link.bind("<Button-1>", lambda e: open_with_default_app(PROJECT_URL))
            ttk.Button(frm, text="Close", command=win.destroy).pack(anchor="e")
            win.transient(self)
            win.grab_set()

        # =====================================================================
        # PANELS
        # =====================================================================
        def _panel_encrypt(self, parent):
            mode = tk.StringVar(value="file")
            box = ttk.Labelframe(parent, text="What to encrypt", padding=8)
            box.pack(fill="x", pady=(0, 6))
            ttk.Radiobutton(box, text="A single file", value="file",
                            variable=mode, command=lambda: _sync()).pack(
                side="left", padx=6)
            ttk.Radiobutton(box, text="A whole folder", value="folder",
                            variable=mode, command=lambda: _sync()).pack(
                side="left", padx=6)

            src = FileRow(parent, self, "Input",
                          on_change=lambda v: out.set(_suggest(v)))
            src.pack(fill="x", pady=4)
            out = FileRow(parent, self, "Save as (.cbox)", mode="save_cbox",
                          filetypes=CBOX_TYPES)
            out.pack(fill="x", pady=4)
            pw = PassRow(parent, "Passphrase")
            pw.pack(fill="x", pady=4)
            pw2 = PassRow(parent, "Confirm")
            pw2.pack(fill="x", pady=4)
            selfx = tk.BooleanVar(value=False)
            ttk.Checkbutton(parent, variable=selfx,
                            text="Also write a self-decrypting companion .py "
                                 "(recipient needs Python)").pack(anchor="w", pady=4)
            ttk.Label(parent, style="Muted.TLabel", wraplength=560, justify="left",
                      text="AES-256-GCM with a scrypt-derived key. Keep the "
                           "passphrase safe — without it the data cannot be "
                           "recovered.").pack(anchor="w", pady=(2, 4))
            run = ttk.Button(parent, text="Encrypt", style="Accent.TButton")
            run.pack(anchor="w", pady=6)

            def _suggest(v):
                if not v:
                    return ""
                base = os.path.normpath(v)
                return base + ".cbox"

            def _sync():
                if mode.get() == "folder":
                    src.mode = "dir"
                else:
                    src.mode = "open_any"

            def go():
                inp, dest = src.get(), out.get()
                p1, p2 = pw.get(), pw2.get()
                if not inp:
                    self._show_error("Choose an input file or folder.")
                    return
                if not dest:
                    self._show_error("Choose an output .cbox file.")
                    return
                if not p1:
                    self._show_error("Enter a passphrase.")
                    return
                if p1 != p2:
                    self._show_error("The two passphrases do not match.")
                    return
                is_folder = mode.get() == "folder"

                def work():
                    if is_folder:
                        encrypt_folder(inp, dest, p1)
                    else:
                        encrypt_file(inp, dest, p1)
                    if selfx.get():
                        make_self_decrypting(dest, dest + ".open.py")
                    return dest

                self._bg(work, lambda d: self.report_success(
                    f"Encrypted → {d}", [d]), button=run, busy="Encrypting…")

            run.configure(command=go)

        def _panel_decrypt(self, parent):
            mode = tk.StringVar(value="file")
            box = ttk.Labelframe(parent, text="Restore as", padding=8)
            box.pack(fill="x", pady=(0, 6))
            ttk.Radiobutton(box, text="A single file", value="file",
                            variable=mode, command=lambda: _sync()).pack(
                side="left", padx=6)
            ttk.Radiobutton(box, text="A folder (was encrypted as a folder)",
                            value="folder", variable=mode,
                            command=lambda: _sync()).pack(side="left", padx=6)

            src = FileRow(parent, self, "Input (.cbox)", mode="open_cbox",
                          filetypes=CBOX_TYPES,
                          on_change=lambda v: out.set(_suggest(v)))
            src.pack(fill="x", pady=4)
            out = FileRow(parent, self, "Output", mode="save_any")
            out.pack(fill="x", pady=4)
            pw = PassRow(parent, "Passphrase")
            pw.pack(fill="x", pady=4)
            ttk.Label(parent, style="Muted.TLabel", wraplength=560, justify="left",
                      text="A wrong passphrase or a tampered/corrupt file is "
                           "detected and refused — no partial output is written."
                      ).pack(anchor="w", pady=(2, 4))
            run = ttk.Button(parent, text="Decrypt", style="Accent.TButton")
            run.pack(anchor="w", pady=6)

            def _suggest(v):
                if not v:
                    return ""
                if v.lower().endswith(".cbox"):
                    return v[:-5]
                return v + ".out"

            def _sync():
                out.mode = "dir" if mode.get() == "folder" else "save_any"

            def go():
                inp, dest, p1 = src.get(), out.get(), pw.get()
                if not inp:
                    self._show_error("Choose a .cbox file.")
                    return
                if not dest:
                    self._show_error("Choose an output location.")
                    return
                if not p1:
                    self._show_error("Enter the passphrase.")
                    return
                is_folder = mode.get() == "folder"

                def work():
                    if is_folder:
                        decrypt_folder(inp, dest, p1)
                    else:
                        decrypt_file(inp, dest, p1)
                    return dest

                self._bg(work, lambda d: self.report_success(
                    f"Decrypted → {d}", [d]), button=run, busy="Decrypting…")

            run.configure(command=go)

        def _panel_shred(self, parent):
            src = FileRow(parent, self, "File to shred")
            src.pack(fill="x", pady=4)
            row = ttk.Frame(parent, style="TFrame")
            row.pack(fill="x", pady=4)
            ttk.Label(row, text="Passes", width=14, anchor="w").pack(side="left")
            passes = tk.StringVar(value="1")
            ttk.Spinbox(row, from_=1, to=35, textvariable=passes,
                        width=6).pack(side="left")
            confirm = tk.BooleanVar(value=False)
            ttk.Checkbutton(parent, variable=confirm,
                            text="I understand this permanently destroys the file"
                            ).pack(anchor="w", pady=6)
            ttk.Label(parent, style="Muted.TLabel", wraplength=560, justify="left",
                      text="Best-effort only. On SSDs/flash (wear-levelling) and "
                           "copy-on-write or snapshotting filesystems, overwriting "
                           "may NOT destroy the original blocks. For real "
                           "assurance use full-disk encryption or destroy the "
                           "drive.").pack(anchor="w", pady=(0, 4))
            run = ttk.Button(parent, text="Shred file", style="Accent.TButton")
            run.pack(anchor="w", pady=6)

            def go():
                path = src.get()
                if not path:
                    self._show_error("Choose a file to shred.")
                    return
                if not confirm.get():
                    self._show_error("Tick the confirmation box first.")
                    return
                try:
                    n = int(passes.get())
                except ValueError:
                    self._show_error("Passes must be a whole number.")
                    return
                self._bg(lambda: secure_delete(path, passes=n),
                         lambda _r: self.report_success(
                             f"Shredded {path} ({n} pass(es))."),
                         button=run, busy="Shredding…")

            run.configure(command=go)

    return App


def main():
    """Entry point: build the root window and run.  Degrades on headless hosts.

    Importing this module does nothing; only this function creates a Tk root.
    With no display (e.g. a server), it prints a friendly note and returns 0
    instead of raising.
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
