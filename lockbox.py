"""LockBox — folder encryption app.

Drag-in folder → encrypted `Vaulted/` sibling. The verified plaintext source
is removed by default, so Finder shows the vault rather than its contents.
Decrypt back to `Unvaulted/`.
Every source file is AES-256-GCM'd with a scrypt-derived key. Filenames and
directory structure are hidden inside the encrypted blobs.
"""

from __future__ import annotations

import json
import os
import queue
import sqlite3
import sys
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import applog
from crypto_core import (
    LockBoxError,
    WrongPassword,
    decrypt_vault,
    encrypt_folder,
    encrypt_folders,
)

APP_NAME = "LockBox"
APP_VERSION = "1.0.1"

# ---------- paths / prefs / history -----------------------------------------

def _app_support_dir() -> Path:
    base = Path.home() / "Library" / "Application Support" / APP_NAME
    base.mkdir(parents=True, exist_ok=True)
    return base

PREFS_PATH = _app_support_dir() / "prefs.json"
HISTORY_PATH = _app_support_dir() / "history.sqlite3"


# ---------- plugin loader -----------------------------------------------
# Core app functionality stays untouched by plugins. A plugin is a single
# .py file dropped into ~/Library/Application Support/LockBox/plugins/
# that exports a `register(app)` function; official plugins arrive via a
# reviewed PR to the GitHub repo rather than being written ad-hoc.

def _plugins_dir() -> Path:
    d = _app_support_dir() / "plugins"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _plugin_state_path() -> Path:
    return _app_support_dir() / "plugin_state.json"


def _load_plugin_state() -> dict:
    """Maps plugin filename -> enabled bool. Missing entries default enabled."""
    try:
        return json.loads(_plugin_state_path().read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save_plugin_state(state: dict) -> None:
    try:
        _plugin_state_path().write_text(json.dumps(state, indent=2))
    except Exception:
        pass


def _scan_plugin_metadata() -> list:
    """List every .py file in the plugins folder with its name/description/
    enabled state, WITHOUT importing/executing any of them — safe to call
    even for plugins the user has disabled. Uses static AST parsing to read
    top-level PLUGIN_NAME / PLUGIN_DESCRIPTION string assignments."""
    import ast
    d = _plugins_dir()
    state = _load_plugin_state()
    plugins = []
    for path in sorted(d.glob("*.py")):
        if path.name.startswith("_"):
            continue
        name = path.stem
        description = "No description provided."
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"),
                              filename=path.name)
            for node in tree.body:
                if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                        and isinstance(node.targets[0], ast.Name) \
                        and isinstance(node.value, ast.Constant) \
                        and isinstance(node.value.value, str):
                    if node.targets[0].id == "PLUGIN_NAME":
                        name = node.value.value
                    elif node.targets[0].id == "PLUGIN_DESCRIPTION":
                        description = node.value.value
        except Exception:
            pass
        plugins.append({
            "fname": path.name, "name": name, "description": description,
            "enabled": state.get(path.name, True),
        })
    return plugins


def load_plugins(app) -> list:
    """Discover and register enabled plugins. Plugins the user has disabled
    (via Plugins -> Manage Plugins...) are skipped entirely — never
    imported, so their code never runs."""
    import importlib.util
    d = _plugins_dir()
    state = _load_plugin_state()
    loaded = []
    prev_dont_write = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        for path in sorted(d.glob("*.py")):
            if path.name.startswith("_"):
                continue
            if not state.get(path.name, True):
                continue  # disabled — skip entirely, no import
            try:
                spec = importlib.util.spec_from_file_location(
                    f"lockbox_plugin_{path.stem}", path)
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                if hasattr(mod, "register") and callable(mod.register):
                    mod.register(app)
                    loaded.append(getattr(mod, "PLUGIN_NAME", path.stem))
            except Exception as e:
                applog.error(f"[{APP_NAME}] plugin {path.name} failed: {e}")
    finally:
        sys.dont_write_bytecode = prev_dont_write
    return loaded


def load_prefs() -> dict:
    try:
        return json.loads(PREFS_PATH.read_text("utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def save_prefs(prefs: dict) -> None:
    try:
        PREFS_PATH.write_text(json.dumps(prefs, indent=2), "utf-8")
    except OSError as e:
        applog.warning(f"save_prefs failed: {e}")


def _history_conn() -> sqlite3.Connection:
    con = sqlite3.connect(HISTORY_PATH)
    con.execute(
        """CREATE TABLE IF NOT EXISTS ops (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL NOT NULL,
            action TEXT NOT NULL,
            source TEXT NOT NULL,
            output TEXT NOT NULL,
            file_count INTEGER NOT NULL,
            ok INTEGER NOT NULL,
            note TEXT
        )"""
    )
    return con


def log_op(action: str, source: Path, output: Path, count: int, ok: bool, note: str = "") -> None:
    try:
        con = _history_conn()
        con.execute(
            "INSERT INTO ops (ts, action, source, output, file_count, ok, note)"
            " VALUES (?,?,?,?,?,?,?)",
            (time.time(), action, str(source), str(output), count, 1 if ok else 0, note),
        )
        con.commit()
        con.close()
    except sqlite3.Error as e:
        applog.warning(f"log_op failed to record '{action}' for {source}: {e}")


# ---------- window helpers --------------------------------------------------

def center_window(win: tk.Misc, width: int, height: int) -> None:
    win.update_idletasks()
    sw = win.winfo_screenwidth()
    sh = win.winfo_screenheight()
    x = max(0, (sw - width) // 2)
    y = max(0, (sh - height) // 3)
    win.geometry(f"{width}x{height}+{x}+{y}")


# ---------- password dialog -------------------------------------------------

class PasswordDialog(tk.Toplevel):
    def __init__(self, parent: tk.Tk, mode: str, folder_name: str):
        super().__init__(parent)
        self.title(f"{APP_NAME} — {mode.title()}")
        self.transient(parent)
        self.resizable(False, False)
        self.result: str | None = None
        self._mode = mode  # "encrypt" or "decrypt"

        pad = {"padx": 16, "pady": 6}
        ttk.Label(
            self,
            text=f"{mode.title()} '{folder_name}'",
            font=("Helvetica", 13, "bold"),
        ).grid(row=0, column=0, columnspan=2, sticky="w", **pad)

        ttk.Label(self, text="Password:").grid(row=1, column=0, sticky="e", **pad)
        self.pw1 = ttk.Entry(self, show="•", width=32)
        self.pw1.grid(row=1, column=1, sticky="w", **pad)

        if mode == "encrypt":
            ttk.Label(self, text="Confirm:").grid(row=2, column=0, sticky="e", **pad)
            self.pw2 = ttk.Entry(self, show="•", width=32)
            self.pw2.grid(row=2, column=1, sticky="w", **pad)
        else:
            self.pw2 = None

        self.msg = ttk.Label(self, text="", foreground="#e5533d")
        self.msg.grid(row=3, column=0, columnspan=2, sticky="w", **pad)

        btns = ttk.Frame(self)
        btns.grid(row=4, column=0, columnspan=2, sticky="e", padx=12, pady=(0, 12))
        ttk.Button(btns, text="Cancel", width=10, command=self._cancel).pack(side="right", padx=4)
        ttk.Button(btns, text="OK", width=10, command=self._ok, default="active").pack(side="right")

        self.bind("<Return>", lambda _e: self._ok())
        self.bind("<Escape>", lambda _e: self._cancel())

        self.update_idletasks()
        center_window(self, self.winfo_reqwidth(), self.winfo_reqheight())

        self.pw1.focus_set()
        self.grab_set()

    def _ok(self) -> None:
        p1 = self.pw1.get()
        if not p1:
            self.msg.configure(text="Password required.")
            return
        if self._mode == "encrypt":
            if len(p1) < 8:
                self.msg.configure(text="Use at least 8 characters.")
                return
            if self.pw2 is not None and p1 != self.pw2.get():
                self.msg.configure(text="Passwords don't match.")
                return
        self.result = p1
        self.destroy()

    def _cancel(self) -> None:
        self.result = None
        self.destroy()


# ---------- combine-folders dialog -------------------------------------------

class CombineFoldersDialog(tk.Toplevel):
    """Pick two or more folders to fold into a single vault."""

    def __init__(self, parent: tk.Tk):
        super().__init__(parent)
        self.title(f"{APP_NAME} — Combine Folders")
        self.transient(parent)
        self.resizable(False, False)
        self.result: list[Path] | None = None
        self._folders: list[Path] = []

        pad = {"padx": 16, "pady": 6}
        ttk.Label(
            self,
            text="Add folders to combine into one vault",
            font=("Helvetica", 13, "bold"),
        ).grid(row=0, column=0, columnspan=2, sticky="w", **pad)
        ttk.Label(
            self,
            text="Each folder keeps its own name as a top-level folder inside the vault.",
            foreground="systemSecondaryLabelColor",
        ).grid(row=1, column=0, columnspan=2, sticky="w", padx=16)

        list_frame = ttk.Frame(self)
        list_frame.grid(row=2, column=0, columnspan=2, sticky="nsew", padx=16, pady=8)
        self.listbox = tk.Listbox(
            list_frame,
            height=8,
            width=54,
            activestyle="none",
            background="systemTextBackgroundColor",
            foreground="systemTextColor",
            selectbackground="systemSelectedTextBackgroundColor",
            selectforeground="systemSelectedTextColor",
        )
        self.listbox.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(list_frame, command=self.listbox.yview)
        sb.pack(side="right", fill="y")
        self.listbox.configure(yscrollcommand=sb.set)

        add_row = ttk.Frame(self)
        add_row.grid(row=3, column=0, columnspan=2, sticky="w", padx=16, pady=(0, 6))
        ttk.Button(add_row, text="Add Folder…", command=self._add_folder).pack(side="left")
        ttk.Button(add_row, text="Remove Selected", command=self._remove_selected).pack(
            side="left", padx=8
        )

        self.msg = ttk.Label(self, text="", foreground="#e5533d")
        self.msg.grid(row=4, column=0, columnspan=2, sticky="w", padx=16)

        btns = ttk.Frame(self)
        btns.grid(row=5, column=0, columnspan=2, sticky="e", padx=12, pady=(6, 12))
        ttk.Button(btns, text="Cancel", width=10, command=self._cancel).pack(side="right", padx=4)
        ttk.Button(
            btns, text="Combine…", width=12, command=self._ok, default="active"
        ).pack(side="right")

        self.bind("<Escape>", lambda _e: self._cancel())

        self.update_idletasks()
        center_window(self, self.winfo_reqwidth(), self.winfo_reqheight())
        self.grab_set()

    def _add_folder(self) -> None:
        chosen = filedialog.askdirectory(parent=self, initialdir=str(Path.home()))
        if not chosen:
            return
        path = Path(chosen).resolve()
        if path in self._folders:
            self.msg.configure(text=f"'{path.name}' is already in the list.")
            return
        if any(f.name == path.name for f in self._folders):
            self.msg.configure(text=f"Another selected folder is also named '{path.name}'.")
            return
        self._folders.append(path)
        self.listbox.insert("end", str(path))
        self.msg.configure(text="")

    def _remove_selected(self) -> None:
        for idx in reversed(self.listbox.curselection()):
            self.listbox.delete(idx)
            del self._folders[idx]
        self.msg.configure(text="")

    def _ok(self) -> None:
        if len(self._folders) < 2:
            self.msg.configure(text="Add at least two folders to combine.")
            return
        self.result = list(self._folders)
        self.destroy()

    def _cancel(self) -> None:
        self.result = None
        self.destroy()


# ---------- main window -----------------------------------------------------

class LockBoxApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.prefs = load_prefs()
        self._build_menu()
        self._build_ui()
        load_plugins(self)
        self._worker: threading.Thread | None = None
        self._events: queue.Queue = queue.Queue()
        self.root.after(80, self._pump_events)
        self.root.report_callback_exception = self._on_callback_exception
        applog.info(f"{APP_NAME} {APP_VERSION} started.")

    # Uncaught errors ----------------------------------------------------------
    # Tk's default report_callback_exception just prints to stderr, which is
    # invisible once this is a packaged .app — nothing is left to diagnose a
    # bug that wasn't already wrapped in an explicit try/except.
    def _on_callback_exception(self, exc_type, exc_value, exc_tb) -> None:
        applog.exception("Unhandled error in a UI callback")
        messagebox.showerror(
            APP_NAME, f"An unexpected error occurred:\n{exc_value}\n\nSee View Log for details."
        )

    # Menu ---------------------------------------------------------------------

    def _build_menu(self) -> None:
        menubar = tk.Menu(self.root)
        pluginsm = tk.Menu(menubar, tearoff=0)
        pluginsm.add_command(label="Manage Plugins…", command=self._open_plugin_manager)
        pluginsm.add_command(label="Open Plugins Folder…", command=self._open_plugins_folder)
        menubar.add_cascade(label="Plugins", menu=pluginsm)
        helpm = tk.Menu(menubar, tearoff=0)
        helpm.add_command(label="View Log in Console...", command=self._open_log_console)
        helpm.add_command(label="Reveal Log in Finder", command=self._reveal_log)
        menubar.add_cascade(label="Help", menu=helpm)
        self.root.config(menu=menubar)

    def _open_plugins_folder(self) -> None:
        import subprocess
        subprocess.run(["open", str(_plugins_dir())], check=False)

    def _open_plugin_manager(self) -> None:
        win = tk.Toplevel(self.root)
        win.title("Manage Plugins")
        win.geometry("480x380")
        win.minsize(420, 260)
        win.transient(self.root)

        ttk.Label(win, text="Installed Plugins", font=('Helvetica', 14, 'bold'),
                  padding=(14, 12, 14, 4)).pack(anchor='w')

        plugins = _scan_plugin_metadata()
        list_frame = ttk.Frame(win, padding=(14, 0, 14, 0))
        list_frame.pack(fill='both', expand=True)

        restart_note = ttk.Label(win, text="", foreground='#c07a00',
                                  padding=(14, 4))
        restart_note.pack(fill='x')

        if not plugins:
            ttk.Label(list_frame,
                      text="No plugins installed.\n\nOfficial plugins ship "
                           f"through the {APP_NAME} GitHub repo — install a "
                           "released one by dropping its file into the "
                           "plugins folder.",
                      foreground='#888', justify='center',
                      wraplength=380).pack(expand=True, pady=40)
        else:
            for meta in plugins:
                row = ttk.Frame(list_frame, padding=(0, 8))
                row.pack(fill='x')
                top = ttk.Frame(row)
                top.pack(fill='x')
                ttk.Label(top, text=meta['name'],
                          font=('Helvetica', 12, 'bold')).pack(side='left')
                toggle_btn = tk.Label(top, width=3, font=('Helvetica', 12, 'bold'),
                                       relief='flat', cursor='pointinghand')
                toggle_btn.pack(side='right')
                ttk.Label(row, text=meta['description'], foreground='#888',
                          wraplength=420, justify='left').pack(anchor='w', pady=(2, 0))
                ttk.Separator(list_frame, orient='horizontal').pack(fill='x', pady=(4, 0))

                def refresh_toggle(btn=toggle_btn, m=meta):
                    if m['enabled']:
                        btn.config(text='✓', fg='white', bg='#4CAF50')
                    else:
                        btn.config(text='✗', fg='white', bg='#e57373')

                def on_toggle(event=None, btn=toggle_btn, m=meta):
                    m['enabled'] = not m['enabled']
                    state = _load_plugin_state()
                    state[m['fname']] = m['enabled']
                    _save_plugin_state(state)
                    refresh_toggle(btn, m)
                    restart_note.config(text=f"Restart {APP_NAME} for changes to take effect.")

                toggle_btn.bind('<Button-1>', on_toggle)
                refresh_toggle()

        btn_row = ttk.Frame(win, padding=12)
        btn_row.pack(fill='x')
        ttk.Button(btn_row, text="Open Plugins Folder…",
                   command=self._open_plugins_folder).pack(side='left')
        ttk.Button(btn_row, text="Close", command=win.destroy).pack(side='right')

    def _open_log_console(self) -> None:
        ok, msg = applog.open_in_console()
        if not ok:
            messagebox.showerror(APP_NAME, msg)

    def _reveal_log(self) -> None:
        ok, msg = applog.reveal_in_finder()
        if not ok:
            messagebox.showerror(APP_NAME, msg)

    # UI ---------------------------------------------------------------------

    def _build_ui(self) -> None:
        self.root.title(f"{APP_NAME} {APP_VERSION}")
        w, h = self.prefs.get("win_w", 700), self.prefs.get("win_h", 500)
        center_window(self.root, w, h)
        self.root.minsize(640, 380)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        outer = ttk.Frame(self.root, padding=16)
        outer.pack(fill="both", expand=True)

        ttk.Label(
            outer,
            text="LockBox",
            font=("Helvetica", 22, "bold"),
        ).pack(anchor="w")
        ttk.Label(
            outer,
            text="Encrypt a folder into an opaque sibling Vaulted/ folder. Decrypt it back.",
            foreground="systemSecondaryLabelColor",
        ).pack(anchor="w", pady=(0, 12))

        # Folder row
        row = ttk.Frame(outer)
        row.pack(fill="x", pady=4)
        ttk.Label(row, text="Folder:").pack(side="left")
        self.folder_var = tk.StringVar(value=self.prefs.get("last_folder", ""))
        self.folder_entry = ttk.Entry(row, textvariable=self.folder_var)
        self.folder_entry.pack(side="left", fill="x", expand=True, padx=8)
        self.choose_btn = ttk.Button(row, text="Choose…", command=self._choose_folder)
        self.choose_btn.pack(side="left")

        # Combine option — when checked, "Encrypt Folder" prompts for two or
        # more folders (via a picker) and folds them into one vault instead
        # of using the Folder field above.
        self.combine_var = tk.BooleanVar(value=False)
        self.combine_chk = ttk.Checkbutton(
            outer,
            text="Combine multiple folders into one vault",
            variable=self.combine_var,
            command=self._on_combine_toggle,
        )
        self.combine_chk.pack(anchor="w", pady=(4, 0))

        # Buttons
        btn_row = ttk.Frame(outer)
        btn_row.pack(fill="x", pady=(12, 8))
        self.enc_btn = ttk.Button(
            btn_row, text="Encrypt Folder", width=18, command=self._on_encrypt
        )
        self.enc_btn.pack(side="left")
        self.dec_btn = ttk.Button(
            btn_row, text="Decrypt Vault", width=18, command=self._on_decrypt
        )
        self.dec_btn.pack(side="left", padx=8)

        # The normal lock-up flow replaces the visible plaintext folder with
        # a verified vault.  Keeping the original is still available for a
        # backup-first workflow, but must be opted into deliberately.
        self.delete_source_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            outer,
            text="Keep the original folder after encrypting",
            variable=self.delete_source_var,
        ).pack(anchor="w", pady=(0, 4))

        # Folder-name visibility: file contents and names are always
        # encrypted; this only controls whether the vault's own top-level
        # folder is named after the source (visible in Finder) or hidden
        # behind the generic "data" name. Meaningless in Combine mode
        # (always concealed there), so it's disabled while that's checked.
        self.reveal_name_var = tk.BooleanVar(value=False)
        self.reveal_name_chk = ttk.Checkbutton(
            outer,
            text="Show the original folder name inside the vault",
            variable=self.reveal_name_var,
        )
        self.reveal_name_chk.pack(anchor="w", pady=(0, 8))

        # Key size: AES-256 is the default; AES-128 has fewer rounds and
        # encrypts faster on large batches, at a reduced (still strong)
        # security margin. Recorded per-vault, so decrypt never needs it.
        key_row = ttk.Frame(outer)
        key_row.pack(fill="x", pady=(0, 8))
        ttk.Label(key_row, text="Encryption:").pack(side="left")
        self.key_bits_var = tk.IntVar(value=256)
        ttk.Radiobutton(
            key_row, text="AES-256 (default)", variable=self.key_bits_var, value=256
        ).pack(side="left", padx=(8, 0))
        ttk.Radiobutton(
            key_row, text="AES-128 (faster)", variable=self.key_bits_var, value=128
        ).pack(side="left", padx=(8, 0))

        # Progress
        self.progress = ttk.Progressbar(outer, mode="determinate", length=100)
        self.progress.pack(fill="x", pady=(16, 4))
        self.status_var = tk.StringVar(value="Idle.")
        ttk.Label(outer, textvariable=self.status_var, foreground="systemSecondaryLabelColor").pack(anchor="w")

        # Log
        ttk.Label(outer, text="Activity", font=("Helvetica", 11, "bold")).pack(
            anchor="w", pady=(14, 2)
        )
        log_frame = ttk.Frame(outer)
        log_frame.pack(fill="both", expand=True)
        self.log = tk.Text(
            log_frame,
            height=8,
            wrap="none",
            background="systemTextBackgroundColor",
            foreground="systemTextColor",
            insertbackground="systemTextColor",
        )
        self.log.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(log_frame, command=self.log.yview)
        sb.pack(side="right", fill="y")
        self.log.configure(yscrollcommand=sb.set, state="disabled")

    # Actions ----------------------------------------------------------------

    def _choose_folder(self) -> None:
        initial = self.folder_var.get() or str(Path.home())
        chosen = filedialog.askdirectory(parent=self.root, initialdir=initial)
        if chosen:
            self.folder_var.set(chosen)

    def _validate_folder(self) -> Path | None:
        raw = self.folder_var.get().strip()
        if not raw:
            messagebox.showerror(APP_NAME, "Pick a folder first.")
            return None
        path = Path(raw).expanduser()
        if not path.is_dir():
            messagebox.showerror(APP_NAME, f"Not a folder:\n{path}")
            return None
        return path

    def _is_vault(self, path: Path) -> bool:
        return (path / "vault.meta").is_file()

    def _on_combine_toggle(self) -> None:
        state = "disabled" if self.combine_var.get() else "normal"
        self.folder_entry.configure(state=state)
        self.choose_btn.configure(state=state)
        self.reveal_name_chk.configure(state=state)

    def _on_encrypt(self) -> None:
        if self._worker and self._worker.is_alive():
            return
        if self.combine_var.get():
            self._start_combine_flow()
            return
        path = self._validate_folder()
        if not path:
            return
        if self._is_vault(path):
            if not messagebox.askyesno(
                APP_NAME,
                f"'{path.name}' looks like an existing vault. Encrypt it again anyway?",
            ):
                return
        # Warn if huge
        try:
            file_count = sum(1 for _ in path.rglob("*") if _.is_file())
        except OSError:
            file_count = 0
        if file_count == 0:
            messagebox.showerror(APP_NAME, "No files found inside that folder.")
            return
        keep_original = self.delete_source_var.get()
        if not keep_original:
            note = (
                "Every file is encrypted and verified first — source files are "
                "only deleted after the ENTIRE folder has been verified in the "
                "vault. On success, Finder will show only the encrypted vault. "
                "A failure partway through leaves the source untouched."
            )
        else:
            note = (
                "The original folder will stay beside the encrypted vault."
            )
        if not messagebox.askyesno(
            APP_NAME,
            f"Encrypt {file_count} file(s) from '{path.name}'?\n\n{note}",
        ):
            return
        dlg = PasswordDialog(self.root, "encrypt", path.name)
        self.root.wait_window(dlg)
        if not dlg.result:
            return
        self._start_worker(
            self._do_encrypt,
            path,
            dlg.result,
            not keep_original,
            self.key_bits_var.get(),
            self.reveal_name_var.get(),
        )

    def _on_decrypt(self) -> None:
        if self._worker and self._worker.is_alive():
            return
        path = self._validate_folder()
        if not path:
            return
        if not self._is_vault(path):
            messagebox.showerror(
                APP_NAME,
                f"'{path.name}' is not a LockBox vault (missing vault.meta).",
            )
            return
        dlg = PasswordDialog(self.root, "decrypt", path.name)
        self.root.wait_window(dlg)
        if not dlg.result:
            return
        self._start_worker(self._do_decrypt, path, dlg.result)

    def _start_combine_flow(self) -> None:
        dlg = CombineFoldersDialog(self.root)
        self.root.wait_window(dlg)
        if not dlg.result:
            return
        folders = dlg.result
        try:
            file_count = sum(
                1 for f in folders for p in f.rglob("*") if p.is_file()
            )
        except OSError:
            file_count = 0
        if file_count == 0:
            messagebox.showerror(APP_NAME, "No files found inside those folders.")
            return
        names = ", ".join(f.name for f in folders)
        keep_original = self.delete_source_var.get()
        if not keep_original:
            note = (
                "Every file is encrypted and verified first — source files are "
                "only deleted after ALL folders have been fully verified in "
                "the vault. On success, Finder will show only the encrypted vault. "
                "A failure partway through leaves everything untouched."
            )
        else:
            note = (
                "The original folders will stay beside the encrypted vault."
            )
        if not messagebox.askyesno(
            APP_NAME,
            f"Combine {len(folders)} folders ({file_count} file(s) total) into one vault?\n\n"
            f"{names}\n\n{note}",
        ):
            return
        pw_dlg = PasswordDialog(self.root, "encrypt", f"{len(folders)} folders")
        self.root.wait_window(pw_dlg)
        if not pw_dlg.result:
            return
        self._start_worker(
            self._do_combine, folders, pw_dlg.result, not keep_original, self.key_bits_var.get()
        )

    # Worker plumbing --------------------------------------------------------

    def _start_worker(self, target, path, password: str, *extra_args) -> None:
        self.enc_btn.configure(state="disabled")
        self.dec_btn.configure(state="disabled")
        self.combine_chk.configure(state="disabled")
        self.progress.configure(value=0, maximum=100)
        self.status_var.set("Working…")
        self._log_clear()
        self._worker = threading.Thread(
            target=target, args=(path, password, *extra_args), daemon=True
        )
        self._worker.start()

    def _do_encrypt(
        self,
        path: Path,
        password: str,
        delete_source: bool = False,
        key_bits: int = 256,
        reveal_folder_name: bool = True,
    ) -> None:
        def prog(name: str, cur: int, total: int) -> None:
            self._events.put(("progress", name, cur, total))
        try:
            vault = encrypt_folder(
                path,
                password,
                progress=prog,
                delete_source=delete_source,
                key_bits=key_bits,
                reveal_folder_name=reveal_folder_name,
            )
            count = sum(1 for _ in vault.rglob("*.enc"))
            self._events.put(("done", "encrypt", path, vault, count, None, delete_source))
        except Exception as exc:  # noqa: BLE001
            applog.exception(f"encrypt failed for {path}")
            self._events.put(
                ("done", "encrypt", path, path.parent / "Vaulted", 0, exc, delete_source)
            )

    def _do_decrypt(self, path: Path, password: str) -> None:
        def prog(name: str, cur: int, total: int) -> None:
            self._events.put(("progress", name, cur, total))
        try:
            dest = decrypt_vault(path, password, progress=prog)
            count = sum(1 for _ in dest.rglob("*") if _.is_file())
            self._events.put(("done", "decrypt", path, dest, count, None, False))
        except Exception as exc:  # noqa: BLE001
            applog.exception(f"decrypt failed for {path}")
            self._events.put(("done", "decrypt", path, path, 0, exc, False))

    def _do_combine(
        self,
        folders: list[Path],
        password: str,
        delete_source: bool = False,
        key_bits: int = 256,
    ) -> None:
        def prog(name: str, cur: int, total: int) -> None:
            self._events.put(("progress", name, cur, total))
        desc = ", ".join(f.name for f in folders)
        try:
            vault = encrypt_folders(
                folders, password, progress=prog, delete_source=delete_source, key_bits=key_bits
            )
            count = sum(1 for _ in vault.rglob("*.enc"))
            self._events.put(("done", "encrypt", desc, vault, count, None, delete_source))
        except Exception as exc:  # noqa: BLE001
            applog.exception(f"combine-encrypt failed for {desc}")
            self._events.put(
                ("done", "encrypt", desc, folders[0].parent / "Vaulted", 0, exc, delete_source)
            )

    # Event pump -------------------------------------------------------------

    def _pump_events(self) -> None:
        try:
            while True:
                evt = self._events.get_nowait()
                kind = evt[0]
                if kind == "progress":
                    _, name, cur, total = evt
                    if total:
                        self.progress.configure(maximum=total, value=cur)
                    if name == "scan":
                        self.status_var.set(f"Found {total} file(s)…")
                    elif name == "deleting":
                        self.status_var.set(f"Deleting verified source… ({cur}/{total})")
                    elif name == "done":
                        self.status_var.set(f"Finalizing… ({cur}/{total})")
                    else:
                        self.status_var.set(f"[{cur}/{total}] {name}")
                        self._log_add(f"  · {name}")
                elif kind == "done":
                    _, action, src, out, count, exc, deleted = evt
                    self.enc_btn.configure(state="normal")
                    self.dec_btn.configure(state="normal")
                    self.combine_chk.configure(state="normal")
                    if exc is None:
                        self.status_var.set(f"{action.title()} complete → {out.name}")
                        self._log_add(f"Done. {count} file(s) → {out}")
                        log_op(action, src, out, count, True)
                        if action == "encrypt":
                            source_note = (
                                "The verified source files were deleted."
                                if deleted
                                else "The original source is untouched."
                            )
                            messagebox.showinfo(
                                APP_NAME,
                                f"Encrypt complete.\n\n{count} file(s) encrypted.\n\n"
                                f"{source_note}\n"
                                f"Encrypted folder created at:\n{out}",
                            )
                        else:
                            messagebox.showinfo(
                                APP_NAME,
                                f"{action.title()} complete.\n\n{count} file(s) written to:\n{out}",
                            )
                    else:
                        note = str(exc)
                        self.status_var.set(f"{action.title()} failed: {note}")
                        self._log_add(f"ERROR: {note}")
                        log_op(action, src, out, count, False, note)
                        if isinstance(exc, WrongPassword):
                            messagebox.showerror(APP_NAME, "Wrong password.")
                        elif isinstance(exc, LockBoxError):
                            messagebox.showerror(APP_NAME, note)
                        else:
                            messagebox.showerror(APP_NAME, f"Unexpected error:\n{note}")
        except queue.Empty:
            pass
        self.root.after(80, self._pump_events)

    # Log helpers ------------------------------------------------------------

    def _log_add(self, text: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", text + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _log_clear(self) -> None:
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

    # Shutdown ---------------------------------------------------------------

    def _on_close(self) -> None:
        try:
            self.prefs["win_w"] = self.root.winfo_width()
            self.prefs["win_h"] = self.root.winfo_height()
            self.prefs["last_folder"] = self.folder_var.get()
            save_prefs(self.prefs)
        finally:
            self.root.destroy()


# ---------- self test -------------------------------------------------------

def _self_test() -> int:
    """Round-trip encrypt/decrypt into a temp dir. Returns exit code."""
    import shutil
    import tempfile

    tmp = Path(tempfile.mkdtemp(prefix="lockbox-selftest-"))
    try:
        src = tmp / "Secret"
        (src / "sub").mkdir(parents=True)
        (src / "hello.txt").write_bytes(b"hello world\n")
        (src / "sub" / "a.bin").write_bytes(os.urandom(4096))
        (src / "sub" / "utf.txt").write_text("héllo — üñïçødé", "utf-8")

        password = "correct horse battery staple"

        # Default: source is left untouched, blob dir named after the folder.
        vault = encrypt_folder(src, password)
        assert vault.is_dir(), "vault dir not created"
        assert (vault / "vault.meta").is_file(), "no vault.meta"
        assert src.exists(), "source was deleted despite delete_source defaulting to False"
        assert (vault / "Secret").is_dir(), "blob dir not named after source folder"
        meta = json.loads((vault / "vault.meta").read_text("utf-8"))
        assert meta["key_bits"] == 256, "key_bits did not default to 256"

        # reveal_folder_name=False conceals the folder name behind "data".
        src_hidden = tmp / "TopSecretProject"
        src_hidden.mkdir()
        (src_hidden / "f.txt").write_bytes(b"shh")
        vault_hidden = encrypt_folder(src_hidden, password, reveal_folder_name=False)
        assert (vault_hidden / "data").is_dir(), "concealed encrypt did not use 'data'"
        assert not (vault_hidden / "TopSecretProject").exists(), (
            "concealed encrypt leaked the source folder name"
        )
        out_hidden = decrypt_vault(vault_hidden, password, destination=tmp / "RestoredHidden")
        assert (out_hidden / "f.txt").read_bytes() == b"shh"

        # Wrong password should fail
        try:
            decrypt_vault(vault, "wrong password", destination=tmp / "should_not")
        except WrongPassword:
            pass
        else:
            raise AssertionError("wrong password did not raise")

        out = decrypt_vault(vault, password, destination=tmp / "Restored")
        assert (out / "hello.txt").read_bytes() == b"hello world\n"
        assert (out / "sub" / "utf.txt").read_text("utf-8") == "héllo — üñïçødé"
        assert (out / "sub" / "a.bin").stat().st_size == 4096

        # Explicit delete_source=True still works (opt-in legacy behavior).
        src2 = tmp / "SecretToDelete"
        src2.mkdir()
        (src2 / "f.txt").write_bytes(b"gone")
        vault2 = encrypt_folder(src2, password, delete_source=True)
        assert not src2.exists(), "delete_source=True did not remove source"
        decrypt_vault(vault2, password, destination=tmp / "Restored2")
        assert (tmp / "Restored2" / "f.txt").read_bytes() == b"gone"

        # AES-128 (faster) option — decrypt auto-detects key size from
        # vault.meta, no key_bits argument needed at decrypt time.
        src128 = tmp / "Speedy"
        src128.mkdir()
        (src128 / "f.txt").write_bytes(b"fast bytes")
        vault128 = encrypt_folder(src128, password, key_bits=128)
        meta128 = json.loads((vault128 / "vault.meta").read_text("utf-8"))
        assert meta128["key_bits"] == 128, "key_bits not recorded as 128"
        out128 = decrypt_vault(vault128, password, destination=tmp / "Restored128")
        assert (out128 / "f.txt").read_bytes() == b"fast bytes"

        # Invalid key size must be rejected before touching disk.
        try:
            encrypt_folder(src128, password, key_bits=192)
        except LockBoxError:
            pass
        else:
            raise AssertionError("invalid key_bits did not raise")

        # Combine: two folders -> one vault, each kept under its own name.
        src_a = tmp / "AlphaFolder"
        src_b = tmp / "BetaFolder"
        src_a.mkdir()
        src_b.mkdir()
        (src_a / "a.txt").write_bytes(b"alpha")
        (src_b / "b.txt").write_bytes(b"beta")

        combo_vault = encrypt_folders([src_a, src_b], password)
        assert src_a.exists() and src_b.exists(), (
            "combine deleted source despite delete_source defaulting to False"
        )

        combo_out = decrypt_vault(combo_vault, password, destination=tmp / "Combined")
        assert (combo_out / "AlphaFolder" / "a.txt").read_bytes() == b"alpha"
        assert (combo_out / "BetaFolder" / "b.txt").read_bytes() == b"beta"

        # Combine: duplicate folder names must be rejected.
        dup_a = tmp / "dupdir" / "Same"
        dup_b = tmp / "otherdir" / "Same"
        dup_a.mkdir(parents=True)
        dup_b.mkdir(parents=True)
        (dup_a / "x.txt").write_bytes(b"x")
        (dup_b / "y.txt").write_bytes(b"y")
        try:
            encrypt_folders([dup_a, dup_b], password)
        except LockBoxError:
            pass
        else:
            raise AssertionError("duplicate folder names did not raise")
        assert dup_a.exists() and dup_b.exists(), "rejected combine deleted source"

        print("self-test: PASS")
        return 0
    except AssertionError as exc:
        print(f"self-test: FAIL — {exc}")
        return 1
    except Exception as exc:  # noqa: BLE001
        print(f"self-test: ERROR — {exc}")
        return 2
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main() -> int:
    if "--self-test" in sys.argv:
        return _self_test()
    root = tk.Tk()
    ttk.Style(root).theme_use("aqua")  # inherits system Light/Dark automatically
    LockBoxApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
