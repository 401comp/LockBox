# LockBox

Folder and loose-file encryption for macOS. Pick a folder, give it a password,
and LockBox creates a sibling `FolderName.lockbox` folder. Double-click that
folder in Finder to launch LockBox and enter its password. When you select
individual files instead, LockBox puts them in `Enc Files.lockbox`.

Unlike full-disk (FileVault) or container-mount (VeraCrypt) tools, LockBox
operates at folder granularity: you point it at exactly what you want
protected, and the rest of your disk stays untouched.

## What it does

- **Encrypts a selected folder** into a same-named sibling `.lockbox` folder —
  random-UUID `.enc` blobs under `data/`, plus a small `vault.meta` header. Original filenames
  and folder structure live *inside* the encrypted blobs. After every file is
  encrypted and verified, the source folder is removed by default, leaving
  only the opaque vault in Finder. A failure leaves the source intact.
- **Decrypts a vault** back into a sibling `Unvaulted/`, reconstructing the
  original tree (paths and mtimes preserved).
- **Prompts for a password every time** — nothing is stored in the Keychain.
- **Write-then-verify-then-delete**: each file is encrypted to a `.tmp`, read
  back and decrypted, byte-compared to the original, then renamed to `.enc`,
  and only then removed from source. A crash mid-operation cannot lose data.

## Crypto

- **KDF**: scrypt, N=2¹⁷, r=8, p=1, 16-byte salt → 32-byte key.
- **Cipher**: AES-256-GCM, 12-byte nonce per file.
- **Verifier**: encrypted marker in `vault.meta` — wrong passwords are
  rejected before any file is touched.
- **Filename hiding**: original path/size/mtime live in an authenticated
  header inside each blob. The `.lockbox` tree is opaque without the key.
- **Finder opening**: `.lockbox` is registered with LockBox, so a double-click
  prompts for the vault password instead of exposing an ordinary working folder.

## Safety notes

- **The password is the only key.** There is no recovery mechanism, no backup
  key, no vendor override. Forget it and the data is gone.
- **Encrypt over a copy the first time** until you trust the round-trip.
- LockBox uses `os.remove()` on originals — it does not do secure-erase
  overwrites (a modern SSD's wear-leveling makes that mostly theatre anyway).
- A vault's manifest and ciphertext blobs remain visible to a shell or to
  Finder's “Show Hidden Files” setting, but they are encrypted data—not hidden
  plaintext—and cannot reveal the original files without the password.

## Usage

1. Launch LockBox.
2. Pick a folder, or click **Choose Files…** for loose files.
3. Click **Encrypt Selection** → enter a password twice.
4. To decrypt: double-click the `.lockbox` folder, or choose it in LockBox.

Output goes next to the input:

```
Documents/
  Secret/               ← removed after successful encrypt (the default)
  Secret.lockbox/       ← new, double-click to prompt for password
    vault.meta
    data/
      3f9a…e1.enc
      7c02…88.enc
```

If that vault name already exists, LockBox uses a timestamped `.lockbox`
variant. Loose files always use `Enc Files.lockbox`.

## Build

Requires Homebrew Python 3.14 with Tk 9.

```
./build.sh
```

That script creates a local `.venv`, installs `cryptography` and `py2app`,
runs the self-test, builds `dist/LockBox.app`, checks with `otool -L` that
nothing links back to Homebrew paths (so the .app runs on Macs without
Homebrew), and produces `dist/LockBox.dmg` and the self-contained
`dist/LockBox-macos.zip`.

Override the interpreter with `PYTHON_BIN=/path/to/python ./build.sh`.

## Self-test

```
.venv/bin/python lockbox.py --self-test
```

Round-trips a temp folder through encrypt → wrong-password check → decrypt
→ byte-compare.

## Plugins

LockBox supports drop-in plugins without touching core functionality.
A plugin is a single `.py` file placed in
`~/Library/Application Support/LockBox/plugins/` that exports a
`register(app)` function; it loads automatically the next time you launch.

**Plugins → Manage Plugins…** lists every installed plugin with a
description and an enable/disable toggle. Disabling a plugin persists
immediately and takes effect on the next launch — its code is never even
imported while disabled. Official plugins ship through pull requests to
this repo rather than being written ad-hoc.

## Files

- `lockbox.py` — Tk UI, background worker, prefs (`~/Library/Application
  Support/LockBox/prefs.json`), history log (SQLite, same dir).
- `crypto_core.py` — vault format, scrypt/AES-GCM, encrypt/decrypt engines.
- `setup.py` — py2app config.
- `build.sh` — venv + build + DMG.

## License

MIT — see `LICENSE`.
