"""LockBox crypto core.

Vault layout inside a visible, Finder-openable ``<name>.lockbox/`` folder:
  vault.meta               JSON header: magic, version, KDF params
                            (salt,n,r,p), verifier tag, creation time, and
                            the name of the blob directory below.
  data/<uuid>.enc           One encrypted blob per source file. Blob layout:
                            12-byte nonce ||
                            AES-256-GCM(ciphertext+tag) where the plaintext
                            is: 4-byte big-endian header length || JSON
                            header ({path, size, mtime}) || raw file bytes.

Original filenames and directory structure live entirely inside the encrypted
blobs; the ``.lockbox`` tree is opaque without the password.

Encrypting deletes the source by default, but only after every encrypted blob
has been written and verified byte-for-byte. Pass `delete_source=False` only
when a caller explicitly needs a plaintext copy.

Key size defaults to AES-256. Pass `key_bits=128` to `encrypt_folder`/
`encrypt_folders` for AES-128 instead — fewer AES rounds (10 vs 14) means
faster encryption on large batches, at a reduced (but still very strong)
security margin. The chosen size is recorded in `vault.meta` so decrypt
always picks the right key length automatically; it isn't a setting you
choose again at decrypt time.
"""

from __future__ import annotations

import json
import os
import secrets
import struct
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = "LOCKBOX1"
KDF_N = 2 ** 17
KDF_R = 8
KDF_P = 1
KEY_LEN = 32
SALT_LEN = 16
NONCE_LEN = 12
VERIFIER_PT = b"lockbox-verify-v1"


class LockBoxError(Exception):
    pass


class WrongPassword(LockBoxError):
    pass


@dataclass
class VaultMeta:
    salt: bytes
    n: int
    r: int
    p: int
    verifier: bytes
    verifier_nonce: bytes
    created: float
    data_dir_name: str = "data"
    key_bits: int = 256

    def to_json(self) -> str:
        return json.dumps(
            {
                "magic": MAGIC,
                "salt": self.salt.hex(),
                "kdf": {"n": self.n, "r": self.r, "p": self.p},
                "verifier": self.verifier.hex(),
                "verifier_nonce": self.verifier_nonce.hex(),
                "created": self.created,
                "data_dir_name": self.data_dir_name,
                "key_bits": self.key_bits,
            },
            indent=2,
        )

    @classmethod
    def from_json(cls, text: str) -> "VaultMeta":
        obj = json.loads(text)
        if obj.get("magic") != MAGIC:
            raise LockBoxError("Not a LockBox vault (magic mismatch)")
        k = obj["kdf"]
        return cls(
            salt=bytes.fromhex(obj["salt"]),
            n=int(k["n"]),
            r=int(k["r"]),
            p=int(k["p"]),
            verifier=bytes.fromhex(obj["verifier"]),
            verifier_nonce=bytes.fromhex(obj["verifier_nonce"]),
            created=float(obj["created"]),
            data_dir_name=obj.get("data_dir_name", "data"),
            key_bits=int(obj.get("key_bits", 256)),
        )


def derive_key(password: str, salt: bytes, n: int, r: int, p: int, key_len: int = KEY_LEN) -> bytes:
    kdf = Scrypt(salt=salt, length=key_len, n=n, r=r, p=p)
    return kdf.derive(password.encode("utf-8"))


def _validate_key_bits(key_bits: int) -> None:
    if key_bits not in (128, 256):
        raise LockBoxError(f"Unsupported key size: {key_bits}-bit (use 128 or 256)")


def _new_meta(
    password: str, data_dir_name: str = "data", key_bits: int = 256
) -> tuple[VaultMeta, bytes]:
    salt = secrets.token_bytes(SALT_LEN)
    key = derive_key(password, salt, KDF_N, KDF_R, KDF_P, key_bits // 8)
    nonce = secrets.token_bytes(NONCE_LEN)
    verifier = AESGCM(key).encrypt(nonce, VERIFIER_PT, None)
    meta = VaultMeta(
        salt=salt,
        n=KDF_N,
        r=KDF_R,
        p=KDF_P,
        verifier=verifier,
        verifier_nonce=nonce,
        created=time.time(),
        data_dir_name=data_dir_name,
        key_bits=key_bits,
    )
    return meta, key


def load_meta_and_key(vault_dir: Path, password: str) -> tuple[VaultMeta, bytes]:
    meta_path = vault_dir / "vault.meta"
    if not meta_path.exists():
        raise LockBoxError(f"vault.meta not found in {vault_dir}")
    meta = VaultMeta.from_json(meta_path.read_text("utf-8"))
    key = derive_key(password, meta.salt, meta.n, meta.r, meta.p, meta.key_bits // 8)
    try:
        pt = AESGCM(key).decrypt(meta.verifier_nonce, meta.verifier, None)
    except Exception as exc:
        raise WrongPassword("Password does not match this vault") from exc
    if pt != VERIFIER_PT:
        raise WrongPassword("Password does not match this vault")
    return meta, key


def _encrypt_bytes(key: bytes, header: dict, payload: bytes) -> bytes:
    header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    plaintext = struct.pack(">I", len(header_bytes)) + header_bytes + payload
    nonce = secrets.token_bytes(NONCE_LEN)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce + ct


def _decrypt_bytes(key: bytes, blob: bytes) -> tuple[dict, bytes]:
    if len(blob) < NONCE_LEN + 4:
        raise LockBoxError("Encrypted blob too short")
    nonce, ct = blob[:NONCE_LEN], blob[NONCE_LEN:]
    plaintext = AESGCM(key).decrypt(nonce, ct, None)
    (hlen,) = struct.unpack(">I", plaintext[:4])
    header = json.loads(plaintext[4 : 4 + hlen].decode("utf-8"))
    payload = plaintext[4 + hlen :]
    return header, payload


def _iter_files(source: Path) -> Iterable[Path]:
    for p in source.rglob("*"):
        if p.is_file() and not p.is_symlink():
            yield p


def _pick_vault_dir(parent: Path, label: str) -> Path:
    """Return a visible, Finder-openable ``.lockbox`` folder path."""
    base = parent / f"{label}.lockbox"
    if not base.exists():
        return base
    stamp = time.strftime("%Y-%m-%d_%H%M%S")
    return parent / f"{label}_{stamp}.lockbox"


def _worker_count() -> int:
    # Encrypt/decrypt of one file is I/O-bound (disk read/write) with a
    # short burst of CPU (AES-GCM via OpenSSL, which releases the GIL), so
    # threads — not processes — parallelize it well. Capped at 8: past
    # that, disk I/O dominates and more threads stop helping.
    return min(8, max(2, os.cpu_count() or 4))


def _encrypt_one(fpath: Path, rel: str, key: bytes, data_dir: Path) -> Path:
    """Encrypt one file to a .tmp, verify by reading it back and
    decrypting, then rename to .enc. Returns fpath on success; raises
    LockBoxError on a verify mismatch, leaving the source untouched.
    """
    payload = fpath.read_bytes()
    header = {
        "path": rel,
        "size": len(payload),
        "mtime": fpath.stat().st_mtime,
    }
    blob = _encrypt_bytes(key, header, payload)

    out_name = uuid.uuid4().hex + ".enc"
    tmp_path = data_dir / (out_name + ".tmp")
    final_path = data_dir / out_name
    tmp_path.write_bytes(blob)

    # Verify: read back, decrypt, compare.
    verify_blob = tmp_path.read_bytes()
    v_header, v_payload = _decrypt_bytes(key, verify_blob)
    if v_header != header or v_payload != payload:
        tmp_path.unlink(missing_ok=True)
        raise LockBoxError(f"Verify failed for {rel} — aborting, source intact")

    os.rename(tmp_path, final_path)
    return fpath


def _encrypt_entries(
    entries: list[tuple[Path, str]],
    key: bytes,
    data_dir: Path,
    delete_source: bool,
    progress: Callable[[str, int, int], None] | None,
) -> None:
    """Encrypt and verify every entry first, across a thread pool; only
    delete source files afterward, and only if every single one made it
    into the vault.

    `entries` is a list of (absolute source file, vault-relative path)
    pairs. Each file is encrypted to a .tmp, read back and decrypted,
    compared byte-for-byte, then renamed to .enc — same guarantee as doing
    it one at a time, just spread across threads since the work is
    I/O-bound. Deletion is a SEPARATE pass that only starts once the full
    inventory has been encrypted and verified — a failure on any single
    file (or on the count check itself) aborts before a single source file
    is touched, instead of leaving a part-deleted source behind.
    """
    total = len(entries)
    if progress:
        progress("scan", 0, total)

    encrypted: list[Path] = []
    with ThreadPoolExecutor(max_workers=_worker_count()) as pool:
        futures = {
            pool.submit(_encrypt_one, fpath, rel, key, data_dir): rel
            for fpath, rel in entries
        }
        for idx, future in enumerate(as_completed(futures), start=1):
            rel = futures[future]
            fpath = future.result()  # re-raises here if this entry failed
            encrypted.append(fpath)
            if progress:
                progress(rel, idx, total)

    # Inventory check — every entry must be accounted for in the vault
    # before any source file is deleted.
    if len(encrypted) != total:
        raise LockBoxError(
            f"Inventory mismatch: {len(encrypted)}/{total} files verified in "
            "the vault — refusing to delete any source files."
        )

    if delete_source:
        if progress:
            progress("deleting", 0, total)
        with ThreadPoolExecutor(max_workers=_worker_count()) as pool:
            futures = [pool.submit(fpath.unlink) for fpath in encrypted]
            for idx, future in enumerate(as_completed(futures), start=1):
                future.result()
                if progress:
                    progress("deleting", idx, total)

    if progress:
        progress("done", total, total)


def _remove_emptied_source(source: Path) -> None:
    """Remove now-empty directories bottom-up, then the source root itself."""
    for d in sorted(
        (p for p in source.rglob("*") if p.is_dir()),
        key=lambda p: len(p.parts),
        reverse=True,
    ):
        try:
            d.rmdir()
        except OSError:
            pass
    try:
        source.rmdir()
    except OSError:
        pass


def encrypt_folder(
    source: Path,
    password: str,
    progress: Callable[[str, int, int], None] | None = None,
    delete_source: bool = True,
    key_bits: int = 256,
) -> Path:
    """Encrypt every file under `source` into a sibling ``.lockbox`` folder.

    Every source file is removed only after the verified
    write-then-verify-then-delete sequence (each file is
    encrypted to a .tmp, read back and decrypted, compared byte-for-byte,
    then renamed to .enc, and only then removed from source). `key_bits`
    is 256 (default) or 128 — see module docstring.

    The vault folder carries the source folder's name, while every item
    inside it is ciphertext.  ``.lockbox`` is registered with the macOS app,
    so double-clicking the folder opens LockBox and asks for its password.
    """
    _validate_key_bits(key_bits)
    source = source.resolve()
    if not source.is_dir():
        raise LockBoxError(f"Not a directory: {source}")

    data_dir_name = "data"
    vault_dir = _pick_vault_dir(source.parent, source.name)
    data_dir = vault_dir / data_dir_name
    data_dir.mkdir(parents=True, exist_ok=False)

    meta, key = _new_meta(password, data_dir_name=data_dir_name, key_bits=key_bits)
    (vault_dir / "vault.meta").write_text(meta.to_json(), "utf-8")

    entries = [(f, f.relative_to(source).as_posix()) for f in _iter_files(source)]
    _encrypt_entries(entries, key, data_dir, delete_source, progress)

    if delete_source:
        _remove_emptied_source(source)
    return vault_dir


def encrypt_folders(
    sources: list[Path],
    password: str,
    progress: Callable[[str, int, int], None] | None = None,
    delete_source: bool = True,
    key_bits: int = 256,
) -> Path:
    """Encrypt multiple folders into ONE combined sibling ``.lockbox`` folder.

    Sources are removed after verification by default (see `encrypt_folder`). Each
    folder's files are stored under a `<folder-name>/` prefix inside the
    vault, so `decrypt_vault` recreates them as separate top-level folders.
    Folder names must be distinct (they become that prefix). `key_bits` is
    256 (default) or 128 — see module docstring. The vault is created next
    to the first folder in `sources`.
    """
    _validate_key_bits(key_bits)
    sources = [s.resolve() for s in sources]
    if not sources:
        raise LockBoxError("No folders given.")
    for s in sources:
        if not s.is_dir():
            raise LockBoxError(f"Not a directory: {s}")
    names = [s.name for s in sources]
    if len(set(names)) != len(names):
        raise LockBoxError("Folders being combined must have distinct names.")

    vault_dir = _pick_vault_dir(sources[0].parent, "Combined Folders")
    data_dir = vault_dir / "data"
    data_dir.mkdir(parents=True, exist_ok=False)

    meta, key = _new_meta(password, key_bits=key_bits)
    (vault_dir / "vault.meta").write_text(meta.to_json(), "utf-8")

    entries = [
        (f, (Path(src.name) / f.relative_to(src)).as_posix())
        for src in sources
        for f in _iter_files(src)
    ]
    _encrypt_entries(entries, key, data_dir, delete_source, progress)

    if delete_source:
        for src in sources:
            _remove_emptied_source(src)
    return vault_dir


def encrypt_files(
    sources: list[Path],
    password: str,
    progress: Callable[[str, int, int], None] | None = None,
    delete_source: bool = True,
    key_bits: int = 256,
) -> Path:
    """Encrypt selected loose files into an ``Enc Files.lockbox`` folder.

    Folder selections retain their own vault folder through ``encrypt_folder``.
    This path is deliberately separate so loose files never masquerade as a
    source directory and always land in the predictable Enc Files container.
    """
    _validate_key_bits(key_bits)
    sources = [s.resolve() for s in sources]
    if not sources:
        raise LockBoxError("No files given.")
    if any(not source.is_file() or source.is_symlink() for source in sources):
        raise LockBoxError("Loose-file encryption accepts regular files only.")
    names = [source.name for source in sources]
    if len(set(names)) != len(names):
        raise LockBoxError("Selected files must have distinct names.")

    parent = Path(os.path.commonpath([str(source.parent) for source in sources]))
    vault_dir = _pick_vault_dir(parent, "Enc Files")
    data_dir = vault_dir / "data"
    data_dir.mkdir(parents=True, exist_ok=False)
    meta, key = _new_meta(password, data_dir_name="data", key_bits=key_bits)
    (vault_dir / "vault.meta").write_text(meta.to_json(), "utf-8")
    _encrypt_entries(
        [(source, source.name) for source in sources], key, data_dir, delete_source, progress
    )
    return vault_dir


def migrate_legacy_vault(vault_dir: Path) -> Path:
    """Upgrade a one-folder legacy ``Vaulted/<original-name>/`` vault.

    No ciphertext is decrypted, regenerated, or deleted.  The old payload
    directory is renamed to anonymous ``data/`` and the outer vault becomes
    ``<original-name>.lockbox`` beside the old ``Vaulted/`` parent, matching
    the original input folder's location.  The
    migration only accepts the old single-payload layout; combined vaults
    retain their existing shape because there is no single truthful name for
    their outer folder.
    """
    vault_dir = vault_dir.resolve()
    meta_path = vault_dir / "vault.meta"
    if not meta_path.is_file():
        raise LockBoxError(f"vault.meta not found in {vault_dir}")
    meta = VaultMeta.from_json(meta_path.read_text("utf-8"))
    old_data_dir = vault_dir / meta.data_dir_name
    if meta.data_dir_name == "data":
        raise LockBoxError("This vault already uses the current anonymous layout.")
    if not old_data_dir.is_dir():
        raise LockBoxError(f"Legacy payload directory is missing: {meta.data_dir_name}")
    unexpected = [p.name for p in vault_dir.iterdir() if p.name not in {"vault.meta", meta.data_dir_name}]
    if unexpected:
        raise LockBoxError("Legacy vault has unexpected items; refusing to migrate it.")
    # Old ``Vaulted`` was created beside the input folder, so its parent is
    # the input location. Keep the upgraded vault beside that input too.
    destination = _pick_vault_dir(vault_dir.parent, meta.data_dir_name)
    if destination.exists():
        raise LockBoxError(f"Destination already exists: {destination.name}")

    # Rename ciphertext first.  If interrupted before the metadata update,
    # current LockBox can still recognize `data/` as its recovery fallback.
    old_data_dir.rename(vault_dir / "data")
    meta.data_dir_name = "data"
    tmp_meta = vault_dir / "vault.meta.tmp"
    tmp_meta.write_text(meta.to_json(), "utf-8")
    os.replace(tmp_meta, meta_path)
    vault_dir.rename(destination)
    return destination


def _decrypt_one(bpath: Path, key: bytes, destination: Path) -> str:
    """Decrypt one blob and write it under `destination`. Returns the
    original relative path (for progress display).
    """
    blob = bpath.read_bytes()
    header, payload = _decrypt_bytes(key, blob)
    rel = header["path"]
    # Guard against path escape.
    out_path = (destination / rel).resolve()
    if not str(out_path).startswith(str(destination.resolve())):
        raise LockBoxError(f"Refusing path escape: {rel}")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(payload)
    try:
        mtime = float(header.get("mtime", 0))
        if mtime:
            os.utime(out_path, (mtime, mtime))
    except OSError:
        pass
    return rel


def decrypt_vault(
    vault_dir: Path,
    password: str,
    destination: Path | None = None,
    progress: Callable[[str, int, int], None] | None = None,
) -> Path:
    """Decrypt `vault_dir` into a sibling `Unvaulted/` folder (or given path)."""
    vault_dir = vault_dir.resolve()
    meta, key = load_meta_and_key(vault_dir, password)

    data_dir = vault_dir / meta.data_dir_name
    # Recovery for an interrupted legacy-layout migration: the payload was
    # already made anonymous but the metadata update had not landed yet.
    if not data_dir.is_dir() and (vault_dir / "data").is_dir():
        data_dir = vault_dir / "data"
    if not data_dir.is_dir():
        raise LockBoxError(f"No {meta.data_dir_name}/ inside {vault_dir}")

    if destination is None:
        base = vault_dir.parent / "Unvaulted"
        destination = base
        n = 1
        while destination.exists():
            n += 1
            destination = vault_dir.parent / f"Unvaulted_{n}"
    destination.mkdir(parents=True, exist_ok=False)

    blobs = sorted(data_dir.glob("*.enc"))
    total = len(blobs)
    if progress:
        progress("scan", 0, total)

    with ThreadPoolExecutor(max_workers=_worker_count()) as pool:
        futures = [pool.submit(_decrypt_one, bpath, key, destination) for bpath in blobs]
        for idx, future in enumerate(as_completed(futures), start=1):
            rel = future.result()
            if progress:
                progress(rel, idx, total)

    if progress:
        progress("done", total, total)
    return destination
