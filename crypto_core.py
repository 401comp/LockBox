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
FILE_MAGIC = b"LOCKBOX-FILE-1\0"
FILE_HEADER_LEN = struct.Struct(">I")
FILE_RECORD_LEN = struct.Struct(">Q")


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


def _load_file_meta_and_key(vault_file: Path, password: str) -> tuple[VaultMeta, bytes, int]:
    """Load the unencrypted format header of a single-file vault.

    The header holds only KDF and password-verifier data.  Every original name,
    path, timestamp, and file byte remains inside individually authenticated
    encrypted records after it.
    """
    try:
        with vault_file.open("rb") as handle:
            if handle.read(len(FILE_MAGIC)) != FILE_MAGIC:
                raise LockBoxError("Not a single-file LockBox vault")
            raw_len = handle.read(FILE_HEADER_LEN.size)
            if len(raw_len) != FILE_HEADER_LEN.size:
                raise LockBoxError("Single-file vault header is incomplete")
            (header_len,) = FILE_HEADER_LEN.unpack(raw_len)
            if header_len < 2 or header_len > 1024 * 1024:
                raise LockBoxError("Single-file vault header has an invalid size")
            raw_meta = handle.read(header_len)
            if len(raw_meta) != header_len:
                raise LockBoxError("Single-file vault header is incomplete")
            offset = handle.tell()
    except OSError as exc:
        raise LockBoxError(f"Could not read vault: {exc}") from exc

    try:
        meta = VaultMeta.from_json(raw_meta.decode("utf-8"))
    except Exception as exc:
        raise LockBoxError("Vault is damaged or was modified (invalid header).") from exc
    key = derive_key(password, meta.salt, meta.n, meta.r, meta.p, meta.key_bits // 8)
    try:
        verified = AESGCM(key).decrypt(meta.verifier_nonce, meta.verifier, None)
    except Exception as exc:
        raise WrongPassword("Password does not match this vault") from exc
    if verified != VERIFIER_PT:
        raise WrongPassword("Password does not match this vault")
    return meta, key, offset


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


def _pick_vault_file(parent: Path, label: str) -> Path:
    """Return an unused, opaque single-file vault path."""
    return _pick_vault_dir(parent, label)


def _validate_vault_file_path(vault_file: Path) -> Path:
    vault_file = vault_file.expanduser().resolve()
    if vault_file.exists():
        raise LockBoxError(f"A file already exists at: {vault_file}")
    if vault_file.suffix.lower() != ".lockbox":
        raise LockBoxError("Single-file vault names must end in .lockbox")
    if not vault_file.parent.is_dir():
        raise LockBoxError(f"Vault destination folder does not exist: {vault_file.parent}")
    return vault_file


def _write_file_vault(
    entries: list[tuple[Path, str]],
    password: str,
    vault_file: Path,
    delete_source: bool,
    progress: Callable[[str, int, int], None] | None,
    key_bits: int,
) -> Path:
    """Create, verify, then atomically publish one opaque vault file."""
    if not entries:
        raise LockBoxError("No files to encrypt.")
    vault_file = _validate_vault_file_path(vault_file)
    meta, key = _new_meta(password, data_dir_name="", key_bits=key_bits)
    tmp_file = vault_file.with_name(vault_file.name + ".tmp")
    if tmp_file.exists():
        raise LockBoxError(f"Temporary vault file already exists: {tmp_file}")
    total = len(entries)
    verified = False
    try:
        with tmp_file.open("xb") as handle:
            meta_bytes = meta.to_json().encode("utf-8")
            handle.write(FILE_MAGIC)
            handle.write(FILE_HEADER_LEN.pack(len(meta_bytes)))
            handle.write(meta_bytes)
            for idx, (source, rel) in enumerate(entries, start=1):
                payload = source.read_bytes()
                header = {"path": rel, "size": len(payload), "mtime": source.stat().st_mtime}
                blob = _encrypt_bytes(key, header, payload)
                handle.write(FILE_RECORD_LEN.pack(len(blob)))
                handle.write(blob)
                if progress:
                    progress(rel, idx, total)
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(tmp_file, vault_file)
        _, verify_key, offset = _load_file_meta_and_key(vault_file, password)
        with vault_file.open("rb") as handle:
            handle.seek(offset)
            for source, expected_rel in entries:
                raw_len = handle.read(FILE_RECORD_LEN.size)
                if len(raw_len) != FILE_RECORD_LEN.size:
                    raise LockBoxError("Vault verification found a missing encrypted record")
                (blob_len,) = FILE_RECORD_LEN.unpack(raw_len)
                blob = handle.read(blob_len)
                if len(blob) != blob_len:
                    raise LockBoxError("Vault verification found a truncated encrypted record")
                header, payload = _decrypt_bytes(verify_key, blob)
                if header.get("path") != expected_rel or payload != source.read_bytes():
                    raise LockBoxError(f"Vault verification failed for {expected_rel}; source left intact")
            if handle.read(1):
                raise LockBoxError("Vault verification found unexpected trailing data")

        verified = True
        if delete_source:
            if progress:
                progress("deleting", 0, total)
            for idx, (source, _rel) in enumerate(entries, start=1):
                source.unlink()
                if progress:
                    progress("deleting", idx, total)
        if progress:
            progress("done", total, total)
        return vault_file
    except Exception:
        tmp_file.unlink(missing_ok=True)
        # A failed verification must never leave an ambiguous, apparently
        # successful final vault beside untouched source files.
        if not verified:
            vault_file.unlink(missing_ok=True)
        raise


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
    delete_source: bool = False,
    key_bits: int = 256,
    vault_file: Path | None = None,
) -> Path:
    """Encrypt every file under `source` into one opaque ``.lockbox`` file."""
    _validate_key_bits(key_bits)
    source = source.resolve()
    if not source.is_dir():
        raise LockBoxError(f"Not a directory: {source}")

    entries = [(f, f.relative_to(source).as_posix()) for f in _iter_files(source)]
    vault_file = vault_file or _pick_vault_file(source.parent, source.name)
    result = _write_file_vault(entries, password, vault_file, delete_source, progress, key_bits)

    if delete_source:
        _remove_emptied_source(source)
    return result


def encrypt_folders(
    sources: list[Path],
    password: str,
    progress: Callable[[str, int, int], None] | None = None,
    delete_source: bool = False,
    key_bits: int = 256,
    vault_file: Path | None = None,
) -> Path:
    """Encrypt multiple folders into one opaque ``.lockbox`` file."""
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

    entries = [
        (f, (Path(src.name) / f.relative_to(src)).as_posix())
        for src in sources
        for f in _iter_files(src)
    ]
    vault_file = vault_file or _pick_vault_file(sources[0].parent, "Combined Folders")
    result = _write_file_vault(entries, password, vault_file, delete_source, progress, key_bits)

    if delete_source:
        for src in sources:
            _remove_emptied_source(src)
    return result


def encrypt_files(
    sources: list[Path],
    password: str,
    progress: Callable[[str, int, int], None] | None = None,
    delete_source: bool = False,
    key_bits: int = 256,
    vault_file: Path | None = None,
) -> Path:
    """Encrypt selected loose files into one opaque ``.lockbox`` file."""
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
    vault_file = vault_file or _pick_vault_file(parent, "Enc Files")
    return _write_file_vault(
        [(source, source.name) for source in sources], password, vault_file,
        delete_source, progress, key_bits,
    )


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


def _pick_unvaulted_destination(vault_path: Path, destination: Path | None) -> Path:
    if destination is not None:
        return destination
    base = vault_path.parent / "Unvaulted"
    candidate = base
    n = 1
    while candidate.exists():
        n += 1
        candidate = vault_path.parent / f"Unvaulted_{n}"
    return candidate


def _decrypt_file_vault(
    vault_file: Path,
    password: str,
    destination: Path | None,
    progress: Callable[[str, int, int], None] | None,
) -> Path:
    """Decrypt a single-file vault with authenticated, corruption-safe reads."""
    _meta, key, offset = _load_file_meta_and_key(vault_file, password)
    records: list[bytes] = []
    try:
        with vault_file.open("rb") as handle:
            handle.seek(offset)
            while True:
                raw_len = handle.read(FILE_RECORD_LEN.size)
                if not raw_len:
                    break
                if len(raw_len) != FILE_RECORD_LEN.size:
                    raise LockBoxError("Vault is damaged or was modified (truncated record length).")
                (blob_len,) = FILE_RECORD_LEN.unpack(raw_len)
                if blob_len < NONCE_LEN + 4 or blob_len > 1024 * 1024 * 1024 * 8:
                    raise LockBoxError("Vault is damaged or was modified (invalid record length).")
                blob = handle.read(blob_len)
                if len(blob) != blob_len:
                    raise LockBoxError("Vault is damaged or was modified (truncated encrypted record).")
                records.append(blob)
    except OSError as exc:
        raise LockBoxError(f"Could not read vault: {exc}") from exc

    destination = _pick_unvaulted_destination(vault_file, destination)
    destination.mkdir(parents=True, exist_ok=False)
    total = len(records)
    if progress:
        progress("scan", 0, total)
    try:
        for idx, blob in enumerate(records, start=1):
            try:
                header, payload = _decrypt_bytes(key, blob)
            except Exception as exc:
                raise LockBoxError("Vault is damaged or was modified; no more files were restored.") from exc
            rel = str(header.get("path", ""))
            if not rel:
                raise LockBoxError("Vault is damaged or was modified (missing encrypted path).")
            out_path = (destination / rel).resolve()
            if not str(out_path).startswith(str(destination.resolve())):
                raise LockBoxError("Vault is damaged or was modified (unsafe encrypted path).")
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_bytes(payload)
            try:
                mtime = float(header.get("mtime", 0))
                if mtime:
                    os.utime(out_path, (mtime, mtime))
            except OSError:
                pass
            if progress:
                progress(rel, idx, total)
    except Exception:
        # Do not leave a partial plaintext restore after an authenticity failure.
        for path in sorted(destination.rglob("*"), key=lambda p: len(p.parts), reverse=True):
            try:
                path.unlink() if path.is_file() else path.rmdir()
            except OSError:
                pass
        try:
            destination.rmdir()
        except OSError:
            pass
        raise
    if progress:
        progress("done", total, total)
    return destination


def decrypt_vault(
    vault_dir: Path,
    password: str,
    destination: Path | None = None,
    progress: Callable[[str, int, int], None] | None = None,
) -> Path:
    """Decrypt either a current single-file vault or a legacy folder vault."""
    vault_dir = vault_dir.resolve()
    if vault_dir.is_file():
        return _decrypt_file_vault(vault_dir, password, destination, progress)
    meta, key = load_meta_and_key(vault_dir, password)

    data_dir = vault_dir / meta.data_dir_name
    # Recovery for an interrupted legacy-layout migration: the payload was
    # already made anonymous but the metadata update had not landed yet.
    if not data_dir.is_dir() and (vault_dir / "data").is_dir():
        data_dir = vault_dir / "data"
    if not data_dir.is_dir():
        raise LockBoxError(f"No {meta.data_dir_name}/ inside {vault_dir}")

    destination = _pick_unvaulted_destination(vault_dir, destination)
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
