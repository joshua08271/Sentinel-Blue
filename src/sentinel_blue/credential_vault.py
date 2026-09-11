"""Operator-side encrypted credential journal; never deployed to target hosts."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import stat
import string
from pathlib import Path

from .json_codec import canonical_json_bytes, strict_json_loads
from .state import AgentProcessLock, read_private_json, write_private_json


def private_directory(path: Path):
    path = path.absolute()
    for ancestor in (path, *path.parents):
        if ancestor.is_symlink():
            raise ValueError("private storage cannot contain symlink ancestors")
    if os.name == "nt":
        from .win_state import acquire_windows_state_tree
        return acquire_windows_state_tree(path, initialize=True)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("private storage must be owned by the operator with mode 0700")
    return None


def new_password() -> str:
    alphabet = string.ascii_letters + string.digits + "-_!@#%+="
    while True:
        value = "".join(secrets.choice(alphabet) for _ in range(32))
        if all(any(c in group for c in value) for group in
               (string.ascii_lowercase, string.ascii_uppercase, string.digits, "-_!@#%+=")):
            return value


def validate_password(value: str) -> str:
    if (not isinstance(value, str) or not 20 <= len(value) <= 128
            or not value.isascii() or any(ord(c) < 33 or ord(c) > 126 for c in value)):
        raise ValueError("new account passwords require 20–128 printable non-space ASCII characters")
    return value


class CredentialVault:
    """Exclusive, crash-safe AES-256-GCM vault with a fixed-cost scrypt KDF.

    Salt, KDF and revision are authenticated. Keys/passphrases never enter the
    vault or reports. An attacker replacing both the file and an old valid copy
    is outside this local-storage boundary: use trusted backups and protect the
    operator machine. Python does not guarantee erasure of secret strings.
    """

    def __init__(self, directory: str | Path, passphrase: str, *, create=False):
        if not isinstance(passphrase, str) or not 16 <= len(passphrase) <= 4096:
            raise ValueError("vault passphrase requires at least 16 characters")
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
        except ImportError:
            raise RuntimeError("credential vault requires the optional cryptography dependency") from None
        self.directory = Path(directory).absolute()
        self.path = self.directory / "vault.json"
        self.guard = private_directory(self.directory)
        self.lock = AgentProcessLock(self.directory)
        try:
            self.lock.acquire()
            exists = self.path.exists() or self.path.is_symlink()
            if not exists and not create:
                raise ValueError("vault does not exist; initialize it before rotation")
            if exists:
                info = self.path.lstat()
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                        or os.name == "posix" and (info.st_uid != os.geteuid() or info.st_mode & 0o077)):
                    raise ValueError("vault file permissions or link count are unsafe")
                envelope = read_private_json(self.path)
                header = envelope["header"]
                if (set(envelope) != {"header", "nonce", "ciphertext"}
                        or set(header) != {"version", "salt", "kdf", "revision"}
                        or header["version"] != 1 or header["kdf"] != "scrypt-32768-8-1"
                        or type(header["revision"]) is not int or header["revision"] < 1):
                    raise ValueError("unsupported vault format")
                self.salt = base64.b64decode(header["salt"], validate=True)
                self.revision = header["revision"]
            else:
                self.salt, self.revision = secrets.token_bytes(16), 0
            if len(self.salt) != 16:
                raise ValueError("invalid vault salt")
            key = Scrypt(salt=self.salt, length=32, n=32768, r=8, p=1).derive(passphrase.encode())
            self.cipher = AESGCM(key)
            if exists:
                try:
                    nonce = base64.b64decode(envelope["nonce"], validate=True)
                    if len(nonce) != 12:
                        raise ValueError("invalid nonce")
                    plain = self.cipher.decrypt(nonce, base64.b64decode(envelope["ciphertext"], validate=True),
                                                canonical_json_bytes(header))
                    self.data = strict_json_loads(plain, max_bytes=2 * 1024 * 1024)
                    if not isinstance(self.data, dict) or set(self.data) != {"entries", "audit"}:
                        raise ValueError("invalid vault payload")
                    if not isinstance(self.data["entries"], dict) or not isinstance(self.data["audit"], list):
                        raise ValueError("invalid vault collections")
                except Exception:
                    raise ValueError("vault authentication failed: wrong passphrase or modified vault") from None
            else:
                self.data = {"entries": {}, "audit": []}
                self.save()
        except BaseException:
            self.close()
            raise

    def save(self):
        revision = self.revision + 1
        header = {"version": 1, "salt": base64.b64encode(self.salt).decode(),
                  "kdf": "scrypt-32768-8-1", "revision": revision}
        plain = canonical_json_bytes(self.data, max_bytes=2 * 1024 * 1024)
        nonce = secrets.token_bytes(12)
        encrypted = self.cipher.encrypt(nonce, plain, canonical_json_bytes(header))
        write_private_json(self.path, {"header": header, "nonce": base64.b64encode(nonce).decode(),
                                       "ciphertext": base64.b64encode(encrypted).decode()})
        self.revision = revision

    def close(self):
        self.lock.close()
        if self.guard is not None:
            self.guard.close()
            self.guard = None
        self.cipher = None
        self.data = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
