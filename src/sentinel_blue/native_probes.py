"""Bounded scoring transactions using fixed native clients and protocol APIs.

No arbitrary command field is accepted. The caller scopes and pins the endpoint
before invoking this module. Secrets travel in private files or stdin, never in
process arguments or the returned diagnostics. SMB uses a single low-level
connection (no DFS referral following); SSH never accepts a new host key.
"""

from __future__ import annotations

import hashlib
import importlib.util
import ipaddress
import json
import math
import os
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

from .state import read_private_text


IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,62}\Z")
RELATIVE = re.compile(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*\Z")


def _identifier(value, name):
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise ValueError(f"{name} requires a simple SQL identifier")
    return value


def _relative(value):
    if not isinstance(value, str) or len(value) > 512 or not RELATIVE.fullmatch(value):
        raise ValueError("probe path requires simple relative path components")
    if any(p in {".", ".."} for p in value.split("/")):
        raise ValueError("probe path cannot traverse directories")
    return value


def _secret(spec):
    path = spec.get("password_file")
    if not isinstance(path, str) or not Path(path).is_absolute():
        raise ValueError("probe requires an absolute private password_file")
    if os.name == "posix" and Path(path).stat().st_mode & 0o077:
        raise ValueError("scoring password file must not grant group or other access")
    value = read_private_text(path, 4096).removesuffix("\n").removesuffix("\r")
    if not value or any(c in value for c in "\r\n\0"):
        raise ValueError("password_file requires one nonempty password line")
    return value


def _port(spec, default):
    value = spec.get("port", default)
    if type(value) is not int or not 1 <= value <= 65535:
        raise ValueError("probe port is invalid")
    return value


def _command(argv, seconds, *, incoming=b"", env=None):
    """Return bounded stdout; neither argv nor client errors enter reports."""
    if seconds <= 0:
        raise TimeoutError("scoring transaction deadline expired")
    with tempfile.TemporaryFile() as source, tempfile.TemporaryFile() as output:
        source.write(incoming)
        source.seek(0)
        process = subprocess.Popen(argv, stdin=source, stdout=output, stderr=subprocess.DEVNULL,
                                   env=env, start_new_session=os.name == "posix")
        try:
            process.wait(timeout=seconds)
        except subprocess.TimeoutExpired:
            if os.name == "posix":
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:
                # The worker can itself own psql/nsupdate children. Stop only
                # this process tree; a surviving write client is uncertain.
                subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=3, check=False)
                if process.poll() is None:
                    process.kill()
            process.wait(timeout=3)
            raise TimeoutError("scoring transaction timed out; write cleanup may be uncertain") from None
        if process.returncode != 0:
            raise RuntimeError("native scoring client failed; check credentials, protocol, and dependencies")
        output.seek(0)
        result = output.read(65537)
        if len(result) > 65536:
            raise RuntimeError("scoring response exceeds 64 KiB")
        return result


def _binary(name):
    result = shutil.which(name)
    if not result:
        raise RuntimeError(f"scoring client is not installed: {name}")
    return result


def _sql(kind, spec, address, timeout):
    username = _identifier(spec.get("username"), "username")
    database = _identifier(spec.get("database"), "database")
    password = _secret(spec)
    mode = spec.get("operation", "access")
    if mode not in {"access", "readwrite"}:
        raise ValueError("SQL operation must be access or readwrite")
    expected = "1"
    query = "SELECT 1;"
    if mode == "readwrite":
        if spec.get("allow_write") is not True:
            raise ValueError("SQL readwrite requires explicit allow_write")
        table = _identifier(spec.get("table"), "table")
        nonce = secrets.token_hex(16)
        expected = nonce + "\n0"
        query = (f"BEGIN; INSERT INTO {table} (probe_key,probe_value) VALUES ('{nonce}','{nonce}'); "
                 f"SELECT probe_value FROM {table} WHERE probe_key='{nonce}'; ROLLBACK; "
                 f"SELECT COUNT(*) FROM {table} WHERE probe_key='{nonce}';")
        if kind == "mysql":
            # Non-transactional tables cannot promise rollback of the probe row.
            query = (f"SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA='{database}' "
                     f"AND TABLE_NAME='{table}';\n" + query)
    with tempfile.TemporaryDirectory(prefix="sb-sql-probe-") as directory:
        root = Path(directory)
        port = _port(spec, 5432 if kind == "postgres" else 3306)
        if kind == "postgres":
            escape = lambda s: s.replace("\\", "\\\\").replace(":", "\\:")
            password_path = root / "pgpass"
            password_path.write_text(":".join(map(escape, [address, str(port), database, username, password])) + "\n")
            password_path.chmod(0o600)
            env = {k: v for k, v in os.environ.items() if not k.startswith("PG")}
            tls = spec.get("sslmode", "require")
            if tls not in {"require", "verify-full", "disable"}:
                raise ValueError("PostgreSQL sslmode must be require, verify-full, or explicit disable")
            env.update(PGPASSFILE=str(password_path), PGSSLMODE=tls,
                       PGCONNECT_TIMEOUT=str(max(1, math.ceil(timeout))),
                       PGOPTIONS=f"-c statement_timeout={max(1, math.floor(timeout * 1000))}")
            if tls == "verify-full":
                env["PGSSLROOTCERT"] = str(Path(spec["ca_file"]).resolve(strict=True))
            argv = [_binary("psql"), "-X", "-w", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1",
                    "-h", address, "-p", str(port), "-U", username, "-d", database, "-c", query]
        else:
            escape = lambda s: s.replace("\\", "\\\\").replace('"', '\\"')
            config = root / "mysql.cnf"
            config.write_text(f'[client]\nuser="{username}"\npassword="{escape(password)}"\n')
            config.chmod(0o600)
            env = {k: v for k, v in os.environ.items() if not k.startswith("MYSQL")}
            argv = [_binary("mysql"), "--defaults-file=" + str(config), "--no-login-paths", "--protocol=TCP",
                    "--host=" + address, "--port=" + str(port), "--database=" + database,
                    "--batch", "--raw", "--skip-column-names", "--local-infile=0",
                    "--connect-timeout=" + str(max(1, math.ceil(timeout)))]
            tls = spec.get("sslmode", "REQUIRED")
            if tls not in {"REQUIRED", "VERIFY_IDENTITY", "DISABLED"}:
                raise ValueError("MySQL sslmode must be REQUIRED, VERIFY_IDENTITY, or explicit DISABLED")
            argv.append("--ssl-mode=" + tls)
            if tls == "VERIFY_IDENTITY":
                argv.append("--ssl-ca=" + str(Path(spec["ca_file"]).resolve(strict=True)))
            if mode == "readwrite":
                start = time.monotonic()
                check_query, query = query.split("\n", 1)
                result = _command(argv, timeout, incoming=check_query.encode(), env=env).strip()
                if result != b"InnoDB":
                    raise RuntimeError("MySQL write check requires an InnoDB probe table")
                timeout -= time.monotonic() - start
        output = _command(argv, timeout, incoming=query.encode() if kind == "mysql" else b"", env=env)
    if output.decode("utf-8", errors="strict").strip() != expected:
        raise RuntimeError("SQL transaction returned an unexpected value")
    return f"{kind} authenticated {mode} transaction passed"


def _ssh(spec, address, timeout):
    import paramiko

    username = spec.get("username")
    if not isinstance(username, str) or not re.fullmatch(r"[A-Za-z0-9_.@\\-]{1,128}", username):
        raise ValueError("SSH requires an explicit scoring username")
    known_hosts = Path(spec["known_hosts_file"])
    if not known_hosts.is_absolute() or known_hosts.is_symlink() or not known_hosts.is_file():
        raise ValueError("SSH requires an absolute verified known_hosts_file")
    nonce = "sb_login_" + secrets.token_hex(16)
    client = paramiko.SSHClient()
    client.load_host_keys(str(known_hosts))
    # RejectPolicy remains in force; no TOFU, agent, proxy, or implicit key search.
    try:
        options = {}
        if spec.get("key_file"):
            key = Path(spec["key_file"])
            read_private_text(key, 65536)
            options["key_filename"] = str(key)
        else:
            options["password"] = _secret(spec)
        client.connect(address, port=_port(spec, 22), username=username, timeout=timeout,
                       banner_timeout=timeout, auth_timeout=timeout, channel_timeout=timeout,
                       allow_agent=False, look_for_keys=False, **options)
        _stdin, stdout, _stderr = client.exec_command("echo " + nonce, timeout=timeout)
        if stdout.read(1024).decode("utf-8", errors="strict").strip() != nonce:
            raise RuntimeError("SSH login did not return the fresh expected response")
        if stdout.channel.recv_exit_status() != 0:
            raise RuntimeError("SSH scoring command failed")
    finally:
        client.close()
    return "SSH scoring-account login and fresh command response passed"


def _smb(spec, address, timeout):
    from smbprotocol.connection import Connection
    from smbprotocol.file_info import FileAttributes
    from smbprotocol.open import (Open, ImpersonationLevel, FilePipePrinterAccessMask as Access,
                                  ShareAccess, CreateDisposition, CreateOptions)
    from smbprotocol.session import Session
    from smbprotocol.tree import TreeConnect

    share = _relative(spec.get("share"))
    if "/" in share:
        raise ValueError("SMB share must be a single name")
    username = spec.get("username")
    if not isinstance(username, str) or not username or len(username) > 256 or any(c in username for c in "\0\r\n"):
        raise ValueError("SMB requires an explicit scoring username")
    operation = spec.get("operation", "login")
    if operation not in {"login", "read", "write"}:
        raise ValueError("SMB operation must be login, read, or write")
    encrypt = spec.get("encrypt", True)
    if type(encrypt) is not bool:
        raise ValueError("SMB encrypt must be boolean")
    password = _secret(spec)
    connection = Connection(uuid.uuid4(), address, port=_port(spec, 445), require_signing=True)
    opened = None
    try:
        connection.connect(timeout=timeout)
        # Explicit NTLM avoids off-target Kerberos discovery. Guest sessions
        # cannot meet the required signing/encryption policy.
        session = Session(connection, username=username, password=password,
                          require_encryption=encrypt, auth_protocol="ntlm")
        session.connect()
        tree = TreeConnect(session, f"\\\\{address}\\{share}")
        tree.connect()
        if operation != "login":
            if operation == "read":
                path = _relative(spec.get("path"))
                digest = spec.get("expected_sha256", "")
                if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
                    raise ValueError("SMB read requires an exact expected_sha256")
                disposition = CreateDisposition.FILE_OPEN
                options = CreateOptions.FILE_NON_DIRECTORY_FILE
                access = Access.FILE_READ_DATA | Access.FILE_READ_ATTRIBUTES
            else:
                if spec.get("allow_write") is not True:
                    raise ValueError("SMB write requires explicit allow_write")
                directory = _relative(spec.get("directory"))
                path = directory + "/sb-probe-" + secrets.token_hex(16)
                disposition = CreateDisposition.FILE_CREATE  # Never replace an existing file.
                options = CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_DELETE_ON_CLOSE
                access = Access.FILE_READ_DATA | Access.FILE_WRITE_DATA | Access.DELETE
            opened = Open(tree, path.replace("/", "\\"))
            opened.create(ImpersonationLevel.Impersonation, access, FileAttributes.FILE_ATTRIBUTE_NORMAL,
                          ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE | ShareAccess.FILE_SHARE_DELETE,
                          disposition, options)
            if operation == "write":
                payload = secrets.token_bytes(64)
                # The native Windows target rejects per-WRITE write-through.
                # An acknowledged FLUSH provides the persistence check before
                # readback without relying on that incompatible request flag.
                if opened.write(payload) != len(payload):
                    raise RuntimeError("SMB write was incomplete")
                opened.flush()
                if opened.read(0, len(payload)) != payload:
                    raise RuntimeError("SMB write readback did not match")
            else:
                size = opened.end_of_file
                if size is None or not 0 <= size <= 65536:
                    raise RuntimeError("SMB verification file exceeds 64 KiB")
                payload = opened.read(0, size) if size else b""
                if len(payload) != size or hashlib.sha256(payload).hexdigest() != digest:
                    raise RuntimeError("SMB read checksum did not match")
            opened.close()  # An acknowledged close also completes delete-on-close.
            opened = None
        tree.disconnect()
        session.disconnect()
    finally:
        # Closing the transport also releases a pending delete-on-close handle.
        # A timeout is never reported as successful cleanup.
        connection.disconnect(close=False)
    return f"SMB authenticated {operation} transaction passed"


def _dns_update(spec, address, timeout):
    from .probes import _dns_query

    if spec.get("allow_write") is not True:
        raise ValueError("dynamic DNS requires explicit allow_write")
    zone = spec.get("zone", "")
    if not isinstance(zone, str) or len(zone) > 190 or not re.fullmatch(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\.?", zone):
        raise ValueError("dynamic DNS requires an explicit zone")
    prefix = spec.get("prefix", "")
    if not isinstance(prefix, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,20}", prefix):
        raise ValueError("dynamic DNS requires an approved probe name prefix")
    key = Path(spec["key_file"])
    read_private_text(key, 16384)
    if not key.is_absolute():
        raise ValueError("dynamic DNS key_file must be absolute")
    value = str(ipaddress.IPv4Address(spec["value"]))
    name = prefix + "-" + secrets.token_hex(12) + "." + zone.rstrip(".") + "."
    port = _port(spec, 53)
    base = f"server {address} {port}\nzone {zone.rstrip('.')}.\n"
    argv = [_binary("nsupdate"), "-v", "-k", str(key)]
    deadline = time.monotonic() + timeout
    # Reserve time for cleanup inside the SAME transaction deadline.
    action_deadline = time.monotonic() + timeout * 0.65
    attempted = False
    try:
        attempted = True
        _command(argv, action_deadline - time.monotonic(), incoming=(base +
                 f"prereq nxdomain {name}\nupdate add {name} 30 A {value}\nsend\n").encode())
        for transport in ("udp", "tcp"):
            _dns_query(address, port, name, "A", max(0.001, action_deadline - time.monotonic()),
                       [value], transport)
    finally:
        if attempted:
            # Value-dependent prerequisites protect any record changed by others.
            _command(argv, deadline - time.monotonic(), incoming=(base +
                     f"prereq yxrrset {name} A {value}\nupdate delete {name} A {value}\nsend\n").encode())
    return "authenticated dynamic DNS add, UDP/TCP readback, and delete passed"


def _perform(kind, spec, address, timeout):
    if kind in {"mysql", "postgres"}:
        return _sql(kind, spec, address, timeout)
    if kind == "ssh-login":
        return _ssh(spec, address, timeout)
    if kind == "smb":
        return _smb(spec, address, timeout)
    if kind == "dns-update":
        return _dns_update(spec, address, timeout)
    if kind == "icmp":
        if os.name == "nt":
            argv = [_binary("ping"), "-n", "1", "-w", str(max(1, int(timeout * 1000))), address]
        else:
            argv = [_binary("ping"), "-n", "-c", "1", "-W", str(max(1, math.ceil(timeout))), address]
        output = _command(argv, timeout)
        # Windows ping can return zero for ICMP destination-unreachable replies.
        if os.name == "nt" and not re.search(rb"\bTTL=\d+", output, re.IGNORECASE):
            raise RuntimeError("no ICMP echo reply was verified")
        return "ICMP echo reply received"
    raise ValueError("unsupported native scoring probe")


def run_native_probe(kind, spec, address, timeout):
    # A child provides one hard overall deadline even when a library has several
    # internal request timers. It also prevents logging/cache state crossing probes.
    package_root = str(Path(__file__).parent.parent)
    # Preserve explicitly configured dependency paths in embedded Python too;
    # its isolated mode intentionally ignores the PYTHONPATH environment.
    module_paths = json.dumps([package_root, *[str(Path(p).absolute()) for p in sys.path if p]])
    code = "import json,sys; sys.path[:0]=json.loads(sys.argv[1]); from sentinel_blue.native_probes import _worker; _worker()"
    payload = json.dumps({"kind": kind, "spec": spec, "address": address, "timeout": timeout}).encode()
    if len(payload) > 65536:
        raise ValueError("native scoring specification exceeds 64 KiB")
    result = _command([sys.executable, "-c", code, module_paths], timeout, incoming=payload)
    record = json.loads(result)
    if record.get("healthy") is not True:
        raise RuntimeError(record.get("detail", "scoring transaction failed"))
    return record["detail"]


def dependency_readiness(probes):
    """Read-only observer preflight; an absent client is not a down service."""
    modules = {"ssh-login": "paramiko", "smb": "smbprotocol"}
    binaries = {"icmp": "ping", "postgres": "psql", "mysql": "mysql", "dns-update": "nsupdate"}
    missing = []
    for kind in sorted({spec.get("kind", "tcp") for spec in probes}):
        if kind in modules and importlib.util.find_spec(modules[kind]) is None:
            missing.append("Python module " + modules[kind])
        if kind in binaries and not shutil.which(binaries[kind]):
            missing.append("executable " + binaries[kind])
    return {"ready": not missing, "missing": missing,
            "scope": "observer client availability; credentials and service health are checked by transactions"}


def _worker():
    try:
        request = json.loads(sys.stdin.buffer.read(65537))
        detail = _perform(request["kind"], request["spec"], request["address"], request["timeout"])
        result = {"healthy": True, "detail": detail}
    except Exception as exc:
        # Library exceptions may contain credentials, paths, or protocol dumps.
        result = {"healthy": False, "detail": "scoring transaction failed (" + type(exc).__name__ + ")"}
    print(json.dumps(result))
