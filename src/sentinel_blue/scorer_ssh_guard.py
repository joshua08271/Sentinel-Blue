"""Per-account OpenSSH source restrictions and optional approved public-key pins.

Pins require an explicit reviewed profile. Host telemetry does not authenticate
a scoring engine, and this adapter does not filter SMB/SQL/HTTP.
"""

from __future__ import annotations

import base64
import fnmatch
import hashlib
import ipaddress
import os
import shutil
from pathlib import Path

from .identity_guard import validate_guards
from .restoration import RestorePointStore
from .security_native import NativeSecurityBackend, native_command


FRAGMENT = Path("/etc/ssh/sshd_config.d/90-sentinel-scoring.conf")

PIN_SETTINGS = {
    'AuthenticationMethods':'publickey', 'PubkeyAuthentication':'yes',
    'PasswordAuthentication':'no', 'KbdInteractiveAuthentication':'no',
    'HostbasedAuthentication':'no', 'GSSAPIAuthentication':'no',
    'AuthorizedKeysCommand':'none', 'TrustedUserCAKeys':'none',
    'AuthorizedPrincipalsFile':'none', 'AuthorizedPrincipalsCommand':'none',
    'PubkeyAcceptedAlgorithms':'ssh-ed25519,rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521',
}


def key_file(guard):
    identity = guard['agent_id'] + '\0' + guard['name']
    return FRAGMENT.with_name('sentinel-scorer-' + hashlib.sha256(identity.encode()).hexdigest()[:20] + '.keys')


def verify_key_settings(output, guard):
    if 'ssh_public_keys' not in guard:
        return
    settings = dict(line.split(' ',1) for line in output.decode().splitlines() if ' ' in line)
    # A synthetic hostname must not make a Match Host exception disappear from
    # verification. Pinned-key enforcement requires numeric peer matching.
    required = {**PIN_SETTINGS, 'AuthorizedKeysFile':str(key_file(guard)), 'UseDNS':'no'}
    if any(settings.get(name.lower()) != value for name, value in required.items()):
        raise ValueError('effective OpenSSH configuration does not enforce the approved scorer keys')


def render_ssh_guard(guards):
    guards = validate_guards(guards)
    lines = ["# Managed by Sentinel Blue; reviewed scoring-account source restrictions."]
    for guard in guards:
        from .security_native import _account_name
        name = _account_name(guard["name"])
        if guard["account_id"] == "0" or name == "root":
            raise ValueError("SSH scorer restrictions cannot target the root account")
        sources = ",".join("!" + source for source in guard["allowed_sources"])
        lines += [f"Match User {name} Address *,{sources}", f"    DenyUsers {name}", "Match all"]
        if 'ssh_public_keys' in guard:
            path = str(key_file(guard))
            if any(c.isspace() for c in path) or any(c in path for c in '%*?[]"\\'):
                raise ValueError('scorer key-file path must be literal and unambiguous')
            lines += [f'Match User {name}', f'    AuthorizedKeysFile {path}']
            lines += [f'    {key} {value}' for key, value in PIN_SETTINGS.items()]
            lines.append('Match all')
    return ("\n".join(lines) + "\n").encode()


def _denies(output, name):
    for line in output.decode().splitlines():
        key, _, values = line.partition(" ")
        if key == "denyusers" and any(fnmatch.fnmatchcase(name, value) for value in values.split()):
            return True
    return False


def enforce_ssh_guard(guards, state_dir, *, command=native_command, backend=None):
    if os.name != "posix":
        raise ValueError("native SSH guard currently supports Linux OpenSSH")
    guards = validate_guards(guards)
    data = render_ssh_guard(guards)
    if not guards:
        raise ValueError("SSH guard requires at least one explicit scorer identity")
    backend = backend or NativeSecurityBackend()
    for guard in guards:
        identity = backend.account(guard["name"])
        if identity["account_id"] != guard["account_id"] or not identity["enabled"]:
            raise ValueError("scoring account UID or enabled state differs from the approved inventory")
    sshd = shutil.which("sshd")
    if not sshd:
        raise ValueError("OpenSSH server is unavailable")
    if not FRAGMENT.parent.is_dir() or FRAGMENT.parent.is_symlink():
        raise ValueError("a verified OpenSSH configuration-fragment directory is required")
    from .credential_vault import private_directory
    root = Path(state_dir).absolute()
    guard = private_directory(root)
    store = RestorePointStore(state_dir)
    from .state import AgentProcessLock, write_private_json
    import time
    try:
        with AgentProcessLock(root):
            journal = root / "ssh-guard.json"
            from .state import read_private_json
            if journal.exists():
                previous = read_private_json(journal)
                if previous.get("status") not in {"verified", "rolled_back"}:
                    raise ValueError("an interrupted SSH guard change requires review")
            changes = [(key_file(g), ('\n'.join(g['ssh_public_keys'])+'\n').encode(), 0o644)
                       for g in guards if 'ssh_public_keys' in g]
            changes.append((FRAGMENT, data, 0o600))
            states = []
            for path, content, mode in changes:
                before = store._read_target_if_present(path)
                metadata = {'mode':mode, 'uid':0, 'gid':0, 'xattrs':{},
                            'windows_security_descriptor':None, 'windows_security_descriptor_version':None}
                states.append((path, content, before, metadata))
            record = {"status": "applying", "created_at": time.time(), "new_sha256": hashlib.sha256(data).hexdigest(),
                      'files':[{'path':str(path),'new_sha256':hashlib.sha256(content).hexdigest(),
                                'before':{'content':base64.b64encode(before[0]).decode(),'metadata':before[1]} if before else None}
                               for path, content, before, _ in states]}
            write_private_json(journal, record)
            unit, reload_attempted, applied = None, False, []
            try:
                for path, content, before, metadata in states:
                    # Record an attempted write before it can fail ambiguously.
                    applied.append((path, content, before, metadata))
                    store._replace_target(path, content, metadata, expected_current=before)
                    if path != FRAGMENT:
                        keygen = shutil.which('ssh-keygen')
                        if not keygen:
                            raise ValueError('ssh-keygen is required to validate scorer public keys')
                        command([keygen, '-l', '-f', str(path)])
                command([sshd, "-t"])
                # Verify the daemon actually includes this file, for both allowed
                # peers and one denied peer per address family. Merely writing a
                # configuration fragment is not acceptance.
                for item in guards:
                    networks = [ipaddress.ip_network(n) for n in item["allowed_sources"]]
                    for network in networks:
                        address = str(network.network_address + (1 if network.num_addresses > 1 else 0))
                        output = command([sshd, "-T", "-C", f"user={item['name']},addr={address},host={address},laddr=127.0.0.1,lport=22"])
                        if _denies(output, item["name"]):
                            raise ValueError("approved scorer source would be denied")
                        verify_key_settings(output, item)
                    for version, candidates in ((4, ("198.51.100.254", "203.0.113.254", "10.255.255.254", "192.0.2.254")),
                                                (6, ("2001:db8:ffff::1", "fdff::1", "2001:db8::1"))):
                        address = next((a for a in candidates if not any(ipaddress.ip_address(a) in n for n in networks)), None)
                        if address is None:
                            raise ValueError("approved sources are too broad for the required deny verification")
                        output = command([sshd, "-T", "-C", f"user={item['name']},addr={address},host={address},laddr=127.0.0.1,lport=22"])
                        if not _denies(output, item["name"]):
                            raise ValueError("OpenSSH did not enforce the scorer source restriction")
                for candidate in ("ssh.service", "sshd.service"):
                    try:
                        if command(["systemctl", "is-active", candidate]).strip() == b"active":
                            unit = candidate
                            break
                    except RuntimeError:
                        continue
                if unit is None:
                    raise ValueError("an active OpenSSH service is required for guarded reload")
                reload_attempted = True
                command(["systemctl", "reload", unit])
                for path, content, _, metadata in states:
                    observed = store._read_target_if_present(path)
                    if observed is None or observed[0] != content or not store._metadata_matches(metadata, observed[1]):
                        raise ValueError('scorer configuration changed during guarded reload')
                record["status"] = "verified"
                write_private_json(journal, record)
            except Exception:
                record['status'] = 'uncertain'
                try:
                    for path, content, before, metadata in reversed(applied):
                        current = store._read_target_if_present(path)
                        if current is None and before is None:
                            continue
                        if current is not None and before is not None and current[0] == before[0] and store._metadata_matches(before[1],current[1]):
                            continue
                        if current is None or current[0] != content or not store._metadata_matches(metadata,current[1]):
                            raise ValueError('guarded rollback found an unrelated file change')
                        if before is None:
                            store._unlink_target(path, expected_current=current)
                        else:
                            store._replace_target(path, before[0], before[1], expected_current=current)
                    if applied:
                        command([sshd, "-t"])
                        if reload_attempted:
                            command(["systemctl", "reload", unit])
                    record["status"] = "rolled_back"
                except Exception:
                    pass
                write_private_json(journal, record)
                raise
    finally:
        if guard is not None:
            guard.close()
    return {"status": "verified", "scope": "Linux SSH named scoring-account sources and configured public-key pins",
            "accounts": [g["name"] for g in guards], "scorer_authenticated": False,
            'approved_key_authentication_required':[g['name'] for g in guards if 'ssh_public_keys' in g],
            "other_protocols_enforced": False}
