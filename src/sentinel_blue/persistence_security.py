"""Baseline-independent persistence review and exact-object quarantine.

Unknown entries are review findings, never automatically classified as malware.
Removal is authorized by a reviewed plan binding an exact native snapshot. It
does not certify a root-controlled machine or terminate detached payloads.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import time
from pathlib import Path, PurePosixPath, PureWindowsPath

from .credential_vault import private_directory
from .json_codec import canonical_json_bytes
from .restoration import RestorePointStore
from .state import AgentProcessLock, read_private_json, write_private_json
from .validation import ModelBoundAlertCandidate


SHA = re.compile(r"[0-9a-f]{64}\Z")
KINDS = {"file", "authorized-keys", "systemd-service", "scheduled-task", "registry-value"}
CRITICAL = {"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", "/etc/sudoers",
            "/etc/ssh/sshd_config", "/etc/crontab", "/etc/profile", "/etc/ld.so.preload"}


def fingerprint(value):
    return hashlib.sha256(canonical_json_bytes(value, max_bytes=4 * 1024 * 1024)).hexdigest()


def validate_persistence_policy(value):
    if value is None:
        return {"trusted": [], "malicious_sha256": []}
    if not isinstance(value, dict) or set(value) != {"trusted", "malicious_sha256"}:
        raise ValueError("persistence_policy requires trusted and malicious_sha256 arrays")
    trusted, hashes = value["trusted"], value["malicious_sha256"]
    if not isinstance(trusted, list) or len(trusted) > 8192 or not isinstance(hashes, list) or len(hashes) > 4096:
        raise ValueError("persistence policy exceeds its bounds")
    seen = set()
    for row in trusted:
        if not isinstance(row, dict) or set(row) != {"agent_id", "kind", "name", "sha256"}:
            raise ValueError("trusted persistence needs an exact agent, kind, name and SHA-256")
        if any(not isinstance(v, str) or not 1 <= len(v) <= 1024 or any(ord(c) < 32 for c in v)
               for v in row.values()) or row["agent_id"] == "*" or not SHA.fullmatch(row["sha256"]):
            raise ValueError("invalid trusted persistence binding")
        key = (row["agent_id"], row["kind"], row["name"])
        if key in seen:
            raise ValueError("duplicate trusted persistence binding")
        seen.add(key)
    if any(not isinstance(h, str) or not SHA.fullmatch(h) for h in hashes):
        raise ValueError("malicious persistence fingerprints require SHA-256")
    if any(row["sha256"] in hashes for row in trusted):
        raise ValueError("a persistence fingerprint cannot be both trusted and malicious")
    return value


def analyze_persistence_trust(telemetry, policy, model):
    policy = validate_persistence_policy(policy)
    trusted = {(r["kind"], r["name"]): r["sha256"] for r in policy["trusted"]
               if r["agent_id"] == telemetry.get("agent_id")}
    revoked = set(policy["malicious_sha256"])
    unknown, malicious = [], []
    for item in telemetry.get("persistence", []):
        digest = item.get("sha256", "")
        key = (item.get("kind"), item.get("name"))
        if digest in revoked:
            malicious.append(item)
        elif not digest or trusted.get(key) != digest:
            unknown.append(item)
    alerts = []
    for label, items, severity in (("known_malicious_persistence", malicious, "critical"),
                                   ("persistence_inventory_unverified", unknown, "medium")):
        if not items:
            continue
        features = {"persistence_change": 1.0}
        alerts.append(ModelBoundAlertCandidate(
            kind=label, title=("Known malicious persistence observed" if malicious is items
                               else "Existing persistence requires inventory review"),
            summary=f"{len(items)} startup entries require review against an independent trusted inventory.",
            severity=severity, confidence=0.95 if malicious is items else 0.65,
            model_features=features,
            evidence={"count": len(items), "items": items[:16], "baseline_independent": True,
                      "all_backdoors_found": False},
            recommendation="Review the exact native object and its dependencies; quarantine only an approved matching object.",
            recommended_action="snapshot",
        ))
    return alerts


def validate_target(target):
    if not isinstance(target, dict) or target.get("kind") not in KINDS:
        raise ValueError("unsupported persistence-removal target")
    allowed = {"kind", "path"}
    if target["kind"] == "authorized-keys":
        allowed.add("key_sha256")
    elif target["kind"] == "systemd-service":
        allowed.add("service")
    elif target["kind"] == "scheduled-task":
        allowed = {"kind", "task_path", "task_name"}
    elif target["kind"] == "registry-value":
        allowed = {"kind", "hive", "key", "value_name"}
    if set(target) != allowed:
        raise ValueError("persistence target has missing or unexpected fields")
    for name, value in target.items():
        if not isinstance(value, str) or not 1 <= len(value) <= 2048 or any(ord(c) < 32 for c in value):
            raise ValueError("persistence target contains unsafe text")
    if "path" in target:
        path = (PureWindowsPath(target['path']) if PureWindowsPath(target['path']).is_absolute()
                else PurePosixPath(target['path']))
        if not path.is_absolute() or ".." in path.parts:
            raise ValueError("persistence removal requires an absolute, unambiguous path")
        if target["kind"] != "authorized-keys" and (str(path) in CRITICAL or path.name.casefold() in {
                "authorized_keys", "administrators_authorized_keys", "sshd_config"}):
            raise ValueError("shared identity/startup configuration cannot be removed wholesale")
    if target["kind"] == "authorized-keys" and not SHA.fullmatch(target["key_sha256"]):
        raise ValueError("SSH key revocation requires a SHA-256 of the decoded public key blob")
    if target["kind"] == "systemd-service" and not re.fullmatch(r"[A-Za-z0-9_.@-]+\.service", target["service"]):
        raise ValueError("systemd removal requires an exact service name")
    if target["kind"] == "scheduled-task":
        path, name = target['task_path'], target['task_name']
        if (not path.startswith('\\') or not path.endswith('\\')
                or any(c in path + name for c in '*?[]/') or '\\' in name
                or any(part in {'.', '..'} for part in path.split('\\'))):
            raise ValueError("scheduled-task removal requires one literal task path and name")
    if target["kind"] == "registry-value":
        if target["hive"] not in {"HKLM", "HKU"} or not re.fullmatch(
                r"(?:S-1-(?:\d+-)+\d+\\)?Software\\(?:WOW6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Run(?:Once)?",
                target["key"], re.I):
            raise ValueError("registry removal is limited to exact Run/RunOnce values")
    return dict(target)


def revoke_key_lines(data, key_sha256):
    from .ssh_keys import authorized_key
    lines, removed = [], 0
    for line in data.splitlines(keepends=True):
        key = authorized_key(line)
        digest = hashlib.sha256(key[1]).hexdigest() if key else None
        if digest == key_sha256:
            removed += 1
        else:
            lines.append(line)
    if not removed:
        raise ValueError("the exact revoked SSH key is not present")
    return b"".join(lines), removed


class PersistenceRemediator:
    def __init__(self, directory, native=None):
        self.directory = Path(directory).absolute()
        self.guard = private_directory(self.directory)
        self.lock = AgentProcessLock(self.directory)
        self.files = RestorePointStore(self.directory)
        if native is None:
            from .security_native import NativeSecurityBackend
            native = NativeSecurityBackend()
        self.native = native

    def close(self):
        self.lock.close()
        if self.guard is not None:
            self.guard.close()
            self.guard = None

    def snapshot(self, target):
        target = validate_target(target)
        kind = target["kind"]
        if kind in {"scheduled-task", "registry-value"}:
            return {"target": target, "native": self.native.persistence_snapshot(target)}
        path = Path(target["path"])
        if path.stat(follow_symlinks=False).st_nlink != 1:
            raise ValueError("persistence target has multiple hard links")
        data, metadata = self.files._read_target(path)
        if kind == "authorized-keys":
            revoke_key_lines(data, target["key_sha256"])
        native = self.native.persistence_snapshot(target) if kind == "systemd-service" else None
        return {"target": target, "content": base64.b64encode(data).decode(), "metadata": metadata,
                "native": native}

    def inspect(self, target):
        snapshot = self.snapshot(target)
        return {"target": target, "snapshot_sha256": fingerprint(snapshot), "removal_supported": True,
                "running_payloads_assessed": False}

    def remove(self, target, expected, *, operation_id):
        if not SHA.fullmatch(expected) or not re.fullmatch(r"[a-zA-Z0-9_-]{8,96}", operation_id):
            raise ValueError("removal requires an exact review digest and operation identifier")
        with self.lock:
            record_path = self.directory / (operation_id + ".json")
            if record_path.exists():
                old = read_private_json(record_path)
                if old.get("snapshot_sha256") != expected or old.get("target") != target:
                    raise ValueError("removal operation was rebound")
                if old["status"] == "quarantined" and not self._matches_quarantine(old):
                    return {"status": "reappeared", "replayed": False, "operation_id": operation_id,
                            "review_required": True}
                return {"status": old["status"], "replayed": False, "operation_id": operation_id,
                        "review_required": old["status"] != "quarantined"}
            before = self.snapshot(target)
            if fingerprint(before) != expected:
                raise ValueError("persistence object changed after review; no removal performed")
            record = {"target": target, "snapshot_sha256": expected, "before": before,
                      "status": "prepared", "created_at": time.time()}
            write_private_json(record_path, record)
            try:
                # Persist uncertainty before the first external/native side effect.
                record["status"] = "applying"
                write_private_json(record_path, record)
                if fingerprint(self.snapshot(target)) != expected:
                    raise ValueError("persistence object changed before mutation")
                kind = target["kind"]
                if kind in {"scheduled-task", "registry-value"}:
                    self.native.persistence_remove(target, before["native"])
                    after = None
                else:
                    if kind == "systemd-service":
                        self.native.persistence_remove(target, before["native"])
                    current = self.files._read_target(Path(target["path"]))
                    data = base64.b64decode(before["content"])
                    if current[0] != data or not self.files._metadata_matches(before["metadata"], current[1]):
                        raise ValueError("target changed during quarantine")
                    if kind == "authorized-keys":
                        after, removed = revoke_key_lines(data, target["key_sha256"])
                        record["keys_removed"] = removed
                        self.files._replace_target(Path(target["path"]), after, before["metadata"], expected_current=current)
                    else:
                        self.files._unlink_target(Path(target["path"]), expected_current=current)
                        after = None
                    if kind == "systemd-service":
                        self.native.reload_systemd()
                record["after_content"] = base64.b64encode(after).decode() if after is not None else None
                if not self._matches_quarantine(record):
                    raise ValueError("quarantine could not be verified")
                record["status"] = "quarantined"
                write_private_json(record_path, record)
            except Exception:
                record["status"] = "uncertain"
                write_private_json(record_path, record)
                return {"status": "uncertain", "operation_id": operation_id, "review_required": True}
            return {"status": "quarantined", "operation_id": operation_id, "evidence_preserved": True,
                    "running_payloads_assessed": False, "host_clean": False}

    def _matches_quarantine(self, record):
        target = record["target"]
        if target["kind"] in {"scheduled-task", "registry-value"}:
            return self.native.persistence_absent(target)
        if target["kind"] == 'systemd-service' and not self.native.persistence_absent(target):
            return False
        current = self.files._read_target_if_present(Path(target["path"]))
        expected = record.get("after_content")
        return (current is None if expected is None else current is not None and
                current[0] == base64.b64decode(expected) and
                self.files._metadata_matches(record["before"]["metadata"], current[1]))

    def _matches_restoration(self, before, observed):
        # A restored file is a new filesystem object. Windows file IDs and
        # creation/write timestamps are pre-mutation race guards, not attributes
        # a replacement can retain. Content, ACLs/mode and native startup state
        # must still match the approved evidence.
        return (before['target'] == observed['target']
                and before.get('content') == observed.get('content')
                and before.get('native') == observed.get('native')
                and ('metadata' not in before or self.files._metadata_matches(
                    before['metadata'], observed.get('metadata'))))

    def restore(self, operation_id):
        if not re.fullmatch(r"[a-zA-Z0-9_-]{8,96}", operation_id):
            raise ValueError("invalid quarantine operation identifier")
        with self.lock:
            path = self.directory / (operation_id + ".json")
            record = read_private_json(path)
            if record["status"] != "quarantined" or not self._matches_quarantine(record):
                raise ValueError("rollback requires an unchanged, verified quarantine")
            before, target = record["before"], record["target"]
            if fingerprint(before) != record["snapshot_sha256"]:
                raise ValueError("quarantine evidence was modified")
            record["status"] = "restoring"
            write_private_json(path, record)
            try:
                if "content" in before:
                    current = self.files._read_target_if_present(Path(target["path"]))
                    self.files._replace_target(Path(target["path"]), base64.b64decode(before["content"]),
                                               before["metadata"], expected_current=current)
                if before.get("native") is not None:
                    self.native.persistence_restore(target, before["native"])
                if not self._matches_restoration(before, self.snapshot(target)):
                    raise ValueError("rollback verification failed")
                record["status"] = "restored"
                write_private_json(path, record)
            except Exception:
                record["status"] = "uncertain"
                write_private_json(path, record)
                return {"status": "uncertain", "review_required": True}
            return {"status": "restored", "operation_id": operation_id}
