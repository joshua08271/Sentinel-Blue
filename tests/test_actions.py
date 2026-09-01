import os
import json
import signal
import subprocess
import tempfile
import time
import unittest
import hashlib
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import call, patch

from sentinel_blue import restoration
from sentinel_blue.actions import ActionExecutor
from sentinel_blue.protocol import ProbeResult
from sentinel_blue.process_identity import inspect_process_identity
from sentinel_blue.restoration import RestorePointStore
from sentinel_blue.state import write_private_json
from sentinel_blue.validation import telemetry_observation_sha256


class ActionTests(unittest.TestCase):
    @staticmethod
    def _metadata(mode=0o600):
        return {
            "mode": mode,
            "uid": -1,
            "gid": -1,
            "xattrs": {},
            "windows_security_descriptor": None,
            "windows_security_descriptor_version": None,
        }

    @staticmethod
    def _identity(process_id: int = 4242, boot_id: str = "test-boot") -> dict:
        return {
            "schema": "sentinel-process-v1",
            "platform": "linux",
            "process_id": process_id,
            "boot_id": boot_id,
            "start_time": "123456",
            "executable_path": "/usr/bin/fixture",
            "executable_file_id": "dev:1:ino:2",
            "user_id": "uid:1000:1000",
            "kernel_session_id": "99",
        }

    @classmethod
    def _session_telemetry(
        cls,
        process_id: int = 4242,
        *,
        boot_id: str = "test-boot",
        identity: dict | None = None,
        sequence: int = 7,
        source: str = "local",
    ) -> dict:
        identity = identity or cls._identity(process_id, boot_id)
        return {
            "agent_id": "agent-test",
            "hostname": "host-test",
            "platform": "Linux test",
            "observed_at": time.time(),
            "queued_at": time.time(),
            "boot_id": boot_id,
            "sequence": sequence,
            "sessions": [
                {
                    "username": "test",
                    "source": source,
                    "session_id": "pts/1",
                    "process_id": process_id,
                    "privileged": True,
                    "interactive": True,
                    "process_identity": identity,
                }
            ],
        }

    @staticmethod
    def _session_parameters(telemetry: dict) -> dict:
        return {
            "session": dict(telemetry["sessions"][0]),
            "observation": {
                "boot_id": telemetry["boot_id"],
                "sequence": telemetry["sequence"],
                "payload_sha256": telemetry_observation_sha256(telemetry),
            },
        }

    def test_recovery_rescan_errors_fail_closed_without_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            executor = ActionExecutor(directory)
            with patch.object(
                executor.restore_points,
                "recover_incomplete",
                side_effect=ValueError("malformed transaction"),
            ):
                recovery = executor.refresh_restore_recovery()
        self.assertFalse(recovery["healthy"])
        self.assertIn("recovery scan failed", recovery["error"])

    def test_restore_uses_one_optional_snapshot_as_its_pre_state_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = RestorePointStore(root / "state")
            target = root / "protected.conf"
            trusted = b"approved"
            before = b"pre-restoration"
            expected = hashlib.sha256(trusted).hexdigest()
            record = {"sha256": expected, **self._metadata()}
            with (
                patch.object(store, "_read_manifest", return_value={str(target): record}),
                patch.object(store, "_read_private_file", return_value=trusted),
                patch.object(
                    store,
                    "_read_target_if_present",
                    return_value=(before, self._metadata()),
                ) as optional_read,
                patch.object(store, "_atomic_write") as evidence_write,
                patch.object(store, "_write_json"),
                patch.object(store, "_replace_target"),
                patch.object(
                    store,
                    "_read_target",
                    return_value=(trusted, self._metadata()),
                ),
                patch(
                    "sentinel_blue.restoration.validate_restored_configuration",
                    return_value={
                        "applicable": False,
                        "available": False,
                        "healthy": None,
                    },
                ),
                patch.object(Path, "exists", side_effect=AssertionError),
                patch.object(Path, "is_file", side_effect=AssertionError),
                patch.object(Path, "is_symlink", side_effect=AssertionError),
            ):
                result = store.restore(
                    {
                        "path": str(target),
                        "baseline_sha256": expected,
                        "observed_sha256": hashlib.sha256(before).hexdigest(),
                    },
                    allowed=True,
                )
        self.assertTrue(result["success"])
        self.assertTrue(result["evidence_preserved"])
        optional_read.assert_called_once_with(target)
        self.assertEqual(evidence_write.call_args.args[1], before)

    def test_rollback_absence_verification_uses_optional_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = RestorePointStore(root / "state")
            target = root / "created.conf"
            restored = b"approved"
            restored_digest = hashlib.sha256(restored).hexdigest()
            transaction_id = str(uuid.uuid4())
            transaction = {
                "transaction_id": transaction_id,
                "status": "committed",
                "rolled_back": False,
                "path": str(target),
                "existed": False,
                "restored_sha256": restored_digest,
                "restored_metadata": self._metadata(),
                "before_metadata": self._metadata(),
            }
            with (
                patch.object(
                    store,
                    "_read_private_file",
                    return_value=json.dumps(transaction).encode("utf-8"),
                ),
                patch.object(
                    store,
                    "_read_target_if_present",
                    side_effect=[(restored, self._metadata()), None],
                ) as optional_read,
                patch.object(store, "_restore_before"),
                patch.object(store, "_write_json"),
                patch.object(Path, "exists", side_effect=AssertionError),
                patch.object(Path, "is_file", side_effect=AssertionError),
                patch.object(Path, "is_symlink", side_effect=AssertionError),
            ):
                result = store.rollback(transaction_id, allowed=True)
        self.assertTrue(result["success"])
        self.assertEqual(optional_read.call_count, 2)

    def test_manifest_and_blob_absence_use_optional_private_reads(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = RestorePointStore(root / "state")
            target = root / "protected.conf"
            approved = b"approved"
            digest = hashlib.sha256(approved).hexdigest()
            with (
                patch.object(
                    store, "_read_private_file_if_present", return_value=None
                ) as optional_read,
                patch.object(Path, "exists", side_effect=AssertionError),
                patch.object(Path, "is_file", side_effect=AssertionError),
                patch.object(Path, "is_symlink", side_effect=AssertionError),
            ):
                self.assertEqual(store._read_manifest(), {})
            optional_read.assert_called_once_with(
                store.manifest_path, restoration.MAX_MANIFEST_BYTES
            )

            with (
                patch.object(store, "_read_manifest", return_value={}),
                patch.object(
                    store,
                    "_read_target",
                    return_value=(approved, self._metadata()),
                ),
                patch.object(
                    store, "_read_private_file_if_present", return_value=None
                ) as optional_read,
                patch.object(store, "_read_private_file", return_value=approved) as exact_read,
                patch.object(store, "_atomic_write"),
                patch.object(store, "_write_manifest"),
                patch.object(Path, "exists", side_effect=AssertionError),
                patch.object(Path, "is_file", side_effect=AssertionError),
                patch.object(Path, "is_symlink", side_effect=AssertionError),
            ):
                result = store.capture(
                    [{"path": str(target), "sha256": digest}]
                )
            self.assertTrue(result["success"])
            optional_read.assert_called_once_with(store.blobs / digest, restoration.MAX_FILE_BYTES)
            exact_read.assert_called_once_with(
                store.blobs / digest, restoration.MAX_FILE_BYTES
            )
            self.assertIs(result["capture_receipts"][0]["stored"], True)
            self.assertIs(
                result["capture_receipts"][0]["backup_matches_source"], True
            )

    def test_restore_point_capture_binds_the_approved_security_descriptor(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "protected.conf"
            target.write_bytes(b"approved")
            store = RestorePointStore(root / "state")
            metadata = {
                "mode": 0o600,
                "uid": -1,
                "gid": -1,
                "xattrs": {},
                "windows_security_descriptor": "descriptor-base64",
                "windows_security_descriptor_version": 3,
            }
            with patch.object(
                store,
                "_read_target",
                return_value=(b"approved", metadata),
            ):
                result = store.capture(
                    [
                        {
                            "path": str(target),
                            "sha256": hashlib.sha256(b"approved").hexdigest(),
                            "security_descriptor_sha256": "0" * 64,
                        }
                    ]
                )
        self.assertFalse(result["success"])
        self.assertIn("security metadata", result["rejected"][0]["reason"])

    @unittest.skipUnless(os.name == "posix", "POSIX metadata stability test")
    def test_restore_point_capture_rejects_metadata_changed_during_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "protected.conf"
            target.write_bytes(b"approved")
            digest = hashlib.sha256(target.read_bytes()).hexdigest()
            store = RestorePointStore(root / "state")
            with patch.object(
                RestorePointStore,
                "_capture_xattrs",
                side_effect=[{"user.fixture": "first"}, {"user.fixture": "second"}],
            ):
                result = store.capture(
                    [{"path": str(target), "sha256": digest}]
                )
        self.assertFalse(result["success"])
        self.assertEqual(result["captured"], [])
        self.assertEqual(result["capture_receipts"], [])
        self.assertIn(
            "changed during restore-point capture", result["rejected"][0]["reason"]
        )

    def test_startup_reports_prior_failed_undo_as_unhealthy(self):
        with tempfile.TemporaryDirectory() as directory:
            store = RestorePointStore(Path(directory) / "state")
            transaction_id = str(uuid.uuid4())
            store._write_json(
                store.transactions / f"{transaction_id}.json",
                {"transaction_id": transaction_id, "status": "undo_failed"},
            )
            report = store.recover_incomplete()
        self.assertFalse(report["healthy"])
        self.assertIn("operator recovery", report["unresolved"][0]["reason"])

    def test_startup_preserves_new_file_with_metadata_only_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = RestorePointStore(root / "state")
            target = root / "created.conf"
            target.write_bytes(b"restored")
            restored, restored_metadata = store._read_target(target)
            transaction_id = str(uuid.uuid4())
            store._write_json(
                store.transactions / f"{transaction_id}.json",
                {
                    "transaction_id": transaction_id,
                    "status": "prepared",
                    "path": str(target),
                    "existed": False,
                    "before_sha256": None,
                    "evidence": None,
                    "before_metadata": {},
                    "restored_sha256": hashlib.sha256(restored).hexdigest(),
                    "restored_metadata": restored_metadata,
                    "rolled_back": False,
                },
            )
            target.chmod(0o400 if target.stat().st_mode & 0o777 != 0o400 else 0o600)
            report = store.recover_incomplete()
            self.assertTrue(target.exists())
        self.assertFalse(report["healthy"])
        self.assertIn("newer change", report["unresolved"][0]["reason"])

    def test_failed_automatic_rollback_is_persisted_as_unhealthy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "protected.conf"
            target.write_bytes(b"approved")
            approved = hashlib.sha256(target.read_bytes()).hexdigest()
            store = RestorePointStore(root / "state", ["127.0.0.0/8"])
            self.assertTrue(
                store.capture([{"path": str(target), "sha256": approved}])["success"]
            )
            target.write_bytes(b"compromised")
            observed = hashlib.sha256(target.read_bytes()).hexdigest()
            with (
                patch.object(store, "_restore_before", return_value=None),
                patch(
                    "sentinel_blue.restoration.run_probes",
                    return_value=[ProbeResult("health", "127.0.0.1", False)],
                ),
            ):
                with self.assertRaisesRegex(OSError, "rollback"):
                    store.restore(
                        {
                            "path": str(target),
                            "baseline_sha256": approved,
                            "observed_sha256": observed,
                        },
                        allowed=True,
                        probes=[{"name": "health"}],
                    )
            transaction = json.loads(
                next(store.transactions.glob("*.json")).read_text(encoding="utf-8")
            )
            report = store.recover_incomplete()
        self.assertEqual(transaction["status"], "rollback_failed")
        self.assertFalse(report["healthy"])

    def test_concurrent_restore_point_captures_preserve_every_manifest_entry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executor = ActionExecutor(root, allow_restoration=True)
            items = []
            for index in range(16):
                target = root / f"protected-{index}.conf"
                target.write_text(f"approved-{index}", encoding="utf-8")
                items.append({"path": str(target), "sha256": hashlib.sha256(target.read_bytes()).hexdigest()})
            with ThreadPoolExecutor(max_workers=8) as pool:
                results = list(
                    pool.map(
                        lambda item: executor.restore_points.capture([item]),
                        items,
                    )
                )
            self.assertTrue(all(result["success"] for result in results))
            manifest = executor.restore_points._read_manifest()
            self.assertEqual(set(manifest), {item["path"] for item in items})

    def test_capture_restore_and_operator_undo_are_reversible(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "protected.conf"
            target.write_text("approved\n", encoding="utf-8")
            approved = hashlib.sha256(target.read_bytes()).hexdigest()
            executor = ActionExecutor(directory, allow_restoration=True)
            capture = executor.execute(
                "capture_restore_point",
                {"files": [{"path": str(target), "sha256": approved}]},
                {},
            )
            self.assertTrue(capture["success"])
            self.assertIs(capture["dry_run"], False)
            target.write_text("tampered\n", encoding="utf-8")
            observed = hashlib.sha256(target.read_bytes()).hexdigest()
            restored = executor.execute(
                "restore_integrity",
                {
                    "path": str(target),
                    "baseline_sha256": approved,
                    "observed_sha256": observed,
                },
                {},
            )
            self.assertTrue(restored["success"])
            self.assertEqual(target.read_text(encoding="utf-8"), "approved\n")
            self.assertTrue(restored["evidence_preserved"])
            undone = executor.execute(
                "rollback_integrity",
                restored["pre_state"],
                {},
            )
            self.assertTrue(undone["success"])
            self.assertEqual(target.read_text(encoding="utf-8"), "tampered\n")

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "setxattr"), "POSIX xattrs unavailable")
    def test_restoration_and_undo_preserve_extended_attributes(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "protected.conf"
            target.write_text("approved\n", encoding="utf-8")
            try:
                os.setxattr(target, "user.sentinel-blue-test", b"approved")
            except OSError as exc:
                self.skipTest(f"filesystem xattrs unavailable: {exc}")
            approved = hashlib.sha256(target.read_bytes()).hexdigest()
            executor = ActionExecutor(Path(directory) / "state", allow_restoration=True)
            captured = executor.execute(
                "capture_restore_point",
                {"files": [{"path": str(target), "sha256": approved}]},
                {},
            )
            self.assertTrue(captured["success"])
            target.write_text("tampered\n", encoding="utf-8")
            os.setxattr(target, "user.sentinel-blue-test", b"tampered")
            restored = executor.execute(
                "restore_integrity",
                {
                    "path": str(target),
                    "baseline_sha256": approved,
                    "observed_sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
                },
                {},
            )
            self.assertTrue(restored["success"])
            self.assertEqual(os.getxattr(target, "user.sentinel-blue-test"), b"approved")
            undone = executor.execute("rollback_integrity", restored["pre_state"], {})
            self.assertTrue(undone["success"])
            self.assertEqual(os.getxattr(target, "user.sentinel-blue-test"), b"tampered")

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "symlink"), "POSIX symlinks unavailable")
    def test_restore_refuses_symbolic_link_in_parent_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real = root / "real"
            real.mkdir()
            target = real / "protected.conf"
            target.write_text("approved", encoding="utf-8")
            linked = root / "linked"
            linked.symlink_to(real, target_is_directory=True)
            through_link = linked / target.name
            executor = ActionExecutor(root / "state", allow_restoration=True)
            result = executor.execute(
                "capture_restore_point",
                {
                    "files": [
                        {
                            "path": str(through_link),
                            "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
                        }
                    ]
                },
                {},
            )
            self.assertFalse(result["success"])
            self.assertTrue(result["rejected"])

    def test_windows_acl_capture_uses_the_pinned_native_snapshot(self):
        target = Path("C:/ProgramData/SentinelBlue/test.conf")
        with (
            patch("sentinel_blue.restoration.os.name", "nt"),
            patch(
                "sentinel_blue.restoration._windows_read_file_snapshot",
                return_value=(
                    b"approved",
                    {
                        "windows_security_descriptor": "O:BAG:SYD:(A;;FA;;;SY)"
                    },
                ),
            ) as snapshot,
            patch("sentinel_blue.restoration._restore_windows_security_descriptor") as apply,
        ):
            sddl = RestorePointStore._windows_acl(target)
            RestorePointStore._apply_windows_acl(target, sddl)
        self.assertEqual(sddl, "O:BAG:SYD:(A;;FA;;;SY)")
        snapshot.assert_called_once_with(target, restoration.MAX_FILE_BYTES)
        apply.assert_called_once_with(target, sddl)

    def test_restoration_is_dry_run_without_explicit_agent_permission(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "protected.conf"
            target.write_text("approved", encoding="utf-8")
            approved = hashlib.sha256(target.read_bytes()).hexdigest()
            executor = ActionExecutor(directory)
            self.assertTrue(
                executor.execute(
                    "capture_restore_point",
                    {"files": [{"path": str(target), "sha256": approved}]},
                    {},
                )["success"]
            )
            target.write_text("changed", encoding="utf-8")
            result = executor.execute(
                "restore_integrity",
                {"path": str(target), "baseline_sha256": approved},
                {},
            )
            self.assertTrue(result["success"])
            self.assertTrue(result["dry_run"])
            self.assertEqual(target.read_text(encoding="utf-8"), "changed")

    def test_restoration_rolls_back_when_service_probe_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "protected.conf"
            target.write_text("approved", encoding="utf-8")
            approved = hashlib.sha256(target.read_bytes()).hexdigest()
            executor = ActionExecutor(directory, allow_restoration=True)
            executor.execute(
                "capture_restore_point",
                {"files": [{"path": str(target), "sha256": approved}]},
                {},
            )
            target.write_text("required-change", encoding="utf-8")
            observed = hashlib.sha256(target.read_bytes()).hexdigest()
            unhealthy = ProbeResult("service-monitor-example", "http://127.0.0.1", False, 1.0, "failed")
            with patch("sentinel_blue.restoration.run_probes", return_value=[unhealthy]):
                result = executor.execute(
                    "restore_integrity",
                    {
                        "path": str(target),
                        "baseline_sha256": approved,
                        "observed_sha256": observed,
                        "probes": [{"name": "service-monitor-example"}],
                    },
                    {},
                )
            self.assertFalse(result["success"])
            self.assertTrue(result["rolled_back"])
            self.assertEqual(target.read_text(encoding="utf-8"), "required-change")

    def test_restoration_rolls_back_when_service_config_validator_rejects(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "protected.conf"
            target.write_text("approved", encoding="utf-8")
            approved = hashlib.sha256(target.read_bytes()).hexdigest()
            executor = ActionExecutor(directory, allow_restoration=True)
            executor.execute(
                "capture_restore_point",
                {"files": [{"path": str(target), "sha256": approved}]},
                {},
            )
            target.write_text("required-change", encoding="utf-8")
            validation = {
                "applicable": True, "available": True, "healthy": False,
                "validator": "fixture", "detail": "synthetic invalid config",
            }
            with patch(
                "sentinel_blue.restoration.validate_restored_configuration",
                return_value=validation,
            ):
                result = executor.execute(
                    "restore_integrity",
                    {"path": str(target), "baseline_sha256": approved},
                    {},
                )
            self.assertFalse(result["success"])
            self.assertTrue(result["rolled_back"])
            self.assertEqual(result["config_validation"], validation)
            self.assertEqual(target.read_text(encoding="utf-8"), "required-change")

    def test_corrupt_manifest_is_preserved_and_blocks_restoration(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "protected.conf"
            target.write_text("approved", encoding="utf-8")
            approved = hashlib.sha256(target.read_bytes()).hexdigest()
            executor = ActionExecutor(directory, allow_restoration=True)
            executor.execute(
                "capture_restore_point",
                {"files": [{"path": str(target), "sha256": approved}]},
                {},
            )
            manifest = executor.restore_points.manifest_path
            manifest.write_text("{corrupt", encoding="utf-8")
            target.write_text("tampered", encoding="utf-8")
            result = executor.execute(
                "restore_integrity",
                {"path": str(target), "baseline_sha256": approved},
                {},
            )
            self.assertFalse(result["success"])
            self.assertIn("manifest is corrupt", result["message"])
            self.assertEqual(manifest.read_text(encoding="utf-8"), "{corrupt")
            self.assertEqual(target.read_text(encoding="utf-8"), "tampered")

    def test_duplicate_manifest_path_is_preserved_and_blocks_restoration(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "protected.conf"
            target.write_text("approved", encoding="utf-8")
            approved = hashlib.sha256(target.read_bytes()).hexdigest()
            executor = ActionExecutor(directory, allow_restoration=True)
            executor.execute(
                "capture_restore_point",
                {"files": [{"path": str(target), "sha256": approved}]},
                {},
            )
            manifest = executor.restore_points.manifest_path
            record = json.dumps(
                {
                    "sha256": approved,
                    **self._metadata(),
                },
                separators=(",", ":"),
            )
            manifest.write_text(
                "{" + json.dumps(str(target)) + ":" + record + ","
                + json.dumps(str(target)) + ":" + record + "}",
                encoding="utf-8",
            )
            target.write_text("tampered", encoding="utf-8")
            result = executor.execute(
                "restore_integrity",
                {"path": str(target), "baseline_sha256": approved},
                {},
            )
            self.assertFalse(result["success"])
            self.assertIn("manifest is corrupt", result["message"])
            self.assertEqual(target.read_text(encoding="utf-8"), "tampered")

    def test_restoration_state_writer_refuses_nonfinite_values(self):
        with tempfile.TemporaryDirectory() as directory:
            store = RestorePointStore(Path(directory) / "state")
            destination = store.transactions / f"{uuid.uuid4()}.json"
            with self.assertRaisesRegex(ValueError, "invalid or exceeds"):
                store._write_json(destination, {"created_at": float("nan")})
            self.assertFalse(destination.exists())

    def test_interrupted_target_replacement_restores_prechange_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "protected.conf"
            target.write_text("approved", encoding="utf-8")
            approved = hashlib.sha256(target.read_bytes()).hexdigest()
            executor = ActionExecutor(directory, allow_restoration=True)
            executor.execute(
                "capture_restore_point",
                {"files": [{"path": str(target), "sha256": approved}]},
                {},
            )
            target.write_text("prechange", encoding="utf-8")
            original = executor.restore_points._replace_target
            calls = 0

            def interrupt_once(path, data, metadata):
                nonlocal calls
                calls += 1
                original(path, data, metadata)
                if calls == 1:
                    raise OSError("synthetic power loss")

            with patch.object(executor.restore_points, "_replace_target", side_effect=interrupt_once):
                result = executor.execute(
                    "restore_integrity",
                    {"path": str(target), "baseline_sha256": approved},
                    {},
                )
            self.assertFalse(result["success"])
            self.assertEqual(target.read_text(encoding="utf-8"), "prechange")

    def test_startup_recovers_a_restoration_interrupted_after_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "protected.conf"
            target.write_text("approved", encoding="utf-8")
            approved = hashlib.sha256(target.read_bytes()).hexdigest()
            executor = ActionExecutor(directory, allow_restoration=True)
            executor.execute(
                "capture_restore_point",
                {"files": [{"path": str(target), "sha256": approved}]},
                {},
            )
            target.write_text("prechange", encoding="utf-8")
            original = executor.restore_points._replace_target

            def simulated_process_death(path, data, metadata):
                original(path, data, metadata)
                raise SystemExit("synthetic process death")

            with patch.object(
                executor.restore_points,
                "_replace_target",
                side_effect=simulated_process_death,
            ):
                with self.assertRaises(SystemExit):
                    executor.restore_points.restore(
                        {"path": str(target), "baseline_sha256": approved},
                        allowed=True,
                    )
            self.assertEqual(target.read_text(encoding="utf-8"), "approved")
            restarted = ActionExecutor(directory, allow_restoration=True)
            self.assertTrue(restarted.restore_recovery["healthy"])
            self.assertEqual(len(restarted.restore_recovery["recovered"]), 1)
            self.assertEqual(target.read_text(encoding="utf-8"), "prechange")

    def test_startup_aborts_an_interrupted_operator_undo(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "protected.conf"
            target.write_text("approved", encoding="utf-8")
            approved = hashlib.sha256(target.read_bytes()).hexdigest()
            executor = ActionExecutor(directory, allow_restoration=True)
            executor.execute(
                "capture_restore_point",
                {"files": [{"path": str(target), "sha256": approved}]},
                {},
            )
            target.write_text("pre-restoration", encoding="utf-8")
            restored = executor.execute(
                "restore_integrity",
                {"path": str(target), "baseline_sha256": approved},
                {},
            )
            transaction_id = restored["pre_state"]["transaction_id"]
            with patch(
                "sentinel_blue.restoration.run_probes",
                side_effect=SystemExit("synthetic process death"),
            ):
                with self.assertRaises(SystemExit):
                    executor.restore_points.rollback(transaction_id, allowed=True)
            self.assertEqual(target.read_text(encoding="utf-8"), "pre-restoration")
            restarted = ActionExecutor(directory, allow_restoration=True)
            self.assertTrue(restarted.restore_recovery["healthy"])
            self.assertEqual(restarted.restore_recovery["recovered"], [transaction_id])
            self.assertEqual(target.read_text(encoding="utf-8"), "approved")
            transaction = restarted.restore_points.transactions / f"{transaction_id}.json"
            self.assertIn('"status": "committed"', transaction.read_text(encoding="utf-8"))

    @unittest.skipUnless(os.name == "posix", "POSIX metadata fixture")
    def test_operator_undo_rejects_metadata_only_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "protected.conf"
            target.write_text("approved", encoding="utf-8")
            target.chmod(0o640)
            approved = hashlib.sha256(target.read_bytes()).hexdigest()
            executor = ActionExecutor(directory, allow_restoration=True)
            executor.execute(
                "capture_restore_point",
                {"files": [{"path": str(target), "sha256": approved}]},
                {},
            )
            target.write_text("pre-restoration", encoding="utf-8")
            restored = executor.execute(
                "restore_integrity",
                {"path": str(target), "baseline_sha256": approved},
                {},
            )
            target.chmod(0o600)
            result = executor.execute("rollback_integrity", restored["pre_state"], {})
            self.assertFalse(result["success"])
            self.assertIn("security metadata changed", result["message"])

    def test_windows_path_validation_defers_reparse_checks_to_pinned_handles(self):
        target = Path("C:/ProgramData/SentinelBlue/protected.conf")
        with (
            patch("sentinel_blue.restoration.os.name", "nt"),
            patch.object(Path, "exists", side_effect=AssertionError),
            patch.object(Path, "is_symlink", side_effect=AssertionError),
            patch.object(Path, "lstat", side_effect=AssertionError),
        ):
            RestorePointStore._validate_windows_path(target)

    def test_windows_path_validation_rejects_stream_and_namespace_paths(self):
        paths = [
            Path("C:/ProgramData/SentinelBlue/protected.conf:stream"),
            Path("//server/share/protected.conf"),
        ]
        with patch("sentinel_blue.restoration.os.name", "nt"):
            for target in paths:
                with self.subTest(target=str(target)):
                    with self.assertRaisesRegex(ValueError, "local filesystem paths"):
                        RestorePointStore._validate_windows_path(target)

    def test_restore_refuses_stale_observation(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "protected.conf"
            target.write_text("approved", encoding="utf-8")
            approved = hashlib.sha256(target.read_bytes()).hexdigest()
            executor = ActionExecutor(directory, allow_restoration=True)
            executor.execute(
                "capture_restore_point",
                {"files": [{"path": str(target), "sha256": approved}]},
                {},
            )
            target.write_text("second-change", encoding="utf-8")
            result = executor.execute(
                "restore_integrity",
                {
                    "path": str(target),
                    "baseline_sha256": approved,
                    "observed_sha256": "a" * 64,
                },
                {},
            )
            self.assertFalse(result["success"])
            self.assertIn("changed again", result["message"])

    @unittest.skipUnless(hasattr(os, "symlink"), "symbolic links unavailable")
    def test_restore_point_blob_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "protected.conf"
            target.write_text("approved", encoding="utf-8")
            approved = hashlib.sha256(target.read_bytes()).hexdigest()
            executor = ActionExecutor(directory, allow_restoration=True)
            executor.execute(
                "capture_restore_point",
                {"files": [{"path": str(target), "sha256": approved}]},
                {},
            )
            blob = executor.restore_points.blobs / approved
            blob.unlink()
            blob.symlink_to(target)
            target.write_text("tampered", encoding="utf-8")
            result = executor.execute(
                "restore_integrity",
                {"path": str(target), "baseline_sha256": approved},
                {},
            )
            self.assertFalse(result["success"])
            self.assertIn("non-symlink", result["message"])
            self.assertEqual(target.read_text(encoding="utf-8"), "tampered")

    @unittest.skipUnless(hasattr(os, "symlink"), "symbolic links unavailable")
    def test_undo_rejects_symlinked_transaction_record(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "protected.conf"
            target.write_text("approved", encoding="utf-8")
            approved = hashlib.sha256(target.read_bytes()).hexdigest()
            executor = ActionExecutor(directory, allow_restoration=True)
            executor.execute(
                "capture_restore_point",
                {"files": [{"path": str(target), "sha256": approved}]},
                {},
            )
            target.write_text("tampered", encoding="utf-8")
            restored = executor.execute(
                "restore_integrity",
                {"path": str(target), "baseline_sha256": approved},
                {},
            )
            transaction_id = restored["pre_state"]["transaction_id"]
            transaction = executor.restore_points.transactions / f"{transaction_id}.json"
            replacement = Path(directory) / "untrusted.json"
            replacement.write_text(transaction.read_text(encoding="utf-8"), encoding="utf-8")
            transaction.unlink()
            transaction.symlink_to(replacement)
            result = executor.execute(
                "rollback_integrity",
                {"transaction_id": transaction_id},
                {},
            )
            self.assertFalse(result["success"])
            self.assertIn("non-symlink", result["message"])
    def test_containment_is_dry_run_by_default(self):
        with tempfile.TemporaryDirectory() as directory:
            executor = ActionExecutor(directory)
            result = executor.execute(
                "quarantine_session",
                {"session": {"username": "root", "process_id": 999999}},
                {},
            )
        self.assertTrue(result["success"])
        self.assertTrue(result["dry_run"])

    def test_quarantine_ttl_is_finite_and_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(
                ActionExecutor(directory, quarantine_ttl=0).quarantine_ttl,
                30.0,
            )
            self.assertEqual(
                ActionExecutor(directory, quarantine_ttl=99_999).quarantine_ttl,
                3600.0,
            )
            for invalid in (True, float("nan"), float("inf"), "300"):
                with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                    ActionExecutor(directory, quarantine_ttl=invalid)

    def test_snapshot_is_created(self):
        with tempfile.TemporaryDirectory() as directory:
            executor = ActionExecutor(directory)
            result = executor.execute("snapshot", {}, {"agent_id": "test"})
            self.assertTrue(result["success"])
            self.assertEqual(len(list(executor.state_dir.glob("snapshot-*.json"))), 1)

    def test_snapshot_history_is_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            executor = ActionExecutor(directory)
            with patch("sentinel_blue.actions.MAX_SNAPSHOTS", 2):
                for sequence in range(3):
                    self.assertTrue(executor.execute("snapshot", {}, {"sequence": sequence})["success"])
            records = sorted(executor.state_dir.glob("snapshot-*.json"))
            self.assertEqual(len(records), 2)

    def test_terminal_service_transaction_history_is_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            executor = ActionExecutor(directory)
            for sequence in range(3):
                write_private_json(
                    Path(directory) / f"service-transaction-terminal-{sequence}.json",
                    {"status": "committed", "completed_at": float(sequence)},
                )
            with patch("sentinel_blue.actions.MAX_SERVICE_TRANSACTIONS", 2):
                self.assertEqual(executor._prune_service_transactions(), [])
            self.assertEqual(
                len(list(Path(directory).glob("service-transaction-*.json"))),
                2,
            )

    def test_service_recovery_is_dry_run_by_default(self):
        with tempfile.TemporaryDirectory() as directory:
            executor = ActionExecutor(directory)
            result = executor.execute("restart_service", {"service": "web.service"}, {})
        self.assertTrue(result["success"])
        self.assertTrue(result["dry_run"])

    def test_action_and_restoration_probes_receive_the_exact_host_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            executor = ActionExecutor(
                directory,
                authorized_networks=["203.0.113.0/24"],
                authorized_hosts=["203.0.113.7"],
                excluded_hosts=["203.0.113.99"],
            )
            healthy = ProbeResult("web", "203.0.113.7", True)
            with patch("sentinel_blue.actions.run_probes", return_value=[healthy]) as runner:
                result = executor.execute(
                    "validate_service",
                    {"probes": [{"name": "web"}]},
                    {},
                )
        self.assertTrue(result["success"])
        runner.assert_called_once_with(
            [{"name": "web"}],
            ["203.0.113.0/24"],
            authorized_hosts=["203.0.113.7"],
            excluded_hosts=["203.0.113.99"],
        )
        self.assertEqual(executor.restore_points.authorized_hosts, ["203.0.113.7"])
        self.assertEqual(executor.restore_points.excluded_hosts, ["203.0.113.99"])

    def test_service_state_inspection_failure_is_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            executor = ActionExecutor(directory, allow_containment=True)
            with patch.object(executor, "_service_state", side_effect=OSError("unavailable")):
                result = executor.execute("restart_service", {"service": "web.service"}, {})
        self.assertFalse(result["success"])
        self.assertIn("inspection failed", result["message"])

    @unittest.skipIf(os.name != "posix", "Linux process suspension test")
    def test_live_quarantine_and_release_own_child_process(self):
        child = subprocess.Popen(["sleep", "30"])
        try:
            with tempfile.TemporaryDirectory() as directory:
                executor = ActionExecutor(directory, allow_containment=True)
                identity = inspect_process_identity(child.pid)
                telemetry = self._session_telemetry(
                    child.pid,
                    boot_id=identity["boot_id"],
                    identity=identity,
                )
                quarantine = executor.execute(
                    "quarantine_session",
                    self._session_parameters(telemetry),
                    telemetry,
                )
                self.assertTrue(quarantine["success"])
                release_telemetry = dict(telemetry)
                release_telemetry["sequence"] += 1
                release_telemetry["queued_at"] = time.time()
                release = executor.execute(
                    "release_quarantine",
                    self._session_parameters(release_telemetry),
                    release_telemetry,
                )
                self.assertTrue(release["success"])
        finally:
            try:
                os.kill(child.pid, signal.SIGCONT)
            except ProcessLookupError:
                pass
            child.terminate()
            child.wait(timeout=5)

    def test_failed_service_probe_restores_previous_state(self):
        with tempfile.TemporaryDirectory() as directory:
            executor = ActionExecutor(directory, allow_containment=True)
            unhealthy = ProbeResult("web", "http://127.0.0.1", False, 1.0, "timeout")
            with (
                patch.object(executor, "_service_state", side_effect=["stopped", "running"]),
                patch.object(executor, "_set_service_state") as set_state,
                patch("sentinel_blue.actions.run_probes", return_value=[unhealthy]),
            ):
                result = executor.execute(
                    "restart_service",
                    {"service": "web.service", "probes": [{"name": "web"}]},
                    {},
                )
            self.assertFalse(result["success"])
            self.assertTrue(result["rolled_back"])
            self.assertEqual(
                set_state.call_args_list,
                [call("web.service", "running"), call("web.service", "stopped")],
            )

    def test_quarantine_preparation_write_failure_never_suspends_process(self):
        with tempfile.TemporaryDirectory() as directory:
            executor = ActionExecutor(directory, allow_containment=True)
            identity = self._identity()
            telemetry = self._session_telemetry(identity=identity)
            with (
                patch.object(executor, "_process_identity", return_value=identity),
                patch.object(executor, "_suspend_process") as suspend,
                patch.object(executor, "_resume_process") as resume,
                patch("sentinel_blue.actions.write_private_json", side_effect=OSError("disk unavailable")),
            ):
                result = executor.execute(
                    "quarantine_session",
                    self._session_parameters(telemetry),
                    telemetry,
                )
            suspend.assert_not_called()
            resume.assert_not_called()
            self.assertFalse(result["success"])
            self.assertFalse(result["rolled_back"])

    def test_later_same_boot_observation_can_quarantine_the_exact_process(self):
        with tempfile.TemporaryDirectory() as directory:
            executor = ActionExecutor(directory, allow_containment=True)
            identity = self._identity()
            source = self._session_telemetry(identity=identity, sequence=7)
            parameters = self._session_parameters(source)
            current = self._session_telemetry(identity=identity, sequence=8)
            with (
                patch.object(executor, "_process_identity", return_value=identity),
                patch.object(executor, "_suspend_process") as suspend,
            ):
                result = executor.execute(
                    "quarantine_session", parameters, current
                )
        self.assertTrue(result["success"])
        suspend.assert_called_once_with(4242, identity)
        self.assertEqual(result["record"]["target_observation"], parameters["observation"])
        self.assertEqual(result["record"]["execution_observation"]["sequence"], 8)
        self.assertEqual(
            result["record"]["execution_observation"]["payload_sha256"],
            telemetry_observation_sha256(current),
        )

    def test_later_same_boot_observation_can_release_the_exact_process(self):
        with tempfile.TemporaryDirectory() as directory:
            executor = ActionExecutor(directory, allow_containment=True)
            identity = self._identity()
            source = self._session_telemetry(identity=identity, sequence=7)
            source_parameters = self._session_parameters(source)
            with (
                patch.object(executor, "_process_identity", return_value=identity),
                patch.object(executor, "_suspend_process"),
            ):
                self.assertTrue(
                    executor.execute(
                        "quarantine_session", source_parameters, source
                    )["success"]
                )
            current = self._session_telemetry(identity=identity, sequence=8)
            with (
                patch.object(executor, "_process_identity", return_value=identity),
                patch.object(executor, "_resume_process") as resume,
            ):
                released = executor.execute(
                    "release_quarantine", source_parameters, current
                )
        self.assertTrue(released["success"])
        resume.assert_called_once_with(4242, identity)

    def test_session_action_refuses_older_or_rebooted_telemetry(self):
        identity = self._identity()
        source = self._session_telemetry(identity=identity, sequence=7)
        parameters = self._session_parameters(source)
        cases = (
            self._session_telemetry(identity=identity, sequence=6),
            self._session_telemetry(
                identity=self._identity(4242, "new-boot"),
                sequence=8,
                boot_id="new-boot",
            ),
        )
        for current in cases:
            with self.subTest(boot=current["boot_id"], sequence=current["sequence"]):
                with tempfile.TemporaryDirectory() as directory:
                    executor = ActionExecutor(directory, allow_containment=True)
                    with (
                        patch.object(executor, "_process_identity") as process_identity,
                        patch.object(executor, "_suspend_process") as suspend,
                    ):
                        result = executor.execute(
                            "quarantine_session", parameters, current
                        )
                self.assertFalse(result["success"])
                self.assertTrue(result["review_required"])
                process_identity.assert_not_called()
                suspend.assert_not_called()

    def test_session_action_refuses_same_sequence_payload_substitution(self):
        identity = self._identity()
        source = self._session_telemetry(identity=identity, sequence=7)
        parameters = self._session_parameters(source)
        current = dict(source)
        current["hostname"] = "substituted-host"
        with tempfile.TemporaryDirectory() as directory:
            executor = ActionExecutor(directory, allow_containment=True)
            with (
                patch.object(executor, "_process_identity") as process_identity,
                patch.object(executor, "_suspend_process") as suspend,
            ):
                result = executor.execute(
                    "quarantine_session", parameters, current
                )
        self.assertFalse(result["success"])
        self.assertTrue(result["review_required"])
        process_identity.assert_not_called()
        suspend.assert_not_called()

    def test_session_action_refuses_changed_session_or_native_identity(self):
        identity = self._identity()
        source = self._session_telemetry(identity=identity, sequence=7)
        parameters = self._session_parameters(source)

        changed_session = self._session_telemetry(identity=identity, sequence=8)
        changed_session["sessions"][0]["source"] = "203.0.113.9"
        replacement_identity = self._identity()
        replacement_identity["start_time"] = "987654"

        for current, kernel_identity, expects_lookup in (
            (changed_session, identity, False),
            (
                self._session_telemetry(identity=identity, sequence=8),
                replacement_identity,
                True,
            ),
        ):
            with self.subTest(expects_lookup=expects_lookup):
                with tempfile.TemporaryDirectory() as directory:
                    executor = ActionExecutor(directory, allow_containment=True)
                    with (
                        patch.object(
                            executor,
                            "_process_identity",
                            return_value=kernel_identity,
                        ) as process_identity,
                        patch.object(executor, "_suspend_process") as suspend,
                    ):
                        result = executor.execute(
                            "quarantine_session", parameters, current
                        )
                self.assertFalse(result["success"])
                self.assertTrue(result["review_required"])
                self.assertEqual(process_identity.called, expects_lookup)
                suspend.assert_not_called()

    def test_quarantine_commit_write_failure_resumes_process(self):
        with tempfile.TemporaryDirectory() as directory:
            executor = ActionExecutor(directory, allow_containment=True)
            identity = self._identity()
            telemetry = self._session_telemetry(identity=identity)
            real_write = write_private_json
            calls = 0

            def fail_second(path, payload):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("disk unavailable")
                return real_write(path, payload)

            with (
                patch.object(executor, "_process_identity", return_value=identity),
                patch.object(executor, "_suspend_process") as suspend,
                patch.object(executor, "_resume_process") as resume,
                patch("sentinel_blue.actions.write_private_json", side_effect=fail_second),
            ):
                result = executor.execute(
                    "quarantine_session",
                    self._session_parameters(telemetry),
                    telemetry,
                )
            suspend.assert_called_once_with(4242, identity)
            resume.assert_called_once_with(4242, identity)
            self.assertFalse(result["success"])
            self.assertTrue(result["rolled_back"])

    def test_quarantine_resume_failure_retains_a_fail_closed_record(self):
        with tempfile.TemporaryDirectory() as directory:
            executor = ActionExecutor(directory, allow_containment=True)
            identity = self._identity()
            telemetry = self._session_telemetry(identity=identity)
            real_write = write_private_json
            calls = 0

            def fail_second(path, payload):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("disk unavailable during active commit")
                return real_write(path, payload)

            with (
                patch.object(executor, "_process_identity", return_value=identity),
                patch.object(executor, "_suspend_process"),
                patch.object(
                    executor, "_resume_process", side_effect=OSError("resume unavailable")
                ) as resume,
                patch("sentinel_blue.actions.write_private_json", side_effect=fail_second),
            ):
                result = executor.execute(
                    "quarantine_session",
                    self._session_parameters(telemetry),
                    telemetry,
                )
            record = executor._read_quarantine()["4242"]
            self.assertFalse(result["success"])
            self.assertFalse(result["rolled_back"])
            self.assertEqual(record["status"], "rollback_failed")
            self.assertIn("resume unavailable", record["last_error"])
            self.assertFalse(executor.quarantine_recovery["healthy"])
            resume.assert_called_once_with(4242, identity)

    def test_failed_quarantine_probe_and_resume_preserves_recovery_record(self):
        unhealthy = ProbeResult("health", "127.0.0.1", False)
        with tempfile.TemporaryDirectory() as directory:
            executor = ActionExecutor(directory, allow_containment=True)
            identity = self._identity()
            telemetry = self._session_telemetry(identity=identity)
            with (
                patch.object(executor, "_process_identity", return_value=identity),
                patch.object(executor, "_suspend_process"),
                patch.object(
                    executor, "_resume_process", side_effect=OSError("resume unavailable")
                ) as resume,
                patch("sentinel_blue.actions.run_probes", return_value=[unhealthy]),
            ):
                result = executor.execute(
                    "quarantine_session",
                    {
                        **self._session_parameters(telemetry),
                        "probes": [{"name": "health"}],
                    },
                    telemetry,
                )
            record = executor._read_quarantine()["4242"]
            self.assertFalse(result["success"])
            self.assertFalse(result["rolled_back"])
            self.assertEqual(record["status"], "rollback_failed")
            self.assertFalse(executor.quarantine_recovery["healthy"])
            self.assertEqual(resume.call_count, 2)

    @unittest.skipIf(os.name != "posix", "Linux process suspension recovery test")
    def test_startup_recovers_quarantine_interrupted_after_suspend(self):
        child = subprocess.Popen(["sleep", "30"])
        try:
            with tempfile.TemporaryDirectory() as directory:
                executor = ActionExecutor(directory, allow_containment=True)
                identity = inspect_process_identity(child.pid)
                telemetry = self._session_telemetry(
                    child.pid,
                    boot_id=identity["boot_id"],
                    identity=identity,
                )
                original = executor._write_quarantine
                calls = 0

                def interrupt_second(records):
                    nonlocal calls
                    calls += 1
                    if calls == 2:
                        raise SystemExit("synthetic process death")
                    return original(records)

                with patch.object(executor, "_write_quarantine", side_effect=interrupt_second):
                    with self.assertRaises(SystemExit):
                        executor.execute(
                            "quarantine_session",
                            self._session_parameters(telemetry),
                            telemetry,
                        )
                restarted = ActionExecutor(directory, allow_containment=True)
                self.assertTrue(restarted.quarantine_recovery["healthy"])
                self.assertIn(child.pid, restarted.quarantine_recovery["recovered"])
                self.assertEqual(restarted._read_quarantine(), {})
        finally:
            try:
                os.kill(child.pid, signal.SIGCONT)
            except ProcessLookupError:
                pass
            child.terminate()
            child.wait(timeout=5)

    def test_successful_service_recovery_exposes_reversible_pre_state(self):
        with tempfile.TemporaryDirectory() as directory:
            executor = ActionExecutor(directory, allow_containment=True)
            with (
                patch.object(executor, "_service_state", side_effect=["stopped", "running"]),
                patch.object(executor, "_set_service_state"),
                patch("sentinel_blue.actions.run_probes", return_value=[]),
            ):
                result = executor.execute("restart_service", {"service": "web.service"}, {})
            self.assertTrue(result["success"])
            self.assertEqual(
                result["pre_state"], {"service": "web.service", "desired_state": "stopped"}
            )

    def test_interrupted_service_change_requires_review_instead_of_blind_rollback(self):
        with tempfile.TemporaryDirectory() as directory:
            executor = ActionExecutor(directory, allow_containment=True)
            with (
                patch.object(executor, "_service_state", return_value="stopped"),
                patch.object(
                    executor,
                    "_set_service_state",
                    side_effect=SystemExit("synthetic process death after service change"),
                ),
            ):
                with self.assertRaises(SystemExit):
                    executor.execute("restart_service", {"service": "web.service"}, {})
            with patch.object(ActionExecutor, "_service_state", return_value="running"):
                restarted = ActionExecutor(directory, allow_containment=True)
            self.assertFalse(restarted.service_recovery["healthy"])
            self.assertIn("operator review", restarted.service_recovery["unresolved"][0]["reason"])

    def test_service_rollback_is_dry_run_by_default(self):
        with tempfile.TemporaryDirectory() as directory:
            executor = ActionExecutor(directory)
            result = executor.execute(
                "rollback_service",
                {"service": "web.service", "desired_state": "stopped"},
                {},
            )
        self.assertTrue(result["success"])
        self.assertTrue(result["dry_run"])

    def test_expired_quarantine_from_prior_boot_never_resumes_reused_pid(self):
        with tempfile.TemporaryDirectory() as directory:
            executor = ActionExecutor(directory, allow_containment=True)
            executor.quarantine_file.write_text(
                '{"4242":{"process_id":4242,"expires_at":' + str(time.time() - 1) + ',"boot_id":"old-boot"}}'
            )
            with patch.object(executor, "_resume_process") as resume:
                released = executor.release_expired_quarantines("new-boot")
            self.assertEqual(released, [])
            resume.assert_not_called()
            self.assertEqual(executor._read_quarantine(), {})

    def test_expired_quarantine_resume_failure_retains_record_and_blocks_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            executor = ActionExecutor(directory, allow_containment=True)
            executor._write_quarantine(
                {
                    "4242": {
                        "process_id": 4242,
                        "process_identity": self._identity(4242, "same-boot"),
                        "expires_at": time.time() - 1,
                        "boot_id": "same-boot",
                        "status": "active",
                    }
                }
            )
            with (
                patch.object(
                    executor,
                    "_process_identity",
                    return_value=self._identity(4242, "same-boot"),
                ),
                patch.object(
                    executor, "_resume_process", side_effect=OSError("resume unavailable")
                ),
            ):
                released = executor.release_expired_quarantines("same-boot")
            record = executor._read_quarantine()["4242"]
            self.assertEqual(released, [])
            self.assertEqual(record["status"], "release_failed")
            self.assertIn("resume unavailable", record["last_error"])
            self.assertFalse(executor.quarantine_recovery["healthy"])

    def test_expired_quarantine_identity_lookup_failure_retains_record(self):
        with tempfile.TemporaryDirectory() as directory:
            executor = ActionExecutor(directory, allow_containment=True)
            executor._write_quarantine(
                {
                    "4242": {
                        "process_id": 4242,
                        "process_identity": self._identity(4242, "same-boot"),
                        "expires_at": time.time() - 1,
                        "boot_id": "same-boot",
                        "status": "active",
                    }
                }
            )
            with (
                patch.object(
                    executor, "_process_identity", side_effect=OSError("identity unavailable")
                ),
                patch.object(executor, "_resume_process") as resume,
            ):
                released = executor.release_expired_quarantines("same-boot")
            self.assertEqual(released, [])
            resume.assert_not_called()
            record = executor._read_quarantine()["4242"]
            self.assertEqual(record["status"], "release_failed")
            self.assertIn("identity unavailable", record["last_error"])

    def test_expired_quarantine_without_identity_never_signals_a_pid(self):
        with tempfile.TemporaryDirectory() as directory:
            executor = ActionExecutor(directory, allow_containment=True)
            executor._write_quarantine(
                {
                    "4242": {
                        "process_id": 4242,
                        "expires_at": time.time() - 1,
                        "boot_id": "same-boot",
                        "status": "active",
                    }
                }
            )
            with (
                patch.object(executor, "_process_identity") as identity,
                patch.object(executor, "_resume_process") as resume,
            ):
                released = executor.release_expired_quarantines("same-boot")
            self.assertEqual(released, [])
            identity.assert_not_called()
            resume.assert_not_called()
            self.assertEqual(
                executor._read_quarantine()["4242"]["status"], "release_failed"
            )

    def test_startup_failed_quarantine_states_remain_unhealthy_when_resume_fails(self):
        for status in ("rollback_failed", "release_failed"):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                write_private_json(
                    root / "quarantine.json",
                    {
                        "4242": {
                            "process_id": 4242,
                            "process_identity": self._identity(4242, "same-boot"),
                            "expires_at": time.time() + 60,
                            "boot_id": "same-boot",
                            "status": status,
                        }
                    },
                )
                with (
                    patch.object(
                        ActionExecutor,
                        "_process_identity",
                        return_value=self._identity(4242, "same-boot"),
                    ),
                    patch.object(
                        ActionExecutor,
                        "_resume_process",
                        side_effect=OSError("resume unavailable"),
                    ),
                ):
                    restarted = ActionExecutor(root, allow_containment=True)
                self.assertFalse(restarted.quarantine_recovery["healthy"])
                self.assertEqual(restarted._read_quarantine()["4242"]["status"], status)

    def test_service_rollback_failure_is_rechecked_and_gates_actions(self):
        with tempfile.TemporaryDirectory() as directory:
            executor = ActionExecutor(directory, allow_containment=True)
            identifier = str(uuid.uuid4())
            transaction_path = (
                Path(directory) / f"service-transaction-{identifier}.json"
            )
            write_private_json(
                transaction_path,
                {
                    "transaction_id": identifier,
                    "operation": "restart_service",
                    "service": "web.service",
                    "before": "stopped",
                    "desired": "running",
                    "created_at": time.time(),
                    "status": "rollback_failed",
                },
            )
            with patch.object(executor, "_service_state", return_value="running"):
                failed = executor.refresh_service_recovery()
            self.assertFalse(failed["healthy"])
            self.assertIn("operator review", failed["unresolved"][0]["reason"])
            with patch.object(executor, "_service_state", return_value="stopped"):
                recovered = executor.refresh_service_recovery()
            self.assertTrue(recovered["healthy"])
            self.assertIn(identifier, recovered["recovered"])
            self.assertEqual(
                json.loads(transaction_path.read_text(encoding="utf-8"))["status"],
                "recovered",
            )


if __name__ == "__main__":
    unittest.main()
