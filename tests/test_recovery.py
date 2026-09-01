import hashlib
import os
import sqlite3
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

from sentinel_blue.json_codec import canonical_json_bytes, canonical_json_dumps
from sentinel_blue.recovery import (
    ANCHOR_FORMAT,
    MANIFEST_FILENAME,
    AnchorConflictError,
    CrashAction,
    RecoveryAuthenticationError,
    RecoveryError,
    RecoveryPathError,
    RecoverySemanticError,
    _anchor_transition_lock,
    advance_backup_anchor,
    abort_pending_anchor,
    begin_pending_anchor,
    build_backup_manifest,
    commit_pending_anchor,
    decide_crash_state,
    initialize_anchor,
    inspect_controller_database,
    load_anchor,
    load_backup_manifest,
    load_recovery_key,
    make_committed_anchor,
    open_verified_database,
    sign_payload,
    upgrade_legacy_anchor,
    validate_anchor,
    validate_manifest,
    verify_backup_bundle,
    verify_signed_payload,
    write_backup_manifest,
)


APPLICATION_ID = 0x53424C55
USER_VERSION = 8
RELEASE_SHA256 = "a" * 64
PROFILE_FINGERPRINT = "b" * 64


class RecoveryFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        if os.name == "posix":
            self.root.chmod(0o700)
        self.key = bytes(range(32))
        self.instance_id = str(uuid.uuid4())
        self.database_constraints = {
            "expected_application_id": APPLICATION_ID,
            "expected_user_version": USER_VERSION,
            "required_tables": {"controller_state", "evidence"},
            "allowed_tables": {"controller_state", "evidence"},
        }

    def tearDown(self):
        self.temporary.cleanup()

    def database(
        self,
        path: Path,
        *,
        generation: int = 1,
        sequence: int = 1,
        invalid_governance: bool = False,
    ) -> Path:
        connection = sqlite3.connect(path)
        try:
            connection.execute(f"PRAGMA application_id={APPLICATION_ID}")
            connection.execute(f"PRAGMA user_version={USER_VERSION}")
            connection.execute(
                "CREATE TABLE controller_state("
                "state_key TEXT PRIMARY KEY, state_value TEXT NOT NULL, updated_at INTEGER NOT NULL)"
            )
            active = canonical_json_dumps(
                {
                    "schema": 1,
                    "profile_id": "range-profile",
                    "profile_fingerprint": PROFILE_FINGERPRINT,
                    "agent_version": "1.9.7",
                    "release_sha256": RELEASE_SHA256,
                }
            )
            governance = (
                '{"same":1,"same":2}'
                if invalid_governance
                else canonical_json_dumps(
                    {
                        "schema": 1,
                        "profile_fingerprint": PROFILE_FINGERPRINT,
                        "autonomy_mode": "observe",
                        "emergency_stopped": True,
                        "revision": 3,
                    }
                )
            )
            values = {
                "controller_instance_id": self.instance_id,
                "recovery_generation": str(generation),
                "backup_sequence": str(sequence),
                "active_release_binding": active,
                "governance": governance,
            }
            connection.executemany(
                "INSERT INTO controller_state(state_key, state_value, updated_at) VALUES(?, ?, 1)",
                sorted(values.items()),
            )
            connection.execute(
                "CREATE TABLE evidence(evidence_id TEXT PRIMARY KEY, detail TEXT NOT NULL)"
            )
            connection.execute("INSERT INTO evidence VALUES('one', 'preserve')")
            connection.commit()
        finally:
            connection.close()
        if os.name == "posix":
            path.chmod(0o600)
        return path

    def bundle(self, *, generation: int = 1, sequence: int = 1) -> Path:
        bundle = self.root / f"backup-g{generation}-b{sequence}.sbbackup"
        bundle.mkdir()
        if os.name == "posix":
            bundle.chmod(0o700)
        database = self.database(
            bundle / "controller.db", generation=generation, sequence=sequence
        )
        manifest = build_backup_manifest(
            database,
            self.key,
            release_version="1.9.7",
            release_sha256=RELEASE_SHA256,
            profile_id="range-profile",
            profile_fingerprint=PROFILE_FINGERPRINT,
            backup_id=str(uuid.UUID(int=sequence)),
            created_at_ns=100 + sequence,
            **self.database_constraints,
        )
        write_backup_manifest(bundle / MANIFEST_FILENAME, manifest, self.key)
        return bundle


class SignedRecoveryDocumentTests(RecoveryFixture):
    def test_domain_separation_tamper_and_wrong_key_fail_authentication(self):
        payload = {"bounded": True, "counter": 1}
        record = sign_payload(payload, self.key, purpose="manifest")
        self.assertEqual(
            verify_signed_payload(record, self.key, purpose="manifest"), payload
        )
        with self.assertRaises(RecoveryAuthenticationError):
            verify_signed_payload(record, self.key, purpose="anchor")
        with self.assertRaises(RecoveryAuthenticationError):
            verify_signed_payload(record, b"x" * 32, purpose="manifest")
        altered = {
            **record,
            "signed": {**record["signed"], "counter": 2},
        }
        with self.assertRaises(RecoveryAuthenticationError):
            verify_signed_payload(altered, self.key, purpose="manifest")

    def test_malformed_signature_envelopes_are_authentication_failures(self):
        record = sign_payload({"bounded": True}, self.key, purpose="manifest")
        malformed = {
            **record,
            "signature": {**record["signature"], "value": "A" * 64},
        }
        with self.assertRaises(RecoveryAuthenticationError):
            verify_signed_payload(malformed, self.key, purpose="manifest")
        malformed = {
            **record,
            "signature": {**record["signature"], "extra": True},
        }
        with self.assertRaises(RecoveryAuthenticationError):
            verify_signed_payload(malformed, self.key, purpose="manifest")

    def test_private_key_loader_rejects_permissions_links_and_oversize(self):
        key_path = self.root / "recovery.key"
        key_path.write_bytes(self.key)
        if os.name == "posix":
            key_path.chmod(0o600)
        self.assertEqual(load_recovery_key(key_path), self.key)

        if os.name == "posix":
            key_path.chmod(0o640)
            with self.assertRaisesRegex(RecoveryPathError, "group or other"):
                load_recovery_key(key_path)
            key_path.chmod(0o600)

        oversized = self.root / "oversized.key"
        oversized.write_bytes(b"k" * 4097)
        if os.name == "posix":
            oversized.chmod(0o600)
        with self.assertRaisesRegex(RecoveryPathError, "size limit"):
            load_recovery_key(oversized)

        if hasattr(os, "symlink"):
            link = self.root / "key-link"
            link.symlink_to(key_path)
            with self.assertRaisesRegex(RecoveryPathError, "symbolic link"):
                load_recovery_key(link)

    @unittest.skipUnless(hasattr(os, "link"), "hard links unavailable")
    def test_private_key_loader_rejects_hard_links(self):
        key_path = self.root / "recovery.key"
        key_path.write_bytes(self.key)
        if os.name == "posix":
            key_path.chmod(0o600)
        os.link(key_path, self.root / "second-name.key")
        with self.assertRaisesRegex(RecoveryPathError, "hard links"):
            load_recovery_key(key_path)


class RecoveryAnchorTests(RecoveryFixture):
    @unittest.skipUnless(hasattr(os, "fork"), "requires POSIX process locks")
    def test_advisory_anchor_lock_is_released_by_process_death(self):
        anchor_path = self.root / "crash-anchor.json"
        process = os.fork()
        if process == 0:  # pragma: no cover - assertion runs in the parent
            try:
                with _anchor_transition_lock(anchor_path):
                    os._exit(0)
            except BaseException:
                os._exit(1)
        _pid, status = os.waitpid(process, 0)
        self.assertTrue(os.WIFEXITED(status))
        self.assertEqual(os.WEXITSTATUS(status), 0)
        self.assertTrue(
            (self.root / ".crash-anchor.json.transition.lock").is_file()
        )
        # os._exit bypassed the context manager's finally block.  Reacquiring
        # proves the kernel, not file deletion, owns lock lifetime.
        with _anchor_transition_lock(anchor_path):
            pass

    def test_pending_commit_lifecycle_and_crash_decisions(self):
        anchor_path = self.root / "anchor.json"
        committed = make_committed_anchor(
            self.instance_id,
            recovery_generation=3,
            backup_sequence_floor=7,
            updated_at_ns=10,
        )
        initialize_anchor(anchor_path, self.key, committed)
        self.assertEqual(load_anchor(anchor_path, self.key), committed)
        if os.name == "posix":
            self.assertEqual(anchor_path.stat().st_mode & 0o777, 0o600)

        pending = begin_pending_anchor(
            anchor_path,
            self.key,
            committed,
            "c" * 64,
            previous_database_sha256="d" * 64,
            pending_backup_sequence=8,
            updated_at_ns=11,
        )
        self.assertEqual(pending["phase"], "pending")
        self.assertEqual(pending["recovery_generation"], 4)
        old_live = decide_crash_state(
            pending,
            live_controller_instance_id=self.instance_id,
            live_recovery_generation=3,
            live_database_sha256="d" * 64,
            live_backup_sequence=7,
        )
        self.assertEqual(old_live.action, CrashAction.ABORT_PENDING)
        altered_old_live = decide_crash_state(
            pending,
            live_controller_instance_id=self.instance_id,
            live_recovery_generation=3,
            live_database_sha256="e" * 64,
            live_backup_sequence=7,
        )
        self.assertEqual(altered_old_live.action, CrashAction.BLOCK)
        wrong_staged = decide_crash_state(
            pending,
            live_controller_instance_id=self.instance_id,
            live_recovery_generation=4,
            live_database_sha256="d" * 64,
            live_backup_sequence=8,
        )
        self.assertEqual(wrong_staged.action, CrashAction.BLOCK)
        exact_staged = decide_crash_state(
            pending,
            live_controller_instance_id=self.instance_id,
            live_recovery_generation=4,
            live_database_sha256="c" * 64,
            live_backup_sequence=8,
        )
        self.assertEqual(exact_staged.action, CrashAction.COMMIT_PENDING)

        final = commit_pending_anchor(
            anchor_path,
            self.key,
            pending,
            live_controller_instance_id=self.instance_id,
            live_recovery_generation=4,
            live_database_sha256="c" * 64,
            live_backup_sequence=8,
            updated_at_ns=12,
        )
        self.assertEqual(final["phase"], "committed")
        self.assertEqual(final["backup_sequence_floor"], 8)
        self.assertEqual(
            decide_crash_state(
                final,
                live_controller_instance_id=self.instance_id,
                live_recovery_generation=4,
                live_database_sha256="e" * 64,
                live_backup_sequence=8,
            ).action,
            CrashAction.START,
        )

    def test_pending_anchor_can_abort_only_through_exact_transition(self):
        anchor_path = self.root / "anchor.json"
        committed = make_committed_anchor(self.instance_id, updated_at_ns=20)
        initialize_anchor(anchor_path, self.key, committed)
        pending = begin_pending_anchor(
            anchor_path,
            self.key,
            committed,
            "f" * 64,
            previous_database_sha256="0" * 64,
            pending_backup_sequence=1,
            updated_at_ns=21,
        )
        restored = abort_pending_anchor(
            anchor_path,
            self.key,
            pending,
            live_controller_instance_id=self.instance_id,
            live_recovery_generation=1,
            live_database_sha256="0" * 64,
            live_backup_sequence=0,
            updated_at_ns=22,
        )
        self.assertEqual(restored["phase"], "committed")
        self.assertEqual(restored["recovery_generation"], 1)
        with self.assertRaises(AnchorConflictError):
            begin_pending_anchor(
                anchor_path,
                self.key,
                committed,
                "0" * 64,
                previous_database_sha256="1" * 64,
                pending_backup_sequence=1,
                updated_at_ns=23,
            )

    def test_anchor_rejects_nonadvancing_timestamp_and_active_advisory_lock(self):
        anchor_path = self.root / "anchor.json"
        committed = make_committed_anchor(self.instance_id, updated_at_ns=30)
        initialize_anchor(anchor_path, self.key, committed)
        with self.assertRaisesRegex(RecoveryError, "timestamp"):
            begin_pending_anchor(
                anchor_path,
                self.key,
                committed,
                "1" * 64,
                previous_database_sha256="2" * 64,
                pending_backup_sequence=1,
                updated_at_ns=30,
            )
        lock = self.root / ".anchor.json.transition.lock"
        self.assertTrue(lock.is_file())
        with _anchor_transition_lock(anchor_path):
            with self.assertRaisesRegex(AnchorConflictError, "transition"):
                begin_pending_anchor(
                    anchor_path,
                    self.key,
                    committed,
                    "1" * 64,
                    previous_database_sha256="2" * 64,
                    pending_backup_sequence=1,
                    updated_at_ns=31,
                )
        # The persistent lock inode remains after release but does not become a
        # stale lock after a process exits.
        self.assertTrue(lock.is_file())
        pending = begin_pending_anchor(
            anchor_path,
            self.key,
            committed,
            "1" * 64,
            previous_database_sha256="2" * 64,
            pending_backup_sequence=1,
            updated_at_ns=31,
        )
        self.assertEqual(pending["phase"], "pending")

    def test_crash_decision_blocks_wrong_instance_and_generation(self):
        committed = make_committed_anchor(self.instance_id, updated_at_ns=40)
        self.assertEqual(
            decide_crash_state(
                committed,
                live_controller_instance_id=str(uuid.uuid4()),
                live_recovery_generation=1,
                live_database_sha256="2" * 64,
                live_backup_sequence=0,
            ).action,
            CrashAction.BLOCK,
        )

        invalid = {**committed, "recovery_generation": True}
        self.assertEqual(
            decide_crash_state(
                invalid,
                live_controller_instance_id=self.instance_id,
                live_recovery_generation=1,
                live_database_sha256="2" * 64,
                live_backup_sequence=0,
            ).action,
            CrashAction.BLOCK,
        )

    def test_commit_and_abort_require_the_exact_crash_decision(self):
        anchor_path = self.root / "anchor.json"
        committed = make_committed_anchor(self.instance_id, updated_at_ns=70)
        initialize_anchor(anchor_path, self.key, committed)
        pending = begin_pending_anchor(
            anchor_path,
            self.key,
            committed,
            "3" * 64,
            previous_database_sha256="5" * 64,
            pending_backup_sequence=1,
            updated_at_ns=71,
        )
        with self.assertRaisesRegex(AnchorConflictError, "cannot commit"):
            commit_pending_anchor(
                anchor_path,
                self.key,
                pending,
                live_controller_instance_id=self.instance_id,
                live_recovery_generation=2,
                live_database_sha256="4" * 64,
                live_backup_sequence=1,
                updated_at_ns=72,
            )
        self.assertEqual(load_anchor(anchor_path, self.key), pending)
        with self.assertRaisesRegex(AnchorConflictError, "cannot abort"):
            abort_pending_anchor(
                anchor_path,
                self.key,
                pending,
                live_controller_instance_id=self.instance_id,
                live_recovery_generation=2,
                live_database_sha256="3" * 64,
                live_backup_sequence=1,
                updated_at_ns=72,
            )
        self.assertEqual(load_anchor(anchor_path, self.key), pending)
        self.assertEqual(
            decide_crash_state(
                committed,
                live_controller_instance_id=self.instance_id,
                live_recovery_generation=2,
                live_database_sha256="2" * 64,
                live_backup_sequence=1,
            ).action,
            CrashAction.BLOCK,
        )

    def test_committed_anchor_enforces_sequence_floor(self):
        committed = make_committed_anchor(
            self.instance_id,
            backup_sequence_floor=12,
            updated_at_ns=80,
        )
        for sequence in (12, 13):
            self.assertEqual(
                decide_crash_state(
                    committed,
                    live_controller_instance_id=self.instance_id,
                    live_recovery_generation=1,
                    live_database_sha256="a" * 64,
                    live_backup_sequence=sequence,
                ).action,
                CrashAction.START,
            )
        below = decide_crash_state(
            committed,
            live_controller_instance_id=self.instance_id,
            live_recovery_generation=1,
            live_database_sha256="a" * 64,
            live_backup_sequence=11,
        )
        self.assertEqual(below.action, CrashAction.BLOCK)
        self.assertIn("below the protected floor", below.reason)
        missing = decide_crash_state(
            committed,
            live_controller_instance_id=self.instance_id,
            live_recovery_generation=1,
            live_database_sha256="a" * 64,
        )
        self.assertEqual(missing.action, CrashAction.BLOCK)
        self.assertIn("sequence is required", missing.reason)

    def test_legacy_committed_anchor_blocks_until_explicit_sequence_upgrade(self):
        anchor_path = self.root / "legacy-anchor.json"
        legacy = {
            "format": ANCHOR_FORMAT,
            "schema": 1,
            "controller_instance_id": self.instance_id,
            "recovery_generation": 3,
            "previous_recovery_generation": 3,
            "phase": "committed",
            "previous_database_sha256": "",
            "pending_database_sha256": "",
            "updated_at_ns": 90,
        }
        self.assertEqual(validate_anchor(legacy), legacy)
        blocked = decide_crash_state(
            legacy,
            live_controller_instance_id=self.instance_id,
            live_recovery_generation=3,
            live_database_sha256="b" * 64,
            live_backup_sequence=9,
        )
        self.assertEqual(blocked.action, CrashAction.BLOCK)
        self.assertIn("explicit upgrade", blocked.reason)
        with self.assertRaisesRegex(RecoveryError, "explicit offline upgrade"):
            initialize_anchor(anchor_path, self.key, legacy)

        anchor_path.write_bytes(
            canonical_json_bytes(sign_payload(legacy, self.key, purpose="anchor"))
        )
        if os.name == "posix":
            anchor_path.chmod(0o600)
        upgraded = upgrade_legacy_anchor(
            anchor_path,
            self.key,
            legacy,
            live_controller_instance_id=self.instance_id,
            live_recovery_generation=3,
            live_backup_sequence=9,
            updated_at_ns=91,
        )
        self.assertEqual(upgraded["schema"], 2)
        self.assertEqual(upgraded["backup_sequence_floor"], 9)
        self.assertEqual(load_anchor(anchor_path, self.key), upgraded)
        self.assertEqual(
            decide_crash_state(
                upgraded,
                live_controller_instance_id=self.instance_id,
                live_recovery_generation=3,
                live_database_sha256="b" * 64,
                live_backup_sequence=9,
            ).action,
            CrashAction.START,
        )

    def test_legacy_pending_anchor_keeps_exact_crash_resolution_but_cannot_upgrade(self):
        legacy = {
            "format": ANCHOR_FORMAT,
            "schema": 1,
            "controller_instance_id": self.instance_id,
            "recovery_generation": 2,
            "previous_recovery_generation": 1,
            "phase": "pending",
            "previous_database_sha256": "c" * 64,
            "pending_database_sha256": "d" * 64,
            "updated_at_ns": 100,
        }
        self.assertEqual(
            decide_crash_state(
                legacy,
                live_controller_instance_id=self.instance_id,
                live_recovery_generation=1,
                live_database_sha256="c" * 64,
            ).action,
            CrashAction.ABORT_PENDING,
        )
        with self.assertRaisesRegex(RecoveryError, "must be resolved"):
            upgrade_legacy_anchor(
                self.root / "unused.json",
                self.key,
                legacy,
                live_controller_instance_id=self.instance_id,
                live_recovery_generation=1,
                live_backup_sequence=4,
            )


class BackupBundleTests(RecoveryFixture):
    def test_complete_bundle_verifies_without_mutating_database(self):
        bundle = self.bundle()
        database = bundle / "controller.db"
        before = (
            hashlib.sha256(database.read_bytes()).hexdigest(),
            database.stat().st_mtime_ns,
        )
        verified = verify_backup_bundle(
            bundle,
            self.key,
            expected_controller_instance_id=self.instance_id,
            expected_release_sha256=RELEASE_SHA256,
            expected_profile_fingerprint=PROFILE_FINGERPRINT,
            **self.database_constraints,
        )
        anchor_path = self.root / "anchor.json"
        anchor = make_committed_anchor(self.instance_id, updated_at_ns=50)
        initialize_anchor(anchor_path, self.key, anchor)
        anchored = advance_backup_anchor(
            anchor_path,
            self.key,
            anchor,
            verified,
            updated_at_ns=51,
        )
        verified = verify_backup_bundle(
            bundle,
            self.key,
            anchor=anchored,
            expected_controller_instance_id=self.instance_id,
            expected_release_sha256=RELEASE_SHA256,
            expected_profile_fingerprint=PROFILE_FINGERPRINT,
            **self.database_constraints,
        )
        after = (
            hashlib.sha256(database.read_bytes()).hexdigest(),
            database.stat().st_mtime_ns,
        )
        self.assertEqual(before, after)
        self.assertTrue(verified.requires_reconciliation)
        self.assertEqual(verified.anchor_binding, "latest")
        self.assertEqual(verified.inspection.application_id, APPLICATION_ID)
        self.assertEqual(verified.inspection.user_version, USER_VERSION)
        self.assertEqual(
            set(verified.inspection.state_hashes),
            {"active_release_binding_sha256", "governance_sha256"},
        )

    def test_latest_backup_binding_rejects_same_sequence_substitution(self):
        bundle = self.bundle()
        verified = verify_backup_bundle(
            bundle, self.key, **self.database_constraints
        )
        anchor_path = self.root / "binding-anchor.json"
        committed = make_committed_anchor(self.instance_id, updated_at_ns=110)
        initialize_anchor(anchor_path, self.key, committed)
        anchored = advance_backup_anchor(
            anchor_path,
            self.key,
            committed,
            verified,
            updated_at_ns=111,
        )
        with self.assertRaisesRegex(AnchorConflictError, "does not advance"):
            advance_backup_anchor(
                anchor_path,
                self.key,
                anchored,
                verified,
                updated_at_ns=112,
            )

        manifest_path = bundle / MANIFEST_FILENAME
        manifest = load_backup_manifest(manifest_path, self.key)
        substituted = {
            **manifest,
            "backup_id": str(uuid.UUID(int=1234)),
        }
        manifest_path.unlink()
        manifest_path.write_bytes(
            canonical_json_bytes(
                sign_payload(substituted, self.key, purpose="manifest")
            )
        )
        if os.name == "posix":
            manifest_path.chmod(0o600)
        with self.assertRaisesRegex(
            RecoveryAuthenticationError, "latest-backup binding"
        ):
            verify_backup_bundle(
                bundle,
                self.key,
                anchor=anchored,
                **self.database_constraints,
            )

    def test_unanchored_same_generation_future_sequence_is_rejected(self):
        bundle = self.bundle(sequence=3)
        anchor = make_committed_anchor(
            self.instance_id,
            backup_sequence_floor=2,
            updated_at_ns=120,
        )
        with self.assertRaisesRegex(
            RecoveryAuthenticationError, "sequence is newer"
        ):
            verify_backup_bundle(
                bundle,
                self.key,
                anchor=anchor,
                **self.database_constraints,
            )

    def test_verification_uses_external_pragmas_and_table_constraints(self):
        bundle = self.bundle()
        database = bundle / "controller.db"
        manifest_path = bundle / MANIFEST_FILENAME
        manifest_path.unlink()
        connection = sqlite3.connect(database)
        connection.execute(f"PRAGMA application_id={APPLICATION_ID + 1}")
        connection.execute("CREATE TABLE untrusted_authority(value TEXT)")
        connection.commit()
        connection.close()
        if os.name == "posix":
            database.chmod(0o600)
        record = build_backup_manifest(
            database,
            self.key,
            release_version="1.9.7",
            release_sha256=RELEASE_SHA256,
            profile_id="range-profile",
            profile_fingerprint=PROFILE_FINGERPRINT,
            expected_application_id=APPLICATION_ID + 1,
            expected_user_version=USER_VERSION,
            required_tables={"controller_state", "evidence"},
            allowed_tables={
                "controller_state",
                "evidence",
                "untrusted_authority",
            },
        )
        write_backup_manifest(manifest_path, record, self.key)
        with self.assertRaisesRegex(
            RecoverySemanticError, "trusted constraint"
        ):
            verify_backup_bundle(
                bundle, self.key, **self.database_constraints
            )

        constraints = {
            **self.database_constraints,
            "expected_application_id": APPLICATION_ID + 1,
        }
        with self.assertRaisesRegex(RecoverySemanticError, "unexpected tables"):
            verify_backup_bundle(bundle, self.key, **constraints)

    def test_backup_operations_require_nonempty_explicit_constraints(self):
        bundle = self.bundle()
        with self.assertRaises(TypeError):
            verify_backup_bundle(bundle, self.key)
        with self.assertRaisesRegex(ValueError, "non-empty"):
            verify_backup_bundle(
                bundle,
                self.key,
                expected_application_id=APPLICATION_ID,
                expected_user_version=USER_VERSION,
                required_tables=frozenset(),
                allowed_tables=frozenset(),
            )

    def test_older_generation_is_recovery_input_but_future_is_rejected(self):
        old_bundle = self.bundle(generation=1, sequence=1)
        current_anchor = make_committed_anchor(
            self.instance_id,
            recovery_generation=2,
            backup_sequence_floor=2,
            updated_at_ns=60,
        )
        self.assertTrue(
            verify_backup_bundle(
                old_bundle,
                self.key,
                anchor=current_anchor,
                **self.database_constraints,
            ).requires_reconciliation
        )

        future_bundle = self.bundle(generation=2, sequence=2)
        stale_anchor = make_committed_anchor(
            self.instance_id,
            recovery_generation=1,
            backup_sequence_floor=1,
            updated_at_ns=61,
        )
        with self.assertRaisesRegex(RecoveryAuthenticationError, "newer"):
            verify_backup_bundle(
                future_bundle,
                self.key,
                anchor=stale_anchor,
                **self.database_constraints,
            )

    def test_database_manifest_and_key_tampering_are_rejected(self):
        bundle = self.bundle()
        database = bundle / "controller.db"
        with database.open("ab") as handle:
            handle.write(b"tamper")
        with self.assertRaises(RecoveryAuthenticationError):
            verify_backup_bundle(bundle, self.key, **self.database_constraints)

        bundle = self.bundle(sequence=2)
        manifest_path = bundle / MANIFEST_FILENAME
        manifest = load_backup_manifest(manifest_path, self.key)
        altered = sign_payload(
            {**manifest, "created_at_ns": manifest["created_at_ns"] + 1},
            b"z" * 32,
            purpose="manifest",
        )
        manifest_path.write_bytes(canonical_json_bytes(altered))
        if os.name == "posix":
            manifest_path.chmod(0o600)
        with self.assertRaises(RecoveryAuthenticationError):
            verify_backup_bundle(bundle, self.key, **self.database_constraints)

        with self.assertRaises(RecoveryAuthenticationError):
            verify_backup_bundle(
                self.bundle(sequence=3),
                b"y" * 32,
                **self.database_constraints,
            )

    def test_manifest_strict_json_and_exact_schema_are_enforced(self):
        bundle = self.bundle()
        manifest_path = bundle / MANIFEST_FILENAME
        manifest_path.write_bytes(
            b'{"signed":{},"signed":{},"signature":{}}'
        )
        if os.name == "posix":
            manifest_path.chmod(0o600)
        with self.assertRaisesRegex(RecoveryError, "strict JSON"):
            load_backup_manifest(manifest_path, self.key)

        record = build_backup_manifest(
            self.bundle(sequence=2) / "controller.db",
            self.key,
            release_version="1.9.7",
            release_sha256=RELEASE_SHA256,
            profile_id="range-profile",
            profile_fingerprint=PROFILE_FINGERPRINT,
            **self.database_constraints,
        )
        payload = dict(record["signed"])
        payload["unknown"] = True
        with self.assertRaises(RecoveryError):
            validate_manifest(payload)
        payload = dict(record["signed"])
        payload["created_at_ns"] = True
        with self.assertRaises(RecoveryError):
            validate_manifest(payload)
        payload = dict(record["signed"])
        payload["schema"] = True
        with self.assertRaises(RecoveryError):
            validate_manifest(payload)

    def test_manifest_is_create_only_and_release_state_is_exactly_bound(self):
        bundle = self.bundle()
        manifest_path = bundle / MANIFEST_FILENAME
        record = sign_payload(
            load_backup_manifest(manifest_path, self.key),
            self.key,
            purpose="manifest",
        )
        with self.assertRaisesRegex(RecoveryPathError, "already exists"):
            write_backup_manifest(manifest_path, record, self.key)

        database = self.database(self.root / "release-mismatch.db")
        with self.assertRaisesRegex(RecoverySemanticError, "release metadata"):
            build_backup_manifest(
                database,
                self.key,
                release_version="1.9.7",
                release_sha256="c" * 64,
                profile_id="range-profile",
                profile_fingerprint=PROFILE_FINGERPRINT,
                **self.database_constraints,
            )

        manifest = load_backup_manifest(manifest_path, self.key)
        altered = {
            **manifest,
            "release": {**manifest["release"], "sha256": "c" * 64},
        }
        manifest_path.unlink()
        manifest_path.write_bytes(
            canonical_json_bytes(sign_payload(altered, self.key, purpose="manifest"))
        )
        if os.name == "posix":
            manifest_path.chmod(0o600)
        with self.assertRaisesRegex(RecoverySemanticError, "release metadata"):
            verify_backup_bundle(bundle, self.key, **self.database_constraints)

    def test_verified_database_staging_uses_one_hash_bound_descriptor(self):
        bundle = self.bundle()
        verified = verify_backup_bundle(
            bundle, self.key, **self.database_constraints
        )
        expected = (bundle / "controller.db").read_bytes()
        with open_verified_database(verified) as descriptor:
            self.assertEqual(os.read(descriptor, len(expected) + 1), expected)

        replacement = self.database(
            self.root / "replacement.db", generation=1, sequence=9
        )
        os.replace(replacement, bundle / "controller.db")
        with self.assertRaisesRegex(
            RecoveryAuthenticationError, "changed before staging"
        ):
            with open_verified_database(verified):
                pass

    def test_bundle_rejects_extra_entries_links_and_public_files(self):
        bundle = self.bundle()
        extra = bundle / "controller.db-wal"
        extra.write_bytes(b"not allowed")
        if os.name == "posix":
            extra.chmod(0o600)
        with self.assertRaisesRegex(RecoveryPathError, "exactly"):
            verify_backup_bundle(bundle, self.key, **self.database_constraints)

        if hasattr(os, "symlink"):
            bundle = self.bundle(sequence=2)
            outside = self.root / "outside.db"
            outside.write_bytes((bundle / "controller.db").read_bytes())
            if os.name == "posix":
                outside.chmod(0o600)
            (bundle / "controller.db").unlink()
            (bundle / "controller.db").symlink_to(outside)
            with self.assertRaisesRegex(RecoveryPathError, "non-regular"):
                verify_backup_bundle(
                    bundle, self.key, **self.database_constraints
                )

        if os.name == "posix":
            bundle = self.bundle(sequence=3)
            (bundle / "controller.db").chmod(0o644)
            with self.assertRaisesRegex(RecoveryPathError, "group or other"):
                verify_backup_bundle(
                    bundle, self.key, **self.database_constraints
                )


class DatabaseSemanticInspectionTests(RecoveryFixture):
    def test_forbidden_schema_objects_and_foreign_key_failures_are_rejected(self):
        view_db = self.root / "view.db"
        connection = sqlite3.connect(view_db)
        connection.execute("CREATE TABLE item(id INTEGER PRIMARY KEY)")
        connection.execute("CREATE VIEW item_view AS SELECT id FROM item")
        connection.commit()
        connection.close()
        if os.name == "posix":
            view_db.chmod(0o600)
        with self.assertRaisesRegex(RecoverySemanticError, "forbidden schema"):
            inspect_controller_database(view_db)

        foreign_db = self.root / "foreign.db"
        connection = sqlite3.connect(foreign_db)
        connection.execute("CREATE TABLE parent(id INTEGER PRIMARY KEY)")
        connection.execute(
            "CREATE TABLE child(id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parent(id))"
        )
        connection.execute("INSERT INTO child VALUES(1, 999)")
        connection.commit()
        connection.close()
        if os.name == "posix":
            foreign_db.chmod(0o600)
        with self.assertRaisesRegex(RecoverySemanticError, "foreign_key"):
            inspect_controller_database(foreign_db)

    def test_invalid_bound_state_and_noncanonical_recovery_state_fail_closed(self):
        invalid = self.database(
            self.root / "invalid-state.db", invalid_governance=True
        )
        with self.assertRaisesRegex(RecoverySemanticError, "governance"):
            inspect_controller_database(
                invalid, require_recovery_state=True, require_state_hashes=True
            )

        noncanonical = self.database(self.root / "noncanonical.db")
        connection = sqlite3.connect(noncanonical)
        connection.execute(
            "UPDATE controller_state SET state_value='01' WHERE state_key='recovery_generation'"
        )
        connection.commit()
        connection.close()
        if os.name == "posix":
            noncanonical.chmod(0o600)
        with self.assertRaisesRegex(RecoverySemanticError, "canonical integer"):
            inspect_controller_database(noncanonical, require_recovery_state=True)

    def test_duplicate_or_non_text_recovery_state_fails_closed(self):
        duplicate = self.database(self.root / "duplicate-state.db")
        connection = sqlite3.connect(duplicate)
        connection.execute("ALTER TABLE controller_state RENAME TO old_state")
        connection.execute(
            "CREATE TABLE controller_state(state_key, state_value, updated_at)"
        )
        connection.execute(
            "INSERT INTO controller_state SELECT state_key, state_value, updated_at FROM old_state"
        )
        connection.execute(
            "INSERT INTO controller_state SELECT state_key, state_value, updated_at "
            "FROM old_state WHERE state_key='governance'"
        )
        connection.execute("DROP TABLE old_state")
        connection.commit()
        connection.close()
        if os.name == "posix":
            duplicate.chmod(0o600)
        with self.assertRaisesRegex(RecoverySemanticError, "duplicate recovery state"):
            inspect_controller_database(
                duplicate, require_recovery_state=True, require_state_hashes=True
            )

        binary = self.database(self.root / "binary-state.db")
        connection = sqlite3.connect(binary)
        connection.execute(
            "UPDATE controller_state SET state_value=? WHERE state_key='governance'",
            (sqlite3.Binary(b"{}"),),
        )
        connection.commit()
        connection.close()
        if os.name == "posix":
            binary.chmod(0o600)
        with self.assertRaisesRegex(RecoverySemanticError, "exact text"):
            inspect_controller_database(
                binary, require_recovery_state=True, require_state_hashes=True
            )

    def test_database_path_replacement_during_inspection_is_rejected(self):
        database = self.database(self.root / "race.db")
        replacement = self.database(
            self.root / "race-replacement.db", generation=1, sequence=2
        )
        displaced = self.root / "race-displaced.db"
        original_connect = sqlite3.connect
        swapped = False

        def replace_then_connect(*args, **kwargs):
            nonlocal swapped
            if not swapped:
                swapped = True
                os.replace(database, displaced)
                os.replace(replacement, database)
            return original_connect(*args, **kwargs)

        with mock.patch(
            "sentinel_blue.recovery.sqlite3.connect",
            side_effect=replace_then_connect,
        ):
            with self.assertRaisesRegex(RecoveryPathError, "changed during"):
                inspect_controller_database(database, require_recovery_state=True)

    def test_application_schema_and_table_expectations_are_exact(self):
        database = self.database(self.root / "expected.db")
        with self.assertRaisesRegex(RecoverySemanticError, "application_id"):
            inspect_controller_database(
                database, expected_application_id=APPLICATION_ID + 1
            )
        with self.assertRaisesRegex(RecoverySemanticError, "user_version"):
            inspect_controller_database(database, expected_user_version=USER_VERSION + 1)
        with self.assertRaisesRegex(RecoverySemanticError, "missing required"):
            inspect_controller_database(database, required_tables={"missing"})
        with self.assertRaisesRegex(RecoverySemanticError, "unexpected tables"):
            inspect_controller_database(database, allowed_tables={"controller_state"})


if __name__ == "__main__":
    unittest.main()
