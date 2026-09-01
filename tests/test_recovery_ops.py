from __future__ import annotations

import os
from pathlib import Path
import shutil
import tempfile
import unittest

from sentinel_blue.__main__ import parser
from sentinel_blue.recovery_ops import (
    controller_recovery_status,
    create_controller_backup,
    initialize_controller_recovery,
    verify_controller_backup,
)
from sentinel_blue.store import Store


class RecoveryOperationsTests(unittest.TestCase):
    def test_fresh_recovery_init_does_not_apply_a_legacy_enrollment_fence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            database = root / "controller.db"
            anchor = root / "recovery.anchor"
            key = b"r" * 48
            initialize_controller_recovery(database, anchor, key)
            store = Store(database)
            try:
                state = store._http_request_replay_state_locked()
                self.assertEqual(state["migration_floor"], 0.0)
                deadline = store.initialize_enrollment_deadline(1.0, 0.0)
                self.assertGreater(deadline, 0.0)
            finally:
                store.close()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        if os.name == "posix":
            self.root.chmod(0o700)
        self.database = self.root / "controller.db"
        self.anchor = self.root / "controller.anchor"
        self.backups = self.root / "backups"
        self.backups.mkdir(mode=0o700)
        if os.name == "posix":
            self.backups.chmod(0o700)
        self.key = bytes(range(32))

    def tearDown(self):
        self.temporary.cleanup()

    def initialize(self) -> dict:
        return initialize_controller_recovery(
            self.database, self.anchor, self.key
        )

    def bind_release(self, store: Store) -> None:
        store.activate_release_binding(
            profile_id="range-profile",
            profile_fingerprint="b" * 64,
            agent_version="1.9.9",
            release_sha256="a" * 64,
            strict=True,
        )
        store.load_governance(
            profile_fingerprint="b" * 64,
            default_mode="observe",
            strict=False,
            allowed_modes={"observe"},
        )

    def test_authenticated_backup_advances_anchor_and_verifies_latest(self):
        initialized = self.initialize()
        self.assertTrue(initialized["ready"])
        store = Store(self.database)
        try:
            self.bind_release(store)
            created = create_controller_backup(
                store, self.backups, self.anchor, self.key
            )
        finally:
            store.close()
        self.assertEqual(created["backup_sequence"], 1)
        self.assertEqual(created["protected_sequence_floor"], 1)
        verified = verify_controller_backup(
            created["bundle"], self.anchor, self.key
        )
        self.assertTrue(verified["verified"])
        self.assertEqual(verified["anchor_binding"], "latest")
        status = controller_recovery_status(
            self.database, self.anchor, self.key
        )
        self.assertTrue(status["ready"])
        self.assertEqual(status["protected_sequence_floor"], 1)

    def test_same_generation_database_rollback_below_anchor_floor_is_blocked(self):
        self.initialize()
        before_backup = self.root / "before-backup.db"
        shutil.copy2(self.database, before_backup)
        if os.name == "posix":
            before_backup.chmod(0o600)
        store = Store(self.database)
        try:
            self.bind_release(store)
            create_controller_backup(store, self.backups, self.anchor, self.key)
        finally:
            store.close()
        shutil.copy2(before_backup, self.database)
        if os.name == "posix":
            self.database.chmod(0o600)
        status = controller_recovery_status(
            self.database, self.anchor, self.key
        )
        self.assertFalse(status["ready"])
        self.assertEqual(status["action"], "block")
        self.assertIn("below the protected floor", status["reason"])

    def test_public_cli_has_no_live_restore_command(self):
        choices = parser()._subparsers._group_actions[0].choices
        self.assertIn("recovery-init", choices)
        self.assertIn("recovery-status", choices)
        self.assertIn("recovery-backup", choices)
        self.assertIn("recovery-verify", choices)
        self.assertNotIn("recovery-restore", choices)
        self.assertNotIn("restore", choices)


if __name__ == "__main__":
    unittest.main()
