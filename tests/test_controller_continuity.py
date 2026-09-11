"""Committed authority may survive a crash; interrupted authority never may."""
import copy
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from sentinel_blue import __version__
from sentinel_blue.auth import derive_enrollment_ticket
from sentinel_blue.controller import ControllerApp
from sentinel_blue.event_profile import EventProfile
from sentinel_blue.recovery_ops import initialize_controller_recovery
from sentinel_blue.store import Store


class ControllerContinuityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.database = self.root / "controller.db"
        self.anchor = self.root / "recovery.anchor"
        self.key = b"r" * 48
        initialize_controller_recovery(self.database, self.anchor, self.key)
        self.store = Store(self.database)
        raw = copy.deepcopy(EventProfile.testing().raw)
        raw["recovery"]["resume_after_controller_crash"] = True
        raw["release"]["sha256"] = "a" * 64
        raw["official_identities"] = [{"agent_id": "agent-one", "name": "root", "class": "blue-admin"}]
        self.profile = EventProfile.from_dict(raw)

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def app(self, *, crash=False, authenticated=True, profile=None):
        app = ControllerApp(
            self.store, "t" * 64, operator_token="o" * 64,
            operator_credential_epoch=2,
            event_profile=profile or self.profile,
            recovery_key=self.key if authenticated else None,
            recovery_anchor=self.anchor if authenticated else None,
            require_authenticated_recovery=authenticated,
            unclean_shutdown=crash,
        )
        if not crash:
            app.set_autonomy_mode((profile or self.profile).autonomy_mode)
            app.resume_changes()
        return app

    def restart(self):
        self.store.close()
        self.store = Store(self.database)

    def test_committed_authority_and_revision_survive_unclean_restart(self):
        original = self.app()
        session, dirty = self.store.begin_controller_session()
        self.assertFalse(dirty)
        expected = original.governance_status()
        self.restart()  # Do not clear the session marker.
        _, dirty = self.store.begin_controller_session()
        self.assertTrue(dirty)
        recovered = self.app(crash=dirty)
        self.assertEqual(recovered.autonomy_mode, expected["autonomy_mode"])
        self.assertFalse(recovered.emergency_stopped)
        self.assertEqual(recovered._governance_revision, expected["governance_revision"])
        self.assertGreater(recovered._recovery_fresh_after, 0)

    def test_emergency_stop_is_never_cleared_by_crash_resume(self):
        original = self.app()
        original.emergency_stop()
        revision = original._governance_revision
        self.restart()
        recovered = self.app(crash=True)
        self.assertTrue(recovered.emergency_stopped)
        self.assertEqual(recovered._governance_revision, revision)

    def test_resume_is_opt_in_and_requires_authenticated_recovery(self):
        self.app()
        recovered = self.app(crash=True, authenticated=False)
        self.assertTrue(recovered.emergency_stopped)
        raw = copy.deepcopy(self.profile.raw)
        raw["recovery"].pop("resume_after_controller_crash")
        legacy = EventProfile.from_dict(raw)
        recovered = self.app(crash=True, profile=legacy)
        self.assertEqual(recovered.autonomy_mode, "observe")
        self.assertTrue(recovered.emergency_stopped)

    def test_profile_change_cannot_inherit_resume_authority(self):
        self.app()
        raw = copy.deepcopy(self.profile.raw)
        raw["profile_id"] += "-changed"
        recovered = self.app(crash=True, profile=EventProfile.from_dict(raw))
        self.assertTrue(recovered.emergency_stopped)

    def test_corrupt_governance_starts_stopped_even_with_resume_enabled(self):
        self.app()
        self.store._connection.execute(
            "UPDATE controller_state SET state_value='{}' WHERE state_key='governance'"
        )
        self.store._connection.commit()
        recovered = self.app(crash=True)
        self.assertTrue(recovered.emergency_stopped)

    def test_failed_governance_commit_retains_intent_across_restart(self):
        original = self.app()
        # Abort the authoritative UPDATE after its separate intent COMMIT.
        self.store._connection.execute(
            """CREATE TEMP TRIGGER fail_governance BEFORE UPDATE ON controller_state
               WHEN NEW.state_key='governance'
               BEGIN SELECT RAISE(ABORT, 'injected commit failure'); END"""
        )
        with self.assertRaises(sqlite3.DatabaseError):
            self.store.update_governance(
                profile_fingerprint=self.profile.fingerprint, mode="range-autonomous",
                emergency_stopped=True, expected_revision=original._governance_revision,
            )
        self.restart()
        recovered = self.app(crash=True)
        self.assertTrue(recovered.emergency_stopped)
        self.assertEqual(recovered.autonomy_mode, "observe")
        self.assertIsNone(self.store._connection.execute(
            "SELECT 1 FROM controller_state WHERE state_key='governance_transition_intent'"
        ).fetchone())

    def test_crash_resume_holds_dispatch_until_complete_post_start_sample(self):
        original = self.app()
        sample = {"agent_id": "agent-one", "hostname": "host", "platform": "Linux",
                  "observed_at": time.time() - 1, "boot_id": "boot-one", "sequence": 1,
                  "profile_id": self.profile.profile_id, "profile_fingerprint": self.profile.fingerprint,
                  "agent_version": __version__, "queued_at": time.time()}
        token = original.enroll(
            {**sample, "enrollment_nonce": "b" * 64},
            authenticated_ticket=derive_enrollment_ticket("t" * 64, self.profile.fingerprint, "agent-one"),
        )["agent_token"]
        original.ingest(sample, "agent-one", token)
        action_id = original._queue_action("agent-one", "snapshot", {})
        recovered = self.app(crash=True)
        self.assertEqual(recovered.pending_actions_for_agent("agent-one"), [])
        self.assertIsNone(recovered._queue_action("agent-one", "snapshot", {}, automated=True))
        rollback = recovered._queue_action(
            "agent-one", "rollback_service", {"service": "owned.service", "desired_state": "stopped"},
        )
        self.assertEqual([row.action_id for row in recovered.pending_actions_for_agent("agent-one")], [rollback])
        sample.update(sequence=2, observed_at=time.time(), collector_errors=["incomplete"])
        recovered.ingest(sample, "agent-one", token)
        self.assertEqual(recovered.pending_actions_for_agent("agent-one"), [])
        sample.update(sequence=3, observed_at=time.time(), collector_errors=[])
        recovered.ingest(sample, "agent-one", token)
        self.assertEqual([row.action_id for row in recovered.pending_actions_for_agent("agent-one")], [action_id])

    def test_explicit_force_safe_clears_interrupted_intent_atomically(self):
        self.app()
        self.store._connection.execute(
            "INSERT INTO controller_state VALUES('governance_transition_intent', '{}', ?)"
            , (time.time(),)
        )
        self.store._connection.commit()
        self.store.force_safe_governance(self.profile.fingerprint)
        self.restart()
        recovered = self.app(crash=True)
        self.assertTrue(recovered.emergency_stopped)
        recovered.resume_changes()  # No obsolete intent blocks explicit recovery.
        self.assertFalse(recovered.emergency_stopped)

    def test_profile_rejects_implicit_truthy_resume_configuration(self):
        for invalid in ("true", 1, None):
            with self.subTest(invalid=invalid):
                raw = copy.deepcopy(self.profile.raw)
                raw["recovery"]["resume_after_controller_crash"] = invalid
                with self.assertRaisesRegex(ValueError, "must be a boolean"):
                    EventProfile.from_dict(raw)

    def test_forced_stop_cannot_be_overridden_by_crash_resume_policy(self):
        original = self.app()
        state = self.store.load_governance(
            profile_fingerprint=self.profile.fingerprint, default_mode=original.autonomy_mode,
            strict=True, force_safe=True, unclean_shutdown=True, resume_after_crash=True,
        )
        self.assertTrue(state["emergency_stopped"])
        self.assertEqual(state["autonomy_mode"], "observe")

    def test_transient_write_failure_does_not_leave_in_memory_revision_stuck(self):
        original = self.app()
        with patch.object(self.store, "update_governance", side_effect=OSError("transient failure")):
            with self.assertRaises(OSError):
                original.emergency_stop()
        self.assertTrue(original.emergency_stopped)
        original.resume_changes()
        self.assertFalse(original.emergency_stopped)
        self.assertEqual(original.autonomy_mode, "observe")
