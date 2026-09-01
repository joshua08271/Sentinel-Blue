import hashlib
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from sentinel_blue.store import HTTP_REQUEST_REPLAY_STATE_KEY, Store


def marker(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


class PersistentHttpReplayTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.database = Path(self.directory.name) / "replay.db"
        self.store = Store(self.database)
        self.store.initialize_http_request_replay(300.0, now=1_000.0)
        self.store.register_agent("agent-a", "host-a", "Linux")
        self.secret = self.store.ensure_agent_secret("agent-a")

    def tearDown(self):
        self.store.close()
        self.directory.cleanup()

    def admit(
        self,
        signature: str,
        timestamp: float,
        *,
        now: float | None = None,
        agent_id: str = "agent-a",
        secret: str | None = None,
        epoch: int = 0,
        auth_kind: str = "agent",
        max_entries: int = 8,
        max_principals: int = 4,
    ) -> str:
        return self.store.admit_http_request(
            agent_id,
            signature,
            str(timestamp),
            auth_kind=auth_kind,
            expected_credential_epoch=epoch,
            expected_agent_secret=(self.secret if secret is None else secret),
            max_entries=max_entries,
            max_principals=max_principals,
            max_clock_skew=300.0,
            now=timestamp if now is None else now,
        )

    def test_marker_survives_restart_and_fresh_signature_still_works(self):
        request_signature = marker("first")
        self.assertEqual(self.admit(request_signature, 1_000.0), "accepted")
        self.store.close()
        self.store = Store(self.database)
        self.store.initialize_http_request_replay(300.0, now=1_001.0)
        snapshot = self.store.agent_http_auth_snapshot("agent-a")
        self.assertIsNotNone(snapshot)
        self.secret = str(snapshot["agent_secret"])
        self.assertEqual(
            self.admit(request_signature, 1_000.0, now=1_001.0),
            "duplicate",
        )
        self.assertEqual(self.admit(marker("fresh"), 1_001.0), "accepted")

    def test_concurrent_duplicate_admission_has_one_winner(self):
        request_signature = marker("concurrent")

        def attempt(_: int) -> str:
            return self.admit(request_signature, 1_000.0)

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(attempt, range(8)))
        self.assertEqual(results.count("accepted"), 1)
        self.assertEqual(results.count("duplicate"), 7)

    def test_marker_remains_live_at_the_inclusive_freshness_boundary(self):
        request_signature = marker("inclusive-boundary")
        self.assertEqual(self.admit(request_signature, 1_000.0), "accepted")
        self.assertEqual(
            self.admit(request_signature, 1_000.0, now=1_300.0),
            "duplicate",
        )

    def test_capacity_is_partitioned_and_expired_rows_are_reclaimed(self):
        self.assertEqual(
            self.admit(marker("a-1"), 1_000.0, max_entries=2), "accepted"
        )
        self.assertEqual(
            self.admit(marker("a-2"), 1_000.0, max_entries=2), "accepted"
        )
        self.assertEqual(
            self.admit(marker("a-3"), 1_000.0, max_entries=2), "capacity"
        )

        self.store.register_agent("agent-b", "host-b", "Linux")
        other_secret = self.store.ensure_agent_secret("agent-b")
        self.assertEqual(
            self.admit(
                marker("b-1"),
                1_000.0,
                agent_id="agent-b",
                secret=other_secret,
                max_entries=2,
            ),
            "accepted",
        )
        self.assertEqual(
            self.admit(marker("a-after-expiry"), 1_301.0, max_entries=2),
            "accepted",
        )

    def test_principal_capacity_never_evicts_live_markers(self):
        self.assertEqual(
            self.admit(marker("principal-a"), 1_000.0, max_principals=1),
            "accepted",
        )
        self.store.register_agent("agent-b", "host-b", "Linux")
        other_secret = self.store.ensure_agent_secret("agent-b")
        self.assertEqual(
            self.admit(
                marker("principal-b"),
                1_000.0,
                agent_id="agent-b",
                secret=other_secret,
                max_principals=1,
            ),
            "principal_capacity",
        )
        self.assertEqual(
            self.admit(marker("principal-a-2"), 1_000.0, max_principals=1),
            "accepted",
        )

    def test_legacy_database_gets_a_conservative_migration_fence(self):
        legacy_database = Path(self.directory.name) / "legacy.db"
        legacy = Store(legacy_database)
        legacy.register_agent("legacy-agent", "legacy-host", "Linux")
        legacy_secret = legacy.ensure_agent_secret("legacy-agent")
        legacy.close()

        upgraded = Store(legacy_database)
        try:
            upgraded.initialize_http_request_replay(300.0, now=2_000.0)
            common = {
                "auth_kind": "agent",
                "expected_credential_epoch": 0,
                "expected_agent_secret": legacy_secret,
                "max_entries": 8,
                "max_principals": 2,
                "max_clock_skew": 300.0,
            }
            self.assertEqual(
                upgraded.admit_http_request(
                    "legacy-agent",
                    marker("migration-old"),
                    "2300.0",
                    now=2_300.0,
                    **common,
                ),
                "stale",
            )
            self.assertEqual(
                upgraded.admit_http_request(
                    "legacy-agent",
                    marker("migration-new"),
                    "2300.001",
                    now=2_300.001,
                    **common,
                ),
                "accepted",
            )
        finally:
            upgraded.close()

    def test_clock_rollback_cannot_resurrect_a_pruned_request(self):
        old_signature = marker("old-clock")
        self.assertEqual(self.admit(old_signature, 1_000.0), "accepted")
        self.assertEqual(self.admit(marker("advance-clock"), 1_400.0), "accepted")
        self.assertEqual(
            self.admit(old_signature, 1_000.0, now=1_000.0),
            "stale",
        )

    def test_authority_change_is_detected_before_marker_commit(self):
        old_secret = self.secret
        self.store.rotate_agent_credential("agent-a")
        self.assertEqual(
            self.admit(
                marker("old-authority"),
                1_000.0,
                secret=old_secret,
                epoch=0,
            ),
            "authority_changed",
        )

    def test_lifecycle_changes_do_not_clear_enrollment_replay_evidence(self):
        enrollment_signature = marker("enrollment")
        self.assertEqual(
            self.admit(
                enrollment_signature,
                1_000.0,
                epoch=0,
                auth_kind="enrollment",
            ),
            "accepted",
        )
        self.store.rotate_agent_credential("agent-a")
        self.assertEqual(
            self.admit(
                enrollment_signature,
                1_000.0,
                now=1_001.0,
                epoch=1,
                auth_kind="enrollment",
            ),
            "duplicate",
        )
        self.assertTrue(self.store.set_agent_enabled("agent-a", False))
        self.assertTrue(self.store.set_agent_enabled("agent-a", True))
        snapshot = self.store.agent_http_auth_snapshot("agent-a")
        self.assertEqual(
            self.admit(
                enrollment_signature,
                1_000.0,
                now=1_002.0,
                epoch=int(snapshot["credential_epoch"]),
                auth_kind="enrollment",
            ),
            "duplicate",
        )

    def test_corrupt_replay_state_fails_closed(self):
        with self.store._lock:
            self.store._connection.execute(
                "UPDATE controller_state SET state_value='{}' WHERE state_key=?",
                (HTTP_REQUEST_REPLAY_STATE_KEY,),
            )
            self.store._connection.commit()
        with self.assertRaisesRegex(ValueError, "replay state"):
            self.admit(marker("corrupt-state"), 1_000.0)


if __name__ == "__main__":
    unittest.main()
