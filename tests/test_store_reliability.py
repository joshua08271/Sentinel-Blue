import os
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from sentinel_blue.protocol import AlertCandidate
from sentinel_blue.store import (
    MAX_AUTOMATED_OUTSTANDING_ACTIONS_PER_AGENT,
    MAX_OUTSTANDING_ACTIONS_PER_AGENT,
    ActionQuotaExceeded,
    Store,
)


class StoreReliabilityTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.directory.name) / "store.db")
        self.store.register_agent("agent-a", "host-a", "Linux")

    def tearDown(self):
        self.store.close()
        self.directory.cleanup()

    def test_action_delivery_is_leased_and_idempotent(self):
        action_id = self.store.queue_action("agent-a", "snapshot", {})
        first = self.store.pending_actions("agent-a", lease_seconds=30)
        self.assertEqual(first[0].action_id, action_id)
        self.assertEqual(self.store.pending_actions("agent-a", lease_seconds=30), [])
        with self.store._lock:
            self.store._connection.execute(
                "UPDATE actions SET dispatched_at=? WHERE action_id=?",
                (time.time() - 31, action_id),
            )
            self.store._connection.commit()
        retry = self.store.pending_actions("agent-a", lease_seconds=30)
        self.assertEqual(retry[0].action_id, action_id)
        result = {"success": True, "message": "ok"}
        self.assertTrue(self.store.complete_action(action_id, result, "agent-a"))
        self.assertTrue(self.store.complete_action(action_id, result, "agent-a"))

    def test_pending_action_delivery_is_limited_and_leases_only_returned_rows(self):
        action_ids = [
            self.store.queue_action("agent-a", "snapshot", {"index": index})
            for index in range(40)
        ]
        delivered = self.store.pending_actions("agent-a")
        self.assertEqual(len(delivered), 32)
        delivered_ids = {item.action_id for item in delivered}
        for action_id in action_ids:
            expected = "dispatched" if action_id in delivered_ids else "queued"
            self.assertEqual(self.store.get_action(action_id)["status"], expected)

    def test_byte_aware_delivery_fails_only_undeliverable_row_and_continues(self):
        oversized = self.store.queue_action(
            "agent-a", "snapshot", {"blob": "x" * 2_000}
        )
        small = self.store.queue_action("agent-a", "snapshot", {"small": True})
        delivered = self.store.pending_actions(
            "agent-a", max_serialized_bytes=1_000
        )
        self.assertEqual([item.action_id for item in delivered], [small])
        self.assertEqual(self.store.get_action(oversized)["status"], "failed")
        self.assertEqual(self.store.get_action(small)["status"], "dispatched")

    def test_repeated_automatic_snapshots_coalesce_while_outstanding(self):
        first = self.store.queue_action(
            "agent-a", "snapshot", {"evidence": "first"}, automated=True
        )
        second = self.store.queue_action(
            "agent-a", "snapshot", {"evidence": "second"}, automated=True
        )
        self.assertEqual(second, first)
        with self.store._lock:
            count = self.store._connection.execute(
                "SELECT COUNT(*) FROM actions WHERE agent_id='agent-a'"
            ).fetchone()[0]
        self.assertEqual(count, 1)

    def test_outstanding_action_quotas_reserve_capacity_for_manual_actions(self):
        for index in range(MAX_AUTOMATED_OUTSTANDING_ACTIONS_PER_AGENT):
            self.store.queue_action(
                "agent-a",
                "validate_service",
                {"index": index},
                automated=True,
            )
        with self.assertRaises(ActionQuotaExceeded):
            self.store.queue_action(
                "agent-a",
                "validate_service",
                {},
                automated=True,
            )
        for index in range(
            MAX_OUTSTANDING_ACTIONS_PER_AGENT
            - MAX_AUTOMATED_OUTSTANDING_ACTIONS_PER_AGENT
        ):
            self.store.queue_action("agent-a", "observe", {"index": index})
        with self.assertRaises(ActionQuotaExceeded):
            self.store.queue_action("agent-a", "observe", {})

    def test_wrong_agent_cannot_complete_action(self):
        action_id = self.store.queue_action("agent-a", "snapshot", {})
        self.assertFalse(self.store.complete_action(action_id, {"success": True}, "agent-b"))

    def test_duplicate_alert_updates_occurrence_count(self):
        candidate = AlertCandidate(
            "test_kind", "Test", "summary", "high", 0.9, {"stable": True}, "review", "snapshot"
        )
        alert_id = self.store.add_alert("agent-a", candidate)
        self.assertEqual(self.store.add_alert("agent-a", candidate), alert_id)
        alert = next(item for item in self.store.dashboard()["alerts"] if item["alert_id"] == alert_id)
        self.assertEqual(alert["occurrence_count"], 2)

    def test_alert_quota_reserves_higher_severity_capacity_without_eviction(self):
        admitted = []
        for index in range(17):
            admitted.append(
                self.store.add_alert(
                    "agent-a",
                    AlertCandidate(
                        "medium_flood",
                        "Medium",
                        "summary",
                        "medium",
                        0.5,
                        {"index": index},
                        "review",
                        "observe",
                    ),
                )
            )
        self.assertEqual(sum(item is not None for item in admitted), 16)
        critical = self.store.add_alert(
            "agent-a",
            AlertCandidate(
                "critical_evidence",
                "Critical",
                "summary",
                "critical",
                0.99,
                {"stable": True},
                "review",
                "snapshot",
            ),
        )
        self.assertIsNotNone(critical)
        dashboard = self.store.dashboard()["alerts"]
        self.assertEqual(sum(item["severity"] == "medium" for item in dashboard), 16)
        self.assertIn(critical, {item["alert_id"] for item in dashboard})

    def test_change_grant_is_bound_to_one_observed_digest(self):
        grant_id = self.store.create_change_grant("agent-a", "/etc/test.conf", 60)
        first = self.store.consume_change_grant("agent-a", "/etc/test.conf", "a" * 64)
        repeated = self.store.consume_change_grant("agent-a", "/etc/test.conf", "a" * 64)
        different = self.store.consume_change_grant("agent-a", "/etc/test.conf", "b" * 64)
        self.assertEqual(first["grant_id"], grant_id)
        self.assertEqual(repeated["grant_id"], grant_id)
        self.assertIsNone(different)

    def test_backup_is_consistent(self):
        destination = Path(self.directory.name) / "backup.db"
        self.store.backup(destination)
        backup = Store(destination)
        try:
            self.assertEqual(backup.integrity_check(), "ok")
            self.assertEqual(backup.agent_count(), 1)
        finally:
            backup.close()

    def test_backup_refuses_to_overwrite_live_database(self):
        with self.assertRaises(ValueError):
            self.store.backup(self.store.path)

    def test_failed_backup_preserves_previous_complete_backup(self):
        destination = Path(self.directory.name) / "backup.db"
        destination.write_bytes(b"previous-complete-backup")
        with patch.object(self.store, "_backup_to", side_effect=OSError("disk full")):
            with self.assertRaisesRegex(OSError, "disk full"):
                self.store.backup(destination)
        self.assertEqual(destination.read_bytes(), b"previous-complete-backup")

    @unittest.skipUnless(hasattr(os, "symlink"), "symbolic links unavailable")
    def test_backup_refuses_symbolic_link_destination(self):
        target = Path(self.directory.name) / "outside.db"
        target.write_bytes(b"preserve")
        link = Path(self.directory.name) / "backup-link.db"
        link.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "symbolic link"):
            self.store.backup(link)
        self.assertEqual(target.read_bytes(), b"preserve")

    def test_database_is_private_and_agent_secret_is_stable(self):
        first = self.store.ensure_agent_secret("agent-a")
        self.assertEqual(first, self.store.ensure_agent_secret("agent-a"))
        if os.name == "posix":
            self.assertEqual(Path(self.store.path).stat().st_mode & 0o777, 0o600)

    def test_database_uses_durable_and_bounded_concurrency_pragmas(self):
        with self.store._lock:
            synchronous = self.store._connection.execute("PRAGMA synchronous").fetchone()[0]
            busy_timeout = self.store._connection.execute("PRAGMA busy_timeout").fetchone()[0]
            trusted = self.store._connection.execute("PRAGMA trusted_schema").fetchone()[0]
        self.assertEqual(synchronous, 2)
        self.assertEqual(busy_timeout, 5000)
        self.assertEqual(trusted, 0)

    def test_concurrent_agent_ingest_remains_consistent(self):
        agents = [f"concurrent-{index}" for index in range(8)]
        for agent in agents:
            self.store.register_agent(agent, agent, "Linux")

        def ingest(agent: str) -> None:
            for sequence in range(40):
                self.store.save_telemetry(
                    agent,
                    {
                        "agent_id": agent,
                        "hostname": agent,
                        "platform": "Linux",
                        "observed_at": time.time(),
                        "boot_id": "stable-boot",
                        "sequence": sequence,
                    },
                )

        with ThreadPoolExecutor(max_workers=len(agents)) as pool:
            list(pool.map(ingest, agents))
        self.assertEqual(self.store.integrity_check(), "ok")
        self.assertEqual(len(self.store.latest_telemetry()), len(agents))

    @unittest.skipUnless(hasattr(os, "symlink"), "symbolic links unavailable")
    def test_database_refuses_symbolic_link_path(self):
        target = Path(self.directory.name) / "other.db"
        target.write_bytes(b"")
        link = Path(self.directory.name) / "linked.db"
        link.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "symbolic link"):
            Store(link)

    def test_sequence_replay_is_idempotent_but_reuse_is_rejected(self):
        payload = {
            "agent_id": "agent-a",
            "hostname": "host-a",
            "platform": "Linux",
            "observed_at": time.time(),
            "boot_id": "boot-stable",
            "sequence": 4,
        }
        self.assertTrue(self.store.save_telemetry("agent-a", payload))
        self.assertFalse(self.store.save_telemetry("agent-a", payload))
        with self.assertRaises(ValueError):
            self.store.save_telemetry("agent-a", {**payload, "hostname": "tampered"})
        with self.assertRaises(ValueError):
            self.store.save_telemetry("agent-a", {**payload, "sequence": 3})
        self.assertTrue(
            self.store.save_telemetry("agent-a", {**payload, "boot_id": "boot-new", "sequence": 1})
        )

    def test_baseline_promotion_is_bound_to_exact_latest_sample_and_is_immutable(self):
        # This intentionally covers the Store's no-file compatibility path.
        # Integrity-bearing baselines are promoted only through ControllerApp
        # capture actions and exact receipts in the controller tests.
        first = {
            "agent_id": "agent-a",
            "hostname": "host-a",
            "platform": "Linux",
            "observed_at": time.time(),
            "boot_id": "approval-boot",
            "sequence": 1,
            "collector_errors": ["transient"],
        }
        self.assertTrue(self.store.save_telemetry("agent-a", first))
        self.store.create_baseline("agent-a", first)

        assessed = {**first, "sequence": 2, "collector_errors": []}
        self.assertTrue(self.store.save_telemetry("agent-a", assessed))
        replacement = {**assessed, "sequence": 3, "hostname": "newest-host"}
        self.assertNotIn("integrity", replacement)
        self.assertTrue(self.store.save_telemetry("agent-a", replacement))

        self.assertFalse(
            self.store.approve_baseline("agent-a", expected_telemetry=assessed)
        )
        self.assertEqual(self.store.baseline_status("agent-a"), "pending")
        self.assertEqual(self.store.get_baseline("agent-a"), first)

        self.assertTrue(
            self.store.approve_baseline("agent-a", expected_telemetry=replacement)
        )
        self.assertEqual(self.store.baseline_status("agent-a"), "approved")
        self.assertEqual(self.store.get_baseline("agent-a"), replacement)

        later = {**replacement, "sequence": 4, "hostname": "post-approval-host"}
        self.assertTrue(self.store.save_telemetry("agent-a", later))
        self.assertFalse(
            self.store.approve_baseline("agent-a", expected_telemetry=later)
        )
        self.assertEqual(self.store.get_baseline("agent-a"), replacement)

    def test_rejected_replay_does_not_refresh_agent_health(self):
        payload = {
            "agent_id": "agent-a",
            "hostname": "host-a",
            "platform": "Linux",
            "observed_at": time.time(),
            "boot_id": "boot-health",
            "sequence": 5,
        }
        self.store.save_telemetry("agent-a", payload)
        with self.store._lock:
            self.store._connection.execute(
                "UPDATE agents SET last_seen=? WHERE agent_id=?", (10.0, "agent-a")
            )
            self.store._connection.commit()
        self.store.register_agent("agent-a", "host-a", "Linux", touch_last_seen=False)
        with self.assertRaises(ValueError):
            self.store.save_telemetry("agent-a", {**payload, "sequence": 4})
        agent = next(item for item in self.store.dashboard()["agents"] if item["agent_id"] == "agent-a")
        self.assertEqual(agent["last_seen"], 10.0)


if __name__ == "__main__":
    unittest.main()
