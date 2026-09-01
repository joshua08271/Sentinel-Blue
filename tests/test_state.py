import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from sentinel_blue.agent import execute_queued_action
from sentinel_blue import state
from sentinel_blue.state import AgentProcessLock, ActionJournal, SequenceCounter, TelemetrySpool


class StateTests(unittest.TestCase):
    def test_spool_is_ordered_acknowledged_and_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            spool = TelemetrySpool(directory, max_items=2)
            spool.enqueue({"sequence": 1})
            spool.enqueue({"sequence": 2})
            spool.enqueue({"sequence": 3})
            pending = spool.pending()
            self.assertEqual([item[1]["sequence"] for item in pending], [2, 3])
            spool.acknowledge(pending[0][0])
            self.assertEqual(len(spool.pending()), 1)

    def test_corrupt_spool_item_is_quarantined(self):
        with tempfile.TemporaryDirectory() as directory:
            spool = TelemetrySpool(directory)
            (spool.directory / "000.json").write_text("not-json", encoding="utf-8")
            self.assertEqual(spool.pending(), [])
            self.assertEqual(len(list(spool.directory.glob("*.corrupt"))), 1)

    def test_nonfinite_spool_item_is_quarantined_before_transmission(self):
        with tempfile.TemporaryDirectory() as directory:
            spool = TelemetrySpool(directory)
            (spool.directory / "000.json").write_text(
                '{"agent_id":"agent-one","observed_at":NaN}',
                encoding="utf-8",
            )
            self.assertEqual(spool.pending(), [])
            self.assertEqual(len(list(spool.directory.glob("*.corrupt"))), 1)

    def test_state_writer_refuses_nonfinite_values(self):
        with tempfile.TemporaryDirectory() as directory:
            spool = TelemetrySpool(directory)
            with self.assertRaisesRegex(ValueError, "non-finite"):
                spool.enqueue({"observed_at": float("nan")})
            self.assertEqual(list(spool.directory.iterdir()), [])

    def test_duplicate_action_journal_fields_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "action-journal.json"
            path.write_text(
                '{"action-1":{"status":"completed","status":"in_progress"}}',
                encoding="utf-8",
            )
            journal = ActionJournal(directory)
            self.assertFalse(journal.healthy)
            with self.assertRaisesRegex(RuntimeError, "requires review"):
                journal.get("action-1")

    def test_permanently_rejected_item_does_not_block_later_telemetry(self):
        with tempfile.TemporaryDirectory() as directory:
            spool = TelemetrySpool(directory, max_items=2)
            first = spool.enqueue({"sequence": 1})
            spool.enqueue({"sequence": 2})
            rejected = spool.reject(first, "controller-400")
            self.assertTrue(rejected.exists())
            self.assertEqual([item[1]["sequence"] for item in spool.pending()], [2])

    def test_action_journal_survives_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = ActionJournal(directory)
            journal.remember("action-1", {"success": True})
            self.assertEqual(ActionJournal(directory).get("action-1"), {"success": True})

    def test_action_journal_capacity_preserves_protected_tombstones(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = ActionJournal(directory, maximum=2, retention_seconds=60)
            journal.remember("action-1", {"success": True}, now=100)
            journal.remember(
                "action-2",
                {"success": True},
                expires_at=150,
                now=100,
            )
            with self.assertRaisesRegex(RuntimeError, "capacity is exhausted"):
                journal.begin("action-3", "snapshot", now=151)
            self.assertIsNotNone(journal.record("action-1"))
            self.assertIsNotNone(journal.record("action-2"))
            self.assertIsNone(journal.record("action-3"))

    def test_action_journal_prunes_only_after_expiry_and_recent_retention(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = ActionJournal(directory, maximum=1, retention_seconds=10)
            journal.remember(
                "old-action",
                {"success": True},
                expires_at=20,
                now=0,
            )
            with self.assertRaisesRegex(RuntimeError, "capacity is exhausted"):
                journal.begin("too-soon", "snapshot", now=29)
            self.assertTrue(
                journal.begin(
                    "new-action",
                    "snapshot",
                    "a" * 64,
                    expires_at=40,
                    profile_fingerprint="b" * 64,
                    now=31,
                )
            )
            self.assertIsNone(journal.record("old-action"))
            self.assertEqual(journal.record("new-action")["status"], "in_progress")

    def test_action_journal_preserves_current_profile_epoch_until_upgrade(self):
        with tempfile.TemporaryDirectory() as directory:
            current = ActionJournal(
                directory,
                maximum=1,
                retention_seconds=0,
                profile_fingerprint="a" * 64,
            )
            current.remember("epoch-action", {"success": True}, now=1)
            with self.assertRaisesRegex(RuntimeError, "capacity is exhausted"):
                current.begin("same-epoch", "snapshot", now=100)

            upgraded = ActionJournal(
                directory,
                maximum=1,
                retention_seconds=0,
                profile_fingerprint="b" * 64,
            )
            self.assertTrue(
                upgraded.begin(
                    "next-epoch",
                    "snapshot",
                    "c" * 64,
                    profile_fingerprint="b" * 64,
                    now=100,
                )
            )
            self.assertIsNone(upgraded.record("epoch-action"))

    def test_action_journal_rejects_same_id_with_an_altered_envelope(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = ActionJournal(directory)
            self.assertTrue(
                journal.begin(
                    "immutable-action",
                    "snapshot",
                    "a" * 64,
                    expires_at=200,
                    now=100,
                )
            )
            with self.assertRaisesRegex(RuntimeError, "different envelope"):
                journal.record("immutable-action", "b" * 64)
            self.assertEqual(
                journal.record("immutable-action", "a" * 64)["status"],
                "in_progress",
            )

    def test_corrupt_action_journal_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "action-journal.json"
            path.write_text("{corrupt", encoding="utf-8")
            journal = ActionJournal(directory)
            self.assertFalse(journal.healthy)
            with self.assertRaisesRegex(RuntimeError, "requires review"):
                journal.get("action-1")

    def test_interrupted_action_is_never_replayed(self):
        class InterruptingExecutor:
            calls = 0

            def execute(self, *_args, **_kwargs):
                self.calls += 1
                raise SystemExit("synthetic process death")

        action = {"action_id": "action-crash", "action_type": "restart_service", "parameters": {}}
        health = {"action_safe": True, "critical_errors": []}
        with tempfile.TemporaryDirectory() as directory:
            first = ActionJournal(directory)
            executor = InterruptingExecutor()
            with self.assertRaises(SystemExit):
                execute_queued_action(first, executor, action, {}, health)
            restarted = ActionJournal(directory)
            result = execute_queued_action(restarted, executor, action, {}, health)
            self.assertFalse(result["success"])
            self.assertTrue(result["interrupted"])
            self.assertEqual(executor.calls, 1)
            self.assertEqual(ActionJournal(directory).get("action-crash"), result)

    def test_state_writer_refuses_symbolic_link_target(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "outside.json"
            target.write_text("{}", encoding="utf-8")
            journal_path = Path(directory) / "action-journal.json"
            try:
                journal_path.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("symbolic links unavailable")
            journal = ActionJournal(directory)
            self.assertFalse(journal.healthy)

    def test_spool_refuses_symbolic_link_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "outside"
            target.mkdir()
            try:
                (root / "telemetry-spool").symlink_to(target, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symbolic links unavailable")
            with self.assertRaisesRegex(ValueError, "symbolic link"):
                TelemetrySpool(root)

    def test_sequence_survives_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(SequenceCounter(directory).next(), 1)
            self.assertEqual(SequenceCounter(directory).next(), 2)

    def test_atomic_writer_closes_temporary_before_replace(self):
        real_open = state.os.open
        real_fstat = state.os.fstat
        real_replace = state.os.replace
        temporary_descriptor = {"value": None}

        def capturing_open(path, flags, mode=0o777):
            descriptor = real_open(path, flags, mode)
            if str(path).endswith(".tmp"):
                temporary_descriptor["value"] = descriptor
            return descriptor

        def checking_replace(source, destination):
            descriptor = temporary_descriptor["value"]
            self.assertIsNotNone(descriptor)
            with self.assertRaises(OSError):
                real_fstat(descriptor)
            return real_replace(source, destination)

        with tempfile.TemporaryDirectory() as directory:
            with patch.object(state.os, "open", side_effect=capturing_open), patch.object(
                state.os, "replace", side_effect=checking_replace
            ):
                self.assertEqual(SequenceCounter(directory).next(), 1)

    def test_windows_atomic_replace_retries_only_sharing_violations(self):
        sharing_error = OSError("synthetic sharing violation")
        sharing_error.winerror = 32
        with patch.object(state, "os", wraps=state.os) as windows_os, patch.object(
            state.time, "sleep"
        ) as sleep:
            windows_os.name = "nt"
            windows_os.replace.side_effect = [sharing_error, None]
            state._replace_with_retry(Path("source"), Path("destination"))
        self.assertEqual(windows_os.replace.call_count, 2)
        sleep.assert_called_once()

    def test_agent_process_lock_refuses_a_second_owner(self):
        with tempfile.TemporaryDirectory() as directory:
            first = AgentProcessLock(directory).acquire()
            try:
                with self.assertRaisesRegex(RuntimeError, "already owns"):
                    AgentProcessLock(directory).acquire()
            finally:
                first.close()
            AgentProcessLock(directory).acquire().close()

    def test_corrupt_sequence_state_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "sequence.json").write_text('{“sequence”:-1}', encoding="utf-8")
            sequence = SequenceCounter(directory)
            self.assertFalse(sequence.healthy)
            with self.assertRaisesRegex(RuntimeError, "requires review"):
                sequence.next()


if __name__ == "__main__":
    unittest.main()
