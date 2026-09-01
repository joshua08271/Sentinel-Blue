from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from sentinel_blue.operator_auth import operator_key_fingerprint
from sentinel_blue.store import Store


TOKEN_ONE = "1" * 32
TOKEN_TWO = "2" * 32
PRINCIPAL = "blue-lead"
SKEW = 300.0


def initialize(
    store: Store,
    token: str = TOKEN_ONE,
    *,
    epoch: int = 1,
    principal: str = PRINCIPAL,
    now: float = 1_000.0,
) -> dict[str, object]:
    return store.initialize_operator_auth(
        principal_id=principal,
        key_fingerprint=operator_key_fingerprint(token),
        credential_epoch=epoch,
        max_clock_skew=SKEW,
        now=now,
    )


def admit(
    store: Store,
    request_id: str,
    *,
    token: str = TOKEN_ONE,
    epoch: int = 1,
    principal: str = PRINCIPAL,
    timestamp: int = 1_001,
    now: float = 1_001.0,
    marker: str | None = None,
    max_entries: int = 8,
) -> str:
    return store.admit_operator_request(
        principal_id=principal,
        credential_epoch=epoch,
        request_id=request_id,
        marker_sha256=marker or request_id * 2,
        request_timestamp=timestamp,
        expected_key_fingerprint=operator_key_fingerprint(token),
        method="POST",
        target="/api/v1/governance/mode",
        max_entries=max_entries,
        max_clock_skew=SKEW,
        now=now,
    )


class PersistentOperatorAuthTests(unittest.TestCase):
    def test_exact_request_replay_survives_controller_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "controller.db"
            first = Store(database)
            initialize(first)
            self.assertEqual(admit(first, "a" * 32), "accepted")
            audit = first._connection.execute(
                "SELECT actor, operation FROM audit_log"
            ).fetchone()
            self.assertEqual(tuple(audit), (PRINCIPAL, "operator_request_admitted"))
            first.close()

            second = Store(database)
            initialize(second, now=1_002.0)
            try:
                self.assertEqual(
                    admit(second, "a" * 32, now=1_002.0), "duplicate"
                )
                self.assertEqual(
                    admit(
                        second,
                        "b" * 32,
                        marker="c" * 64,
                        timestamp=1_002,
                        now=1_002.0,
                    ),
                    "accepted",
                )
            finally:
                second.close()

    def test_request_id_conflicts_capacity_and_clock_rollback_fail_closed(self):
        store = Store(":memory:")
        initialize(store, now=2_000.0)
        self.assertEqual(
            admit(
                store,
                "d" * 32,
                marker="e" * 64,
                timestamp=2_000,
                now=2_000.0,
                max_entries=1,
            ),
            "accepted",
        )
        self.assertEqual(
            admit(
                store,
                "d" * 32,
                marker="f" * 64,
                timestamp=2_001,
                now=2_001.0,
                max_entries=1,
            ),
            "request_id_conflict",
        )
        self.assertEqual(
            admit(
                store,
                "e" * 32,
                marker="0" * 64,
                timestamp=2_001,
                now=2_001.0,
                max_entries=1,
            ),
            "capacity",
        )
        self.assertEqual(
            admit(
                store,
                "f" * 32,
                marker="1" * 64,
                timestamp=1_600,
                now=1_700.0,
            ),
            "stale",
        )
        store.close()

    def test_rotation_requires_a_new_key_and_the_next_epoch(self):
        store = Store(":memory:")
        initialize(store)
        with self.assertRaisesRegex(ValueError, "new key"):
            initialize(store, TOKEN_ONE, epoch=2, now=1_010.0)
        with self.assertRaisesRegex(ValueError, "next credential epoch"):
            initialize(store, TOKEN_TWO, epoch=1, now=1_010.0)
        info = initialize(store, TOKEN_TWO, epoch=2, now=1_010.0)
        self.assertEqual(info["credential_epoch"], 2)
        self.assertEqual(info["request_not_before"], 1_011)
        self.assertEqual(
            admit(
                store,
                "2" * 32,
                token=TOKEN_TWO,
                epoch=2,
                timestamp=1_010,
                now=1_010.0,
            ),
            "stale",
        )
        self.assertEqual(
            admit(
                store,
                "3" * 32,
                token=TOKEN_TWO,
                epoch=2,
                timestamp=1_011,
                now=1_011.0,
            ),
            "accepted",
        )
        store.close()

    def test_bearer_release_database_requires_explicit_fresh_epoch(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "legacy.db"
            prior = Store(database)
            prior.close()

            upgraded = Store(database)
            with self.assertRaisesRegex(ValueError, "fresh operator key"):
                initialize(upgraded, epoch=1)
            info = initialize(upgraded, TOKEN_TWO, epoch=2)
            self.assertEqual(info["credential_epoch"], 2)
            upgraded.close()


if __name__ == "__main__":
    unittest.main()
