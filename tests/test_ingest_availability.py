import json
import tempfile
import threading
import time
import unittest
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError

from sentinel_blue.agent import AgentClient
from sentinel_blue.adversarial_lab import valid_payload
from sentinel_blue.auth import PrincipalRateLimiter
from sentinel_blue.controller import (
    ControllerApp,
    ControllerServer,
    make_handler,
    prioritize_detection_candidates,
)
from sentinel_blue.protocol import (
    MAX_AGENT_EGRESS_BYTES,
    MAX_DETECTION_CANDIDATES_PER_KIND,
    AlertCandidate,
)
from sentinel_blue.store import Store


def candidate(index: int, *, kind: str = "hostile_flood", severity: str = "high") -> AlertCandidate:
    return AlertCandidate(
        kind=kind,
        title=f"Candidate {index}",
        summary="authenticated hostile telemetry candidate",
        severity=severity,
        confidence=0.9,
        evidence={"index": index},
        recommendation="preserve evidence",
        recommended_action="snapshot",
    )


def telemetry(agent_id: str) -> dict:
    payload = valid_payload()
    payload.update(
        {
            "agent_id": agent_id,
            "hostname": agent_id,
            "observed_at": time.time(),
        }
    )
    return payload


class IngestAvailabilityTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.directory.name) / "availability.db")
        self.app = ControllerApp(
            self.store,
            "e" * 32,
            operator_token="o" * 32,
            max_agents=4,
        )

    def tearDown(self):
        self.store.close()
        self.directory.cleanup()

    def test_candidate_selection_is_severity_first_and_per_kind_bounded(self):
        candidates = [
            *[candidate(index, kind="same", severity="medium") for index in range(20)],
            *[candidate(100 + index, kind="same", severity="critical") for index in range(10)],
            candidate(999, kind="other", severity="high"),
        ]
        selected, summary = prioritize_detection_candidates(candidates)
        same = [item for item in selected if item.kind == "same"]
        self.assertEqual(len(same), MAX_DETECTION_CANDIDATES_PER_KIND)
        self.assertEqual({item.severity for item in same}, {"critical"})
        self.assertIn("other", {item.kind for item in selected})
        self.assertEqual(summary["suppressed_candidates"], 22)

    def test_4096_candidates_create_only_bounded_alerts_and_one_snapshot(self):
        flooded = [candidate(index) for index in range(4_096)]
        with patch("sentinel_blue.controller.detect", return_value=flooded):
            alert_ids = self.app.ingest(telemetry("hostile-agent"))
        self.assertEqual(len(alert_ids), MAX_DETECTION_CANDIDATES_PER_KIND)
        with self.store._lock:
            alert_count = self.store._connection.execute(
                "SELECT COUNT(*) FROM alerts WHERE agent_id='hostile-agent'"
            ).fetchone()[0]
            action_count = self.store._connection.execute(
                "SELECT COUNT(*) FROM actions WHERE agent_id='hostile-agent'"
            ).fetchone()[0]
            overflow = self.store._connection.execute(
                """
                SELECT detail_json FROM audit_log
                WHERE operation='ingest_candidate_overflow' AND subject='hostile-agent'
                ORDER BY created_at DESC LIMIT 1
                """
            ).fetchone()
        self.assertEqual(alert_count, MAX_DETECTION_CANDIDATES_PER_KIND)
        self.assertEqual(action_count, 1)
        detail = json.loads(overflow["detail_json"])
        self.assertEqual(detail["observed_candidates"], 4_096)
        self.assertEqual(detail["selected_candidates"], MAX_DETECTION_CANDIDATES_PER_KIND)

        with patch("sentinel_blue.controller.detect", return_value=[]):
            self.assertEqual(self.app.ingest(telemetry("healthy-agent")), [])
        self.assertEqual(
            self.store.latest_telemetry_for_agent("healthy-agent")["agent_id"],
            "healthy-agent",
        )

    def test_pending_action_serialization_stays_below_controller_ceiling(self):
        for index in range(32):
            self.store.queue_action(
                "delivery-agent",
                "snapshot",
                {"index": index, "blob": "x" * 60_000},
            )
        actions = self.store.pending_actions("delivery-agent")
        body = json.dumps(
            {"actions": [asdict(item) for item in actions]},
            separators=(",", ":"),
            default=str,
        ).encode()
        self.assertLessEqual(len(body), MAX_AGENT_EGRESS_BYTES)
        self.assertLess(len(actions), 32)
        with self.store._lock:
            dispatched = self.store._connection.execute(
                "SELECT COUNT(*) FROM actions WHERE status='dispatched'"
            ).fetchone()[0]
        self.assertEqual(dispatched, len(actions))


class AuthenticatedHttpAvailabilityTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.directory.name) / "http-availability.db")
        self.app = ControllerApp(
            self.store,
            "e" * 32,
            operator_token="o" * 32,
            max_agents=2,
        )
        self.server = ControllerServer(("127.0.0.1", 0), make_handler(self.app))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        self.hostile = AgentClient(self.url, "e" * 32, "hostile-agent")
        self.healthy = AgentClient(self.url, "e" * 32, "healthy-agent")
        self.hostile.enroll("hostile", "Linux")
        self.healthy.enroll("healthy", "Linux")

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.store.close()
        self.directory.cleanup()

    def test_hostile_agent_rate_limit_does_not_throttle_healthy_agent(self):
        self.app.ingest_limiter = PrincipalRateLimiter(
            rate_per_second=0.01,
            burst=1,
            max_principals=2,
        )
        self.hostile.telemetry(telemetry("hostile-agent"))
        with self.assertRaises(HTTPError) as raised:
            self.hostile.telemetry(telemetry("hostile-agent"))
        self.assertEqual(raised.exception.code, 429)
        self.assertTrue(raised.exception.sentinel_blue_verified)
        self.healthy.telemetry(telemetry("healthy-agent"))
        self.assertEqual(
            self.store.latest_telemetry_for_agent("healthy-agent")["agent_id"],
            "healthy-agent",
        )

    def test_oversized_agent_payload_is_replaced_by_signed_bounded_error(self):
        with patch.object(
            self.app,
            "ingest",
            return_value=["a" * 64 for _ in range(20_000)],
        ):
            with self.assertRaises(HTTPError) as raised:
                self.hostile.telemetry(telemetry("hostile-agent"))
        self.assertEqual(raised.exception.code, 503)
        self.assertTrue(raised.exception.sentinel_blue_verified)
        self.assertEqual(
            raised.exception.sentinel_blue_error,
            "controller response exceeds the egress limit",
        )
        self.assertLess(
            int(raised.exception.headers["Content-Length"]),
            MAX_AGENT_EGRESS_BYTES,
        )


if __name__ == "__main__":
    unittest.main()
