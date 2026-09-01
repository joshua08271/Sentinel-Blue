from __future__ import annotations

import copy
from pathlib import Path
import tempfile
import time
import unittest

from sentinel_blue import __version__
from sentinel_blue.adversarial_lab import valid_payload
from sentinel_blue.auth import derive_enrollment_ticket
from sentinel_blue.controller import ControllerApp
from sentinel_blue.event_profile import EventProfile
from sentinel_blue.store import Store


class PersistentLearningLineageTests(unittest.TestCase):
    agent_id = "learning-agent"
    release_sha256 = "a" * 64
    campaign_id = "range-campaign-one"

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.directory.name) / "learning.db")
        raw = copy.deepcopy(EventProfile.testing().raw)
        raw["profile_id"] = "learning-lineage-profile"
        raw["release"]["version"] = __version__
        raw["release"]["sha256"] = self.release_sha256
        raw["official_identities"] = [
            {
                "agent_id": self.agent_id,
                "name": self.agent_id,
                "class": "service",
                "source": "test-inventory",
            }
        ]
        self.profile = EventProfile.from_dict(raw)
        self.app = ControllerApp(
            self.store,
            "e" * 32,
            event_profile=self.profile,
            operator_token="o" * 32,
            operator_principal_id="blue-lead",
            campaign_id=self.campaign_id,
        )
        enrollment = {
            "agent_id": self.agent_id,
            "hostname": "learning-host",
            "platform": "Linux",
            "agent_version": __version__,
            "profile_id": self.profile.profile_id,
            "profile_fingerprint": self.profile.fingerprint,
            "enrollment_nonce": "1" * 64,
        }
        enrolled = self.app.enroll(
            enrollment,
            authenticated_ticket=derive_enrollment_ticket(
                self.app.token, self.profile.fingerprint, self.agent_id
            ),
        )
        self.agent_token = enrolled["agent_token"]

    def tearDown(self):
        self.store.close()
        self.directory.cleanup()

    def telemetry(self, sequence: int) -> dict:
        payload = valid_payload()
        payload.update(
            {
                "agent_id": self.agent_id,
                "hostname": "learning-host",
                "agent_version": __version__,
                "profile_id": self.profile.profile_id,
                "profile_fingerprint": self.profile.fingerprint,
                "boot_id": "learning-boot-one",
                "sequence": sequence,
                "observed_at": time.time(),
                "queued_at": time.time(),
            }
        )
        payload["accounts"].append(
            {
                "name": "unverified-admin",
                "account_id": "1001",
                "privileged": True,
                "enabled": True,
            }
        )
        return payload

    def provenance(self) -> dict[str, str]:
        return {
            "campaign_id": self.campaign_id,
            "profile_id": self.profile.profile_id,
            "profile_fingerprint": self.profile.fingerprint,
            "release_sha256": self.release_sha256,
            "agent_version": __version__,
            "model_fingerprint": self.app.model_fingerprint,
        }

    def ingest(self, sequence: int) -> str:
        alerts = self.app.ingest(
            self.telemetry(sequence),
            expected_agent_id=self.agent_id,
            expected_agent_secret=self.agent_token,
        )
        matching = [
            alert_id
            for alert_id in alerts
            if self.store.get_alert(alert_id)["kind"]
            == "unverified_privileged_account"
        ]
        self.assertEqual(len(matching), 1)
        return matching[0]

    def test_decision_labels_the_exact_creation_occurrence_and_reviewer(self):
        alert_id = self.ingest(1)
        self.assertEqual(self.ingest(2), alert_id)
        lineage = self.store.alert_learning_lineage(alert_id)
        self.assertNotEqual(
            lineage["creation_occurrence_id"], lineage["last_occurrence_id"]
        )

        result = self.app.decision(
            alert_id,
            "reject",
            reviewer_principal_id="blue-lead",
        )
        self.assertEqual(result["decision"], "reject")
        samples = self.store.learning_samples(
            provenance_filter=self.provenance()
        )
        self.assertEqual(len(samples), 1)
        sample = samples[0]
        self.assertEqual(
            sample["occurrence_id"], lineage["creation_occurrence_id"]
        )
        self.assertEqual(sample["reviewer_principal_id"], "blue-lead")
        self.assertEqual(sample["label_source"], "operator-decision")
        self.assertEqual(sample["label"], 0)
        self.assertEqual(sample["features"]["unknown_privileged_account"], 1.0)

    def test_durable_quarantine_permanently_excludes_lineage(self):
        alert_id = self.ingest(1)
        self.app.decision(
            alert_id,
            "reject",
            reviewer_principal_id="blue-lead",
        )
        sample = self.store.learning_samples(
            provenance_filter=self.provenance()
        )[0]
        self.store._quarantine_json(
            "alert_occurrences",
            sample["occurrence_id"],
            "candidate_json",
            "forensic-test",
            "forensic exclusion",
        )
        self.assertEqual(
            self.store.learning_samples(provenance_filter=self.provenance()),
            [],
        )


if __name__ == "__main__":
    unittest.main()
