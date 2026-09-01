import argparse
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sentinel_blue.learning import (
    MAX_WEIGHT_DELTA_FROM_BUNDLED,
    MIN_FEEDBACK_SAMPLES,
    run,
    train_candidate,
)
from sentinel_blue.risk import RiskModel, features_for_kind
from sentinel_blue.protocol import AlertCandidate
from sentinel_blue.simulator import training_samples
from sentinel_blue.store import Store


class EligibleFeedbackStore:
    """Model the Store contract: only exact eligible provenance is returned."""

    def __init__(self, store, expected_filter):
        self.store = store
        self.expected_filter = expected_filter
        self.requests = []

    def feedback_samples(self, *, provenance_filter=None):
        self.requests.append(provenance_filter)
        if provenance_filter != self.expected_filter:
            return []
        return self.store.feedback_samples()


class LearningTests(unittest.TestCase):
    @staticmethod
    def _provenance(model=None, *, campaign_id="campaign-one"):
        active = model or RiskModel()
        return {
            "campaign_id": campaign_id,
            "profile_id": "profile-one",
            "profile_fingerprint": "a" * 64,
            "release_sha256": "b" * 64,
            "agent_version": "1.9.7",
            "model_fingerprint": active.fingerprint(),
        }

    @classmethod
    def _eligible(cls, store, model=None, *, campaign_id="campaign-one"):
        provenance = cls._provenance(model, campaign_id=campaign_id)
        return EligibleFeedbackStore(store, provenance), provenance

    @staticmethod
    def _record_balanced_synthetic_feedback(
        store, *, flipped=False, per_label=80
    ):
        counts = {0: 0, 1: 0}
        for index, (features, expected) in enumerate(
            training_samples(seed=7331, count=2500)[:2000]
        ):
            label = 1 - expected if flipped else expected
            if counts[label] >= per_label:
                continue
            store.record_feedback(
                f"synthetic-{index}",
                "synthetic-ground-truth",
                "approve" if label else "reject",
                label,
                features,
            )
            counts[label] += 1
            if all(value >= per_label for value in counts.values()):
                break
        return counts

    def test_feedback_produces_regression_gated_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "learning.db")
            output = Path(directory) / "candidate.json"
            try:
                self._record_balanced_synthetic_feedback(store)
                model = RiskModel()
                eligible, provenance = self._eligible(store, model)
                report = train_candidate(
                    eligible, model, output, provenance_filter=provenance
                )
                self.assertTrue(report["accepted"])
                self.assertTrue(output.exists())
                self.assertTrue(output.with_suffix(".json.report.json").exists())
                lineage = json.loads(output.read_text(encoding="utf-8"))["lineage"]
                self.assertEqual(
                    lineage["trusted_base_fingerprint"],
                    report["trusted_base_fingerprint"],
                )
                self.assertEqual(
                    lineage["training_data_fingerprint"],
                    report["training_data_fingerprint"],
                )
                self.assertEqual(report["provenance_filter"], provenance)
                self.assertRegex(report["provenance_fingerprint"], r"^[0-9a-f]{64}$")
                self.assertEqual(eligible.requests, [provenance])
                self.assertLess(report["metrics_after"]["brier"], report["metrics_before"]["brier"])
                self.assertLessEqual(
                    report["observed_maximum_weight_delta"],
                    MAX_WEIGHT_DELTA_FROM_BUNDLED,
                )
            finally:
                store.close()

    def test_alert_decision_and_feedback_commit_atomically(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "atomic-feedback.db")
            try:
                alert_id = store.add_alert(
                    "learning-agent",
                    AlertCandidate(
                        "service_probe_failed",
                        "Probe failed",
                        "fixture",
                        "high",
                        0.9,
                        {"probe": {"name": "health", "target": "local"}},
                        "review",
                        "validate_service",
                    ),
                )
                self.assertIsNotNone(alert_id)
                with patch.object(
                    store,
                    "record_feedback",
                    side_effect=RuntimeError("injected feedback failure"),
                ):
                    with self.assertRaisesRegex(RuntimeError, "injected"):
                        store.decide_alert_with_feedback(
                            str(alert_id),
                            "reject",
                            "service_probe_failed",
                            0,
                            features_for_kind("service_probe_failed"),
                        )
                self.assertEqual(store.get_alert(str(alert_id))["status"], "open")
                with store._lock:
                    count = store._connection.execute(
                        "SELECT COUNT(*) FROM learning_feedback"
                    ).fetchone()[0]
                self.assertEqual(count, 0)
            finally:
                store.close()

    def test_empty_and_handful_feedback_never_emit_a_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "learning.db")
            output = Path(directory) / "candidate.json"
            try:
                model = RiskModel()
                eligible, provenance = self._eligible(store, model)
                report = train_candidate(
                    eligible, model, output, provenance_filter=provenance
                )
                self.assertFalse(report["accepted"])
                self.assertIn("insufficient_feedback_samples", report["reasons"])
                self.assertFalse(output.exists())
                for index in range(5):
                    store.record_feedback(
                        f"alert-{index}",
                        "service_probe_failed",
                        "approve",
                        1,
                        features_for_kind("service_probe_failed"),
                    )
                report = train_candidate(
                    eligible, model, output, provenance_filter=provenance
                )
                self.assertFalse(report["accepted"])
                self.assertLess(report["eligible_feedback"], MIN_FEEDBACK_SAMPLES)
                self.assertFalse(output.exists())
            finally:
                store.close()

    def test_balanced_but_nondiverse_feedback_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "learning.db")
            output = Path(directory) / "candidate.json"
            try:
                features = features_for_kind("service_probe_failed")
                for index in range(MIN_FEEDBACK_SAMPLES):
                    label = index % 2
                    store.record_feedback(
                        f"alert-{index}", "service_probe_failed", "review", label, features
                    )
                model = RiskModel()
                eligible, provenance = self._eligible(store, model)
                report = train_candidate(
                    eligible, model, output, provenance_filter=provenance
                )
                self.assertFalse(report["accepted"])
                self.assertIn("insufficient_feature_coverage", report["reasons"])
                self.assertIn("insufficient_signature_diversity", report["reasons"])
                self.assertFalse(output.exists())
            finally:
                store.close()

    def test_regressing_feedback_preserves_an_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "learning.db")
            output = Path(directory) / "candidate.json"
            output.write_bytes(b"trusted prior candidate")
            try:
                self._record_balanced_synthetic_feedback(store, flipped=True)
                model = RiskModel()
                eligible, provenance = self._eligible(store, model)
                report = train_candidate(
                    eligible, model, output, provenance_filter=provenance
                )
                self.assertFalse(report["accepted"])
                self.assertIn("brier_regression", report["reasons"])
                self.assertIn("roc_auc_regression", report["reasons"])
                self.assertEqual(output.read_bytes(), b"trusted prior candidate")
            finally:
                store.close()

    def test_repeated_generations_are_root_bound_and_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = Store(root / "learning.db")
            try:
                self._record_balanced_synthetic_feedback(store)
                first_output = root / "candidate-1.json"
                initial = RiskModel()
                eligible, provenance = self._eligible(store, initial)
                first = train_candidate(
                    eligible, initial, first_output, provenance_filter=provenance
                )
                self.assertTrue(first["accepted"])
                prior = RiskModel.load(first_output)
                expected_fingerprint = prior.fingerprint()
                for generation in range(2, 8):
                    output = root / f"candidate-{generation}.json"
                    eligible, provenance = self._eligible(store, prior)
                    report = train_candidate(
                        eligible, prior, output, provenance_filter=provenance
                    )
                    self.assertTrue(report["accepted"])
                    prior = RiskModel.load(output)
                    self.assertEqual(prior.fingerprint(), expected_fingerprint)
                    self.assertLessEqual(
                        report["observed_maximum_weight_delta"],
                        MAX_WEIGHT_DELTA_FROM_BUNDLED,
                    )
            finally:
                store.close()

    def test_unbound_legacy_feedback_cannot_train(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "learning.db")
            output = Path(directory) / "candidate.json"
            try:
                self._record_balanced_synthetic_feedback(store)
                report = train_candidate(store, RiskModel(), output)
                self.assertFalse(report["accepted"])
                self.assertEqual(report["reasons"], ["missing_provenance_filter"])
                self.assertEqual(report["recorded_feedback"], 0)
                self.assertFalse(output.exists())
            finally:
                store.close()

    def test_provenance_is_part_of_the_training_data_lineage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = Store(root / "learning.db")
            try:
                self._record_balanced_synthetic_feedback(store)
                model = RiskModel()
                first_store, first_filter = self._eligible(
                    store, model, campaign_id="campaign-one"
                )
                second_store, second_filter = self._eligible(
                    store, model, campaign_id="campaign-two"
                )
                first = train_candidate(
                    first_store,
                    model,
                    root / "first.json",
                    provenance_filter=first_filter,
                )
                second = train_candidate(
                    second_store,
                    model,
                    root / "second.json",
                    provenance_filter=second_filter,
                )
                self.assertTrue(first["accepted"])
                self.assertTrue(second["accepted"])
                self.assertNotEqual(
                    first["provenance_fingerprint"],
                    second["provenance_fingerprint"],
                )
                self.assertNotEqual(
                    first["training_data_fingerprint"],
                    second["training_data_fingerprint"],
                )
            finally:
                store.close()

    def test_provenance_model_binding_must_match_the_supplied_base(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "learning.db")
            try:
                provenance = self._provenance()
                provenance["model_fingerprint"] = "0" * 64
                with self.assertRaisesRegex(ValueError, "supplied base model"):
                    train_candidate(
                        store,
                        RiskModel(),
                        Path(directory) / "candidate.json",
                        provenance_filter=provenance,
                    )
            finally:
                store.close()

    def test_learning_cli_refuses_to_overwrite_its_base_model(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            model = root / "model.json"
            RiskModel().save(model)
            with self.assertRaisesRegex(ValueError, "differ"):
                run(
                    argparse.Namespace(
                        database=str(root / "learning.db"),
                        base_model=str(model),
                        output=str(model),
                    )
                )
            database = root / "learning.db"
            with self.assertRaisesRegex(ValueError, "database"):
                run(
                    argparse.Namespace(
                        database=str(database),
                        base_model=None,
                        output=str(database),
                    )
                )

    def test_feedback_rejects_poisoned_types_and_stored_features(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "learning.db")
            try:
                with self.assertRaisesRegex(ValueError, "type coercion"):
                    store.record_feedback("alert-1", "kind", "approve", 1, {"probe_failure": "1"})
                with self.assertRaisesRegex(ValueError, "unknown model feature"):
                    store.record_feedback("alert-1", "kind", "approve", 1, {"all_powerful": 1.0})
                with self.assertRaisesRegex(ValueError, "exactly zero or one"):
                    store.record_feedback("alert-1", "kind", "approve", True, {"probe_failure": 1.0})
                store.record_feedback("alert-2", "kind", "approve", 1, {"probe_failure": 1.0})
                store._connection.execute(
                    "UPDATE learning_feedback SET features_json=?",
                    ('{"probe_failure":"1"}',),
                )
                store._connection.commit()
                self.assertEqual(store.feedback_samples(), [])
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
