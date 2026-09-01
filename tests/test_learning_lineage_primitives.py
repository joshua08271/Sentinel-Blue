import hashlib
import tempfile
import unittest
from pathlib import Path

from sentinel_blue.detection import detect
from sentinel_blue.learning import (
    DATASET_MANIFEST_SCHEMA,
    DatasetLineageError,
    LearningSample,
    build_grouped_dataset,
    train_candidate,
)
from sentinel_blue.risk import RiskModel
from sentinel_blue.simulator import training_samples
from sentinel_blue.validation import ExactModelFeatures, ModelBoundAlertCandidate


class LegacyFeedbackOnly:
    def feedback_samples(self, *, provenance_filter=None):
        return []


class StructuredFeedback:
    def __init__(self, rows):
        self.rows = rows

    def learning_samples(self, *, provenance_filter=None):
        return list(self.rows)


class LearningLineagePrimitiveTests(unittest.TestCase):
    @staticmethod
    def provenance(model=None):
        active = model or RiskModel()
        return {
            "campaign_id": "campaign-one",
            "profile_id": "profile-one",
            "profile_fingerprint": "a" * 64,
            "release_sha256": "b" * 64,
            "agent_version": "1.9.7",
            "model_fingerprint": active.fingerprint(),
        }

    @staticmethod
    def sample(group: int, label: int, ordinal: int = 0):
        features = {
            "probe_failure": 1.0 if label else 0.0,
            "collector_failure": 0.0 if label else 1.0,
        }
        exact = ExactModelFeatures(features)
        suffix = f"{group}-{label}-{ordinal}"
        return {
            "label_id": f"label-{suffix}",
            "alert_id": f"alert-{suffix}",
            "occurrence_id": f"occurrence-{suffix}",
            "observation_id": f"observation-{suffix}",
            "incident_group_id": f"incident-{group}",
            "features": features,
            "features_sha256": exact.sha256,
            "candidate_sha256": f"{group + 1:064x}",
            "telemetry_sha256": f"{group + 101:064x}",
            "label": label,
            "reviewer_principal_id": "operator-one",
            "label_source": "independent-ground-truth",
        }

    def test_exact_features_and_candidate_binding_are_immutable_copies(self):
        source = {"probe_failure": 1}
        exact = ExactModelFeatures(source)
        source["probe_failure"] = 0
        exported = exact.as_dict()
        exported["probe_failure"] = 0
        self.assertEqual(exact.as_dict(), {"probe_failure": 1.0})

        candidate = ModelBoundAlertCandidate(
            kind="service_probe_failed",
            title="Probe failed",
            summary="fixture",
            severity="critical",
            confidence=0.9,
            evidence={"probe": {"name": "health"}},
            recommendation="review",
            recommended_action="snapshot",
            model_features={"probe_failure": 1.0},
        )
        candidate.model_features["probe_failure"] = 0.0
        self.assertEqual(candidate.model_features, {"probe_failure": 1.0})
        with self.assertRaisesRegex(AttributeError, "immutable"):
            candidate._exact_model_features = ExactModelFeatures(
                {"collector_failure": 1.0}
            )
        self.assertEqual(
            candidate.model_features_sha256,
            candidate.evidence["_sentinel_blue_model_features"]["sha256"],
        )

    def test_detectors_bind_the_exact_values_actually_scored(self):
        telemetry = {
            "accounts": [],
            "sessions": [],
            "services": [],
            "listeners": [],
            "integrity": [],
            "routes": [],
            "probes": [{"name": "health", "healthy": False}],
            "collector_errors": [],
        }
        alert = next(
            item
            for item in detect(telemetry, None, set(), RiskModel())
            if item.kind == "service_probe_failed"
        )
        self.assertIsInstance(alert, ModelBoundAlertCandidate)
        self.assertEqual(alert.model_features, {"probe_failure": 1.0})
        self.assertEqual(
            alert.model_features_sha256,
            ExactModelFeatures(alert.model_features).sha256,
        )

    def test_manifest_split_is_deterministic_and_never_splits_incident_groups(self):
        rows = [self.sample(group, label) for group in range(8) for label in (0, 1)]
        provenance_fingerprint = "f" * 64
        first_train, first_holdout, first_manifest = build_grouped_dataset(
            rows, provenance_fingerprint
        )
        second_train, second_holdout, second_manifest = build_grouped_dataset(
            list(reversed(rows)), provenance_fingerprint
        )
        first_training_groups = {item.incident_group_id for item in first_train}
        first_holdout_groups = {item.incident_group_id for item in first_holdout}
        self.assertFalse(first_training_groups & first_holdout_groups)
        self.assertEqual({item.label for item in first_train}, {0, 1})
        self.assertEqual({item.label for item in first_holdout}, {0, 1})
        self.assertEqual(first_manifest.sha256, second_manifest.sha256)
        self.assertEqual(first_train, second_train)
        self.assertEqual(first_holdout, second_holdout)
        self.assertEqual(first_manifest.as_dict()["schema"], DATASET_MANIFEST_SCHEMA)

    def test_duplicate_occurrence_or_wrong_feature_digest_is_rejected(self):
        rows = [self.sample(group, label) for group in range(4) for label in (0, 1)]
        rows[1]["occurrence_id"] = rows[0]["occurrence_id"]
        with self.assertRaisesRegex(DatasetLineageError, "duplicate_occurrence"):
            build_grouped_dataset(rows, "f" * 64)

        damaged = self.sample(1, 1)
        damaged["features_sha256"] = "0" * 64
        with self.assertRaisesRegex(DatasetLineageError, "features_digest"):
            LearningSample(damaged)

    def test_deployable_training_refuses_legacy_tuple_only_input(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "candidate.json"
            model = RiskModel()
            report = train_candidate(
                LegacyFeedbackOnly(),
                model,
                output,
                provenance_filter=self.provenance(model),
                require_structured_lineage=True,
            )
            self.assertFalse(report["accepted"])
            self.assertIn("missing_structured_learning_lineage", report["reasons"])
            self.assertFalse(output.exists())

    def test_structured_training_emits_a_schema_three_dataset_sidecar(self):
        counts = {0: 0, 1: 0}
        rows = []
        for features, label in training_samples(seed=7331, count=2500):
            if counts[label] >= 100:
                continue
            ordinal = counts[label]
            counts[label] += 1
            group = ordinal % 20
            label_id = f"label-{label}-{ordinal}"
            exact = ExactModelFeatures(features)
            rows.append(
                {
                    "label_id": label_id,
                    "alert_id": f"alert-{label}-{ordinal}",
                    "occurrence_id": f"occurrence-{label}-{ordinal}",
                    "observation_id": f"observation-{label}-{ordinal}",
                    "incident_group_id": f"incident-{group}",
                    "features": features,
                    "features_sha256": exact.sha256,
                    "candidate_sha256": hashlib.sha256(
                        f"candidate-{label_id}".encode()
                    ).hexdigest(),
                    "telemetry_sha256": hashlib.sha256(
                        f"telemetry-{label_id}".encode()
                    ).hexdigest(),
                    "label": label,
                    "reviewer_principal_id": "operator-one",
                    "label_source": "independent-ground-truth",
                }
            )
            if counts == {0: 100, 1: 100}:
                break
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "candidate.json"
            model = RiskModel()
            report = train_candidate(
                StructuredFeedback(rows),
                model,
                output,
                provenance_filter=self.provenance(model),
                require_structured_lineage=True,
            )
            self.assertTrue(report["accepted"], report["reasons"])
            self.assertTrue(output.exists())
            self.assertTrue(output.with_suffix(".json.dataset.json").exists())
            self.assertEqual(report["dataset_manifest"]["schema"], 3)
            self.assertTrue(report["feedback_holdout_metrics_before"])
            self.assertTrue(report["feedback_holdout_metrics_after"])


if __name__ == "__main__":
    unittest.main()
