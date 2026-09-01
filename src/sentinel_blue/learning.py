"""Poison-resistant, regression-gated post-use learning."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .json_codec import canonical_json_bytes
from .risk import FEATURES, RiskModel
from .simulator import evaluate, training_samples
from .store import Store
from .validation import ExactModelFeatures, MODEL_FEATURE_SCHEMA_SHA256


# These are admission floors, not a claim that 120 observations can certify a
# competition model. They prevent an empty, one-sided, or handful-sized set of
# operator decisions from producing a deployable artifact at all. Native range
# certification still requires a representative, independently labelled corpus.
MIN_FEEDBACK_SAMPLES = 120
MIN_FEEDBACK_PER_LABEL = 40
MIN_ACTIVE_FEATURES = 8
MIN_DISTINCT_SIGNATURES = 8
MIN_PAIRED_FEATURES = 6
MAX_SAMPLES_PER_SIGNATURE_LABEL = 32
MAX_WEIGHT_DELTA_FROM_BUNDLED = 0.20
METRIC_EPSILON = 1e-12
DATASET_MANIFEST_SCHEMA = 3
STRUCTURED_HOLDOUT_FRACTION = 0.20
MIN_STRUCTURED_INCIDENT_GROUPS = 4
MAX_STRUCTURED_SAMPLES = 10_000
PROVENANCE_FILTER_FIELDS = frozenset(
    {
        "campaign_id",
        "profile_id",
        "profile_fingerprint",
        "release_sha256",
        "agent_version",
        "model_fingerprint",
    }
)
SHA256_TEXT = re.compile(r"^[0-9a-f]{64}$")
PROVENANCE_TEXT = re.compile(r"^[A-Za-z0-9_.:@+-]{1,128}$")
LEARNING_SAMPLE_FIELDS = frozenset(
    {
        "label_id",
        "alert_id",
        "occurrence_id",
        "observation_id",
        "incident_group_id",
        "features",
        "features_sha256",
        "candidate_sha256",
        "telemetry_sha256",
        "label",
        "reviewer_principal_id",
        "label_source",
    }
)


class DatasetLineageError(ValueError):
    """Raised when exact learning lineage cannot form an isolated dataset."""


def _lineage_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not PROVENANCE_TEXT.fullmatch(value):
        raise DatasetLineageError(f"invalid_{label}")
    return value


def _lineage_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA256_TEXT.fullmatch(value):
        raise DatasetLineageError(f"invalid_{label}")
    return value


@dataclass(frozen=True, slots=True, init=False)
class LearningSample:
    """One immutable operator label joined to one exact alert occurrence."""

    label_id: str
    alert_id: str
    occurrence_id: str
    observation_id: str
    incident_group_id: str
    features: ExactModelFeatures
    candidate_sha256: str
    telemetry_sha256: str
    label: int
    reviewer_principal_id: str
    label_source: str
    lineage_sha256: str

    def __init__(self, value: Any) -> None:
        if isinstance(value, LearningSample):
            for field in self.__slots__:
                object.__setattr__(self, field, getattr(value, field))
            return
        if not isinstance(value, dict) or set(value) != LEARNING_SAMPLE_FIELDS:
            raise DatasetLineageError("learning_sample_schema_mismatch")
        try:
            exact_features = ExactModelFeatures(value["features"])
        except ValueError as exc:
            raise DatasetLineageError("invalid_exact_model_features") from exc
        expected_features_sha256 = _lineage_sha256(
            value["features_sha256"], "features_sha256"
        )
        if expected_features_sha256 != exact_features.sha256:
            raise DatasetLineageError("features_digest_mismatch")
        label = value["label"]
        if type(label) is not int or label not in {0, 1}:
            raise DatasetLineageError("invalid_learning_label")
        fields = {
            "label_id": _lineage_text(value["label_id"], "label_id"),
            "alert_id": _lineage_text(value["alert_id"], "alert_id"),
            "occurrence_id": _lineage_text(value["occurrence_id"], "occurrence_id"),
            "observation_id": _lineage_text(value["observation_id"], "observation_id"),
            "incident_group_id": _lineage_text(
                value["incident_group_id"], "incident_group_id"
            ),
            "candidate_sha256": _lineage_sha256(
                value["candidate_sha256"], "candidate_sha256"
            ),
            "telemetry_sha256": _lineage_sha256(
                value["telemetry_sha256"], "telemetry_sha256"
            ),
            "reviewer_principal_id": _lineage_text(
                value["reviewer_principal_id"], "reviewer_principal_id"
            ),
            "label_source": _lineage_text(value["label_source"], "label_source"),
        }
        lineage_payload = {
            **fields,
            "features": exact_features.as_dict(),
            "features_sha256": exact_features.sha256,
            "label": label,
        }
        for name, item in fields.items():
            object.__setattr__(self, name, item)
        object.__setattr__(self, "features", exact_features)
        object.__setattr__(self, "label", label)
        object.__setattr__(
            self,
            "lineage_sha256",
            hashlib.sha256(canonical_json_bytes(lineage_payload)).hexdigest(),
        )

    def feature_label(self) -> tuple[dict[str, float], int]:
        return self.features.as_dict(), self.label

    def manifest_entry(self, partition: str) -> dict[str, Any]:
        return {
            "label_id": self.label_id,
            "incident_group_id": self.incident_group_id,
            "label": self.label,
            "features_sha256": self.features.sha256,
            "lineage_sha256": self.lineage_sha256,
            "partition": partition,
        }


@dataclass(frozen=True, slots=True, init=False)
class DatasetManifest:
    """Canonical schema-3 manifest for group-isolated learning inputs."""

    provenance_fingerprint: str
    training_group_ids: tuple[str, ...]
    holdout_group_ids: tuple[str, ...]
    entries: tuple[tuple[str, str, int, str, str, str], ...]
    sha256: str

    def __init__(
        self,
        provenance_fingerprint: str,
        training: tuple[LearningSample, ...],
        holdout: tuple[LearningSample, ...],
    ) -> None:
        provenance = _lineage_sha256(
            provenance_fingerprint, "provenance_fingerprint"
        )
        training_groups = tuple(sorted({item.incident_group_id for item in training}))
        holdout_groups = tuple(sorted({item.incident_group_id for item in holdout}))
        if not training_groups or not holdout_groups or set(training_groups) & set(holdout_groups):
            raise DatasetLineageError("incident_group_partition_overlap")
        rows = [
            item.manifest_entry(partition)
            for partition, samples in (("training", training), ("holdout", holdout))
            for item in samples
        ]
        rows.sort(key=lambda row: row["label_id"])
        entries = tuple(
            (
                row["label_id"],
                row["incident_group_id"],
                row["label"],
                row["features_sha256"],
                row["lineage_sha256"],
                row["partition"],
            )
            for row in rows
        )
        object.__setattr__(self, "provenance_fingerprint", provenance)
        object.__setattr__(self, "training_group_ids", training_groups)
        object.__setattr__(self, "holdout_group_ids", holdout_groups)
        object.__setattr__(self, "entries", entries)
        object.__setattr__(
            self,
            "sha256",
            hashlib.sha256(canonical_json_bytes(self.as_dict())).hexdigest(),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": DATASET_MANIFEST_SCHEMA,
            "kind": "sentinel-blue-group-isolated-learning-dataset",
            "provenance_fingerprint": self.provenance_fingerprint,
            "feature_schema_sha256": MODEL_FEATURE_SCHEMA_SHA256,
            "training_group_ids": list(self.training_group_ids),
            "holdout_group_ids": list(self.holdout_group_ids),
            "training_sample_count": sum(
                1 for entry in self.entries if entry[5] == "training"
            ),
            "holdout_sample_count": sum(
                1 for entry in self.entries if entry[5] == "holdout"
            ),
            "samples": [
                {
                    "label_id": entry[0],
                    "incident_group_id": entry[1],
                    "label": entry[2],
                    "features_sha256": entry[3],
                    "lineage_sha256": entry[4],
                    "partition": entry[5],
                }
                for entry in self.entries
            ],
        }


def _normalize_provenance_filter(
    value: dict[str, Any], base_model: RiskModel
) -> tuple[dict[str, str], str]:
    if not isinstance(value, dict) or set(value) != PROVENANCE_FILTER_FIELDS:
        raise ValueError(
            "learning provenance_filter must contain the exact campaign, profile, "
            "release, agent-version, and model binding"
        )
    normalized: dict[str, str] = {}
    for name in ("campaign_id", "profile_id", "agent_version"):
        item = value.get(name)
        if not isinstance(item, str) or not PROVENANCE_TEXT.fullmatch(item):
            raise ValueError(f"learning provenance_filter {name} is invalid")
        normalized[name] = item
    for name in ("profile_fingerprint", "release_sha256", "model_fingerprint"):
        item = value.get(name)
        if not isinstance(item, str) or not SHA256_TEXT.fullmatch(item.casefold()):
            raise ValueError(f"learning provenance_filter {name} is not a SHA-256 digest")
        normalized[name] = item.casefold()
    if normalized["model_fingerprint"] != base_model.fingerprint():
        raise ValueError(
            "learning provenance_filter model_fingerprint does not match the supplied base model"
        )
    canonical = json.dumps(
        normalized,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")
    return normalized, hashlib.sha256(canonical).hexdigest()


def build_grouped_dataset(
    samples: list[LearningSample | dict[str, Any]],
    provenance_fingerprint: str,
) -> tuple[tuple[LearningSample, ...], tuple[LearningSample, ...], DatasetManifest]:
    """Split whole stable incident groups into deterministic train/holdout sets."""
    if not isinstance(samples, list) or len(samples) > MAX_STRUCTURED_SAMPLES:
        raise DatasetLineageError("structured_sample_limit_exceeded")
    normalized = tuple(sorted((LearningSample(item) for item in samples), key=lambda item: item.label_id))
    if len({item.label_id for item in normalized}) != len(normalized):
        raise DatasetLineageError("duplicate_label_id")
    if len({item.occurrence_id for item in normalized}) != len(normalized):
        raise DatasetLineageError("duplicate_occurrence_label")

    grouped: dict[str, list[LearningSample]] = defaultdict(list)
    for item in normalized:
        grouped[item.incident_group_id].append(item)
    if len(grouped) < MIN_STRUCTURED_INCIDENT_GROUPS:
        raise DatasetLineageError("insufficient_incident_groups")
    group_labels = {
        group_id: {item.label for item in group_samples}
        for group_id, group_samples in grouped.items()
    }
    for label in (0, 1):
        if sum(label in labels for labels in group_labels.values()) < 2:
            raise DatasetLineageError("insufficient_group_label_diversity")

    provenance = _lineage_sha256(
        provenance_fingerprint, "provenance_fingerprint"
    )
    ordered_groups = sorted(
        grouped,
        key=lambda group_id: (
            hashlib.sha256(
                f"{provenance}\x00{group_id}".encode("utf-8")
            ).hexdigest(),
            group_id,
        ),
    )
    target = max(2, math.ceil(len(ordered_groups) * STRUCTURED_HOLDOUT_FRACTION))
    target = min(target, len(ordered_groups) - 2)
    selected: list[str] = []

    def selected_labels() -> set[int]:
        return set().union(*(group_labels[group_id] for group_id in selected)) if selected else set()

    def leaves_training_labels(candidate: str) -> bool:
        removed = {*selected, candidate}
        remaining_labels = set().union(
            *(labels for group_id, labels in group_labels.items() if group_id not in removed)
        )
        return remaining_labels == {0, 1}

    for label in (0, 1):
        if label in selected_labels():
            continue
        candidate = next(
            (
                group_id
                for group_id in ordered_groups
                if group_id not in selected
                and label in group_labels[group_id]
                and leaves_training_labels(group_id)
            ),
            None,
        )
        if candidate is None:
            raise DatasetLineageError("incident_group_holdout_unsatisfied")
        selected.append(candidate)
    for group_id in ordered_groups:
        if len(selected) >= target:
            break
        if group_id not in selected and leaves_training_labels(group_id):
            selected.append(group_id)
    if len(selected) < 2:
        raise DatasetLineageError("incident_group_holdout_unsatisfied")

    holdout_groups = set(selected)
    training = tuple(
        item for item in normalized if item.incident_group_id not in holdout_groups
    )
    holdout = tuple(
        item for item in normalized if item.incident_group_id in holdout_groups
    )
    if (
        {item.label for item in training} != {0, 1}
        or {item.label for item in holdout} != {0, 1}
    ):
        raise DatasetLineageError("incident_group_label_partition_invalid")
    manifest = DatasetManifest(provenance, training, holdout)
    return training, holdout, manifest


def _feature_signature(features: dict[str, float]) -> tuple[tuple[str, float], ...]:
    return tuple(
        (name, float(features.get(name, 0.0)))
        for name in FEATURES
        if float(features.get(name, 0.0)) > 0.0
    )


def _eligible_feedback(
    feedback: list[tuple[dict[str, float], int]],
) -> list[tuple[dict[str, float], int]]:
    # Unknown and malformed values already fail closed in Store. Empty feature
    # maps arise from alert kinds that have no learning contract and must never
    # count toward a candidate's evidence floor.
    return [
        (dict(features), label)
        for features, label in feedback
        if _feature_signature(features)
    ]


def _feedback_readiness(
    feedback: list[tuple[dict[str, float], int]],
) -> tuple[list[str], dict[str, Any]]:
    labels = Counter(label for _, label in feedback)
    signatures = {_feature_signature(features) for features, _ in feedback}
    feature_labels: dict[str, set[int]] = defaultdict(set)
    for features, label in feedback:
        for name, value in features.items():
            if value > 0.0:
                feature_labels[name].add(label)
    active_features = sorted(feature_labels)
    paired_features = sorted(
        name for name, observed_labels in feature_labels.items() if observed_labels == {0, 1}
    )
    reasons: list[str] = []
    if len(feedback) < MIN_FEEDBACK_SAMPLES:
        reasons.append("insufficient_feedback_samples")
    if labels[0] < MIN_FEEDBACK_PER_LABEL or labels[1] < MIN_FEEDBACK_PER_LABEL:
        reasons.append("insufficient_label_balance")
    if len(active_features) < MIN_ACTIVE_FEATURES:
        reasons.append("insufficient_feature_coverage")
    if len(signatures) < MIN_DISTINCT_SIGNATURES:
        reasons.append("insufficient_signature_diversity")
    if len(paired_features) < MIN_PAIRED_FEATURES:
        reasons.append("insufficient_paired_feature_evidence")
    return reasons, {
        "eligible_feedback": len(feedback),
        "label_counts": {"benign": labels[0], "incident": labels[1]},
        "active_features": active_features,
        "distinct_signatures": len(signatures),
        "paired_features": paired_features,
    }


def _bounded_training_feedback(
    feedback: list[tuple[dict[str, float], int]],
) -> list[tuple[dict[str, float], int]]:
    """Deterministically cap any one feature/label stratum's influence."""
    groups: dict[
        tuple[tuple[tuple[str, float], ...], int],
        tuple[dict[str, float], int, int],
    ] = {}
    for features, label in feedback:
        key = (_feature_signature(features), label)
        prior = groups.get(key)
        if prior is None:
            groups[key] = (dict(features), label, 1)
        else:
            groups[key] = (prior[0], prior[1], prior[2] + 1)
    result: list[tuple[dict[str, float], int]] = []
    ordered = [groups[key] for key in sorted(groups)]
    maximum = min(
        MAX_SAMPLES_PER_SIGNATURE_LABEL,
        max((count for _, _, count in ordered), default=0),
    )
    for index in range(maximum):
        for features, label, count in ordered:
            if index < min(count, MAX_SAMPLES_PER_SIGNATURE_LABEL):
                result.append((features, label))
    return result


def _bounded_structured_feedback(
    samples: tuple[LearningSample, ...],
) -> tuple[LearningSample, ...]:
    """Cap feature/label strata without discarding immutable sample identity."""
    groups: dict[
        tuple[tuple[tuple[str, float], ...], int], list[LearningSample]
    ] = defaultdict(list)
    for sample in samples:
        groups[(_feature_signature(sample.features.as_dict()), sample.label)].append(sample)
    for group in groups.values():
        group.sort(key=lambda item: (item.lineage_sha256, item.label_id))
    ordered_keys = sorted(groups)
    maximum = min(
        MAX_SAMPLES_PER_SIGNATURE_LABEL,
        max((len(groups[key]) for key in ordered_keys), default=0),
    )
    bounded: list[LearningSample] = []
    for index in range(maximum):
        for key in ordered_keys:
            if index < min(len(groups[key]), MAX_SAMPLES_PER_SIGNATURE_LABEL):
                bounded.append(groups[key][index])
    return tuple(bounded)


def score_metrics(
    model: RiskModel, samples: list[tuple[dict[str, float], int]]
) -> dict[str, float]:
    """Measure threshold behavior, calibration, loss, and ranking."""
    if not samples:
        raise ValueError("model evaluation requires labelled samples")
    scored = [(model.predict(features), label) for features, label in samples]
    accuracy = sum((score >= 0.5) == bool(label) for score, label in scored) / len(scored)
    brier = sum((score - float(label)) ** 2 for score, label in scored) / len(scored)
    log_loss = -sum(
        float(label) * math.log(max(METRIC_EPSILON, min(1.0 - METRIC_EPSILON, score)))
        + (1.0 - float(label))
        * math.log(max(METRIC_EPSILON, min(1.0 - METRIC_EPSILON, 1.0 - score)))
        for score, label in scored
    ) / len(scored)
    positive = [score for score, label in scored if label == 1]
    negative = [score for score, label in scored if label == 0]
    if not positive or not negative:
        raise ValueError("model evaluation requires both labels")
    wins = sum(
        1.0
        if positive_score > negative_score
        else 0.5
        if positive_score == negative_score
        else 0.0
        for positive_score in positive
        for negative_score in negative
    )
    roc_auc = wins / (len(positive) * len(negative))
    return {
        "accuracy": accuracy,
        "brier": brier,
        "log_loss": log_loss,
        "roc_auc": roc_auc,
    }


def _write_report(output_path: Path, report: dict[str, Any]) -> None:
    from .state import write_private_json

    report_path = output_path.with_suffix(output_path.suffix + ".report.json")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    write_private_json(report_path, report)


def _write_dataset_manifest(output_path: Path, manifest: DatasetManifest) -> None:
    from .state import write_private_json

    manifest_path = output_path.with_suffix(output_path.suffix + ".dataset.json")
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    write_private_json(
        manifest_path,
        {**manifest.as_dict(), "dataset_manifest_sha256": manifest.sha256},
    )


def _paths_alias(left: str | Path, right: str | Path) -> bool:
    first = Path(left)
    second = Path(right)
    if first.resolve() == second.resolve():
        return True
    if first.exists() and second.exists():
        try:
            return os.path.samefile(first, second)
        except OSError:
            return False
    return False


def train_candidate(
    store: Store,
    base_model: RiskModel,
    output: str | Path,
    provenance_filter: dict[str, Any] | None = None,
    *,
    require_structured_lineage: bool = False,
) -> dict[str, Any]:
    synthetic = training_samples(seed=7331, count=2500)
    split = int(len(synthetic) * 0.8)
    regression = synthetic[split:]
    output_path = Path(output)
    if provenance_filter is None:
        report = {
            "accepted": False,
            "reasons": ["missing_provenance_filter"],
            "recorded_feedback": 0,
            "ignored_unmapped_feedback": 0,
            "eligible_feedback": 0,
            "label_counts": {"benign": 0, "incident": 0},
            "active_features": [],
            "distinct_signatures": 0,
            "paired_features": [],
            "synthetic_regression_samples": len(regression),
            "trusted_base_fingerprint": RiskModel.bundled().fingerprint(),
            "supplied_base_fingerprint": base_model.fingerprint(),
            "provenance_filter": None,
            "provenance_fingerprint": None,
            "structured_lineage": False,
            "dataset_manifest": None,
            "dataset_manifest_sha256": None,
            "feedback_holdout_metrics_before": None,
            "feedback_holdout_metrics_after": None,
            "maximum_weight_delta_from_bundled": MAX_WEIGHT_DELTA_FROM_BUNDLED,
            "metrics_before": None,
            "metrics_after": None,
            "accuracy_before": None,
            "accuracy_after": None,
            "precision_after": None,
            "recall_after": None,
            "output": None,
        }
        _write_report(output_path, report)
        return report
    normalized_provenance, provenance_fingerprint = _normalize_provenance_filter(
        provenance_filter, base_model
    )

    structured_reader = getattr(store, "learning_samples", None)
    structured = callable(structured_reader)
    structured_samples: tuple[LearningSample, ...] = ()
    holdout_samples: tuple[LearningSample, ...] = ()
    manifest: DatasetManifest | None = None
    lineage_reasons: list[str] = []
    recorded_count = 0
    ignored_count = 0
    if structured:
        raw_samples = structured_reader(provenance_filter=normalized_provenance)
        if not isinstance(raw_samples, list):
            raise DatasetLineageError("structured_samples_must_be_a_list")
        recorded_count = len(raw_samples)
        try:
            structured_samples, holdout_samples, manifest = build_grouped_dataset(
                raw_samples, provenance_fingerprint
            )
        except DatasetLineageError as exc:
            lineage_reasons.append(str(exc))
        feedback = [sample.feature_label() for sample in structured_samples]
    elif require_structured_lineage:
        feedback = []
        lineage_reasons.append("missing_structured_learning_lineage")
    else:
        recorded_feedback = store.feedback_samples(
            provenance_filter=normalized_provenance
        )
        recorded_count = len(recorded_feedback)
        feedback = _eligible_feedback(recorded_feedback)
        ignored_count = recorded_count - len(feedback)
    readiness_reasons, readiness = _feedback_readiness(feedback)
    readiness_reasons = [*lineage_reasons, *readiness_reasons]

    # Every generation is rebuilt from the model inside this exact runtime.
    # The caller's active model is lineage evidence only; it can never become a
    # moving clamp anchor that ratchets on repeated restarts.
    trusted_base = RiskModel.bundled()
    candidate = RiskModel(weights=dict(trusted_base.weights), bias=trusted_base.bias)
    before_metrics = score_metrics(trusted_base, regression)
    before_scenarios = evaluate(trusted_base)
    holdout_feedback = [sample.feature_label() for sample in holdout_samples]
    holdout_before_metrics = (
        score_metrics(trusted_base, holdout_feedback) if holdout_feedback else None
    )
    report: dict[str, Any] = {
        "accepted": False,
        "reasons": list(readiness_reasons),
        "recorded_feedback": recorded_count,
        "ignored_unmapped_feedback": ignored_count,
        **readiness,
        "structured_lineage": structured,
        "structured_training_samples": len(structured_samples),
        "structured_holdout_samples": len(holdout_samples),
        "dataset_manifest": manifest.as_dict() if manifest else None,
        "dataset_manifest_sha256": manifest.sha256 if manifest else None,
        "synthetic_regression_samples": len(regression),
        "trusted_base_fingerprint": trusted_base.fingerprint(),
        "supplied_base_fingerprint": base_model.fingerprint(),
        "provenance_filter": normalized_provenance,
        "provenance_fingerprint": provenance_fingerprint,
        "maximum_weight_delta_from_bundled": MAX_WEIGHT_DELTA_FROM_BUNDLED,
        "metrics_before": {name: round(value, 6) for name, value in before_metrics.items()},
        "metrics_after": None,
        "feedback_holdout_metrics_before": (
            {
                name: round(value, 6)
                for name, value in holdout_before_metrics.items()
            }
            if holdout_before_metrics
            else None
        ),
        "feedback_holdout_metrics_after": None,
        "accuracy_before": round(before_metrics["accuracy"], 4),
        "accuracy_after": None,
        "precision_after": before_scenarios["precision"],
        "recall_after": before_scenarios["recall"],
        "output": None,
    }
    if manifest is not None:
        _write_dataset_manifest(output_path, manifest)
    if readiness_reasons:
        _write_report(output_path, report)
        return report

    if manifest is not None:
        bounded_structured = _bounded_structured_feedback(structured_samples)
        bounded_feedback = [sample.feature_label() for sample in bounded_structured]
        fingerprint_payload = {
            "schema": DATASET_MANIFEST_SCHEMA,
            "provenance_fingerprint": provenance_fingerprint,
            "dataset_manifest_sha256": manifest.sha256,
            "effective_training_label_ids": [
                sample.label_id for sample in bounded_structured
            ],
        }
    else:
        bounded_feedback = _bounded_training_feedback(feedback)
        fingerprint_payload = {
            "schema": 2,
            "provenance_fingerprint": provenance_fingerprint,
            "samples": [
                {"features": _feature_signature(features), "label": label}
                for features, label in bounded_feedback
            ],
        }
    report["training_feedback"] = len(bounded_feedback)
    training_data_fingerprint = hashlib.sha256(
        canonical_json_bytes(fingerprint_payload)
    ).hexdigest()
    report["training_data_fingerprint"] = training_data_fingerprint
    for features, label in bounded_feedback:
        prediction = candidate.predict(features)
        error = float(label) - prediction
        for name, value in features.items():
            if not value:
                continue
            trusted_weight = trusted_base.weights[name]
            proposed = candidate.weights[name] + 0.02 * error * float(value)
            candidate.weights[name] = max(
                trusted_weight - MAX_WEIGHT_DELTA_FROM_BUNDLED,
                min(trusted_weight + MAX_WEIGHT_DELTA_FROM_BUNDLED, proposed),
            )

    maximum_delta = max(
        abs(candidate.weights[name] - trusted_base.weights[name]) for name in FEATURES
    )
    after_metrics = score_metrics(candidate, regression)
    after_scenarios = evaluate(candidate)
    holdout_after_metrics = (
        score_metrics(candidate, holdout_feedback) if holdout_feedback else None
    )
    report["metrics_after"] = {
        name: round(value, 6) for name, value in after_metrics.items()
    }
    report["accuracy_after"] = round(after_metrics["accuracy"], 4)
    report["feedback_holdout_metrics_after"] = (
        {
            name: round(value, 6)
            for name, value in holdout_after_metrics.items()
        }
        if holdout_after_metrics
        else None
    )
    report["precision_after"] = after_scenarios["precision"]
    report["recall_after"] = after_scenarios["recall"]
    report["observed_maximum_weight_delta"] = round(maximum_delta, 12)

    regressions: list[str] = []
    if after_metrics["accuracy"] + METRIC_EPSILON < before_metrics["accuracy"]:
        regressions.append("accuracy_regression")
    if after_metrics["brier"] > before_metrics["brier"] + METRIC_EPSILON:
        regressions.append("brier_regression")
    if after_metrics["log_loss"] > before_metrics["log_loss"] + METRIC_EPSILON:
        regressions.append("log_loss_regression")
    if after_metrics["roc_auc"] + METRIC_EPSILON < before_metrics["roc_auc"]:
        regressions.append("roc_auc_regression")
    if after_scenarios["precision"] < before_scenarios["precision"]:
        regressions.append("scenario_precision_regression")
    if after_scenarios["recall"] < before_scenarios["recall"]:
        regressions.append("scenario_recall_regression")
    if maximum_delta > MAX_WEIGHT_DELTA_FROM_BUNDLED + METRIC_EPSILON:
        regressions.append("immutable_base_delta_exceeded")

    if holdout_before_metrics is not None and holdout_after_metrics is not None:
        if (
            holdout_after_metrics["accuracy"] + METRIC_EPSILON
            < holdout_before_metrics["accuracy"]
        ):
            regressions.append("feedback_holdout_accuracy_regression")
        if (
            holdout_after_metrics["brier"]
            > holdout_before_metrics["brier"] + METRIC_EPSILON
        ):
            regressions.append("feedback_holdout_brier_regression")
        if (
            holdout_after_metrics["log_loss"]
            > holdout_before_metrics["log_loss"] + METRIC_EPSILON
        ):
            regressions.append("feedback_holdout_log_loss_regression")
        if (
            holdout_after_metrics["roc_auc"] + METRIC_EPSILON
            < holdout_before_metrics["roc_auc"]
        ):
            regressions.append("feedback_holdout_roc_auc_regression")

    improved = (
        after_metrics["accuracy"] > before_metrics["accuracy"] + METRIC_EPSILON
        or after_metrics["brier"] + METRIC_EPSILON < before_metrics["brier"]
        or after_metrics["log_loss"] + METRIC_EPSILON < before_metrics["log_loss"]
        or after_metrics["roc_auc"] > before_metrics["roc_auc"] + METRIC_EPSILON
    )
    holdout_improved = bool(
        holdout_before_metrics is not None
        and holdout_after_metrics is not None
        and (
            holdout_after_metrics["accuracy"]
            > holdout_before_metrics["accuracy"] + METRIC_EPSILON
            or holdout_after_metrics["brier"] + METRIC_EPSILON
            < holdout_before_metrics["brier"]
            or holdout_after_metrics["log_loss"] + METRIC_EPSILON
            < holdout_before_metrics["log_loss"]
            or holdout_after_metrics["roc_auc"]
            > holdout_before_metrics["roc_auc"] + METRIC_EPSILON
        )
    )
    if not improved and not holdout_improved:
        regressions.append("no_score_metric_improvement")
    report["reasons"] = regressions
    report["accepted"] = not regressions
    if report["accepted"]:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        candidate.save(
            output_path,
            lineage={
                "schema": 1,
                "kind": "sentinel-blue-adaptive-confidence-model",
                "trusted_base_fingerprint": trusted_base.fingerprint(),
                "training_data_fingerprint": training_data_fingerprint,
                "maximum_weight_delta_from_bundled": MAX_WEIGHT_DELTA_FROM_BUNDLED,
                "regression_metrics": report["metrics_after"],
            },
        )
        report["output"] = str(output_path.resolve())
    _write_report(output_path, report)
    return report


def run(args: argparse.Namespace) -> None:
    reserved = [("controller database", args.database)]
    if args.base_model:
        reserved.append(("supplied base model", args.base_model))
    for label, path in reserved:
        if _paths_alias(args.output, path):
            raise ValueError(f"adaptive output must differ from the {label}")
    store = Store(args.database)
    try:
        model = RiskModel.load(args.base_model) if args.base_model else RiskModel.bundled()
        provenance_filter = {
            name: getattr(args, name, None)
            for name in PROVENANCE_FILTER_FIELDS
        }
        if any(value is None for value in provenance_filter.values()):
            raise ValueError(
                "learning requires an exact campaign, profile, release, "
                "agent-version, and model provenance filter"
            )
        print(
            json.dumps(
                train_candidate(
                    store,
                    model,
                    args.output,
                    provenance_filter=provenance_filter,
                    require_structured_lineage=True,
                ),
                indent=2,
            )
        )
    finally:
        store.close()
