import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import sentinel_blue.risk as risk_module
from sentinel_blue.risk import RiskModel


class RiskModelTests(unittest.TestCase):
    def test_bundled_model_is_the_immutable_default_lineage(self):
        bundled = RiskModel.bundled()
        default = RiskModel()
        self.assertEqual(bundled.fingerprint(), default.fingerprint())
        changed = RiskModel(weights=dict(bundled.weights), bias=bundled.bias)
        changed.weights["probe_failure"] += 0.01
        self.assertNotEqual(changed.fingerprint(), bundled.fingerprint())

    def test_model_rejects_nonfinite_or_incomplete_weights(self):
        model = RiskModel()
        valid = {"bias": model.bias, "weights": dict(model.weights)}
        with self.assertRaises(ValueError):
            RiskModel.from_dict({**valid, "bias": float("nan")})
        incomplete = {**valid, "weights": {"probe_failure": 1.0}}
        with self.assertRaises(ValueError):
            RiskModel.from_dict(incomplete)

    def test_model_rejects_overflow_and_values_outside_absolute_bounds(self):
        model = RiskModel()
        valid = {"bias": model.bias, "weights": dict(model.weights)}
        for invalid_bias in (30.0001, float("inf"), 10**400):
            with self.subTest(field="bias", value=str(invalid_bias)[:32]):
                with self.assertRaisesRegex(ValueError, "safe range"):
                    RiskModel.from_dict({**valid, "bias": invalid_bias})
        for invalid_weight in (20.0001, float("-inf"), 10**400):
            weights = dict(model.weights)
            weights["probe_failure"] = invalid_weight
            with self.subTest(field="weight", value=str(invalid_weight)[:32]):
                with self.assertRaisesRegex(ValueError, "safe range"):
                    RiskModel.from_dict({"bias": model.bias, "weights": weights})

    def test_verified_load_hashes_and_parses_the_same_byte_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "model.json"
            original = RiskModel()
            original.save(path)
            expected = hashlib.sha256(path.read_bytes()).hexdigest()
            replacement = RiskModel(weights=dict(original.weights), bias=original.bias)
            replacement.weights["probe_failure"] += 0.1
            strict_json = risk_module._strict_json

            def replace_before_parse(raw):
                replacement.save(path)
                return strict_json(raw)

            with patch.object(risk_module, "_strict_json", side_effect=replace_before_parse):
                loaded = RiskModel.load_verified(path, expected)
            self.assertEqual(loaded.fingerprint(), original.fingerprint())
            self.assertEqual(RiskModel.load(path).fingerprint(), replacement.fingerprint())

    def test_verified_load_rejects_mismatch_duplicate_keys_and_nonstandard_numbers(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "model.json"
            model = RiskModel()
            model.save(path)
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            with self.assertRaisesRegex(ValueError, "digest"):
                RiskModel.load_verified(path, "0" * 64)
            valid = json.loads(path.read_text(encoding="utf-8"))
            path.write_text(
                '{"bias":-1.1,"bias":0,"weights":'
                + json.dumps(valid["weights"], sort_keys=True)
                + "}",
                encoding="utf-8",
            )
            duplicate_digest = hashlib.sha256(path.read_bytes()).hexdigest()
            with self.assertRaisesRegex(ValueError, "duplicate field"):
                RiskModel.load_verified(path, duplicate_digest)
            path.write_text(
                '{"bias":NaN,"weights":' + json.dumps(valid["weights"]) + "}",
                encoding="utf-8",
            )
            nonfinite_digest = hashlib.sha256(path.read_bytes()).hexdigest()
            with self.assertRaisesRegex(ValueError, "non-finite"):
                RiskModel.load_verified(path, nonfinite_digest)

    def test_save_and_fingerprint_refuse_invalid_in_memory_numeric_state(self):
        with tempfile.TemporaryDirectory() as directory:
            model = RiskModel()
            model.weights["probe_failure"] = float("nan")
            output = Path(directory) / "invalid.json"
            with self.assertRaisesRegex(ValueError, "safe range"):
                model.save(output)
            with self.assertRaisesRegex(ValueError, "safe range"):
                model.fingerprint()
            self.assertFalse(output.exists())

    def test_model_rejects_string_and_boolean_number_coercion(self):
        model = RiskModel()
        valid = {"bias": model.bias, "weights": dict(model.weights)}
        for coerced in ("-1.1", True):
            with self.subTest(field="bias", value=coerced):
                with self.assertRaisesRegex(ValueError, "without type coercion"):
                    RiskModel.from_dict({**valid, "bias": coerced})
        for coerced in ("1.4", False):
            weights = dict(model.weights)
            weights["unknown_privileged_account"] = coerced
            with self.subTest(field="weight", value=coerced):
                with self.assertRaisesRegex(ValueError, "without type coercion"):
                    RiskModel.from_dict({"bias": model.bias, "weights": weights})


if __name__ == "__main__":
    unittest.main()
