import subprocess
import unittest
import hashlib
import os
import ssl
import tempfile
from pathlib import Path
from unittest.mock import patch

from sentinel_blue.config_validation import (
    require_https_controller_origin,
    validate_bound_transport,
    validate_controller_ca_binding,
    validate_restored_configuration,
    validate_tls_server_material,
    validation_command,
)
from sentinel_blue.event_profile import EventProfile
from tests.test_event_profile import live_profile


class ConfigValidationTests(unittest.TestCase):
    def test_checksum_bound_controller_origins_require_https(self):
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            require_https_controller_origin("http://192.0.2.1:8765")
        self.assertEqual(
            require_https_controller_origin("https://192.0.2.1:8765/"),
            "https://192.0.2.1:8765",
        )

    def test_controller_ca_is_exactly_bound_and_parsed(self):
        with tempfile.TemporaryDirectory() as directory:
            ca_file = Path(directory) / "controller-ca.crt"
            ca_file.write_bytes(b"fixture PEM bytes")
            payload = live_profile()
            payload["release"]["controller_ca_sha256"] = hashlib.sha256(
                ca_file.read_bytes()
            ).hexdigest()
            profile = EventProfile.from_dict(payload)
            with patch(
                "sentinel_blue.config_validation.ssl.create_default_context"
            ) as create_context:
                self.assertEqual(
                    validate_controller_ca_binding(profile, ca_file), ca_file
                )
            create_context.assert_called_once_with(cafile=str(ca_file))
            ca_file.write_bytes(b"substituted PEM bytes")
            with self.assertRaisesRegex(ValueError, "digest"):
                validate_controller_ca_binding(profile, ca_file)

    def test_malformed_ca_and_server_key_permissions_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ca_file = root / "controller-ca.crt"
            ca_file.write_bytes(b"invalid PEM")
            payload = live_profile()
            payload["release"]["controller_ca_sha256"] = hashlib.sha256(
                ca_file.read_bytes()
            ).hexdigest()
            profile = EventProfile.from_dict(payload)
            with patch(
                "sentinel_blue.config_validation.ssl.create_default_context",
                side_effect=ssl.SSLError("bad CA"),
            ):
                with self.assertRaisesRegex(ValueError, "valid PEM"):
                    validate_controller_ca_binding(profile, ca_file)
            cert = root / "server.crt"
            key = root / "server.key"
            cert.write_bytes(b"certificate")
            key.write_bytes(b"private key")
            key.chmod(0o644)
            if os.name == "posix":
                with self.assertRaisesRegex(ValueError, "group- or world"):
                    validate_tls_server_material(cert, key)

    def test_unbound_disposable_library_profile_preserves_http_compatibility(self):
        validate_bound_transport(
            EventProfile.testing(), role="agent", controller="http://127.0.0.1:8765"
        )

    def test_allowlisted_paths_use_fixed_argument_vectors(self):
        with patch("sentinel_blue.config_validation.shutil.which", return_value="/usr/sbin/sshd"):
            self.assertEqual(
                validation_command("/etc/ssh/sshd_config"),
                ("/usr/sbin/sshd", ["-t", "-f", "/etc/ssh/sshd_config"]),
            )
        self.assertIsNone(validation_command("/tmp/unrecognized.conf"))

    def test_validator_failure_is_bounded_and_reported(self):
        completed = subprocess.CompletedProcess([], 1, "", "invalid directive")
        with (
            patch("sentinel_blue.config_validation.shutil.which", return_value="/usr/sbin/visudo"),
            patch("sentinel_blue.config_validation.subprocess.run", return_value=completed) as execute,
        ):
            result = validate_restored_configuration("/etc/sudoers")
        self.assertFalse(result["healthy"])
        self.assertEqual(execute.call_args.args[0], ["/usr/sbin/visudo", "-c", "-f", "/etc/sudoers"])
        self.assertFalse(execute.call_args.kwargs.get("shell", False))

    def test_windows_openssh_path_uses_fixed_sshd_validator(self):
        with (
            patch("sentinel_blue.config_validation.Path.is_file", return_value=False),
            patch("sentinel_blue.config_validation.shutil.which", return_value="C:\\OpenSSH\\sshd.exe"),
        ):
            selected = validation_command("C:\\ProgramData\\ssh\\sshd_config")
        self.assertEqual(
            selected,
            (
                "C:\\OpenSSH\\sshd.exe",
                ["-t", "-f", "C:\\ProgramData\\ssh\\sshd_config"],
            ),
        )


if __name__ == "__main__":
    unittest.main()
