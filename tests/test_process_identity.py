import os
import signal
import unittest
from unittest.mock import patch

from sentinel_blue.process_identity import (
    ProcessIdentityMismatch,
    signal_verified_process,
    validate_process_identity,
)


def _identity(process_id: int = 4242, *, start_time: str = "123456") -> dict:
    return {
        "schema": "sentinel-process-v1",
        "platform": "linux",
        "process_id": process_id,
        "boot_id": "95b2c85c-f17a-49e5-bace-ff36caaa0001",
        "start_time": start_time,
        "executable_path": "/usr/bin/fixture",
        "executable_file_id": "dev:1:ino:2",
        "user_id": "uid:1000:1000",
        "kernel_session_id": "99",
    }


class ProcessIdentityTests(unittest.TestCase):
    def test_identity_schema_is_exact_and_rejects_type_confusion(self):
        expected = _identity()
        self.assertEqual(validate_process_identity(expected), expected)
        for mutation in (
            {**expected, "unknown": "field"},
            {key: value for key, value in expected.items() if key != "start_time"},
            {**expected, "process_id": True},
            {**expected, "boot_id": "unknown"},
            {**expected, "start_time": "12.5"},
        ):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                validate_process_identity(mutation)

    @unittest.skipUnless(
        hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"),
        "Linux pidfd process control is unavailable",
    )
    def test_pid_reuse_identity_mismatch_never_signals_replacement(self):
        expected = _identity(start_time="123456")
        replacement = _identity(start_time="987654")
        with (
            patch("sentinel_blue.process_identity.platform.system", return_value="Linux"),
            patch("sentinel_blue.process_identity.os.pidfd_open", return_value=71) as opener,
            patch(
                "sentinel_blue.process_identity._linux_process_identity",
                return_value=replacement,
            ),
            patch("sentinel_blue.process_identity.signal.pidfd_send_signal") as sender,
            patch("sentinel_blue.process_identity.os.close") as closer,
        ):
            with self.assertRaises(ProcessIdentityMismatch):
                signal_verified_process(4242, expected, "suspend")
        opener.assert_called_once_with(4242, 0)
        sender.assert_not_called()
        closer.assert_called_once_with(71)

    @unittest.skipUnless(
        hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"),
        "Linux pidfd process control is unavailable",
    )
    def test_verified_signal_uses_pidfd_after_exact_revalidation(self):
        expected = _identity()
        with (
            patch("sentinel_blue.process_identity.platform.system", return_value="Linux"),
            patch("sentinel_blue.process_identity.os.pidfd_open", return_value=72),
            patch(
                "sentinel_blue.process_identity._linux_process_identity",
                return_value=expected,
            ),
            patch("sentinel_blue.process_identity.signal.pidfd_send_signal") as sender,
            patch("sentinel_blue.process_identity.os.close"),
        ):
            signal_verified_process(4242, expected, "resume")
        sender.assert_called_once_with(72, signal.SIGCONT)


if __name__ == "__main__":
    unittest.main()
