import socket
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

from sentinel_blue.controller import ControllerApp
from sentinel_blue.event_profile import EventProfile
from sentinel_blue.store import Store
from sentinel_blue.syslog_monitor import SyslogMonitor, classify
from tests.test_event_profile import live_profile


class SyslogTests(unittest.TestCase):
    def test_classifier(self):
        self.assertEqual(classify("useradd unexpected-maint")[0], "high")
        self.assertEqual(classify("Failed password for root")[0], "medium")

    def test_udp_event_is_stored(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "syslog.db")
            app = ControllerApp(store, "a" * 32, operator_token="o" * 32)
            monitor = SyslogMonitor(app, "127.0.0.1", 0)
            monitor.start()
            try:
                sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sender.sendto(b"useradd suspicious", monitor.address)
                sender.close()
                for _ in range(20):
                    if store.dashboard()["events"]:
                        break
                    time.sleep(0.02)
                self.assertEqual(store.dashboard()["events"][0]["severity"], "high")
            finally:
                monitor.stop()
                store.close()

    def test_checksum_bound_profiles_refuse_unauthenticated_udp_syslog(self):
        app = SimpleNamespace(event_profile=EventProfile.from_dict(live_profile()))
        with self.assertRaisesRegex(ValueError, "unauthenticated UDP syslog"):
            SyslogMonitor(app, "127.0.0.1", 0)


if __name__ == "__main__":
    unittest.main()
