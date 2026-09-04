import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from sentinel_blue.change_watch import ChangeWatcher


class ChangeWatcherTests(unittest.TestCase):
    def test_live_file_change_wakes_waiter_and_names_target(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "protected.conf"
            target.write_text("approved", encoding="utf-8")
            watcher = ChangeWatcher([str(target)], poll_interval=0.1)
            watcher.start()
            try:
                time.sleep(0.05)
                target.write_text("changed", encoding="utf-8")
                self.assertTrue(watcher.wait(2.0))
                self.assertEqual(watcher.changed_paths(), [str(target)])
            finally:
                watcher.stop()

    def test_portable_fingerprint_fallback_detects_delete_and_recreate(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "protected.conf"
            target.write_text("approved", encoding="utf-8")
            watcher = ChangeWatcher([str(target)], poll_interval=0.1)
            with patch.object(watcher, "_open_inotify", return_value=(-1, {})):
                watcher.start()
                try:
                    target.unlink()
                    self.assertTrue(watcher.wait(2.0))
                    self.assertIn(str(target), watcher.changed_paths())
                    target.write_text("recreated", encoding="utf-8")
                    self.assertTrue(watcher.wait(2.0))
                    self.assertIn(str(target), watcher.changed_paths())
                finally:
                    watcher.stop()

    def test_paths_are_absolute_deduplicated_and_bounded(self):
        root = Path(tempfile.gettempdir()).resolve()
        paths = [str(root / f"sentinel-watch-{index}") for index in range(300)]
        watcher = ChangeWatcher([paths[0], paths[0], "relative", *paths[1:]])
        self.assertEqual(len(watcher.paths), 256)
        self.assertEqual(str(watcher.paths[0]), paths[0])


if __name__ == "__main__":
    unittest.main()
