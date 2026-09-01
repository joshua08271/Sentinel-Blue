import tempfile
import unittest
from pathlib import Path

from sentinel_blue.diagnostics import doctor
from sentinel_blue.store import Store


class DiagnosticsTests(unittest.TestCase):
    def test_doctor_checks_resources_and_database(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "controller.db"
            store = Store(database)
            store.close()
            result = doctor(Path(directory) / "state", database)
            self.assertTrue(result["ready"])
            self.assertEqual(result["required_failures"], 0)


if __name__ == "__main__":
    unittest.main()
