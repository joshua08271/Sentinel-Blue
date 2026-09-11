import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sentinel_blue.event_profile import EventProfile
from sentinel_blue.setup import compile_plan
from sentinel_blue.setup_transport import run_process
from tools.setup_native_rehearsal import linux_inputs, profile_inventory


@unittest.skipUnless(os.name == "posix", "Linux input compilation and shell syntax")
class NativeSetupInputTests(unittest.TestCase):
    def test_four_service_rehearsal_compiles_and_all_generated_scripts_parse(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "fixture.pyz"
            runtime.write_bytes(b"non-executed parser fixture")
            tasks, services, initial, identities, cleanup, secrets = linux_inputs(root, "unitparser")
            inventory = profile_inventory(runtime, tasks, services)
            plan = compile_plan(inventory, EventProfile.from_dict(inventory["event_profile"]), root)
            self.assertEqual(plan["uncovered_services"], [])
            self.assertEqual(len(services), 4)
            self.assertEqual(len(tasks), 7)
            for task in plan["tasks"]:
                for phase in ["check", "apply"]:
                    with self.subTest(task=task["id"], phase=phase):
                        result = run_process(["bash", "-n"], task[phase], 3)
                        self.assertEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
