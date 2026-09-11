import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from tools.azure_setup_guest import validate_guest
from tools import azure_setup_guest


class AzureSetupGuestGuardTests(unittest.TestCase):
    def test_single_core_preparation_does_not_compete_with_feature_inventory(self):
        from types import SimpleNamespace
        for platform, cpus, expected in [('nt',1,False), ('nt',None,False), ('nt',2,True), ('posix',4,False)]:
            with self.subTest(platform=platform, cpus=cpus), patch.object(azure_setup_guest, 'os',
                    SimpleNamespace(name=platform, cpu_count=lambda: cpus)):
                self.assertEqual(azure_setup_guest.overlap_defender_preparation(), expected)

    def test_timed_out_setup_retains_task_timings_without_commands_or_secrets(self):
        from sentinel_blue.state import write_private_json
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            write_private_json(root/'state/setup-state.json',{'tasks':{
                'features':{'status':'ready','seconds':55.5,'initial_check_seconds':55.5,
                            'apply':{'output':'private-secret'},'checks':[{'argv':'private-secret'}]},
                'website':{'status':'running','started_at':123},
                'smb-share':{'status':'deadline','changed':False}}})
            result=azure_setup_guest.setup_state_diagnostic(root)
            self.assertTrue(result['available'])
            self.assertTrue(result['not_a_completion_proof'])
            self.assertEqual(result['tasks']['features']['seconds'],55.5)
            self.assertEqual(result['tasks']['website'],{'persisted_status':'running'})
            self.assertNotIn('private-secret',json.dumps(result))
            self.assertNotIn('apply',json.dumps(result))

    def test_malformed_task_diagnostics_do_not_replace_the_setup_result(self):
        from sentinel_blue.state import write_private_json
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for tasks in ([],{'features':{'status':'ready','seconds':True}},
                          {'features':{'status':'ready','seconds':float('inf')}},
                          {'features':{'status':'invented-ready'}}):
                with self.subTest(tasks=tasks):
                    # Deliberately encode invalid native state; no mutation is
                    # authorized by this post-run diagnostic.
                    path=root/'state/setup-state.json';path.parent.mkdir(mode=0o700,exist_ok=True)
                    path.write_text(json.dumps({'tasks':tasks}));path.chmod(0o600)
                    self.assertFalse(azure_setup_guest.setup_state_diagnostic(root)['available'])

    def test_partial_fixture_failure_writes_private_result_and_holds_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / 'runtime.pyz'
            runtime.write_bytes(b'owned fixture runtime')
            output = root / 'result.json'
            partial = []

            def failed_builder(fixture_root, suffix):
                marker = fixture_root / 'partial-owned-fixture'
                marker.write_text('requires inspection')
                partial.append(marker)
                raise subprocess.TimeoutExpired(['owned-command', 'private-secret-must-not-copy'], 120)

            argv = ['azure_setup_guest', '--runtime', str(runtime), '--expected-resource-id', 'owned',
                    '--output', str(output), '--with-defender']
            with (
                patch.object(sys, 'argv', argv),
                patch.object(sys, 'path', list(sys.path)),
                patch.object(azure_setup_guest, 'validate_guest', return_value={'scope_verified':True}),
                patch('tools.competition_native_inputs.linux_competition_inputs', side_effect=failed_builder),
                patch('tools.competition_native_inputs.windows_competition_inputs', side_effect=failed_builder),
                contextlib.redirect_stdout(io.StringIO()) as console,
            ):
                code = azure_setup_guest.main()
            self.assertEqual(code, 2)
            result = json.loads(output.read_text())
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['error_type'], 'TimeoutExpired')
            self.assertEqual(result['failure_stage'], 'fixture_inputs')
            self.assertFalse(result['cleanup']['verified'])
            self.assertNotIn('complete_opening_seconds', result)
            self.assertNotIn('private-secret', output.read_text() + console.getvalue())
            self.assertTrue(partial[0].exists())
            self.assertIn('SB_SETUP_RESULT_GZIP=', console.getvalue())

    def test_controller_and_arbitrary_targets_rejected_without_metadata_request(self):
        for target in ["sb-controller", "sb-redsim", "production"]:
            identity = ("/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/sentinel-blue-range-wus2"
                        "/providers/Microsoft.Compute/virtualMachines/" + target)
            with patch("tools.azure_setup_guest.urllib.request.build_opener") as request:
                with self.assertRaisesRegex(ValueError, "two existing"):
                    validate_guest(identity)
                request.assert_not_called()

    def test_different_subscription_metadata_cannot_authorize_guest_mutation(self):
        identity = ("/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/sentinel-blue-range-wus2"
                    "/providers/Microsoft.Compute/virtualMachines/sb-linux-target")
        metadata = {"compute": {"resourceId": identity.replace("000000000001", "000000000002")}}
        response = contextlib.closing(io.BytesIO(json.dumps(metadata).encode()))
        opener = Mock()
        opener.open.return_value = response
        with patch("tools.azure_setup_guest.urllib.request.build_opener", return_value=opener):
            with self.assertRaisesRegex(ValueError, "identity"):
                validate_guest(identity)


if __name__ == "__main__":
    unittest.main()
