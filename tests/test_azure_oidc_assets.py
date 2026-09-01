import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "azure-lab-oidc.yml"
BOOTSTRAP = ROOT / "tools" / "bootstrap_azure_oidc.sh"


FAKE_AZ = r'''#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

arguments = sys.argv[1:]
state_path = Path(os.environ["FAKE_AZ_STATE"])
state = json.loads(state_path.read_text()) if state_path.exists() else {}
state.setdefault("commands", []).append(arguments)
state_path.write_text(json.dumps(state))

subscription = "00000000-0000-0000-0000-000000000001"
tenant = "00000000-0000-0000-0000-000000000002"
group = "sentinel-blue-range-wus2"
group_id = f"/subscriptions/{subscription}/resourceGroups/{group}"
client = "00000000-0000-0000-0000-000000000003"
principal = "00000000-0000-0000-0000-000000000004"
identity = {
    "clientId": client,
    "principalId": principal,
    "tenantId": tenant,
    "resourceGroup": group,
}
credential = {
    "name": "github-azure-lab",
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:joshua08271/Sentinel-Blue:environment:azure-lab",
    "audiences": ["api://AzureADTokenExchange"],
}
role_id = f"/subscriptions/{subscription}/providers/Microsoft.Authorization/roleDefinitions/00000000-0000-0000-0000-000000000005"

def save():
    state_path.write_text(json.dumps(state))

def value(flag):
    return arguments[arguments.index(flag) + 1]

if arguments[:2] == ["account", "show"]:
    print(json.dumps({"id": subscription, "tenantId": tenant}))
elif arguments[:2] == ["group", "show"]:
    print(json.dumps({"id": group_id}))
elif arguments[:2] == ["vm", "list"]:
    names = ["sb-controller", "sb-linux-target", "sb-redsim", "sb-windows-target"]
    if os.environ.get("FAKE_AZ_EXTRA_VM") == "1":
        names.append("unexpected-vm")
    print("\n".join(names))
elif arguments[:2] == ["vm", "show"]:
    vm = value("--name")
    print(f"{group_id}/providers/Microsoft.Network/networkInterfaces/{vm}-nic")
elif arguments[:3] == ["network", "nic", "show"]:
    print("")
elif arguments[:2] == ["identity", "show"]:
    if not state.get("identity"):
        raise SystemExit(3)
    print(json.dumps(identity))
elif arguments[:2] == ["identity", "create"]:
    state["identity"] = True
    save()
    print(json.dumps(identity))
elif arguments[:3] == ["identity", "federated-credential", "show"]:
    if not state.get("credential"):
        raise SystemExit(3)
    print(json.dumps(credential))
elif arguments[:3] == ["identity", "federated-credential", "create"]:
    state["credential"] = True
    save()
elif arguments[:3] == ["identity", "federated-credential", "list"]:
    print(json.dumps([credential] if state.get("credential") else []))
elif arguments[:3] == ["role", "definition", "list"]:
    if not state.get("role"):
        print("null")
    else:
        print(json.dumps(state["role"]))
elif arguments[:3] == ["role", "definition", "create"]:
    definition = json.loads(value("--role-definition"))
    state["role"] = {
        "id": role_id,
        "roleName": definition["Name"],
        "roleType": "CustomRole",
        "assignableScopes": definition["AssignableScopes"],
        "permissions": [{
            "actions": definition["Actions"],
            "notActions": definition["NotActions"],
            "dataActions": definition["DataActions"],
            "notDataActions": definition["NotDataActions"],
        }],
    }
    save()
elif arguments[:3] == ["role", "assignment", "create"]:
    state["assignment"] = True
    save()
elif arguments[:3] == ["role", "assignment", "list"]:
    assignment = {
        "id": f"{group_id}/providers/Microsoft.Authorization/roleAssignments/00000000-0000-0000-0000-000000000006",
        "scope": group_id,
        "roleDefinitionName": "Sentinel Blue Private Lab Operator",
        "roleDefinitionId": role_id,
    }
    if "--query" in arguments:
        print(assignment["id"] if state.get("assignment") else "")
    else:
        print(json.dumps([assignment] if state.get("assignment") else []))
else:
    print(f"unexpected fake az invocation: {arguments!r}", file=sys.stderr)
    raise SystemExit(64)
'''


FAKE_GH = "#!/usr/bin/env bash\nexit 1\n"


class AzureOidcAssetTests(unittest.TestCase):
    def test_workflow_is_manual_passwordless_and_pinned(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", workflow)
        self.assertNotIn("\n  push:", workflow)
        self.assertNotIn("\n  pull_request:", workflow)
        self.assertNotIn("\n  schedule:", workflow)
        self.assertIn("contents: read", workflow)
        self.assertIn("id-token: write", workflow)
        self.assertNotIn("contents: write", workflow)
        self.assertNotIn("client-secret", workflow.lower())
        self.assertNotIn("secrets.", workflow)
        self.assertIn(
            "azure/login@7184910d9eb2b1c5e48f7073824a90609bb9b6d6",
            workflow,
        )

    def test_workflow_is_bound_to_exact_private_lab(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        for required in (
            "joshua08271/Sentinel-Blue",
            "refs/heads/main",
            "name: azure-lab",
            "sentinel-blue-range-wus2",
            "sb-controller",
            "sb-linux-target",
            "sb-redsim",
            "sb-windows-target",
            "public-IP attachment",
        ):
            self.assertIn(required, workflow)
        self.assertIn("verify|inventory", workflow)
        self.assertIn("DEALLOCATE sentinel-blue-range-wus2", workflow)
        self.assertNotIn("inputs.command", workflow)
        self.assertNotIn("run-command", workflow)
        self.assertNotIn("vm start", workflow)
        self.assertIn("cancel-in-progress: false", workflow)

    def test_bootstrap_uses_exact_federated_subject_and_custom_role(self):
        bootstrap = BOOTSTRAP.read_text(encoding="utf-8")
        for required in (
            'GITHUB_REPOSITORY="joshua08271/Sentinel-Blue"',
            'GITHUB_ENVIRONMENT="azure-lab"',
            'RESOURCE_GROUP="sentinel-blue-range-wus2"',
            'OIDC_ISSUER="https://token.actions.githubusercontent.com"',
            'OIDC_AUDIENCE="api://AzureADTokenExchange"',
            'OIDC_SUBJECT="repo:${GITHUB_REPOSITORY}:environment:${GITHUB_ENVIRONMENT}"',
            "Microsoft.Compute/virtualMachines/runCommand/action",
            "Microsoft.Compute/virtualMachines/deallocate/action",
            "--assignee-object-id",
            "--include-inherited",
        ):
            self.assertIn(required, bootstrap)
        self.assertNotIn("--password", bootstrap)
        self.assertNotIn("credential reset", bootstrap)
        self.assertNotIn("Contributor", bootstrap)
        self.assertNotIn("Owner", bootstrap)
        self.assertNotIn("az vm start", bootstrap)
        self.assertNotIn("az vm run-command", bootstrap)

    @unittest.skipUnless(os.name == "posix", "bootstrap execution requires POSIX Bash")
    def test_bootstrap_creates_and_revalidates_exact_mock_trust(self):
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            fake_bin = temp / "bin"
            fake_bin.mkdir()
            (fake_bin / "az").write_text(FAKE_AZ, encoding="utf-8")
            (fake_bin / "gh").write_text(FAKE_GH, encoding="utf-8")
            (fake_bin / "az").chmod(0o755)
            (fake_bin / "gh").chmod(0o755)
            state = temp / "state.json"
            environment = {
                **os.environ,
                "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
                "FAKE_AZ_STATE": str(state),
            }

            for _run in range(2):
                result = subprocess.run(
                    ["bash", str(BOOTSTRAP)],
                    cwd=ROOT,
                    env=environment,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("No client secret was created", result.stdout)

            observed = json.loads(state.read_text(encoding="utf-8"))
            self.assertTrue(observed["identity"])
            self.assertTrue(observed["credential"])
            self.assertTrue(observed["role"])
            self.assertTrue(observed["assignment"])
            command_text = "\n".join(" ".join(command) for command in observed["commands"])
            self.assertNotIn("vm start", command_text)
            self.assertNotIn("vm deallocate", command_text)
            self.assertNotIn("vm run-command", command_text)

    @unittest.skipUnless(os.name == "posix", "bootstrap execution requires POSIX Bash")
    def test_bootstrap_rejects_unexpected_vm_before_creating_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            fake_bin = temp / "bin"
            fake_bin.mkdir()
            (fake_bin / "az").write_text(FAKE_AZ, encoding="utf-8")
            (fake_bin / "gh").write_text(FAKE_GH, encoding="utf-8")
            (fake_bin / "az").chmod(0o755)
            (fake_bin / "gh").chmod(0o755)
            state = temp / "state.json"
            result = subprocess.run(
                ["bash", str(BOOTSTRAP)],
                cwd=ROOT,
                env={
                    **os.environ,
                    "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
                    "FAKE_AZ_STATE": str(state),
                    "FAKE_AZ_EXTRA_VM": "1",
                },
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("VM inventory differs", result.stderr)
            observed = json.loads(state.read_text(encoding="utf-8"))
            self.assertNotIn("identity", observed)


if __name__ == "__main__":
    unittest.main()
