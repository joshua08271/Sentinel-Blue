"""Adversarial identity cases present before the defender's first baseline."""
from dataclasses import asdict
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from sentinel_blue import collectors
from sentinel_blue.detection import detect


class PreexistingPrivilegedAccountTests(unittest.TestCase):
    def alerts(self, accounts, protected=()):
        telemetry = {"platform": "Linux", "accounts": accounts, "collector_errors": []}
        return detect(telemetry, telemetry, set(protected))

    def test_initial_baseline_does_not_approve_unknown_uid_zero(self):
        account = {"name": "preexisting-backup", "account_id": "0", "privileged": True, "enabled": True}
        alert = next(a for a in self.alerts([account]) if a.kind == "unverified_privileged_account")
        self.assertFalse(alert.evidence["new_since_baseline"])
        self.assertEqual(alert.recommended_action, "snapshot")

    def test_noninteractive_privileged_account_still_requires_review(self):
        account = {"name": "preexisting-backup", "account_id": "0", "privileged": True, "enabled": False}
        self.assertIn("unverified_privileged_account", {a.kind for a in self.alerts([account])})

    def test_builtin_spelling_does_not_exempt_wrong_identity(self):
        for name, account_id in [("Administrator", "0"), ("root", "1000"), ("Root", "0")]:
            with self.subTest(name=name, account_id=account_id):
                account = {"name": name, "account_id": account_id, "privileged": True, "enabled": True}
                self.assertIn("unverified_privileged_account", {a.kind for a in self.alerts([account])})
        account = {"name": "Administrator", "account_id": "S-1-5-21-1-2-3-1001", "privileged": True, "enabled": True}
        telemetry = {"platform": "Windows", "accounts": [account]}
        self.assertIn("unverified_privileged_account", {a.kind for a in detect(telemetry, telemetry, set())})

    def test_identified_builtin_accounts_have_no_presence_only_alert(self):
        for platform, name, account_id in [("Linux", "root", "0"), ("Windows", "Administrator", "S-1-5-21-1-2-3-500")]:
            with self.subTest(platform=platform):
                account = {"name": name, "account_id": account_id, "privileged": True, "enabled": True}
                telemetry = {"platform": platform, "accounts": [account]}
                self.assertFalse([a for a in detect(telemetry, telemetry, set()) if a.kind == "unverified_privileged_account"])

    def test_case_collision_cannot_hide_behind_protected_root_or_row_order(self):
        real = {"name": "root", "account_id": "0", "privileged": True, "enabled": True}
        alias = {**real, "name": "Root"}
        for accounts in ([real, alias], [alias, real]):
            with self.subTest(first=accounts[0]["name"]):
                alerts = [a for a in self.alerts(accounts, {"root"}) if a.kind == "unverified_privileged_account"]
                self.assertTrue(any(a.evidence["account"]["name"] == "Root" for a in alerts))
                self.assertTrue(all(a.recommended_action == "snapshot" for a in alerts))

    def test_protected_account_id_replacement_is_not_suppressed(self):
        for old_id, new_id in [("1001", "0"), ("S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002")]:
            with self.subTest(old_id=old_id):
                old = {"name": "scorer", "account_id": old_id, "privileged": True, "enabled": True}
                new = {**old, "account_id": new_id}
                alerts = detect({"accounts": [new]}, {"accounts": [old]}, {"scorer"})
                alert = next((a for a in alerts if a.kind == "protected_identity_unavailable"), None)
                self.assertIsNotNone(alert)
                self.assertTrue(alert.evidence["identity_changed"])
                self.assertEqual(alert.recommended_action, "snapshot")

    def test_verified_protected_identity_stays_protected(self):
        account = {"name": "scorer", "account_id": "1001", "privileged": True, "enabled": True}
        self.assertFalse(self.alerts([account], {"scorer"}))

    @unittest.skipIf(collectors.pwd is None or collectors.grp is None, "Linux account APIs required")
    def test_primary_privileged_group_is_collected_without_explicit_membership(self):
        account = SimpleNamespace(pw_name="preexisting-admin", pw_uid=1001, pw_gid=27, pw_shell="/bin/bash")
        group = SimpleNamespace(gr_name="sudo", gr_gid=27, gr_mem=[])
        with patch.object(collectors.pwd, "getpwall", return_value=[account]), \
             patch.object(collectors.grp, "getgrall", return_value=[group]), \
             patch.object(collectors, "_run", return_value=SimpleNamespace(returncode=0, stdout="sudo:x:27:\n")):
            records = [asdict(a) for a in collectors._linux_accounts()]
        self.assertTrue(records[0]["privileged"])
        self.assertIn("unverified_privileged_account", {a.kind for a in self.alerts(records)})


if __name__ == "__main__":
    unittest.main()
