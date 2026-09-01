import json
import unittest
from pathlib import Path

from sentinel_blue import __version__

ROOT = Path(__file__).resolve().parents[1]


class PortalExtensionTests(unittest.TestCase):
    def test_permissions_are_requested_only_for_configured_origins(self):
        manifest = json.loads((ROOT / "portal-extension" / "manifest.json").read_text())
        self.assertNotIn("host_permissions", manifest)
        self.assertNotIn("content_scripts", manifest)
        self.assertEqual(manifest["version"], __version__)
        popup = (ROOT / "portal-extension" / "popup.js").read_text()
        self.assertIn("chrome.permissions.request({origins})", popup)
        self.assertIn("new URL(tab.url).origin !== p.portalOrigin", popup)
        self.assertIn("RandomNumberGenerator", popup)
        self.assertNotIn("relay-enrollment", popup)
        self.assertNotIn("--auto-restore", popup)
        self.assertIn("--preflight", popup)
        self.assertIn("--probe-config", popup)
        self.assertIn("--event-profile", popup)
        self.assertIn("single_live_scored_network", popup)
        self.assertIn("blue_staging_non_authoritative", popup)
        self.assertIn("services_confirmed", popup)
        self.assertIn("release SHA-256", popup)
        self.assertNotIn("--preflight || true", popup)
        self.assertIn("deployment preflight failed", popup)
        self.assertIn("deployment execution failed", popup)
        self.assertIn("controller health check failed", popup)
        self.assertIn("package exceeds 128 MiB limit", popup)
        self.assertNotIn("'--model'", popup)
        self.assertIn("--operator-principal-id", popup)
        self.assertIn("--operator-credential-epoch", popup)
        self.assertIn("--recovery-key-file", popup)
        self.assertIn("--recovery-anchor", popup)
        self.assertIn("--tls-cert", popup)
        self.assertIn("--tls-key", popup)
        self.assertIn("--tls-ca-file", popup)
        self.assertIn("https://${p.controllerHost}:8765", popup)
        self.assertNotIn("Remove-Item $tokenPath", popup)

    def test_bootstrap_is_single_relay_only(self):
        html = (ROOT / "portal-extension" / "popup.html").read_text()
        content = (ROOT / "portal-extension" / "content.js").read_text()
        popup = (ROOT / "portal-extension" / "popup.js").read_text()
        self.assertIn("Bootstrap this relay console", html)
        self.assertNotIn("bootstrapAll", content)
        self.assertIn("waitForSingle", content)
        self.assertIn("totals.consoles !== 1", popup)
        self.assertIn("frameId: selected.frameId", popup)


if __name__ == "__main__":
    unittest.main()
