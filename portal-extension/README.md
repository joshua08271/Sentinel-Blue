# Portal bootstrap extension

This unpacked Chromium extension implements the website-console portion of
Sentinel Blue deployment. It is intentionally declarative because competition
portals use different HTML, iframe, noVNC, RDP, and terminal implementations.

The team configures the exact approved portal origin and selectors before the
tool-freeze deadline. After the competitor completes the normal website login,
the extension can inject the checksum-pinned bootstrap into the selected relay
console. It deliberately does not inject the controller bootstrap into every
device: that would create conflicting controllers and enrollment secrets.

The relay generates separate enrollment, operator-signing, and recovery secrets
inside the competition desktop. None is transmitted from the physical laptop.
The approved controller certificate, private key, and pinned CA must already be
provisioned at the absolute paths entered in the extension; the helper will not
generate an unapproved trust anchor or fall back to plaintext. Sentinel Blue 1.9.11 is the
current locally certified candidate: its exact packaged local gate passed,
while native Azure acceptance remains pending. Version 1.9.10 remains the last
fully closed private native checkpoint. Do not mark 1.9.11 approved or frozen
until the native gate closes. An
eventual 1.9.11
deployment inventory must embed an approved default-deny event profile with the
exact release digest,
public/freeze/submission declarations, one-live-network flags, scope and
exclusions, routes and paths, official identities, and confirmed service
manifests. Draft or mismatched profiles stop before bootstrap. The relay then
starts the controller and executes the scope-checked inventory through SSH,
WinRM, local, or approved adapter transports. It does not enable automatic
restoration and does not create an undeclared local relay agent.

Limitations:

- The extension cannot bypass MFA, CAPTCHA, disabled clipboard controls, or
  cross-origin restrictions imposed by the portal.
- Canvas-only consoles may ignore synthetic keyboard events. They require an
  approved clipboard API, portal API, or site-specific adapter.
- Portal selectors and the visible controller address must be configured and
  tested against the event's approved practice portal.
- The relay must have Python 3.11+, the approved TLS files, and private storage
  for the database, recovery key/anchor, operator key, and authenticated bundles.
- Re-running the bootstrap preserves existing private authorities. Operator-key
  rotation and recovery reconciliation remain explicit offline procedures.
- The exact public package URL, SHA-256, event profile, and applicable release
  lead times must be frozen, submitted, and approved before use.
- No host permission is granted at install time. A click requests only the
  configured portal and console-frame origins, and each frame independently
  checks its exact origin before accepting a message.
- This extension and its frozen profile must be submitted with the rest of the
  team-written software for competition approval.
