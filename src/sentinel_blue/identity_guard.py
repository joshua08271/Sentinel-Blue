"""Review protected-identity use without treating a protected name as trust.

Observed peer addresses are a useful restriction, not cryptographic proof of
the official scoring engine. No result in this module grants access or labels
an allowed source authenticated. OS services still perform authentication.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from .validation import ModelBoundAlertCandidate


def validate_guards(value: Any) -> list[dict]:
    if not isinstance(value, list) or len(value) > 2048:
        raise ValueError("identity_guards must be a bounded array")
    result, seen = [], set()
    for row in value:
        required = {"agent_id", "name", "account_id", "allowed_sources"}
        if not isinstance(row, dict) or not required <= set(row) or set(row) - required - {'ssh_public_keys'}:
            raise ValueError("identity guard requires agent_id, name, account_id and allowed_sources")
        for field in ("agent_id", "name", "account_id"):
            if (not isinstance(row[field], str) or not 1 <= len(row[field]) <= 256
                    or any(ord(c) < 32 for c in row[field])):
                raise ValueError("identity guard contains an invalid identity")
        if row["agent_id"] == "*":
            raise ValueError("identity guards require an exact agent, not a wildcard")
        if not re.fullmatch(r"\d+|S-1-(?:\d+-)+\d+", row["account_id"], re.I):
            raise ValueError("identity guard requires a native UID or SID")
        sources = row["allowed_sources"]
        if not isinstance(sources, list) or not 1 <= len(sources) <= 64:
            raise ValueError("identity guard requires bounded source networks")
        networks = []
        for source in sources:
            if not isinstance(source, str):
                raise ValueError('identity guard source networks must be strings')
            network = ipaddress.ip_network(source, strict=True)
            if not network.prefixlen:
                raise ValueError("identity guard cannot trust every source")
            networks.append(str(network))
        key = (row["agent_id"], row["name"].casefold())
        if key in seen:
            raise ValueError("duplicate identity guard")
        seen.add(key)
        normalized = {**row, "allowed_sources": networks}
        if 'ssh_public_keys' in row:
            from .ssh_keys import pinned_public_keys
            normalized['ssh_public_keys'] = pinned_public_keys(row['ssh_public_keys'])
        result.append(normalized)
    return result


def _source_allowed(source: str, networks: list[str]) -> bool:
    try:
        address = ipaddress.ip_address(source)
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        return any(address in ipaddress.ip_network(network) for network in networks)
    except (ValueError, TypeError):
        return False


def analyze_protected_access(telemetry, protected_accounts, guards, model):
    guards = validate_guards(guards)
    windows = str(telemetry.get("platform", "")).lower().startswith("windows")
    def leaf(name):
        text = str(name).casefold()
        return text.rsplit("\\", 1)[-1].split("@", 1)[0] if windows else text
    applicable = {g["name"].casefold(): g for g in guards
                  if g["agent_id"] == telemetry.get("agent_id")}
    protected = {leaf(name) for name in protected_accounts} | {leaf(name) for name in applicable}
    accounts = {}
    for account in telemetry.get("accounts", []):
        accounts.setdefault(leaf(account.get("name", "")), []).append(account)
    observations = [("session", s.get("username", ""), s.get("source", "unknown"),
                     (s.get("process_identity") or {}).get("user_id", ""), "")
                    for s in telemetry.get("sessions", [])]
    observations += [("authentication", e.get("account", ""), e.get("remote_address", "unknown"),
                      e.get("account_id", ""), e.get("account_domain", ""))
                     for e in telemetry.get("security_events", [])
                     if e.get("category") == "auth_success"]
    alerts, seen = [], set()
    for guard in applicable.values():
        if windows and any(separator in guard['name'] for separator in ('\\','@')):
            continue  # Domain identities are verified from native login subjects.
        rows = accounts.get(leaf(guard['name']), [])
        if (len(rows) != 1 or rows[0].get('account_id') != guard['account_id']
                or (not windows and rows[0].get('name') != guard['name'])):
            features = {'protected_identity_loss':1.0}
            alerts.append(ModelBoundAlertCandidate(
                kind='protected_identity_inventory_mismatch', title='Protected native account identity is missing or changed',
                summary=f"The native identity for {guard['name']} does not match its independent guard.",
                severity='critical',confidence=0.98,model_features=features,
                evidence={'expected':{'name':guard['name'],'account_id':guard['account_id']},
                          'observed':rows,'baseline_independent':True,'missing':not rows},
                recommendation='Verify the event roster and preserve the required account; investigate the UID/SID replacement before changing access.',
                recommended_action='snapshot'))
    for origin, name, source, observed_id, domain in observations:
        normalized = leaf(name)
        # Do not let an earlier valid login suppress a different native identity.
        key = (origin, str(name), source, observed_id, domain)
        if normalized not in protected or key in seen:
            continue
        seen.add(key)
        candidates = [g for g in applicable.values() if leaf(g["name"]) == normalized]
        guard = candidates[0] if len(candidates) == 1 else None
        rows = accounts.get(normalized, [])
        identity_ok = bool(guard and len(rows) == 1
                           and rows[0].get("account_id") == guard["account_id"]
                           and (windows
                                or rows[0].get("name") == guard["name"]))
        if observed_id:
            identity_ok = bool(guard and observed_id.casefold() == guard["account_id"].casefold()
                               and (windows or str(name) == guard["name"]))
        elif windows:
            # A local-account lookup cannot authenticate a domain login. Windows
            # events and sessions must identify the actual subject's native SID.
            identity_ok = False
        source_ok = bool(guard and _source_allowed(source, guard["allowed_sources"]))
        if identity_ok and source_ok:
            continue
        reasons = (["missing_identity_guard"] if not guard else
                   ([] if identity_ok else ["native_identity_unverified"]) +
                   ([] if source_ok else ["source_outside_approved_networks"]))
        features = {"protected_identity": 1.0, "external_source": 1.0}
        alerts.append(ModelBoundAlertCandidate(
            kind="protected_identity_access_unverified",
            title="Protected account access requires verification",
            summary=f"Access by protected account {name} from {source} failed its identity/source checks.",
            severity="high" if not guard else "critical",
            confidence=round(max(0.8, min(0.99, model.predict(features))), 3),
            model_features=features,
            evidence={"account": {"name": name, "account_id": observed_id, "domain": domain},
                      "source": source, "observation": origin,
                      "reasons": reasons, "identity_matched": identity_ok,
                      "source_matched": source_ok, "scorer_authenticated": False},
            recommendation=("Preserve the required account. Verify this access through the official "
                            "scoring/administration inventory. A username or source-IP match alone "
                            "does not authenticate the operator; no blanket containment is authorized."),
            recommended_action="snapshot",
        ))
    return alerts
