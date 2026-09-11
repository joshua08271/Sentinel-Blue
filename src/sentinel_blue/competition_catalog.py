"""Exact score columns supplied by the operator; no inferred OS or SQL engine."""

from __future__ import annotations

from urllib.parse import urlparse


CATALOGS = {
    "ncae": (
        ("router-icmp", "Router ICMP", "icmp"),
        ("ssh-login", "SSH Login", "ssh-login"),
        ("smb-login", "SMB Login", "smb-login"),
        ("smb-write", "SMB Write", "smb-write"),
        ("smb-read", "SMB Read", "smb-read"),
        ("www-content", "WWW Content", "http-content"),
        ("www-ssl", "WWW SSL", "https"),
        ("www-ssh", "WWW SSH", "ssh-login"),
        ("sql-access", "SQL Access", "sql"),
        ("sql-ssh", "SQL SSH", "ssh-login"),
        ("dns-int", "DNS INT", "dns-forward"),
        ("dynamic-dns", "Dynamic DNS", "dns-update"),
        ("dns-ssh", "DNS SSH", "ssh-login"),
    ),
    "gddc-ualbany": (
        ("router-icmp", "Router ICMP", "icmp"),
        ("ssh-login", "SSH Login", "ssh-login"),
        ("smb-login", "SMB Login", "smb-login"),
        ("smb-write", "SMB Write", "smb-write"),
        ("smb-read", "SMB Read", "smb-read"),
        ("www-port-80", "WWW Port 80", "http-port-80"),
        ("www-content", "WWW Content", "http-content"),
        ("www-ssl", "WWW SSL", "https"),
        ("postgres-access", "Postgres Access", "postgres"),
        ("dns-int-fwd", "DNS INT FWD", "dns-forward"),
        ("dns-int-rev", "DNS INT REV", "dns-reverse"),
        ("dns-ext-fwd", "DNS EXT FWD", "dns-forward"),
        ("dns-ext-rev", "DNS EXT REV", "dns-reverse"),
    ),
}


def catalog_rows(name):
    if name not in CATALOGS:
        raise ValueError("opening catalog must be ncae or gddc-ualbany")
    return [{"id": key, "label": label, "transaction": kind} for key, label, kind in CATALOGS[name]]


def matches_requirement(requirement, probe):
    """Reject weaker checks such as TCP-open standing in for authenticated SMB."""
    kind = probe.get("kind")
    if requirement.startswith("smb-"):
        operation = requirement.removeprefix("smb-")
        return (kind == "smb" and probe.get("operation", "login") == operation and
                bool(probe.get("username")) and bool(probe.get("password_file")) and
                bool(probe.get("share")) and
                (operation != "write" or (probe.get("allow_write") is True and bool(probe.get("directory")))) and
                (operation != "read" or (bool(probe.get("path")) and bool(probe.get("expected_sha256")))))
    if requirement == "ssh-login":
        return (kind == "ssh-login" and bool(probe.get("username")) and bool(probe.get("known_hosts_file")) and
                bool(probe.get("password_file") or probe.get("key_file")))
    if requirement in {"sql", "postgres"}:
        return (kind in ({"mysql", "postgres"} if requirement == "sql" else {"postgres"}) and
                bool(probe.get("username")) and bool(probe.get("database")) and bool(probe.get("password_file")))
    if requirement == "http-content":
        return kind in {"http", "https"} and bool(probe.get("expected_body")) and probe.get("expected_status") == [200]
    if requirement == "https":
        return (kind in {"https", "tls"} and probe.get("verify", True) is True and
                (kind == "tls" or urlparse(probe.get("target", "")).scheme == "https"))
    if requirement == "http-port-80":
        if kind == "tcp":
            return probe.get("port") == 80
        parsed = urlparse(probe.get("target", ""))
        return kind == "http" and parsed.scheme == "http" and (parsed.port or 80) == 80
    if requirement in {"dns-forward", "dns-reverse"}:
        record = probe.get("record_type", "A").upper()
        return (kind == "dns" and bool(probe.get("query")) and bool(probe.get("expected_answers")) and
                record in ({"PTR"} if requirement == "dns-reverse" else {"A", "AAAA"}))
    if requirement == "dns-update":
        return (kind == "dns-update" and probe.get("allow_write") is True and
                all(probe.get(key) for key in ("zone", "prefix", "key_file", "value")))
    return requirement == kind == "icmp"


def bind_catalog(name, bindings, setup_plan):
    rows = catalog_rows(name)
    if not isinstance(bindings, dict) or set(bindings) != {row["id"] for row in rows}:
        raise ValueError("opening requires exactly every score column from the selected screenshot catalog")
    result = []
    used = set()
    for row in rows:
        binding = bindings[row["id"]]
        if not isinstance(binding, dict) or set(binding) != {"task", "probe"}:
            raise ValueError("each score binding must name one setup task and one probe")
        tasks = [task for task in setup_plan["tasks"] if task["id"] == binding["task"] and task["service_key"]]
        if len(tasks) != 1:
            raise ValueError(f"{row['label']} needs a final service setup task")
        probes = [probe for probe in tasks[0]["probes"] if probe.get("name") == binding["probe"]]
        if len(probes) != 1 or not matches_requirement(row["transaction"], probes[0]):
            raise ValueError(f"{row['label']} needs its matching scoring transaction")
        reference = (binding["task"], binding["probe"])
        if reference in used:
            raise ValueError("two score columns cannot reuse the same probe binding")
        used.add(reference)
        result.append(row | {"task": binding["task"], "host": tasks[0]["host"], "probe": probes[0]})
    return result
