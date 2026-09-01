"""Fail closed when source or packaged release identities disagree."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import stat
import tomllib
import unicodedata
import zipfile
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
WINDOWS_UNSAFE = frozenset('<>"|?*')
WINDOWS_RESERVED = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}
GENERATED_RUNTIME_MAIN = (
    b"from sentinel_blue.__main__ import main\n\n"
    b"if __name__ == '__main__':\n"
    b"    main()\n"
)


def _unsafe_windows_part(part: str) -> bool:
    stem = part.rstrip(" .").partition(".")[0].upper()
    return (
        part.endswith((" ", "."))
        or stem in WINDOWS_RESERVED
        or any(ord(character) < 32 or character in WINDOWS_UNSAFE for character in part)
    )


def _python_version(source: str, label: str) -> str:
    assignments: list[str] = []
    for node in ast.parse(source, filename=label).body:
        if (
            isinstance(node, (ast.Assign, ast.AnnAssign))
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(target, ast.Name) and target.id == "__version__" for target in targets):
                assignments.append(node.value.value)
    if len(assignments) != 1 or not VERSION.fullmatch(assignments[0]):
        raise ValueError(f"{label} must contain one literal semantic __version__")
    return assignments[0]


def _safe_archive(archive: zipfile.ZipFile, label: str) -> dict[str, zipfile.ZipInfo]:
    entries: dict[str, zipfile.ZipInfo] = {}
    folded: set[str] = set()
    for info in archive.infolist():
        path = PurePosixPath(info.filename)
        logical_name = path.as_posix()
        canonical_name = f"{logical_name}/" if info.is_dir() else logical_name
        if (
            not info.filename
            or not path.parts
            or path.is_absolute()
            or ".." in path.parts
            or "\\" in info.filename
            or ":" in info.filename
            or any(_unsafe_windows_part(part) for part in path.parts)
            or info.filename != canonical_name
            or info.flag_bits & 0x1
        ):
            raise ValueError(f"{label} contains an unsafe archive member")
        mode = info.external_attr >> 16
        if (
            stat.S_ISLNK(mode)
            or (mode and not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)))
            or (mode and stat.S_ISDIR(mode) != info.is_dir())
        ):
            raise ValueError(f"{label} contains a link or special archive member")
        folded_name = unicodedata.normalize("NFC", logical_name).casefold()
        if info.filename in entries or folded_name in folded:
            raise ValueError(f"{label} contains duplicate or case-colliding members")
        entries[info.filename] = info
        folded.add(folded_name)
    if archive.testzip() is not None:
        raise ValueError(f"{label} failed its CRC check")
    return entries


def check_source(expected: str | None = None) -> str:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    version = str(project["project"]["version"])
    if not VERSION.fullmatch(version):
        raise ValueError("pyproject.toml has an invalid release version")
    if expected is not None and expected.removeprefix("v") != version:
        raise ValueError(f"release version {version} does not match expected {expected}")
    init_version = _python_version(
        (ROOT / "src/sentinel_blue/__init__.py").read_text(encoding="utf-8"),
        "src/sentinel_blue/__init__.py",
    )
    manifest = json.loads(
        (ROOT / "portal-extension/manifest.json").read_text(encoding="utf-8")
    )
    inventory = json.loads(
        (ROOT / "examples/inventory.example.json").read_text(encoding="utf-8")
    )
    release = inventory.get("event_profile", {}).get("release", {})
    identities = {
        "Python package": init_version,
        "portal extension": str(manifest.get("version", "")),
        "example inventory": str(release.get("version", "")),
    }
    mismatched = [label for label, value in identities.items() if value != version]
    if mismatched:
        raise ValueError(f"release version mismatch in {', '.join(mismatched)}")
    if f"sentinel-blue-{version}.pyz" not in str(release.get("public_url", "")):
        raise ValueError("example inventory public URL does not match the release version")
    popup = (ROOT / "portal-extension/popup.js").read_text(encoding="utf-8")
    if "chrome.runtime.getManifest().version" not in popup:
        raise ValueError("portal extension does not derive its release version from the manifest")
    required_labels = {
        "portal-extension/README.md": f"Sentinel Blue {version} is the",
    }
    optional_labels = {
        "README.md": f"# Sentinel Blue {version}",
        "SECURITY.md": f"Sentinel Blue {version} is defensive software",
        "docs/ARCHITECTURE.md": f"# Sentinel Blue {version} architecture",
        "docs/MONITORED_RESTORATION.md": f"Sentinel Blue {version} implements",
        "docs/COMPETITION_REQUIREMENTS.md": f"to Sentinel Blue {version}.",
        "docs/ROADMAP.md": f"Run the exact {version} release",
    }
    for name, text in required_labels.items():
        if text not in (ROOT / name).read_text(encoding="utf-8"):
            raise ValueError(f"{name} does not identify the current release")
    for name, text in optional_labels.items():
        path = ROOT / name
        if path.exists() and text not in path.read_text(encoding="utf-8"):
            raise ValueError(f"{name} does not identify the current release")
    return version


def check_bundle(bundle: Path, version: str) -> None:
    expected_names = {
        f"sentinel-blue-{version}.pyz",
        f"sentinel-blue-portal-extension-{version}.zip",
        f"sentinel-blue-source-{version}.zip",
        "SHA256SUMS",
    }
    with zipfile.ZipFile(bundle) as outer:
        entries = _safe_archive(outer, bundle.name)
        if set(entries) != expected_names:
            raise ValueError("complete bundle members do not match the release version")
        members = {name: outer.read(name) for name in entries}
    checksum_rows: dict[str, str] = {}
    checksum_names = expected_names - {"SHA256SUMS"}
    for line in members["SHA256SUMS"].decode("utf-8").splitlines():
        digest, separator, name = line.partition("  ")
        if (
            not separator
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or name not in checksum_names
            or name in checksum_rows
        ):
            raise ValueError("SHA256SUMS contains an invalid row")
        checksum_rows[name] = digest
    if set(checksum_rows) != checksum_names:
        raise ValueError("SHA256SUMS does not enumerate the release artifacts exactly")
    for name in checksum_names:
        if checksum_rows.get(name) != hashlib.sha256(members[name]).hexdigest():
            raise ValueError(f"checksum mismatch for {name}")

    runtime_name = f"sentinel-blue-{version}.pyz"
    with zipfile.ZipFile(_BytesPath(members[runtime_name])) as runtime:
        runtime_entries = _safe_archive(runtime, runtime_name)
        runtime_members = {name: runtime.read(name) for name in runtime_entries}
        runtime_version = _python_version(
            runtime_members["sentinel_blue/__init__.py"].decode("utf-8"), runtime_name
        )
        if runtime_version != version or "__main__.py" not in runtime_entries:
            raise ValueError("runtime identity does not match the complete bundle")

    extension_name = f"sentinel-blue-portal-extension-{version}.zip"
    with zipfile.ZipFile(_BytesPath(members[extension_name])) as extension:
        extension_entries = _safe_archive(extension, extension_name)
        extension_members = {name: extension.read(name) for name in extension_entries}
        manifest_name = "portal-extension/manifest.json"
        if manifest_name not in extension_entries:
            raise ValueError("extension manifest is missing")
        manifest = json.loads(extension_members[manifest_name])
        if str(manifest.get("version")) != version:
            raise ValueError("extension bundle version does not match")

    source_name = f"sentinel-blue-source-{version}.zip"
    with zipfile.ZipFile(_BytesPath(members[source_name])) as source:
        source_entries = _safe_archive(source, source_name)
        source_members = {name: source.read(name) for name in source_entries}
        for required in (
            "pyproject.toml",
            "src/sentinel_blue/__init__.py",
            "portal-extension/manifest.json",
        ):
            if required not in source_entries:
                raise ValueError(f"source bundle is missing {required}")
        source_project = tomllib.loads(source_members["pyproject.toml"].decode("utf-8"))
        source_version = _python_version(
            source_members["src/sentinel_blue/__init__.py"].decode("utf-8"), source_name
        )
        source_manifest = json.loads(source_members["portal-extension/manifest.json"])
        if {
            str(source_project["project"]["version"]),
            source_version,
            str(source_manifest.get("version")),
        } != {version}:
            raise ValueError("source bundle identities do not match")

    source_runtime_members = {
        name.removeprefix("src/"): content
        for name, content in source_members.items()
        if name.startswith("src/sentinel_blue/")
    }
    expected_runtime_names = {*source_runtime_members, "__main__.py"}
    if set(runtime_members) != expected_runtime_names:
        raise ValueError("runtime members do not match the source package exactly")
    for name, source_content in source_runtime_members.items():
        if runtime_members[name] != source_content:
            raise ValueError(f"runtime member {name} does not byte-match the source bundle")
    if runtime_members["__main__.py"] != GENERATED_RUNTIME_MAIN:
        raise ValueError("generated runtime __main__.py does not match the release entrypoint")

    source_extension_members = {
        name: content
        for name, content in source_members.items()
        if name.startswith("portal-extension/")
    }
    if set(extension_members) != set(source_extension_members):
        raise ValueError("portal extension members do not match the source bundle exactly")
    for name, source_content in source_extension_members.items():
        if extension_members[name] != source_content:
            raise ValueError(f"portal extension member {name} does not byte-match the source bundle")


class _BytesPath:
    """Minimal seekable wrapper accepted by ZipFile without temporary artifacts."""

    def __init__(self, value: bytes):
        import io

        self._stream = io.BytesIO(value)

    def read(self, *args):
        return self._stream.read(*args)

    def seek(self, *args):
        return self._stream.seek(*args)

    def tell(self):
        return self._stream.tell()

    def seekable(self):
        return True


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected")
    parser.add_argument("--bundle", type=Path)
    args = parser.parse_args()
    version = check_source(args.expected)
    if args.bundle is not None:
        check_bundle(args.bundle, version)
    print(json.dumps({"passed": True, "version": version, "bundle": str(args.bundle or "")}))


if __name__ == "__main__":
    main()
