"""Build byte-reproducible defensive-core runtime, source, and complete bundles."""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
import tomllib
import zipfile
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
VERSION = str(tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"])
FIXED_ZIP_TIME = (2026, 1, 1, 0, 0, 0)

try:
    from tools.check_release_consistency import check_bundle, check_source
except ModuleNotFoundError:  # Direct execution places tools/ first on sys.path.
    from check_release_consistency import check_bundle, check_source


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def _entries(paths: Iterable[Path]) -> list[tuple[str, bytes]]:
    result: list[tuple[str, bytes]] = []
    names: set[str] = set()
    folded_names: set[str] = set()
    for base in paths:
        if base.is_symlink():
            raise ValueError(f"release input must not be a symbolic link: {base}")
        if not base.exists():
            raise ValueError(f"release input does not exist: {base}")
        if not base.is_file() and not base.is_dir():
            raise ValueError(f"release input is not a regular file or directory: {base}")
        candidates = [base] if base.is_file() else sorted(base.rglob("*"))
        for item in candidates:
            if item.is_symlink():
                raise ValueError(f"release input must not be a symbolic link: {item}")
            mode = item.stat(follow_symlinks=False).st_mode
            ignored = (
                "__pycache__" in item.parts
                or any(part.endswith(".egg-info") for part in item.parts)
                or item.suffix in {".pyc", ".pyo"}
            )
            if ignored or stat.S_ISDIR(mode):
                continue
            if not stat.S_ISREG(mode):
                raise ValueError(f"release input must be a regular file: {item}")
            name = item.relative_to(ROOT).as_posix()
            if name in names or name.casefold() in folded_names:
                raise ValueError(f"release inputs contain a duplicate or case collision: {name}")
            names.add(name)
            folded_names.add(name.casefold())
            result.append((name, item.read_bytes()))
    return sorted(result, key=lambda item: item[0])


def _write_zip(
    destination: Path,
    entries: Iterable[tuple[str, bytes]],
    prefix: bytes = b"",
) -> None:
    prepared = list(entries)
    names = [name for name, _content in prepared]
    if len(names) != len(set(names)) or len(names) != len({name.casefold() for name in names}):
        raise ValueError("archive entries contain a duplicate or case collision")
    destination.write_bytes(prefix)
    with zipfile.ZipFile(
        destination, "a", compression=zipfile.ZIP_STORED
    ) as archive:
        for name, content in prepared:
            info = zipfile.ZipInfo(name, FIXED_ZIP_TIME)
            info.create_system = 3
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, content, compress_type=zipfile.ZIP_STORED)


def zip_tree(destination: Path, paths: list[Path]) -> None:
    _write_zip(destination, _entries(paths))


def build(output: Path) -> list[Path]:
    check_source(VERSION)
    source_paths = [
        ROOT / "README.md",
        ROOT / "LICENSE",
        ROOT / "SECURITY.md",
        ROOT / "pyproject.toml",
        ROOT / ".gitignore",
        ROOT / ".gitattributes",
        ROOT / "src",
        ROOT / "tests",
        ROOT / "examples",
        ROOT / "models",
        ROOT / "docs",
        ROOT / "packaging",
        ROOT / "tools",
        ROOT / ".github",
    ]
    resolved_output = output.resolve()
    if any(
        path.is_dir() and resolved_output.is_relative_to(path.resolve())
        for path in source_paths
    ):
        raise ValueError("release output must be outside included source directories")
    source_entries = _entries(source_paths)
    output.mkdir(parents=True, exist_ok=True)
    zipapp_path = output / f"sentinel-blue-{VERSION}.pyz"
    runtime_entries = [
        (name.removeprefix("src/"), content)
        for name, content in source_entries
        if name.startswith("src/")
    ]
    runtime_entries.append(
        (
            "__main__.py",
            b"from sentinel_blue.__main__ import main\n\nif __name__ == '__main__':\n    main()\n",
        )
    )
    _write_zip(zipapp_path, runtime_entries, prefix=b"#!/usr/bin/env python3\n")
    if os.name == "posix":
        zipapp_path.chmod(0o755)

    source_path = output / f"sentinel-blue-source-{VERSION}.zip"
    _write_zip(source_path, source_entries)
    primary_artifacts = [zipapp_path, source_path]
    checksum_path = output / "SHA256SUMS"
    checksum_path.write_bytes(
        "".join(
            f"{digest(path)}  {path.name}\n" for path in primary_artifacts
        ).encode("utf-8")
    )
    bundle_path = output / f"sentinel-blue-complete-lab-{VERSION}.zip"
    _write_zip(
        bundle_path,
        [(path.name, path.read_bytes()) for path in [*primary_artifacts, checksum_path]],
    )
    check_bundle(bundle_path, VERSION)
    return [*primary_artifacts, checksum_path, bundle_path]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=str(ROOT / "dist"))
    args = parser.parse_args()
    for artifact in build(Path(args.output)):
        print(f"{digest(artifact)}  {artifact}")


if __name__ == "__main__":
    main()
