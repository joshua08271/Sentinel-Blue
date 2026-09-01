import hashlib
import io
import tempfile
import unittest
import zipfile
from pathlib import Path

from tools.build_release import ROOT, VERSION, _entries, build
from tools.check_release_consistency import _safe_archive, check_bundle, check_source


def _zip_bytes(entries: list[tuple[str, bytes]]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, content in entries:
            info = zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, content, compress_type=zipfile.ZIP_STORED)
    return buffer.getvalue()


def _replace_zip_member(archive_bytes: bytes, member: str, content: bytes) -> bytes:
    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
        entries = [
            (name, content if name == member else archive.read(name))
            for name in archive.namelist()
        ]
    return _zip_bytes(entries)


def _refresh_bundle_artifact(
    bundle: Path,
    destination: Path,
    artifact_name: str,
    artifact_content: bytes,
) -> None:
    with zipfile.ZipFile(bundle) as archive:
        members = {name: archive.read(name) for name in archive.namelist()}
    members[artifact_name] = artifact_content
    checksum_names = sorted(name for name in members if name != "SHA256SUMS")
    members["SHA256SUMS"] = "".join(
        f"{hashlib.sha256(members[name]).hexdigest()}  {name}\n"
        for name in checksum_names
    ).encode("utf-8")
    destination.write_bytes(_zip_bytes(list(members.items())))


class ReleaseBuilderTests(unittest.TestCase):
    def test_entry_collection_ignores_generated_package_metadata(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            package = Path(directory) / "probe"
            metadata = package / "sentinel_blue.egg-info"
            metadata.mkdir(parents=True)
            (package / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
            (metadata / "PKG-INFO").write_text("generated\n", encoding="utf-8")
            entries = _entries([package])
            names = [name for name, _content in entries]
            self.assertEqual(len(names), 1)
            self.assertTrue(names[0].endswith("/probe/module.py"), names)

    def test_builds_core_runtime_source_and_complete_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            artifacts = build(Path(directory))
            names = {path.name for path in artifacts}
            self.assertIn(f"sentinel-blue-{VERSION}.pyz", names)
            self.assertIn(f"sentinel-blue-source-{VERSION}.zip", names)
            self.assertIn(f"sentinel-blue-complete-lab-{VERSION}.zip", names)
            self.assertFalse(any("portal-extension" in name for name in names))
            with zipfile.ZipFile(Path(directory) / f"sentinel-blue-{VERSION}.pyz") as archive:
                self.assertIn("sentinel_blue/__main__.py", archive.namelist())
                self.assertFalse(any(".egg-info/" in name for name in archive.namelist()))
            with zipfile.ZipFile(Path(directory) / f"sentinel-blue-source-{VERSION}.zip") as archive:
                self.assertIn(".gitignore", archive.namelist())
                self.assertFalse(any(".egg-info/" in name for name in archive.namelist()))
            with zipfile.ZipFile(Path(directory) / f"sentinel-blue-complete-lab-{VERSION}.zip") as archive:
                self.assertEqual(
                    {
                        f"sentinel-blue-{VERSION}.pyz",
                        f"sentinel-blue-source-{VERSION}.zip",
                        "SHA256SUMS",
                    },
                    set(archive.namelist()),
                )
            self.assertEqual(check_source(VERSION), VERSION)
            check_bundle(
                Path(directory) / f"sentinel-blue-complete-lab-{VERSION}.zip",
                VERSION,
            )

    def test_build_is_byte_reproducible(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            first_hashes = {
                path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in build(Path(first))
            }
            second_hashes = {
                path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in build(Path(second))
            }
            self.assertEqual(first_hashes, second_hashes)

    def test_archive_guard_rejects_noncanonical_and_platform_unsafe_names(self):
        cases = (
            (("path/item", b"a"), ("path/./item", b"b")),
            (("path/item", b"a"), ("path//item", b"b")),
            (("C:/outside", b"a"),),
            (("path/item:stream", b"a"),),
            (("path/item", b"a"), ("path/item.", b"b")),
            (("path/item", b"a"), ("path/it?m", b"b")),
            (("path/CON.txt", b"a"),),
            (("caf\N{LATIN SMALL LETTER E WITH ACUTE}", b"a"), ("cafe\N{COMBINING ACUTE ACCENT}", b"b")),
            ((".", b"a"),),
        )
        for entries in cases:
            with self.subTest(names=[name for name, _content in entries]):
                with zipfile.ZipFile(io.BytesIO(_zip_bytes(list(entries)))) as archive:
                    with self.assertRaisesRegex(ValueError, "unsafe|duplicate"):
                        _safe_archive(archive, "probe")

    def test_bundle_guard_rejects_duplicate_and_extra_checksum_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifacts = build(root)
            bundle = next(path for path in artifacts if "complete-lab" in path.name)
            with zipfile.ZipFile(bundle) as archive:
                members = {name: archive.read(name) for name in archive.namelist()}
            checksum = members["SHA256SUMS"]
            mutations = (
                checksum + checksum.splitlines(keepends=True)[0],
                checksum + b"0" * 64 + b"  unlisted.zip\n",
            )
            for index, mutated_checksum in enumerate(mutations):
                with self.subTest(index=index):
                    mutated_bundle = root / f"mutated-{index}.zip"
                    mutated_bundle.write_bytes(
                        _zip_bytes(
                            [
                                (name, mutated_checksum if name == "SHA256SUMS" else content)
                                for name, content in members.items()
                            ]
                        )
                    )
                    with self.assertRaisesRegex(ValueError, "invalid row"):
                        check_bundle(mutated_bundle, VERSION)

    def test_bundle_guard_rejects_repacked_checksum_refreshed_inner_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifacts = build(root)
            bundle = next(path for path in artifacts if "complete-lab" in path.name)
            runtime_name = f"sentinel-blue-{VERSION}.pyz"
            source_name = f"sentinel-blue-source-{VERSION}.zip"
            with zipfile.ZipFile(bundle) as archive:
                runtime = archive.read(runtime_name)
                source = archive.read(source_name)
            mutations = (
                (
                    runtime_name,
                    _replace_zip_member(
                        runtime,
                        "sentinel_blue/auth.py",
                        b"# repacked runtime drift\n",
                    ),
                    "runtime member",
                ),
                (
                    runtime_name,
                    _replace_zip_member(runtime, "__main__.py", b"raise SystemExit(0)\n"),
                    "generated runtime __main__",
                ),
                (
                    source_name,
                    _replace_zip_member(
                        source,
                        "src/sentinel_blue/auth.py",
                        b"# repacked source drift\n",
                    ),
                    "runtime member",
                ),
            )
            for index, (artifact_name, artifact_content, error) in enumerate(mutations):
                with self.subTest(artifact=artifact_name, error=error):
                    mutated_bundle = root / f"inner-drift-{index}.zip"
                    _refresh_bundle_artifact(
                        bundle,
                        mutated_bundle,
                        artifact_name,
                        artifact_content,
                    )
                    with self.assertRaisesRegex(ValueError, error):
                        check_bundle(mutated_bundle, VERSION)


if __name__ == "__main__":
    unittest.main()
