#!/usr/bin/env python3
"""Join the original Sentinel Blue 2.0.20 installer; never execute its contents.

Put the 10 supplied installer.partNNN files beside this script and run it.
Only Python's standard library is used. Raw .part files are also accepted.
Checksums detect accidental corruption; they are not a publisher signature.
"""
from pathlib import Path
from contextlib import contextmanager
import argparse
import hashlib
import io
import json
import os
import sys
import tempfile
import zipfile

MANIFEST = json.loads('{"format": "sentinel-blue-exact-file-split-v1", "release": "2.0.20", "original": {"name": "sentinel-blue-2.0.20-linux-gui1-x86_64.run", "bytes": 79638062, "sha256": "b9c969ecb5f6984b5a56d3d8cc53b6e3fa16b49c3856eddd371bd7ca6b506da8"}, "parts": [{"number": 1, "name": "installer.part001", "archive": "installer.part001.zip", "bytes": 8000001, "sha256": "b426369370af8895aa9b2366c4bce40aabe90e31afa127a11b0dd7d9e6932767"}, {"number": 2, "name": "installer.part002", "archive": "installer.part002.zip", "bytes": 8000001, "sha256": "fbd146d996a46363a292845ff01c4f474c7bf7ec5339111a71ecc75fd730ca3a"}, {"number": 3, "name": "installer.part003", "archive": "installer.part003.zip", "bytes": 8000001, "sha256": "ceba91527c6f87d5fdec856232540893f7fab562da2d197299558406eda13cd9"}, {"number": 4, "name": "installer.part004", "archive": "installer.part004.zip", "bytes": 8000001, "sha256": "d19bb90fc8e61ad92bd7f90bd9b9e2489f5bab85c69e6da80a1c691dd8b744ea"}, {"number": 5, "name": "installer.part005", "archive": "installer.part005.zip", "bytes": 8000001, "sha256": "afd69a1d6e1d8724d9cdd6d529d7aa0851c690855235f2dfe6f25d9586e5aa3d"}, {"number": 6, "name": "installer.part006", "archive": "installer.part006.zip", "bytes": 8000001, "sha256": "2a44dc626c741ecb9aced0233f64bd2bb544af41367407eb56cfd8cfc1fbb81a"}, {"number": 7, "name": "installer.part007", "archive": "installer.part007.zip", "bytes": 8000001, "sha256": "30a9a7a8d2c77bdb4c740f64eb5218597b44bb6e8756180c893d9084780cdeb0"}, {"number": 8, "name": "installer.part008", "archive": "installer.part008.zip", "bytes": 8000001, "sha256": "2cc54022026f27dfca182c008c9aa2cab92c19abc423300f89f93020f5b18247"}, {"number": 9, "name": "installer.part009", "archive": "installer.part009.zip", "bytes": 8000001, "sha256": "65b89522569fab7dca877916b52fc893e4bf61394fa63d5fd58ec699aa776c88"}, {"number": 10, "name": "installer.part010", "archive": "installer.part010.zip", "bytes": 7638053, "sha256": "1926ed7b472b9062e66e265af1b47df2687a2ba010bc3981b88ff699a5078c46"}]}')

@contextmanager
def open_piece(directory, part):
    """Read only the expected ZIP member; do not extract archive paths."""
    archive = directory / part["archive"]
    raw = directory / part["name"]
    if archive.exists():
        with zipfile.ZipFile(archive) as bundle:
            matches = [i for i in bundle.infolist() if i.filename == part["name"]]
            if len(matches) != 1:
                raise ValueError("Missing or duplicate piece inside " + archive.name)
            item = matches[0]
            if item.is_dir() or item.file_size != part["bytes"] or item.flag_bits & 1:
                raise ValueError("Unexpected size or encrypted piece in " + archive.name)
            with bundle.open(item) as stream:
                yield stream
    elif raw.is_file():
        if raw.stat().st_size != part["bytes"]:
            raise ValueError("Wrong size: " + raw.name)
        with raw.open("rb") as stream:
            yield stream
    else:
        raise FileNotFoundError("Missing " + part["archive"] + " (or " + part["name"] + ")")

def copy_checked(stream, part, sink, total_hash):
    count = 0
    piece_hash = hashlib.sha256()
    while True:
        block = stream.read(min(1024 * 1024, part["bytes"] - count + 1))
        if not block:
            break
        count += len(block)
        if count > part["bytes"]:
            raise ValueError("Piece exceeds recorded size: " + part["name"])
        piece_hash.update(block)
        total_hash.update(block)
        if sink is not None:
            sink.write(block)
    if count != part["bytes"] or piece_hash.hexdigest() != part["sha256"]:
        raise ValueError("Checksum or size mismatch: " + part["name"])
    return count

def join(directory, output=None):
    """Verify ordered chunks; publish only a fully verified result."""
    total = hashlib.sha256()
    size = 0
    temporary = None
    sink = None
    if output is not None:
        if output.exists() or output.is_symlink():
            raise FileExistsError("Refusing to overwrite " + str(output))
        fd, temporary = tempfile.mkstemp(prefix=".sentinel-join-", suffix=".tmp", dir=output.parent)
        sink = os.fdopen(fd, "wb")
    try:
        for part in MANIFEST["parts"]:
            with open_piece(directory, part) as stream:
                size += copy_checked(stream, part, sink, total)
            print("Verified part {}/{}".format(part["number"], len(MANIFEST["parts"])))
        expected = MANIFEST["original"]
        if size != expected["bytes"] or total.hexdigest() != expected["sha256"]:
            raise ValueError("Reassembled file does not match the original")
        if sink is not None:
            sink.flush()
            os.fsync(sink.fileno())
            sink.close()
            sink = None
            # Atomic no-overwrite publication on filesystems supporting hard links.
            # If unsupported, leave no final output; choose a local filesystem.
            os.link(temporary, output)
        print("Verified entire installer: {} bytes; SHA-256 {}".format(size, total.hexdigest()))
        if output is not None:
            print("Saved: " + str(output))
        return total.hexdigest()
    finally:
        if sink is not None:
            sink.close()
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=Path(__file__).resolve().parent,
                        help="Folder containing all 10 installer parts (default: beside script)")
    parser.add_argument("--output", type=Path, help="New output file; existing files are never overwritten")
    parser.add_argument("--verify-only", action="store_true", help="Verify without creating the installer")
    args = parser.parse_args()
    if args.verify_only and args.output is not None:
        parser.error("--output cannot be combined with --verify-only")
    destination = None if args.verify_only else (args.output or args.directory / MANIFEST["original"]["name"])
    try:
        join(args.directory, destination)
    except (OSError, ValueError, RuntimeError, zipfile.BadZipFile) as exc:
        print("Not saved: " + str(exc), file=sys.stderr)
        return 1
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
