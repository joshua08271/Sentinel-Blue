import ctypes
import hashlib
import json
import os
import tempfile
import unittest
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from sentinel_blue import restoration


class _NativeFunction:
    def __init__(self, callback):
        self.callback = callback
        self.argtypes = None
        self.restype = None

    def __call__(self, *args):
        return self.callback(*args)


class _TokenApis:
    def __init__(
        self,
        *,
        prior_thread_token: bool = False,
        thread_token_error: int = 1008,
        adjust_error: int = 0,
        revert_succeeds: bool = True,
    ):
        self.prior_thread_token = prior_thread_token
        self.thread_token_error = thread_token_error
        self.adjust_error = adjust_error
        self.revert_succeeds = revert_succeeds
        self.last_error = 0
        self.opened_process = False
        self.adjusted_handles = []
        self.set_thread_handles = []
        self.revert_calls = 0
        self.closed_handles = []
        self.advapi32 = SimpleNamespace(
            OpenThreadToken=_NativeFunction(self._open_thread_token),
            OpenProcessToken=_NativeFunction(self._open_process_token),
            DuplicateTokenEx=_NativeFunction(self._duplicate_token),
            SetThreadToken=_NativeFunction(self._set_thread_token),
            RevertToSelf=_NativeFunction(self._revert_to_self),
            LookupPrivilegeValueW=_NativeFunction(lambda *_args: 1),
            AdjustTokenPrivileges=_NativeFunction(self._adjust_token),
        )
        self.kernel32 = SimpleNamespace(
            GetCurrentThread=_NativeFunction(lambda: 1),
            GetCurrentProcess=_NativeFunction(lambda: 2),
            GetCurrentThreadId=_NativeFunction(lambda: 99),
            CloseHandle=_NativeFunction(self._close_handle),
        )

    @staticmethod
    def _value(handle):
        return int(getattr(handle, "value", handle) or 0)

    def _open_thread_token(self, _thread, _access, _open_as_self, output):
        if not self.prior_thread_token:
            self.last_error = self.thread_token_error
            return 0
        output._obj.value = 10
        return 1

    def _open_process_token(self, _process, _access, output):
        self.opened_process = True
        output._obj.value = 11
        return 1

    def _duplicate_token(self, _source, _access, _attributes, _level, _kind, output):
        output._obj.value = 22
        return 1

    def _set_thread_token(self, _thread, token):
        self.set_thread_handles.append(self._value(token))
        return 1

    def _revert_to_self(self):
        self.revert_calls += 1
        if not self.revert_succeeds:
            self.last_error = 5
            return 0
        return 1

    def _adjust_token(self, token, *_args):
        self.adjusted_handles.append(self._value(token))
        self.last_error = self.adjust_error
        return 1

    def _close_handle(self, token):
        self.closed_handles.append(self._value(token))
        return 1

    def dll(self, name, **_kwargs):
        return self.advapi32 if name.casefold().startswith("advapi32") else self.kernel32

    def set_last_error(self, value):
        self.last_error = int(value)


class _FakeWindowsFileOps:
    """Linux-runnable recorder for the handle-only Windows mutation flow."""

    def __init__(
        self,
        *,
        reparse_handle=None,
        fail_rename=False,
        read_data=b"approved bytes",
        zero_links_while_delete_pending=False,
    ):
        self.events = []
        self.reparse_handle = reparse_handle
        self.fail_rename = fail_rename
        self.read_data = read_data
        self.zero_links_while_delete_pending = zero_links_while_delete_pending
        self.delete_pending_handles = set()
        self.written = {}
        self._directory_handles = iter((10, 11))

    def open_file(self, path, desired_access, share_mode, creation, flags):
        if creation == restoration.WINDOWS_CREATE_NEW:
            handle = 90
        elif str(path).casefold().endswith("target.conf"):
            handle = 91
        elif "\\.sentinel-" in str(path).casefold():
            handle = 92
        else:
            handle = next(self._directory_handles)
        self.events.append(
            ("open", handle, str(path), desired_access, share_mode, creation, flags)
        )
        return handle

    def file_attributes(self, handle):
        self.events.append(("attributes", handle))
        if handle == self.reparse_handle:
            return (
                restoration.WINDOWS_FILE_ATTRIBUTE_DIRECTORY
                | restoration.WINDOWS_REPARSE_POINT_ATTRIBUTE
            )
        if handle in {10, 11}:
            return restoration.WINDOWS_FILE_ATTRIBUTE_DIRECTORY
        return restoration.WINDOWS_FILE_ATTRIBUTE_NORMAL

    def final_path(self, handle):
        self.events.append(("final_path", handle))
        return (
            "\\\\?\\Volume{00000000-0000-0000-0000-000000000001}\\"
            if handle == 10
            else r"\\?\Volume{00000000-0000-0000-0000-000000000001}\safe"
        )

    def file_snapshot(self, handle):
        self.events.append(("snapshot", handle))
        return {
            "attributes": self.file_attributes(handle),
            "size": len(self.written.get(handle, self.read_data)),
            "modified_at": 1234.5,
            "creation_ticks": 116444736000000000 + 12300000000,
            "modified_ticks": 116444736000000000 + 12345000000,
            "identity": (1, 2, handle),
            "links": (
                0
                if self.zero_links_while_delete_pending
                and handle in self.delete_pending_handles
                else 1
            ),
        }

    def read_file(self, handle, maximum):
        self.events.append(("read", handle, maximum))
        return self.read_data[: maximum + 1]

    def write_file(self, handle, data):
        self.events.append(("write", handle, data))
        self.written[handle] = bytes(data)

    def flush_file(self, handle):
        self.events.append(("flush", handle))

    def apply_mode(self, handle, mode):
        self.events.append(("mode", handle, mode))

    def set_delete_disposition(self, handle, delete):
        self.events.append(("delete", handle, delete))
        if delete:
            self.delete_pending_handles.add(handle)
        else:
            self.delete_pending_handles.discard(handle)

    def rename_file(self, handle, parent_handle, leaf, *, replace_if_exists=True):
        self.events.append(
            ("rename", handle, parent_handle, leaf, replace_if_exists)
        )
        if self.fail_rename:
            raise OSError("synthetic rename failure")

    def close(self, handle):
        self.events.append(("close", handle))


class WindowsRestorationTests(unittest.TestCase):
    @staticmethod
    def _expected_metadata(
        *,
        handle=91,
        data=b"approved bytes",
        descriptor="approved-descriptor",
    ):
        return {
            "mode": 0o666,
            "windows_security_descriptor": descriptor,
            "windows_security_descriptor_version": (
                restoration.WINDOWS_SECURITY_DESCRIPTOR_VERSION
            ),
            "windows_file_identity": [1, 2, handle],
            "windows_creation_ticks": 116444736000000000 + 12300000000,
            "windows_modified_ticks": 116444736000000000 + 12345000000,
            "windows_file_size": len(data),
            "windows_hard_links": 1,
            "windows_file_attributes": restoration.WINDOWS_FILE_ATTRIBUTE_NORMAL,
        }

    def _patched_token_apis(self, api):
        return (
            patch.object(ctypes, "WinDLL", create=True, side_effect=api.dll),
            patch.object(
                ctypes, "get_last_error", create=True, side_effect=lambda: api.last_error
            ),
            patch.object(ctypes, "set_last_error", create=True, side_effect=api.set_last_error),
        )

    def test_privilege_scope_uses_disposable_thread_token(self):
        api = _TokenApis()
        first, second, third = self._patched_token_apis(api)
        with first, second, third:
            with restoration._windows_privileges_unlocked("SeBackupPrivilege"):
                self.assertEqual(api.set_thread_handles, [22])
        self.assertTrue(api.opened_process)
        self.assertEqual(api.adjusted_handles, [22])
        self.assertEqual(api.revert_calls, 1)
        self.assertEqual(api.closed_handles, [22, 11])

    def test_privilege_scope_restores_preexisting_thread_token(self):
        api = _TokenApis(prior_thread_token=True)
        first, second, third = self._patched_token_apis(api)
        with first, second, third:
            with restoration._windows_privileges_unlocked("SeRestorePrivilege"):
                pass
        self.assertFalse(api.opened_process)
        self.assertEqual(api.set_thread_handles, [22, 10])
        self.assertEqual(api.revert_calls, 0)
        self.assertEqual(api.closed_handles, [22, 10])

    def test_privilege_revert_failure_is_fail_stop(self):
        api = _TokenApis(revert_succeeds=False)
        first, second, third = self._patched_token_apis(api)
        with (
            first,
            second,
            third,
            patch.object(
                restoration,
                "_windows_privilege_fail_stop",
                side_effect=RuntimeError("synthetic fail-stop"),
            ) as fail_stop,
        ):
            with self.assertRaisesRegex(RuntimeError, "synthetic fail-stop"):
                with restoration._windows_privileges_unlocked("SeSecurityPrivilege"):
                    pass
        fail_stop.assert_called_once_with()

    def test_unexpected_thread_token_error_never_falls_back_to_process_token(self):
        api = _TokenApis(thread_token_error=5)
        first, second, third = self._patched_token_apis(api)
        with first, second, third:
            with self.assertRaisesRegex(OSError, "thread token"):
                with restoration._windows_privileges_unlocked("SeBackupPrivilege"):
                    self.fail("privilege scope must not be entered")
        self.assertFalse(api.opened_process)
        self.assertEqual(api.set_thread_handles, [])

    def test_unassigned_privilege_never_attaches_scoped_token(self):
        api = _TokenApis(adjust_error=1300)
        first, second, third = self._patched_token_apis(api)
        with first, second, third:
            with self.assertRaisesRegex(PermissionError, "not assigned"):
                with restoration._windows_privileges_unlocked("SeBackupPrivilege"):
                    self.fail("privilege scope must not be entered")
        self.assertEqual(api.set_thread_handles, [])
        self.assertEqual(api.revert_calls, 0)
        self.assertEqual(api.closed_handles, [22, 11])

    def test_file_information_structures_match_the_win32_abi(self):
        self.assertEqual(ctypes.sizeof(restoration._WindowsRenameChoice), 4)
        self.assertEqual(
            ctypes.sizeof(restoration._WindowsFileDispositionInformation), 1
        )
        disposition = restoration._WindowsFileDispositionInformation(1)
        self.assertEqual(ctypes.string_at(ctypes.byref(disposition), 1), b"\x01")

        leaf = "target.conf"
        encoded = leaf.encode("utf-16-le")
        information = restoration._windows_file_rename_information(77, leaf)
        kind = type(information)
        self.assertEqual(kind.choice.offset, 0)
        self.assertEqual(kind.RootDirectory.offset % ctypes.alignment(ctypes.c_void_p), 0)
        self.assertEqual(information.ReplaceIfExists, 1)
        self.assertEqual(information.RootDirectory, 77)
        self.assertEqual(information.FileNameLength, len(encoded))
        self.assertEqual(
            ctypes.string_at(
                ctypes.addressof(information) + kind.FileName.offset,
                information.FileNameLength,
            ),
            encoded,
        )
        self.assertGreaterEqual(
            ctypes.sizeof(information), kind.FileName.offset + len(encoded) + 2
        )
        self.assertEqual(
            restoration._windows_file_rename_information_size(information),
            ctypes.sizeof(restoration._WindowsFileRenameInformationHeader)
            + len(encoded),
        )
        non_replacing = restoration._windows_file_rename_information(
            77,
            leaf,
            replace_if_exists=False,
        )
        self.assertEqual(non_replacing.ReplaceIfExists, 0)
        with self.assertRaisesRegex(ValueError, "unsafe file name"):
            restoration._windows_file_rename_information(77, "..\\escape")

    def test_delete_disposition_is_passed_as_a_one_byte_boolean(self):
        observed = []
        native = object.__new__(restoration._WindowsNativeFileOps)

        def set_information(handle, information_class, pointer, size):
            observed.append(
                (
                    handle,
                    information_class,
                    size,
                    ctypes.string_at(pointer, size),
                )
            )
            return 1

        native._set_information = set_information
        native.set_delete_disposition(41, True)
        self.assertEqual(
            observed,
            [(41, restoration.WINDOWS_FILE_DISPOSITION_INFO_CLASS, 1, b"\x01")],
        )

    def test_rename_uses_the_variable_win32_buffer_length(self):
        observed = []
        native = object.__new__(restoration._WindowsNativeFileOps)

        def set_information(handle, information_class, pointer, size):
            observed.append((handle, information_class, size, ctypes.string_at(pointer, size)))
            return 1

        native._set_information = set_information
        native.rename_file(41, 77, "target.conf")
        self.assertEqual(observed[0][0:2], (41, restoration.WINDOWS_FILE_RENAME_INFO_CLASS))
        expected = restoration._windows_file_rename_information(
            77,
            "target.conf",
        )
        self.assertEqual(
            observed[0][2],
            restoration._windows_file_rename_information_size(expected),
        )
        kind = type(expected)
        serialized = observed[0][3]
        root_size = ctypes.sizeof(ctypes.c_void_p)
        self.assertEqual(
            int.from_bytes(
                serialized[
                    kind.RootDirectory.offset : kind.RootDirectory.offset + root_size
                ],
                "little",
            ),
            77,
        )
        encoded = "target.conf".encode("utf-16-le")
        self.assertEqual(
            serialized[kind.FileName.offset : kind.FileName.offset + len(encoded)],
            encoded,
        )
        self.assertEqual(serialized[-2:], b"\x00\x00")

    @unittest.skipUnless(os.name == "nt", "native Windows file APIs unavailable")
    def test_native_atomic_write_publishes_exact_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "native-atomic-write.bin"
            expected = b"sentinel\x1a\r\nblue\x00binary"
            restoration._windows_atomic_write(target, expected, 0o600, None)
            self.assertEqual(target.read_bytes(), expected)

    def test_descriptor_equivalence_uses_acl_semantics_and_fails_closed(self):
        shared = (
            1,
            0,
            0,
            b"owner",
            b"group",
            ("present", 2, (b"\x00\x00\x04\x00",)),
            ("absent",),
        )
        semantic_keys = {
            "first-encoding": shared,
            "second-encoding": shared,
            "different-acl": (
                *shared[:5],
                ("present", 2, (b"\x01\x00\x04\x00",)),
                shared[6],
            ),
        }
        with (
            patch.object(restoration.os, "name", "nt"),
            patch.object(
                restoration,
                "_windows_security_descriptor_semantics",
                side_effect=lambda value: semantic_keys[value],
            ),
        ):
            self.assertTrue(
                restoration._windows_security_descriptors_equivalent(
                    "first-encoding", "second-encoding"
                )
            )
            self.assertFalse(
                restoration._windows_security_descriptors_equivalent(
                    "first-encoding", "different-acl"
                )
            )
            self.assertFalse(
                restoration._windows_security_descriptors_equivalent(
                    "first-encoding", "malformed"
                )
            )
        self.assertTrue(
            restoration._windows_security_descriptors_equivalent(
                "same-encoding", "same-encoding"
            )
        )
        self.assertFalse(
            restoration._windows_security_descriptors_equivalent("", "")
        )

    @unittest.skipUnless(os.name == "nt", "native Windows file APIs unavailable")
    def test_native_acl_round_trip_preserves_security_semantics(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "native-acl-round-trip.bin"
            original = b"approved-state"
            replacement_bytes = b"restored-state\x00binary"
            target.write_bytes(original)
            before_data, before_snapshot = restoration._windows_read_file_snapshot(
                target, restoration.MAX_FILE_BYTES
            )
            before_metadata = restoration._windows_metadata_from_native_snapshot(
                before_snapshot
            )
            restoration._windows_atomic_write(
                target,
                replacement_bytes,
                int(before_metadata["mode"]),
                before_metadata,
                expected_current=(before_data, before_metadata),
            )
            after_data, after_snapshot = restoration._windows_read_file_snapshot(
                target, restoration.MAX_FILE_BYTES
            )
            self.assertEqual(after_data, replacement_bytes)
            self.assertTrue(
                restoration._windows_security_descriptors_equivalent(
                    before_metadata["windows_security_descriptor"],
                    after_snapshot["windows_security_descriptor"],
                )
            )

    def test_private_file_verifies_links_after_delete_pending_is_cleared(self):
        class DeletePendingLinkCount(_FakeWindowsFileOps):
            def __init__(self):
                super().__init__(read_data=b"")
                self.delete_pending = {}
                self.written = {}

            def write_file(self, handle, data):
                self.written[handle] = bytes(data)
                super().write_file(handle, data)

            def set_delete_disposition(self, handle, delete):
                self.delete_pending[handle] = bool(delete)
                super().set_delete_disposition(handle, delete)

            def file_snapshot(self, handle):
                pending = self.delete_pending.get(handle, False)
                self.events.append(("snapshot", handle, pending))
                return {
                    "attributes": restoration.WINDOWS_FILE_ATTRIBUTE_NORMAL,
                    "size": len(self.written.get(handle, b"")),
                    "modified_at": 1234.5,
                    "creation_ticks": 116444736000000000 + 12300000000,
                    "modified_ticks": 116444736000000000 + 12345000000,
                    "identity": (1, 2, handle),
                    # NTFS may expose zero links while delete-on-close is armed.
                    "links": 0 if pending else 1,
                }

        native = DeletePendingLinkCount()
        restoration._windows_write_new_private_file(
            Path(r"C:\safe\ownership.key"),
            b"k" * restoration.WINDOWS_TEMP_KEY_BYTES,
            native=native,
        )
        snapshots = [event for event in native.events if event[0] == "snapshot"]
        self.assertEqual(snapshots, [("snapshot", 90, True), ("snapshot", 90, False)])
        self.assertEqual(
            [event for event in native.events if event[0] == "delete"],
            [("delete", 90, True), ("delete", 90, False)],
        )
        self.assertEqual(
            [event for event in native.events if event[0] == "close"][-3:],
            [("close", 90), ("close", 11), ("close", 10)],
        )

    def test_private_file_rearms_cleanup_when_post_publish_gate_fails(self):
        class UnsafePublishedLinkCount(_FakeWindowsFileOps):
            def __init__(self):
                super().__init__(read_data=b"")
                self.delete_pending = {}
                self.written = {}

            def write_file(self, handle, data):
                self.written[handle] = bytes(data)
                super().write_file(handle, data)

            def set_delete_disposition(self, handle, delete):
                self.delete_pending[handle] = bool(delete)
                super().set_delete_disposition(handle, delete)

            def file_snapshot(self, handle):
                pending = self.delete_pending.get(handle, False)
                self.events.append(("snapshot", handle, pending))
                return {
                    "attributes": restoration.WINDOWS_FILE_ATTRIBUTE_NORMAL,
                    "size": len(self.written.get(handle, b"")),
                    "modified_at": 1234.5,
                    "creation_ticks": 116444736000000000 + 12300000000,
                    "modified_ticks": 116444736000000000 + 12345000000,
                    "identity": (1, 2, handle),
                    "links": 0 if pending else 2,
                }

        native = UnsafePublishedLinkCount()
        with self.assertRaisesRegex(OSError, "after publication"):
            restoration._windows_write_new_private_file(
                Path(r"C:\safe\ownership.key"),
                b"k" * restoration.WINDOWS_TEMP_KEY_BYTES,
                native=native,
            )
        self.assertEqual(
            [event for event in native.events if event[0] == "delete"],
            [("delete", 90, True), ("delete", 90, False), ("delete", 90, True)],
        )
        self.assertEqual(
            [event for event in native.events if event[0] == "close"][-3:],
            [("close", 90), ("close", 11), ("close", 10)],
        )

    def test_path_parser_accepts_only_unaliased_local_drive_files(self):
        root, parents, leaf = restoration._windows_path_components(
            Path(r"c:\ProgramData\Sentinel Blue\agent.json")
        )
        self.assertEqual(root, "C:\\")
        self.assertEqual(parents, ["ProgramData", "Sentinel Blue"])
        self.assertEqual(leaf, "agent.json")
        unsafe = (
            r"\\server\share\agent.json",
            r"\\?\C:\safe\agent.json",
            r"C:\safe\agent.json:stream",
            r"C:\safe\..\agent.json",
            r"C:\safe\CON.txt",
            "C:\\safe\\trailing.\\agent.json",
            r"C:relative\agent.json",
            "C:\\",
        )
        for candidate in unsafe:
            with self.subTest(candidate=candidate):
                with self.assertRaises(ValueError):
                    restoration._windows_path_components(Path(candidate))

    def test_parent_walk_holds_no_reparse_handles_and_closes_in_reverse(self):
        native = _FakeWindowsFileOps()
        with restoration._windows_pinned_parent(
            Path(r"C:\safe\target.conf"),
            native,
            require_add_file=True,
        ) as (parent_handle, parent_path, leaf):
            self.assertEqual(parent_handle, 11)
            self.assertTrue(parent_path.casefold().endswith("}\\safe"))
            self.assertEqual(leaf, "target.conf")
        opens = [event for event in native.events if event[0] == "open"]
        self.assertEqual(opens[0][2], "C:\\")
        self.assertTrue(opens[1][2].casefold().endswith("}\\safe"))
        for event in opens:
            self.assertTrue(
                event[6] & restoration.WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT
            )
            self.assertEqual(event[4], restoration.WINDOWS_FILE_SHARE_READ)
            self.assertFalse(event[4] & restoration.WINDOWS_FILE_SHARE_WRITE)
            self.assertFalse(event[4] & restoration.WINDOWS_FILE_SHARE_DELETE)
        self.assertFalse(opens[0][3] & restoration.WINDOWS_FILE_ADD_FILE)
        self.assertTrue(opens[-1][3] & restoration.WINDOWS_FILE_ADD_FILE)
        self.assertEqual(native.events[-2:], [("close", 11), ("close", 10)])

        default_native = _FakeWindowsFileOps()
        with restoration._windows_pinned_parent(
            Path(r"C:\safe\target.conf"), default_native
        ):
            pass
        default_opens = [
            event for event in default_native.events if event[0] == "open"
        ]
        self.assertTrue(
            all(
                event[4] == restoration.WINDOWS_FILE_SHARE_READ
                for event in default_opens
            )
        )
        self.assertTrue(
            all(
                not event[3] & restoration.WINDOWS_FILE_ADD_FILE
                for event in default_opens
            )
        )


    def test_parent_walk_rejects_reparse_and_closes_every_open_handle(self):
        native = _FakeWindowsFileOps(reparse_handle=11)
        with self.assertRaisesRegex(ValueError, "reparse point"):
            with restoration._windows_pinned_parent(
                Path(r"C:\safe\target.conf"), native
            ):
                self.fail("unsafe parent must not be yielded")
        self.assertEqual(native.events[-2:], [("close", 11), ("close", 10)])

    def test_read_snapshot_pins_ancestors_and_binds_all_observations_to_leaf_handle(self):
        native = _FakeWindowsFileOps(read_data=b"trusted content")

        def capture(path, *, native_handle):
            native.events.append(("capture_descriptor", native_handle, str(path)))
            return "approved-descriptor"

        with (
            patch.object(
                restoration,
                "_capture_windows_security_descriptor",
                side_effect=capture,
            ),
            patch.object(Path, "open", side_effect=AssertionError),
            patch.object(Path, "lstat", side_effect=AssertionError),
        ):
            data, snapshot = restoration._windows_read_file_snapshot(
                Path(r"C:\safe\target.conf"),
                1024,
                native=native,
            )

        self.assertEqual(data, b"trusted content")
        self.assertEqual(snapshot["windows_security_descriptor"], "approved-descriptor")
        leaf_open = [
            event
            for event in native.events
            if event[0] == "open" and event[1] == 91
        ][0]
        self.assertTrue(leaf_open[3] & restoration.WINDOWS_GENERIC_READ)
        self.assertTrue(leaf_open[3] & restoration.WINDOWS_READ_CONTROL)
        self.assertTrue(leaf_open[3] & restoration.WINDOWS_ACCESS_SYSTEM_SECURITY)
        self.assertEqual(leaf_open[4], restoration.WINDOWS_FILE_SHARE_READ)
        self.assertFalse(leaf_open[4] & restoration.WINDOWS_FILE_SHARE_WRITE)
        self.assertFalse(leaf_open[4] & restoration.WINDOWS_FILE_SHARE_DELETE)
        self.assertTrue(
            leaf_open[6] & restoration.WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT
        )
        self.assertIn(("read", 91, 1024), native.events)
        self.assertIn(
            ("capture_descriptor", 91, r"C:\safe\target.conf"), native.events
        )
        self.assertEqual(native.events[-3:], [("close", 91), ("close", 11), ("close", 10)])

    def test_read_snapshot_rejects_oversized_or_reparse_leaf_before_read(self):
        oversized = _FakeWindowsFileOps(read_data=b"too large")
        with self.assertRaisesRegex(ValueError, "byte limit"):
            restoration._windows_read_file_snapshot(
                Path(r"C:\safe\target.conf"),
                2,
                capture_security=False,
                native=oversized,
            )
        self.assertNotIn("read", [event[0] for event in oversized.events])
        self.assertEqual(
            oversized.events[-3:],
            [("close", 91), ("close", 11), ("close", 10)],
        )

        reparse = _FakeWindowsFileOps(reparse_handle=91)
        with self.assertRaisesRegex(ValueError, "reparse point"):
            restoration._windows_read_file_snapshot(
                Path(r"C:\safe\target.conf"),
                1024,
                capture_security=False,
                native=reparse,
            )
        self.assertNotIn("read", [event[0] for event in reparse.events])
        self.assertEqual(
            reparse.events[-3:],
            [("close", 91), ("close", 11), ("close", 10)],
        )

    def test_optional_snapshot_distinguishes_absence_from_unsafe_or_denied_state(self):
        target = Path(r"C:\safe\target.conf")
        for error in (
            FileNotFoundError(restoration.WINDOWS_ERROR_FILE_NOT_FOUND, "missing"),
            OSError(restoration.WINDOWS_ERROR_PATH_NOT_FOUND, "missing parent"),
        ):
            with self.subTest(error=error):
                with patch.object(
                    restoration,
                    "_windows_read_file_snapshot",
                    side_effect=error,
                ):
                    self.assertIsNone(
                        restoration._windows_read_file_snapshot_if_present(
                            target, 1024
                        )
                    )

        for error in (
            PermissionError(5, "access denied"),
            OSError(32, "sharing violation"),
            ValueError("reparse point"),
        ):
            with self.subTest(error=error):
                with patch.object(
                    restoration,
                    "_windows_read_file_snapshot",
                    side_effect=error,
                ):
                    with self.assertRaises(type(error)):
                        restoration._windows_read_file_snapshot_if_present(
                            target, 1024
                        )

    def test_restore_store_routes_target_and_private_reads_through_pinned_snapshot(self):
        target = Path(r"C:\safe\target.conf")
        target_snapshot = {
            "attributes": restoration.WINDOWS_FILE_ATTRIBUTE_READONLY,
            "size": 8,
            "creation_ticks": 122,
            "modified_ticks": 123,
            "identity": (1, 2, 3),
            "links": 1,
            "windows_security_descriptor": "approved-descriptor",
        }
        with (
            patch.object(restoration.os, "name", "nt"),
            patch.object(
                restoration,
                "_windows_read_file_snapshot",
                return_value=(b"approved", target_snapshot),
            ) as read_snapshot,
            patch.object(Path, "open", side_effect=AssertionError),
            patch.object(Path, "lstat", side_effect=AssertionError),
        ):
            data, metadata = restoration.RestorePointStore._read_target(target)
        self.assertEqual(data, b"approved")
        self.assertEqual(metadata["mode"], 0o444)
        self.assertEqual(
            metadata["windows_security_descriptor"], "approved-descriptor"
        )
        read_snapshot.assert_called_once_with(target, restoration.MAX_FILE_BYTES)

        with (
            patch.object(restoration.os, "name", "nt"),
            patch.object(
                restoration,
                "_windows_read_file_snapshot",
                return_value=(b"private", {"size": 7}),
            ) as read_snapshot,
            patch.object(Path, "open", side_effect=AssertionError),
            patch.object(Path, "lstat", side_effect=AssertionError),
        ):
            data = restoration.RestorePointStore._read_private_file(target, 4096)
        self.assertEqual(data, b"private")
        read_snapshot.assert_called_once_with(
            target,
            4096,
            capture_security=False,
        )

    def test_windows_optional_store_reads_never_use_path_existence_gates(self):
        target = Path(r"C:\safe\target.conf")
        with (
            patch.object(restoration.os, "name", "nt"),
            patch.object(
                restoration,
                "_windows_read_file_snapshot_if_present",
                return_value=None,
            ) as snapshot,
            patch.object(Path, "exists", side_effect=AssertionError),
            patch.object(Path, "is_file", side_effect=AssertionError),
            patch.object(Path, "is_symlink", side_effect=AssertionError),
        ):
            self.assertIsNone(
                restoration.RestorePointStore._read_target_if_present(target)
            )
            self.assertIsNone(
                restoration.RestorePointStore._read_private_file_if_present(
                    target, 4096
                )
            )
        self.assertEqual(snapshot.call_count, 2)
        self.assertEqual(
            snapshot.call_args_list[1].kwargs,
            {"capture_security": False},
        )

    def test_atomic_write_applies_and_verifies_descriptor_before_publish(self):
        native = _FakeWindowsFileOps()
        descriptor = "approved-descriptor"

        def apply(_path, encoded, *, native_handle):
            native.events.append(("apply_descriptor", native_handle, encoded))

        captures = 0

        def capture(_path, *, native_handle):
            nonlocal captures
            captures += 1
            native.events.append(("capture_descriptor", native_handle))
            return "temporary-descriptor" if captures == 1 else descriptor

        with (
            patch.object(
                restoration,
                "_restore_windows_security_descriptor",
                side_effect=apply,
            ),
            patch.object(
                restoration,
                "_capture_windows_security_descriptor",
                side_effect=capture,
            ),
            patch.object(restoration.os, "replace", side_effect=AssertionError),
        ):
            restoration._windows_atomic_write(
                Path(r"C:\safe\target.conf"),
                b"trusted bytes",
                0o640,
                {"windows_security_descriptor": descriptor},
                native=native,
            )
        names = [event[0] for event in native.events]
        expected_order = [
            "write",
            "flush",
            "mode",
            "apply_descriptor",
            "capture_descriptor",
            "delete",
            "rename",
        ]
        positions = []
        start = 0
        for name in expected_order:
            position = names.index(name, start)
            positions.append(position)
            start = position + 1
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(native.events[positions[3]], ("apply_descriptor", 90, descriptor))
        self.assertEqual(native.events[positions[4]], ("capture_descriptor", 90))
        self.assertEqual(native.events[positions[5]], ("delete", 90, False))
        self.assertEqual(
            native.events[positions[6]],
            ("rename", 90, 11, "target.conf", True),
        )
        self.assertEqual(native.events[-3:], [("close", 90), ("close", 11), ("close", 10)])

    def test_atomic_write_keeps_an_equivalent_inherited_descriptor(self):
        native = _FakeWindowsFileOps()
        descriptor = "approved-descriptor"
        with (
            patch.object(
                restoration,
                "_restore_windows_security_descriptor",
            ) as apply_descriptor,
            patch.object(
                restoration,
                "_capture_windows_security_descriptor",
                return_value=descriptor,
            ) as capture_descriptor,
        ):
            restoration._windows_atomic_write(
                Path(r"C:\safe\target.conf"),
                b"trusted bytes",
                0o600,
                {"windows_security_descriptor": descriptor},
                native=native,
            )
        apply_descriptor.assert_not_called()
        capture_descriptor.assert_called_once_with(
            Path(r"C:\safe\target.conf"), native_handle=90
        )
        self.assertIn("rename", [event[0] for event in native.events])

    def test_atomic_write_rearms_delete_disposition_if_publish_fails(self):
        native = _FakeWindowsFileOps(fail_rename=True)
        with self.assertRaisesRegex(OSError, "synthetic rename failure"):
            restoration._windows_atomic_write(
                Path(r"C:\safe\target.conf"),
                b"trusted bytes",
                0o600,
                None,
                native=native,
            )
        delete_events = [event for event in native.events if event[0] == "delete"]
        self.assertEqual(
            delete_events,
            [("delete", 90, True), ("delete", 90, False), ("delete", 90, True)],
        )
        rename_position = [event[0] for event in native.events].index("rename")
        self.assertIn(("mode", 90, 0o600), native.events[rename_position + 1 :])
        self.assertEqual(native.events[-3:], [("close", 90), ("close", 11), ("close", 10)])

    def test_atomic_write_does_not_delete_an_ambiguously_published_target(self):
        class InterruptedAfterRename(_FakeWindowsFileOps):
            def rename_file(
                self,
                handle,
                parent_path,
                leaf,
                *,
                replace_if_exists=True,
            ):
                self.events.append(
                    ("rename", handle, parent_path, leaf, replace_if_exists)
                )
                # Model an asynchronous Python exception delivered after the
                # native rename completed but before the caller can record it.
                raise KeyboardInterrupt("synthetic post-rename interruption")

        native = InterruptedAfterRename()
        with self.assertRaisesRegex(KeyboardInterrupt, "post-rename interruption"):
            restoration._windows_atomic_write(
                Path(r"C:\safe\target.conf"),
                b"trusted bytes",
                0o600,
                None,
                native=native,
            )
        self.assertEqual(
            [event for event in native.events if event[0] == "delete"],
            [("delete", 90, True), ("delete", 90, False)],
        )
        self.assertEqual(native.events[-3:], [("close", 90), ("close", 11), ("close", 10)])

    def test_conditional_publish_rechecks_and_pins_exact_target_through_rename(self):
        native = _FakeWindowsFileOps()
        expected = self._expected_metadata()

        def capture(_path, *, native_handle):
            return (
                "approved-descriptor"
                if native_handle == 91
                else "restored-descriptor"
            )

        with (
            patch.object(restoration, "_restore_windows_security_descriptor"),
            patch.object(
                restoration,
                "_capture_windows_security_descriptor",
                side_effect=capture,
            ),
        ):
            restoration._windows_atomic_write(
                Path(r"C:\safe\target.conf"),
                b"restored bytes",
                0o600,
                {"windows_security_descriptor": "restored-descriptor"},
                native=native,
                expected_current=(b"approved bytes", expected),
            )

        opens = [event for event in native.events if event[0] == "open"]
        target_open = next(event for event in opens if event[1] == 91)
        temp_open = next(event for event in opens if event[1] == 90)
        self.assertLess(native.events.index(target_open), native.events.index(temp_open))
        self.assertEqual(
            target_open[4],
            restoration.WINDOWS_FILE_SHARE_READ
            | restoration.WINDOWS_FILE_SHARE_DELETE,
        )
        self.assertFalse(target_open[4] & restoration.WINDOWS_FILE_SHARE_WRITE)
        rename_index = next(
            index
            for index, event in enumerate(native.events)
            if event[0] == "rename"
        )
        target_close_index = native.events.index(("close", 91))
        self.assertLess(rename_index, target_close_index)
        self.assertEqual(
            native.events[rename_index],
            ("rename", 90, 11, "target.conf", True),
        )

    def test_conditional_publish_rejects_stale_native_identity_before_staging(self):
        native = _FakeWindowsFileOps()
        expected = self._expected_metadata(handle=999)
        with patch.object(
            restoration,
            "_capture_windows_security_descriptor",
            return_value="approved-descriptor",
        ):
            with self.assertRaisesRegex(ValueError, "changed before publish"):
                restoration._windows_atomic_write(
                    Path(r"C:\safe\target.conf"),
                    b"restored bytes",
                    0o600,
                    None,
                    native=native,
                    expected_current=(b"approved bytes", expected),
                )
        self.assertNotIn(
            restoration.WINDOWS_CREATE_NEW,
            [event[5] for event in native.events if event[0] == "open"],
        )
        self.assertNotIn("rename", [event[0] for event in native.events])

    def test_final_name_recheck_catches_substitution_after_staging(self):
        class SubstitutedName(_FakeWindowsFileOps):
            def __init__(self):
                super().__init__()
                self.target_opens = 0

            def open_file(self, path, desired_access, share_mode, creation, flags):
                handle = super().open_file(
                    path, desired_access, share_mode, creation, flags
                )
                if str(path).casefold().endswith("target.conf"):
                    self.target_opens += 1
                    if self.target_opens == 2:
                        previous = self.events[-1]
                        self.events[-1] = ("open", 93, *previous[2:])
                        return 93
                return handle

        native = SubstitutedName()
        expected = self._expected_metadata()
        with patch.object(
            restoration,
            "_capture_windows_security_descriptor",
            return_value="approved-descriptor",
        ):
            with self.assertRaisesRegex(ValueError, "name changed before publish"):
                restoration._windows_atomic_write(
                    Path(r"C:\safe\target.conf"),
                    b"restored bytes",
                    0o600,
                    None,
                    native=native,
                    expected_current=(b"approved bytes", expected),
                )
        self.assertNotIn("rename", [event[0] for event in native.events])
        self.assertEqual(
            [event for event in native.events if event[0] == "delete"],
            [("delete", 90, True)],
        )

    def test_expected_absence_uses_non_replacing_native_rename(self):
        native = _FakeWindowsFileOps()
        restoration._windows_atomic_write(
            Path(r"C:\safe\target.conf"),
            b"restored bytes",
            0o600,
            None,
            native=native,
            expected_current=None,
        )
        rename = next(event for event in native.events if event[0] == "rename")
        self.assertEqual(rename, ("rename", 90, 11, "target.conf", False))
        self.assertNotIn(91, [event[1] for event in native.events if event[0] == "open"])

    def test_conditional_unlink_never_deletes_changed_content(self):
        native = _FakeWindowsFileOps(read_data=b"newer content")
        expected = self._expected_metadata(data=b"older content")
        with patch.object(
            restoration,
            "_capture_windows_security_descriptor",
            return_value="approved-descriptor",
        ):
            with self.assertRaisesRegex(ValueError, "changed before removal"):
                restoration._windows_unlink(
                    Path(r"C:\safe\target.conf"),
                    native=native,
                    expected_current=(b"older content", expected),
                )
        self.assertNotIn(("delete", 91, True), native.events)

    def test_authenticated_temp_record_rejects_attacker_modified_evidence(self):
        registry = object.__new__(restoration._WindowsTempOwnershipRegistry)
        registry._key = b"k" * restoration.WINDOWS_TEMP_KEY_BYTES
        payload = {
            "version": 1,
            "record_id": "a" * 32,
            "destination": "C:/safe/target.conf",
            "parent_final_path": (
                r"\\?\Volume{00000000-0000-0000-0000-000000000001}\safe"
            ),
            "temporary_leaf": f".sentinel-{'b' * 32}.tmp",
            "identity": [1, 2, 92],
            "creation_ticks": 1,
            "modified_ticks": 2,
            "size": 10,
            "attributes": restoration.WINDOWS_FILE_ATTRIBUTE_NORMAL,
            "links": 1,
            "content_sha256": hashlib.sha256(b"temp bytes").hexdigest(),
            "security_descriptor_sha256": hashlib.sha256(b"temp-desc").hexdigest(),
            "created_at_ns": 3,
        }
        signed = dict(payload)
        signed["mac"] = registry._mac(payload)
        self.assertEqual(
            registry._decode_record(registry._canonical(signed), "a" * 32),
            signed,
        )
        signed["identity"] = [9, 9, 9]
        with self.assertRaisesRegex(ValueError, "authentication failed"):
            registry._decode_record(registry._canonical(signed), "a" * 32)

    def test_temp_registry_normalizes_delete_pending_zero_links(self):
        registry = object.__new__(restoration._WindowsTempOwnershipRegistry)
        registry.root = Path(r"C:\safe\records")
        registry._key = b"k" * restoration.WINDOWS_TEMP_KEY_BYTES
        native = _FakeWindowsFileOps(
            read_data=b"temp bytes", zero_links_while_delete_pending=True
        )
        native.delete_pending_handles.add(90)
        written = {}

        def capture_record(path, data, **_kwargs):
            written["path"] = path
            written["data"] = data

        def read_record(path, _maximum, **_kwargs):
            self.assertEqual(path, written["path"])
            return written["data"], {
                "attributes": restoration.WINDOWS_FILE_ATTRIBUTE_NORMAL,
                "size": len(written["data"]),
                "modified_at": 1234.5,
                "creation_ticks": 1,
                "modified_ticks": 2,
                "identity": (1, 2, 93),
                "links": 1,
                "windows_security_descriptor": "record-descriptor",
            }

        with patch.object(
            restoration,
            "_capture_windows_security_descriptor",
            return_value="temp-descriptor",
        ), patch.object(
            restoration,
            "_windows_write_new_private_file",
            side_effect=capture_record,
        ), patch.object(
            restoration,
            "_windows_read_file_snapshot",
            side_effect=read_record,
        ):
            ownership = registry.register(
                destination=Path(r"C:\safe\target.conf"),
                parent_path=(
                    r"\\?\Volume{00000000-0000-0000-0000-000000000001}\safe"
                ),
                temporary_leaf=f".sentinel-{'b' * 32}.tmp",
                temporary_handle=90,
                data=b"temp bytes",
                native=native,
            )
        record = json.loads(ownership["data"].decode("ascii"))
        self.assertEqual(record["links"], 1)

    def test_temp_ownership_is_durable_before_delete_on_close_is_disarmed(self):
        native = _FakeWindowsFileOps(zero_links_while_delete_pending=True)
        registered_links = []

        class Registry:
            def register(self, **kwargs):
                native.events.append(("ownership_register",))
                registered_links.append(
                    native.file_snapshot(kwargs["temporary_handle"])["links"]
                )
                return {"record": "owned"}

            def complete(self, _ownership):
                native.events.append(("ownership_complete",))

        restoration._windows_atomic_write(
            Path(r"C:\safe\target.conf"),
            b"restored bytes",
            0o600,
            None,
            native=native,
            temp_registry=Registry(),
        )
        register = native.events.index(("ownership_register",))
        disarm = native.events.index(("delete", 90, False))
        rename = next(
            index
            for index, event in enumerate(native.events)
            if event[0] == "rename"
        )
        complete = native.events.index(("ownership_complete",))
        close = native.events.index(("close", 90))
        self.assertLess(register, disarm)
        self.assertLess(disarm, rename)
        self.assertLess(close, complete)
        self.assertEqual(registered_links, [0])

    def test_ambiguous_publish_interruption_retains_temp_ownership_record(self):
        class InterruptedAfterRename(_FakeWindowsFileOps):
            def rename_file(
                self,
                handle,
                parent_path,
                leaf,
                *,
                replace_if_exists=True,
            ):
                self.events.append(
                    ("rename", handle, parent_path, leaf, replace_if_exists)
                )
                raise KeyboardInterrupt("synthetic publish interruption")

        native = InterruptedAfterRename()

        class Registry:
            def register(self, **_kwargs):
                native.events.append(("ownership_register",))
                return {"record": "owned"}

            def complete(self, _ownership):
                native.events.append(("ownership_complete",))

        with self.assertRaisesRegex(KeyboardInterrupt, "publish interruption"):
            restoration._windows_atomic_write(
                Path(r"C:\safe\target.conf"),
                b"restored bytes",
                0o600,
                None,
                native=native,
                temp_registry=Registry(),
            )
        self.assertIn(("ownership_register",), native.events)
        self.assertNotIn(("ownership_complete",), native.events)

    def test_orphan_cleanup_deletes_only_the_identity_and_metadata_bound_temp(self):
        temporary_leaf = f".sentinel-{'b' * 32}.tmp"
        parent = r"\\?\Volume{00000000-0000-0000-0000-000000000001}\safe"

        def record(identity):
            return {
                "destination": "C:/safe/target.conf",
                "parent_final_path": parent,
                "temporary_leaf": temporary_leaf,
                "identity": identity,
                "creation_ticks": 116444736000000000 + 12300000000,
                "modified_ticks": 116444736000000000 + 12345000000,
                "size": len(b"temp bytes"),
                "attributes": restoration.WINDOWS_FILE_ATTRIBUTE_NORMAL,
                "links": 1,
                "content_sha256": hashlib.sha256(b"temp bytes").hexdigest(),
                "security_descriptor_sha256": hashlib.sha256(b"temp-desc").hexdigest(),
            }

        registry = object.__new__(restoration._WindowsTempOwnershipRegistry)
        exact = _FakeWindowsFileOps(read_data=b"temp bytes")
        with (
            patch.object(restoration, "_WindowsNativeFileOps", return_value=exact),
            patch.object(restoration, "_windows_privileges", return_value=nullcontext()),
            patch.object(
                restoration,
                "_capture_windows_security_descriptor",
                return_value="temp-desc",
            ),
        ):
            registry._cleanup_temp(record([1, 2, 92]))
        self.assertIn(("delete", 92, True), exact.events)

        planted = _FakeWindowsFileOps(read_data=b"temp bytes")
        with (
            patch.object(restoration, "_WindowsNativeFileOps", return_value=planted),
            patch.object(restoration, "_windows_privileges", return_value=nullcontext()),
            patch.object(
                restoration,
                "_capture_windows_security_descriptor",
                return_value="temp-desc",
            ),
        ):
            with self.assertRaisesRegex(ValueError, "no longer matches"):
                registry._cleanup_temp(record([9, 9, 9]))
        self.assertNotIn(("delete", 92, True), planted.events)

    def test_descriptor_mismatch_never_publishes_temporary_file(self):
        native = _FakeWindowsFileOps()
        with (
            patch.object(restoration, "_restore_windows_security_descriptor"),
            patch.object(
                restoration,
                "_capture_windows_security_descriptor",
                return_value="different-descriptor",
            ),
        ):
            with self.assertRaisesRegex(OSError, "did not match"):
                restoration._windows_atomic_write(
                    Path(r"C:\safe\target.conf"),
                    b"trusted bytes",
                    0o600,
                    {"windows_security_descriptor": "approved-descriptor"},
                    native=native,
                )
        self.assertNotIn("rename", [event[0] for event in native.events])
        self.assertEqual(native.events[-3:], [("close", 90), ("close", 11), ("close", 10)])

    def test_unlink_uses_open_leaf_handle_and_delete_disposition(self):
        native = _FakeWindowsFileOps()
        with patch.object(Path, "unlink", side_effect=AssertionError):
            restoration._windows_unlink(
                Path(r"C:\safe\target.conf"), native=native
            )
        self.assertIn(("delete", 91, True), native.events)
        self.assertEqual(
            native.events[-4:],
            [("delete", 91, True), ("close", 91), ("close", 11), ("close", 10)],
        )

    def test_security_information_rejects_null_dacl_and_tracks_sacl_separately(self):
        with self.assertRaisesRegex(ValueError, "no DACL"):
            restoration._windows_restoration_security_information(
                0, dacl_present=False, dacl_pointer=0, sacl_present=False
            )
        with self.assertRaisesRegex(ValueError, "NULL DACL"):
            restoration._windows_restoration_security_information(
                0, dacl_present=True, dacl_pointer=0, sacl_present=False
            )
        without_sacl = restoration._windows_restoration_security_information(
            0, dacl_present=True, dacl_pointer=1, sacl_present=False
        )
        self.assertFalse(without_sacl & restoration.WINDOWS_SACL_SECURITY_INFORMATION)
        self.assertFalse(
            without_sacl
            & (
                restoration.WINDOWS_PROTECTED_SACL_SECURITY_INFORMATION
                | restoration.WINDOWS_UNPROTECTED_SACL_SECURITY_INFORMATION
            )
        )
        with_sacl = restoration._windows_restoration_security_information(
            restoration.WINDOWS_SE_DACL_PROTECTED
            | restoration.WINDOWS_SE_SACL_PROTECTED,
            dacl_present=True,
            dacl_pointer=1,
            sacl_present=True,
        )
        self.assertTrue(with_sacl & restoration.WINDOWS_SACL_SECURITY_INFORMATION)
        self.assertTrue(
            with_sacl & restoration.WINDOWS_PROTECTED_DACL_SECURITY_INFORMATION
        )
        self.assertTrue(
            with_sacl & restoration.WINDOWS_PROTECTED_SACL_SECURITY_INFORMATION
        )

if __name__ == "__main__":
    unittest.main()
