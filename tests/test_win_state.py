import ctypes
import os
import unittest
from dataclasses import dataclass
from pathlib import Path

from sentinel_blue import win_state


def exact_security(directory=True):
    return win_state.WindowsSecurityState(
        win_state.SYSTEM_SID,
        True,
        True,
        win_state._expected_aces(directory),
    )


def inherited_security(directory, owner=win_state.SYSTEM_SID):
    return win_state.WindowsSecurityState(
        owner,
        True,
        False,
        win_state._expected_aces(directory, inherited=True),
    )


def insecure_security(owner="S-1-5-21-1000"):
    return win_state.WindowsSecurityState(
        owner,
        True,
        False,
        (
            *win_state._expected_aces(True, inherited=True),
            win_state.WindowsAccessAce("S-1-5-32-545", 0x001301BF, 0x13),
        ),
    )


@dataclass
class _Node:
    directory: bool
    security: win_state.WindowsSecurityState
    reparse: bool = False
    device: bool = False
    links: int = 1


class _FakeBackend:
    """In-memory recorder for the policy/lifecycle layer."""

    def __init__(self, nodes=None):
        self.nodes = {}
        self.handles = {}
        self.handle_identities = {}
        self.identity_sequences = {}
        self.next_handle = 10
        self.opened = []
        self.closed = []
        self.applied = []
        self.created = []
        self.final_paths = {}
        self.events = []
        self.close_failures = {}
        self.apply_is_effective = True
        for path, node in (nodes or {}).items():
            self.nodes[self._key(path)] = node

    @staticmethod
    def _key(path):
        return str(path).replace("/", "\\").rstrip("\\").casefold() or "\\"

    @staticmethod
    def _display(path):
        value = str(path).replace("/", "\\")
        return value[:-1] if len(value) > 3 and value.endswith("\\") else value

    def add(
        self,
        path,
        *,
        directory,
        security=None,
        reparse=False,
        device=False,
        links=1,
    ):
        self.nodes[self._key(path)] = _Node(
            directory,
            security or exact_security(directory),
            reparse,
            device,
            links,
        )

    def is_missing(self, exc):
        return isinstance(exc, FileNotFoundError)

    def open_node(
        self,
        path,
        *,
        write_security=False,
        allow_data_writers=False,
    ):
        key = self._key(path)
        if key not in self.nodes:
            raise FileNotFoundError(2, "missing")
        handle = self.next_handle
        self.next_handle += 1
        self.handles[handle] = key
        identities = self.identity_sequences.get(key)
        self.handle_identities[handle] = (
            identities.pop(0) if identities else key
        )
        self.opened.append(
            (handle, self._display(path), write_security, allow_data_writers)
        )
        self.events.append(("open", key, write_security, allow_data_writers))
        return handle

    def close(self, handle):
        if handle not in self.handles:
            raise OSError("double close")
        remaining = self.close_failures.get(handle, 0)
        if remaining:
            self.close_failures[handle] = remaining - 1
            raise OSError("injected close failure")
        self.handles.pop(handle)
        self.handle_identities.pop(handle)
        self.closed.append(handle)

    def attributes(self, handle):
        node = self.nodes[self.handles[handle]]
        result = (
            win_state.WINDOWS_FILE_ATTRIBUTE_DIRECTORY if node.directory else 0x80
        )
        if node.reparse:
            result |= win_state.WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT
        if node.device:
            result |= win_state.WINDOWS_FILE_ATTRIBUTE_DEVICE
        return result

    def final_path(self, handle):
        key = self.handles[handle]
        if key in self.final_paths:
            return self.final_paths[key]
        tail = key[2:].lstrip("\\")
        root = "\\\\?\\Volume{00000000-0000-0000-0000-000000000001}\\"
        return root + tail

    def link_count(self, handle):
        return self.nodes[self.handles[handle]].links

    def identity(self, handle):
        return self.handle_identities[handle]

    def security_state(self, handle):
        return self.nodes[self.handles[handle]].security

    def apply_private_security(self, handle, directory):
        key = self.handles[handle]
        self.applied.append((key, directory))
        self.events.append(("apply", key, directory))
        if self.apply_is_effective:
            self.nodes[key].security = exact_security(directory)

    def create_directory(self, path):
        key = self._key(path)
        if key in self.nodes:
            raise OSError(183, "exists")
        self.nodes[key] = _Node(True, exact_security(True))
        self.created.append(key)

    def list_children(self, path, limit):
        parent = self._key(path)
        prefix = parent + "\\"
        names = []
        for key in self.nodes:
            if not key.startswith(prefix):
                continue
            remainder = key[len(prefix) :]
            if "\\" not in remainder:
                names.append(remainder)
                if len(names) > limit:
                    raise win_state.WindowsStateSecurityError(
                        "Windows state tree exceeds its entry budget"
                    )
        return sorted(names)


def basic_backend(root_security=None):
    backend = _FakeBackend()
    backend.add("C:\\", directory=True)
    backend.add("C:\\ProgramData", directory=True)
    if root_security is not None:
        backend.add(
            "C:\\ProgramData\\SentinelBlue",
            directory=True,
            security=root_security,
        )
    return backend


class WindowsStatePathTests(unittest.TestCase):
    def test_native_structures_match_the_win32_abi(self):
        self.assertEqual(ctypes.sizeof(win_state._Acl), 8)
        self.assertEqual(ctypes.sizeof(win_state._AceHeader), 4)
        self.assertEqual(ctypes.sizeof(win_state._ByHandleFileInformation), 52)
        if ctypes.sizeof(ctypes.c_void_p) == 8:
            self.assertEqual(ctypes.sizeof(win_state._SecurityDescriptor), 40)
            self.assertEqual(ctypes.sizeof(win_state._SecurityAttributes), 24)
        else:
            self.assertEqual(ctypes.sizeof(win_state._SecurityDescriptor), 20)
            self.assertEqual(ctypes.sizeof(win_state._SecurityAttributes), 12)

    def test_accepts_only_bounded_absolute_local_drive_directory(self):
        path, prefixes = win_state._windows_directory_prefixes(
            "c:\\ProgramData\\SentinelBlue\\state\\"
        )
        self.assertEqual(path, r"C:\ProgramData\SentinelBlue\state")
        self.assertEqual(prefixes[0], "C:\\")
        self.assertEqual(prefixes[-1], path)

        rejected = (
            r"\\server\share\state",
            r"\\?\C:\state",
            r"\\.\C:\state",
            r"C:relative",
            r"C:\state\..\escape",
            r"C:\state\token:stream",
            "C:\\state\\trailing. ",
            r"C:\state\CON",
            "C:\\",
        )
        for candidate in rejected:
            with self.subTest(candidate=candidate):
                with self.assertRaises(win_state.WindowsStateSecurityError):
                    win_state._windows_directory_prefixes(candidate)

    def test_default_call_is_noop_off_windows(self):
        if os.name == "nt":
            self.skipTest("non-Windows contract")
        self.assertIsNone(
            win_state.acquire_windows_state_tree(r"C:\ProgramData\SentinelBlue")
        )


class WindowsStateGuardTests(unittest.TestCase):
    root = r"C:\ProgramData\SentinelBlue"

    def test_creates_root_with_private_descriptor_and_holds_complete_chain(self):
        backend = basic_backend()
        guard = win_state.acquire_windows_state_tree(
            self.root, initialize=True, backend=backend
        )
        self.assertIsNotNone(guard)
        assert guard is not None
        self.assertEqual(backend.created, [backend._key(self.root)])
        self.assertEqual(len(backend.handles), 3)
        self.assertEqual([item[1] for item in backend.opened[:3]], [
            "C:\\",
            r"C:\ProgramData",
            self.root,
        ])
        self.assertTrue(all(not item[2] for item in backend.opened[:3]))
        self.assertEqual(guard.refresh().entries, 0)
        expected_close = [item[0] for item in reversed(backend.opened[:3])]
        guard.close()
        self.assertEqual(backend.closed[-3:], expected_close)
        self.assertFalse(backend.handles)

    def test_hardens_only_an_empty_insecure_legacy_root(self):
        backend = basic_backend(insecure_security())
        guard = win_state.acquire_windows_state_tree(
            self.root, initialize=True, backend=backend
        )
        self.assertIsNotNone(guard)
        self.assertEqual(backend.applied, [(backend._key(self.root), True)])
        assert guard is not None
        guard.close()

    def test_post_hardening_descriptor_mismatch_is_fatal(self):
        backend = basic_backend(insecure_security())
        backend.apply_is_effective = False
        with self.assertRaises(win_state.WindowsStateSecurityError):
            win_state.acquire_windows_state_tree(
                self.root, initialize=True, backend=backend
            )
        self.assertEqual(backend.applied, [(backend._key(self.root), True)])
        self.assertFalse(backend.handles)

    def test_refuses_nonempty_insecure_legacy_root_without_mutation(self):
        backend = basic_backend(insecure_security())
        backend.add(self.root + r"\identity.json", directory=False)
        with self.assertRaisesRegex(
            win_state.WindowsStateSecurityError, "nonempty insecure legacy"
        ):
            win_state.acquire_windows_state_tree(
                self.root, initialize=True, backend=backend
            )
        self.assertEqual(backend.applied, [])
        self.assertFalse(backend.handles)
        self.assertEqual(backend.closed, [12, 11, 10])

    def test_safe_nonempty_legacy_root_is_fully_audited_then_normalized(self):
        backend = basic_backend(
            inherited_security(True, win_state.ADMINISTRATORS_SID)
        )
        backend.add(
            self.root + r"\state",
            directory=True,
            security=inherited_security(True, win_state.ADMINISTRATORS_SID),
        )
        backend.add(
            self.root + r"\state\identity.json",
            directory=False,
            security=inherited_security(False),
        )
        guard = win_state.acquire_windows_state_tree(
            self.root,
            initialize=True,
            backend=backend,
        )
        assert guard is not None
        expected = {
            (backend._key(self.root), True),
            (backend._key(self.root + r"\state"), True),
            (backend._key(self.root + r"\state\identity.json"), False),
        }
        self.assertEqual(set(backend.applied), expected)
        first_apply = next(
            index for index, event in enumerate(backend.events) if event[0] == "apply"
        )
        audited_keys = {
            event[1]
            for event in backend.events[:first_apply]
            if event[0] == "open"
        }
        self.assertIn(backend._key(self.root + r"\state\identity.json"), audited_keys)
        self.assertEqual(guard.refresh().hardened, 0)
        guard.close()

    def test_safe_legacy_root_with_unsafe_content_is_never_mutated(self):
        backend = basic_backend(
            inherited_security(True, win_state.ADMINISTRATORS_SID)
        )
        backend.add(
            self.root + r"\unsafe.json",
            directory=False,
            security=win_state.WindowsSecurityState(
                win_state.SYSTEM_SID,
                True,
                True,
                (
                    *win_state._expected_aces(False),
                    win_state.WindowsAccessAce("S-1-5-32-545", 1, 0),
                ),
            ),
        )
        with self.assertRaises(win_state.WindowsStateSecurityError):
            win_state.acquire_windows_state_tree(
                self.root,
                initialize=True,
                backend=backend,
            )
        self.assertEqual(backend.applied, [])

    def test_validation_mode_never_repairs_an_insecure_root(self):
        backend = basic_backend(insecure_security())
        with self.assertRaises(win_state.WindowsStateSecurityError):
            win_state.acquire_windows_state_tree(
                self.root, initialize=False, backend=backend
            )
        self.assertEqual(backend.applied, [])

    def test_rejects_reparse_ancestor_root_and_descendant(self):
        for bad_path in (
            r"C:\ProgramData",
            self.root,
            self.root + r"\restore-points",
        ):
            with self.subTest(path=bad_path):
                backend = basic_backend(exact_security(True))
                if bad_path.endswith("restore-points"):
                    backend.add(bad_path, directory=True, reparse=True)
                else:
                    backend.nodes[backend._key(bad_path)].reparse = True
                with self.assertRaisesRegex(
                    win_state.WindowsStateSecurityError, "reparse"
                ):
                    win_state.acquire_windows_state_tree(
                        self.root, backend=backend
                    )
                self.assertFalse(backend.handles)

    def test_recursive_directories_remain_pinned_while_enumerated(self):
        class PinRequiredBackend(_FakeBackend):
            def __init__(self):
                super().__init__()
                self.enumerated_without_pin = []

            def list_children(self, path, limit):
                key = self._key(path)
                if key not in self.handles.values():
                    self.enumerated_without_pin.append(key)
                    # Model the escaped enumeration an attacker gets after a
                    # checked directory name is swapped to a junction.
                    return ["outside.json"]
                return super().list_children(path, limit)

        backend = PinRequiredBackend()
        backend.add("C:\\", directory=True)
        backend.add(r"C:\ProgramData", directory=True)
        backend.add(self.root, directory=True)
        backend.add(self.root + r"\nested", directory=True)
        backend.add(self.root + r"\nested\state.json", directory=False)
        guard = win_state.acquire_windows_state_tree(self.root, backend=backend)
        assert guard is not None
        self.assertEqual(backend.enumerated_without_pin, [])
        guard.close()

    def test_directory_share_is_narrowed_by_identity_checked_path_open(self):
        backend = basic_backend(exact_security(True))
        nested = self.root + r"\restore-points"
        backend.add(nested, directory=True)

        guard = win_state.acquire_windows_state_tree(self.root, backend=backend)
        assert guard is not None

        opens = [
            item
            for item in backend.opened
            if backend._key(item[1]) == backend._key(nested)
        ]
        self.assertEqual(
            [(item[2], item[3]) for item in opens],
            [(False, True), (False, False)],
        )
        # The permissive no-delete pin is closed only after the restrictive
        # by-path handle has been opened and identity-checked.
        self.assertLess(
            backend.closed.index(opens[0][0]),
            backend.closed.index(opens[1][0]),
        )
        guard.close()

    def test_directory_identity_change_is_rejected_before_enumeration(self):
        backend = basic_backend(exact_security(True))
        nested = self.root + r"\restore-points"
        backend.add(nested, directory=True)
        backend.identity_sequences[backend._key(nested)] = [
            "audited-object",
            "replacement-object",
        ]

        with self.assertRaisesRegex(
            win_state.WindowsStateSecurityError, "identity changed"
        ):
            win_state.acquire_windows_state_tree(self.root, backend=backend)

        self.assertEqual(backend.applied, [])
        self.assertFalse(backend.handles)

    def test_acl_write_handle_must_match_the_audited_object(self):
        backend = basic_backend(exact_security(True))
        nested = self.root + r"\restore-points"
        backend.add(
            nested,
            directory=True,
            security=inherited_security(True),
        )
        backend.identity_sequences[backend._key(nested)] = [
            "audited-object",
            "audited-object",
            "replacement-object",
        ]

        with self.assertRaisesRegex(
            win_state.WindowsStateSecurityError, "identity changed"
        ):
            win_state.acquire_windows_state_tree(self.root, backend=backend)

        self.assertEqual(backend.applied, [])
        self.assertFalse(backend.handles)

    def test_hard_linked_file_is_rejected_before_any_hardening(self):
        backend = basic_backend(exact_security(True))
        backend.add(
            self.root + r"\linked.json",
            directory=False,
            security=inherited_security(False),
            links=2,
        )
        with self.assertRaisesRegex(
            win_state.WindowsStateSecurityError, "hard-linked"
        ):
            win_state.acquire_windows_state_tree(self.root, backend=backend)
        self.assertEqual(backend.applied, [])

    def test_each_prefix_is_bound_to_its_canonical_volume_path(self):
        for name, bad_path in (
            (
                "same-volume-alias",
                r"\\?\Volume{00000000-0000-0000-0000-000000000001}\Elsewhere",
            ),
            (
                "cross-volume",
                r"\\?\Volume{00000000-0000-0000-0000-000000000002}\ProgramData",
            ),
        ):
            with self.subTest(name=name):
                backend = basic_backend(exact_security(True))
                backend.final_paths[backend._key(r"C:\ProgramData")] = bad_path
                with self.assertRaises(win_state.WindowsStateSecurityError):
                    win_state.acquire_windows_state_tree(self.root, backend=backend)
                self.assertFalse(backend.handles)

    def test_exact_secure_tree_is_accepted_without_mutation(self):
        backend = basic_backend(exact_security(True))
        backend.add(self.root + r"\identity.json", directory=False)
        backend.add(self.root + r"\telemetry-spool", directory=True)
        backend.add(
            self.root + r"\telemetry-spool\0001.json", directory=False
        )
        guard = win_state.acquire_windows_state_tree(self.root, backend=backend)
        assert guard is not None
        report = guard.refresh()
        self.assertEqual(report.entries, 3)
        self.assertEqual(report.hardened, 0)
        self.assertEqual(backend.applied, [])
        guard.close()

    def test_safe_inherited_descendants_are_hardened_after_complete_audit(self):
        backend = basic_backend(exact_security(True))
        backend.add(
            self.root + r"\state",
            directory=True,
            security=inherited_security(True, win_state.ADMINISTRATORS_SID),
        )
        backend.add(
            self.root + r"\state\sequence.json",
            directory=False,
            security=inherited_security(False),
        )
        guard = win_state.acquire_windows_state_tree(self.root, backend=backend)
        assert guard is not None
        self.assertCountEqual(
            backend.applied,
            [
                (backend._key(self.root + r"\state"), True),
                (backend._key(self.root + r"\state\sequence.json"), False),
            ],
        )
        self.assertEqual(guard.refresh().hardened, 0)
        guard.close()

    def test_validation_can_accept_safe_inherited_children_without_mutating(self):
        backend = basic_backend(exact_security(True))
        backend.add(
            self.root + r"\state",
            directory=True,
            security=inherited_security(True),
        )
        guard = win_state.acquire_windows_state_tree(
            self.root,
            harden_safe_descendants=False,
            backend=backend,
        )
        assert guard is not None
        self.assertEqual(backend.applied, [])
        self.assertEqual(
            guard.refresh(harden_safe_descendants=False).entries, 1
        )
        guard.close()

    def test_unsafe_child_blocks_all_candidate_hardening(self):
        backend = basic_backend(exact_security(True))
        backend.add(
            self.root + r"\safe-child.json",
            directory=False,
            security=inherited_security(False),
        )
        unsafe = win_state.WindowsSecurityState(
            win_state.SYSTEM_SID,
            True,
            True,
            (
                *win_state._expected_aces(False),
                win_state.WindowsAccessAce("S-1-5-32-545", 1, 0),
            ),
        )
        backend.add(
            self.root + r"\unsafe-child.json",
            directory=False,
            security=unsafe,
        )
        with self.assertRaisesRegex(
            win_state.WindowsStateSecurityError, "exactly two"
        ):
            win_state.acquire_windows_state_tree(self.root, backend=backend)
        self.assertEqual(backend.applied, [])
        self.assertFalse(backend.handles)

    def test_rejects_absent_null_dacl_wrong_owner_deny_and_inherit_only(self):
        cases = {
            "null": win_state.WindowsSecurityState(
                win_state.SYSTEM_SID, False, True, ()
            ),
            "owner": win_state.WindowsSecurityState(
                "S-1-5-21-1000", True, True, win_state._expected_aces(False)
            ),
            "deny": win_state.WindowsSecurityState(
                win_state.SYSTEM_SID,
                True,
                True,
                (
                    win_state.WindowsAccessAce(
                        win_state.SYSTEM_SID,
                        win_state.FILE_ALL_ACCESS,
                        0,
                        1,
                    ),
                    win_state.WindowsAccessAce(
                        win_state.ADMINISTRATORS_SID,
                        win_state.FILE_ALL_ACCESS,
                        0,
                    ),
                ),
            ),
            "inherit_only": win_state.WindowsSecurityState(
                win_state.SYSTEM_SID,
                True,
                False,
                tuple(
                    win_state.WindowsAccessAce(
                        ace.sid,
                        ace.mask,
                        ace.flags | win_state.INHERIT_ONLY_ACE,
                    )
                    for ace in win_state._expected_aces(False)
                ),
            ),
        }
        for name, security in cases.items():
            with self.subTest(name=name):
                backend = basic_backend(exact_security(True))
                backend.add(
                    self.root + r"\child.json",
                    directory=False,
                    security=security,
                )
                with self.assertRaises(win_state.WindowsStateSecurityError):
                    win_state.acquire_windows_state_tree(self.root, backend=backend)
                self.assertEqual(backend.applied, [])

    def test_entry_budget_is_fail_closed_and_not_truncated(self):
        backend = basic_backend(exact_security(True))
        for index in range(3):
            backend.add(self.root + f"\\{index}.json", directory=False)
        with self.assertRaisesRegex(
            win_state.WindowsStateSecurityError, "entry budget"
        ):
            win_state.acquire_windows_state_tree(
                self.root, maximum_entries=2, backend=backend
            )
        self.assertFalse(backend.handles)

    def test_depth_budget_is_fail_closed(self):
        backend = basic_backend(exact_security(True))
        backend.add(self.root + r"\one", directory=True)
        backend.add(self.root + r"\one\two", directory=True)
        with self.assertRaisesRegex(
            win_state.WindowsStateSecurityError, "depth budget"
        ):
            win_state.acquire_windows_state_tree(
                self.root, maximum_depth=1, backend=backend
            )

    def test_device_descendant_is_rejected(self):
        backend = basic_backend(exact_security(True))
        backend.add(self.root + r"\device", directory=False, device=True)
        with self.assertRaisesRegex(
            win_state.WindowsStateSecurityError, "device"
        ):
            win_state.acquire_windows_state_tree(self.root, backend=backend)

    def test_invalid_traversal_bounds_are_rejected_before_open(self):
        backend = basic_backend(exact_security(True))
        for kwargs in (
            {"maximum_entries": 0},
            {"maximum_entries": True},
            {"maximum_entries": 65537},
            {"maximum_depth": 0},
            {"maximum_depth": True},
            {"maximum_depth": 65},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    win_state.acquire_windows_state_tree(
                        self.root, backend=backend, **kwargs
                    )
        self.assertEqual(backend.opened, [])

    def test_refresh_detects_root_acl_widening_and_closed_guard(self):
        backend = basic_backend(exact_security(True))
        guard = win_state.acquire_windows_state_tree(self.root, backend=backend)
        assert guard is not None
        backend.nodes[backend._key(self.root)].security = insecure_security()
        with self.assertRaises(win_state.WindowsStateSecurityError):
            guard.refresh()
        guard.close()
        with self.assertRaisesRegex(win_state.WindowsStateSecurityError, "closed"):
            guard.refresh()

    def test_failure_closes_handles_exactly_once_in_reverse_order(self):
        backend = basic_backend(exact_security(True))
        backend.add(self.root + r"\bad", directory=True, reparse=True)
        with self.assertRaises(win_state.WindowsStateSecurityError):
            win_state.acquire_windows_state_tree(self.root, backend=backend)
        self.assertFalse(backend.handles)
        self.assertEqual(len(backend.closed), len(set(backend.closed)))
        # The last three are the lifetime chain; the child was closed first.
        self.assertEqual(backend.closed[-3:], [12, 11, 10])

    def test_close_failure_is_retriable_but_guard_stays_unusable(self):
        backend = basic_backend(exact_security(True))
        guard = win_state.acquire_windows_state_tree(self.root, backend=backend)
        assert guard is not None
        failed_handle = guard._handles[1]
        backend.close_failures[failed_handle] = 1
        with self.assertRaisesRegex(OSError, "injected close"):
            guard.close()
        self.assertTrue(guard.closed)
        self.assertEqual(guard._handles, [failed_handle])
        with self.assertRaisesRegex(win_state.WindowsStateSecurityError, "closed"):
            guard.refresh()
        guard.close()
        self.assertEqual(guard._handles, [])
        self.assertFalse(backend.handles)

    def test_module_has_no_process_or_shell_dependency(self):
        source = Path(win_state.__file__).read_text(encoding="utf-8")
        for forbidden in ("import subprocess", "subprocess.", "os.system", "icacls"):
            self.assertNotIn(forbidden, source.casefold())


if __name__ == "__main__":
    unittest.main()
