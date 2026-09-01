import socket
import threading
import unittest

from sentinel_blue.discovery import discover_hosts


class DiscoveryTests(unittest.TestCase):
    def test_discovers_only_explicit_single_host_scope(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]
        stop = threading.Event()

        def accept_once():
            try:
                connection, _ = listener.accept()
                connection.close()
            finally:
                stop.set()

        thread = threading.Thread(target=accept_once, daemon=True)
        thread.start()
        try:
            hosts = discover_hosts(
                ["127.0.0.1/32"],
                port_map={port: ("linux", "ssh")},
                timeout=0.5,
                max_addresses=1,
            )
            self.assertEqual(hosts[0]["address"], "127.0.0.1")
            self.assertEqual(hosts[0]["transport"], "ssh")
        finally:
            listener.close()
            thread.join(timeout=2)

    def test_refuses_broad_scope(self):
        with self.assertRaises(ValueError):
            discover_hosts(["198.51.100.0/16"], max_addresses=256)

    def test_refuses_huge_ipv6_scope_without_materializing_it(self):
        with self.assertRaises(ValueError):
            discover_hosts(["2001:db8::/64"], max_addresses=128)


if __name__ == "__main__":
    unittest.main()
