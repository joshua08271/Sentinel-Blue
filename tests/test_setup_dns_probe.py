import contextlib
import ipaddress
import socket
import struct
import threading
import unittest

from sentinel_blue.probes import run_probe


def wire_name(name):
    return b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split(".")) + b"\0"


def record(owner, kind, data):
    return owner + struct.pack("!HHIH", kind, 1, 60, len(data)) + data


@contextlib.contextmanager
def dns_fixture(records, *, question=None):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(("127.0.0.1", 0))
        server.settimeout(2)
        def answer():
            request, peer = server.recvfrom(4096)
            response = request[:2] + struct.pack("!HHHHH", 0x8180, 1, len(records), 0, 0)
            response += request[12:] if question is None else question
            server.sendto(response + b"".join(records), peer)
        thread = threading.Thread(target=answer, daemon=True)
        thread.start()
        try:
            yield server.getsockname()[1]
        finally:
            thread.join(timeout=3)


class ExactDNSSetupTests(unittest.TestCase):
    def probe(self, records, *, expected=None, record_type="A", question=None):
        with dns_fixture(records, question=question) as port:
            return run_probe({"kind": "dns", "target": "127.0.0.1", "port": port,
                              "query": "www.setup.test", "record_type": record_type,
                              "expected_answers": expected or ["127.0.0.1"], "timeout": 1},
                             ["127.0.0.0/8"], authorized_hosts=["127.0.0.1"])

    def test_exact_address_passes_through_real_udp_probe(self):
        self.assertTrue(self.probe([record(b"\xc0\x0c", 1, b"\x7f\0\0\1")]).healthy)

    def test_wrong_address_fails_even_with_successful_dns_response(self):
        self.assertFalse(self.probe([record(b"\xc0\x0c", 1, b"\x7f\0\0\2")]).healthy)

    def test_unrelated_owner_cannot_supply_expected_address(self):
        self.assertFalse(self.probe([record(wire_name("unrelated.setup.test"), 1, b"\x7f\0\0\1")]).healthy)

    def test_cname_chain_to_exact_address_passes(self):
        alias = wire_name("real.setup.test")
        self.assertTrue(self.probe([record(b"\xc0\x0c", 5, alias), record(alias, 1, b"\x7f\0\0\1")]).healthy)

    def test_aaaa_answer_uses_exact_ipv6_comparison(self):
        packed = ipaddress.ip_address("::1").packed
        self.assertTrue(self.probe([record(b"\xc0\x0c", 28, packed)], expected=["::1"], record_type="AAAA").healthy)

    def test_compression_loop_is_rejected_without_hanging(self):
        offset = 12 + len(wire_name("www.setup.test")) + 4
        pointer = struct.pack("!H", 0xC000 | offset)
        self.assertFalse(self.probe([record(pointer, 1, b"\x7f\0\0\1")]).healthy)

    def test_mismatched_question_is_rejected(self):
        question = wire_name("bad.setup.test") + struct.pack("!HH", 1, 1)
        self.assertFalse(self.probe([record(b"\xc0\x0c", 1, b"\x7f\0\0\1")], question=question).healthy)


if __name__ == "__main__":
    unittest.main()
