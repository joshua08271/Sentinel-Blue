import hashlib
import socket
import threading
import unittest

from sentinel_blue.probes import run_probe


class FTPProbeTests(unittest.TestCase):
    def exercise(self, expected, payload=b"verified download\n", *, announce_other_ip=False):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(5)
        data = socket.socket()
        data.bind(("127.0.0.1", 0))
        data.listen(1)
        data.settimeout(5)
        port = listener.getsockname()[1]
        data_port = data.getsockname()[1]
        errors = []

        def serve():
            try:
                with listener.accept()[0] as control:
                    control.settimeout(5)
                    stream = control.makefile("rb")
                    control.sendall(b"220 owned FTP fixture\r\n")
                    while True:
                        line = stream.readline()
                        if not line:
                            break
                        if line.startswith(b"USER"):
                            control.sendall(b"331 password required\r\n")
                        elif line.startswith(b"PASS"):
                            control.sendall(b"230 logged in\r\n")
                        elif line.startswith(b"TYPE"):
                            control.sendall(b"200 binary\r\n")
                        elif line.startswith(b"PASV"):
                            address = "192,0,2,222" if announce_other_ip else "127,0,0,1"
                            control.sendall(f"227 Entering Passive Mode ({address},{data_port // 256},{data_port % 256})\r\n".encode())
                        elif line.startswith(b"RETR"):
                            control.sendall(b"150 transferring\r\n")
                            with data.accept()[0] as channel:
                                channel.sendall(payload)
                            control.sendall(b"226 done\r\n")
                        else:
                            control.sendall(b"500 unsupported\r\n")
                    stream.close()
            except Exception as exc:
                errors.append(type(exc).__name__)
            finally:
                listener.close()
                data.close()

        thread = threading.Thread(target=serve)
        thread.start()
        try:
            result = run_probe({"kind": "ftp", "target": "127.0.0.1", "port": port,
                                "path": "health.txt", "expected_sha256": expected}, ["127.0.0.0/8"])
        finally:
            thread.join(timeout=6)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        return result

    def test_login_and_exact_content_verified(self):
        result = self.exercise(hashlib.sha256(b"verified download\n").hexdigest())
        self.assertTrue(result.healthy, result.detail)

    def test_wrong_download_does_not_count_as_healthy(self):
        result = self.exercise("a" * 64)
        self.assertFalse(result.healthy)
        self.assertIn("checksum", result.detail)

    def test_passive_address_cannot_redirect_outside_the_scoped_host(self):
        result = self.exercise(hashlib.sha256(b"verified download\n").hexdigest(), announce_other_ip=True)
        self.assertTrue(result.healthy, result.detail)

    def test_ftp_command_delimiters_refused(self):
        result = run_probe({"kind": "ftp", "target": "127.0.0.1", "path": "file\r\nDELE other",
                            "expected_sha256": "a" * 64}, ["127.0.0.0/8"])
        self.assertFalse(result.healthy)
        self.assertIn("delimiter", result.detail)


if __name__ == "__main__":
    unittest.main()
