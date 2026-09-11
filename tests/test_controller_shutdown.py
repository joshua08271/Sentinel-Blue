import signal
import threading
import time
import unittest
from unittest.mock import Mock, patch

from sentinel_blue.controller import (
    _controller_shutdown_signals,
    _drain_controller_workers,
    relay_probe_loop,
)
from sentinel_blue.probes import ProbeBatchCancelled, run_probes
from sentinel_blue.protocol import ProbeResult


class ControllerShutdownTests(unittest.TestCase):
    def test_drain_waits_for_both_requests_and_background_database_users(self):
        release = threading.Event()
        worker = threading.Thread(target=release.wait, name="owned-maintenance")
        worker.start()
        server = Mock()
        server.active_connections.return_value = {"127.0.0.1": 1}
        result = []
        draining = threading.Thread(
            target=lambda: result.append(_drain_controller_workers(server, [worker], timeout=2))
        )
        draining.start()
        try:
            release.set()
            worker.join(timeout=1)
            draining.join(timeout=0.1)
            self.assertTrue(draining.is_alive(), "active requests still own the database")
            server.active_connections.return_value = {}
            draining.join(timeout=1)
            self.assertEqual(result, [True])
        finally:
            release.set()
            worker.join(timeout=1)
            server.active_connections.return_value = {}
            draining.join(timeout=2)

    def test_unfinished_worker_retains_failure_at_shared_deadline(self):
        release = threading.Event()
        worker = threading.Thread(target=release.wait, name="owned-stalled-worker")
        worker.start()
        server = Mock()
        server.active_connections.return_value = {}
        try:
            started = time.monotonic()
            with self.assertLogs("sentinel_blue.controller", level="ERROR") as logs:
                drained = _drain_controller_workers(server, [worker], timeout=0.05)
            self.assertFalse(drained)
            self.assertTrue(worker.is_alive())
            self.assertLess(time.monotonic() - started, 1)
            self.assertIn("owned-stalled-worker", " ".join(logs.output))
        finally:
            release.set()
            worker.join(timeout=1)

    def test_signal_handlers_remain_installed_until_cleanup_finishes(self):
        server = Mock()
        installed = {}
        originals = {number: signal.getsignal(number) for number in (signal.SIGTERM, signal.SIGINT)}
        with patch("sentinel_blue.controller.signal.signal", side_effect=lambda number, handler: installed.update({number: handler})):
            with _controller_shutdown_signals(server):
                stop = installed[signal.SIGTERM]
                stop(signal.SIGTERM, None)
                server.serve_forever()
                # A second stop during database cleanup must neither restore the
                # default kill handler nor start a second shutdown thread.
                self.assertIs(installed[signal.SIGTERM], stop)
                stop(signal.SIGTERM, None)
            self.assertEqual(installed, originals)
        server.shutdown.assert_called_once()

    def test_cancelled_probe_batch_skips_queued_network_work_and_joins_running_work(self):
        stop = threading.Event()
        release = threading.Event()
        entered = threading.Barrier(17)
        failures = []
        specs = [{"name": str(index)} for index in range(64)]

        def probe(spec, *_args, **_kwargs):
            entered.wait(timeout=5)
            release.wait(timeout=5)
            return ProbeResult(spec["name"], "fixture", True)

        def batch():
            try:
                run_probes(specs, [], stop_event=stop)
            except BaseException as exc:
                failures.append(exc)

        with patch("sentinel_blue.probes.run_probe", side_effect=probe) as runner:
            worker = threading.Thread(target=batch)
            worker.start()
            try:
                entered.wait(timeout=5)
                stop.set()
                worker.join(timeout=0.05)
                self.assertTrue(worker.is_alive(), "in-flight probes must finish before cancellation returns")
                release.set()
                worker.join(timeout=5)
                self.assertFalse(worker.is_alive())
                self.assertEqual(runner.call_count, 16)
                self.assertEqual(len(failures), 1)
                self.assertIsInstance(failures[0], ProbeBatchCancelled)
            finally:
                stop.set()
                release.set()
                worker.join(timeout=5)

    def test_pre_cancelled_batch_never_opens_a_connection(self):
        stop = threading.Event()
        stop.set()
        with patch("sentinel_blue.probes.run_probe") as runner:
            with self.assertRaises(ProbeBatchCancelled):
                run_probes([{"name": "fixture"}], [], stop_event=stop)
        runner.assert_not_called()

    def test_relay_does_not_publish_a_probe_batch_after_shutdown_requested(self):
        stop = threading.Event()
        app = Mock()

        def complete(*_args, **_kwargs):
            stop.set()
            return [ProbeResult("fixture", "127.0.0.1", True)]

        with patch("sentinel_blue.probes.run_probes", side_effect=complete):
            relay_probe_loop(app, [{}], 5, stop)
        app.ingest.assert_not_called()

    def test_probe_cancellation_is_a_clean_relay_exit(self):
        app = Mock()
        with patch("sentinel_blue.probes.run_probes", side_effect=ProbeBatchCancelled), patch("sentinel_blue.controller.LOG.exception") as log:
            relay_probe_loop(app, [{}], 5, threading.Event())
        app.ingest.assert_not_called()
        log.assert_not_called()


if __name__ == "__main__":
    unittest.main()
