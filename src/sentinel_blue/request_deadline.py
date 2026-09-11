"""Bound an agent's network wait, including slow headers, bodies and DNS.

Python's socket timeout limits idle I/O, not the duration of a request. A
single daemon worker contains an uninterruptible platform resolver; another
worker is never admitted while it is still draining. Late responses cannot
update agent authentication or action state.
"""

from __future__ import annotations

from http.client import HTTPConnection, HTTPSConnection
import math
import socket
import threading
import time
from typing import Any, Callable
from urllib.error import URLError
from urllib.request import HTTPHandler, HTTPSHandler


class RequestBudget:
    def __init__(self, seconds: float, label: str = "controller request"):
        if type(seconds) not in (int, float) or not math.isfinite(seconds) or seconds <= 0:
            raise ValueError("network deadline must be positive and finite")
        self.deadline = time.monotonic() + seconds
        self.label = label
        self._lock = threading.Lock()
        self._cancelled = False
        self._sockets: list[socket.socket] = []

    def attach(self, connection: socket.socket) -> None:
        with self._lock:
            expired = self._cancelled or time.monotonic() >= self.deadline
            if not expired:
                self._sockets.append(connection)
        if expired:
            self._close_socket(connection)
            raise TimeoutError(self.label + " deadline exceeded")

    def remaining(self) -> float:
        with self._lock:
            remaining = self.deadline - time.monotonic()
            if self._cancelled or remaining <= 0:
                raise TimeoutError(self.label + " deadline exceeded")
        return remaining

    @staticmethod
    def _close_socket(connection: socket.socket) -> None:
        try:
            connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        connection.close()

    def close(self) -> None:
        with self._lock:
            self._cancelled = True
            connections, self._sockets = self._sockets, []
        for connection in connections:
            self._close_socket(connection)


class _BudgetConnection:
    def __init__(self, *args: Any, budget: RequestBudget, **kwargs: Any):
        self._budget = budget
        super().__init__(*args, **kwargs)

    def connect(self) -> None:
        super().connect()
        self._budget.attach(self.sock)


class _HTTPConnection(_BudgetConnection, HTTPConnection):
    pass


class _HTTPSConnection(_BudgetConnection, HTTPSConnection):
    pass


class DeadlineHTTPHandler(HTTPHandler):
    def http_open(self, request: Any) -> Any:
        return self.do_open(_HTTPConnection, request, budget=request._sentinel_blue_budget)


class DeadlineHTTPSHandler(HTTPSHandler):
    def https_open(self, request: Any) -> Any:
        return self.do_open(_HTTPSConnection, request, context=self._context,
                            budget=request._sentinel_blue_budget)


class BoundedRequest:
    """One network operation at a time, with a deadline on the caller's wait."""

    def __init__(self, *, label: str = "controller request", thread_name: str = "sentinel-agent-request") -> None:
        self._lock = threading.Lock()
        self._worker: threading.Thread | None = None
        self._running = False
        self._label = label
        self._thread_name = thread_name

    @property
    def running(self) -> bool:
        with self._lock:
            return self._running

    def run(self, operation: Callable[[RequestBudget], Any], seconds: float) -> Any:
        budget = RequestBudget(seconds, self._label)
        finished = threading.Event()
        outcome: dict[str, Any] = {}

        def work() -> None:
            try:
                outcome["result"] = operation(budget)
            except BaseException as exc:
                outcome["error"] = exc
            finally:
                budget.close()
                outcome["completed_at"] = time.monotonic()
                with self._lock:
                    self._running = False
                finished.set()

        with self._lock:
            if self._running:
                raise URLError("previous " + self._label + " is still draining")
            self._worker = threading.Thread(target=work, name=self._thread_name, daemon=True)
            self._running = True
            try:
                self._worker.start()
            except BaseException:
                self._running = False
                raise
        if not finished.wait(max(0.0, budget.deadline - time.monotonic())):
            budget.close()
            raise TimeoutError(self._label + " deadline exceeded")
        if outcome["completed_at"] > budget.deadline:
            raise TimeoutError(self._label + " deadline exceeded")
        if "error" in outcome:
            raise outcome["error"]
        return outcome["result"]


class BoundedRequestPool:
    """Fixed process-wide capacity, retained while abandoned workers drain.

    A stuck resolver cannot create new workers on every probe cycle. Capacity
    exhaustion fails explicitly; a late resolver result must still pass the
    operation's budget check before a socket or native client is used.
    """

    def __init__(self, capacity: int, *, label: str, thread_name: str):
        if type(capacity) is not int or not 1 <= capacity <= 64:
            raise ValueError("network worker capacity must be 1..64")
        self._lock = threading.Lock()
        self._requests = [BoundedRequest(label=label, thread_name=thread_name) for _ in range(capacity)]
        self._reserved: set[int] = set()
        self._label = label

    def run(self, operation: Callable[[RequestBudget], Any], seconds: float) -> Any:
        with self._lock:
            available = next((index for index, request in enumerate(self._requests)
                              if index not in self._reserved and not request.running), None)
            if available is None:
                raise RuntimeError(self._label + " worker capacity exhausted; previous requests are still draining")
            self._reserved.add(available)
        try:
            return self._requests[available].run(operation, seconds)
        finally:
            with self._lock:
                self._reserved.remove(available)
