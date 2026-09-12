"""Run fixed read-only inventory sections in one finite PowerShell process."""
from __future__ import annotations

import json
import logging
import math
import os
import re
import subprocess
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .windows_queries import WINDOWS_QUERIES

LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class QueryResult:
    rows: list[dict[str, Any]] = field(default_factory=list)
    error: str = ""
    seconds: float = 0.0


def decode_rows(output: str) -> list[dict[str, Any]]:
    if not output.strip():
        return []
    value = json.loads(output)
    rows = value if isinstance(value, list) else [value]
    if any(not isinstance(row, dict) for row in rows):
        raise ValueError("PowerShell inventory JSON must contain object rows")
    return rows


def batch_script(queries: Mapping[str, str]) -> str:
    if not 1 <= len(queries) <= 16 or any(
        not re.fullmatch(r"[A-Z_]{1,32}", name) or not isinstance(script, str)
        for name, script in queries.items()
    ):
        raise ValueError("invalid fixed Windows inventory sections")
    entries = "\n".join(
        "[PSCustomObject]@{Name='" + name + "';Code={\n" + script + "\n}}"
        for name, script in queries.items()
    )
    # Each script block gets its own variable scope, while the PowerShell host
    # and imported native modules are reused. Session inventory runs last and
    # excludes this still-running helper using its real $PID.
    return "$ErrorActionPreference='Stop'\n$queries=@(\n" + entries + r"""
)
foreach ($query in $queries) {
  $watch = [Diagnostics.Stopwatch]::StartNew()
  $ok = $false; $payload = ''; $problem = ''
  try {
    $native = @(& $query.Code 2>&1)
    if (@($native | Where-Object { $_ -is [Management.Automation.ErrorRecord] }).Count) {
      throw 'Inventory emitted a nonterminating error'
    }
    if (@($native | Where-Object { $_ -isnot [string] }).Count) {
      throw 'Inventory emitted non-JSON output'
    }
    $payload = [string]::Join("`n", [string[]]$native)
    $ok = $true
  } catch {
    $line = [int]$_.InvocationInfo.ScriptLineNumber - [int]$query.Code.Ast.Extent.StartLineNumber
    $problem = 'Native section failed: ' + $_.Exception.GetType().Name + ' (section line ' + $line + ')'
  }
  $watch.Stop()
  $record = [PSCustomObject]@{Schema=1;Section=$query.Name;OK=$ok;Payload=$payload;Error=$problem;Seconds=$watch.Elapsed.TotalSeconds}
  [Console]::Out.WriteLine(($record | ConvertTo-Json -Depth 3 -Compress))
  [Console]::Out.Flush()
}
"""


def decode_batch(output: bytes, queries: Mapping[str, str], *, interrupted: bool = False) -> dict[str, QueryResult]:
    """Never let missing, duplicate or malformed records establish completeness."""
    results: dict[str, QueryResult] = {}
    if len(output) > 16 * 1024 * 1024:
        raise ValueError("Windows inventory output exceeded its bound")
    lines = output.splitlines(keepends=True)
    if interrupted and lines and not lines[-1].endswith(b"\n"):
        lines.pop()  # Only complete flushed records survive a killed helper.
    for line in lines:
        if not line.strip():
            continue
        record = json.loads(line.decode("utf-8"))
        if not isinstance(record, dict) or set(record) != {"Schema", "Section", "OK", "Payload", "Error", "Seconds"}:
            raise ValueError("invalid Windows inventory record")
        name = record["Section"]
        if not isinstance(name, str) or name not in queries or name in results:
            raise ValueError("unknown or duplicate Windows inventory section")
        elapsed = record["Seconds"]
        if (
            type(record["Schema"]) is not int or record["Schema"] != 1
            or type(record["OK"]) is not bool
            or not isinstance(record["Payload"], str) or not isinstance(record["Error"], str)
            or type(elapsed) not in (int, float) or not math.isfinite(elapsed) or elapsed < 0
            or (record["OK"] and record["Error"]) or (not record["OK"] and not record["Error"])
        ):
            raise ValueError("malformed Windows inventory status")
        if record["OK"]:
            try:
                results[name] = QueryResult(decode_rows(record["Payload"]), seconds=elapsed)
            except (ValueError, TypeError):
                results[name] = QueryResult(error="Windows inventory section returned invalid JSON rows", seconds=elapsed)
        else:
            results[name] = QueryResult(error=record["Error"][:256], seconds=elapsed)
    for name in queries:
        results.setdefault(name, QueryResult(error="Windows inventory section did not complete"))
    return results


def read_query_batch(deadline: float, queries: Mapping[str, str] = WINDOWS_QUERIES) -> dict[str, QueryResult]:
    if os.name == 'nt' and queries is WINDOWS_QUERIES:
        from .windows_inventory_host import read_owned_inventory
        results = read_owned_inventory(deadline)
        LOG.info("Windows native inventory section seconds: %s", json.dumps(
            {name: round(row.seconds, 3) for name, row in results.items()}, sort_keys=True))
        return results
    started = time.monotonic()
    remaining = deadline - started
    if not math.isfinite(remaining) or remaining <= 0:
        return {name: QueryResult(error="Windows inventory query budget exhausted") for name in queries}
    script = batch_script(queries)
    # Script bytes go through stdin so the combined queries cannot hit Windows'
    # command-line length limit and no privileged script is staged in a temp file.
    command = ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
               "$ErrorActionPreference='Stop'; "
               "[Console]::InputEncoding=[Text.UTF8Encoding]::new($false); "
               "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); "
               "& ([ScriptBlock]::Create([Console]::In.ReadToEnd()))"]
    interrupted = False
    try:
        result = subprocess.run(command, input=script.encode("utf-8"), capture_output=True,
                                timeout=remaining, check=False,
                                # A finite inventory helper must still receive
                                # CPU time during ordinary busy-loop pressure.
                                # Only this child uses AboveNormal; the parent
                                # and monitored services keep their priorities.
                                creationflags=(getattr(subprocess, "CREATE_NO_WINDOW", 0)
                                               | getattr(subprocess, "ABOVE_NORMAL_PRIORITY_CLASS",
                                                         getattr(subprocess, "NORMAL_PRIORITY_CLASS", 0))))
        output = result.stdout
        if result.returncode or result.stderr.strip():
            raise RuntimeError("Windows inventory helper reported a process error")
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or b""
        interrupted = True
    except (OSError, RuntimeError) as exc:
        return {name: QueryResult(error=str(exc)[:256]) for name in queries}
    try:
        results = decode_batch(output, queries, interrupted=interrupted)
    except (ValueError, TypeError, UnicodeError):
        return {name: QueryResult(error="Windows inventory helper returned an invalid batch") for name in queries}
    if interrupted or time.monotonic() >= deadline:
        # Even if every record was flushed, a timed-out helper is not a complete
        # successful observation. The overall collection deadline is unchanged.
        last = next(reversed(queries))
        results[last] = QueryResult(error="Windows inventory helper exhausted its collection budget")
    LOG.info("Windows native inventory section seconds: %s", json.dumps(
        {name: round(row.seconds, 3) for name, row in results.items()}, sort_keys=True))
    return results
