"""Condense related alerts into short incident summaries for the team."""

from __future__ import annotations

from collections import defaultdict
from typing import Any


SEVERITY_SCORE = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def correlate(alerts: list[dict[str, Any]], window: float = 900) -> list[dict[str, Any]]:
    open_alerts = [item for item in alerts if item.get("status") == "open"]
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for alert in open_alerts:
        groups[str(alert.get("agent_id", "unknown"))].append(alert)
    incidents: list[dict[str, Any]] = []
    for agent_id, items in groups.items():
        items.sort(key=lambda item: float(item.get("created_at", 0)))
        buckets: list[list[dict[str, Any]]] = []
        for item in items:
            if not buckets or float(item.get("created_at", 0)) - float(buckets[-1][-1].get("created_at", 0)) > window:
                buckets.append([item])
            else:
                buckets[-1].append(item)
        for bucket in buckets:
            severity = max(
                (str(item.get("severity", "low")) for item in bucket),
                key=lambda value: SEVERITY_SCORE.get(value, 0),
            )
            kinds = sorted({str(item.get("kind", "unknown")) for item in bucket})
            score = min(100, sum(SEVERITY_SCORE.get(str(item.get("severity")), 0) * 18 for item in bucket))
            incidents.append(
                {
                    "incident_id": f"{agent_id}:{int(float(bucket[0].get('created_at', 0)) // window)}",
                    "agent_id": agent_id,
                    "severity": severity,
                    "risk_score": score,
                    "alert_count": len(bucket),
                    "kinds": kinds,
                    "summary": (
                        f"{len(bucket)} related finding(s): " + ", ".join(kind.replace("_", " ") for kind in kinds[:4])
                    ),
                    "first_seen": min(float(item.get("created_at", 0)) for item in bucket),
                    "last_seen": max(float(item.get("created_at", 0)) for item in bucket),
                }
            )
    return sorted(incidents, key=lambda item: (SEVERITY_SCORE.get(item["severity"], 0), item["last_seen"]), reverse=True)
