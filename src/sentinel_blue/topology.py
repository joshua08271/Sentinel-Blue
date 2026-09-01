"""Passive topology graph construction from agent observations."""

from __future__ import annotations

import ipaddress
from typing import Any


def _allowed(address: str, networks: list[ipaddress._BaseNetwork]) -> bool:
    try:
        value = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return False
    if value.is_loopback or value.is_link_local:
        return True
    return not networks or any(value in network for network in networks)


def _host_address(value: str) -> str | None:
    try:
        text = value.split("%", 1)[0]
        return str(ipaddress.ip_interface(text).ip if "/" in text else ipaddress.ip_address(text))
    except ValueError:
        return None


def build_topology(
    telemetry_by_agent: list[dict[str, Any]], authorized_networks: list[str]
) -> dict[str, Any]:
    networks = [ipaddress.ip_network(value, strict=False) for value in authorized_networks]
    nodes: dict[str, dict[str, Any]] = {}
    links: set[tuple[str, str, str]] = set()
    address_owners: dict[str, str] = {}
    for telemetry in telemetry_by_agent:
        agent_id = str(telemetry.get("agent_id", telemetry.get("hostname", "unknown")))
        for interface in telemetry.get("interfaces", []):
            for raw_address in interface.get("addresses", []):
                address = _host_address(str(raw_address))
                if address and _allowed(address, networks):
                    address_owners.setdefault(address, agent_id)
    for telemetry in telemetry_by_agent:
        agent_id = str(telemetry.get("agent_id", telemetry.get("hostname", "unknown")))
        host_addresses = sorted(
            address for address, owner in address_owners.items() if owner == agent_id
        )
        nodes[agent_id] = {
            "id": agent_id,
            "label": str(telemetry.get("hostname", agent_id)),
            "kind": "managed-host",
            "platform": str(telemetry.get("platform", "unknown")),
            "listeners": len(telemetry.get("listeners", [])),
            "addresses": host_addresses,
        }
        for neighbor in telemetry.get("neighbors", []):
            raw_address = str(neighbor.get("address", ""))
            address = _host_address(raw_address) or raw_address
            if not address or not _allowed(address, networks):
                continue
            neighbor_id = address_owners.get(address, f"address:{address}")
            if neighbor_id != agent_id:
                nodes.setdefault(
                    neighbor_id,
                    {
                        "id": neighbor_id,
                        "label": address,
                        "kind": "observed-neighbor",
                        "hardware_address": str(neighbor.get("hardware_address", "")),
                    },
                )
                links.add((agent_id, neighbor_id, str(neighbor.get("interface", ""))))
        for route in telemetry.get("routes", []):
            raw_gateway = str(route.get("gateway", ""))
            gateway = _host_address(raw_gateway) or raw_gateway
            if not gateway or gateway in {"0.0.0.0", "::"} or not _allowed(gateway, networks):
                continue
            gateway_id = f"address:{gateway}"
            nodes.setdefault(gateway_id, {"id": gateway_id, "label": gateway, "kind": "gateway"})
            links.add((agent_id, gateway_id, str(route.get("interface", ""))))
    return {
        "nodes": sorted(nodes.values(), key=lambda item: (item["kind"], item["label"])),
        "links": [
            {"source": source, "target": target, "interface": interface}
            for source, target, interface in sorted(links)
        ],
        "source": "passive-agent-observations",
    }
