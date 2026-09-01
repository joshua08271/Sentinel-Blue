"""Strictly scope-limited management-plane discovery for assigned networks."""

from __future__ import annotations

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from itertools import islice
from typing import Any


DEFAULT_MANAGEMENT_PORTS = {
    22: ("linux", "ssh"),
    5985: ("windows", "winrm"),
    5986: ("windows", "winrm"),
}


def discover_hosts(
    authorized_networks: list[str],
    port_map: dict[int, tuple[str, str]] | None = None,
    timeout: float = 0.2,
    max_addresses: int = 1024,
) -> list[dict[str, Any]]:
    mappings = port_map or DEFAULT_MANAGEMENT_PORTS
    networks = [ipaddress.ip_network(value, strict=False) for value in authorized_networks]
    addresses: list[str] = []
    for network in networks:
        remaining = max_addresses - len(addresses)
        hosts = [str(value) for value in islice(network.hosts(), remaining + 1)]
        if len(hosts) > remaining:
            raise ValueError(
                f"authorized scope contains more than {max_addresses} addresses; provide an inventory "
                "or smaller explicit CIDRs"
            )
        addresses.extend(hosts)

    def check(address: str, port: int) -> tuple[str, int, bool]:
        try:
            with socket.create_connection((address, port), timeout=timeout):
                return address, port, True
        except OSError:
            return address, port, False

    observed: dict[str, set[int]] = {}
    with ThreadPoolExecutor(max_workers=min(64, max(1, len(addresses) * len(mappings)))) as pool:
        futures = [pool.submit(check, address, port) for address in addresses for port in mappings]
        for future in as_completed(futures):
            address, port, reachable = future.result()
            if reachable:
                observed.setdefault(address, set()).add(port)

    hosts: list[dict[str, Any]] = []
    for address, ports in sorted(observed.items(), key=lambda item: ipaddress.ip_address(item[0])):
        selected = min(ports, key=lambda port: (0 if mappings[port][1] == "ssh" else 1, port))
        platform_name, transport = mappings[selected]
        hosts.append(
            {
                "name": f"discovered-{address.replace(':', '-').replace('.', '-')}",
                "address": address,
                "platform": platform_name,
                "transport": transport,
                "discovered_management_ports": sorted(ports),
            }
        )
    return hosts
