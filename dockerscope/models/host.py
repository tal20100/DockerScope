from __future__ import annotations
from dataclasses import dataclass

@dataclass
class HostNetworkSnapshot:
    ip_addr: str
    ip_link: str
    bridges: str
    ip_route: str
    iptables_nat: str
    iptables_filter: str
    bridge_link: str