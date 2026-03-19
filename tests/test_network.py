from __future__ import annotations

from dockerscope.models.container import ContainerReachability, PublishedPortInfo
from dockerscope.models.host import HostNetworkSnapshot
from dockerscope.core.reachability import analyze_container_reachability


class DummyContainer:
    def __init__(self) -> None:
        self.name = "web"
        self.network_mode = "bridge"
        self.ports = {"80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "80"}]}


def _snapshot_with_default_route() -> HostNetworkSnapshot:
    return HostNetworkSnapshot(
        ip_addr="",
        ip_link="",
        bridges="",
        ip_route="default via 192.168.1.1 dev eth0\n",
        iptables_nat="DNAT       tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:80",
        iptables_filter="",
        bridge_link="",
    )


def test_analyze_container_reachability_basic() -> None:
    c = DummyContainer()
    snapshot = _snapshot_with_default_route()

    reach: ContainerReachability = analyze_container_reachability(c, snapshot)

    assert reach.can_reach_host is True
    assert reach.can_reach_lan is True
    # Internet reachability may depend on live HTTP check; do not assert True here.
    assert len(reach.published_ports) == 1
    p: PublishedPortInfo = reach.published_ports[0]
    assert p.host_ip == "0.0.0.0"
    assert p.host_port == "80"
    assert p.reachable_from_lan is True
