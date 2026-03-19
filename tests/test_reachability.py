"""Tests for reachability analysis."""
from __future__ import annotations

from dockerscope.models.host import HostNetworkSnapshot
from dockerscope.core.reachability import (
    _has_default_route,
    _is_loopback_ip,
    _is_private_ip,
    _iptables_has_dnat_for_port,
    analyze_container_reachability,
)


def _empty_snapshot(**overrides) -> HostNetworkSnapshot:
    data = dict(
        ip_addr="",
        ip_link="",
        bridges="",
        ip_route="",
        iptables_nat="",
        iptables_filter="",
        bridge_link="",
    )
    data.update(overrides)
    return HostNetworkSnapshot(**data)


class _DummyContainer:
    def __init__(self, name="web", network_mode="bridge", ports=None):
        self.name = name
        self.network_mode = network_mode
        self.ports = ports or {}


class TestHasDefaultRoute:
    def test_with_default_route(self):
        snap = _empty_snapshot(ip_route="default via 192.168.1.1 dev eth0\n10.0.0.0/8 dev docker0")
        assert _has_default_route(snap) is True

    def test_without_default_route(self):
        snap = _empty_snapshot(ip_route="10.0.0.0/8 dev docker0\n172.17.0.0/16 dev docker0")
        assert _has_default_route(snap) is False

    def test_empty_route(self):
        snap = _empty_snapshot(ip_route="")
        assert _has_default_route(snap) is False


class TestIpClassification:
    def test_loopback(self):
        assert _is_loopback_ip("127.0.0.1") is True
        assert _is_loopback_ip("127.0.0.2") is True
        assert _is_loopback_ip("10.0.0.1") is False

    def test_private_ips(self):
        assert _is_private_ip("10.0.0.1") is True
        assert _is_private_ip("192.168.1.1") is True
        assert _is_private_ip("172.16.0.1") is True
        assert _is_private_ip("172.31.255.254") is True

    def test_public_ips(self):
        assert _is_private_ip("8.8.8.8") is False
        assert _is_private_ip("1.1.1.1") is False

    def test_172_boundary(self):
        assert _is_private_ip("172.15.0.1") is False
        assert _is_private_ip("172.32.0.1") is False


class TestIptablesDnat:
    def test_port_present(self):
        snap = _empty_snapshot(iptables_nat="DNAT tcp -- 0.0.0.0/0 0.0.0.0/0 tcp dpt:80")
        assert _iptables_has_dnat_for_port(snap, "80") is True

    def test_port_absent(self):
        snap = _empty_snapshot(iptables_nat="DNAT tcp -- 0.0.0.0/0 0.0.0.0/0 tcp dpt:80")
        assert _iptables_has_dnat_for_port(snap, "443") is False


class TestAnalyzeContainerReachability:
    def test_host_network_mode(self):
        c = _DummyContainer(network_mode="host")
        snap = _empty_snapshot()
        reach = analyze_container_reachability(c, snap)
        assert reach.can_reach_host is True
        assert any("host network mode" in n.lower() for n in reach.notes)

    def test_bridge_mode_notes(self):
        c = _DummyContainer(network_mode="bridge")
        snap = _empty_snapshot()
        reach = analyze_container_reachability(c, snap)
        assert any("bridge" in n.lower() for n in reach.notes)

    def test_published_ports_parsed(self):
        c = _DummyContainer(ports={
            "80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "80"}],
            "443/tcp": [{"HostIp": "127.0.0.1", "HostPort": "443"}],
        })
        snap = _empty_snapshot(ip_route="default via 192.168.1.1 dev eth0")
        reach = analyze_container_reachability(c, snap)
        assert len(reach.published_ports) == 2

        # 0.0.0.0 binding should be LAN reachable
        wide_port = next(p for p in reach.published_ports if p.host_ip == "0.0.0.0")
        assert wide_port.reachable_from_lan is True

        # 127.0.0.1 binding should NOT be LAN reachable
        local_port = next(p for p in reach.published_ports if p.host_ip == "127.0.0.1")
        assert local_port.reachable_from_lan is False

    def test_no_ports_empty_published(self):
        c = _DummyContainer(ports={})
        snap = _empty_snapshot()
        reach = analyze_container_reachability(c, snap)
        assert reach.published_ports == []

    def test_no_default_route_note(self):
        c = _DummyContainer()
        snap = _empty_snapshot(ip_route="10.0.0.0/8 dev docker0")
        reach = analyze_container_reachability(c, snap)
        assert any("no default route" in n.lower() for n in reach.notes)

    def test_user_defined_network_note(self):
        c = _DummyContainer(network_mode="my_custom_network")
        snap = _empty_snapshot()
        reach = analyze_container_reachability(c, snap)
        assert any("my_custom_network" in n for n in reach.notes)
