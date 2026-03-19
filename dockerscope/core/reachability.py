from __future__ import annotations

import platform
import subprocess
from urllib.error import URLError
from urllib.request import urlopen

from dockerscope.models.container import PublishedPortInfo, ContainerReachability
from dockerscope.models.host import HostNetworkSnapshot


# -----------------------------
# Collector functions
# -----------------------------
def _run_command(cmd: list[str]) -> str:
    try:
        result = subprocess.run(
            cmd, check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )
        return result.stdout
    except Exception as exc:
        return f"error running {' '.join(cmd)}: {exc}"

def collect_host_network_info() -> HostNetworkSnapshot:
    system = platform.system().lower()
    if system != "linux":
        placeholder = f"{system} host: detailed reachability only on Linux."
        return HostNetworkSnapshot(
            ip_addr=placeholder,
            ip_link=placeholder,
            bridges=placeholder,
            ip_route=placeholder,
            iptables_nat=placeholder,
            iptables_filter=placeholder,
            bridge_link=placeholder,
        )

    bridges_output = _run_command(["ip", "-d", "link", "show", "type", "bridge"])
    if "not found" in bridges_output.lower() or "error" in bridges_output.lower():
        bridges_output = _run_command(["brctl", "show"])

    return HostNetworkSnapshot(
        ip_addr=_run_command(["ip", "a"]),
        ip_link=_run_command(["ip", "link"]),
        bridges=bridges_output,
        ip_route=_run_command(["ip", "route"]),
        iptables_nat=_run_command(["iptables", "-t", "nat", "-L", "-n"]),
        iptables_filter=_run_command(["iptables", "-L", "-n"]),
        bridge_link=_run_command(["bridge", "link"]),
    )

def _can_reach_internet(url: str = "https://www.google.com", timeout: int = 2) -> bool:
    """
    Perform a lightweight HTTPS GET to check Internet reachability.

    This is deliberately simple and time-bounded so it is safe to run
    on production hosts. any network or SSL error is treated as
    "no Internet" rather than failing the analysis.
    """
    try:
        with urlopen(url, timeout=timeout) as resp:  # type: ignore[call-arg]
            return 200 <= getattr(resp, "status", 200) < 400
    except (URLError, OSError, ValueError):
        return False

# -----------------------------
# Analyzer / Reachability
# -----------------------------
def _has_default_route(snapshot: HostNetworkSnapshot) -> bool:
    for line in snapshot.ip_route.splitlines():
        if line.strip().startswith("default "):
            return True
    return False

def _is_loopback_ip(ip: str) -> bool:
    return ip.startswith("127.")

def _is_private_ip(ip: str) -> bool:
    return (
        ip.startswith("10.")
        or ip.startswith("192.168.")
        or (ip.startswith("172.") and any(ip.startswith(f"172.{n}.") for n in range(16, 32)))
    )

def _iptables_has_dnat_for_port(snapshot: HostNetworkSnapshot, port: str) -> bool:
    return f"dpt:{port}" in snapshot.iptables_nat

def analyze_container_reachability(container: object, snapshot: HostNetworkSnapshot) -> ContainerReachability:
    """Best-effort reachability analysis for a container (includes Google ping)."""
    notes: list[str] = []
    published: list[PublishedPortInfo] = []

    default_route = _has_default_route(snapshot)
    internet_flag = _can_reach_internet() and default_route

    if not default_route:
        notes.append("Host has no default route; Internet may be unreachable.")

    for container_port, bindings in (getattr(container, "ports", {}) or {}).items():
        if not bindings:
            continue
        for binding in bindings:
            host_ip = binding.get("HostIp") or "0.0.0.0"
            host_port = binding.get("HostPort") or "?"
            reachable_lan = False
            reachable_internet = False

            if host_port != "?":
                if host_ip in ("0.0.0.0", "::"):
                    reachable_lan = True
                    reachable_internet = internet_flag and _iptables_has_dnat_for_port(snapshot, host_port)
                elif _is_loopback_ip(host_ip):
                    reachable_lan = False
                    reachable_internet = False
                elif _is_private_ip(host_ip):
                    reachable_lan = True
                    reachable_internet = False
                else:
                    reachable_lan = True
                    reachable_internet = internet_flag

            published.append(
                PublishedPortInfo(
                    container_port=str(container_port),
                    host_ip=str(host_ip),
                    host_port=str(host_port),
                    reachable_from_lan=reachable_lan,
                    reachable_from_internet=reachable_internet,
                )
            )

    nm = getattr(container, "network_mode", "") or ""
    nm_lower = nm.lower()

    if nm_lower == "host":
        can_reach_host = True
        can_reach_lan = True
        can_reach_internet = internet_flag
        notes.append("Container uses host network mode; shares host namespace.")
    else:
        can_reach_host = True
        can_reach_lan = True
        can_reach_internet = internet_flag
        if nm_lower in ("bridge", "", "default"):
            notes.append("Container attached to default Docker bridge; traffic SNATed to host.")
        else:
            notes.append(f"Container uses user-defined network mode '{nm}'.")

    return ContainerReachability(
        container_name=getattr(container, "name", "unknown"),
        network_mode=nm,
        published_ports=published,
        can_reach_host=can_reach_host,
        can_reach_lan=can_reach_lan,
        can_reach_internet=can_reach_internet,
        notes=notes,
    )