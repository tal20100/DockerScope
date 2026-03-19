from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ContainerInfo:
    """Normalized subset of Docker container inspection data used by dockerscope."""

    id: str
    name: str
    image: str
    privileged: bool
    network_mode: str
    status: str
    mounts: list[dict[str, Any]] = field(default_factory=list)
    ports: dict[str, Any] = field(default_factory=dict)
    capabilities: list[str] = field(default_factory=list)

@dataclass
class PublishedPortInfo:
    container_port: str
    host_ip: str
    host_port: str
    reachable_from_lan: bool
    reachable_from_internet: bool

@dataclass
class ContainerReachability:
    container_name: str
    network_mode: str
    published_ports: list[PublishedPortInfo]
    can_reach_host: bool
    can_reach_lan: bool
    can_reach_internet: bool
    notes: list[str]
