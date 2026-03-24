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
    pid_mode: str | None = None
    user: str | None = None
    security_opt: list[str] | None = None
