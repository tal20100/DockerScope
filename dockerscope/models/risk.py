from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Risk:
    container: str
    risk_type: str
    severity: str
    description: str
    attack_explanation: str
    attack_commands: list[str]
    remediation: str
    details: dict[str, Any] = field(default_factory=dict)
