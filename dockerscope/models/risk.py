from __future__ import annotations
from dataclasses import dataclass
from typing import Any

@dataclass
class Risk:
    container: str
    risk_type: str
    description: str
    details: dict[str, Any]
