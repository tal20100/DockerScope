from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

DEFAULT_CONFIG_PATH = Path(os.path.expanduser("~")) / ".dockerscope" / "config.yaml"


def load_config(path: Optional[os.PathLike[str] | str] = None) -> Optional[Dict[str, Any]]:
    """
    Load the YAML configuration file if it exists.

    Returns None if the file is missing or invalid.
    """
    cfg_path = Path(path) if path is not None else DEFAULT_CONFIG_PATH
    if not cfg_path.exists():
        return None
    try:
        with cfg_path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        if not isinstance(data, dict):
            return None
        return data
    except Exception:
        # On parse or IO errors, fall back to no config rather than crashing
        return None
