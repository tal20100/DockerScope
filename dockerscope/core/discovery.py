from __future__ import annotations

from typing import Optional

from dockerscope.models.container import ContainerInfo

from .docker_client import list_containers


def _extract_container_info(container: object) -> ContainerInfo:
    """
    Convert a Docker SDK container object into a ContainerInfo instance.

    This keeps dockerscope decoupled from the raw Docker SDK structures.
    """
    inspect: dict = container.attrs  # full inspection data

    host_config: dict = inspect.get("HostConfig", {}) or {}
    config: dict = inspect.get("Config", {}) or {}
    state: dict = inspect.get("State", {}) or {}

    privileged = bool(host_config.get("Privileged", False))
    network_mode = str(host_config.get("NetworkMode", ""))
    status = str(state.get("Status") or getattr(container, "status", "") or "unknown")

    mounts = inspect.get("Mounts", []) or []

    ports = inspect.get("NetworkSettings", {}).get("Ports", {}) or {}

    # Capabilities can be specified under HostConfig.CapAdd/CapDrop in many setups.
    cap_add = host_config.get("CapAdd") or []
    cap_drop = host_config.get("CapDrop") or []
    capabilities = [f"CAP_ADD:{c}" for c in cap_add] + [f"CAP_DROP:{c}" for c in cap_drop]

    return ContainerInfo(
        id=inspect.get("Id", container.id),
        name=inspect.get("Name", container.name).lstrip("/"),
        image=config.get("Image", getattr(container.image, "tags", [None])[0] or "unknown"),
        privileged=privileged,
        network_mode=network_mode,
        status=status,
        mounts=mounts,
        ports=ports,
        capabilities=capabilities,
    )


def discover_containers(all_containers: bool = False) -> list[ContainerInfo]:
    """
    Discover containers and return normalized metadata.

    This is the main entry point for other modules and the CLI.
    """
    containers = list_containers(all_containers=all_containers)
    return [_extract_container_info(c) for c in containers]


def find_container(name_or_id: str) -> Optional[ContainerInfo]:
    """
    Find a single container by exact name or ID prefix.
    """
    for info in discover_containers(all_containers=True):
        if info.id.startswith(name_or_id) or info.name == name_or_id:
            return info
    return None
