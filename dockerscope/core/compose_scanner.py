"""Compose Scanner — static analysis of docker-compose files for security risks.

Parses a docker-compose YAML file and evaluates each service for
misconfigurations using the same detection logic as the runtime analyzer.
Does NOT require a running Docker daemon.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from dockerscope.core.risks import evaluate_container_risks
from dockerscope.models.container import ContainerInfo
from dockerscope.models.risk import Risk


def scan_compose_file(path: str) -> list[tuple[str, list[Risk]]]:
    """Parse a docker-compose.yml and return (service_name, risks) for each service.

    Args:
        path: Filesystem path to a docker-compose YAML file.

    Returns:
        List of (service_name, risks) tuples — one per service.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the YAML is invalid or unparseable.
    """
    filepath = Path(path)
    if not filepath.exists():
        raise FileNotFoundError(
            f"Compose file not found: {filepath}. "
            f"Check the path and try again."
        )

    raw = filepath.read_text(encoding="utf-8")
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML in {filepath}: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError(
            f"Expected a YAML mapping in {filepath}, got {type(data).__name__}. "
            f"Is this a valid docker-compose file?"
        )

    # Compose v2+ uses top-level "services"; v1 has services at root
    services: dict = data.get("services") or {}
    if not isinstance(services, dict):
        services = {}

    # Warn about unknown compose version but continue
    data.get("version")

    results: list[tuple[str, list[Risk]]] = []
    for service_name, service_def in services.items():
        if not isinstance(service_def, dict):
            service_def = {}
        container = _service_to_container_info(service_name, service_def)
        risks = evaluate_container_risks(container)
        results.append((service_name, risks))

    return results


def _service_to_container_info(name: str, svc: dict) -> ContainerInfo:
    """Convert a compose service definition to a ContainerInfo for risk evaluation.

    Args:
        name: Service name from the compose file.
        svc: Service definition dictionary.

    Returns:
        ContainerInfo populated from compose keys.
    """
    image = svc.get("image", "<build>")
    privileged = bool(svc.get("privileged", False))
    network_mode = svc.get("network_mode", "bridge") or "bridge"

    # Mounts — handle both short and long syntax
    mounts = _parse_volumes(svc.get("volumes", []))

    # Ports
    ports = _parse_ports(svc.get("ports", []))

    # Capabilities
    cap_add = svc.get("cap_add", []) or []
    cap_drop = svc.get("cap_drop", []) or []
    capabilities = [f"CAP_ADD:{c}" for c in cap_add] + [f"CAP_DROP:{c}" for c in cap_drop]

    # PID mode
    pid_mode = None
    pid_val = svc.get("pid", "")
    if pid_val == "host":
        pid_mode = "host"

    # User
    user = svc.get("user")
    if user is not None:
        user = str(user)

    # Security options
    security_opt = svc.get("security_opt")
    if security_opt is not None and not isinstance(security_opt, list):
        security_opt = [str(security_opt)]

    return ContainerInfo(
        id=f"compose-{name}",
        name=name,
        image=image,
        privileged=privileged,
        network_mode=network_mode,
        status="not_running",
        mounts=mounts,
        ports=ports,
        capabilities=capabilities,
        pid_mode=pid_mode,
        user=user,
        security_opt=security_opt,
    )


def _parse_volumes(volumes: list) -> list[dict[str, str]]:
    """Parse compose volume entries into mount dicts.

    Handles both short syntax (``"./host:/container"``) and long syntax
    (``{type: bind, source: ..., target: ...}``).

    Args:
        volumes: List of volume entries from compose file.

    Returns:
        List of mount dictionaries with Source/Destination keys.
    """
    if not volumes:
        return []

    mounts: list[dict[str, str]] = []
    for vol in volumes:
        if isinstance(vol, str):
            parts = vol.split(":")
            if len(parts) >= 2:
                source = parts[0]
                dest = parts[1]
                mode = parts[2] if len(parts) > 2 else "rw"
            else:
                source = ""
                dest = parts[0]
                mode = "rw"
            mounts.append({"Source": source, "Destination": dest, "Mode": mode})
        elif isinstance(vol, dict):
            source = str(vol.get("source", ""))
            target = str(vol.get("target", ""))
            read_only = vol.get("read_only", False)
            mode = "ro" if read_only else "rw"
            mounts.append({"Source": source, "Destination": target, "Mode": mode})

    return mounts


def _parse_ports(ports: list) -> dict[str, list[dict[str, str]]]:
    """Parse compose port entries into Docker-style ports dict.

    Handles both short syntax (``"8080:80"``) and long syntax
    (``{target: 80, published: 8080}``).

    Args:
        ports: List of port entries from compose file.

    Returns:
        Dictionary mapping ``"port/tcp"`` to list of binding dicts.
    """
    if not ports:
        return {}

    result: dict[str, list[dict[str, str]]] = {}
    for port in ports:
        if isinstance(port, str):
            # Formats: "8080:80", "8080:80/udp", "127.0.0.1:8080:80", "80"
            parts = str(port).split(":")
            if len(parts) == 1:
                # Just container port
                container_port = parts[0].split("/")[0]
                proto = "tcp"
                if "/" in parts[0]:
                    proto = parts[0].split("/")[1]
                key = f"{container_port}/{proto}"
                result[key] = [{"HostIp": "0.0.0.0", "HostPort": container_port}]
            elif len(parts) == 2:
                # host_port:container_port
                host_port = parts[0]
                container_part = parts[1]
                container_port = container_part.split("/")[0]
                proto = "tcp"
                if "/" in container_part:
                    proto = container_part.split("/")[1]
                key = f"{container_port}/{proto}"
                result[key] = [{"HostIp": "0.0.0.0", "HostPort": host_port}]
            elif len(parts) == 3:
                # host_ip:host_port:container_port
                host_ip = parts[0]
                host_port = parts[1]
                container_part = parts[2]
                container_port = container_part.split("/")[0]
                proto = "tcp"
                if "/" in container_part:
                    proto = container_part.split("/")[1]
                key = f"{container_port}/{proto}"
                result[key] = [{"HostIp": host_ip, "HostPort": host_port}]
        elif isinstance(port, (int, float)):
            key = f"{int(port)}/tcp"
            result[key] = [{"HostIp": "0.0.0.0", "HostPort": str(int(port))}]
        elif isinstance(port, dict):
            target = str(port.get("target", ""))
            published = str(port.get("published", target))
            host_ip = str(port.get("host_ip", "0.0.0.0"))
            proto = str(port.get("protocol", "tcp"))
            key = f"{target}/{proto}"
            result[key] = [{"HostIp": host_ip, "HostPort": published}]

    return result
