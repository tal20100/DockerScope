"""
Risk Detection - Comprehensive security risk detection for Docker containers.

This module implements detection rules for identifying dangerous configurations
that could lead to container escape, privilege escalation, or data exfiltration.

Detection categories:
- CRITICAL: Docker socket access, privileged mode, critical capabilities
- HIGH: Dangerous capabilities, sensitive mounts, host namespace sharing
- MEDIUM: Port exposure, missing security profiles, resource limits
- LOW: Running as root, unpinned images
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from dockerscope.core.discovery import ContainerInfo
from dockerscope.config.load_config import load_config
from dockerscope.models.risk import Risk

# Dangerous paths for container mounts
DOCKER_SOCK_PATHS = {"/var/run/docker.sock", "/run/docker.sock"}
DANGEROUS_HOST_MOUNTS = {
    "/",  # Root filesystem
    "/etc",  # System configuration
    "/root",  # Root home directory
    "/boot",  # Boot partition
    "/var/lib/docker",  # Docker data directory
    "/usr/bin",  # System binaries
    "/usr/sbin",  # System admin binaries
    "/proc",  # Process information
    "/sys",  # System information
    "/dev"  # Device files
}

# Linux capabilities that pose security risks
CRITICAL_CAPABILITIES = {
    "SYS_ADMIN",  # Near-root privileges, can mount filesystems
    "SYS_MODULE",  # Can load kernel modules
}

DANGEROUS_CAPABILITIES = {
    "SYS_RAWIO",  # Raw I/O access
    "SYS_PTRACE",  # Can debug/inject into other processes
    "SYS_BOOT",  # Can reboot system
    "NET_ADMIN",  # Network administration
    "DAC_OVERRIDE",  # Bypass file permission checks
    "DAC_READ_SEARCH",  # Bypass file read permissions
    "SETUID",  # Can change user IDs
    "SETGID",  # Can change group IDs
}

# Dangerous namespace modes
DANGEROUS_NAMESPACE_MODES = {"host"}


def _is_dangerous_mount(source: str, destination: str) -> bool:
    """
    Check if a mount is considered dangerous.

    Checks both exact matches and subpaths of dangerous locations.
    For example, /etc/ssh is dangerous because it's under /etc.

    Args:
        source: Mount source path
        destination: Mount destination path

    Returns:
        True if mount is dangerous
    """
    if not source:
        return False

    source = str(source)

    # Direct match
    if source in DANGEROUS_HOST_MOUNTS:
        return True

    # Check if source is a subpath of any dangerous mount
    # e.g., /etc/ssh, /var/lib/docker/overlay2
    for base in DANGEROUS_HOST_MOUNTS:
        if base == "/":
            continue  # Root ("/") exact match already handled above
        if source.startswith(base + "/"):
            return True

    return False


def _has_critical_capability(capabilities: list[str]) -> Optional[str]:
    """
    Check for critical added capabilities that enable privilege escalation.

    Only CAP_ADD entries are checked. CAP_DROP entries are security-positive
    and should not be flagged.

    Args:
        capabilities: List of capabilities (with CAP_ADD:/CAP_DROP: prefix)

    Returns:
        Name of first critical capability found, or None
    """
    for cap in capabilities:
        if not cap.startswith("CAP_ADD:"):
            continue
        cap_name = cap.removeprefix("CAP_ADD:")
        if cap_name in CRITICAL_CAPABILITIES:
            return cap_name
    return None


def _has_dangerous_capability(capabilities: list[str]) -> Optional[str]:
    """
    Check for dangerous added capabilities that expand attack surface.

    Only CAP_ADD entries are checked. CAP_DROP entries are security-positive.

    Args:
        capabilities: List of capabilities (with CAP_ADD:/CAP_DROP: prefix)

    Returns:
        Name of first dangerous capability found, or None
    """
    for cap in capabilities:
        if not cap.startswith("CAP_ADD:"):
            continue
        cap_name = cap.removeprefix("CAP_ADD:")
        if cap_name in DANGEROUS_CAPABILITIES:
            return cap_name
    return None


def _is_running_as_root(container: ContainerInfo) -> bool:
    """
    Check if container is running as root user.

    Note: Requires 'user' field in ContainerInfo.
    Returns False if field not available.

    Args:
        container: Container information

    Returns:
        True if running as root
    """
    # Check if container has user field
    user = getattr(container, 'user', None)
    if user is None:
        return False

    # Root can be specified as "root", "0", or empty string
    return user in ("root", "0", "")


def evaluate_container_risks(container: ContainerInfo) -> list[Risk]:
    """
    Evaluate a container for security risks.

    Implements comprehensive detection rules across all severity levels.
    Each rule generates a Risk object with detailed information for
    remediation and attack path analysis.

    Args:
        container: Container to evaluate

    Returns:
        List of detected Risk objects
    """
    risks: list[Risk] = []

    # ========================================================================
    # CRITICAL RISKS
    # ========================================================================

    # Rule 1: Privileged container
    if container.privileged:
        risks.append(
            Risk(
                container=container.name,
                risk_type="privileged_container",
                description="Container is running in privileged mode.",
                details={
                    "network_mode": container.network_mode,
                    "impact": "Full host access via device access and capability bypass"
                },
            )
        )

    # Rule 2: Docker socket mount
    for mount in container.mounts:
        src = mount.get("Source") or mount.get("src") or ""
        dst = mount.get("Destination") or mount.get("dst") or ""

        if src in DOCKER_SOCK_PATHS or dst in DOCKER_SOCK_PATHS:
            risks.append(
                Risk(
                    container=container.name,
                    risk_type="docker_sock_mount",
                    description="Container has access to the Docker socket.",
                    details={
                        "source": src,
                        "destination": dst,
                        "impact": "Can control Docker daemon and create privileged containers"
                    },
                )
            )

    # Rule 3: Critical capabilities
    critical_cap = _has_critical_capability(container.capabilities)
    if critical_cap:
        risks.append(
            Risk(
                container=container.name,
                risk_type="critical_capability",
                description=f"Container has critical capability: {critical_cap}",
                details={
                    "capability": critical_cap,
                    "impact": "Near-root privileges, can bypass most security controls"
                },
            )
        )

    # ========================================================================
    # HIGH RISKS
    # ========================================================================

    # Rule 4: Host network mode
    if container.network_mode == "host":
        risks.append(
            Risk(
                container=container.name,
                risk_type="host_network_mode",
                description="Container is using host network mode.",
                details={
                    "impact": "Can see all host network traffic and bind to any port"
                },
            )
        )

    # Rule 5: Host PID namespace (if available)
    pid_mode = getattr(container, 'pid_mode', None)
    if pid_mode and pid_mode in DANGEROUS_NAMESPACE_MODES:
        risks.append(
            Risk(
                container=container.name,
                risk_type="host_pid_mode",
                description="Container shares host PID namespace.",
                details={
                    "pid_mode": pid_mode,
                    "impact": "Can see and interact with all host processes"
                },
            )
        )

    # Rule 6: Dangerous host mounts
    for mount in container.mounts:
        src = mount.get("Source") or mount.get("src") or ""
        dst = mount.get("Destination") or mount.get("dst") or ""
        mode = mount.get("Mode", "rw")

        if _is_dangerous_mount(src, dst):
            # Skip docker.sock (already checked)
            if src in DOCKER_SOCK_PATHS:
                continue

            is_writable = "rw" in mode.lower()

            risks.append(
                Risk(
                    container=container.name,
                    risk_type="dangerous_host_mount",
                    description=f"Container mounts sensitive host path: {src}",
                    details={
                        "source": src,
                        "destination": dst,
                        "mode": mode,
                        "writable": is_writable,
                        "impact": f"{'Can modify' if is_writable else 'Can read'} sensitive host files"
                    },
                )
            )

    # Rule 7: Dangerous capabilities
    dangerous_cap = _has_dangerous_capability(container.capabilities)
    if dangerous_cap:
        risks.append(
            Risk(
                container=container.name,
                risk_type="dangerous_capability",
                description=f"Container has dangerous capability: {dangerous_cap}",
                details={
                    "capability": dangerous_cap,
                    "impact": "Extended privileges that may enable container escape"
                },
            )
        )

    # ========================================================================
    # MEDIUM RISKS
    # ========================================================================

    # Rule 8: Ports exposed to all interfaces (0.0.0.0)
    for container_port, bindings in (container.ports or {}).items():
        if not bindings:
            continue
        for binding in bindings:
            host_ip = binding.get("HostIp", "")
            host_port = binding.get("HostPort", "")

            # 0.0.0.0, empty string, or :: means all interfaces
            if host_ip in ("0.0.0.0", "", "::"):
                risks.append(
                    Risk(
                        container=container.name,
                        risk_type="wide_exposed_port",
                        description=f"Port {container_port} is exposed on all interfaces (0.0.0.0).",
                        details={
                            "container_port": container_port,
                            "host_ip": host_ip or "0.0.0.0",
                            "host_port": host_port,
                            "impact": "Service accessible from any network interface"
                        },
                    )
                )

    # Rule 9: No security profiles (if available)
    security_opt = getattr(container, 'security_opt', None)
    if security_opt is not None:
        # Check if security profiles are explicitly disabled
        if 'apparmor=unconfined' in security_opt or 'seccomp=unconfined' in security_opt:
            risks.append(
                Risk(
                    container=container.name,
                    risk_type="no_security_profiles",
                    description="Container has security profiles disabled.",
                    details={
                        "security_opt": security_opt,
                        "impact": "Fewer restrictions on syscalls and operations"
                    },
                )
            )

    # Rule 10: No resource limits (if available)
    resources = getattr(container, 'resources', None)
    if resources is not None:
        # Check if no memory or CPU limits are set
        has_limits = any(resources.values()) if isinstance(resources, dict) else False
        if not has_limits:
            risks.append(
                Risk(
                    container=container.name,
                    risk_type="no_resource_limits",
                    description="Container has no CPU or memory limits set.",
                    details={
                        "impact": "Can consume excessive host resources (DoS potential)"
                    },
                )
            )

    # ========================================================================
    # LOW RISKS
    # ========================================================================

    # Rule 11: Running as root
    if _is_running_as_root(container):
        risks.append(
            Risk(
                container=container.name,
                risk_type="running_as_root",
                description="Container process is running as root user.",
                details={
                    "impact": "If container is compromised, attacker has root privileges inside container"
                },
            )
        )

    # Rule 12: Unpinned image tag (using :latest)
    if container.image.endswith(":latest") or ":" not in container.image:
        risks.append(
            Risk(
                container=container.name,
                risk_type="unpinned_image",
                description="Container using unpinned image tag (:latest or no tag).",
                details={
                    "image": container.image,
                    "impact": "Image may change unexpectedly, introducing vulnerabilities"
                },
            )
        )

    return risks


def filter_risks_with_whitelist(
        risks: list[Risk],
        cfg: Optional[dict] = None
) -> list[Risk]:
    """
    Filter risks based on whitelist configuration.

    Allows users to acknowledge and accept specific risks for specific
    containers. Useful for tools like Portainer or Watchtower that
    legitimately need elevated privileges.

    Example config (~/.dockerscope/config.yaml):
        whitelist:
          portainer:
            allow:
              - docker_sock_mount
              - wide_exposed_port
          watchtower:
            allow:
              - docker_sock_mount

    Args:
        risks: List of detected risks
        cfg: Configuration dictionary (loads from file if None)

    Returns:
        Filtered list of risks (whitelisted risks removed)
    """
    if cfg is None:
        cfg = load_config() or {}

    whitelist_cfg = cfg.get("whitelist", {})

    if not whitelist_cfg:
        return risks

    filtered: list[Risk] = []

    for risk in risks:
        # Check if this container is in whitelist
        container_cfg = whitelist_cfg.get(risk.container)

        if not isinstance(container_cfg, dict):
            # No whitelist for this container
            filtered.append(risk)
            continue

        # Get allowed risk types for this container
        allowed = set(container_cfg.get("allow", []))

        # Skip if this risk type is allowed
        if risk.risk_type in allowed:
            continue

        filtered.append(risk)

    return filtered


def get_risk_severity(risk_type: str) -> str:
    """
    Get severity level for a risk type.

    Args:
        risk_type: Risk type identifier

    Returns:
        "CRITICAL", "HIGH", "MEDIUM", or "LOW"
    """
    critical_types = {
        "docker_sock_mount",
        "privileged_container",
        "critical_capability",
    }

    high_types = {
        "dangerous_host_mount",
        "host_network_mode",
        "host_pid_mode",
        "dangerous_capability",
    }

    medium_types = {
        "wide_exposed_port",
        "no_security_profiles",
        "no_resource_limits",
    }

    if risk_type in critical_types:
        return "CRITICAL"
    elif risk_type in high_types:
        return "HIGH"
    elif risk_type in medium_types:
        return "MEDIUM"
    else:
        return "LOW"


def get_remediation_advice(risk: Risk) -> str:
    """
    Get specific remediation advice for a risk.

    Provides actionable steps to fix or mitigate the identified risk.

    Args:
        risk: Risk object

    Returns:
        Remediation advice string
    """
    remediations = {
        "docker_sock_mount": (
            "Remove the docker.sock mount from the container. "
            "If Docker API access is required, use Docker API over TCP with TLS authentication."
        ),
        "privileged_container": (
            "Remove the --privileged flag. "
            "Grant only specific capabilities needed using --cap-add instead."
        ),
        "critical_capability": (
            f"Remove the {risk.details.get('capability', 'capability')} capability. "
            "Only grant minimal capabilities required for container function."
        ),
        "dangerous_capability": (
            f"Remove the {risk.details.get('capability', 'capability')} capability if not essential. "
            "Use more specific, limited permissions instead."
        ),
        "dangerous_host_mount": (
            f"Remove or restrict the mount of {risk.details.get('source', 'path')}. "
            "If absolutely needed, mount as read-only using :ro flag."
        ),
        "host_network_mode": (
            "Use bridge networking instead of host mode. "
            "Map only specific ports using -p flag."
        ),
        "host_pid_mode": (
            "Remove --pid=host flag unless absolutely necessary for monitoring tools."
        ),
        "wide_exposed_port": (
            f"Bind port to specific interface (e.g., 127.0.0.1:{risk.details.get('host_port', 'PORT')}) "
            "instead of 0.0.0.0. Use firewall rules to restrict external access."
        ),
        "no_security_profiles": (
            "Enable default security profiles (AppArmor/Seccomp) or create custom ones. "
            "Remove 'unconfined' security options."
        ),
        "no_resource_limits": (
            "Set CPU and memory limits using --memory and --cpus flags to prevent resource exhaustion."
        ),
        "running_as_root": (
            "Run container as non-root user. "
            "Add USER directive in Dockerfile or use --user flag at runtime."
        ),
        "unpinned_image": (
            f"Use specific image tag instead of :latest. "
            f"Example: {risk.details.get('image', 'image').replace(':latest', ':1.0.0').replace('latest', '1.0.0')}"
        ),
    }

    return remediations.get(
        risk.risk_type,
        "Review container security configuration and apply least privilege principles."
    )