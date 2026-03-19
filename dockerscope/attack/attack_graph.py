"""
Attack Graph Builder - Models attack paths as a directed graph.

This module builds a comprehensive directed graph representing all possible
attack paths in a Docker environment. It extends the MVP implementation with:
- Volume node analysis
- Network connectivity modeling
- Risk scoring for nodes and edges
- Path scoring based on exploitability and impact
- Export functionality for visualization
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Iterable

import networkx as nx
from rich.tree import Tree

from dockerscope.models.container import ContainerInfo
from dockerscope.models.risk import Risk


@dataclass
class AttackPath:
    """
    Represents a complete attack path with scoring metrics.

    Attributes:
        path_id: Unique identifier for this path
        nodes: List of node IDs in the path
        description: Human-readable description of the attack path
        exploitability: How easy it is to exploit (0.0-1.0)
        impact: Severity if exploited (0.0-1.0)
        risk_score: Combined risk metric
        techniques: Attack techniques used at each hop
        remediation: Recommended fixes to block this path
    """
    path_id: str
    nodes: list[str]
    description: str
    exploitability: float = 0.5
    impact: float = 0.5
    risk_score: float = 0.25
    techniques: list[str] = field(default_factory=list)
    remediation: str = ""


def build_attack_graph(
        containers: Iterable[ContainerInfo],
        risks: Iterable[Risk]
) -> nx.DiGraph:
    """
    Build a complete attack graph from containers and detected risks.

    Construction process:
    1. Add base nodes (host, daemon, socket)
    2. Add container nodes with risk scores
    3. Add volume nodes for shared/sensitive paths
    4. Add network nodes for shared networks
    5. Add edges based on risks
    6. Add edges for network connectivity
    7. Add edges for shared volumes

    Args:
        containers: List of container information objects
        risks: List of detected security risks

    Returns:
        NetworkX DiGraph with all attack paths modeled
    """
    g = nx.DiGraph()

    # Add foundational nodes (attack targets)
    g.add_node(
        "host_root",
        node_type="host",
        label="Host System",
        risk_score=100
    )
    g.add_node(
        "docker_daemon",
        node_type="daemon",
        label="Docker Daemon",
        risk_score=95
    )
    g.add_node(
        "docker.sock",
        node_type="socket",
        label="Docker Socket",
        risk_score=90
    )

    # Edge: daemon -> host (daemon has full control)
    g.add_edge(
        "docker_daemon",
        "host_root",
        method="full_control",
        technique="Create Privileged Container",
        exploitability=1.0,
        impact=1.0,
        description="Docker daemon can create privileged containers with host root access"
    )

    # Edge: socket -> daemon (socket provides API access)
    g.add_edge(
        "docker.sock",
        "docker_daemon",
        method="daemon_api",
        technique="Docker API Access",
        exploitability=1.0,
        impact=0.95,
        description="Docker socket provides full API access to daemon"
    )

    # Add container nodes with risk scoring
    container_dict = {}
    for c in containers:
        risk_score = _calculate_container_risk_score(c, risks)
        g.add_node(
            c.name,
            node_type="container",
            label=c.name,
            data=c,
            risk_score=risk_score
        )
        container_dict[c.name] = c

    # Add volume nodes (shared volumes and sensitive mounts)
    volume_usage = _add_volume_nodes(g, containers)

    # Add network nodes (shared networks)
    network_usage = _add_network_nodes(g, containers)

    # Add edges based on detected risks
    for r in risks:
        _add_risk_edges(g, r, containers)

    # Add edges for network connectivity (lateral movement)
    _add_network_edges(g, containers, network_usage)

    # Add edges for shared volumes (data access)
    _add_volume_edges(g, containers, volume_usage)

    return g


def _calculate_container_risk_score(
        container: ContainerInfo,
        risks: Iterable[Risk]
) -> int:
    """
    Calculate risk score for a container based on its configuration.
    Higher permissions result in higher scores.

    Args:
        container: Container to score
        risks: All detected risks (to find container-specific ones)

    Returns:
        Risk score between 10 and 100
    """
    score = 10  # Base score for any container

    # Privileged mode is critical
    if container.privileged:
        score += 50

    # Check for container-specific risks
    container_risks = [r for r in risks if r.container == container.name]

    for risk in container_risks:
        if risk.risk_type == "docker_sock_mount":
            score += 40
        elif risk.risk_type == "dangerous_host_mount":
            score += 30
        elif risk.risk_type == "host_network_mode":
            score += 20
        elif risk.risk_type == "wide_exposed_port":
            score += 5

    # Check added capabilities only (CAP_DROP is security-positive)
    for cap in container.capabilities:
        if not cap.startswith("CAP_ADD:"):
            continue
        cap_name = cap.removeprefix("CAP_ADD:")
        if cap_name in ("SYS_ADMIN", "SYS_MODULE"):
            score += 25
        elif cap_name in ("NET_ADMIN", "SYS_PTRACE"):
            score += 15

    return min(score, 100)


def _add_volume_nodes(
        g: nx.DiGraph,
        containers: Iterable[ContainerInfo]
) -> dict[str, set[str]]:
    """
    Add volume nodes to the graph for shared or sensitive paths.

    Tracks which containers use which volumes to identify:
    - Shared volumes (potential lateral movement)
    - Sensitive host paths (potential privilege escalation)

    Args:
        g: Graph to modify
        containers: All containers

    Returns:
        Dictionary mapping volume_path -> set of container names
    """
    volume_usage: dict[str, set[str]] = {}

    for container in containers:
        for mount in container.mounts:
            source = mount.get("Source") or mount.get("src") or ""
            if not source or not source.startswith("/"):
                continue

            # Track containers using this volume
            if source not in volume_usage:
                volume_usage[source] = set()
            volume_usage[source].add(container.name)

            # Add volume node if shared or sensitive
            if source not in g.nodes() and (
                    len(volume_usage[source]) > 1 or
                    _is_sensitive_path(source)
            ):
                risk_score = _calculate_volume_risk_score(source)
                g.add_node(
                    f"volume:{source}",
                    node_type="volume",
                    label=source,
                    writable=True,  # Will be refined based on mount mode
                    risk_score=risk_score
                )

    return volume_usage


def _is_sensitive_path(path: str) -> bool:
    """Check if a path is considered sensitive for security."""
    sensitive_paths = {
        "/", "/etc", "/root", "/boot", "/usr/bin", "/usr/sbin",
        "/proc", "/sys", "/dev", "/var/log", "/var/lib/docker"
    }
    for sp in sensitive_paths:
        if sp == "/":
            if path == "/":
                return True
        elif path == sp or path.startswith(sp + "/"):
            return True
    return False


def _calculate_volume_risk_score(path: str) -> int:
    """
    Calculate risk score for a volume based on its path.
    More sensitive paths receive higher scores.

    Args:
        path: Volume path on host

    Returns:
        Risk score between 20 and 100
    """
    score = 20  # Base score

    # Critical system paths
    critical_paths = {"/", "/etc", "/root", "/boot", "/var/lib/docker"}
    high_paths = {"/usr/bin", "/usr/sbin", "/proc", "/sys", "/dev"}

    for cp in critical_paths:
        if cp == "/":
            if path == "/":
                score += 40
                break
        elif path == cp or path.startswith(cp + "/"):
            score += 40
            break

    for hp in high_paths:
        if path == hp or path.startswith(hp + "/"):
            score += 25
            break

    return min(score, 100)


def _add_network_nodes(
        g: nx.DiGraph,
        containers: Iterable[ContainerInfo]
) -> dict[str, set[str]]:
    """
    Add network nodes for shared networks.

    Identifies networks that connect multiple containers,
    enabling lateral movement analysis.

    Args:
        g: Graph to modify
        containers: All containers

    Returns:
        Dictionary mapping network_name -> set of container names
    """
    network_usage: dict[str, set[str]] = {}

    for container in containers:
        network_mode = container.network_mode or "bridge"

        # Host mode networks are shared with host
        if network_mode == "host":
            network_usage.setdefault("host_network", set()).add(container.name)
        else:
            network_usage.setdefault(network_mode, set()).add(container.name)

    # Add network nodes for shared networks
    for network_name, container_names in network_usage.items():
        if len(container_names) > 1:
            g.add_node(
                f"network:{network_name}",
                node_type="network",
                label=network_name,
                containers=list(container_names)
            )

    return network_usage


def _add_risk_edges(
        g: nx.DiGraph,
        risk: Risk,
        containers: Iterable[ContainerInfo]
) -> None:
    """
    Add edges to graph based on detected risk.
    Each risk type creates different attack path edges.

    Args:
        g: Graph to modify
        risk: Detected risk
        containers: All containers (for context)
    """
    container_name = risk.container

    if risk.risk_type == "docker_sock_mount":
        # Path: container -> socket -> daemon -> host
        g.add_edge(
            container_name,
            "docker.sock",
            method="mount_docker_sock",
            technique="Docker Socket Mount Access",
            exploitability=1.0,
            impact=0.9,
            description=f"Container {container_name} has docker.sock mounted"
        )

    elif risk.risk_type == "privileged_container":
        # Direct path: privileged container -> host
        g.add_edge(
            container_name,
            "host_root",
            method="privileged_escape",
            technique="Container Escape via Privileged Mode",
            exploitability=0.9,
            impact=1.0,
            description="Privileged container can access all devices and escape to host"
        )

    elif risk.risk_type == "dangerous_host_mount":
        # Path: container -> volume -> host
        source = risk.details.get("source", "")
        if source:
            volume_id = f"volume:{source}"

            # Ensure volume node exists
            if volume_id not in g.nodes():
                g.add_node(
                    volume_id,
                    node_type="volume",
                    label=source,
                    risk_score=_calculate_volume_risk_score(source)
                )

            # Edge: container -> volume
            g.add_edge(
                container_name,
                volume_id,
                method="volume_mount",
                technique="Dangerous Host Mount Access",
                exploitability=0.8,
                impact=0.7,
                description=f"Access to sensitive path {source}"
            )

            # Edge: volume -> host
            g.add_edge(
                volume_id,
                "host_root",
                method="filesystem_access",
                technique="Host Filesystem Modification",
                exploitability=0.7,
                impact=0.9,
                description=f"Can modify sensitive host files at {source}"
            )

    elif risk.risk_type == "host_network_mode":
        # Direct access to host network stack
        g.add_edge(
            container_name,
            "host_root",
            method="network_access",
            technique="Host Network Stack Access",
            exploitability=0.6,
            impact=0.6,
            description="Host network mode provides access to host network interfaces"
        )


def _add_network_edges(
        g: nx.DiGraph,
        containers: Iterable[ContainerInfo],
        network_usage: dict[str, set[str]]
) -> None:
    """
    Add edges between containers on shared networks.
    Enables lateral movement analysis.

    Args:
        g: Graph to modify
        containers: All containers
        network_usage: Map of network -> containers
    """
    for network_name, container_names in network_usage.items():
        if len(container_names) <= 1:
            continue

        # Every pair of containers on same network can communicate
        container_list = list(container_names)
        for i, container_a in enumerate(container_list):
            for container_b in container_list[i + 1:]:
                # Bidirectional edges (lateral movement both ways)
                g.add_edge(
                    container_a,
                    container_b,
                    method="network_lateral",
                    technique="Lateral Movement via Shared Network",
                    exploitability=0.5,
                    impact=0.3,
                    description=f"Containers share network {network_name}"
                )
                g.add_edge(
                    container_b,
                    container_a,
                    method="network_lateral",
                    technique="Lateral Movement via Shared Network",
                    exploitability=0.5,
                    impact=0.3,
                    description=f"Containers share network {network_name}"
                )


def _add_volume_edges(
        g: nx.DiGraph,
        containers: Iterable[ContainerInfo],
        volume_usage: dict[str, set[str]]
) -> None:
    """
    Add edges for shared volumes between containers.
    Shared volumes can enable data exfiltration or lateral movement.

    Args:
        g: Graph to modify
        containers: All containers
        volume_usage: Map of volume -> containers
    """
    for volume_path, container_names in volume_usage.items():
        if len(container_names) <= 1:
            continue

        volume_id = f"volume:{volume_path}"
        if volume_id not in g.nodes():
            continue

        # Add edge from each container to shared volume
        for container_name in container_names:
            if container_name in g.nodes():
                g.add_edge(
                    container_name,
                    volume_id,
                    method="shared_volume",
                    technique="Shared Volume Access",
                    exploitability=0.6,
                    impact=0.4,
                    description=f"Access to shared volume {volume_path}"
                )


def explain_attack_paths(
        graph: nx.DiGraph,
        container_name: str,
        max_paths: int = 10
) -> list[AttackPath]:
    """
    Find and explain all attack paths from a container.

    Searches for paths to critical targets (host_root, docker_daemon)
    and scores them based on exploitability and impact.

    Args:
        graph: Attack graph
        container_name: Starting container
        max_paths: Maximum paths to return

    Returns:
        List of AttackPath objects, sorted by risk score (highest first)
    """
    if container_name not in graph:
        return []

    targets = ["host_root", "docker_daemon"]
    paths: list[AttackPath] = []

    for target in targets:
        if target not in graph:
            continue

        try:
            # Find all simple paths (no cycles)
            for path_nodes in nx.all_simple_paths(
                    graph,
                    source=container_name,
                    target=target,
                    cutoff=5  # Limit path length
            ):
                attack_path = _create_attack_path(graph, path_nodes, target)
                paths.append(attack_path)

                if len(paths) >= max_paths:
                    break
        except nx.NetworkXNoPath:
            continue

    # Sort by risk score (highest first)
    paths.sort(key=lambda p: p.risk_score, reverse=True)
    return paths[:max_paths]


def _create_attack_path(
        graph: nx.DiGraph,
        path_nodes: list[str],
        target: str
) -> AttackPath:
    """
    Create an AttackPath object with complete scoring metrics.

    Calculates:
    - Exploitability (average of all edges)
    - Impact (based on target node)
    - Risk score (exploitability × impact × path_length_factor)

    Args:
        graph: Attack graph
        path_nodes: Node IDs in the path
        target: Target node

    Returns:
        Complete AttackPath object
    """
    # Collect techniques and exploitability from each edge
    techniques = []
    exploitability_scores = []

    for i in range(len(path_nodes) - 1):
        source = path_nodes[i]
        dest = path_nodes[i + 1]

        if graph.has_edge(source, dest):
            edge_data = graph[source][dest]
            technique = edge_data.get("technique", "Unknown")
            techniques.append(technique)
            exploitability_scores.append(edge_data.get("exploitability", 0.5))

    # Average exploitability across all hops
    avg_exploitability = (
        sum(exploitability_scores) / len(exploitability_scores)
        if exploitability_scores else 0.5
    )

    # Impact based on target node risk score
    target_data = graph.nodes[path_nodes[-1]]
    impact = target_data.get("risk_score", 50) / 100.0

    # Shorter paths are more dangerous (easier to exploit)
    path_length_factor = max(0.5, 1.0 - (len(path_nodes) - 2) * 0.1)
    risk_score = avg_exploitability * impact * path_length_factor

    # Build human-readable description
    description = _build_path_description(graph, path_nodes, target)
    remediation = _build_remediation(graph, path_nodes)

    return AttackPath(
        path_id=str(uuid.uuid4())[:8],
        nodes=path_nodes,
        description=description,
        exploitability=avg_exploitability,
        impact=impact,
        risk_score=risk_score,
        techniques=techniques,
        remediation=remediation
    )


def _build_path_description(
        graph: nx.DiGraph,
        path_nodes: list[str],
        target: str
) -> str:
    """Build human-readable description of attack path."""
    parts = []

    for i in range(len(path_nodes) - 1):
        source = path_nodes[i]
        dest = path_nodes[i + 1]

        if graph.has_edge(source, dest):
            method = graph[source][dest].get("method", "unknown")
            parts.append(f"{source} --[{method}]--> {dest}")

    result = " → ".join(parts)

    if target == "host_root":
        result += " (CRITICAL: Full host compromise / root access)"
    elif target == "docker_daemon":
        result += " (HIGH: Control Docker daemon, can create privileged containers)"

    return result


def _build_remediation(graph: nx.DiGraph, path_nodes: list[str]) -> str:
    """Build remediation recommendations for blocking this path."""
    recommendations = []

    for i in range(len(path_nodes) - 1):
        source = path_nodes[i]
        dest = path_nodes[i + 1]

        if not graph.has_edge(source, dest):
            continue

        method = graph[source][dest].get("method", "")

        if method == "mount_docker_sock":
            recommendations.append("Remove docker.sock mount from container")
        elif method == "privileged_escape":
            recommendations.append("Remove --privileged flag")
        elif method == "volume_mount":
            recommendations.append("Mount volumes as read-only (:ro) or remove dangerous mounts")
        elif method == "network_access":
            recommendations.append("Use bridge networking instead of host mode")

    return "; ".join(recommendations) if recommendations else "Review container security configuration"


def build_attack_tree(paths: list[AttackPath], container_name: str) -> Tree:
    """
    Build a Rich Tree visualization of attack paths.

    Creates an ASCII-style tree view suitable for terminal display,
    with color-coding based on risk severity.

    Args:
        paths: List of attack paths
        container_name: Source container

    Returns:
        Rich Tree object for console display
    """
    root = Tree(f"[bold cyan]{container_name}[/bold cyan] (Attack Paths)")

    if not paths:
        root.add("[green]✓ No attack paths to host_root or docker_daemon found[/green]")
        return root

    for idx, path in enumerate(paths, start=1):
        # Color code by risk score
        if path.risk_score > 0.7:
            color = "red"
            severity = "CRITICAL"
        elif path.risk_score > 0.5:
            color = "yellow"
            severity = "HIGH"
        else:
            color = "blue"
            severity = "MEDIUM"

        # Create branch for this path
        branch_text = (
            f"[{color}]{idx}. [{severity}][/{color}] "
            f"Risk: {path.risk_score:.2f} | "
            f"Hops: {len(path.nodes) - 1}"
        )
        branch = root.add(branch_text)

        # Add steps
        for i, technique in enumerate(path.techniques, start=1):
            branch.add(f"Step {i}: {technique}")

        # Add remediation
        if path.remediation:
            branch.add(f"[dim]Fix: {path.remediation}[/dim]")

    return root


def export_graph_to_dict(graph: nx.DiGraph) -> dict:
    """
    Export attack graph to dictionary for JSON serialization.

    Args:
        graph: Attack graph

    Returns:
        Dictionary suitable for JSON.dumps()
    """
    from networkx.readwrite import json_graph
    return json_graph.node_link_data(graph)


def sanitize_graph_for_json(data: dict) -> dict:
    """
    Recursively convert non-serializable objects to dict or string
    """
    if isinstance(data, dict):
        return {k: sanitize_graph_for_json(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [sanitize_graph_for_json(v) for v in data]
    elif hasattr(data, "__dict__"):
        return {k: sanitize_graph_for_json(v) for k, v in data.__dict__.items()}
    else:
        return data


def export_graph_to_dot(graph: nx.DiGraph) -> str:
    """
    Export attack graph to Graphviz DOT format.

    Can be rendered with: dot -Tpng graph.dot -o graph.png

    Args:
        graph: Attack graph

    Returns:
        DOT format string
    """
    lines = []
    lines.append("digraph AttackGraph {")
    lines.append('  rankdir=LR;')
    lines.append('  node [shape=box, style=filled];')
    lines.append('')

    # Node color mapping
    colors = {
        'host': 'red',
        'daemon': 'orange',
        'container': 'lightblue',
        'volume': 'lightyellow',
        'network': 'lightgreen',
        'socket': 'pink'
    }

    # Add nodes
    for node, data in graph.nodes(data=True):
        label = data.get('label', node)
        node_type = data.get('node_type', 'unknown')
        color = colors.get(node_type, 'white')

        # Escape quotes in labels
        label = label.replace('"', '\\"')

        lines.append(f'  "{node}" [label="{label}", fillcolor={color}];')

    lines.append('')

    # Add edges
    for source, target, data in graph.edges(data=True):
        method = data.get('method', '')
        lines.append(f'  "{source}" -> "{target}" [label="{method}"];')

    lines.append('}')

    return '\n'.join(lines)
