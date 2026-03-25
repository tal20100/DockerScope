"""
Attack Graph Builder - Models real container escape paths.

Only three escape vectors are modeled, each corresponding to exact
commands an attacker would run:

1. docker.sock mount -> Docker API -> privileged container -> host root
2. privileged mode / SYS_ADMIN / host PID -> nsenter / mount -> host root
3. writable dangerous host mount -> write cron/binary/key -> host root
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Iterable

import networkx as nx
from rich.tree import Tree

from dockerscope.models.container import ContainerInfo
from dockerscope.models.risk import Risk


@dataclass
class AttackPath:
    """A complete attack path from a container to a critical target."""

    path_id: str
    nodes: list[str]
    description: str
    exploitability: float = 0.5
    impact: float = 0.5
    risk_score: float = 0.25
    techniques: list[str] = field(default_factory=list)
    remediation: str = ""


def build_attack_graph(containers: Iterable[ContainerInfo], risks: Iterable[Risk]) -> nx.DiGraph:
    """
    Build an attack graph containing only real escape paths.

    Nodes: host_root, docker_daemon, docker.sock, containers.
    Edges: only the three known escape vectors.
    """
    g = nx.DiGraph()

    # Attack targets
    g.add_node("host_root", node_type="host", label="Host System", risk_score=100)
    g.add_node("docker_daemon", node_type="daemon", label="Docker Daemon", risk_score=95)
    g.add_node("docker.sock", node_type="socket", label="Docker Socket", risk_score=90)

    # daemon -> host (daemon has full control)
    g.add_edge(
        "docker_daemon",
        "host_root",
        method="full_control",
        technique="Create Privileged Container",
        exploitability=1.0,
        impact=1.0,
        description="Docker daemon can create privileged containers with host root access",
    )

    # socket -> daemon (socket provides API access)
    g.add_edge(
        "docker.sock",
        "docker_daemon",
        method="daemon_api",
        technique="Docker API Access",
        exploitability=1.0,
        impact=0.95,
        description="Docker socket provides full API access to daemon",
    )

    # Add container nodes
    risks_list = list(risks)
    for c in containers:
        risk_score = _calculate_container_risk_score(c, risks_list)
        g.add_node(c.name, node_type="container", label=c.name, data=c, risk_score=risk_score)

    # Add edges based on detected risks
    for r in risks_list:
        _add_risk_edges(g, r)

    return g


def _calculate_container_risk_score(container: ContainerInfo, risks: Iterable[Risk]) -> int:
    """Calculate risk score for a container (10-100)."""
    score = 10

    if container.privileged:
        score += 50

    container_risks = [r for r in risks if r.container == container.name]
    for risk in container_risks:
        if risk.risk_type == "docker_sock_mount":
            score += 40
        elif risk.risk_type == "dangerous_host_mount":
            score += 30
        elif risk.risk_type == "host_pid_mode":
            score += 25

    for cap in container.capabilities:
        if not cap.startswith("CAP_ADD:"):
            continue
        cap_name = cap.removeprefix("CAP_ADD:")
        if cap_name == "SYS_ADMIN":
            score += 25
        elif cap_name == "SYS_PTRACE":
            score += 15

    return min(score, 100)


def _add_risk_edges(g: nx.DiGraph, risk: Risk) -> None:
    """Add graph edges for a detected risk. Only real escape vectors."""
    container_name = risk.container

    if risk.risk_type == "docker_sock_mount":
        # container -> socket -> daemon -> host
        g.add_edge(
            container_name,
            "docker.sock",
            method="mount_docker_sock",
            technique="Docker Socket Mount Access",
            exploitability=1.0,
            impact=0.9,
            description=f"Container {container_name} has docker.sock mounted",
        )

    elif risk.risk_type == "privileged_container":
        # Direct escape: privileged -> host
        g.add_edge(
            container_name,
            "host_root",
            method="privileged_escape",
            technique="Container Escape via Privileged Mode",
            exploitability=0.9,
            impact=1.0,
            description="Privileged container can escape to host via nsenter or device mount",
        )

    elif risk.risk_type == "cap_sys_admin":
        # Direct escape: SYS_ADMIN -> host
        g.add_edge(
            container_name,
            "host_root",
            method="cap_sys_admin_escape",
            technique="Container Escape via SYS_ADMIN",
            exploitability=0.8,
            impact=1.0,
            description="SYS_ADMIN allows mounting host filesystem",
        )

    elif risk.risk_type == "host_pid_mode":
        # Direct escape: host PID -> host
        g.add_edge(
            container_name,
            "host_root",
            method="host_pid_escape",
            technique="Container Escape via Host PID Namespace",
            exploitability=0.85,
            impact=1.0,
            description="Host PID namespace allows nsenter to host",
        )

    elif risk.risk_type == "dangerous_host_mount":
        # Direct escape: writable mount -> host
        source = risk.details.get("source", "")
        g.add_edge(
            container_name,
            "host_root",
            method="dangerous_mount_escape",
            technique=f"Host Compromise via Writable Mount ({source})",
            exploitability=0.8,
            impact=0.9,
            description=f"Writable mount to {source} enables host file modification",
        )

    # host_network_mode and cap_sys_ptrace are reported as findings
    # but do NOT create escape edges in the graph — they are lateral
    # capabilities, not paths to host root.


def explain_attack_paths(
    graph: nx.DiGraph, container_name: str, max_paths: int = 10
) -> list[AttackPath]:
    """
    Find and explain all attack paths from a container to host_root
    or docker_daemon.
    """
    if container_name not in graph:
        return []

    targets = ["host_root", "docker_daemon"]
    paths: list[AttackPath] = []

    for target in targets:
        if target not in graph:
            continue

        try:
            for path_nodes in nx.all_simple_paths(
                graph, source=container_name, target=target, cutoff=5
            ):
                attack_path = _create_attack_path(graph, path_nodes, target)
                paths.append(attack_path)

                if len(paths) >= max_paths:
                    break
        except nx.NetworkXNoPath:
            continue

    paths.sort(key=lambda p: p.risk_score, reverse=True)
    return paths[:max_paths]


def _create_attack_path(graph: nx.DiGraph, path_nodes: list[str], target: str) -> AttackPath:
    """Create an AttackPath with scoring metrics."""
    techniques = []
    exploitability_scores = []

    for i in range(len(path_nodes) - 1):
        source = path_nodes[i]
        dest = path_nodes[i + 1]

        if graph.has_edge(source, dest):
            edge_data = graph[source][dest]
            techniques.append(edge_data.get("technique", "Unknown"))
            exploitability_scores.append(edge_data.get("exploitability", 0.5))

    avg_exploitability = (
        sum(exploitability_scores) / len(exploitability_scores) if exploitability_scores else 0.5
    )

    target_data = graph.nodes[path_nodes[-1]]
    impact = target_data.get("risk_score", 50) / 100.0

    path_length_factor = max(0.5, 1.0 - (len(path_nodes) - 2) * 0.1)
    risk_score = avg_exploitability * impact * path_length_factor

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
        remediation=remediation,
    )


def _build_path_description(graph: nx.DiGraph, path_nodes: list[str], target: str) -> str:
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
        result += " (CRITICAL: Full host compromise)"
    elif target == "docker_daemon":
        result += " (CRITICAL: Docker daemon control)"

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
            recommendations.append("Remove docker.sock mount")
        elif method == "privileged_escape":
            recommendations.append("Remove privileged: true")
        elif method == "cap_sys_admin_escape":
            recommendations.append("Remove SYS_ADMIN from cap_add")
        elif method == "host_pid_escape":
            recommendations.append("Remove pid: host")
        elif method == "dangerous_mount_escape":
            recommendations.append("Remove dangerous mount or make read-only (:ro)")

    return (
        "; ".join(recommendations) if recommendations else "Review container security configuration"
    )


def build_attack_tree(paths: list[AttackPath], container_name: str) -> Tree:
    """Build a Rich Tree visualization of attack paths."""
    root = Tree(f"[bold cyan]{container_name}[/bold cyan] (Attack Paths)")

    if not paths:
        root.add("[green]No escape paths to host found[/green]")
        return root

    for idx, path in enumerate(paths, start=1):
        if path.risk_score > 0.7:
            color = "red"
            severity = "CRITICAL"
        elif path.risk_score > 0.5:
            color = "yellow"
            severity = "HIGH"
        else:
            color = "blue"
            severity = "MEDIUM"

        branch_text = (
            f"[{color}]{idx}. [{severity}][/{color}] "
            f"Risk: {path.risk_score:.2f} | "
            f"Hops: {len(path.nodes) - 1}"
        )
        branch = root.add(branch_text)

        for i, technique in enumerate(path.techniques, start=1):
            branch.add(f"Step {i}: {technique}")

        if path.remediation:
            branch.add(f"[dim]Fix: {path.remediation}[/dim]")

    return root


def export_graph_to_dict(graph: nx.DiGraph) -> Any:
    """Export attack graph to dictionary for JSON serialization."""
    from networkx.readwrite import json_graph

    return json_graph.node_link_data(graph)


def sanitize_graph_for_json(data: dict) -> dict:
    """Recursively convert non-serializable objects to dict or string."""
    if isinstance(data, dict):
        return {k: sanitize_graph_for_json(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [sanitize_graph_for_json(v) for v in data]
    elif hasattr(data, "__dict__"):
        return {k: sanitize_graph_for_json(v) for k, v in data.__dict__.items()}
    else:
        return data


def export_graph_to_dot(graph: nx.DiGraph) -> str:
    """Export attack graph to Graphviz DOT format."""
    lines = []
    lines.append("digraph AttackGraph {")
    lines.append("  rankdir=LR;")
    lines.append("  node [shape=box, style=filled];")
    lines.append("")

    colors = {"host": "red", "daemon": "orange", "container": "lightblue", "socket": "pink"}

    for node, data in graph.nodes(data=True):
        label = data.get("label", node)
        node_type = data.get("node_type", "unknown")
        color = colors.get(node_type, "white")
        label = label.replace('"', '\\"')
        lines.append(f'  "{node}" [label="{label}", fillcolor={color}];')

    lines.append("")

    for source, target, data in graph.edges(data=True):
        method = data.get("method", "")
        lines.append(f'  "{source}" -> "{target}" [label="{method}"];')

    lines.append("}")

    return "\n".join(lines)
