"""Tests for attack graph construction, path finding, and export."""

from __future__ import annotations

import json

from dockerscope.attack.attack_graph import (
    AttackPath,
    build_attack_graph,
    build_attack_tree,
    explain_attack_paths,
    export_graph_to_dict,
    export_graph_to_dot,
    sanitize_graph_for_json,
)
from dockerscope.core.risks import evaluate_container_risks
from dockerscope.models.container import ContainerInfo
from dockerscope.models.risk import Risk


def _container(name: str = "test", **overrides) -> ContainerInfo:
    data = dict(
        id=f"id-{name}",
        name=name,
        image="alpine:3.19",
        privileged=False,
        network_mode="bridge",
        status="running",
        mounts=[],
        ports={},
        capabilities=[],
    )
    data.update(overrides)
    return ContainerInfo(**data)


def _risk(container: str = "test", risk_type: str = "privileged_container", **overrides) -> Risk:
    data = dict(
        container=container,
        risk_type=risk_type,
        severity="CRITICAL",
        description="test",
        attack_explanation="test",
        attack_commands=["test"],
        remediation="test",
        details={},
    )
    data.update(overrides)
    return Risk(**data)


# ========================================================================
# Graph construction
# ========================================================================


class TestBuildAttackGraph:
    def test_base_nodes_always_present(self):
        g = build_attack_graph([], [])
        assert "host_root" in g.nodes
        assert "docker_daemon" in g.nodes
        assert "docker.sock" in g.nodes

    def test_no_host_network_ns_node(self):
        """host_network_ns was removed — it is not an escape target."""
        g = build_attack_graph([], [])
        assert "host_network_ns" not in g.nodes

    def test_daemon_to_host_edge(self):
        g = build_attack_graph([], [])
        assert g.has_edge("docker_daemon", "host_root")

    def test_socket_to_daemon_edge(self):
        g = build_attack_graph([], [])
        assert g.has_edge("docker.sock", "docker_daemon")

    def test_container_added_as_node(self):
        c = _container("web")
        g = build_attack_graph([c], [])
        assert "web" in g.nodes
        assert g.nodes["web"]["node_type"] == "container"

    def test_docker_sock_risk_creates_edge_to_socket(self):
        c = _container("web")
        risk = _risk("web", "docker_sock_mount")
        g = build_attack_graph([c], [risk])
        assert g.has_edge("web", "docker.sock")

    def test_privileged_risk_creates_edge_to_host(self):
        c = _container("web", privileged=True)
        risk = _risk("web", "privileged_container")
        g = build_attack_graph([c], [risk])
        assert g.has_edge("web", "host_root")

    def test_dangerous_mount_creates_direct_edge_to_host(self):
        """Writable mounts now create a direct edge to host_root (no volume intermediary)."""
        c = _container("web")
        risk = _risk("web", "dangerous_host_mount", details={"source": "/etc"})
        g = build_attack_graph([c], [risk])
        assert g.has_edge("web", "host_root")

    def test_host_network_does_not_create_escape_edge(self):
        """host_network_mode is lateral capability, not an escape vector."""
        c = _container("web", network_mode="host")
        risk = _risk("web", "host_network_mode", severity="HIGH")
        g = build_attack_graph([c], [risk])
        assert not g.has_edge("web", "host_root")

    def test_host_pid_creates_edge_to_host(self):
        c = _container("web", pid_mode="host")
        risk = _risk("web", "host_pid_mode")
        g = build_attack_graph([c], [risk])
        assert g.has_edge("web", "host_root")

    def test_cap_sys_admin_creates_edge_to_host(self):
        c = _container("web", capabilities=["CAP_ADD:SYS_ADMIN"])
        risk = _risk("web", "cap_sys_admin")
        g = build_attack_graph([c], [risk])
        assert g.has_edge("web", "host_root")

    def test_no_network_lateral_edges(self):
        """Network lateral edges were removed — normal Docker networking is not an attack."""
        c1 = _container("web", network_mode="bridge")
        c2 = _container("api", network_mode="bridge")
        g = build_attack_graph([c1, c2], [])
        assert not g.has_edge("web", "api")
        assert not g.has_edge("api", "web")

    def test_no_shared_volume_edges(self):
        """Shared volume edges were removed — data access is not container escape."""
        c1 = _container("web", mounts=[{"Source": "/data", "Destination": "/app"}])
        c2 = _container("api", mounts=[{"Source": "/data", "Destination": "/app"}])
        g = build_attack_graph([c1, c2], [])
        assert "volume:/data" not in g.nodes


# ========================================================================
# Attack path finding
# ========================================================================


class TestExplainAttackPaths:
    def test_docker_sock_path_to_host(self):
        c = _container("web")
        risk = _risk("web", "docker_sock_mount")
        g = build_attack_graph([c], [risk])
        paths = explain_attack_paths(g, "web")
        assert any("host_root" in p.nodes for p in paths)

    def test_privileged_direct_path(self):
        c = _container("web", privileged=True)
        risk = _risk("web", "privileged_container")
        g = build_attack_graph([c], [risk])
        paths = explain_attack_paths(g, "web")
        assert any(p.nodes == ["web", "host_root"] for p in paths)

    def test_no_paths_for_safe_container(self):
        c = _container("safe")
        g = build_attack_graph([c], [])
        paths = explain_attack_paths(g, "safe")
        assert len(paths) == 0

    def test_unknown_container_returns_empty(self):
        g = build_attack_graph([], [])
        paths = explain_attack_paths(g, "nonexistent")
        assert paths == []

    def test_paths_sorted_by_risk_score(self):
        c = _container("web", privileged=True)
        risks = [
            _risk("web", "privileged_container"),
            _risk("web", "docker_sock_mount"),
        ]
        g = build_attack_graph([c], risks)
        paths = explain_attack_paths(g, "web")
        if len(paths) >= 2:
            assert paths[0].risk_score >= paths[1].risk_score

    def test_max_paths_respected(self):
        c = _container("web", privileged=True)
        risks = [
            _risk("web", "privileged_container"),
            _risk("web", "docker_sock_mount"),
        ]
        g = build_attack_graph([c], risks)
        paths = explain_attack_paths(g, "web", max_paths=1)
        assert len(paths) <= 1

    def test_attack_path_has_techniques(self):
        c = _container("web")
        risk = _risk("web", "docker_sock_mount")
        g = build_attack_graph([c], [risk])
        paths = explain_attack_paths(g, "web")
        assert len(paths) > 0
        assert len(paths[0].techniques) > 0

    def test_attack_path_has_remediation(self):
        c = _container("web")
        risk = _risk("web", "docker_sock_mount")
        g = build_attack_graph([c], [risk])
        paths = explain_attack_paths(g, "web")
        assert len(paths) > 0
        assert paths[0].remediation != ""

    def test_host_network_no_escape_path(self):
        """host_network_mode alone should NOT create any escape path."""
        c = _container("web", network_mode="host")
        risk = _risk("web", "host_network_mode", severity="HIGH")
        g = build_attack_graph([c], [risk])
        paths = explain_attack_paths(g, "web")
        assert len(paths) == 0

    def test_container_with_no_own_risk_no_path(self):
        """A safe container should not reach host_root even if other containers have risks."""
        safe = _container("safe")
        danger = _container("danger", privileged=True)
        risk = _risk("danger", "privileged_container")
        g = build_attack_graph([safe, danger], [risk])
        paths = explain_attack_paths(g, "safe")
        assert len(paths) == 0


# ========================================================================
# Attack tree visualization
# ========================================================================


class TestBuildAttackTree:
    def test_empty_paths(self):
        tree = build_attack_tree([], "web")
        assert "web" in str(tree.label)

    def test_with_paths(self):
        path = AttackPath(
            path_id="abc",
            nodes=["web", "host_root"],
            description="test path",
            risk_score=0.9,
            techniques=["Container Escape"],
            remediation="Fix it",
        )
        tree = build_attack_tree([path], "web")
        assert "web" in str(tree.label)


# ========================================================================
# Export
# ========================================================================


class TestExportJson:
    def test_export_to_dict(self):
        c = _container("web")
        risk = _risk("web", "docker_sock_mount")
        g = build_attack_graph([c], [risk])
        data = export_graph_to_dict(g)
        assert "nodes" in data or "links" in data

    def test_sanitize_makes_json_serializable(self):
        c = _container("web")
        risk = _risk("web", "docker_sock_mount")
        g = build_attack_graph([c], [risk])
        data = export_graph_to_dict(g)
        sanitized = sanitize_graph_for_json(data)
        json.dumps(sanitized)  # Should not raise

    def test_sanitize_handles_nested_objects(self):
        data = {"key": {"nested": [1, 2, {"deep": True}]}}
        result = sanitize_graph_for_json(data)
        assert result == data


class TestExportDot:
    def test_export_to_dot(self):
        c = _container("web")
        risk = _risk("web", "docker_sock_mount")
        g = build_attack_graph([c], [risk])
        dot = export_graph_to_dot(g)
        assert "digraph AttackGraph" in dot
        assert '"web"' in dot
        assert '"host_root"' in dot

    def test_dot_has_edges(self):
        c = _container("web")
        risk = _risk("web", "docker_sock_mount")
        g = build_attack_graph([c], [risk])
        dot = export_graph_to_dot(g)
        assert "->" in dot

    def test_dot_color_coding(self):
        g = build_attack_graph([], [])
        dot = export_graph_to_dot(g)
        assert "fillcolor=red" in dot  # host_root
        assert "fillcolor=orange" in dot  # docker_daemon


# ========================================================================
# Integration with real risk evaluation
# ========================================================================


class TestIntegration:
    def test_privileged_container_has_path_to_host(self):
        c = _container("priv", privileged=True)
        risks = evaluate_container_risks(c)
        g = build_attack_graph([c], risks)
        paths = explain_attack_paths(g, "priv")
        assert any("host_root" in p.nodes for p in paths)

    def test_sock_mount_has_path_to_daemon(self):
        c = _container(
            "sock",
            mounts=[{"Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock"}],
        )
        risks = evaluate_container_risks(c)
        g = build_attack_graph([c], risks)
        paths = explain_attack_paths(g, "sock")
        assert any("docker_daemon" in p.nodes for p in paths)

    def test_safe_container_no_path_to_host(self):
        c = _container("safe")
        risks = evaluate_container_risks(c)
        g = build_attack_graph([c], risks)
        paths = explain_attack_paths(g, "safe")
        assert len(paths) == 0

    def test_risk_score_bounded_0_to_100(self):
        c = _container("all", privileged=True, capabilities=["CAP_ADD:SYS_ADMIN"])
        risks = evaluate_container_risks(c)
        g = build_attack_graph([c], risks)
        score = g.nodes["all"].get("risk_score", 0)
        assert 0 <= score <= 100
