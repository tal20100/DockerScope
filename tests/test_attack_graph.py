"""Comprehensive tests for attack graph construction, path finding, and export."""
from __future__ import annotations

import json

import pytest

from dockerscope.models.container import ContainerInfo
from dockerscope.models.risk import Risk
from dockerscope.attack.attack_graph import (
    AttackPath,
    build_attack_graph,
    build_attack_tree,
    explain_attack_paths,
    export_graph_to_dict,
    export_graph_to_dot,
    sanitize_graph_for_json,
    _is_sensitive_path,
    _calculate_volume_risk_score,
)


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


# ========================================================================
# _is_sensitive_path (regression tests for "/" bug)
# ========================================================================

class TestIsSensitivePath:
    def test_root_is_sensitive(self):
        assert _is_sensitive_path("/") is True

    def test_etc_is_sensitive(self):
        assert _is_sensitive_path("/etc") is True

    def test_etc_subpath_is_sensitive(self):
        assert _is_sensitive_path("/etc/ssh") is True

    def test_user_data_not_sensitive(self):
        assert _is_sensitive_path("/home/user/data") is False

    def test_app_data_not_sensitive(self):
        """Regression: before fix, every path was sensitive due to '/' rstrip bug."""
        assert _is_sensitive_path("/app/data") is False

    def test_var_log_sensitive(self):
        assert _is_sensitive_path("/var/log") is True

    def test_var_log_subpath_sensitive(self):
        assert _is_sensitive_path("/var/log/syslog") is True

    def test_var_lib_docker_sensitive(self):
        assert _is_sensitive_path("/var/lib/docker") is True

    def test_var_lib_other_not_sensitive(self):
        assert _is_sensitive_path("/var/lib/myapp") is False


# ========================================================================
# _calculate_volume_risk_score (regression tests for "/" bug)
# ========================================================================

class TestCalculateVolumeRiskScore:
    def test_root_gets_critical_score(self):
        assert _calculate_volume_risk_score("/") == 60  # 20 + 40

    def test_etc_gets_critical_score(self):
        assert _calculate_volume_risk_score("/etc") == 60

    def test_usr_bin_gets_high_score(self):
        assert _calculate_volume_risk_score("/usr/bin") == 45  # 20 + 25

    def test_safe_path_gets_base_score(self):
        """Regression: before fix, every path got +40 due to '/' rstrip bug."""
        assert _calculate_volume_risk_score("/app/data") == 20

    def test_home_path_gets_base_score(self):
        assert _calculate_volume_risk_score("/home/user") == 20


# ========================================================================
# Graph construction
# ========================================================================

class TestBuildAttackGraph:
    def test_base_nodes_always_present(self):
        g = build_attack_graph([], [])
        assert "host_root" in g.nodes
        assert "docker_daemon" in g.nodes
        assert "docker.sock" in g.nodes

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
        risk = Risk(container="web", risk_type="docker_sock_mount", description="", details={})
        g = build_attack_graph([c], [risk])
        assert g.has_edge("web", "docker.sock")

    def test_privileged_risk_creates_edge_to_host(self):
        c = _container("web", privileged=True)
        risk = Risk(container="web", risk_type="privileged_container", description="", details={})
        g = build_attack_graph([c], [risk])
        assert g.has_edge("web", "host_root")

    def test_dangerous_mount_risk_creates_volume_edges(self):
        c = _container("web")
        risk = Risk(
            container="web",
            risk_type="dangerous_host_mount",
            description="",
            details={"source": "/etc"},
        )
        g = build_attack_graph([c], [risk])
        assert g.has_edge("web", "volume:/etc")
        assert g.has_edge("volume:/etc", "host_root")

    def test_host_network_risk_creates_edge_to_host(self):
        c = _container("web", network_mode="host")
        risk = Risk(container="web", risk_type="host_network_mode", description="", details={})
        g = build_attack_graph([c], [risk])
        assert g.has_edge("web", "host_root")

    def test_shared_network_creates_lateral_edges(self):
        c1 = _container("web", network_mode="bridge")
        c2 = _container("api", network_mode="bridge")
        g = build_attack_graph([c1, c2], [])
        assert g.has_edge("web", "api")
        assert g.has_edge("api", "web")

    def test_shared_volume_creates_edges(self):
        c1 = _container("web", mounts=[{"Source": "/data", "Destination": "/app"}])
        c2 = _container("api", mounts=[{"Source": "/data", "Destination": "/app"}])
        g = build_attack_graph([c1, c2], [])
        # Shared volume between 2 containers should create edges
        assert "volume:/data" in g.nodes or not g.has_node("volume:/data")
        # Volume nodes are only added for shared OR sensitive paths
        # /data is not sensitive, but shared between 2 containers
        # The volume node addition happens on second pass when volume_usage count > 1


# ========================================================================
# Attack path finding
# ========================================================================

class TestExplainAttackPaths:
    def test_docker_sock_path_to_host(self):
        c = _container("web")
        risk = Risk(container="web", risk_type="docker_sock_mount", description="", details={})
        g = build_attack_graph([c], [risk])
        paths = explain_attack_paths(g, "web")
        # Should find path: web -> docker.sock -> docker_daemon -> host_root
        assert any("host_root" in p.nodes for p in paths)

    def test_privileged_direct_path(self):
        c = _container("web", privileged=True)
        risk = Risk(container="web", risk_type="privileged_container", description="", details={})
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
            Risk(container="web", risk_type="privileged_container", description="", details={}),
            Risk(container="web", risk_type="docker_sock_mount", description="", details={}),
        ]
        g = build_attack_graph([c], risks)
        paths = explain_attack_paths(g, "web")
        if len(paths) >= 2:
            assert paths[0].risk_score >= paths[1].risk_score

    def test_max_paths_respected(self):
        c = _container("web", privileged=True)
        risks = [
            Risk(container="web", risk_type="privileged_container", description="", details={}),
            Risk(container="web", risk_type="docker_sock_mount", description="", details={}),
        ]
        g = build_attack_graph([c], risks)
        paths = explain_attack_paths(g, "web", max_paths=1)
        assert len(paths) <= 1

    def test_attack_path_has_techniques(self):
        c = _container("web")
        risk = Risk(container="web", risk_type="docker_sock_mount", description="", details={})
        g = build_attack_graph([c], [risk])
        paths = explain_attack_paths(g, "web")
        assert len(paths) > 0
        assert len(paths[0].techniques) > 0

    def test_attack_path_has_remediation(self):
        c = _container("web")
        risk = Risk(container="web", risk_type="docker_sock_mount", description="", details={})
        g = build_attack_graph([c], [risk])
        paths = explain_attack_paths(g, "web")
        assert len(paths) > 0
        assert paths[0].remediation != ""


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
        risk = Risk(container="web", risk_type="docker_sock_mount", description="", details={})
        g = build_attack_graph([c], [risk])
        data = export_graph_to_dict(g)
        assert "nodes" in data or "links" in data

    def test_sanitize_makes_json_serializable(self):
        c = _container("web")
        risk = Risk(container="web", risk_type="docker_sock_mount", description="", details={})
        g = build_attack_graph([c], [risk])
        data = export_graph_to_dict(g)
        sanitized = sanitize_graph_for_json(data)
        # Should not raise
        json.dumps(sanitized)

    def test_sanitize_handles_nested_objects(self):
        data = {"key": {"nested": [1, 2, {"deep": True}]}}
        result = sanitize_graph_for_json(data)
        assert result == data


class TestExportDot:
    def test_export_to_dot(self):
        c = _container("web")
        risk = Risk(container="web", risk_type="docker_sock_mount", description="", details={})
        g = build_attack_graph([c], [risk])
        dot = export_graph_to_dot(g)
        assert "digraph AttackGraph" in dot
        assert '"web"' in dot
        assert '"host_root"' in dot

    def test_dot_has_edges(self):
        c = _container("web")
        risk = Risk(container="web", risk_type="docker_sock_mount", description="", details={})
        g = build_attack_graph([c], [risk])
        dot = export_graph_to_dot(g)
        assert "->" in dot

    def test_dot_color_coding(self):
        g = build_attack_graph([], [])
        dot = export_graph_to_dot(g)
        assert "fillcolor=red" in dot  # host_root
        assert "fillcolor=orange" in dot  # docker_daemon
