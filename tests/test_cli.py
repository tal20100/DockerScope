"""Tests for CLI commands using typer's CliRunner."""
from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest
from typer.testing import CliRunner

from dockerscope.cli import app
from dockerscope.models.container import ContainerInfo
from dockerscope.core.docker_client import DockerConnectionError


runner = CliRunner()


def _mock_container(
    name: str = "web",
    image: str = "nginx:1.25",
    privileged: bool = False,
    network_mode: str = "bridge",
    mounts: list | None = None,
    ports: dict | None = None,
    capabilities: list | None = None,
) -> ContainerInfo:
    return ContainerInfo(
        id=f"id-{name}",
        name=name,
        image=image,
        privileged=privileged,
        network_mode=network_mode,
        status="running",
        mounts=mounts or [],
        ports=ports or {},
        capabilities=capabilities or [],
    )


# ========================================================================
# topology
# ========================================================================

class TestTopology:
    @patch("dockerscope.cli.discover_containers")
    def test_topology_shows_containers(self, mock_discover):
        mock_discover.return_value = [_mock_container("web"), _mock_container("api")]
        result = runner.invoke(app, ["topology"])
        assert result.exit_code == 0
        assert "web" in result.output
        assert "api" in result.output

    @patch("dockerscope.cli.discover_containers")
    def test_topology_no_containers(self, mock_discover):
        mock_discover.return_value = []
        result = runner.invoke(app, ["topology"])
        assert result.exit_code == 0
        assert "No containers" in result.output

    @patch("dockerscope.cli.discover_containers")
    def test_topology_docker_error(self, mock_discover):
        mock_discover.side_effect = DockerConnectionError("daemon not running")
        result = runner.invoke(app, ["topology"])
        assert result.exit_code == 1
        assert "Docker Connection Error" in result.output


# ========================================================================
# analyze
# ========================================================================

class TestAnalyze:
    @patch("dockerscope.cli.discover_containers")
    def test_analyze_all(self, mock_discover):
        mock_discover.return_value = [
            _mock_container("web", ports={"80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "80"}]})
        ]
        result = runner.invoke(app, ["analyze"])
        assert result.exit_code == 0

    @patch("dockerscope.cli.find_container")
    @patch("dockerscope.cli.discover_containers")
    def test_analyze_specific_container(self, mock_discover, mock_find):
        c = _mock_container("web", privileged=True)
        mock_discover.return_value = [c]
        mock_find.return_value = c
        result = runner.invoke(app, ["analyze", "web"])
        assert result.exit_code == 0
        assert "web" in result.output

    @patch("dockerscope.cli.find_container")
    @patch("dockerscope.cli.discover_containers")
    def test_analyze_container_not_found(self, mock_discover, mock_find):
        mock_discover.return_value = [_mock_container("web")]
        mock_find.return_value = None
        result = runner.invoke(app, ["analyze", "nonexistent"])
        assert result.exit_code == 1
        assert "not found" in result.output

    @patch("dockerscope.cli.discover_containers")
    def test_analyze_no_containers(self, mock_discover):
        mock_discover.return_value = []
        result = runner.invoke(app, ["analyze"])
        assert result.exit_code == 0
        assert "No containers" in result.output


# ========================================================================
# simulate
# ========================================================================

class TestSimulate:
    @patch("dockerscope.cli.find_container")
    @patch("dockerscope.cli.discover_containers")
    def test_simulate_with_paths(self, mock_discover, mock_find):
        c = _mock_container("web", privileged=True)
        mock_discover.return_value = [c]
        mock_find.return_value = c
        result = runner.invoke(app, ["simulate", "web"])
        assert result.exit_code == 0

    @patch("dockerscope.cli.find_container")
    @patch("dockerscope.cli.discover_containers")
    def test_simulate_no_paths(self, mock_discover, mock_find):
        c = _mock_container("safe")
        mock_discover.return_value = [c]
        mock_find.return_value = c
        result = runner.invoke(app, ["simulate", "safe"])
        assert result.exit_code == 0
        assert "No direct escalation" in result.output

    @patch("dockerscope.cli.find_container")
    @patch("dockerscope.cli.discover_containers")
    def test_simulate_not_found(self, mock_discover, mock_find):
        mock_discover.return_value = [_mock_container("web")]
        mock_find.return_value = None
        result = runner.invoke(app, ["simulate", "nonexistent"])
        assert result.exit_code == 1


# ========================================================================
# export
# ========================================================================

class TestExport:
    @patch("dockerscope.cli.discover_containers")
    def test_export_json(self, mock_discover):
        mock_discover.return_value = [_mock_container("web")]
        result = runner.invoke(app, ["export", "--format", "json"])
        assert result.exit_code == 0

    @patch("dockerscope.cli.discover_containers")
    def test_export_dot(self, mock_discover):
        mock_discover.return_value = [_mock_container("web")]
        result = runner.invoke(app, ["export", "--format", "dot"])
        assert result.exit_code == 0
        assert "digraph" in result.output

    @patch("dockerscope.cli.discover_containers")
    def test_export_to_file(self, mock_discover, tmp_path):
        mock_discover.return_value = [_mock_container("web")]
        outfile = str(tmp_path / "graph.json")
        result = runner.invoke(app, ["export", "--format", "json", "--output", outfile])
        assert result.exit_code == 0
        assert "Successfully exported" in result.output

    @patch("dockerscope.cli.discover_containers")
    def test_export_invalid_format(self, mock_discover):
        mock_discover.return_value = [_mock_container("web")]
        result = runner.invoke(app, ["export", "--format", "xml"])
        assert result.exit_code == 1
        assert "Unsupported format" in result.output

    @patch("dockerscope.cli.discover_containers")
    def test_export_no_containers(self, mock_discover):
        mock_discover.return_value = []
        result = runner.invoke(app, ["export", "--format", "json"])
        assert result.exit_code == 0
        assert "No containers" in result.output


# ========================================================================
# score
# ========================================================================

class TestScore:
    @patch("dockerscope.cli.discover_containers")
    def test_score_clean_environment(self, mock_discover):
        mock_discover.return_value = [_mock_container("safe", image="alpine:3.19")]
        result = runner.invoke(app, ["score"])
        assert result.exit_code == 0

    @patch("dockerscope.cli.discover_containers")
    def test_score_no_containers(self, mock_discover):
        mock_discover.return_value = []
        result = runner.invoke(app, ["score"])
        assert result.exit_code == 0


# ========================================================================
# reachability
# ========================================================================

class TestReachability:
    def test_reachability_no_argument(self):
        result = runner.invoke(app, ["reachability"])
        assert result.exit_code == 1
        assert "Missing" in result.output

    @patch("dockerscope.cli.collect_host_network_info")
    @patch("dockerscope.cli.find_container")
    def test_reachability_with_container(self, mock_find, mock_collect):
        c = _mock_container("web", ports={"80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "80"}]})
        mock_find.return_value = c
        mock_collect.return_value = MagicMock(
            ip_route="default via 192.168.1.1 dev eth0",
            iptables_nat="",
        )
        result = runner.invoke(app, ["reachability", "web"])
        assert result.exit_code == 0


# ========================================================================
# scan-compose
# ========================================================================

class TestScanCompose:
    def test_scan_compose_placeholder(self):
        result = runner.invoke(app, ["scan-compose", "docker-compose.yml"])
        assert result.exit_code == 0
        assert "not yet implemented" in result.output
