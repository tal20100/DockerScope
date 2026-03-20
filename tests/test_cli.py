"""Tests for CLI commands using typer's CliRunner."""
from __future__ import annotations

from unittest.mock import patch

from typer.testing import CliRunner

from dockerscope.cli import app
from dockerscope.core.docker_client import DockerConnectionError
from dockerscope.models.container import ContainerInfo

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
    def test_topology_shows_all_containers(self, mock_discover):
        mock_discover.return_value = [
            _mock_container("web"),
            _mock_container("api", image="node:20"),
        ]
        result = runner.invoke(app, ["topology"])
        assert result.exit_code == 0
        assert "web" in result.output
        assert "api" in result.output
        assert "2" in result.output  # container count

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

    @patch("dockerscope.cli.discover_containers")
    def test_topology_shows_flags_privileged(self, mock_discover):
        mock_discover.return_value = [_mock_container("danger", privileged=True)]
        result = runner.invoke(app, ["topology"])
        assert "PRIV" in result.output

    @patch("dockerscope.cli.discover_containers")
    def test_topology_shows_flags_docker_sock(self, mock_discover):
        mock_discover.return_value = [
            _mock_container(
                "mgmt",
                mounts=[{"Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock"}],
            )
        ]
        result = runner.invoke(app, ["topology"])
        assert "SOCK" in result.output

    @patch("dockerscope.cli.discover_containers")
    def test_topology_shows_flags_host_network(self, mock_discover):
        mock_discover.return_value = [_mock_container("media", network_mode="host")]
        result = runner.invoke(app, ["topology"])
        assert "HOSTNET" in result.output

    @patch("dockerscope.cli.discover_containers")
    def test_topology_clean_container(self, mock_discover):
        mock_discover.return_value = [_mock_container("safe")]
        result = runner.invoke(app, ["topology"])
        assert "clean" in result.output

    @patch("dockerscope.cli.discover_containers")
    def test_topology_shows_ports(self, mock_discover):
        mock_discover.return_value = [
            _mock_container(
                "web",
                ports={"80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]},
            )
        ]
        result = runner.invoke(app, ["topology"])
        assert "8080" in result.output


# ========================================================================
# scan
# ========================================================================

class TestScan:
    @patch("dockerscope.cli.discover_containers")
    def test_scan_all_containers(self, mock_discover):
        mock_discover.return_value = [_mock_container("web"), _mock_container("api")]
        result = runner.invoke(app, ["scan"])
        assert result.exit_code == 0
        assert "web" in result.output
        assert "api" in result.output

    @patch("dockerscope.cli.find_container")
    @patch("dockerscope.cli.discover_containers")
    def test_scan_specific_container(self, mock_discover, mock_find):
        c = _mock_container("web", privileged=True)
        mock_discover.return_value = [c]
        mock_find.return_value = c
        result = runner.invoke(app, ["scan", "web"])
        assert result.exit_code == 0
        assert "web" in result.output

    @patch("dockerscope.cli.find_container")
    @patch("dockerscope.cli.discover_containers")
    def test_scan_container_not_found(self, mock_discover, mock_find):
        mock_discover.return_value = [_mock_container("web")]
        mock_find.return_value = None
        result = runner.invoke(app, ["scan", "nonexistent"])
        assert result.exit_code == 1
        assert "not found" in result.output

    @patch("dockerscope.cli.discover_containers")
    def test_scan_no_containers(self, mock_discover):
        mock_discover.return_value = []
        result = runner.invoke(app, ["scan"])
        assert result.exit_code == 0
        assert "No containers" in result.output

    @patch("dockerscope.cli.discover_containers")
    def test_scan_docker_error(self, mock_discover):
        mock_discover.side_effect = DockerConnectionError("daemon not running")
        result = runner.invoke(app, ["scan"])
        assert result.exit_code == 1
        assert "Docker Connection Error" in result.output

    @patch("dockerscope.cli.discover_containers")
    def test_scan_privileged_shows_attack_commands(self, mock_discover):
        mock_discover.return_value = [_mock_container("danger", privileged=True)]
        result = runner.invoke(app, ["scan"])
        assert "nsenter" in result.output

    @patch("dockerscope.cli.discover_containers")
    def test_scan_safe_container_shows_clean(self, mock_discover):
        mock_discover.return_value = [_mock_container("safe")]
        result = runner.invoke(app, ["scan"])
        assert "No risks" in result.output or "well-configured" in result.output


# ========================================================================
# scan --export
# ========================================================================

class TestScanExport:
    @patch("dockerscope.cli.discover_containers")
    def test_export_json(self, mock_discover):
        mock_discover.return_value = [_mock_container("web")]
        result = runner.invoke(app, ["scan", "--export", "json"])
        assert result.exit_code == 0

    @patch("dockerscope.cli.discover_containers")
    def test_export_dot(self, mock_discover):
        mock_discover.return_value = [_mock_container("web")]
        result = runner.invoke(app, ["scan", "--export", "dot"])
        assert result.exit_code == 0
        assert "digraph" in result.output

    @patch("dockerscope.cli.discover_containers")
    def test_export_to_file(self, mock_discover, tmp_path):
        mock_discover.return_value = [_mock_container("web")]
        outfile = str(tmp_path / "graph.json")
        result = runner.invoke(app, ["scan", "--export", "json", "--output", outfile])
        assert result.exit_code == 0
        assert "Exported" in result.output

    @patch("dockerscope.cli.discover_containers")
    def test_export_invalid_format(self, mock_discover):
        mock_discover.return_value = [_mock_container("web")]
        result = runner.invoke(app, ["scan", "--export", "xml"])
        assert result.exit_code == 1
        assert "Unsupported" in result.output


# ========================================================================
# scan-compose
# ========================================================================

class TestScanCompose:
    def test_scan_compose_file_not_found(self):
        result = runner.invoke(app, ["scan-compose", "/nonexistent/docker-compose.yml"])
        assert result.exit_code == 1
        assert "not found" in result.output.lower()

    def test_scan_compose_safe_file(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(
            "services:\n"
            "  web:\n"
            "    image: nginx:1.25\n"
        )
        result = runner.invoke(app, ["scan-compose", str(compose)])
        assert result.exit_code == 0
        assert "No dangerous" in result.output or "no issues" in result.output.lower()

    def test_scan_compose_critical_exits_1(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(
            "services:\n"
            "  danger:\n"
            "    image: alpine:3.19\n"
            "    privileged: true\n"
        )
        result = runner.invoke(app, ["scan-compose", str(compose)])
        assert result.exit_code == 1
        assert "Do not deploy" in result.output

    def test_scan_compose_shows_service_count(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(
            "services:\n"
            "  web:\n"
            "    image: nginx:1.25\n"
            "  api:\n"
            "    image: node:20\n"
        )
        result = runner.invoke(app, ["scan-compose", str(compose)])
        assert "2" in result.output
