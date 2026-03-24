"""Tests for the docker-compose scanner."""

from __future__ import annotations

import pytest

from dockerscope.core.compose_scanner import scan_compose_file


class TestComposeScanner:
    def test_parses_privileged_service(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(
            "services:\n"
            "  danger:\n"
            "    image: alpine:3.19\n"
            "    privileged: true\n"
        )
        results = scan_compose_file(str(compose))
        assert len(results) == 1
        name, risks = results[0]
        assert name == "danger"
        assert any(r.risk_type == "privileged_container" for r in risks)

    def test_parses_sock_volume(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(
            "services:\n"
            "  portainer:\n"
            "    image: portainer/portainer:latest\n"
            "    volumes:\n"
            "      - /var/run/docker.sock:/var/run/docker.sock\n"
        )
        results = scan_compose_file(str(compose))
        _, risks = results[0]
        assert any(r.risk_type == "docker_sock_mount" for r in risks)

    def test_safe_service_returns_empty_risks(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(
            "services:\n"
            "  safe:\n"
            "    image: alpine:3.19\n"
        )
        results = scan_compose_file(str(compose))
        _, risks = results[0]
        assert len(risks) == 0

    def test_file_not_found_raises(self):
        with pytest.raises(FileNotFoundError):
            scan_compose_file("/nonexistent/docker-compose.yml")

    def test_invalid_yaml_raises_value_error(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text("{{bad yaml: [")
        with pytest.raises(ValueError, match="Invalid YAML"):
            scan_compose_file(str(compose))

    def test_multi_service_isolates_risks(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(
            "services:\n"
            "  danger:\n"
            "    image: alpine:3.19\n"
            "    privileged: true\n"
            "  safe:\n"
            "    image: alpine:3.19\n"
        )
        results = scan_compose_file(str(compose))
        assert len(results) == 2

        danger_risks = [r for name, risks in results for r in risks if name == "danger"]
        safe_risks = [r for name, risks in results for r in risks if name == "safe"]

        assert any(r.risk_type == "privileged_container" for r in danger_risks)
        assert not any(r.risk_type == "privileged_container" for r in safe_risks)

    def test_build_only_service_is_scanned(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(
            "services:\n"
            "  app:\n"
            "    build: ./app\n"
            "    privileged: true\n"
        )
        results = scan_compose_file(str(compose))
        assert len(results) == 1
        _, risks = results[0]
        assert any(r.risk_type == "privileged_container" for r in risks)

    def test_host_network_mode_detected(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(
            "services:\n"
            "  app:\n"
            "    image: alpine:3.19\n"
            "    network_mode: host\n"
        )
        results = scan_compose_file(str(compose))
        _, risks = results[0]
        assert any(r.risk_type == "host_network_mode" for r in risks)

    def test_cap_add_sys_admin_parsed(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(
            "services:\n"
            "  app:\n"
            "    image: alpine:3.19\n"
            "    cap_add:\n"
            "      - SYS_ADMIN\n"
        )
        results = scan_compose_file(str(compose))
        _, risks = results[0]
        assert any(r.risk_type == "cap_sys_admin" for r in risks)

    def test_pid_host_detected(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(
            "services:\n"
            "  app:\n"
            "    image: alpine:3.19\n"
            "    pid: host\n"
        )
        results = scan_compose_file(str(compose))
        _, risks = results[0]
        assert any(r.risk_type == "host_pid_mode" for r in risks)

    def test_long_volume_syntax(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(
            "services:\n"
            "  app:\n"
            "    image: alpine:3.19\n"
            "    volumes:\n"
            "      - type: bind\n"
            "        source: /var/run/docker.sock\n"
            "        target: /var/run/docker.sock\n"
        )
        results = scan_compose_file(str(compose))
        _, risks = results[0]
        assert any(r.risk_type == "docker_sock_mount" for r in risks)

    def test_ports_no_longer_flagged(self, tmp_path):
        """Ports are no longer flagged as risks — they are not attacks from inside the container."""
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(
            "services:\n"
            "  web:\n"
            "    image: nginx:1.25\n"
            "    ports:\n"
            '      - "8080:80"\n'
        )
        results = scan_compose_file(str(compose))
        _, risks = results[0]
        assert not any(r.risk_type == "wide_exposed_port" for r in risks)

    def test_writable_dangerous_mount_detected(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(
            "services:\n"
            "  app:\n"
            "    image: alpine:3.19\n"
            "    volumes:\n"
            "      - /etc:/mnt/etc\n"
        )
        results = scan_compose_file(str(compose))
        _, risks = results[0]
        assert any(r.risk_type == "dangerous_host_mount" for r in risks)
