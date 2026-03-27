"""Tests for the docker-compose scanner."""

from __future__ import annotations

import pytest

from dockerscope.core.compose_scanner import scan_compose_directory, scan_compose_file


class TestComposeScanner:
    def test_parses_privileged_service(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text("services:\n  danger:\n    image: alpine:3.19\n    privileged: true\n")
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
        compose.write_text("services:\n  safe:\n    image: alpine:3.19\n")
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
        compose.write_text("services:\n  app:\n    build: ./app\n    privileged: true\n")
        results = scan_compose_file(str(compose))
        assert len(results) == 1
        _, risks = results[0]
        assert any(r.risk_type == "privileged_container" for r in risks)

    def test_host_network_mode_detected(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text("services:\n  app:\n    image: alpine:3.19\n    network_mode: host\n")
        results = scan_compose_file(str(compose))
        _, risks = results[0]
        assert any(r.risk_type == "host_network_mode" for r in risks)

    def test_cap_add_sys_admin_parsed(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(
            "services:\n  app:\n    image: alpine:3.19\n    cap_add:\n      - SYS_ADMIN\n"
        )
        results = scan_compose_file(str(compose))
        _, risks = results[0]
        assert any(r.risk_type == "cap_sys_admin" for r in risks)

    def test_pid_host_detected(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text("services:\n  app:\n    image: alpine:3.19\n    pid: host\n")
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
            'services:\n  web:\n    image: nginx:1.25\n    ports:\n      - "8080:80"\n'
        )
        results = scan_compose_file(str(compose))
        _, risks = results[0]
        assert not any(r.risk_type == "wide_exposed_port" for r in risks)

    def test_writable_dangerous_mount_detected(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(
            "services:\n  app:\n    image: alpine:3.19\n    volumes:\n      - /etc:/mnt/etc\n"
        )
        results = scan_compose_file(str(compose))
        _, risks = results[0]
        assert any(r.risk_type == "dangerous_host_mount" for r in risks)


class TestComposeDirectoryScanner:
    def test_finds_compose_files_recursively(self, tmp_path):
        (tmp_path / "stackA").mkdir()
        (tmp_path / "stackB" / "nested").mkdir(parents=True)
        (tmp_path / "stackA" / "docker-compose.yml").write_text(
            "services:\n  web:\n    image: nginx:1.25\n"
        )
        (tmp_path / "stackB" / "nested" / "compose.yaml").write_text(
            "services:\n  api:\n    image: node:20\n"
        )
        results = scan_compose_directory(str(tmp_path))
        assert len(results) == 2
        all_services = [name for _, file_results in results for name, _ in file_results]
        assert "web" in all_services
        assert "api" in all_services

    def test_empty_directory_returns_empty(self, tmp_path):
        results = scan_compose_directory(str(tmp_path))
        assert results == []

    def test_invalid_yaml_is_skipped(self, tmp_path):
        (tmp_path / "docker-compose.yml").write_text("{{bad yaml: [")
        results = scan_compose_directory(str(tmp_path))
        assert len(results) == 1
        filepath, file_results = results[0]
        assert file_results == []

    def test_aggregates_risks_across_files(self, tmp_path):
        (tmp_path / "a").mkdir()
        (tmp_path / "b").mkdir()
        (tmp_path / "a" / "docker-compose.yml").write_text(
            "services:\n  danger:\n    image: alpine:3.19\n    privileged: true\n"
        )
        (tmp_path / "b" / "docker-compose.yaml").write_text(
            "services:\n  safe:\n    image: alpine:3.19\n"
        )
        results = scan_compose_directory(str(tmp_path))
        assert len(results) == 2
        all_risks = [r for _, file_results in results for _, risks in file_results for r in risks]
        assert any(r.risk_type == "privileged_container" for r in all_risks)

    def test_matches_variant_compose_names(self, tmp_path):
        """compose-1.yaml, docker-compose.prod.yml, etc. should all be found."""
        (tmp_path / "compose-1.yaml").write_text(
            "services:\n  a:\n    image: alpine:3.19\n"
        )
        (tmp_path / "docker-compose.prod.yml").write_text(
            "services:\n  b:\n    image: alpine:3.19\n"
        )
        results = scan_compose_directory(str(tmp_path))
        assert len(results) == 2

    def test_ignores_non_compose_yaml_files(self, tmp_path):
        (tmp_path / "config.yaml").write_text("key: value\n")
        (tmp_path / "docker-compose.yml").write_text(
            "services:\n  web:\n    image: nginx:1.25\n"
        )
        results = scan_compose_directory(str(tmp_path))
        assert len(results) == 1

    def test_not_a_directory_raises(self, tmp_path):
        f = tmp_path / "file.txt"
        f.write_text("hello")
        with pytest.raises(NotADirectoryError):
            scan_compose_directory(str(f))
