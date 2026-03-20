"""Tests for configuration loading."""
from __future__ import annotations

from pathlib import Path

from dockerscope.config.load_config import load_config


class TestLoadConfig:
    def test_missing_file_returns_none(self):
        result = load_config("/nonexistent/path/config.yaml")
        assert result is None

    def test_valid_yaml(self, tmp_path: Path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text("whitelist:\n  portainer:\n    allow:\n      - docker_sock_mount\n")
        result = load_config(config_file)
        assert result is not None
        assert "whitelist" in result
        assert "portainer" in result["whitelist"]

    def test_empty_yaml_returns_empty_dict(self, tmp_path: Path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text("")
        result = load_config(config_file)
        assert result == {}

    def test_invalid_yaml_returns_none(self, tmp_path: Path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text("{{invalid yaml: [")
        result = load_config(config_file)
        assert result is None

    def test_non_dict_yaml_returns_none(self, tmp_path: Path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text("- just\n- a\n- list\n")
        result = load_config(config_file)
        assert result is None
