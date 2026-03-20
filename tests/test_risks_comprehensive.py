"""Comprehensive tests for risk evaluation and whitelist filtering."""
from __future__ import annotations

import pytest

from dockerscope.core.risks import (
    _is_dangerous_mount,
    evaluate_container_risks,
    filter_risks_with_whitelist,
)
from dockerscope.models.container import ContainerInfo
from dockerscope.models.risk import Risk


def _base_container(**overrides) -> ContainerInfo:
    data = dict(
        id="id",
        name="test",
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
# Risk evaluation
# ========================================================================

class TestPrivilegedContainer:
    def test_privileged_detected(self):
        c = _base_container(privileged=True)
        risks = evaluate_container_risks(c)
        assert any(r.risk_type == "privileged_container" for r in risks)

    def test_non_privileged_no_risk(self):
        c = _base_container(privileged=False)
        risks = evaluate_container_risks(c)
        assert not any(r.risk_type == "privileged_container" for r in risks)

    def test_privileged_has_attack_commands(self):
        c = _base_container(privileged=True)
        risks = evaluate_container_risks(c)
        priv = [r for r in risks if r.risk_type == "privileged_container"][0]
        assert len(priv.attack_commands) > 0
        assert "nsenter" in priv.attack_commands[0]

    def test_privileged_severity_is_critical(self):
        c = _base_container(privileged=True)
        risks = evaluate_container_risks(c)
        priv = [r for r in risks if r.risk_type == "privileged_container"][0]
        assert priv.severity == "CRITICAL"


class TestDockerSocketMount:
    def test_var_run_docker_sock(self):
        c = _base_container(mounts=[
            {"Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock"}
        ])
        risks = evaluate_container_risks(c)
        assert any(r.risk_type == "docker_sock_mount" for r in risks)

    def test_run_docker_sock(self):
        c = _base_container(mounts=[
            {"Source": "/run/docker.sock", "Destination": "/run/docker.sock"}
        ])
        risks = evaluate_container_risks(c)
        assert any(r.risk_type == "docker_sock_mount" for r in risks)

    def test_docker_sock_detected_by_destination(self):
        c = _base_container(mounts=[
            {"Source": "/some/path", "Destination": "/var/run/docker.sock"}
        ])
        risks = evaluate_container_risks(c)
        assert any(r.risk_type == "docker_sock_mount" for r in risks)

    def test_normal_mount_no_sock_risk(self):
        c = _base_container(mounts=[
            {"Source": "/data", "Destination": "/app/data"}
        ])
        risks = evaluate_container_risks(c)
        assert not any(r.risk_type == "docker_sock_mount" for r in risks)

    def test_docker_sock_has_attack_commands(self):
        c = _base_container(mounts=[
            {"Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock"}
        ])
        risks = evaluate_container_risks(c)
        sock = [r for r in risks if r.risk_type == "docker_sock_mount"][0]
        assert any("curl" in cmd for cmd in sock.attack_commands)


class TestDangerousMounts:
    @pytest.mark.parametrize("path", [
        "/etc", "/root", "/boot", "/var/lib/docker",
        "/usr/bin", "/proc", "/sys", "/dev",
    ])
    def test_writable_dangerous_paths_detected(self, path: str):
        c = _base_container(mounts=[
            {"Source": path, "Destination": "/mnt", "Mode": "rw"}
        ])
        risks = evaluate_container_risks(c)
        assert any(r.risk_type == "dangerous_host_mount" for r in risks)

    def test_root_mount_detected(self):
        c = _base_container(mounts=[
            {"Source": "/", "Destination": "/host"}
        ])
        risks = evaluate_container_risks(c)
        assert any(r.risk_type == "dangerous_host_mount" for r in risks)

    def test_subpath_of_dangerous_detected(self):
        c = _base_container(mounts=[
            {"Source": "/etc/ssh", "Destination": "/mnt/ssh"}
        ])
        risks = evaluate_container_risks(c)
        assert any(r.risk_type == "dangerous_host_mount" for r in risks)

    def test_safe_mount_no_risk(self):
        c = _base_container(mounts=[
            {"Source": "/home/user/data", "Destination": "/app/data"}
        ])
        risks = evaluate_container_risks(c)
        assert not any(r.risk_type == "dangerous_host_mount" for r in risks)

    def test_docker_sock_not_duplicated_as_dangerous_mount(self):
        """Docker socket should only appear as docker_sock_mount, not also as dangerous_host_mount."""
        c = _base_container(mounts=[
            {"Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock"}
        ])
        risks = evaluate_container_risks(c)
        types = [r.risk_type for r in risks]
        assert types.count("docker_sock_mount") == 1
        assert "dangerous_host_mount" not in types

    def test_read_only_mount_not_flagged(self):
        """Read-only mounts are not escape vectors."""
        c = _base_container(mounts=[
            {"Source": "/etc", "Destination": "/mnt/etc", "Mode": "ro"}
        ])
        risks = evaluate_container_risks(c)
        assert not any(r.risk_type == "dangerous_host_mount" for r in risks)

    def test_writable_mount_severity_is_critical(self):
        c = _base_container(mounts=[
            {"Source": "/etc", "Destination": "/mnt/etc", "Mode": "rw"}
        ])
        risks = evaluate_container_risks(c)
        mount_risks = [r for r in risks if r.risk_type == "dangerous_host_mount"]
        assert mount_risks[0].severity == "CRITICAL"


class TestHostNetworkMode:
    def test_host_mode_detected(self):
        c = _base_container(network_mode="host")
        risks = evaluate_container_risks(c)
        assert any(r.risk_type == "host_network_mode" for r in risks)

    def test_bridge_mode_no_risk(self):
        c = _base_container(network_mode="bridge")
        risks = evaluate_container_risks(c)
        assert not any(r.risk_type == "host_network_mode" for r in risks)

    def test_host_network_severity_is_high(self):
        c = _base_container(network_mode="host")
        risks = evaluate_container_risks(c)
        net = [r for r in risks if r.risk_type == "host_network_mode"][0]
        assert net.severity == "HIGH"


class TestHostPidMode:
    def test_host_pid_detected(self):
        c = _base_container(pid_mode="host")
        risks = evaluate_container_risks(c)
        assert any(r.risk_type == "host_pid_mode" for r in risks)

    def test_no_pid_mode_no_risk(self):
        c = _base_container()
        risks = evaluate_container_risks(c)
        assert not any(r.risk_type == "host_pid_mode" for r in risks)

    def test_host_pid_severity_is_critical(self):
        c = _base_container(pid_mode="host")
        risks = evaluate_container_risks(c)
        pid = [r for r in risks if r.risk_type == "host_pid_mode"][0]
        assert pid.severity == "CRITICAL"

    def test_host_pid_has_nsenter_command(self):
        c = _base_container(pid_mode="host")
        risks = evaluate_container_risks(c)
        pid = [r for r in risks if r.risk_type == "host_pid_mode"][0]
        assert any("nsenter" in cmd for cmd in pid.attack_commands)


class TestCapabilityDetection:
    def test_cap_add_sys_admin_detected(self):
        c = _base_container(capabilities=["CAP_ADD:SYS_ADMIN"])
        risks = evaluate_container_risks(c)
        assert any(r.risk_type == "cap_sys_admin" for r in risks)

    def test_cap_drop_sys_admin_not_flagged(self):
        c = _base_container(capabilities=["CAP_DROP:SYS_ADMIN"])
        risks = evaluate_container_risks(c)
        assert not any(r.risk_type == "cap_sys_admin" for r in risks)

    def test_cap_add_sys_ptrace_detected(self):
        c = _base_container(capabilities=["CAP_ADD:SYS_PTRACE"])
        risks = evaluate_container_risks(c)
        assert any(r.risk_type == "cap_sys_ptrace" for r in risks)

    def test_cap_drop_sys_ptrace_not_flagged(self):
        c = _base_container(capabilities=["CAP_DROP:SYS_PTRACE"])
        risks = evaluate_container_risks(c)
        assert not any(r.risk_type == "cap_sys_ptrace" for r in risks)

    def test_no_caps_returns_no_cap_risks(self):
        c = _base_container(capabilities=[])
        risks = evaluate_container_risks(c)
        assert not any(r.risk_type in ("cap_sys_admin", "cap_sys_ptrace") for r in risks)

    def test_sys_admin_severity_is_critical(self):
        c = _base_container(capabilities=["CAP_ADD:SYS_ADMIN"])
        risks = evaluate_container_risks(c)
        cap = [r for r in risks if r.risk_type == "cap_sys_admin"][0]
        assert cap.severity == "CRITICAL"

    def test_sys_ptrace_severity_is_high(self):
        c = _base_container(capabilities=["CAP_ADD:SYS_PTRACE"])
        risks = evaluate_container_risks(c)
        cap = [r for r in risks if r.risk_type == "cap_sys_ptrace"][0]
        assert cap.severity == "HIGH"


class TestRemovedRiskTypes:
    """Verify removed risk types no longer generate findings."""

    def test_wide_exposed_port_not_flagged(self):
        c = _base_container(ports={
            "80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "80"}]
        })
        risks = evaluate_container_risks(c)
        assert not any(r.risk_type == "wide_exposed_port" for r in risks)

    def test_running_as_root_not_flagged(self):
        c = _base_container(user="root")
        risks = evaluate_container_risks(c)
        assert not any(r.risk_type == "running_as_root" for r in risks)

    def test_unpinned_image_not_flagged(self):
        c = _base_container(image="nginx:latest")
        risks = evaluate_container_risks(c)
        assert not any(r.risk_type == "unpinned_image" for r in risks)

    def test_no_resource_limits_not_flagged(self):
        c = _base_container()
        risks = evaluate_container_risks(c)
        assert not any(r.risk_type == "no_resource_limits" for r in risks)

    def test_net_admin_not_flagged(self):
        c = _base_container(capabilities=["CAP_ADD:NET_ADMIN"])
        risks = evaluate_container_risks(c)
        assert not any(r.risk_type == "dangerous_capability" for r in risks)


class TestRootContextNote:
    """Root status should appear as context in attack explanations, not as standalone risk."""

    def test_root_context_in_privileged_risk(self):
        c = _base_container(privileged=True, user="root")
        risks = evaluate_container_risks(c)
        priv = [r for r in risks if r.risk_type == "privileged_container"][0]
        assert "runs as root" in priv.attack_explanation

    def test_no_root_context_for_non_root(self):
        c = _base_container(privileged=True, user="appuser")
        risks = evaluate_container_risks(c)
        priv = [r for r in risks if r.risk_type == "privileged_container"][0]
        assert "runs as root" not in priv.attack_explanation


class TestIsDangerousMount:
    def test_empty_source_is_safe(self):
        assert _is_dangerous_mount("", "/mnt") is False

    def test_root_is_dangerous(self):
        assert _is_dangerous_mount("/", "/host") is True

    def test_etc_subpath_is_dangerous(self):
        assert _is_dangerous_mount("/etc/ssh", "/mnt/ssh") is True

    def test_user_data_is_safe(self):
        assert _is_dangerous_mount("/home/user/data", "/app") is False


# ========================================================================
# Whitelist filtering
# ========================================================================

class TestWhitelistFiltering:
    def _make_risk(self, **overrides) -> Risk:
        data = dict(
            container="c",
            risk_type="privileged_container",
            severity="CRITICAL",
            description="test",
            attack_explanation="test",
            attack_commands=["test"],
            remediation="test",
            details={},
        )
        data.update(overrides)
        return Risk(**data)

    def test_empty_whitelist_returns_all(self):
        risks = [self._make_risk()]
        result = filter_risks_with_whitelist(risks, cfg={})
        assert len(result) == 1

    def test_no_config_returns_all(self):
        risks = [self._make_risk()]
        result = filter_risks_with_whitelist(risks, cfg=None)
        assert len(result) == 1

    def test_matching_risk_filtered(self):
        risks = [
            self._make_risk(container="portainer", risk_type="docker_sock_mount"),
            self._make_risk(container="portainer", risk_type="privileged_container"),
        ]
        cfg = {"whitelist": {"portainer": {"allow": ["docker_sock_mount"]}}}
        result = filter_risks_with_whitelist(risks, cfg=cfg)
        assert len(result) == 1
        assert result[0].risk_type == "privileged_container"

    def test_different_container_not_filtered(self):
        risks = [self._make_risk(container="nginx", risk_type="docker_sock_mount")]
        cfg = {"whitelist": {"portainer": {"allow": ["docker_sock_mount"]}}}
        result = filter_risks_with_whitelist(risks, cfg=cfg)
        assert len(result) == 1

    def test_invalid_container_config_not_filtered(self):
        risks = [self._make_risk()]
        cfg = {"whitelist": {"c": "invalid"}}
        result = filter_risks_with_whitelist(risks, cfg=cfg)
        assert len(result) == 1
