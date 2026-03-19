"""Comprehensive tests for risk evaluation and whitelist filtering."""
from __future__ import annotations

import pytest

from dockerscope.models.container import ContainerInfo
from dockerscope.models.risk import Risk
from dockerscope.core.risks import (
    evaluate_container_risks,
    filter_risks_with_whitelist,
    get_risk_severity,
    get_remediation_advice,
    _has_critical_capability,
    _has_dangerous_capability,
    _is_dangerous_mount,
)


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


class TestDangerousMounts:
    @pytest.mark.parametrize("path", [
        "/etc", "/root", "/boot", "/var/lib/docker",
        "/usr/bin", "/proc", "/sys", "/dev",
    ])
    def test_dangerous_paths_detected(self, path: str):
        c = _base_container(mounts=[
            {"Source": path, "Destination": "/mnt"}
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


class TestHostNetworkMode:
    def test_host_mode_detected(self):
        c = _base_container(network_mode="host")
        risks = evaluate_container_risks(c)
        assert any(r.risk_type == "host_network_mode" for r in risks)

    def test_bridge_mode_no_risk(self):
        c = _base_container(network_mode="bridge")
        risks = evaluate_container_risks(c)
        assert not any(r.risk_type == "host_network_mode" for r in risks)


class TestWideExposedPorts:
    def test_all_interfaces_detected(self):
        c = _base_container(ports={
            "80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "80"}]
        })
        risks = evaluate_container_risks(c)
        assert any(r.risk_type == "wide_exposed_port" for r in risks)

    def test_empty_host_ip_detected(self):
        c = _base_container(ports={
            "80/tcp": [{"HostIp": "", "HostPort": "80"}]
        })
        risks = evaluate_container_risks(c)
        assert any(r.risk_type == "wide_exposed_port" for r in risks)

    def test_ipv6_wildcard_detected(self):
        c = _base_container(ports={
            "80/tcp": [{"HostIp": "::", "HostPort": "80"}]
        })
        risks = evaluate_container_risks(c)
        assert any(r.risk_type == "wide_exposed_port" for r in risks)

    def test_localhost_binding_no_risk(self):
        c = _base_container(ports={
            "80/tcp": [{"HostIp": "127.0.0.1", "HostPort": "80"}]
        })
        risks = evaluate_container_risks(c)
        assert not any(r.risk_type == "wide_exposed_port" for r in risks)

    def test_no_bindings_no_risk(self):
        c = _base_container(ports={"80/tcp": None})
        risks = evaluate_container_risks(c)
        assert not any(r.risk_type == "wide_exposed_port" for r in risks)

    def test_multiple_ports_multiple_risks(self):
        c = _base_container(ports={
            "80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "80"}],
            "443/tcp": [{"HostIp": "0.0.0.0", "HostPort": "443"}],
        })
        risks = evaluate_container_risks(c)
        wide_ports = [r for r in risks if r.risk_type == "wide_exposed_port"]
        assert len(wide_ports) == 2


class TestCapabilityDetection:
    def test_cap_add_sys_admin_is_critical(self):
        assert _has_critical_capability(["CAP_ADD:SYS_ADMIN"]) == "SYS_ADMIN"

    def test_cap_drop_sys_admin_not_flagged(self):
        """CAP_DROP is security-positive and should NOT be flagged."""
        assert _has_critical_capability(["CAP_DROP:SYS_ADMIN"]) is None

    def test_cap_add_net_admin_is_dangerous(self):
        assert _has_dangerous_capability(["CAP_ADD:NET_ADMIN"]) == "NET_ADMIN"

    def test_cap_drop_net_admin_not_flagged(self):
        assert _has_dangerous_capability(["CAP_DROP:NET_ADMIN"]) is None

    def test_mixed_caps_only_adds_flagged(self):
        caps = ["CAP_DROP:SYS_ADMIN", "CAP_ADD:SYS_PTRACE"]
        assert _has_critical_capability(caps) is None
        assert _has_dangerous_capability(caps) == "SYS_PTRACE"

    def test_no_caps_returns_none(self):
        assert _has_critical_capability([]) is None
        assert _has_dangerous_capability([]) is None

    def test_critical_cap_generates_risk(self):
        c = _base_container(capabilities=["CAP_ADD:SYS_ADMIN"])
        risks = evaluate_container_risks(c)
        assert any(r.risk_type == "critical_capability" for r in risks)

    def test_dangerous_cap_generates_risk(self):
        c = _base_container(capabilities=["CAP_ADD:NET_ADMIN"])
        risks = evaluate_container_risks(c)
        assert any(r.risk_type == "dangerous_capability" for r in risks)


class TestUnpinnedImage:
    def test_latest_tag_detected(self):
        c = _base_container(image="nginx:latest")
        risks = evaluate_container_risks(c)
        assert any(r.risk_type == "unpinned_image" for r in risks)

    def test_no_tag_detected(self):
        c = _base_container(image="nginx")
        risks = evaluate_container_risks(c)
        assert any(r.risk_type == "unpinned_image" for r in risks)

    def test_pinned_tag_no_risk(self):
        c = _base_container(image="nginx:1.25.3")
        risks = evaluate_container_risks(c)
        assert not any(r.risk_type == "unpinned_image" for r in risks)


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
    def test_empty_whitelist_returns_all(self):
        risks = [Risk(container="c", risk_type="privileged_container", description="", details={})]
        result = filter_risks_with_whitelist(risks, cfg={})
        assert len(result) == 1

    def test_no_config_returns_all(self):
        risks = [Risk(container="c", risk_type="privileged_container", description="", details={})]
        result = filter_risks_with_whitelist(risks, cfg=None)
        assert len(result) == 1

    def test_matching_risk_filtered(self):
        risks = [
            Risk(container="portainer", risk_type="docker_sock_mount", description="", details={}),
            Risk(container="portainer", risk_type="privileged_container", description="", details={}),
        ]
        cfg = {"whitelist": {"portainer": {"allow": ["docker_sock_mount"]}}}
        result = filter_risks_with_whitelist(risks, cfg=cfg)
        assert len(result) == 1
        assert result[0].risk_type == "privileged_container"

    def test_different_container_not_filtered(self):
        risks = [
            Risk(container="nginx", risk_type="docker_sock_mount", description="", details={}),
        ]
        cfg = {"whitelist": {"portainer": {"allow": ["docker_sock_mount"]}}}
        result = filter_risks_with_whitelist(risks, cfg=cfg)
        assert len(result) == 1

    def test_multiple_allowed_types(self):
        risks = [
            Risk(container="p", risk_type="docker_sock_mount", description="", details={}),
            Risk(container="p", risk_type="wide_exposed_port", description="", details={}),
            Risk(container="p", risk_type="privileged_container", description="", details={}),
        ]
        cfg = {"whitelist": {"p": {"allow": ["docker_sock_mount", "wide_exposed_port"]}}}
        result = filter_risks_with_whitelist(risks, cfg=cfg)
        assert len(result) == 1
        assert result[0].risk_type == "privileged_container"

    def test_invalid_container_config_not_filtered(self):
        """If container config is not a dict, skip filtering for that container."""
        risks = [Risk(container="c", risk_type="privileged_container", description="", details={})]
        cfg = {"whitelist": {"c": "invalid"}}
        result = filter_risks_with_whitelist(risks, cfg=cfg)
        assert len(result) == 1


# ========================================================================
# Risk severity
# ========================================================================

class TestRiskSeverity:
    def test_critical_types(self):
        assert get_risk_severity("docker_sock_mount") == "CRITICAL"
        assert get_risk_severity("privileged_container") == "CRITICAL"
        assert get_risk_severity("critical_capability") == "CRITICAL"

    def test_high_types(self):
        assert get_risk_severity("dangerous_host_mount") == "HIGH"
        assert get_risk_severity("host_network_mode") == "HIGH"

    def test_medium_types(self):
        assert get_risk_severity("wide_exposed_port") == "MEDIUM"

    def test_unknown_type_is_low(self):
        assert get_risk_severity("some_unknown_risk") == "LOW"


# ========================================================================
# Remediation advice
# ========================================================================

class TestRemediationAdvice:
    def test_known_risk_gets_specific_advice(self):
        risk = Risk(container="c", risk_type="privileged_container", description="", details={})
        advice = get_remediation_advice(risk)
        assert "--privileged" in advice

    def test_unknown_risk_gets_generic_advice(self):
        risk = Risk(container="c", risk_type="unknown_risk", description="", details={})
        advice = get_remediation_advice(risk)
        assert "least privilege" in advice
