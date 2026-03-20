"""Tests for risk detection — required test cases per specification."""

from __future__ import annotations

from dockerscope.core.risks import evaluate_container_risks, filter_risks_with_whitelist
from dockerscope.models.container import ContainerInfo


def _base_container(**overrides):
    data = dict(
        id="id",
        name="c",
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


def test_privileged_container_is_critical():
    c = _base_container(privileged=True)
    risks = evaluate_container_risks(c)
    priv = [r for r in risks if r.risk_type == "privileged_container"]
    assert len(priv) == 1
    assert priv[0].severity == "CRITICAL"


def test_docker_sock_mount_is_critical():
    for sock_path in ("/var/run/docker.sock", "/run/docker.sock"):
        c = _base_container(mounts=[{"Source": sock_path, "Destination": "/var/run/docker.sock"}])
        risks = evaluate_container_risks(c)
        sock_risks = [r for r in risks if r.risk_type == "docker_sock_mount"]
        assert len(sock_risks) == 1, f"Failed for {sock_path}"
        assert sock_risks[0].severity == "CRITICAL"


def test_host_network_mode_is_high():
    c = _base_container(network_mode="host")
    risks = evaluate_container_risks(c)
    net = [r for r in risks if r.risk_type == "host_network_mode"]
    assert len(net) == 1
    assert net[0].severity == "HIGH"


def test_dangerous_mount_subpath():
    c = _base_container(mounts=[{"Source": "/etc/ssh", "Destination": "/mnt/ssh"}])
    risks = evaluate_container_risks(c)
    assert any(r.risk_type == "dangerous_host_mount" for r in risks)


def test_cap_sys_admin():
    c = _base_container(capabilities=["CAP_ADD:SYS_ADMIN"])
    risks = evaluate_container_risks(c)
    assert any(r.risk_type == "cap_sys_admin" for r in risks)


def test_cap_sys_ptrace():
    c = _base_container(capabilities=["CAP_ADD:SYS_PTRACE"])
    risks = evaluate_container_risks(c)
    assert any(r.risk_type == "cap_sys_ptrace" for r in risks)


def test_safe_container_has_no_risks():
    c = _base_container()
    risks = evaluate_container_risks(c)
    assert len(risks) == 0


def test_whitelist_suppresses_risk():
    c = _base_container(name="portainer", privileged=True)
    risks = evaluate_container_risks(c)
    assert any(r.risk_type == "privileged_container" for r in risks)

    cfg = {"whitelist": {"portainer": {"allow": ["privileged_container"]}}}
    filtered = filter_risks_with_whitelist(risks, cfg=cfg)
    assert not any(r.risk_type == "privileged_container" for r in filtered)


def test_cap_drop_not_flagged():
    c = _base_container(capabilities=["CAP_DROP:SYS_ADMIN"])
    risks = evaluate_container_risks(c)
    assert not any(r.risk_type == "cap_sys_admin" for r in risks)


def test_risks_privileged_and_host_network_and_docker_sock():
    c = _base_container(
        privileged=True,
        network_mode="host",
        mounts=[{"Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock"}],
    )
    risks = evaluate_container_risks(c)
    types = {r.risk_type for r in risks}
    assert "privileged_container" in types
    assert "host_network_mode" in types
    assert "docker_sock_mount" in types


def test_risks_have_attack_commands():
    """Every risk should include at least one attack command."""
    c = _base_container(privileged=True)
    risks = evaluate_container_risks(c)
    for r in risks:
        assert len(r.attack_commands) > 0, f"Risk {r.risk_type} has no attack commands"


def test_risks_have_remediation():
    """Every risk should include remediation advice."""
    c = _base_container(
        privileged=True,
        mounts=[{"Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock"}],
    )
    risks = evaluate_container_risks(c)
    for r in risks:
        assert r.remediation, f"Risk {r.risk_type} has no remediation"


def test_read_only_mount_not_flagged():
    """Read-only mounts to sensitive paths should NOT be flagged as risks."""
    c = _base_container(mounts=[{"Source": "/etc", "Destination": "/mnt/etc", "Mode": "ro"}])
    risks = evaluate_container_risks(c)
    assert not any(r.risk_type == "dangerous_host_mount" for r in risks)


def test_host_pid_mode_is_critical():
    c = _base_container(pid_mode="host")
    risks = evaluate_container_risks(c)
    pid_risks = [r for r in risks if r.risk_type == "host_pid_mode"]
    assert len(pid_risks) == 1
    assert pid_risks[0].severity == "CRITICAL"
