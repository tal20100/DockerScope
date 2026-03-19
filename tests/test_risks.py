from __future__ import annotations

from dockerscope.models.container import ContainerInfo
from dockerscope.core.risks import evaluate_container_risks


def _base_container(**overrides):
    data = dict(
        id="id",
        name="c",
        image="img",
        privileged=False,
        network_mode="bridge",
        status="running",
        mounts=[],
        ports={},
        capabilities=[],
    )
    data.update(overrides)
    return ContainerInfo(**data)


def test_risks_privileged_and_host_network_and_docker_sock() -> None:
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


def test_risks_dangerous_mounts_and_wide_port() -> None:
    c = _base_container(
        mounts=[{"Source": "/etc", "Destination": "/mnt/etc"}],
        ports={"8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]},
    )
    risks = evaluate_container_risks(c)
    types = {r.risk_type for r in risks}

    assert "dangerous_host_mount" in types
    assert "wide_exposed_port" in types
