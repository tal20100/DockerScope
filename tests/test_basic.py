from __future__ import annotations

from dockerscope.attack.attack_graph import build_attack_graph, explain_attack_paths
from dockerscope.core.risks import evaluate_container_risks
from dockerscope.models.container import ContainerInfo
from dockerscope.models.risk import Risk

"""
Basic sanity tests for the dockerscope package.

These tests are intentionally lightweight and avoid requiring a
live Docker daemon, so they can run in more environments.
"""



def test_evaluate_container_risks_privileged_and_docker_sock() -> None:
    """A privileged container with docker.sock mounted should yield multiple risks."""
    c = ContainerInfo(
        id="abc",
        name="test",
        image="alpine:latest",
        privileged=True,
        network_mode="bridge",
        status="running",
        mounts=[{"Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock"}],
        ports={},
        capabilities=[],
    )

    risks = evaluate_container_risks(c)
    types = {r.risk_type for r in risks}
    assert "privileged_container" in types
    assert "docker_sock_mount" in types


def test_attack_graph_paths() -> None:
    """Attack graph should build a path through docker.sock when present."""
    containers = [
        ContainerInfo(
            id="abc",
            name="test",
            image="alpine:latest",
            privileged=False,
            network_mode="bridge",
            status="running",
            mounts=[{"Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock"}],
            ports={},
            capabilities=[],
        )
    ]
    risks = [
        Risk(
            container="test",
            risk_type="docker_sock_mount",
            description="",
            details={},
        )
    ]

    g = build_attack_graph(containers, risks)
    paths = explain_attack_paths(g, "test")
    # Expect a path that ends in host_root eventually.
    assert any("host_root" in p.nodes for p in paths)

