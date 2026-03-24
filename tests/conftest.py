"""Shared test fixtures for DockerScope tests."""

from __future__ import annotations

from typing import Any

from dockerscope.models.container import ContainerInfo


def make_container(**overrides: Any) -> ContainerInfo:
    """Build a ContainerInfo with sensible defaults, overridable for each test.

    Args:
        **overrides: Any ContainerInfo field to override.

    Returns:
        ContainerInfo instance.
    """
    data: dict[str, Any] = dict(
        id="test-id",
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
