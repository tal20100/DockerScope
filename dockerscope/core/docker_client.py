from __future__ import annotations

from functools import cache

import docker
from docker.client import DockerClient


class DockerConnectionError(RuntimeError):
    """Raised when the Docker daemon cannot be reached."""


@cache
def get_client() -> DockerClient:
    """
    Return a cached Docker client connected to the local daemon.

    This uses environment configuration (DOCKER_HOST, etc.) by default.
    """
    try:
        client = docker.from_env()
        # Cheap ping to fail fast if the daemon is unavailable
        client.ping()
    except Exception as exc:  # pragma: no cover - depends on local Docker
        raise DockerConnectionError(f"Unable to connect to Docker daemon: {exc}") from exc
    return client


def list_containers(all_containers: bool = False) -> list:
    """Wrapper for listing containers, mainly for easier mocking/testing."""
    client = get_client()
    return list(client.containers.list(all=all_containers))
