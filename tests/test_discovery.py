from __future__ import annotations

from dockerscope.core.discovery import ContainerInfo, _extract_container_info


class DummyImage:
    tags = ["nginx:latest"]


class DummyContainer:
    def __init__(self) -> None:
        self.id = "abcd1234"
        self.name = "web"
        self.image = DummyImage()
        self.attrs = {
            "Id": self.id,
            "Name": "/web",
            "Config": {"Image": "nginx:latest"},
            "HostConfig": {"Privileged": True, "NetworkMode": "host", "CapAdd": ["NET_ADMIN"]},
            "State": {"Status": "running"},
            "Mounts": [],
            "NetworkSettings": {"Ports": {"80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "80"}]}},
        }


def test_extract_container_info_basic() -> None:
    dummy = DummyContainer()
    info: ContainerInfo = _extract_container_info(dummy)

    assert info.name == "web"
    assert info.image == "nginx:latest"
    assert info.privileged is True
    assert info.network_mode == "host"
    assert info.status == "running"
    assert any(cap.startswith("CAP_ADD:NET_ADMIN") for cap in info.capabilities)
