## DockerScope

**DockerScope** is a CLI tool that analyzes Docker runtime environments on Linux hosts, identifies real security risks, and models practical attack paths an attacker could take from a compromised container.

The primary question DockerScope tries to answer is:

> *“If a container becomes compromised, what could an attacker actually reach or escalate to?”*

It focuses on **runtime Docker environments** rather than image scanning, and is designed to be safe to run on production hosts in read-only mode.

---

## Installation

DockerScope targets **Python 3.11+** and Linux hosts with Docker.

1. Clone the repository:

```bash
git clone https://github.com/your-user/dockerscope.git
cd dockerscope
```

2. Install in editable mode:

```bash
pip install -e .
```

3. Verify the CLI:

```bash
dockerscope --help
```

---

## CLI commands

All commands assume you are running on a Linux host with Docker and that your user can talk to the Docker daemon.

- **Topology**

```bash
dockerscope topology
```

Shows a summary of containers, including image, status, privilege, and network mode.

**Example output:**

```text
┏━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━┓
┃ Name         ┃ Image         ┃ Status   ┃ Privileged ┃ Network  ┃
┡━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━┩
│ web          │ nginx:latest  │ running  │ no         │ bridge   │
│ portainer    │ portainer:ce  │ running  │ yes        │ host     │
└──────────────┴───────────────┴──────────┴────────────┴──────────┘
```

- **Analyze**

```bash
dockerscope analyze
dockerscope analyze my-container
```

Analyzes all containers (or a single container) for risky configurations such as privileged mode, host networking, Docker socket mounts, dangerous host mounts, and wide-exposed ports.

**Example output:**

```text
┏━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━┓
┃ Name         ┃ Image         ┃ Status   ┃ Privileged ┃ Network  ┃
┡━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━┩
│ portainer    │ portainer:ce  │ running  │ yes        │ host     │
└──────────────┴───────────────┴──────────┴────────────┴──────────┘

┏━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Container ┃ Type                 ┃ Description                                         ┃ Details                              ┃
┡━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ portainer │ privileged_container │ Container is running in privileged mode.            │ network_mode=host                    │
│ portainer │ host_network_mode    │ Container is using host network mode.              │                                      │
│ portainer │ docker_sock_mount    │ Container has access to the Docker socket.         │ source=/var/run/docker.sock, …       │
│ portainer │ wide_exposed_port    │ Port is exposed on all interfaces (0.0.0.0).       │ container_port=9000/tcp, host…       │
└───────────┴──────────────────────┴──────────────────────────────────────────────────────┴──────────────────────────────────────┘
```

- **Simulate**

```bash
dockerscope simulate my-container
```

Builds an internal attack graph and prints possible escalation paths starting from the specified container.

**Example output:**

```text
Attack paths starting from container portainer:
1. portainer -> docker.sock -> docker_daemon -> host_root (potential host compromise / root access)
2. portainer -> host_root (potential host compromise / root access)
```

- **Score**

```bash
dockerscope score
```

Calculates an overall security score (0–100, grade A–F) based on detected risks and attack paths across all containers.

- **Export**

```bash
dockerscope export --format json --output graph.json
dockerscope export --format dot | dot -Tpng > graph.png
```

Exports the attack graph in JSON or DOT (Graphviz) format for further analysis or visualization.

- **Reachability**

```bash
dockerscope reachability my-container
```

Analyzes network reachability for a container using host network configuration (`ip route`, `iptables`). On Linux, inspects routing tables and NAT rules to estimate whether published ports are reachable from LAN or Internet. On non-Linux hosts, provides basic network mode and port information only.

- **Scan Compose (placeholder)**

```bash
dockerscope scan-compose docker-compose.yaml
```

Currently prints a placeholder message; later versions will inspect Docker Compose files before deployment.

---

## Whitelist configuration

DockerScope supports whitelisting expected or accepted risks via a YAML file located at:

- `~/.dockerscope/config.yaml`

Format:

```yaml
whitelist:
  portainer:
    allow:
      - docker_sock_mount
      - wide_exposed_port
```

- The top-level key is `whitelist`.
- Each child key is a **container name** (e.g., `portainer`).
- Under `allow`, list **risk types** to ignore for that container.

Supported risk types include:

- `privileged_container`
- `docker_sock_mount`
- `critical_capability`
- `host_network_mode`
- `host_pid_mode`
- `dangerous_host_mount`
- `dangerous_capability`
- `wide_exposed_port`
- `no_security_profiles`
- `no_resource_limits`
- `running_as_root`
- `unpinned_image`

When a risk matches both the container name and a risk type listed in `allow`, it is filtered out of the CLI output.

---

## Attack paths

DockerScope builds a simple attack graph using `networkx` to represent how a compromised container could escalate:

- `container -> docker.sock -> docker_daemon -> host_root`
- `container -> host_root` (for privileged containers or dangerous host mounts)

Each edge in the graph represents a security-relevant relationship, for example:

- **mount_docker_sock** – the container can talk directly to the Docker daemon API.
- **privileged_container** – the container can access host devices and kernel features.
- **dangerous_host_mount** – the container has direct file-system access to sensitive host paths.

The `simulate` command walks this graph and prints human-readable paths, highlighting which containers can potentially compromise the host or gain full control of Docker.

---

## Development and testing

1. Create and activate a virtual environment (recommended).
2. Install the project in editable mode:

```bash
pip install -e .
```

3. Run tests:

```bash
pip install -e ".[dev]"
pytest
```

4. Run the CLI against your local Docker environment:

```bash
dockerscope topology
dockerscope analyze
```

---

## Contributing

Contributions are welcome. To get started:

1. Fork the repository and create a feature branch.
2. Keep changes focused and well-documented.
3. Add or update tests under `tests/` where appropriate.
4. Run the test suite and lint your code before opening a pull request.
5. In your PR description, explain:
   - What problem you are solving.
   - How you validated your changes (manual tests, automated tests, etc.).

Ideas for future work:

- Compose file scanning and policy-as-code integrations.
- Deeper Linux network analysis (veth pair tracing, bridge inspection).
- Capability-aware attack path modeling (e.g., SYS_PTRACE → process injection paths).