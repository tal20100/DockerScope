# DockerScope

> Find out what an attacker could do if they got into your Docker containers.

## Real-World Use Case

You're a DevOps engineer or a homelabber running self-hosted services — Jellyfin, Nextcloud, Home Assistant, Grafana. You pulled docker-compose files from GitHub or a blog post, ran `docker compose up`, and everything works. But those files often include `privileged: true`, Docker socket mounts, or `network_mode: host` without explaining the security implications.

Tools like **Trivy** and **Snyk** scan container *images* for known CVEs — outdated packages, vulnerable libraries. That's important, but it misses a completely different class of risk: **what happens after an attacker gets code execution inside a container?** A container with zero CVEs but `privileged: true` can escape to your host in seconds.

**DockerScope** fills that gap. It analyzes your running Docker environment (or your compose files before deployment) and models real attack paths — privilege escalation, host escape through misconfigurations, and Docker daemon takeover. It tells you exactly what's dangerous, shows the commands an attacker would run, and tells you how to fix it.

## What it detects

| Risk | Severity | What it means | Real-world example |
|------|----------|---------------|-------------------|
| Docker socket mount | CRITICAL | Container can control the Docker daemon | Container with `/var/run/docker.sock` — attacker creates a new privileged container |
| Privileged mode | CRITICAL | Container has near-root access to host | `privileged: true` — attacker uses `nsenter` to get a host shell |
| SYS_ADMIN capability | CRITICAL | Can mount host filesystems | `cap_add: [SYS_ADMIN]` — attacker mounts host disk |
| Host PID namespace | CRITICAL | Container sees all host processes | `pid: host` — attacker uses `nsenter` to get host shell |
| Dangerous host mounts | CRITICAL | Sensitive host paths writable from container | `/etc` mounted writable — attacker modifies `/etc/shadow` |
| Host network mode | HIGH | Container shares the host network stack | Can sniff traffic, bind to any host port, access localhost services |
| SYS_PTRACE capability | HIGH | Can trace and inject into other processes | Combined with host PID, enables host process injection |

> **Note on `nsenter`:** When a container runs with `privileged: true` and shares the host PID namespace, `nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash` gives the attacker a full root shell on the host. The command targets PID 1 (the host's init process) and enters its namespaces — effectively leaving the container entirely. This is not a theoretical risk; it's one command from container to host root.

## Quick start

```bash
# Install via pip
pip install dockerscope

# See what containers you have
dockerscope topology

# Scan everything for risks and attack paths
dockerscope scan

# Scan a specific container
dockerscope scan jellyfin

# Scan a compose file BEFORE deploying (no Docker needed)
dockerscope scan-compose docker-compose.yml
```

## Installation

### pip (recommended)

```bash
pip install dockerscope
```

### Docker

Run DockerScope itself in a container. It needs access to the Docker socket to inspect other containers:

```bash
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock dockerscope scan
```

To scan a compose file:

```bash
docker run --rm -v ./docker-compose.yml:/app/docker-compose.yml dockerscope scan-compose /app/docker-compose.yml
```

### From source

```bash
git clone https://github.com/tal20100/DockerScope.git
cd DockerScope
pip install -e ".[dev]"
```

**Requirements:**
- Python 3.11+
- Docker must be running (except for `scan-compose`, which works offline)
- Your user must be in the `docker` group, or run with `sudo`:
  ```bash
  sudo usermod -aG docker $USER
  # Log out and back in for this to take effect
  ```

## Commands

### `dockerscope topology`

Quick overview of all containers on your host — running and stopped. Shows each container's image, network mode, published ports, and security-relevant flags at a glance.

```
$ dockerscope topology

╭──────────────── Docker Topology ────────────────╮
│ 4 container(s)  3 running  1 stopped            │
╰─────────────────────────────────────────────────╯
┌────────────┬──────────────┬─────────┬─────────┬──────────────────┬─────────┐
│ Container  │ Image        │ Status  │ Network │ Ports            │ Flags   │
├────────────┼──────────────┼─────────┼─────────┼──────────────────┼─────────┤
│ nginx      │ nginx:1.25   │ running │ bridge  │ 0.0.0.0:80->80   │ clean   │
│ jellyfin   │ jellyfin/..  │ running │ host    │                  │ HOSTNET │
│ nextcloud  │ nextcloud:28 │ running │ bridge  │ 0.0.0.0:443->443 │ clean   │
│ watchtower │ watchtower   │ running │ bridge  │                  │ SOCK    │
└────────────┴──────────────┴─────────┴─────────┴──────────────────┴─────────┘

Flags: PRIV=privileged  SOCK=docker.sock  HOSTNET=host network  clean=no issues
Run 'dockerscope scan' to see full risk analysis and attack paths.
```

### `dockerscope scan [CONTAINER]`

Scan all containers (or a specific one) for security risks and escape paths. Every finding includes:
- **What's dangerous** — plain-language explanation
- **Attack commands** — exactly what an attacker would run
- **How to fix it** — specific remediation steps

```bash
dockerscope scan                # Scan all containers
dockerscope scan jellyfin       # Scan specific container
```

You can export the attack graph for visualization:

```bash
dockerscope scan --export json -o graph.json
dockerscope scan --export dot -o graph.dot
dot -Tpng graph.dot -o graph.png    # Render with Graphviz
```

#### Example output

```
============================================================
jellyfin  jellyfin/jellyfin:latest
============================================================

CRITICAL  Container runs in privileged mode.
  Container: jellyfin

  An attacker inside this container has full access to all host
  devices and can escape to the host with a single command.

  Attack command:
    nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash

  Fix:
    Remove 'privileged: true' from your docker-compose.yml. If the
    container needs specific device access, use 'devices:' to grant
    only what is needed.

╔═══════════════ Escape Paths: 1 ═══════════════╗
║ # │ Risk │ Path                         │ Hops ║
╠═══╪══════╪══════════════════════════════╪══════╣
║ 1 │  90% │ jellyfin -> host_root        │    1 ║
╚═══╧══════╧══════════════════════════════╧══════╝
```

### `dockerscope scan-compose FILE`

Scan a docker-compose file for security risks **without Docker running**. Parses the YAML statically and applies the same risk detection.

Exits with code 1 if any CRITICAL risk is found — plug it into your CI pipeline to block dangerous deployments.

```bash
dockerscope scan-compose docker-compose.yml
```

```
┌─ Scanning: docker-compose.yml — 3 services found ─┐

  nginx — no issues found

── dev-tools ──
  CRITICAL: Container runs in privileged mode.
  ...

┌──────────── Summary ────────────┐
│ Critical: 1  High: 0            │
│                                 │
│ Do not deploy without fixing    │
│ critical issues                 │
└─────────────────────────────────┘
```

## Understanding the output

### Attack paths

When you run `dockerscope scan`, the tool builds a directed graph of all possible escape paths. Each path shows how an attacker could move from their initial position (inside a compromised container) toward a critical target (host root access or Docker daemon control).

**Example path:** `jellyfin → host_root` (1 hop, privileged escape)

This means: if an attacker gets code execution inside the Jellyfin container, they can use `nsenter` to escape directly to the host because the container runs in privileged mode.

**Risk scores** range from 0% to 100% and combine:
- **Exploitability** — how easy is each step? (socket mount = trivial, capability abuse = requires knowledge)
- **Impact** — what does the attacker gain? (host root = maximum impact)
- **Path length** — shorter paths are more dangerous (fewer steps to compromise)

## Whitelist / known-safe containers

Some containers legitimately need elevated privileges. For example, Portainer and Watchtower need the Docker socket to function — that's their whole purpose. You can acknowledge these with a whitelist so they don't clutter your scan results.

Create `~/.dockerscope/config.yaml`:

```yaml
whitelist:
  portainer:
    allow:
      - docker_sock_mount
  watchtower:
    allow:
      - docker_sock_mount
```

Whitelisted risks are excluded from scan output. The container name must match exactly.

## Use in CI/CD

Add `scan-compose` to your pipeline to catch misconfigurations before deployment:

```yaml
# .github/workflows/security.yml
name: Docker Security Check
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install dockerscope
      - run: dockerscope scan-compose docker-compose.yml
```

Exit code 1 on critical risks means the CI job fails automatically.

## Contributing

See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) for development setup, how to add new detection rules, and PR guidelines.

## License

MIT License. See [LICENSE](LICENSE) for details.
