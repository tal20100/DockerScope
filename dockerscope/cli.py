"""
DockerScope CLI.

Commands:
    topology      - Show container overview (what you have running)
    scan          - Scan containers for risks and escape paths
    scan-compose  - Scan docker-compose.yml (no Docker needed)
"""

from __future__ import annotations

import json
from typing import Optional  # noqa: UP035

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from dockerscope.attack.attack_graph import (
    build_attack_graph,
    build_attack_tree,
    explain_attack_paths,
    export_graph_to_dict,
    export_graph_to_dot,
    sanitize_graph_for_json,
)
from dockerscope.core.compose_scanner import scan_compose_file
from dockerscope.core.discovery import ContainerInfo, discover_containers, find_container
from dockerscope.core.docker_client import DockerConnectionError
from dockerscope.core.risks import (
    Risk,
    evaluate_container_risks,
    filter_risks_with_whitelist,
)

app = typer.Typer(
    help="DockerScope - If someone got into one of your containers, what could they do from there?",
    add_completion=False,
)
console = Console()


def _print_risks(risks: list[Risk]) -> None:
    """Display risks with attack explanations and remediation."""
    if not risks:
        console.print(
            Panel(
                "[green]No risks detected.[/green]", title="Security Status", border_style="green"
            )
        )
        return

    critical = [r for r in risks if r.severity == "CRITICAL"]
    high = [r for r in risks if r.severity == "HIGH"]

    summary = f"[red]Critical: {len(critical)}[/red]  [yellow]High: {len(high)}[/yellow]"
    console.print(
        Panel(summary, title="Risk Summary", border_style="red" if critical else "yellow")
    )

    sorted_risks = critical + high

    for r in sorted_risks:
        if r.severity == "CRITICAL":
            color = "red"
        else:
            color = "yellow"

        # Header
        console.print(f"\n[bold {color}]{r.severity}[/bold {color}]  {r.description}")
        console.print(f"  [dim]Container:[/dim] [cyan]{r.container}[/cyan]")

        # Why this is dangerous
        console.print(f"\n  {r.attack_explanation}")

        # Attack commands
        if r.attack_commands:
            console.print("\n  [bold]Attack command:[/bold]")
            for cmd in r.attack_commands:
                console.print(f"    [dim]{cmd}[/dim]")

        # Remediation
        console.print("\n  [bold]Fix:[/bold]")
        for line in r.remediation.split("\n"):
            console.print(f"    {line}")

        console.print()


def _require_container(name_or_id: str) -> ContainerInfo:
    """Find container by name or ID, or exit with helpful error."""
    c = find_container(name_or_id)
    if not c:
        console.print(f"[red]Container '{name_or_id}' not found.[/red]")
        console.print("[dim]Run 'dockerscope scan' to scan all containers.[/dim]")
        raise typer.Exit(code=1)
    return c


def _handle_docker_error(exc: DockerConnectionError) -> None:
    """Display helpful error message for Docker connection failures."""
    console.print(f"[red]Docker Connection Error:[/red] {exc}")
    console.print("\n[yellow]Possible causes:[/yellow]")
    console.print("  - Docker daemon is not running")
    console.print("  - You don't have permission to access Docker socket")
    console.print("\n[dim]Try: sudo dockerscope ... or add your user to the docker group[/dim]")


def _format_ports(ports: dict) -> str:
    """Format ports dict into a readable string."""
    if not ports:
        return ""
    parts = []
    for container_port, bindings in ports.items():
        if not bindings:
            continue
        for b in bindings:
            host_ip = b.get("HostIp", "0.0.0.0")
            host_port = b.get("HostPort", "")
            if host_ip and host_port:
                parts.append(f"{host_ip}:{host_port}->{container_port}")
            elif host_port:
                parts.append(f"{host_port}->{container_port}")
    return ", ".join(parts) if parts else ""


def _security_flags(container: ContainerInfo) -> str:
    """Return short security flag indicators for a container."""
    flags = []
    if container.privileged:
        flags.append("[red]PRIV[/red]")
    for m in container.mounts:
        src = m.get("Source") or m.get("src") or ""
        dst = m.get("Destination") or m.get("dst") or ""
        if src in ("/var/run/docker.sock", "/run/docker.sock") or dst in (
            "/var/run/docker.sock",
            "/run/docker.sock",
        ):
            flags.append("[red]SOCK[/red]")
            break
    if container.network_mode == "host":
        flags.append("[yellow]HOSTNET[/yellow]")
    pid_mode = getattr(container, "pid_mode", None)
    if pid_mode == "host":
        flags.append("[yellow]HOSTPID[/yellow]")
    for cap in container.capabilities:
        if cap.startswith("CAP_ADD:"):
            cap_name = cap.removeprefix("CAP_ADD:")
            if cap_name in ("SYS_ADMIN", "SYS_MODULE"):
                flags.append(f"[red]{cap_name}[/red]")
            elif cap_name in ("SYS_PTRACE", "NET_ADMIN"):
                flags.append(f"[yellow]{cap_name}[/yellow]")
    return " ".join(flags) if flags else "[green]clean[/green]"


@app.command()
def topology() -> None:
    """
    Show an overview of all containers on this host.

    Lists every container (running and stopped) with its image,
    status, network mode, published ports, and security-relevant flags.
    Use this to get a quick picture of what you have before scanning.

    Examples:
        dockerscope topology
    """
    try:
        containers = discover_containers(all_containers=True)
    except DockerConnectionError as exc:
        _handle_docker_error(exc)
        raise typer.Exit(code=1)

    if not containers:
        console.print("[yellow]No containers found on this system.[/yellow]")
        raise typer.Exit(code=0)

    running = [c for c in containers if c.status == "running"]
    stopped = [c for c in containers if c.status != "running"]

    console.print(
        Panel(
            f"[bold]{len(containers)}[/bold] container(s)  "
            f"[green]{len(running)} running[/green]  "
            f"[dim]{len(stopped)} stopped[/dim]",
            title="Docker Topology",
            border_style="blue",
        )
    )

    table = Table(show_lines=True, box=box.ROUNDED)
    table.add_column("Container", style="cyan", no_wrap=True)
    table.add_column("Image", style="dim")
    table.add_column("Status")
    table.add_column("Network")
    table.add_column("Ports")
    table.add_column("Flags")

    for c in containers:
        status_style = "green" if c.status == "running" else "dim"
        table.add_row(
            c.name,
            c.image,
            f"[{status_style}]{c.status}[/{status_style}]",
            c.network_mode,
            _format_ports(c.ports),
            _security_flags(c),
        )

    console.print(table)

    # Legend
    console.print(
        "\n[dim]Flags: "
        "[red]PRIV[/red]=privileged  "
        "[red]SOCK[/red]=docker.sock mounted  "
        "[yellow]HOSTNET[/yellow]=host network  "
        "[yellow]HOSTPID[/yellow]=host PID  "
        "[green]clean[/green]=no dangerous settings"
        "[/dim]"
    )
    console.print("[dim]Run 'dockerscope scan' to see full risk analysis and attack paths.[/dim]")


@app.command()
def scan(
    container: Optional[str] = typer.Argument(
        None, help="Container name/ID to scan (scans all if omitted)"
    ),
    export: Optional[str] = typer.Option(
        None, "--export", "-e", help="Export attack graph: json or dot"
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Output file path for export (stdout if omitted)"
    ),
) -> None:
    """
    Scan containers for security risks and escape paths.

    Shows what an attacker could do if they got into your containers.
    Every finding includes the exact commands an attacker would run
    and how to fix the issue.

    Examples:
        dockerscope scan                        # Scan all containers
        dockerscope scan nginx                  # Scan specific container
        dockerscope scan --export json -o graph.json
    """
    if export and export not in ("json", "dot"):
        console.print(f"[red]Unsupported export format: {export}[/red]")
        console.print("[dim]Supported formats: json, dot[/dim]")
        raise typer.Exit(code=1)

    try:
        containers = discover_containers(all_containers=True)
    except DockerConnectionError as exc:
        _handle_docker_error(exc)
        raise typer.Exit(code=1)

    if not containers:
        console.print("[yellow]No containers found on this system.[/yellow]")
        raise typer.Exit(code=0)

    # Focus on specific container if requested
    if container:
        target = _require_container(container)
        scan_containers = [target]
    else:
        scan_containers = containers

    # Collect all risks
    all_risks: list[Risk] = []
    for c in containers:
        all_risks.extend(evaluate_container_risks(c))
    all_risks = filter_risks_with_whitelist(all_risks)

    # Build attack graph
    g = build_attack_graph(containers, all_risks)

    # Handle export
    if export:
        if export == "json":
            data = export_graph_to_dict(g)
            data = sanitize_graph_for_json(data)
            result = json.dumps(data, indent=2)
        else:
            result = export_graph_to_dot(g)

        if output:
            with open(output, "w") as f:
                f.write(result)
            console.print(f"[green]Exported to {output}[/green]")
            if export == "dot":
                console.print(f"[dim]Render with: dot -Tpng {output} -o graph.png[/dim]")
        else:
            console.print(result)
        return

    # Display results for each container
    for c in scan_containers:
        container_risks = [r for r in all_risks if r.container == c.name]
        paths = explain_attack_paths(g, c.name)

        console.print(f"\n[bold]{'=' * 60}[/bold]")
        console.print(f"[bold cyan]{c.name}[/bold cyan]  [dim]{c.image}[/dim]")
        console.print(f"[bold]{'=' * 60}[/bold]")

        if not container_risks and not paths:
            console.print(
                Panel(
                    "[green]No risks detected. This container is well-configured.[/green]",
                    border_style="green",
                )
            )
            continue

        # Show risks
        if container_risks:
            _print_risks(container_risks)

        # Show escape paths
        if paths:
            table = Table(
                title=f"[bold red]Escape Paths: {len(paths)}[/bold red]",
                show_lines=True,
                box=box.DOUBLE_EDGE,
            )
            table.add_column("#", style="bold", width=3, justify="right")
            table.add_column("Risk", style="red", width=7, justify="center")
            table.add_column("Path", style="yellow")
            table.add_column("Hops", width=5, justify="center")

            for idx, p in enumerate(paths, start=1):
                table.add_row(
                    str(idx), f"{int(p.risk_score * 100)}%", p.description, str(len(p.nodes) - 1)
                )

            console.print(table)

            tree = build_attack_tree(paths, c.name)
            console.print("\n[bold]Attack Graph:[/bold]")
            console.print(tree)
            console.print()


@app.command("scan-compose")
def scan_compose(file: str = typer.Argument(..., help="Path to docker-compose.yml file")) -> None:
    """
    Scan a docker-compose file for security risks before deployment.

    Parses the compose file statically - Docker does NOT need to be running.
    Exits with code 1 if critical risks are found (useful for CI).

    Examples:
        dockerscope scan-compose docker-compose.yml
        dockerscope scan-compose ./stacks/nextcloud/docker-compose.yml
    """
    try:
        results = scan_compose_file(file)
    except FileNotFoundError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1)

    console.print(
        Panel(
            f"[bold]Scanning:[/bold] [cyan]{file}[/cyan] - "
            f"[bold]{len(results)}[/bold] service(s) found",
            border_style="blue",
        )
    )

    total_critical = 0
    total_high = 0
    has_critical = False

    for service_name, risks in results:
        if not risks:
            console.print(f"[green]{service_name} - no issues found[/green]\n")
        else:
            console.print(f"\n[bold cyan]{service_name}[/bold cyan]")
            _print_risks(risks)

        for r in risks:
            if r.severity == "CRITICAL":
                total_critical += 1
                has_critical = True
            elif r.severity == "HIGH":
                total_high += 1

    # Summary
    summary = f"[red]Critical: {total_critical}[/red]  [yellow]High: {total_high}[/yellow]"

    if total_critical > 0:
        verdict = "[red]Do not deploy without fixing critical issues[/red]"
    elif total_high > 0:
        verdict = "[yellow]Review high-severity findings before deploying[/yellow]"
    else:
        verdict = "[green]No dangerous configurations found[/green]"

    console.print(
        Panel(
            f"{summary}\n\n{verdict}",
            title="Summary",
            border_style="red" if total_critical > 0 else ("yellow" if total_high > 0 else "green"),
        )
    )

    if has_critical:
        raise typer.Exit(code=1)


def main() -> None:
    """CLI entry point."""
    app()


if __name__ == "__main__":
    main()
