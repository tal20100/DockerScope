"""
DockerScope CLI - Professional command-line interface.

Provides comprehensive Docker security analysis through an intuitive
CLI with rich output formatting and helpful error messages.

Commands:
    topology     - Show container topology
    analyze      - Analyze containers for risks
    simulate     - Simulate attack paths from compromised container
    score        - Calculate overall security score
    export       - Export attack graph
    reachability - Analyze network reachability
    scan-compose - Scan docker-compose.yml
"""

from __future__ import annotations

from typing import Optional
import json

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from dockerscope.attack.attack_graph import (
    build_attack_graph,
    build_attack_tree,
    explain_attack_paths,
    export_graph_to_dict,
    export_graph_to_dot, sanitize_graph_for_json
)
from dockerscope.core.discovery import (
    ContainerInfo,
    discover_containers,
    find_container
)
from dockerscope.core.docker_client import DockerConnectionError
from dockerscope.core.reachability import collect_host_network_info, analyze_container_reachability
from dockerscope.core.risks import (
    Risk,
    evaluate_container_risks,
    filter_risks_with_whitelist,
    get_risk_severity
)
from dockerscope.models.container import ContainerReachability
from dockerscope.models.host import HostNetworkSnapshot

try:
    from dockerscope.core.scorer import calculate_security_score, generate_score_report
    SCORER_AVAILABLE = True
except ImportError:
    SCORER_AVAILABLE = False


app = typer.Typer(
    help="DockerScope – Analyze Docker runtime environments for real security risks and attack paths.",
    add_completion=False
)
console = Console()

def _print_container_summary(containers: list[ContainerInfo]) -> None:
    """
    Display summary table of containers.

    Shows key security-relevant information with visual indicators.
    """
    table = Table(
        title="[bold]Discovered Containers[/bold]",
        show_lines=False,
        box=box.SIMPLE
    )
    table.add_column("Name", style="cyan", no_wrap=True)
    table.add_column("Image", style="green")
    table.add_column("Status", style="yellow")
    table.add_column("Privileged", style="red", justify="center")
    table.add_column("Network", style="blue")

    for c in containers:
        # Status indicator
        status_icon = "🟢" if c.status == "running" else "🔴"

        # Privileged indicator with warning
        priv_icon = "⚠️  YES" if c.privileged else "no"

        table.add_row(
            c.name,
            c.image,
            f"{status_icon} {c.status}",
            priv_icon,
            c.network_mode or "bridge",
        )

    console.print(table)
    console.print(f"\n[dim]Total: {len(containers)} container(s)[/dim]\n")


def _print_risks(risks: list[Risk], title: str = "Detected Risks") -> None:
    """
    Display detailed risk table with severity-based color coding.

    Groups risks by severity and displays with appropriate visual indicators.
    """
    if not risks:
        console.print(Panel(
            "[green]✓ No risks detected (after applying whitelist).[/green]",
            title="Security Status",
            border_style="green"
        ))
        return

    # Categorize risks by severity
    critical = []
    high = []
    medium = []
    low = []

    for r in risks:
        severity = get_risk_severity(r.risk_type)
        if severity == "CRITICAL":
            critical.append(r)
        elif severity == "HIGH":
            high.append(r)
        elif severity == "MEDIUM":
            medium.append(r)
        else:
            low.append(r)

    # Display summary panel
    summary = (
        f"[red]Critical: {len(critical)} 🔴[/red]  "
        f"[yellow]High: {len(high)} 🟠[/yellow]  "
        f"[blue]Medium: {len(medium)} 🟡[/blue]  "
        f"[dim]Low: {len(low)} ⚪[/dim]"
    )
    console.print(Panel(summary, title="Risk Summary", border_style="red"))

    # Detailed risk table
    table = Table(
        title=f"[bold]{title}[/bold]",
        show_lines=True,
        box=box.ROUNDED
    )
    table.add_column("Severity", style="bold", width=12)
    table.add_column("Container", style="cyan")
    table.add_column("Risk Type", style="yellow")
    table.add_column("Description")
    table.add_column("Details", style="dim")

    # Display risks sorted by severity
    sorted_risks = critical + high + medium + low

    for r in sorted_risks:
        # Severity indicator
        severity = get_risk_severity(r.risk_type)
        if severity == "CRITICAL":
            sev_display = "🔴 CRITICAL"
        elif severity == "HIGH":
            sev_display = "🟠 HIGH"
        elif severity == "MEDIUM":
            sev_display = "🟡 MEDIUM"
        else:
            sev_display = "⚪ LOW"

        # Format details
        details_str = ", ".join(f"{k}={v}" for k, v in r.details.items())

        table.add_row(
            sev_display,
            r.container,
            r.risk_type,
            r.description,
            details_str or "-"
        )

    console.print(table)
    console.print()


def _require_container(name_or_id: str) -> ContainerInfo:
    """
    Find container by name or ID, or exit with helpful error.

    Args:
        name_or_id: Container name or ID prefix

    Returns:
        ContainerInfo object

    Raises:
        typer.Exit: If container not found
    """
    c = find_container(name_or_id)
    if not c:
        console.print(f"[red]✗ Container '{name_or_id}' not found[/red]")
        console.print("\n[dim]Run[/dim] [cyan]dockerscope topology[/cyan] [dim]to see available containers[/dim]")
        raise typer.Exit(code=1)
    return c


def _handle_docker_error(exc: DockerConnectionError) -> None:
    """
    Display helpful error message for Docker connection failures.

    Args:
        exc: Docker connection exception
    """
    console.print(f"[red]✗ Docker Connection Error:[/red] {exc}")
    console.print("\n[yellow]Possible causes:[/yellow]")
    console.print("  • Docker daemon is not running")
    console.print("  • You don't have permission to access Docker socket")
    console.print("  • Docker socket path is non-standard")
    console.print("\n[dim]Try:[/dim]")
    console.print("  • [cyan]sudo dockerscope ...[/cyan]")
    console.print("  • Add your user to docker group: [cyan]sudo usermod -aG docker $USER[/cyan]")


# ============================================================================
# Commands
# ============================================================================

@app.command()
def topology() -> None:
    """
    Display Docker runtime topology.

    Shows all containers (running and stopped) with basic security information.

    Example:
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

    _print_container_summary(containers)


@app.command()
def analyze(
    container: Optional[str] = typer.Argument(
        None,
        help="Optional container name/ID to analyze (analyzes all if omitted)"
    )
) -> None:
    """
    Analyze Docker environment for security risks.

    Performs comprehensive security analysis of containers, detecting
    dangerous configurations that could lead to privilege escalation.

    Examples:
        dockerscope analyze              # Analyze all containers
        dockerscope analyze nginx        # Analyze specific container
    """
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
        containers = [target]
        console.print(f"\n[bold]Analyzing container:[/bold] [cyan]{target.name}[/cyan]\n")

    # Evaluate all containers for risks
    all_risks: list[Risk] = []
    for c in containers:
        all_risks.extend(evaluate_container_risks(c))

    # Apply whitelist filtering
    all_risks = filter_risks_with_whitelist(all_risks)

    # Display results
    if not container:  # Show summary only when analyzing all
        _print_container_summary(containers)

    _print_risks(all_risks)

    # Helpful next steps
    if all_risks:
        critical_count = sum(1 for r in all_risks if get_risk_severity(r.risk_type) == "CRITICAL")
        if critical_count > 0:
            console.print(
                f"[red]⚠️  {critical_count} critical risk(s) detected![/red]\n"
                "[yellow]Run 'dockerscope simulate <container>' to see attack paths.[/yellow]"
            )
        else:
            console.print(
                "[yellow]💡 Run 'dockerscope simulate <container>' to see potential attack paths.[/yellow]"
            )


@app.command()
def simulate(
    container: str = typer.Argument(..., help="Container name/ID to simulate compromise from")
) -> None:
    """
    Simulate attack paths from a compromised container.

    Models what an attacker could do if they gained code execution inside
    the specified container. Shows all possible escalation paths to host
    or Docker daemon.

    Example:
        dockerscope simulate nginx
    """
    try:
        containers = discover_containers(all_containers=True)
    except DockerConnectionError as exc:
        _handle_docker_error(exc)
        raise typer.Exit(code=1)

    if not containers:
        console.print("[yellow]No containers found on this system.[/yellow]")
        raise typer.Exit(code=0)

    target = _require_container(container)

    # Collect all risks
    console.print(f"[dim]Analyzing security risks...[/dim]")
    risks: list[Risk] = []
    for c in containers:
        risks.extend(evaluate_container_risks(c))
    risks = filter_risks_with_whitelist(risks)

    # Build attack graph
    console.print(f"[dim]Building attack graph...[/dim]")
    g = build_attack_graph(containers, risks)

    # Find attack paths
    console.print(f"[dim]Finding escalation paths...[/dim]\n")
    paths = explain_attack_paths(g, target.name)

    # Display results
    console.print(
        f"[bold]Attack Path Simulation[/bold]\n"
        f"[dim]Starting from:[/dim] [cyan]{target.name}[/cyan]\n"
    )

    if not paths:
        console.print(Panel(
            "[green]✓ No direct escalation paths to host_root or docker_daemon identified.[/green]\n\n"
            "[dim]This container appears to be relatively isolated.\n"
            "However, always follow security best practices:\n"
            "  • Run as non-root user\n"
            "  • Drop unnecessary capabilities\n"
            "  • Use read-only filesystems where possible[/dim]",
            title="Good News",
            border_style="green"
        ))
        raise typer.Exit(code=0)

    # Display paths in table format
    table = Table(
        title=f"[bold red]⚠️  Attack Paths Found: {len(paths)}[/bold red]",
        show_lines=True,
        box=box.DOUBLE_EDGE
    )
    table.add_column("#", style="bold", width=3, justify="right")
    table.add_column("Risk", style="red", width=7, justify="center")
    table.add_column("Path Description", style="yellow")
    table.add_column("Hops", width=5, justify="center")

    for idx, p in enumerate(paths, start=1):
        risk_score_pct = int(p.risk_score * 100)
        hops = len(p.nodes) - 1

        table.add_row(
            str(idx),
            f"{risk_score_pct}%",
            p.description,
            str(hops)
        )

    console.print(table)

    # Display tree visualization
    tree = build_attack_tree(paths, target.name)
    console.print("\n[bold]Attack Graph (Tree View):[/bold]")
    console.print(tree)
    console.print()

    # Display remediation advice
    if paths:
        top_path = paths[0]  # Highest risk path
        console.print(Panel(
            f"[red]⚠️  CRITICAL:[/red] Attack paths to host compromise detected!\n\n"
            f"[bold]Top priority fix:[/bold]\n{top_path.remediation}\n\n"
            f"[dim]Run 'dockerscope score' to see overall security posture.[/dim]",
            title="Remediation Required",
            border_style="red"
        ))


@app.command()
def score() -> None:
    """
    Calculate overall security score for Docker environment.

    Analyzes all containers and attack paths to generate a comprehensive
    security score (0-100) with letter grade (A-F).

    Example:
        dockerscope score
    """
    if not SCORER_AVAILABLE:
        console.print(Panel(
            "[yellow]⚠️  Security scoring module not available in this version.[/yellow]\n\n"
            "[dim]The scoring feature requires additional dependencies.\n"
            "Run 'dockerscope analyze' for risk detection without scoring.[/dim]",
            title="Feature Not Available",
            border_style="yellow"
        ))
        raise typer.Exit(code=0)

    try:
        containers = discover_containers(all_containers=True)
    except DockerConnectionError as exc:
        _handle_docker_error(exc)
        raise typer.Exit(code=1)

    if not containers:
        console.print("[yellow]No containers found on this system.[/yellow]")
        raise typer.Exit(code=0)

    # Collect risks
    console.print("[dim]Analyzing containers...[/dim]")
    risks: list[Risk] = []
    for c in containers:
        risks.extend(evaluate_container_risks(c))
    risks = filter_risks_with_whitelist(risks)

    # Build attack graph and find paths
    console.print("[dim]Building attack graph...[/dim]")
    g = build_attack_graph(containers, risks)

    console.print("[dim]Finding attack paths...[/dim]")
    all_paths = []
    for c in containers:
        paths = explain_attack_paths(g, c.name, max_paths=5)
        all_paths.extend(paths)

    # Calculate score
    console.print("[dim]Calculating security score...[/dim]\n")
    score_obj = calculate_security_score(risks, all_paths)

    # Generate and display report
    report = generate_score_report(score_obj)

    # Color-code panel by grade
    if score_obj.grade in ["A", "B"]:
        style = "green"
    elif score_obj.grade == "C":
        style = "yellow"
    else:
        style = "red"

    console.print(Panel(
        report,
        title=f"[{style}]Security Score: {score_obj.grade}[/{style}]",
        border_style=style
    ))

    # Recommendations based on score
    if score_obj.total_score < 70:
        console.print("\n[yellow]💡 Recommendations:[/yellow]")
        console.print("  1. Run [cyan]dockerscope analyze[/cyan] to see detailed risks")
        console.print("  2. Fix critical and high-severity issues first")
        console.print("  3. Run [cyan]dockerscope simulate <container>[/cyan] to see attack paths")


@app.command()
def export(
    format: str = typer.Option(
        "json",
        "--format",
        "-f",
        help="Export format: json or dot (Graphviz)"
    ),
    output: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path (prints to stdout if omitted)"
    )
) -> None:
    """
    Export attack graph for visualization or analysis.

    Supports JSON (machine-readable) and DOT (Graphviz) formats.

    Examples:
        dockerscope export --format json --output graph.json
        dockerscope export --format dot | dot -Tpng > graph.png
    """
    if format not in ["json", "dot"]:
        console.print(f"[red]✗ Unsupported format: {format}[/red]")
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

    # Build attack graph
    console.print("[dim]Building attack graph...[/dim]")
    risks: list[Risk] = []
    for c in containers:
        risks.extend(evaluate_container_risks(c))
    risks = filter_risks_with_whitelist(risks)

    g = build_attack_graph(containers, risks)

    # Export to requested format
    console.print(f"[dim]Exporting to {format.upper()} format...[/dim]")
    if format == "json":
        data = export_graph_to_dict(g)
        data = sanitize_graph_for_json(data)
        result = json.dumps(data, indent=2)
    else:  # dot
        result = export_graph_to_dot(g)

    # Output to file or stdout
    if output:
        with open(output, "w") as f:
            f.write(result)
        console.print(f"[green]✓ Successfully exported to {output}[/green]")

        if format == "dot":
            console.print("\n[dim]Render with:[/dim]")
            console.print(f"  [cyan]dot -Tpng {output} -o graph.png[/cyan]")
    else:
        console.print(result)


@app.command()
def reachability(
    container: Optional[str] = typer.Argument(
        None,
        help="Container name/ID"
    )
) -> None:
    """
    Analyze network reachability for a container.

    Determines where the container can be reached from (LAN, Internet)
    and what it can reach (host, LAN, Internet).

    Example:
        dockerscope reachability nginx
    """
    if container is None:
        console.print("[red]✗ Missing required container argument.[/red]")
        console.print("\n[dim]Usage:[/dim]")
        console.print("  Run [cyan]dockerscope topology[/cyan] to list containers")
        console.print("  Then: [cyan]dockerscope reachability <container-name>[/cyan]")
        raise typer.Exit(code=1)

    c = _require_container(container)

    # Collect network information
    console.print(f"[dim]Collecting host network information...[/dim]")
    snapshot: HostNetworkSnapshot = collect_host_network_info()

    console.print(f"[dim]Analyzing reachability...[/dim]\n")
    reach: ContainerReachability = analyze_container_reachability(c, snapshot)

    # Display results
    console.print(Panel(
        f"[bold]Container:[/bold] [cyan]{c.name}[/cyan]\n"
        f"[bold]Network mode:[/bold] [magenta]{reach.network_mode or 'bridge'}[/magenta]",
        title="Reachability Analysis",
        border_style="blue"
    ))

    # Reachability matrix
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="bold")
    table.add_column()

    def _bool_icon(value: bool) -> str:
        return "[green]✓ Yes[/green]" if value else "[red]✗ No[/red]"

    table.add_row("Can reach host:", _bool_icon(reach.can_reach_host))
    table.add_row("Can reach LAN:", _bool_icon(reach.can_reach_lan))
    table.add_row("Can reach Internet:", _bool_icon(reach.can_reach_internet))

    console.print(table)
    console.print()

    # Published ports table
    if reach.published_ports:
        ports_table = Table(
            title="[bold]Published Ports[/bold]",
            show_lines=False,
            box=box.SIMPLE
        )
        ports_table.add_column("Host IP", style="cyan")
        ports_table.add_column("Host Port", style="yellow", justify="right")
        ports_table.add_column("Container Port", style="green", justify="right")
        ports_table.add_column("From LAN", justify="center")
        ports_table.add_column("From Internet", justify="center")

        for p in reach.published_ports:
            ports_table.add_row(
                p.host_ip,
                p.host_port,
                p.container_port,
                "✓" if p.reachable_from_lan else "✗",
                "✓" if p.reachable_from_internet else "✗",
            )

        console.print(ports_table)
    else:
        console.print("[dim]No host ports published for this container.[/dim]")

    # Notes and warnings
    if reach.notes:
        console.print("\n[bold]Analysis Notes:[/bold]")
        for n in reach.notes:
            console.print(f"  • {n}")

    console.print()


@app.command("scan-compose")
def scan_compose(
    file: str = typer.Argument(..., help="Path to docker-compose.yml file")
) -> None:
    """
    Scan docker-compose.yml for security issues (preview).

    This feature is planned but not yet implemented. It will analyze
    docker-compose files before deployment to detect risky configurations.

    Example:
        dockerscope scan-compose docker-compose.yml
    """
    console.print(Panel(
        f"[yellow]⚠️  Docker Compose scanning is not yet implemented.[/yellow]\n\n"
        f"[dim]Received file:[/dim] [cyan]{file}[/cyan]\n\n"
        f"[bold]Planned features:[/bold]\n"
        f"  • Parse docker-compose.yml and detect risky configurations\n"
        f"  • Pre-deployment security warnings\n"
        f"  • Suggest configuration improvements\n"
        f"  • Generate secure docker-compose templates\n\n"
        f"[dim]For now, use:[/dim]\n"
        f"  1. Deploy containers: [cyan]docker-compose up -d[/cyan]\n"
        f"  2. Analyze with: [cyan]dockerscope analyze[/cyan]",
        title="Docker Compose Scanner (Preview)",
        border_style="yellow"
    ))


def main() -> None:
    """CLI entry point."""
    app()


if __name__ == "__main__":
    main()