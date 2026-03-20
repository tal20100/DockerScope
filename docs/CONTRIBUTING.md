# Contributing to DockerScope

Thanks for your interest in contributing! This guide covers everything you need to get started.

## Development setup

1. Clone and install in editable mode with dev dependencies:

```bash
git clone https://github.com/tal20100/DockerScope.git
cd DockerScope
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -e ".[dev]"
```

2. Verify everything works:

```bash
pytest
ruff check .
```

## How to add a new risk detection rule

DockerScope's risk detection lives in `dockerscope/core/risks.py`. Each rule checks a specific container configuration and produces a `Risk` object.

### Step-by-step

**1. Choose severity and risk type**

Pick a severity level (CRITICAL, HIGH, MEDIUM, LOW) and a unique `risk_type` string:

```python
# Example: detect containers with no health check
risk_type = "no_healthcheck"
severity = "LOW"
```

**2. Add the detection logic in `evaluate_container_risks()`**

Open `dockerscope/core/risks.py` and add your check inside the appropriate severity section:

```python
# In evaluate_container_risks(), under LOW RISKS section:

# Rule N: No health check configured
healthcheck = getattr(container, 'healthcheck', None)
if healthcheck is None or healthcheck == {}:
    risks.append(
        Risk(
            container=container.name,
            risk_type="no_healthcheck",
            description="Container has no health check configured.",
            details={
                "impact": "Container failures may go undetected"
            },
        )
    )
```

**3. Register the severity in `get_risk_severity()`**

Add your risk type to the appropriate set:

```python
low_types = {
    "running_as_root",
    "unpinned_image",
    "no_healthcheck",  # Add here
}
```

**4. Add remediation advice in `get_remediation_advice()`**

```python
"no_healthcheck": (
    "Add a HEALTHCHECK instruction to the Dockerfile, or configure "
    "health checks in docker-compose.yml using the healthcheck key."
),
```

**5. Register the scoring penalty in `dockerscope/core/scorer.py`**

Add an entry to `SEVERITY_PENALTIES`:

```python
SEVERITY_PENALTIES = {
    # ...existing entries...
    "no_healthcheck": 3,  # LOW
}
```

**6. Add the field to ContainerInfo if needed**

If your rule needs data that isn't already in `ContainerInfo`, add the field to `dockerscope/models/container.py` and extract it in `dockerscope/core/discovery.py`:

```python
# In container.py:
@dataclass
class ContainerInfo:
    # ...existing fields...
    healthcheck: dict | None = None

# In discovery.py, inside _extract_container_info():
healthcheck = config.get("Healthcheck")
```

**7. Write tests**

Add tests in `tests/test_risks.py` or `tests/test_risks_comprehensive.py`:

```python
def test_no_healthcheck_detected():
    c = _base_container()  # healthcheck defaults to None
    risks = evaluate_container_risks(c)
    assert any(r.risk_type == "no_healthcheck" for r in risks)

def test_healthcheck_present_no_risk():
    c = _base_container(healthcheck={"Test": ["CMD", "curl", "-f", "http://localhost/"]})
    risks = evaluate_container_risks(c)
    assert not any(r.risk_type == "no_healthcheck" for r in risks)
```

**8. Update compose scanner if applicable**

If the risk can be detected from a docker-compose file, add the mapping in `dockerscope/core/compose_scanner.py`:

```python
# In _service_to_container_info():
healthcheck = svc.get("healthcheck")
```

## Running tests locally

```bash
# Run all tests
pytest

# Run with coverage report
pytest --cov=dockerscope --cov-report=term-missing --cov-fail-under=80

# Run a specific test file
pytest tests/test_risks.py

# Run a specific test
pytest tests/test_risks.py::test_privileged_container_is_critical

# Run with verbose output
pytest -v
```

## Linting

```bash
# Check for issues
ruff check .

# Auto-fix what can be fixed
ruff check --fix .

# Check formatting
ruff format --check .

# Auto-format
ruff format .
```

## How to add a new CLI command

1. Add the command function in `dockerscope/cli.py`:

```python
@app.command()
def my_command(
    arg: str = typer.Argument(..., help="Description of the argument"),
    flag: bool = typer.Option(False, "--flag", "-f", help="Description of the flag"),
) -> None:
    """
    One-line description shown in --help.

    Longer description of what the command does and when to use it.

    Example:
        dockerscope my-command some-arg --flag
    """
    # Implementation here
    console.print("[green]Done![/green]")
```

2. Add tests in `tests/test_cli.py` using `CliRunner`:

```python
class TestMyCommand:
    def test_basic_usage(self):
        result = runner.invoke(app, ["my-command", "test-arg"])
        assert result.exit_code == 0

    def test_with_flag(self):
        result = runner.invoke(app, ["my-command", "test-arg", "--flag"])
        assert result.exit_code == 0
```

## PR checklist

Before opening a pull request, verify:

- [ ] `pytest --cov=dockerscope --cov-fail-under=80` passes
- [ ] `ruff check .` passes with zero errors
- [ ] `ruff format --check .` passes
- [ ] New functions have Google-style docstrings with Args/Returns/Raises
- [ ] New functions have type annotations (Python 3.11+ syntax)
- [ ] Tests cover both positive and negative cases
- [ ] Error messages tell the user what to do next, not just what went wrong
- [ ] No hardcoded paths — use `pathlib.Path`
- [ ] No secrets or credentials in the code

## Code style

- Type annotations: use `X | None` instead of `Optional[X]`
- Docstrings: Google style with Args/Returns/Raises sections
- Imports: sorted by `ruff` (stdlib, third-party, local)
- Line length: 100 characters (configured in `pyproject.toml`)
- No `Any` types except where the Docker SDK returns untyped dicts

## Project structure

```
dockerscope/
├── cli.py              # Typer CLI commands
├── core/
│   ├── discovery.py    # Container discovery via Docker SDK
│   ├── risks.py        # Risk detection rules
│   ├── reachability.py # Network reachability analysis
│   ├── scorer.py       # Security scoring (0-100)
│   └── compose_scanner.py  # Static compose file analysis
├── attack/
│   └── attack_graph.py # NetworkX attack path modeling
├── config/
│   └── load_config.py  # YAML config loading
└── models/
    ├── container.py    # ContainerInfo dataclass
    ├── risk.py         # Risk dataclass
    └── host.py         # HostNetworkSnapshot dataclass
```
