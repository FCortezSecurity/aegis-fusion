# Architecture

Aegis Fusion is a pipeline of small layers. Each layer does one job and knows as little as possible about the others.

```
scan target
    -> scanners        run each tool, check its exit code, parse its output
    -> normalization   convert every tool's output into a common Finding
    -> policy          decide pass or fail from configs/policies.yaml
    -> reporting       JSON and Markdown reports
    -> CLI             print a summary and return an exit code
    -> CI              GitHub Actions uses the exit code as the merge gate
```

## Layers

### Scanners (`src/scanners/`)

One wrapper per tool: `bandit_scanner.py`, `pip_audit_scanner.py`, `gitleaks_scanner.py`, `checkov_scanner.py`, `trivy_scanner.py`. A wrapper runs the tool, handles that tool's exit-code convention, rejects empty output, and returns the parsed result. It knows nothing about policy or severity levels.

Gitleaks, Checkov, and Trivy run in Docker. The target folder is mounted read-only, Gitleaks output is redacted, and Trivy keeps its vulnerability database in a named Docker volume so it is downloaded once.

### Normalization (`src/normalization/`)

- `finding.py` defines `Finding`, an immutable dataclass: `tool`, `rule_id`, `severity`, `title`, `file`, `line`, `fix`. It refuses any severity outside CRITICAL, HIGH, MEDIUM, LOW, INFO.
- `adapters.py` has one function per tool that converts raw output into `Finding` objects, plus `normalize_severity`, which translates aliases (for example `MODERATE` to `MEDIUM`) and treats an unknown label as HIGH.

### Policy (`src/policy/`)

- `config.py` loads `configs/policies.yaml`. `severity_for` picks a severity in this order: a rule-specific override, then the tool's default, then a fallback.
- `engine.py` has `evaluate`, which counts findings by severity and returns a `Verdict`: passed or failed, plus the blocking findings and the warnings. A severity name in `fail_on` or `warn_on` that doesn't exist raises an error, so a typo cannot silently disable the gate.

### Reporting (`src/reporting/report.py`)

`build_report` produces the JSON report with every finding. `render_markdown` produces the human report. `group_findings` collapses dependency findings into one row per package, so Django appears once with a count.

### CLI (`src/cli.py`)

Runs the scanners, builds the verdict, writes reports, prints the summary, and returns the exit code. Reports are written before the exit code is returned, so failing scans still produce them.

## How severity is decided

| Tool | Where severity comes from |
|---|---|
| Bandit | The tool's own severity |
| Trivy | The tool's own severity; the policy file can override a rule |
| Gitleaks | `configs/policies.yaml` (default HIGH) |
| pip-audit | `configs/policies.yaml` (default HIGH) |
| Checkov | `configs/policies.yaml` (default MEDIUM, with per-rule overrides) |

Example: Checkov reports `CKV_AWS_24` with no severity. The policy file maps it to HIGH, `HIGH` is in `fail_on`, so it becomes a blocking finding and the scan fails.

## Exit codes and failure handling

| Code | Meaning |
|---|---|
| 0 | Policy satisfied |
| 1 | Policy violated |
| 2 | The scan itself broke |

Scanners disagree on exit codes: Bandit, pip-audit, Gitleaks, and Checkov exit 1 when they find something, Trivy exits 0. Each wrapper accepts its tool's real convention, and any other exit code or empty output becomes an error, which the CLI reports as exit 2.

## CI pipeline (`.github/workflows/ci.yml`)

1. **tests** job: installs dependencies and runs the unit tests.
2. **security-scan** job (after tests): pre-pulls the scanner images with retries, scans `src` (must pass), then scans `samples/vulnerable_app` (must fail with exit code 1), writes the reports to the run summary, and uploads them as an artifact.

`main` is protected by a repository ruleset that requires both jobs to pass and a pull request for every change.

## Adding a scanner

1. Add `src/scanners/<tool>_scanner.py` with a function that runs the tool and returns parsed output.
2. Add an adapter to `src/normalization/adapters.py` that returns `Finding` objects.
3. Call both from `collect_findings` in `src/cli.py`, and add the tool name to the `TOOLS` list there.
4. Add a default (and any rule overrides) under `severity_map` in `configs/policies.yaml`.
5. Add unit tests for the adapter in `tests/unit/`.

## Updating the pinned scanner images

The images are pinned in `src/scanners/images.py`. To update one, using Gitleaks as the example:

```
docker pull zricethezav/gitleaks:latest
docker image inspect zricethezav/gitleaks:latest --format "{{index .RepoDigests 0}}"
docker run --rm zricethezav/gitleaks:latest version
```

Put the new digest and version in `images.py`, run `python -m pytest tests -v` and a scan of `samples/vulnerable_app`, and open a pull request. CI will show whether the results changed.