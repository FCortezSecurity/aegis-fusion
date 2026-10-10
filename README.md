# Aegis Fusion

A DevSecOps security automation tool. It runs five open-source scanners against a project, converts their very different outputs into one common format, applies a written policy to decide pass or fail, writes JSON and Markdown reports, and enforces the result in GitHub Actions, so a change that fails the scan cannot be merged.

![Unified scan result: findings by tool and severity, blocking findings, RESULT: FAIL, exit code 1](docs/images/05-unified-report.png)

*One command, five scanners, one verdict. The exit code is what CI uses as the gate.*

## What it scans

| Scanner | Looks for | Runs on |
|---|---|---|
| [Bandit](https://github.com/PyCQA/bandit) | Insecure Python code | Source files |
| [pip-audit](https://github.com/pypa/pip-audit) | Dependencies with known vulnerabilities | `requirements.txt` |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Hardcoded secrets | Any file |
| [Checkov](https://github.com/bridgecrewio/checkov) | Terraform misconfigurations | `.tf` files |
| [Trivy](https://github.com/aquasecurity/trivy) | Dockerfile misconfigurations and vulnerable image packages | Dockerfiles, container images |

Gitleaks, Checkov, and Trivy run in Docker, so nothing else needs installing.

![Bandit, pip-audit and Gitleaks results in one run](docs/images/03-all-three-scanners.png)

![Checkov, Trivy Dockerfile and Trivy image results](docs/images/04-iac-and-container-scanners.png)

## Quick start

Requires Python 3.14 (what I develop and test on) and Docker.

```powershell
git clone https://github.com/FCortezSecurity/aegis-fusion.git
cd aegis-fusion
python -m venv .venv
.\.venv\Scripts\Activate.ps1      # Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
```

Scan the included sample, which is intentionally vulnerable:

```powershell
python -m src.cli samples/vulnerable_app
```

Options:

| Flag | Effect |
|---|---|
| `--json PATH` | Write a machine-readable JSON report |
| `--markdown PATH` | Write a human-readable Markdown report |
| `--image NAME` | Also scan a container image, e.g. `python:3.8-slim` |
| `--policy PATH` | Use a different policy file |
| `--all` | List every blocking finding instead of the first 15 |

The first run pulls the scanner images and Trivy's vulnerability database, so it takes a few minutes.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Policy satisfied |
| `1` | Policy violated: findings at a blocking severity |
| `2` | The scan itself broke (Docker not running, bad policy file, scanner error) |

## How it works

```
scan target
    -> scanners (Bandit, pip-audit, Gitleaks, Checkov, Trivy)
    -> adapters convert each tool's output into a common Finding
    -> policy engine compares findings against configs/policies.yaml
    -> reports (JSON + Markdown) and an exit code
    -> GitHub Actions uses the exit code as the merge gate
```

Every finding is converted into the same shape (`tool`, `rule_id`, `severity`, `title`, `file`, `line`, `fix`) with severity on one scale: CRITICAL, HIGH, MEDIUM, LOW, INFO. Some tools report no severity at all, so the policy file decides.

```yaml
# configs/policies.yaml (excerpt)
thresholds:
  fail_on: [CRITICAL, HIGH]   # any finding at these levels fails the build
  warn_on: [MEDIUM]           # reported, but does not fail the build

severity_map:
  checkov:
    default: MEDIUM
    rules:
      CKV_AWS_24: HIGH        # SSH open to the whole internet
```

### Reports

Dependency vulnerabilities are grouped by package, so Django shows up as one row with 43 advisories instead of 43 lines. The JSON report keeps every finding.

![Markdown report with grouped dependency findings](docs/images/12b-grouped-dependencies.png)

CI writes the reports to the run summary and uploads them as a build artifact on every run, including failed ones.

![Uploaded aegis-reports artifact](docs/images/13-artifacts.png)

## The CI security gate

Every pull request runs the unit tests and then the scan. A failing scan turns the check red:

![Failed CI run: tests passed, security-scan failed with exit code 1](docs/images/08-ci-red.png)

`main` is protected by a repository ruleset. A pull request needs both `tests` and `security-scan` to pass, and nobody can bypass the rule or push directly to `main`. The same failing check that earlier left the merge button active now blocks it:

![Merge pull request button disabled because required checks failed](docs/images/07b-pr-merge-blocked.png)

A clean change gets through:

![Pull request ready to merge, all checks passed](docs/images/11-pr-ready-to-merge.png)

![Branch ruleset: pull request required, status checks required, force pushes blocked](docs/images/10-branch-ruleset.png)

### The gate tests itself

The pipeline scans the project's own code (`src`), which must pass, and then scans `samples/vulnerable_app`, which must fail with exit code 1. If that second scan ever returns 0 or 2, the build fails, because a gate that cannot catch known-bad code gives false confidence.

![Report for the project's own code (PASS) above the report for the vulnerable sample (FAIL)](docs/images/14-pass-and-fail-reports.png)

## Design decisions

- **Three exit codes.** A crashed scan must never look like a clean pass or like a security failure. This happened for real: a Docker Hub timeout in CI exited with code 2 instead of silently passing.
- **Fail safe.** An unknown severity label is treated as HIGH, and a typo in the policy thresholds raises an error instead of quietly disabling the gate.
- **Per-tool exit-code handling.** Bandit, pip-audit, Gitleaks, and Checkov exit 1 when they find something. Trivy exits 0 even when it does. Each wrapper treats its tool correctly, and empty output counts as a failure.
- **One format.** Findings are an immutable dataclass that validates its severity. Adapters keep the scanners' quirks out of the policy engine.
- **Severity lives in config.** For tools without severity, the mapping is in `configs/policies.yaml`, not buried in code.
- **Least privilege.** Scanner containers mount the target read-only, Gitleaks output is redacted, the workflow token is read-only, runners are pinned to `ubuntu-24.04`, and image pulls are retried.
- **Reports on failure.** Reports are written before the exit code is returned and uploaded with `if: always()`, because failing runs are the ones people need to read.

## Limitations

- **pip-audit reports no severity.** Every advisory defaults to HIGH, so dependency findings dominate the counts. Looking up CVSS scores would fix this.
- **Checkov severities are hand-assigned** in the policy file for the checks seen so far. Everything else defaults to MEDIUM.
- **Scanner images use `:latest`**, so results can change between runs. Pinning versions is the next hardening step. GitHub Actions are pinned by version tag, not commit SHA.
- **Scanner coverage overlaps only partly.** Gitleaks missed the low-entropy `SuperSecret123!` that Bandit caught, which is why several tools run.
- **Narrow scope.** Checkov scans Terraform only, Trivy's config scan covers Dockerfiles only, and the image scan runs on request (`--image`) and not in CI.
- **Not built:** a web dashboard and Windows endpoint telemetry, both optional in my original plan.

## Project layout

```
.github/workflows/ci.yml    CI: tests, security gate, self-test, reports
configs/policies.yaml       thresholds and severity mapping
src/cli.py                  command-line entry point
src/scanners/               one wrapper per scanner
src/normalization/          Finding format and per-tool adapters
src/policy/                 policy loading and pass/fail engine
src/reporting/              JSON and Markdown reports, dependency grouping
tests/unit/                 unit tests (no Docker needed)
samples/vulnerable_app/     intentionally vulnerable scan targets
docs/images/                screenshots
```

Run the tests with:

```powershell
python -m pytest tests -v
```

## A note on the samples

Everything in `samples/vulnerable_app` is intentionally insecure and exists only as a scan target. Do not copy that code into real projects or install its dependencies.

## License

MIT