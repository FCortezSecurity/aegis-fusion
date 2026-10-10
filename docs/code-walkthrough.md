# Code walkthrough

This explains the code in plain language, for someone who does not write Python every day. You do not need to memorize any of it. The goal is to know what each part is for and why it exists.

## The idea in one paragraph

Five security tools each scan a folder and each report results in their own format. Aegis Fusion runs them all, translates every result into one common shape, checks that list against a written policy, and answers one question: **pass or fail?** It also writes reports and returns a number (an exit code) that a pipeline can act on.

## How to read the project

Every folder has one job:

| Folder | Job | Analogy |
|---|---|---|
| `src/scanners/` | Run each tool and capture its output | Five inspectors, each filing a report in their own format |
| `src/normalization/` | Translate every report into one format | A translator |
| `src/policy/` | Decide pass or fail from the rules | The rulebook and the judge |
| `src/reporting/` | Write the JSON and Markdown reports | The secretary |
| `src/cli.py` | Run all of it in order | The manager |
| `configs/policies.yaml` | The rules, written as data | The rulebook itself |
| `tests/` | Check the code does what we think | Quality control |
| `.github/workflows/ci.yml` | Run everything automatically on GitHub | The night shift |

## Follow one finding through the system

Take a single Bandit result: line 11 of `app.py` uses `shell=True`.

1. **Scanner** (`bandit_scanner.py`): runs Bandit, which prints a block of JSON. The wrapper returns that JSON as a Python dictionary.
2. **Adapter** (`adapters.py`): `from_bandit` builds a `Finding` from it: tool `bandit`, rule `B602`, severity `HIGH`, file `app.py`, line 11.
3. **Policy** (`engine.py`): `evaluate` sees that `HIGH` is in the `fail_on` list in `policies.yaml`, so the finding becomes a **blocking** finding.
4. **Report** (`report.py`): the finding appears as one row in the Markdown table.
5. **CLI** (`cli.py`): because at least one finding is blocking, `main` returns exit code `1`.
6. **CI**: GitHub sees the exit code and marks the check red. Because the check is required, the pull request cannot be merged.

## File by file

### `src/cli.py` (the manager)

- `main()` is the entry point. It reads the command-line options (the folder to scan, `--json`, `--markdown`, and so on).
- It then does five steps in order: load the policy, run every scanner (`collect_findings`), evaluate the findings, write the reports, print a summary.
- Everything risky sits inside a `try` block. If something breaks (Docker not running, a bad policy file), the `except` block prints the message and returns **exit code 2**.
- The three exit codes are named constants at the top: `EXIT_PASS = 0`, `EXIT_FAIL = 1`, `EXIT_ERROR = 2`.
- The last two lines, `if __name__ == "__main__": sys.exit(main())`, mean "run `main` when this file is started directly, and hand its number to the operating system".

### `src/scanners/` (the inspectors)

Each file does the same four things:

1. Build a command and run it with `subprocess.run`. Python acts as if you had typed the command in a terminal, and captures what it prints.
2. Check the exit code. Each tool has its own meaning for exit code 1 (see `docs/lessons-learned.md`).
3. Refuse empty output, because empty output means something went wrong.
4. Turn the printed JSON text into a Python dictionary with `json.loads`.

Gitleaks, Checkov, and Trivy run **inside Docker containers**: `docker run --rm -v <folder>:/scan:ro <image> ...`. The `:ro` means the scanner can read your files but cannot change them. The image names come from `images.py`, which pins each one to an exact digest.

### `src/normalization/finding.py` (the common shape)

- `Finding` is a small record with seven fields: `tool`, `rule_id`, `severity`, `title`, `file`, `line`, `fix`.
- `@dataclass(frozen=True)` tells Python to write the boring parts for us, and to make the record **unchangeable** after it is created, so no later step can quietly lower a severity.
- `__post_init__` runs when a `Finding` is created and **rejects any severity that is not CRITICAL, HIGH, MEDIUM, LOW, or INFO**. A typo fails immediately instead of slipping through.

### `src/normalization/adapters.py` (the translator)

- One function per scanner (`from_bandit`, `from_checkov`, and so on). Each takes that tool's raw output and returns a list of `Finding` objects.
- `normalize_severity` cleans up severity words. `MODERATE` becomes `MEDIUM`, and **anything unknown becomes `HIGH`**. Treating the unknown as serious is called "failing safe": if the code is wrong, it is wrong in the direction that blocks a build.
- Several lines use a **list comprehension**, such as `[Finding(...) for r in results]`. Read it as "make one `Finding` for every item in `results`".

### `configs/policies.yaml` and `src/policy/config.py` (the rulebook)

- `thresholds` lists which severities fail the build (`fail_on`) and which only warn (`warn_on`).
- `severity_map` supplies severities for tools that do not report one. Checkov has a default (MEDIUM) and per-rule overrides (for example `CKV_AWS_24: HIGH`).
- `severity_for` picks in this order: the rule's own entry, then the tool's default, then a fallback.
- The file is loaded with `yaml.safe_load`, never plain `yaml.load`. The unsafe one can run code hidden in a file, which is the same Bandit warning (B506) your sample app triggers on purpose.

### `src/policy/engine.py` (the judge)

- `evaluate(findings, policy)` counts findings by severity and sorts them into **blocking** (severity in `fail_on`) and **warnings** (severity in `warn_on`).
- It returns a `Verdict` holding `passed`, the counts, and both lists. `passed` is true only when the blocking list is empty.
- If the policy contains a severity name that does not exist, such as `CRITCAL`, it **raises an error** instead of ignoring it. Otherwise one typo would quietly switch off the whole gate.

### `src/reporting/report.py` (the secretary)

- `build_report` makes the JSON report, with every finding.
- `render_markdown` makes the human-readable report.
- `group_findings` combines all pip-audit findings for one package into a single row, so Django appears once with a count.

### `src/scanners/images.py` (the pins)

Holds the exact Docker images the scanners run, pinned by digest (a fingerprint of the image contents). CI pre-pulls exactly these, so CI and your laptop run the same scanners. A test fails if anyone goes back to an unpinned name.

### `.github/workflows/ci.yml` (the night shift)

- **tests** job: installs the project and runs the unit tests.
- **security-scan** job (after tests): pre-pulls the scanner images with retries, scans `src` (must pass), scans `samples/vulnerable_app` (must **fail** with exit code 1, which proves the gate works), then uploads the reports.
- Steps marked `if: always()` run even when an earlier step failed, because the reports matter most on failing runs.

### `tests/unit/` (quality control)

- `pytest` runs every function whose name starts with `test_`. An `assert` line passes if the statement is true and fails if not.
- Most tests use small made-up findings, so they run in milliseconds and **need no Docker**.
- `test_cli.py` replaces the scanners with fake ones (`monkeypatch`), so it can test the exit codes without running any scan.

## Python ideas used in this project

| Idea | What it means here |
|---|---|
| Function | A named block of code, like `evaluate(...)`, that takes inputs and returns a result |
| List and dictionary | A list is an ordered group of items. A dictionary stores labelled values, like `{"severity": "HIGH"}` |
| Import | `from src.scanners.images import TRIVY_IMAGE` borrows something defined in another file |
| `try` / `except` | "Try this, and if it fails, do that instead of crashing" |
| `raise` | Stop on purpose and report an error |
| f-string | Text with values inside it, like `f"Scan of {target}"` |
| Type hints | Notes like `target: Path` that describe expected inputs. Python does not enforce them, but they help readers |
| Exit code | A number a program returns when it finishes. 0 means success, anything else means something happened |

## Try it yourself

These small experiments make the code feel real. Undo each one afterwards with `git checkout -- <file>`.

1. **Change the rules.** In `configs/policies.yaml`, change `fail_on` to `[CRITICAL]` and rerun `python -m src.cli samples/vulnerable_app`. The blocking count should drop from 63 to 1.
2. **Change one rule.** Under `checkov`, change `CKV_AWS_24: HIGH` to `LOW`. The blocking count should drop by one.
3. **Break the policy on purpose.** Change `fail_on` to `[CRITCAL]`. The run should stop with an error and exit code 2.
4. **Read a test.** Open `tests/unit/test_engine.py` and find the test that checks that a typo in the policy raises an error. Then find the line in `engine.py` that makes it pass.

## Questions you may be asked

**Why three exit codes?** So that a broken scan can never look like a clean pass or like a security failure. A Docker Hub timeout in CI really did exit with code 2.

**Why does the pipeline scan a deliberately vulnerable folder?** It is a self-test. If that scan ever stops failing, the gate is broken, and the build fails.

**Why pin the Docker images?** So a new scanner release cannot change results between runs. Vulnerability data is still fetched fresh, on purpose, so new CVEs are caught.

**What would you improve next?** Look up real CVSS scores for pip-audit findings, run the image scan in CI, and pin the GitHub Actions to commit SHAs. All three are in the README's Limitations.

**Did you write this alone?** Be straightforward: you built it with AI guidance, debugged the real failures yourself (`docs/lessons-learned.md` is the record), and can explain every layer. This file is here so that last part is true.