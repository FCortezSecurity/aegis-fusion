# Usage

```
python -m src.cli TARGET [options]
```

`TARGET` is the folder to scan. Run from the project root, with the virtual environment active and Docker running.

## Options

| Option | Effect |
|---|---|
| `--json PATH` | Write a JSON report (every finding) |
| `--markdown PATH` | Write a Markdown report (dependencies grouped by package) |
| `--image NAME` | Also scan a container image, for example `python:3.8-slim` |
| `--policy PATH` | Use a different policy file |
| `--all` | List every blocking row instead of the first 15 |

## Examples

Scan a folder and write both reports:

```
python -m src.cli samples/vulnerable_app --json reports/aegis.json --markdown reports/aegis.md
```

Scan the project's own code:

```
python -m src.cli src
```

Include a container image:

```
python -m src.cli samples/vulnerable_app --image python:3.8-slim
```

The `reports/` folder is ignored by git.

## Reading the output

1. **Findings by tool** and **by severity** give the totals.
2. **Blocking findings** are those at a severity listed in `fail_on`. Dependency findings are grouped into one row per package.
3. **Warnings** are findings at a `warn_on` severity. They are reported but do not fail the scan.
4. `RESULT: PASS` or `RESULT: FAIL` is the verdict, and the exit code matches it.

## Exit codes in scripts

| Code | Meaning |
|---|---|
| 0 | Policy satisfied |
| 1 | Policy violated |
| 2 | The scan itself broke |

PowerShell: `echo $LASTEXITCODE`. Bash: `echo $?`.

## Changing the policy

Edit `configs/policies.yaml`.

Make MEDIUM findings block too:

```yaml
thresholds:
  fail_on: [CRITICAL, HIGH, MEDIUM]
```

Change a single Checkov rule:

```yaml
severity_map:
  checkov:
    rules:
      CKV_AWS_21: MEDIUM
```

A misspelled severity (for example `CRITCAL`) raises an error and exits with code 2. It never silently disables the gate.

## JSON report fields

| Field | Meaning |
|---|---|
| `schema_version` | Version of the report format |
| `generated_at` | UTC timestamp |
| `target` | The folder that was scanned |
| `result` | `PASS` or `FAIL` |
| `counts` | Findings per severity |
| `blocking_count`, `warning_count` | Findings at blocking and warning severities |
| `findings` | Every finding: `tool`, `rule_id`, `severity`, `title`, `file`, `line`, `fix` |