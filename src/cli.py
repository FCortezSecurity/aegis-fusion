import argparse
import json
import subprocess
import sys
from pathlib import Path


def run_bandit(target: Path) -> dict:
    """Run Bandit against a folder and return its parsed JSON output."""
    result = subprocess.run(
        [sys.executable, "-m", "bandit", "-r", str(target), "-f", "json", "-q"],
        capture_output=True,
        text=True,
    )
    # Bandit exits 1 when it FINDS issues. That is not a failure.
    if result.returncode not in (0, 1) or not result.stdout.strip():
        raise RuntimeError(
            f"Bandit failed (exit {result.returncode}): {result.stderr.strip()}"
        )
    return json.loads(result.stdout)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="aegis", description="Aegis Fusion: security scanning automation"
    )
    parser.add_argument("target", type=Path, help="Folder to scan")
    args = parser.parse_args()

    if not args.target.exists():
        parser.error(f"Target not found: {args.target}")

    data = run_bandit(args.target)
    results = data.get("results", [])
    print(f"Bandit found {len(results)} issue(s)")
    for r in results:
        print(
            f"[{r['issue_severity']}] {r['test_id']} "
            f"{r['filename']}:{r['line_number']} - {r['issue_text']}"
        )


if __name__ == "__main__":
    main()