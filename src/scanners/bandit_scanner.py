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