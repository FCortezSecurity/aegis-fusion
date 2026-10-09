import json
import subprocess
import sys
from pathlib import Path


def run_pip_audit(target: Path) -> dict:
    """Run pip-audit on every requirements.txt under target."""
    merged = {"dependencies": []}

    for req in target.rglob("requirements.txt"):
        result = subprocess.run(
            [
                sys.executable, "-m", "pip_audit",
                "-r", str(req),
                "-f", "json",
                "--progress-spinner", "off",
                "--no-deps",
                "--disable-pip",
            ],
            capture_output=True,
            text=True,
        )
        # pip-audit exits 1 when it FINDS vulnerabilities. That is not a failure.
        if result.returncode not in (0, 1) or not result.stdout.strip():
            raise RuntimeError(
                f"pip-audit failed on {req} (exit {result.returncode}): "
                f"{result.stderr.strip()}"
            )
        merged["dependencies"].extend(json.loads(result.stdout)["dependencies"])

    return merged