import json
import subprocess
from pathlib import Path

from src.scanners.images import GITLEAKS_IMAGE


def run_gitleaks(target: Path) -> list:
    """Run Gitleaks (via Docker) on a folder and return its list of findings."""
    host_path = target.resolve()
    try:
        result = subprocess.run(
            [
                "docker", "run", "--rm",
                "-v", f"{host_path}:/scan:ro",
                GITLEAKS_IMAGE,
                "dir", "/scan",
                "--no-banner",
                "--redact",
                "--report-format", "json",
                "--report-path", "-",
            ],
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        raise RuntimeError("Docker not found. Install Docker Desktop and start it.")

    # Gitleaks exits 1 when it FINDS leaks. That is not a failure.
    if result.returncode not in (0, 1):
        raise RuntimeError(
            f"Gitleaks failed (exit {result.returncode}). Is Docker running? "
            f"{result.stderr.strip()}"
        )

    output = result.stdout.strip()
    if not output:
        if result.returncode == 1:
            raise RuntimeError("Gitleaks reported leaks but produced no output.")
        return []

    findings = json.loads(output)

    # Translate container paths (/scan/...) back to real paths on this machine
    for f in findings:
        relative = f["File"].removeprefix("/scan/")
        f["File"] = str(host_path / relative)
    return findings