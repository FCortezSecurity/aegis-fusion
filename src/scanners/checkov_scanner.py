import json
import subprocess
from pathlib import Path

CHECKOV_IMAGE = "bridgecrew/checkov"


def run_checkov(target: Path) -> dict:
    """Run Checkov (via Docker) on Terraform files in a folder."""
    host_path = target.resolve()
    try:
        result = subprocess.run(
            [
                "docker", "run", "--rm",
                "-v", f"{host_path}:/tf:ro",
                CHECKOV_IMAGE,
                "-d", "/tf",
                "--framework", "terraform",
                "-o", "json",
            ],
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        raise RuntimeError("Docker not found. Install Docker Desktop and start it.")

    # Checkov exits 1 when checks FAIL. That is not a crash.
    if result.returncode not in (0, 1):
        raise RuntimeError(
            f"Checkov failed (exit {result.returncode}). Is Docker running? "
            f"{result.stderr.strip()}"
        )

    output = result.stdout
    # Skip any text before the JSON starts, whichever bracket comes first
    starts = [i for i in (output.find("{"), output.find("[")) if i != -1]
    if not starts:
        # No JSON at all: fine if nothing failed, an error otherwise
        if result.returncode == 1:
            raise RuntimeError("Checkov reported failures but produced no JSON.")
        return {"failed": [], "passed": 0}

    data = json.loads(output[min(starts):])
    blocks = data if isinstance(data, list) else [data]

    failed = []
    passed = 0
    for block in blocks:
        checks = block.get("results", {})
        failed.extend(checks.get("failed_checks", []))
        passed += len(checks.get("passed_checks", []))

    # Translate container paths (/main.tf) to real paths on this machine
    for check in failed:
        check["file_path"] = str(host_path / check["file_path"].lstrip("/"))

    return {"failed": failed, "passed": passed}