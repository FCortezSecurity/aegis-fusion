import json
import subprocess
from pathlib import Path

TRIVY_IMAGE = "aquasec/trivy:latest"
# Named volume so the vulnerability database is downloaded once, not every run
CACHE_MOUNT = ["-v", "aegis-trivy-cache:/root/.cache/"]


def _run_trivy(args: list, mounts: list) -> dict:
    try:
        result = subprocess.run(
            [
                "docker", "run", "--rm",
                *CACHE_MOUNT, *mounts,
                TRIVY_IMAGE, *args,
                "--format", "json", "--quiet",
            ],
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        raise RuntimeError("Docker not found. Install Docker Desktop and start it.")

    # Trivy exits 0 even when it finds problems (unlike the other scanners).
    # So any non-zero exit, or empty output, is a real failure.
    if result.returncode != 0 or not result.stdout.strip():
        raise RuntimeError(
            f"Trivy failed (exit {result.returncode}). Is Docker running? "
            f"{result.stderr.strip()[-500:]}"
        )
    return json.loads(result.stdout)


def run_trivy_config(target: Path) -> list:
    """Scan Dockerfiles in a folder for misconfigurations."""
    host_path = target.resolve()
    data = _run_trivy(
        ["config", "/scan", "--misconfig-scanners", "dockerfile"],
        ["-v", f"{host_path}:/scan:ro"],
    )

    findings = []
    for res in data.get("Results") or []:
        for m in res.get("Misconfigurations") or []:
            if m.get("Status") != "FAIL":
                continue
            findings.append(
                {
                    "id": m.get("ID", "?"),
                    "severity": m.get("Severity", "UNKNOWN"),
                    "title": m.get("Title", ""),
                    "file": str(host_path / res.get("Target", "")),
                    "line": (m.get("CauseMetadata") or {}).get("StartLine", 0),
                    "resolution": m.get("Resolution", ""),
                }
            )
    return findings


def run_trivy_image(image: str) -> list:
    """Scan a container image for HIGH and CRITICAL package vulnerabilities.

    Returns one dict per unique (vulnerability, package) pair.
    """
    data = _run_trivy(
        ["image", "--severity", "HIGH,CRITICAL", "--scanners", "vuln", image],
        [],
    )

    seen = set()
    vulns = []
    for res in data.get("Results") or []:
        for v in res.get("Vulnerabilities") or []:
            key = (v["VulnerabilityID"], v["PkgName"])
            if key in seen:
                continue
            seen.add(key)
            vulns.append(
                {
                    "image": image,
                    "id": v["VulnerabilityID"],
                    "package": v["PkgName"],
                    "installed": v.get("InstalledVersion", ""),
                    "fixed": v.get("FixedVersion", ""),
                    "severity": v.get("Severity", "UNKNOWN"),
                    "title": v.get("Title", ""),
                }
            )
    return vulns