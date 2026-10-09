import argparse
import os
from pathlib import Path

from src.scanners.bandit_scanner import run_bandit
from src.scanners.checkov_scanner import run_checkov
from src.scanners.gitleaks_scanner import run_gitleaks
from src.scanners.pip_audit_scanner import run_pip_audit
from src.scanners.trivy_scanner import run_trivy_config, run_trivy_image


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="aegis", description="Aegis Fusion: security scanning automation"
    )
    parser.add_argument("target", type=Path, help="Folder to scan")
    parser.add_argument(
        "--image", help="Also scan this container image, e.g. python:3.8-slim"
    )
    args = parser.parse_args()

    if not args.target.exists():
        parser.error(f"Target not found: {args.target}")

    # --- Bandit: code issues ---
    bandit_data = run_bandit(args.target)
    results = bandit_data.get("results", [])
    print(f"== Bandit: {len(results)} issue(s) ==")
    for r in results:
        print(
            f"[{r['issue_severity']}] {r['test_id']} "
            f"{r['filename']}:{r['line_number']} - {r['issue_text']}"
        )

    # --- pip-audit: vulnerable dependencies ---
    audit_data = run_pip_audit(args.target)
    vulnerable = []
    total_unique = 0
    for dep in audit_data["dependencies"]:
        unique = {}
        for v in dep.get("vulns", []):
            unique.setdefault(v["id"], v)
        if unique:
            vulnerable.append((dep["name"], dep["version"], unique))
            total_unique += len(unique)

    print(
        f"\n== pip-audit: {len(vulnerable)} vulnerable package(s), "
        f"{total_unique} unique vulnerabilities =="
    )
    for name, version, unique in vulnerable:
        print(f"{name} {version} - {len(unique)} known vulnerabilities")
        for vuln_id, v in list(unique.items())[:3]:
            fixes = ", ".join(v.get("fix_versions", [])) or "no fix listed"
            print(f"    {vuln_id} (fix: {fixes})")
        if len(unique) > 3:
            print(f"    ...and {len(unique) - 3} more")

    # --- Gitleaks: hardcoded secrets ---
    leaks = run_gitleaks(args.target)
    print(f"\n== Gitleaks: {len(leaks)} secret(s) ==")
    for leak in leaks:
        rel = os.path.relpath(leak["File"])
        print(f"[{leak['RuleID']}] {rel}:{leak['StartLine']} - {leak['Description']}")

    # --- Checkov: infrastructure-as-code misconfigurations ---
    checkov = run_checkov(args.target)
    failed = checkov["failed"]
    print(
        f"\n== Checkov: {len(failed)} failed check(s), "
        f"{checkov['passed']} passed =="
    )
    for c in failed:
        rel = os.path.relpath(c["file_path"])
        line = c["file_line_range"][0]
        print(f"[{c['check_id']}] {rel}:{line} - {c['check_name']} ({c['resource']})")

    # --- Trivy: Dockerfile misconfigurations ---
    docker_findings = run_trivy_config(args.target)
    print(f"\n== Trivy (Dockerfile): {len(docker_findings)} issue(s) ==")
    for f in docker_findings:
        rel = os.path.relpath(f["file"])
        print(f"[{f['severity']}] {f['id']} {rel}:{f['line']} - {f['title']}")

    # --- Trivy: container image vulnerabilities (optional) ---
    if args.image:
        img = run_trivy_image(args.image)
        counts = img["counts"]
        print(
            f"\n== Trivy (image {img['image']}): "
            f"{counts['CRITICAL']} CRITICAL, {counts['HIGH']} HIGH =="
        )
        for c in img["critical"]:
            fixed = c["fixed"] or "no fix available"
            print(f"[CRITICAL] {c['id']} {c['package']} {c['installed']} (fix: {fixed})")


if __name__ == "__main__":
    main()