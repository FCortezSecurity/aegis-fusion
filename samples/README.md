# Sample targets

Everything in this folder is **intentionally vulnerable** and exists only as a
scan target for Aegis Fusion. It demonstrates the kinds of issues the scanners
are built to catch.

- Do **not** copy this code into real projects.
- Do **not** install the dependencies listed in `requirements.txt`. They are
  old versions with known CVEs and are only scanned, never installed.

| Path | Purpose |
|------|---------|
| `vulnerable_app/app.py` | Python code with hardcoded secrets, shell injection, weak hashing, and unsafe deserialization (Bandit targets) |
| `vulnerable_app/requirements.txt` | Outdated dependencies with known vulnerabilities (pip-audit targets), added in the next step |