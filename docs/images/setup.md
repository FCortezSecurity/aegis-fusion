# Setup

## Requirements

- Python 3.14 (the version I develop and test on; other versions are untested)
- Git
- Docker, running (Docker Desktop on Windows and macOS). Gitleaks, Checkov, and Trivy run in containers.

## Install

Windows PowerShell:

```powershell
git clone https://github.com/FCortezSecurity/aegis-fusion.git
cd aegis-fusion
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Linux and macOS:

```bash
git clone https://github.com/FCortezSecurity/aegis-fusion.git
cd aegis-fusion
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

`requirements.txt` pins exact versions, so your scanner versions match CI.

## Check the install

The unit tests need no Docker:

```
python -m pytest tests -v
```

Then check Docker and run a first scan:

```
docker version
python -m src.cli samples/vulnerable_app
```

The first scan downloads the scanner images and Trivy's vulnerability database, which takes a few minutes. It should finish with `RESULT: FAIL` and exit code 1, because the sample is intentionally vulnerable.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `error: Docker not found` or `Is Docker running?` (exit code 2) | Start Docker Desktop and wait for it to say the engine is running. |
| `Unable to find image ... Client.Timeout exceeded` (exit code 2) | Docker Hub was slow. Run it again; pulled images are cached afterwards. |
| PowerShell refuses to run `Activate.ps1` | Run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once, then activate again. |
| `ModuleNotFoundError: No module named 'src'` | Run commands from the project root, using `python -m src.cli`. |
| `No module named bandit` | The virtual environment isn't active. Activate it and try again. |
| Strange permission errors on Windows | Don't work from an Administrator terminal or inside a protected folder such as `C:\Windows`. |