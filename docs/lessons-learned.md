# Lessons learned

Problems I hit while building Aegis Fusion, with the root cause of each and what I changed. None of these were planned. Each one is also a small piece of evidence for why the project works the way it does.

## 1. The project folder was locked down

**Symptom:** VS Code refused to save a new file with `EPERM: operation not permitted`.

**Root cause:** I had opened an Administrator PowerShell, which starts in `C:\Windows\system32`, and cloned the repository there. Moving the folder to my user directory kept the restrictive permissions, so an ordinary (non-admin) editor could read the files but not write to them.

**Fix:** Reset ownership and permissions on the project folder (`takeown` and `icacls /reset`) from one admin window, then closed it and worked from a normal terminal.

**Lesson:** Do not work from an elevated terminal or inside a protected system folder. Running everything as admin also hides permission problems that would appear on a normal setup.

## 2. `requirements.txt` was committed as a binary file

**Symptom:** Git printed `Bin` for `requirements.txt` and showed 0 insertions.

**Root cause:** In Windows PowerShell 5.1, `pip freeze > requirements.txt` writes UTF-16. Git treats UTF-16 as binary.

**Fix:** Regenerated the file with an explicit encoding, finally as plain ASCII, and checked that GitHub showed it as text.

**Lesson:** The same shell command behaves differently across platforms. Verify what a generated file really contains before committing it.

## 3. Bandit's exit code hid a missing install

**Symptom:** The CLI crashed with `JSONDecodeError: Expecting value`.

**Root cause:** Bandit exits with code 1 when it finds issues, so the wrapper accepted exit codes 0 and 1. I had run it outside the virtual environment, so Bandit was not installed. Python reported that with exit code 1 too, and the wrapper tried to parse empty output.

**Fix:** Treat empty output as an error whatever the exit code, and raise a readable message that includes the tool's error text.

**Lesson:** A security scanner that fails quietly, or fails confusingly, is worse than one that fails loudly.

## 4. A clean result on a bad sample

**Symptom:** Gitleaks said `no leaks found` on a folder that was supposed to contain secrets.

**Root cause:** `config.py` was empty because I had not saved the file. The scanner was correct, and my test setup was wrong.

**Fix:** Saved the file and reran. Gitleaks then found both secrets.

**Lesson:** Never trust a scanner's "clean" result until it has been proven on input known to be bad. The pipeline now does this on every run (see lesson 8).

## 5. Trivy exits 0 even when it finds problems

**Symptom:** The first Trivy scan reported 117 vulnerabilities and an exit code of 0.

**Root cause:** Bandit, pip-audit, Gitleaks, and Checkov exit 1 when they find something. Trivy exits 0 unless asked otherwise.

**Fix:** Each scanner wrapper follows its own tool's convention. For Trivy, only a non-zero exit or empty output is an error, and the policy engine alone decides pass or fail.

**Lesson:** Do not assume tools share conventions. A pipeline that read "exit 0" as "all clear" would have missed everything Trivy found.

## 6. A Docker Hub timeout in CI

**Symptom:** The CI security job failed with `Unable to find image ... Client.Timeout exceeded`, twice in a row.

**Root cause:** The scanner images were pulled from Docker Hub in the middle of a scan, and the registry did not answer in time. The CLI exited with code 2.

**Fix:** A separate CI step pulls the images first, with four attempts and growing waits. Later I pinned the images by digest so CI and my laptop run the exact same scanners.

**Lesson:** Exit code 2 earned its place. The failure was reported as "the scan broke", not as a clean pass and not as a fake security finding.

## 7. The Merge button stayed active on a failing check

**Symptom:** A pull request with a failing security check still offered **Merge pull request**.

**Root cause:** A check that is not marked required is only advice.

**Fix:** A repository ruleset requires both `tests` and `security-scan` and requires a pull request for every change, with an empty bypass list. The same failing pull request then had a disabled merge button.

**Lesson:** A security gate has to be enforced by the platform, not just reported.

## 8. The tests passed while the code was still wrong

**Symptom:** After pinning the scanner images, all tests passed, but two scanners still used unpinned names.

**Root cause:** The test only checked the pinned list in `images.py`. It could not see scanner modules that ignored it.

**Fix:** Added a test that reads every scanner module and fails if one defines its own image. It caught the Checkov module immediately.

**Lesson:** A passing test only proves what it checks. When a check passes suspiciously easily, ask what it would have missed.

## 9. Too much noise in the dependency findings

**Symptom:** pip-audit produced about 90 lines, 43 of them for Django, and many were duplicates.

**Root cause:** pip-audit reports some advisories more than once and gives no severity.

**Fix:** Deduplicate by advisory ID, group rows by package in the report, and set severity in `configs/policies.yaml`.

**Lesson:** A report people cannot read does not get acted on.

## 10. Generated reports ended up in Git

**Symptom:** `reports/aegis.json` and `reports/aegis.md` appeared in a commit.

**Root cause:** My `.gitignore` edit had not been saved when I ran `git add .`.

**Fix:** `git rm -r --cached reports`, then added `reports/` to `.gitignore`, and squash-merged so the files never reached `main`'s history.

**Lesson:** Run `git status` before `git add .` and read what it says.

## 11. Git slips once `main` was protected

**Symptom:** Commits landed on my local `main`, and pushes were rejected. Several times I deleted a local branch before opening its pull request.

**Root cause:** Once `main` required pull requests, every change needed a branch. I ran my cleanup commands (`git checkout main`, `git branch -D`) straight after pushing instead of after the pull request merged.

**Fix:** Nothing was ever lost. Git prints the commit ID when a branch is deleted, and `git checkout -b new-name <commit-id>` brought the work back. I also learned to run `git reset --hard origin/main` only on a clean tree, after the commit has been saved on a branch.

**Lesson:** Clean up after the merge, not before. Know how to recover with the commit ID.

## 12. My personal email was in the commit history

**Symptom:** The merge box showed my personal email address as the commit author.

**Root cause:** Git used my real address by default, and the repository is public.

**Fix:** Turned on GitHub's private email and the setting that blocks pushes that expose it, and set my local Git email to GitHub's noreply address.

**Lesson:** Earlier commits keep the old address. Rewriting history was not worth breaking a public repository for, so this only protects future commits.

## 13. Code pasted into the wrong place

**Symptom:** `IndentationError`, then a circular import error (`cannot import name 'run_gitleaks'` from the module itself).

**Root cause:** Code pasted into the wrong tab, and snippets pasted into the middle of existing code, which changed the indentation Python depends on.

**Fix:** Replaced whole files instead of patching them, and added quick `Select-String` checks after each change.

**Lesson:** Python's indentation is part of the program. Verify what is actually in a file, not what you intended to put there.