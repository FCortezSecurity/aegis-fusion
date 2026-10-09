# Aegis Fusion security report

- **Target:** `samples/vulnerable_app`
- **Result:** FAIL
- **Generated:** 2026-10-09T20:03:04+00:00

## Summary

| Severity | Findings |
|---|---|
| CRITICAL | 1 |
| HIGH | 62 |
| MEDIUM | 6 |
| LOW | 13 |
| INFO | 0 |

## Findings by tool

| Tool | Findings |
|---|---|
| bandit | 9 |
| checkov | 11 |
| gitleaks | 2 |
| pip-audit | 55 |
| trivy | 5 |

## Blocking findings (63)

_Dependency vulnerabilities are grouped by package._

| Severity | Tool | Rule | Location | Description | Remediation |
|---|---|---|---|---|---|
| CRITICAL | trivy | DS-0031 | `samples\vulnerable_app\Dockerfile:6` | Secrets passed via `build-args` or envs or copied secret files | Use secret mount if secrets are needed during image build. Use volume mount if secret files are needed during container runtime. |
| HIGH | bandit | B602 | `samples\vulnerable_app\app.py:11` | subprocess call with shell=True identified, security issue. | https://bandit.readthedocs.io/en/1.9.4/plugins/b602_subprocess_popen_with_shell_equals_true.html |
| HIGH | bandit | B324 | `samples\vulnerable_app\app.py:15` | Use of weak MD5 hash for security. Consider usedforsecurity=False | https://bandit.readthedocs.io/en/1.9.4/plugins/b324_hashlib.html |
| HIGH | checkov | CKV_AWS_20 | `samples\vulnerable_app\main.tf:2` | S3 Bucket has an ACL defined which allows public READ access. (aws_s3_bucket.data) | https://docs.prismacloud.io/en/enterprise-edition/policy-reference/aws-policies/s3-policies/s3-1-acl-read-permissions-everyone |
| HIGH | checkov | CKV_AWS_24 | `samples\vulnerable_app\main.tf:7` | Ensure no security groups allow ingress from 0.0.0.0:0 to port 22 (aws_security_group.open) | https://docs.prismacloud.io/en/enterprise-edition/policy-reference/aws-policies/aws-networking-policies/networking-1-port-security |
| HIGH | gitleaks | generic-api-key | `samples\vulnerable_app\config.py:2` | Detected a Generic API Key, potentially exposing access to various services and sensitive operations. | Remove the secret from source, rotate it, and load it from a secrets manager or environment variable. |
| HIGH | gitleaks | generic-api-key | `samples\vulnerable_app\config.py:3` | Detected a Generic API Key, potentially exposing access to various services and sensitive operations. | Remove the secret from source, rotate it, and load it from a secrets manager or environment variable. |
| HIGH | pip-audit | 43 advisories | `django==2.2.0` | django==2.2.0: 43 known vulnerabilities | Upgrade the package to a release that fixes these advisories. |
| HIGH | pip-audit | 4 advisories | `flask==0.12.2` | flask==0.12.2: 4 known vulnerabilities | Upgrade the package to a release that fixes these advisories. |
| HIGH | pip-audit | 3 advisories | `pyyaml==5.1` | pyyaml==5.1: 3 known vulnerabilities | Upgrade the package to a release that fixes these advisories. |
| HIGH | pip-audit | 5 advisories | `requests==2.19.0` | requests==2.19.0: 5 known vulnerabilities | Upgrade the package to a release that fixes these advisories. |
| HIGH | trivy | DS-0002 | `samples\vulnerable_app\Dockerfile:3` | Image user should not be 'root' | Add 'USER <non root user name>' line to the Dockerfile |

## Warnings (6)

| Severity | Tool | Rule | Location | Description | Remediation |
|---|---|---|---|---|---|
| MEDIUM | bandit | B506 | `samples\vulnerable_app\app.py:19` | Use of unsafe yaml load. Allows instantiation of arbitrary objects. Consider yaml.safe_load(). | https://bandit.readthedocs.io/en/1.9.4/plugins/b506_yaml_load.html |
| MEDIUM | bandit | B301 | `samples\vulnerable_app\app.py:23` | Pickle and modules that wrap it can be unsafe when used to deserialize untrusted data, possible security issue. | https://bandit.readthedocs.io/en/1.9.4/blacklists/blacklist_calls.html#b301-pickle |
| MEDIUM | bandit | B307 | `samples\vulnerable_app\app.py:27` | Use of possibly insecure function - consider using safer ast.literal_eval. | https://bandit.readthedocs.io/en/1.9.4/blacklists/blacklist_calls.html#b307-eval |
| MEDIUM | checkov | CKV2_AWS_6 | `samples\vulnerable_app\main.tf:2` | Ensure that S3 bucket has a Public Access block (aws_s3_bucket.data) | https://docs.prismacloud.io/en/enterprise-edition/policy-reference/aws-policies/aws-networking-policies/s3-bucket-should-have-public-access-blocks-defaults-to-false-if-the-public-access-block-is-not-attached |
| MEDIUM | checkov | CKV_AWS_145 | `samples\vulnerable_app\main.tf:2` | Ensure that S3 buckets are encrypted with KMS by default (aws_s3_bucket.data) | https://docs.prismacloud.io/en/enterprise-edition/policy-reference/aws-policies/aws-general-policies/ensure-that-s3-buckets-are-encrypted-with-kms-by-default |
| MEDIUM | trivy | DS-0004 | `samples\vulnerable_app\Dockerfile:7` | Port 22 exposed | Remove 'EXPOSE 22' statement from the Dockerfile |
