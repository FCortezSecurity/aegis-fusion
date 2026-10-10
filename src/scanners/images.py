"""Container images used by the scanners, pinned by digest.

A digest pins the exact image contents, so a new upstream release cannot change
results between runs. Update these deliberately, in a pull request.
The comment on each line is the version the digest was taken from.
"""

GITLEAKS_IMAGE = "zricethezav/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"  # v8.30.1
CHECKOV_IMAGE = "bridgecrew/checkov@sha256:8e63f217cb084f1c1a067326a9cf6e37d54bdc82e5822210d50ca4e2f647dd93"  # 3.3.26
TRIVY_IMAGE = "aquasec/trivy@sha256:af6acf9a6b85dfe389a1941505c0ce9efef52a4719635e1a962f022a3d855daa"  # 0.75.0

ALL_IMAGES = [GITLEAKS_IMAGE, CHECKOV_IMAGE, TRIVY_IMAGE]

if __name__ == "__main__":
    # CI uses this to pre-pull exactly the images the code will run.
    print("\n".join(ALL_IMAGES))