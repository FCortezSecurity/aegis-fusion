from dataclasses import asdict, dataclass

# Ordered from most to least severe. The policy engine relies on this order.
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


@dataclass(frozen=True)
class Finding:
    """One security finding, in a format shared by every scanner."""

    tool: str          # which scanner found it: "bandit", "trivy", ...
    rule_id: str       # the scanner's own ID: "B602", "CKV_AWS_24", "CVE-..."
    severity: str      # normalized: CRITICAL, HIGH, MEDIUM, LOW or INFO
    title: str         # short human-readable description
    file: str          # where it was found (path, package, or image name)
    line: int = 0      # line number, or 0 when it doesn't apply
    fix: str = ""      # remediation advice or fixed version, if known

    def __post_init__(self) -> None:
        # Reject bad severities immediately, so a typo in an adapter can't
        # silently slip past the policy engine later.
        if self.severity not in SEVERITIES:
            raise ValueError(
                f"Invalid severity {self.severity!r}; expected one of {SEVERITIES}"
            )

    def to_dict(self) -> dict:
        return asdict(self)