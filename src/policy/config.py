from pathlib import Path

import yaml

# Resolved from this file's location, so it works from any working directory.
DEFAULT_POLICY_PATH = Path(__file__).resolve().parents[2] / "configs" / "policies.yaml"


def load_policy(path: Path = DEFAULT_POLICY_PATH) -> dict:
    """Load and sanity-check the policy file."""
    with open(path, encoding="utf-8") as fh:
        policy = yaml.safe_load(fh)
    if not isinstance(policy, dict) or "thresholds" not in policy:
        raise ValueError(f"Invalid policy file (missing 'thresholds'): {path}")
    return policy


def severity_for(policy: dict, tool: str, rule_id: str, fallback: str = "HIGH") -> str:
    """Pick a severity: rule override, then tool default, then the fallback."""
    tool_map = (policy.get("severity_map") or {}).get(tool, {})
    rule_level = (tool_map.get("rules") or {}).get(rule_id)
    return rule_level or tool_map.get("default") or fallback