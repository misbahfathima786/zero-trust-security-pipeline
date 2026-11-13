"""Security Policy Evaluation Engine.

Loads policy thresholds from security/policies/security-policy.yaml and
evaluates secrets and vulnerability scanner findings against defined pass/fail rules.
"""
from pathlib import Path
import yaml

POLICY_FILE = Path(__file__).resolve().parents[2] / "security" / "policies" / "security-policy.yaml"

DEFAULT_POLICY = {
    "fail_on_secrets": True,
    "vulnerabilities": {
        "fail_on_critical": True,
        "fail_on_high": True,
        "warn_on_medium": True,
    }
}


def load_policy():
    """Load security policy configuration from YAML file or default fallback."""
    if POLICY_FILE.is_file():
        try:
            with open(POLICY_FILE, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
                if isinstance(data, dict) and "policy" in data:
                    return data["policy"]
        except Exception:
            pass
    return DEFAULT_POLICY


def evaluate_policy(secrets_result, trivy_result):
    """Evaluate pipeline scan findings against security policy.

    Returns:
        dict: {
            "result": "passed" | "failed" | "warning",
            "rules": [
                {"name": str, "result": "passed"|"failed"|"warning"|"skipped", "detail": str}
            ],
            "violations_count": int,
            "passed_count": int,
            "warnings_count": int,
            "logs": list of str
        }
    """
    policy = load_policy()
    rules = []
    logs = ["[policy] Loading security policy rules..."]

    secrets_count = secrets_result.get("count") or 0
    trivy_counts = trivy_result.get("counts") or {"critical": 0, "high": 0, "medium": 0, "low": 0}
    is_trivy_applicable = trivy_result.get("is_applicable", True)

    # Rule 1: Secrets detection
    fail_on_secrets = policy.get("fail_on_secrets", True)
    if fail_on_secrets:
        if secrets_count > 0:
            rules.append({
                "name": "Block secrets detected",
                "result": "failed",
                "detail": f"{secrets_count} potential secret{'s' if secrets_count != 1 else ''} found",
            })
            logs.append(f"[policy] VIOLATION: Rule 'Block secrets detected' failed ({secrets_count} secrets).")
        else:
            rules.append({
                "name": "Block secrets detected",
                "result": "passed",
                "detail": "No secrets found",
            })
            logs.append("[policy] PASSED: Rule 'Block secrets detected'.")
    else:
        rules.append({
            "name": "Block secrets detected",
            "result": "skipped",
            "detail": "Rule disabled in policy",
        })

    # Vulnerability Rules
    vuln_policy = policy.get("vulnerabilities", {})
    fail_crit = vuln_policy.get("fail_on_critical", True)
    fail_high = vuln_policy.get("fail_on_high", True)
    warn_med = vuln_policy.get("warn_on_medium", True)

    if not is_trivy_applicable:
        rules.append({
            "name": "Block critical vulnerabilities",
            "result": "passed",
            "detail": "Not applicable (no package manifest in upload)",
        })
        rules.append({
            "name": "Block high vulnerabilities",
            "result": "passed",
            "detail": "Not applicable (no package manifest in upload)",
        })
        rules.append({
            "name": "Warn on medium vulnerabilities",
            "result": "passed",
            "detail": "Not applicable (no package manifest in upload)",
        })
        logs.append("[policy] Vulnerability rules marked not applicable for this upload type.")
    else:
        crit_count = trivy_counts.get("critical", 0)
        high_count = trivy_counts.get("high", 0)
        med_count = trivy_counts.get("medium", 0)

        # Critical
        if fail_crit:
            if crit_count > 0:
                rules.append({
                    "name": "Block critical vulnerabilities",
                    "result": "failed",
                    "detail": f"{crit_count} critical vulnerabilit{'ies' if crit_count != 1 else 'y'} found",
                })
                logs.append(f"[policy] VIOLATION: Rule 'Block critical vulnerabilities' failed ({crit_count} critical).")
            else:
                rules.append({
                    "name": "Block critical vulnerabilities",
                    "result": "passed",
                    "detail": "No critical findings",
                })
                logs.append("[policy] PASSED: Rule 'Block critical vulnerabilities'.")

        # High
        if fail_high:
            if high_count > 0:
                rules.append({
                    "name": "Block high vulnerabilities",
                    "result": "failed",
                    "detail": f"{high_count} high vulnerabilit{'ies' if high_count != 1 else 'y'} found",
                })
                logs.append(f"[policy] VIOLATION: Rule 'Block high vulnerabilities' failed ({high_count} high).")
            else:
                rules.append({
                    "name": "Block high vulnerabilities",
                    "result": "passed",
                    "detail": "No high findings",
                })
                logs.append("[policy] PASSED: Rule 'Block high vulnerabilities'.")

        # Medium
        if warn_med:
            if med_count > 0:
                rules.append({
                    "name": "Warn on medium vulnerabilities",
                    "result": "warning",
                    "detail": f"{med_count} medium vulnerabilit{'ies' if med_count != 1 else 'y'} found",
                })
                logs.append(f"[policy] WARNING: Rule 'Warn on medium vulnerabilities' triggered ({med_count} medium).")
            else:
                rules.append({
                    "name": "Warn on medium vulnerabilities",
                    "result": "passed",
                    "detail": "No medium findings",
                })
                logs.append("[policy] PASSED: Rule 'Warn on medium vulnerabilities'.")

    failed_rules = sum(1 for r in rules if r["result"] == "failed")
    warning_rules = sum(1 for r in rules if r["result"] == "warning")
    passed_rules = sum(1 for r in rules if r["result"] == "passed")

    if failed_rules > 0:
        overall_result = "failed"
        logs.append(f"[policy] Policy check FAILED with {failed_rules} violation(s).")
    elif warning_rules > 0:
        overall_result = "warning"
        logs.append(f"[policy] Policy check passed with {warning_rules} warning(s).")
    else:
        overall_result = "passed"
        logs.append("[policy] Policy check PASSED. All evaluated rules satisfied.")

    return {
        "result": overall_result,
        "rules": rules,
        "violations_count": failed_rules,
        "passed_count": passed_rules,
        "warnings_count": warning_rules,
        "logs": logs,
    }
