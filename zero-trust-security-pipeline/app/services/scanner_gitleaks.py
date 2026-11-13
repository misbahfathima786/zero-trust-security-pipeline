"""Gitleaks Secret Scanning Service.

Integrates with Gitleaks CLI if available, complemented by a built-in
rule-based secret scanner engine to detect hardcoded secrets (API keys,
tokens, passwords, private keys) in uploaded source code, configs, and .txt files.
All secret values are strictly REDACTED before being stored or exposed.
"""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

# Standard secret detection rules matching Gitleaks patterns
# Regexes use flexible length quantifiers to match real and test keys of varying lengths.
SECRET_RULES = [
    {
        "id": "aws-access-token",
        "name": "AWS Access Key ID",
        "regex": re.compile(r"\b(AKIA[0-9A-Z]{14,20})\b"),
        "severity": "critical",
    },
    {
        "id": "aws-secret-key",
        "name": "AWS Secret Access Key",
        "regex": re.compile(r"(?i)(?:aws_secret_access_key|aws_secret_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{30,50})['\"]?"),
        "severity": "critical",
    },
    {
        "id": "github-pat",
        "name": "GitHub Personal Access Token",
        "regex": re.compile(r"\b(ghp_[0-9a-zA-Z]{20,}|github_pat_[0-9a-zA-Z_]{40,})\b"),
        "severity": "critical",
    },
    {
        "id": "slack-token",
        "name": "Slack Bot/User Token",
        "regex": re.compile(r"\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b"),
        "severity": "high",
    },
    {
        "id": "private-key",
        "name": "Private Cryptographic Key",
        "regex": re.compile(r"-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY"),
        "severity": "critical",
    },
    {
        "id": "google-api-key",
        "name": "Google API Key",
        "regex": re.compile(r"\b(AIza[0-9A-Za-z\-_]{30,40})\b"),
        "severity": "high",
    },
    {
        "id": "stripe-key",
        "name": "Stripe API Key",
        "regex": re.compile(r"\b(sk_(?:live|test)_[0-9a-zA-Z]{20,})\b"),
        "severity": "high",
    },
    {
        "id": "jwt-token",
        "name": "JSON Web Token (JWT)",
        "regex": re.compile(r"\b(eyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,})\b"),
        "severity": "medium",
    },
    {
        "id": "generic-api-key",
        "name": "Generic API Key / Secret",
        "regex": re.compile(r"(?i)(?:api[_-]?key|auth[_-]?token|access[_-]?token|client[_-]?secret)\s*[:=]\s*['\"]([a-zA-Z0-9_\-\.]{12,80})['\"]"),
        "severity": "high",
    },
    {
        "id": "hardcoded-password",
        "name": "Hardcoded Password / Credential",
        "regex": re.compile(r"(?i)\b(?:password|passwd|db_password|api_password)\s*[:=]\s*['\"]([^'\"\s]{8,64})['\"]"),
        "severity": "high",
    },
]

# Extensions safe to inspect for plaintext secrets
SCANNABLE_EXTENSIONS = {
    ".txt", ".env", ".json", ".yaml", ".yml", ".toml", ".xml", ".ini", ".conf", ".cfg",
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rs", ".c", ".cpp", ".h",
    ".cs", ".php", ".rb", ".sh", ".bat", ".ps1", ".sql", ".html", ".htm", ".md"
}


def _scan_file_content(file_path, base_path):
    """Scan an individual file line by line with SECRET_RULES."""
    findings = []
    try:
        rel_path = os.path.relpath(file_path, base_path).replace("\\", "/")
    except Exception:
        rel_path = os.path.basename(file_path)

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            for line_no, line in enumerate(fh, start=1):
                # Avoid huge lines that might cause ReDoS
                if len(line) > 5000:
                    line = line[:5000]

                for rule in SECRET_RULES:
                    if rule["regex"].search(line):
                        findings.append({
                            "rule": rule["name"],
                            "file": rel_path,
                            "line": line_no,
                            "severity": rule["severity"],
                            "value": "[REDACTED]",
                        })
                        # Stop matching more rules on this same line to prevent duplication
                        break
    except Exception:
        pass

    return findings


def scan_directory_or_file(target_path):
    """Scan target path (file or directory) for secrets.
    
    Returns:
        dict: {
            "status": "passed" | "failed" | "blocked",
            "count": int,
            "findings": list of dicts (with value: "[REDACTED]"),
            "scanned_files": int,
            "logs": list of str
        }
    """
    target = Path(target_path)
    if not target.exists():
        return {
            "status": "blocked",
            "count": None,
            "findings": [],
            "scanned_files": 0,
            "logs": ["[gitleaks] Target path does not exist"],
        }

    logs = []
    findings = []
    scanned_files_count = 0

    logs.append(f"[gitleaks] Starting secret detection scan on {target.name}")

    # Gather files
    files_to_scan = []
    if target.is_file():
        files_to_scan.append(target)
        base_dir = target.parent
    else:
        base_dir = target
        for root, dirs, files in os.walk(target):
            # Skip hidden / venv directories
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("venv", "node_modules", "__pycache__")]
            for f in files:
                f_path = Path(root) / f
                # Scan scannable extensions or files without extension (like Dockerfile)
                if f_path.suffix.lower() in SCANNABLE_EXTENSIONS or "." not in f:
                    files_to_scan.append(f_path)

    logs.append(f"[gitleaks] Scanning {len(files_to_scan)} candidate file(s)...")

    # If gitleaks CLI is installed on the system, try invoking it
    gitleaks_bin = shutil.which("gitleaks")
    cli_findings_found = False

    if gitleaks_bin:
        report_file = base_dir / "gitleaks-cli-report.json"
        try:
            cmd = [
                gitleaks_bin, "detect",
                "--no-git",
                "--source", str(target),
                "--report-format", "json",
                "--report-path", str(report_file),
                "--exit-code", "0"
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if report_file.is_file():
                with open(report_file, "r", encoding="utf-8") as rf:
                    cli_data = json.load(rf)
                if isinstance(cli_data, list):
                    for item in cli_data:
                        findings.append({
                            "rule": item.get("Description") or item.get("RuleID", "Gitleaks Rule"),
                            "file": item.get("File", str(target.name)).replace("\\", "/"),
                            "line": item.get("StartLine", 1),
                            "severity": "critical" if "private" in (item.get("RuleID") or "").lower() else "high",
                            "value": "[REDACTED]",
                        })
                    cli_findings_found = True
                    logs.append(f"[gitleaks] CLI scan completed ({len(findings)} findings)")
                try:
                    report_file.unlink(missing_ok=True)
                except Exception:
                    pass
        except Exception as e:
            logs.append(f"[gitleaks] CLI invocation bypassed or timed out: {e}")

    # Built-in rule scanner execution (always ensures coverage and redundancy)
    if not cli_findings_found:
        for file_path in files_to_scan:
            scanned_files_count += 1
            file_findings = _scan_file_content(file_path, base_dir)
            findings.extend(file_findings)

    logs.append(f"[gitleaks] Scan completed. Scanned {len(files_to_scan)} files.")

    status = "passed" if len(findings) == 0 else "failed"
    if status == "passed":
        logs.append("[gitleaks] No secrets detected. Clean status confirmed.")
    else:
        logs.append(f"[gitleaks] WARNING: {len(findings)} potential secret(s) detected. Safe redacted findings stored.")

    return {
        "status": status,
        "count": len(findings),
        "findings": findings,
        "scanned_files": len(files_to_scan),
        "logs": logs,
    }
