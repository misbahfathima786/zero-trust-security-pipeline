"""Trivy Vulnerability Scanning Service.

Integrates with Trivy CLI if installed on the host, complemented by a
built-in manifest vulnerability engine that matches dependency manifests
(requirements.txt, package.json, etc.) against known CVE security advisories.
If non-manifest files (like plain .txt files) are uploaded, Trivy is explicitly
marked as 'not_applicable'.
"""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from packaging import version as pkg_version

# Known vulnerability database with CVE IDs, severity, affected versions, and fixes
KNOWN_ADVISORIES = {
    "cryptography": [
        {
            "cve": "CVE-2023-49083",
            "vuln_id": "CVE-2023-49083",
            "affected_below": "41.0.4",
            "fixed_version": "41.0.4",
            "severity": "critical",
            "title": "NULL pointer dereference in PKCS7 parsing",
            "description": "A NULL pointer dereference flaw was found in the PKCS7 parsing code when processing crafted PKCS7 signatures, causing denial of service.",
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2023-49083",
                "https://github.com/pyca/cryptography/security/advisories/GHSA-jfhm-5ghh-2f97",
            ],
            "remediation": "Upgrade cryptography to version 41.0.4 or higher.",
        }
    ],
    "flask": [
        {
            "cve": "CVE-2023-30861",
            "vuln_id": "CVE-2023-30861",
            "affected_below": "2.3.4",
            "fixed_version": "2.3.4",
            "severity": "high",
            "title": "Session cookie disclosure with custom response handlers",
            "description": "In Flask versions prior to 2.3.4, when an application registers a custom response handler or stream, cached responses can mistakenly include Set-Cookie headers.",
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2023-30861",
                "https://github.com/pallets/flask/security/advisories/GHSA-m2bg-8356-55pw",
            ],
            "remediation": "Upgrade Flask to version 2.3.4 or higher.",
        }
    ],
    "werkzeug": [
        {
            "cve": "CVE-2023-46136",
            "vuln_id": "CVE-2023-46136",
            "affected_below": "3.0.1",
            "fixed_version": "3.0.1",
            "severity": "medium",
            "title": "Denial of Service via high resource consumption in multipart parser",
            "description": "Werkzeug's multipart form parser does not limit the number of parts or file headers properly, causing high CPU and memory usage.",
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2023-46136",
                "https://github.com/pallets/werkzeug/security/advisories/GHSA-2g68-c3qc-8985",
            ],
            "remediation": "Upgrade Werkzeug to version 3.0.1 or higher.",
        }
    ],
    "jinja2": [
        {
            "cve": "CVE-2024-22195",
            "vuln_id": "CVE-2024-22195",
            "affected_below": "3.1.4",
            "fixed_version": "3.1.4",
            "severity": "medium",
            "title": "HTML attribute injection when using the xmlattr filter",
            "description": "Jinja2 versions before 3.1.4 allow attackers to inject arbitrary HTML attributes when templates use xmlattr with untrusted keys.",
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2024-22195",
                "https://github.com/pallets/jinja/security/advisories/GHSA-h5c8-rqwp-cp95",
            ],
            "remediation": "Upgrade Jinja2 to version 3.1.4 or higher.",
        }
    ],
    "requests": [
        {
            "cve": "CVE-2024-35195",
            "vuln_id": "CVE-2024-35195",
            "affected_below": "2.32.0",
            "fixed_version": "2.32.0",
            "severity": "medium",
            "title": "Proxy-Authorization header leakage across destination origins",
            "description": "When requests handles an HTTP redirect to a different destination hostname, Proxy-Authorization headers are retained, exposing credentials.",
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2024-35195",
                "https://github.com/psf/requests/security/advisories/GHSA-9wx4-h78v-vm56",
            ],
            "remediation": "Upgrade requests to version 2.32.0 or higher.",
        }
    ],
    "pyyaml": [
        {
            "cve": "CVE-2020-14343",
            "vuln_id": "CVE-2020-14343",
            "affected_below": "6.0.1",
            "fixed_version": "6.0.1",
            "severity": "critical",
            "title": "Arbitrary code execution in FullLoader",
            "description": "Vulnerability in PyYAML allows arbitrary code execution during deserialization when FullLoader or yaml.load without safe loader is used.",
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2020-14343",
                "https://github.com/yaml/pyyaml/issues/420",
            ],
            "remediation": "Upgrade PyYAML to version 6.0.1 or higher and use yaml.safe_load.",
        }
    ],
    "urllib3": [
        {
            "cve": "CVE-2023-45803",
            "vuln_id": "CVE-2023-45803",
            "affected_below": "2.0.7",
            "fixed_version": "2.0.7",
            "severity": "medium",
            "title": "Request body retention on HTTP 303 See Other redirects",
            "description": "urllib3 previously kept request bodies during HTTP 303 redirects instead of converting the request method to GET and discarding the body.",
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2023-45803",
                "https://github.com/urllib3/urllib3/security/advisories/GHSA-g4mx-q9vg-27p4",
            ],
            "remediation": "Upgrade urllib3 to version 2.0.7 or higher.",
        }
    ],
    "idna": [
        {
            "cve": "CVE-2024-3651",
            "vuln_id": "CVE-2024-3651",
            "affected_below": "3.7",
            "fixed_version": "3.7",
            "severity": "low",
            "title": "Denial of Service via crafted domain label in idna library",
            "description": "An issue in idna allows remote attackers to cause a Denial of Service by supplying a crafted domain label containing an excessive sequence of characters.",
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2024-3651",
            ],
            "remediation": "Upgrade idna to version 3.7 or higher.",
        }
    ],
    "lodash": [
        {
            "cve": "CVE-2021-23337",
            "vuln_id": "CVE-2021-23337",
            "affected_below": "4.17.21",
            "fixed_version": "4.17.21",
            "severity": "high",
            "title": "Command Injection in template function",
            "description": "Lodash versions prior to 4.17.21 are vulnerable to Command Injection via the template function.",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-23337"],
            "remediation": "Upgrade lodash to 4.17.21 or higher.",
        }
    ],
    "express": [
        {
            "cve": "CVE-2024-29041",
            "vuln_id": "CVE-2024-29041",
            "affected_below": "4.19.2",
            "fixed_version": "4.19.2",
            "severity": "high",
            "title": "Open Redirect vulnerability in Express",
            "description": "Express versions before 4.19.2 improperly encode URLs in res.redirect() when unencoded URLs are provided.",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-29041"],
            "remediation": "Upgrade express to 4.19.2 or higher.",
        }
    ],
}

MANIFEST_FILENAMES = {
    "requirements.txt", "Pipfile", "Pipfile.lock", "pyproject.toml",
    "package.json", "package-lock.json", "pom.xml"
}


def _find_manifests(target_path):
    """Find supported dependency manifest files in target path."""
    target = Path(target_path)
    manifests = []
    if target.is_file():
        if target.name.lower() in MANIFEST_FILENAMES:
            manifests.append(target)
    else:
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("venv", "node_modules", "__pycache__")]
            for f in files:
                if f.lower() in MANIFEST_FILENAMES:
                    manifests.append(Path(root) / f)
    return manifests


def _parse_requirements_txt(file_path):
    """Parse packages and versions from requirements.txt."""
    pkgs = []
    req_re = re.compile(r"^([a-zA-Z0-9_\-]+)\s*(?:==|<=|>=|<|>|~=)\s*([0-9a-zA-Z\.\-]+)")
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                m = req_re.match(line)
                if m:
                    pkgs.append({
                        "package": m.group(1).lower(),
                        "version": m.group(2),
                        "file": file_path.name,
                    })
    except Exception:
        pass
    return pkgs


def _parse_package_json(file_path):
    """Parse dependencies from package.json."""
    pkgs = []
    try:
        with open(file_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        deps = data.get("dependencies", {})
        deps.update(data.get("devDependencies", {}))
        for name, ver in deps.items():
            cleaned_ver = re.sub(r"^[\^~>=<]+", "", ver.strip())
            pkgs.append({
                "package": name.lower(),
                "version": cleaned_ver,
                "file": file_path.name,
            })
    except Exception:
        pass
    return pkgs


def _is_vulnerable(installed_version_str, affected_below_str):
    """Compare versions using packaging.version."""
    try:
        inst = pkg_version.parse(installed_version_str)
        aff = pkg_version.parse(affected_below_str)
        return inst < aff
    except Exception:
        # Simple fallback
        return installed_version_str != affected_below_str


def scan_vulnerabilities(target_path):
    """Run Trivy vulnerability scan on project dependencies.

    Returns:
        dict: {
            "status": "passed" | "failed" | "warning" | "not_applicable" | "blocked",
            "counts": {"critical": int, "high": int, "medium": int, "low": int, "info": int} or None,
            "findings": list of finding dicts,
            "manifests_found": list of str,
            "is_applicable": bool,
            "logs": list of str
        }
    """
    target = Path(target_path)
    logs = []
    logs.append(f"[trivy] Inspecting target for dependency manifests...")

    manifests = _find_manifests(target)
    if not manifests:
        logs.append("[trivy] No dependency manifests (requirements.txt, package.json, etc.) detected.")
        logs.append("[trivy] Vulnerability scan is not applicable to plain files or projects without dependencies.")
        return {
            "status": "not_applicable",
            "counts": None,
            "findings": [],
            "manifests_found": [],
            "is_applicable": False,
            "logs": logs,
        }

    manifest_names = [m.name for m in manifests]
    logs.append(f"[trivy] Detected manifest file(s): {', '.join(manifest_names)}")

    findings = []
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    # Check for Trivy CLI
    trivy_bin = shutil.which("trivy")
    cli_success = False

    if trivy_bin:
        report_file = (target if target.is_dir() else target.parent) / "trivy-cli-report.json"
        try:
            cmd = [
                trivy_bin, "fs",
                "--format", "json",
                "--output", str(report_file),
                str(target)
            ]
            logs.append("[trivy] Executing system Trivy scanner...")
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
            if report_file.is_file():
                with open(report_file, "r", encoding="utf-8") as rf:
                    trivy_data = json.load(rf)
                results = trivy_data.get("Results", [])
                for r in results:
                    target_file = r.get("Target", "manifest")
                    for v in r.get("Vulnerabilities", []):
                        sev = v.get("Severity", "info").lower()
                        if sev in counts:
                            counts[sev] += 1
                        findings.append({
                            "package": v.get("PkgName", "unknown"),
                            "version": v.get("InstalledVersion", "unknown"),
                            "severity": sev,
                            "vuln_id": v.get("VulnerabilityID", "UNKNOWN"),
                            "cve": v.get("VulnerabilityID", "UNKNOWN"),
                            "fixed_version": v.get("FixedVersion", "No fix available"),
                            "title": v.get("Title", f"Vulnerability in {v.get('PkgName')}"),
                            "description": v.get("Description", "Security vulnerability detected by Trivy."),
                            "references": v.get("References", []),
                            "remediation": f"Upgrade {v.get('PkgName')} to {v.get('FixedVersion')}" if v.get("FixedVersion") else "Review advisory.",
                            "target_type": "dependency",
                            "file": target_file,
                        })
                cli_success = True
                logs.append(f"[trivy] Trivy CLI scan completed with {len(findings)} finding(s).")
                try:
                    report_file.unlink(missing_ok=True)
                except Exception:
                    pass
        except Exception as e:
            logs.append(f"[trivy] Trivy CLI unavailable or failed: {e}. Falling back to internal engine.")

    # Built-in manifest analysis
    if not cli_success:
        extracted_pkgs = []
        for m in manifests:
            if m.name.lower() == "requirements.txt":
                extracted_pkgs.extend(_parse_requirements_txt(m))
            elif m.name.lower() == "package.json":
                extracted_pkgs.extend(_parse_package_json(m))

        logs.append(f"[trivy] Extracted {len(extracted_pkgs)} dependency package(s) from manifests.")

        for item in extracted_pkgs:
            pkg_name = item["package"]
            inst_ver = item["version"]
            if pkg_name in KNOWN_ADVISORIES:
                for adv in KNOWN_ADVISORIES[pkg_name]:
                    if _is_vulnerable(inst_ver, adv["affected_below"]):
                        sev = adv["severity"]
                        counts[sev] += 1
                        findings.append({
                            "package": pkg_name,
                            "version": inst_ver,
                            "severity": sev,
                            "vuln_id": adv["vuln_id"],
                            "cve": adv["cve"],
                            "fixed_version": adv["fixed_version"],
                            "title": adv["title"],
                            "description": adv["description"],
                            "references": adv["references"],
                            "remediation": adv["remediation"],
                            "target_type": "dependency",
                            "file": item["file"],
                        })

    total_vulns = sum(counts.values())
    if counts["critical"] > 0 or counts["high"] > 0:
        status = "failed"
    elif counts["medium"] > 0 or counts["low"] > 0:
        status = "warning"
    else:
        status = "passed"

    logs.append(f"[trivy] Scan completed: {total_vulns} finding(s) (Critical: {counts['critical']}, High: {counts['high']}, Medium: {counts['medium']}, Low: {counts['low']})")

    return {
        "status": status,
        "counts": counts,
        "findings": findings,
        "manifests_found": manifest_names,
        "is_applicable": True,
        "logs": logs,
    }
