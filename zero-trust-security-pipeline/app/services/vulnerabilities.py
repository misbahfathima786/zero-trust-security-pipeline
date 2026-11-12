"""Service for Trivy Vulnerability Scan Results (Page 5).

Provides structured access to vulnerability findings, summary counts,
detailed remediation recommendations, and machine-readable report exports.
"""
import json
from pathlib import Path
from datetime import datetime, timezone
from app.services import runs as run_service

REPORTS_DIR = Path(__file__).resolve().parents[2] / "reports"
TRIVY_SECURITY_DIR = Path(__file__).resolve().parents[2] / "security" / "trivy"

# Detailed descriptions and remediation information for standard findings
VULN_DETAILS_LOOKUP = {
    "SAMPLE-0001": {
        "cve": "CVE-2023-49083",
        "title": "NULL pointer dereference in PKCS7 parsing",
        "description": "A NULL pointer dereference flaw was found in the PKCS7 parsing code when processing crafted PKCS7 signatures. An attacker could exploit this vulnerability to cause a denial of service (application crash).",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2023-49083",
            "https://github.com/pyca/cryptography/security/advisories/GHSA-jfhm-5ghh-2f97",
        ],
        "remediation": "Upgrade cryptography to version 41.0.4 or higher.",
    },
    "SAMPLE-0002": {
        "cve": "CVE-2023-30861",
        "title": "Session cookie disclosure with custom response handlers",
        "description": "In Flask versions prior to 2.3.4, when an application registers a custom response handler or stream, cached responses can mistakenly include Set-Cookie headers across requests, leaking session credentials.",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2023-30861",
            "https://github.com/pallets/flask/security/advisories/GHSA-m2bg-8356-55pw",
        ],
        "remediation": "Upgrade Flask to version 2.3.4 or higher.",
    },
    "SAMPLE-0003": {
        "cve": "CVE-2023-46136",
        "title": "Denial of Service via high resource consumption in multipart parser",
        "description": "Werkzeug's multipart form parser does not limit the number of parts or file headers properly. An attacker sending a specially crafted multipart/form-data payload can consume excessive CPU and memory, causing application unresponsiveness.",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2023-46136",
            "https://github.com/pallets/werkzeug/security/advisories/GHSA-2g68-c3qc-8985",
        ],
        "remediation": "Upgrade Werkzeug to version 2.4.0 or higher.",
    },
    "SAMPLE-0004": {
        "cve": "CVE-2024-22195",
        "title": "HTML attribute injection when using the xmlattr filter",
        "description": "Jinja2 versions before 3.1.4 allow attackers to inject arbitrary HTML attributes when templates use the xmlattr filter with untrusted keys containing spaces or special characters.",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2024-22195",
            "https://github.com/pallets/jinja/security/advisories/GHSA-h5c8-rqwp-cp95",
        ],
        "remediation": "Upgrade Jinja2 to version 3.1.4 or higher.",
    },
    "SAMPLE-0005": {
        "cve": "CVE-2024-35195",
        "title": "Proxy-Authorization header leakage across destination origins",
        "description": "When requests handles an HTTP redirect to a different destination hostname or scheme, the Proxy-Authorization header is unintentionally retained, potentially exposing proxy credentials to downstream servers.",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2024-35195",
            "https://github.com/psf/requests/security/advisories/GHSA-9wx4-h78v-vm56",
        ],
        "remediation": "Upgrade requests to version 2.32.0 or higher.",
    },
    "SAMPLE-0006": {
        "cve": "CVE-2020-14343",
        "title": "Arbitrary code execution in FullLoader",
        "description": "A vulnerability in PyYAML allows arbitrary code execution during deserialization when FullLoader or yaml.load without Loader specification is used on untrusted YAML strings.",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2020-14343",
            "https://github.com/yaml/pyyaml/issues/420",
        ],
        "remediation": "Upgrade PyYAML to version 6.0.1 or higher and use yaml.safe_load.",
    },
    "SAMPLE-0007": {
        "cve": "CVE-2023-45803",
        "title": "Request body retention on HTTP 303 See Other redirects",
        "description": "urllib3 previously kept request bodies during HTTP 303 redirects instead of converting the request method to GET and discarding the body, causing potential unintended data resubmission.",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2023-45803",
            "https://github.com/urllib3/urllib3/security/advisories/GHSA-g4mx-q9vg-27p4",
        ],
        "remediation": "Upgrade urllib3 to version 2.0.7 or higher.",
    },
    "SAMPLE-0008": {
        "cve": "CVE-2024-3651",
        "title": "Denial of Service via crafted domain label in idna library",
        "description": "An issue in idna allows remote attackers to cause a Denial of Service (resource consumption) by supplying a crafted domain label containing an excessive sequence of characters requiring Punycode transcoding.",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2024-3651",
        ],
        "remediation": "Upgrade idna to version 3.7 or higher.",
    },
}


def _enrich_finding(raw_finding):
    """Enrich a finding with CVE ID, description, references, and remediation."""
    vuln_id = raw_finding.get("vuln_id", "VULN-UNKNOWN")
    lookup = VULN_DETAILS_LOOKUP.get(vuln_id, {})
    
    cve = lookup.get("cve", vuln_id if vuln_id.startswith("CVE-") else vuln_id)
    title = lookup.get("title", f"Vulnerability in {raw_finding.get('package', 'component')}")
    description = lookup.get(
        "description",
        f"A security vulnerability ({cve}) was detected in package {raw_finding.get('package')} "
        f"version {raw_finding.get('version')}."
    )
    references = lookup.get("references", [
        f"https://nvd.nist.gov/vuln/detail/{cve}" if cve.startswith("CVE-") else "https://trivy.dev"
    ])
    fixed_ver = raw_finding.get("fixed_version")
    remediation = lookup.get(
        "remediation",
        f"Upgrade {raw_finding.get('package')} to {fixed_ver}." if fixed_ver else "No direct patch available. Review dependency requirements."
    )

    return {
        "package": raw_finding.get("package", "Unknown"),
        "version": raw_finding.get("version", "Unknown"),
        "severity": raw_finding.get("severity", "info").lower(),
        "vuln_id": vuln_id,
        "cve": cve,
        "fixed_version": fixed_ver or "No fix available",
        "title": title,
        "description": description,
        "references": references,
        "remediation": remediation,
        "target_type": "dependency",
    }


def get_trivy_scan_data(run_id=None):
    """Retrieve full Trivy scan findings and counts for a specific build or latest with scan data."""
    # Check for external raw report file first
    for candidate_dir in (REPORTS_DIR, TRIVY_SECURITY_DIR):
        report_file = candidate_dir / "trivy-report.json"
        if report_file.is_file():
            try:
                with open(report_file, encoding="utf-8") as fh:
                    raw_data = json.load(fh)
                return _parse_raw_trivy_report(raw_data)
            except Exception:
                pass

    runs = run_service.list_runs()
    selected_run = None

    if run_id is not None:
        selected_run = run_service.get_run(run_id)
    
    # If no specific run requested, find the run with the most comprehensive findings (e.g. Run 40)
    if selected_run is None:
        candidate_runs = [r for r in runs if r.get("vulnerabilities", {}).get("findings")]
        if candidate_runs:
            selected_run = max(candidate_runs, key=lambda r: len(r.get("vulnerabilities", {}).get("findings", [])))
        elif runs:
            selected_run = runs[0]

    if selected_run is None:
        return {
            "run_id": None,
            "commit": "-",
            "branch": "-",
            "timestamp": "-",
            "status": "blocked",
            "counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "dependencies": [],
            "container_images": [],
            "container_scanned": False,
            "is_sample": True,
        }

    raw_vulns = selected_run.get("vulnerabilities", {})
    raw_counts = raw_vulns.get("counts")
    raw_findings = raw_vulns.get("findings") or []

    # Enrich findings
    enriched_findings = [_enrich_finding(f) for f in raw_findings]

    # Calculate actual summary counts from findings if counts is None
    if raw_counts is not None:
        counts = {
            "critical": raw_counts.get("critical", 0),
            "high": raw_counts.get("high", 0),
            "medium": raw_counts.get("medium", 0),
            "low": raw_counts.get("low", 0),
            "info": raw_counts.get("info", 0),
        }
    else:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in enriched_findings:
            sev = f["severity"]
            if sev in counts:
                counts[sev] += 1

    # Container scan data: check if present in run or stages
    container_scanned = False
    container_findings = []
    if "container_vulnerabilities" in selected_run:
        container_scanned = True
        container_findings = selected_run["container_vulnerabilities"].get("findings", [])

    return {
        "run_id": selected_run.get("run_id"),
        "commit": selected_run.get("commit"),
        "branch": selected_run.get("branch"),
        "timestamp": selected_run.get("timestamp"),
        "status": selected_run.get("overall_status"),
        "counts": counts,
        "total_count": sum(counts.values()),
        "dependencies": enriched_findings,
        "container_images": container_findings,
        "container_scanned": container_scanned,
        "is_sample": run_service.is_sample_data(),
    }


def _parse_raw_trivy_report(data):
    """Parse standard Trivy JSON output structure."""
    results = data.get("Results", [])
    dependencies = []
    container_images = []
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    for res in results:
        target_type = res.get("Class", "os-pkgs")
        for v in res.get("Vulnerabilities", []):
            sev = v.get("Severity", "UNKNOWN").lower()
            if sev in counts:
                counts[sev] += 1
            finding = {
                "package": v.get("PkgName", "Unknown"),
                "version": v.get("InstalledVersion", "Unknown"),
                "severity": sev,
                "vuln_id": v.get("VulnerabilityID", "UNKNOWN"),
                "cve": v.get("VulnerabilityID", "UNKNOWN"),
                "fixed_version": v.get("FixedVersion", "No fix available"),
                "title": v.get("Title", "Vulnerability detected"),
                "description": v.get("Description", "No detailed description provided."),
                "references": v.get("References", []),
                "remediation": f"Upgrade {v.get('PkgName')} to {v.get('FixedVersion')}" if v.get("FixedVersion") else "Review advisory.",
                "target_type": "container" if "container" in target_type else "dependency",
            }
            if finding["target_type"] == "container":
                container_images.append(finding)
            else:
                dependencies.append(finding)

    return {
        "run_id": 42,
        "commit": "live",
        "branch": "main",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "passed" if counts["critical"] + counts["high"] == 0 else "failed",
        "counts": counts,
        "total_count": sum(counts.values()),
        "dependencies": dependencies,
        "container_images": container_images,
        "container_scanned": len(container_images) > 0,
        "is_sample": False,
    }


def export_trivy_report_dict(run_id=None):
    """Generate a clean Trivy-compatible JSON report dictionary for download."""
    data = get_trivy_scan_data(run_id)
    return {
        "SchemaVersion": 2,
        "CreatedAt": datetime.now(timezone.utc).isoformat(),
        "ArtifactName": "securebuild-pipeline",
        "ArtifactType": "repository",
        "Metadata": {
            "OS": {"Family": "debian", "Name": "12 (bookworm)"},
            "ImageConfig": {"architecture": "amd64"},
            "RunId": data.get("run_id"),
            "Commit": data.get("commit"),
            "Branch": data.get("branch"),
        },
        "Results": [
            {
                "Target": "requirements.txt",
                "Class": "lang-pkgs",
                "Type": "pip",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": f["cve"],
                        "PkgName": f["package"],
                        "InstalledVersion": f["version"],
                        "FixedVersion": f["fixed_version"] if f["fixed_version"] != "No fix available" else None,
                        "Severity": f["severity"].upper(),
                        "Title": f["title"],
                        "Description": f["description"],
                        "References": f["references"],
                    }
                    for f in data.get("dependencies", [])
                ],
            }
        ],
    }
