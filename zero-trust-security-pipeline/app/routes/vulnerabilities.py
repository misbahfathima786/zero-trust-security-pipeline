import json
from flask import Blueprint, render_template, request, jsonify, Response
from flask_login import login_required

from app.services import vulnerabilities as vuln_service

vulnerabilities_bp = Blueprint("vulnerabilities", __name__)


@vulnerabilities_bp.route("/")
@login_required
def index():
    """Page 5: Trivy Vulnerability Scan Results."""
    run_id = request.args.get("run_id")
    scan_data = vuln_service.get_trivy_scan_data(run_id)
    return render_template(
        "vulnerabilities/index.html",
        scan=scan_data,
        is_sample=scan_data.get("is_sample", False),
    )


@vulnerabilities_bp.route("/download")
@login_required
def download_report():
    """Download machine-readable Trivy report in JSON format."""
    run_id = request.args.get("run_id")
    report_dict = vuln_service.export_trivy_report_dict(run_id)
    filename = f"trivy-report-build-{report_dict['Metadata'].get('RunId') or 'latest'}.json"
    
    return Response(
        json.dumps(report_dict, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment;filename={filename}"},
    )


@vulnerabilities_bp.route("/api/findings")
@login_required
def api_findings():
    """API endpoint to retrieve findings with optional severity filter."""
    run_id = request.args.get("run_id")
    severity = request.args.get("severity", "all").lower()
    scan_data = vuln_service.get_trivy_scan_data(run_id)
    
    findings = scan_data.get("dependencies", [])
    if severity != "all":
        findings = [f for f in findings if f["severity"] == severity]

    return jsonify({
        "run_id": scan_data.get("run_id"),
        "counts": scan_data.get("counts"),
        "total": len(findings),
        "findings": findings,
    })
