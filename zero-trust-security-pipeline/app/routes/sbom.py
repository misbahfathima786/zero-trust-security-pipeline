import json
from flask import Blueprint, render_template, request, jsonify, Response, redirect, url_for, flash
from flask_login import login_required

from app.services import sbom as sbom_service

sbom_bp = Blueprint("sbom", __name__)


@sbom_bp.route("/")
@login_required
def index():
    """Page 6: Software Bill of Materials (SBOM)."""
    run_id = request.args.get("run_id")
    data = sbom_service.get_sbom_data(run_id)
    return render_template(
        "sbom/index.html",
        sbom=data,
        components=data.get("components", []),
    )


@sbom_bp.route("/export")
@login_required
def export_sbom():
    """Download standard CycloneDX 1.5 JSON SBOM file."""
    run_id = request.args.get("run_id")
    cyclonedx_dict = sbom_service.generate_cyclonedx_sbom(run_id)
    filename = f"securebuild-sbom-build-{run_id or 42}.cdx.json"

    return Response(
        json.dumps(cyclonedx_dict, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment;filename={filename}"},
    )


@sbom_bp.route("/generate", methods=["POST"])
@login_required
def generate():
    """Generate or refresh SBOM artifact for the project."""
    run_id = request.form.get("run_id", 42)
    saved_path = sbom_service.save_generated_sbom(run_id)
    flash("SBOM successfully generated in CycloneDX 1.5 format.", "success")
    return redirect(url_for("sbom.index", run_id=run_id))


@sbom_bp.route("/api/components")
@login_required
def api_components():
    """API endpoint to retrieve SBOM components inventory."""
    run_id = request.args.get("run_id")
    dep_type = request.args.get("type", "all").capitalize()
    license_filter = request.args.get("license", "all")
    
    data = sbom_service.get_sbom_data(run_id)
    comps = data.get("components", [])

    if dep_type in ("Direct", "Transitive"):
        comps = [c for c in comps if c["type"] == dep_type]
    if license_filter != "all":
        comps = [c for c in comps if c["license"] == license_filter]

    return jsonify({
        "total": len(comps),
        "direct_count": sum(1 for c in comps if c["type"] == "Direct"),
        "transitive_count": sum(1 for c in comps if c["type"] == "Transitive"),
        "components": comps,
    })
