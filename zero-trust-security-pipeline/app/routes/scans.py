from pathlib import Path
import shutil
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user

from app.extensions import db
from app.models.scan import ScanRun, Project
from app.services import runs as run_service

scans_bp = Blueprint("scans", __name__)


@scans_bp.route("/")
@login_required
def index():
    scans = run_service.list_scans()
    return render_template(
        "scans/index.html",
        scans=scans,
        summaries=run_service.summaries_by_tab(scans),
        scan_types=run_service.SCAN_TYPES,
        is_sample=run_service.is_sample_data(),
    )


@scans_bp.route("/delete/<int:run_id>", methods=["POST"])
@login_required
def delete(run_id):
    """Securely delete a scan run and its associated artifacts."""
    scan = ScanRun.query.filter_by(run_id=run_id, user_id=current_user.id).first()
    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.is_json

    if not scan:
        msg = f"Scan #{run_id} not found or you are not authorized to delete it."
        if is_ajax:
            return jsonify({"success": False, "error": msg}), 404
        flash(msg, "danger")
        return redirect(url_for("dashboard.index"))

    # Cleanup storage directory if exists
    instance_dir = Path(__file__).resolve().parents[2] / "instance"
    storage_root = instance_dir / "uploads" / f"user_{current_user.id}" / f"run_{run_id}"
    if storage_root.exists():
        try:
            shutil.rmtree(storage_root, ignore_errors=True)
        except Exception:
            pass

    # Delete project record if it exists and has no other scans
    project_id = scan.project_id
    db.session.delete(scan)
    if project_id:
        remaining = ScanRun.query.filter(ScanRun.project_id == project_id, ScanRun.run_id != run_id).count()
        if remaining == 0:
            proj = db.session.get(Project, project_id)
            if proj:
                db.session.delete(proj)

    db.session.commit()

    msg = f"Build #{run_id} and associated scan records were deleted successfully."
    if is_ajax:
        return jsonify({"success": True, "message": msg})

    flash(msg, "success")
    # Redirect to where the user came from or dashboard
    ref = request.referrer
    if ref and "/scans" in ref:
        return redirect(url_for("scans.index"))
    return redirect(url_for("dashboard.index"))
