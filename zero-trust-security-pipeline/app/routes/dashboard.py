from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user

from app.services import runs as run_service
from app.services import pipeline_runner

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
@login_required
def index():
    runs = run_service.list_runs()
    total_scans = len(runs)
    passed_scans = sum(1 for r in runs if r.get("overall_status") == "passed")
    failed_scans = sum(1 for r in runs if r.get("overall_status") == "failed")
    warning_scans = sum(1 for r in runs if r.get("overall_status") == "warning")
    latest_scan = runs[0] if runs else None

    # Calculate detected secrets and vulnerabilities count for latest scan
    latest_secrets = latest_scan["secrets"]["count"] if latest_scan and latest_scan.get("secrets") else None
    latest_vulns = None
    if latest_scan and latest_scan.get("vulnerabilities") and latest_scan["vulnerabilities"].get("counts"):
        latest_vulns = sum(latest_scan["vulnerabilities"]["counts"].values())

    return render_template(
        "dashboard/index.html",
        user=current_user,
        runs=runs,
        total_scans=total_scans,
        passed_scans=passed_scans,
        failed_scans=failed_scans,
        warning_scans=warning_scans,
        latest_scan=latest_scan,
        latest_secrets=latest_secrets,
        latest_vulns=latest_vulns,
        is_sample=run_service.is_sample_data(),
    )


@dashboard_bp.route("/upload", methods=["POST"])
@login_required
def upload():
    """Handle project file or archive upload and trigger security pipeline."""
    uploaded_files = request.files.getlist("files")
    # Also support single 'file' input if submitted that way
    if not uploaded_files or (len(uploaded_files) == 1 and not uploaded_files[0].filename):
        single_file = request.files.get("file")
        if single_file and single_file.filename:
            uploaded_files = [single_file]

    # Filter out empty entries
    uploaded_files = [f for f in uploaded_files if f and f.filename]

    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.is_json

    if not uploaded_files:
        msg = "Please select at least one file or project archive to upload and scan."
        if is_ajax:
            return jsonify({"success": False, "error": msg}), 400
        flash(msg, "warning")
        return redirect(url_for("dashboard.index"))

    project_name = request.form.get("project_name", "").strip()
    if not project_name:
        first_name = uploaded_files[0].filename
        project_name = first_name if len(uploaded_files) == 1 else f"Batch ({len(uploaded_files)} files)"

    branch = request.form.get("branch", "main").strip() or "main"

    success, run_id, msg = pipeline_runner.run_pipeline(
        user_id=current_user.id,
        uploaded_files=uploaded_files,
        project_name=project_name,
        custom_branch=branch,
    )

    if is_ajax:
        return jsonify({
            "success": success,
            "run_id": run_id,
            "message": msg,
            "redirect_url": url_for("pipeline.detail", run_id=run_id),
        })

    if success:
        flash(f"Files uploaded successfully! Build #{run_id} scan completed.", "success")
        return redirect(url_for("pipeline.detail", run_id=run_id))
    else:
        flash(f"Upload or scanning error: {msg}", "danger")
        return redirect(url_for("pipeline.detail", run_id=run_id))
