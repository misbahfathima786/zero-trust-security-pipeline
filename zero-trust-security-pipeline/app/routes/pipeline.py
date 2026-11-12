from flask import Blueprint, redirect, render_template, url_for
from flask_login import login_required

from app.services import runs as run_service

pipeline_bp = Blueprint("pipeline", __name__)


@pipeline_bp.route("/")
@login_required
def latest():
    """Sidebar 'Pipeline' link: open the most recent build."""
    run = run_service.latest_run()
    if run is None:
        return render_template("pipeline/not_found.html", run_id=None), 200
    return redirect(url_for("pipeline.detail", run_id=run["run_id"]))


@pipeline_bp.route("/<run_id>")
@login_required
def detail(run_id):
    run = run_service.get_run(run_id)
    if run is None:
        # Unknown or malformed id: friendly page, real 404 status.
        return render_template("pipeline/not_found.html", run_id=run_id), 404

    older_id, newer_id = run_service.neighbours(run["run_id"])
    return render_template(
        "pipeline/detail.html",
        run=run,
        stages=run_service.stage_view(run),
        duration=run_service.format_duration(run["duration_s"]),
        older_id=older_id,
        newer_id=newer_id,
        is_sample=run_service.is_sample_data(),
    )
