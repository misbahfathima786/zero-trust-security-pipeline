from flask import Blueprint, render_template
from flask_login import login_required

from services import runs as run_service

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
