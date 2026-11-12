from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required

from app.services import history as history_service

history_bp = Blueprint("history", __name__)


@history_bp.route("/")
@login_required
def index():
    """Page 7: Security History & Trends."""
    range_key = request.args.get("range", "30d")
    history_data = history_service.get_history_data(range_key)
    return render_template(
        "history/index.html",
        history=history_data,
        range_key=range_key,
    )


@history_bp.route("/api/trends")
@login_required
def api_trends():
    """API endpoint to retrieve vulnerability trend series by date range."""
    range_key = request.args.get("range", "30d")
    history_data = history_service.get_history_data(range_key)
    return jsonify(history_data)
