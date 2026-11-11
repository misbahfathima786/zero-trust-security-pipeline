"""Jinja filters shared by the pipeline and scan pages."""
from datetime import datetime, timezone


def _parse(value):
    if not value:
        return None
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def format_datetime(value):
    """'07 Nov 2026, 09:30' (UTC)."""
    dt = _parse(value)
    return dt.strftime("%d %b %Y, %H:%M") if dt else "-"


def time_ago(value):
    dt = _parse(value)
    if not dt:
        return "-"
    seconds = int((datetime.now(timezone.utc) - dt).total_seconds())
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    if seconds < 86400:
        return f"{seconds // 3600}h ago"
    return f"{seconds // 86400}d ago"


def register(app):
    app.add_template_filter(format_datetime, "format_datetime")
    app.add_template_filter(time_ago, "time_ago")
