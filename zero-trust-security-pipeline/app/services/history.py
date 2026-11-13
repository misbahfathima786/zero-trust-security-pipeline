"""Service for Security History & Trends (Page 7).

Aggregates historical build scan records, calculates multi-series vulnerability trends
over time, provides risk score and period-over-period trend analysis, and formats
build history for the Recent Builds table.
"""
from datetime import datetime, timezone, timedelta
from app.services import runs as run_service


def _parse_iso(timestamp_str):
    """Safely parse ISO timestamp string to timezone-aware UTC datetime."""
    if not timestamp_str:
        return None
    try:
        # Handle 'Z' suffix
        cleaned = timestamp_str.replace("Z", "+00:00")
        return datetime.fromisoformat(cleaned)
    except Exception:
        return None


def get_history_data(range_key="30d"):
    """Retrieve filtered historical scans, trend series, risk metrics, and recent builds.
    
    range_key: '7d', '30d', '90d', or 'custom'
    """
    all_runs = run_service.list_runs()
    
    # Sort runs chronologically for trend analysis
    sorted_runs = sorted(all_runs, key=lambda r: r.get("timestamp", ""))

    # Completed runs with valid Trivy vulnerability records
    valid_records = []
    for r in sorted_runs:
        vulns = r.get("vulnerabilities", {})
        counts = vulns.get("counts")
        dt = _parse_iso(r.get("timestamp"))

        # Blocked or incomplete scans: flag them properly, do not report as 0
        is_completed = counts is not None and r.get("overall_status") not in ("blocked", "running", "pending")
        
        record = {
            "run_id": r.get("run_id"),
            "commit": r.get("commit"),
            "branch": r.get("branch"),
            "timestamp": r.get("timestamp"),
            "datetime": dt,
            "date_label": dt.strftime("%d %b") if dt else "N/A",
            "full_date_label": dt.strftime("%d %b %I:%M %p") if dt else "N/A",
            "status": r.get("overall_status"),
            "is_completed": is_completed,
            "critical": counts.get("critical", 0) if is_completed else None,
            "high": counts.get("high", 0) if is_completed else None,
            "medium": counts.get("medium", 0) if is_completed else None,
            "low": counts.get("low", 0) if is_completed else None,
            "info": counts.get("info", 0) if is_completed else None,
            "total": sum(counts.values()) if is_completed else None,
        }
        valid_records.append(record)

    # Filter based on range_key
    filtered_records = list(valid_records)
    if valid_records:
        latest_dt = max((rec["datetime"] for rec in valid_records if rec["datetime"]), default=datetime.now(timezone.utc))
        days_map = {"7d": 7, "30d": 30, "90d": 90}
        days = days_map.get(range_key)
        if days:
            cutoff = latest_dt - timedelta(days=days)
            filtered_records = [rec for rec in valid_records if rec["datetime"] and rec["datetime"] >= cutoff]
            # Ensure at least some records are available for display
            if not filtered_records and valid_records:
                filtered_records = valid_records[-5:]

    # Prepare chart series data points
    completed_filtered = [rec for rec in filtered_records if rec["is_completed"]]
    
    dates = [rec["date_label"] for rec in completed_filtered]
    critical_series = [rec["critical"] for rec in completed_filtered]
    high_series = [rec["high"] for rec in completed_filtered]
    medium_series = [rec["medium"] for rec in completed_filtered]
    low_series = [rec["low"] for rec in completed_filtered]

    # Calculate Risk Trend
    # Methodology:
    # Weighted Risk Index = (Critical * 10) + (High * 5) + (Medium * 2) + (Low * 1)
    risk_metric = _calculate_risk_trend(completed_filtered)

    # Recent Builds table (ordered descending by run_id)
    recent_builds = sorted(filtered_records, key=lambda rec: rec["run_id"], reverse=True)

    return {
        "range_key": range_key,
        "labels": dates,
        "critical_series": critical_series,
        "high_series": high_series,
        "medium_series": medium_series,
        "low_series": low_series,
        "risk_metric": risk_metric,
        "recent_builds": recent_builds,
        "has_data": len(completed_filtered) > 0,
        "total_evaluated_builds": len(filtered_records),
    }


def _calculate_risk_trend(records):
    """Calculate transparent risk metrics comparing current period to previous period."""
    if not records:
        return {
            "current_findings": 0,
            "previous_findings": 0,
            "delta": 0,
            "percent_change": 0,
            "direction": "neutral",
            "status_text": "Insufficient data to calculate risk trend.",
            "weighted_score": 0,
        }

    midpoint = len(records) // 2
    if midpoint == 0:
        curr = records[-1]
        curr_total = curr["total"] or 0
        weighted = (curr["critical"] * 10) + (curr["high"] * 5) + (curr["medium"] * 2) + (curr["low"] * 1)
        return {
            "current_findings": curr_total,
            "previous_findings": curr_total,
            "delta": 0,
            "percent_change": 0,
            "direction": "neutral",
            "status_text": "Risk level stable across initial build.",
            "weighted_score": weighted,
        }

    first_half = records[:midpoint]
    second_half = records[midpoint:]

    prev_avg = sum((r["total"] or 0) for r in first_half) / len(first_half)
    curr_avg = sum((r["total"] or 0) for r in second_half) / len(second_half)

    current_latest = records[-1]
    weighted = (
        (current_latest["critical"] * 10)
        + (current_latest["high"] * 5)
        + (current_latest["medium"] * 2)
        + (current_latest["low"] * 1)
    )

    delta = round(curr_avg - prev_avg, 1)
    if prev_avg > 0:
        percent = round(((curr_avg - prev_avg) / prev_avg) * 100, 1)
    else:
        percent = 100.0 if curr_avg > 0 else 0.0

    if delta < 0:
        direction = "down"
        status_text = f"Security posture improved! Vulnerabilities decreased by {abs(percent)}%."
    elif delta > 0:
        direction = "up"
        status_text = f"Attention needed: Vulnerabilities increased by {percent}% over previous period."
    else:
        direction = "neutral"
        status_text = "Security findings remain steady across builds."

    return {
        "current_findings": int(round(curr_avg)),
        "previous_findings": int(round(prev_avg)),
        "delta": delta,
        "percent_change": percent,
        "direction": direction,
        "status_text": status_text,
        "weighted_score": weighted,
    }
