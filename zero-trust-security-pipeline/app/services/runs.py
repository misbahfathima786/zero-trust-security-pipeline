"""Run and scan data access for the Pipeline and Scan Results pages.

SWAP POINT: today every function reads app/sample_data/runs.json. When the
real report loader exists (backend phase), only ``_load()`` changes - the
view helpers below and the templates stay as they are.

Rules this module enforces (from the proposal):
  * a blocked / errored / unknown scan is never reported as clean or zero;
  * secret values are never exposed (only the redacted marker is passed on).
"""
import json
import re
from pathlib import Path

SAMPLE_FILE = Path(__file__).resolve().parents[1] / "sample_data" / "runs.json"

KNOWN_STATUSES = ("passed", "failed", "warning", "running", "pending", "blocked", "skipped")
SEVERITIES = ("critical", "high", "medium", "low", "info")

STAGE_LABELS = {
    "code_push": "Code Push",
    "build": "Build",
    "gitleaks": "Gitleaks",
    "trivy": "Trivy",
    "policy": "Policy Check",
}

SCAN_TYPES = {
    "gitleaks": "Gitleaks (Secrets)",
    "trivy": "Trivy (Vulnerabilities)",
    "policy": "Policy Check",
}

# A run id is digits only. Strict on purpose: the real loader will build file
# paths from it, so "../" and friends must never get through.
_RUN_ID_RE = re.compile(r"^[0-9]{1,9}$")


def _load():
    """Return (runs, is_sample). Replace this body with the real loader."""
    with open(SAMPLE_FILE, encoding="utf-8") as fh:
        data = json.load(fh)
    return data["runs"], bool(data.get("is_sample", False))


def _norm(status):
    """Unknown statuses fail closed: they are shown as blocked, never green."""
    return status if status in KNOWN_STATUSES else "blocked"


def is_sample_data():
    return _load()[1]


def list_runs():
    runs, _ = _load()
    return sorted(runs, key=lambda r: r["run_id"], reverse=True)


def get_run(run_id):
    """Return a run dict or None. ``run_id`` may be str or int."""
    if not _RUN_ID_RE.match(str(run_id)):
        return None
    wanted = int(run_id)
    for run in list_runs():
        if run["run_id"] == wanted:
            return run
    return None


def latest_run():
    runs = list_runs()
    return runs[0] if runs else None


def neighbours(run_id):
    """(older_id, newer_id) around a run, either may be None."""
    ids = sorted(r["run_id"] for r in list_runs())
    if run_id not in ids:
        return None, None
    i = ids.index(run_id)
    return (ids[i - 1] if i > 0 else None, ids[i + 1] if i < len(ids) - 1 else None)


# --------------------------------------------------------------------------
# Build Details view helpers
# --------------------------------------------------------------------------

def stage_view(run):
    out = []
    for s in run["stages"]:
        out.append({
            "key": s["key"],
            "label": STAGE_LABELS.get(s["key"], s["key"]),
            "status": _norm(s["status"]),
            "duration_s": s.get("duration_s"),
            "duration": format_duration(s.get("duration_s")),
        })
    return out


def format_duration(seconds):
    if seconds is None:
        return "-"
    m, s = divmod(int(seconds), 60)
    return f"{m}m {s:02d}s" if m else f"{s}s"


# --------------------------------------------------------------------------
# Scan Results view helpers
# --------------------------------------------------------------------------

def _scan_summary_text(key, status, run):
    """One-line 'Details' cell. Blocked/unknown never reads as clean."""
    if status == "running":
        return "Scan in progress"
    if status == "pending":
        return "Waiting for previous stage"
    if status == "blocked":
        return "Scanner error - result unavailable (not a clean result)"

    if key == "gitleaks":
        n = run["secrets"]["count"]
        if n is None:
            return "Result unavailable"
        return "No secrets found" if n == 0 else f"{n} potential secret{'s' if n != 1 else ''} found"

    if key == "trivy":
        counts = run["vulnerabilities"]["counts"]
        if counts is None:
            return "Result unavailable"
        total = sum(counts.values())
        if total == 0:
            return "No vulnerabilities found"
        text = f"{total} vulnerabilit{'ies' if total != 1 else 'y'}"
        top = next((s for s in SEVERITIES if counts.get(s)), None)
        if top in ("critical", "high"):
            text += f" ({counts[top]} {top})"
        return text

    if key == "policy":
        rules = run["policy"]["rules"]
        failed = sum(1 for r in rules if r["result"] == "failed")
        if status == "failed":
            return f"{failed} rule{'s' if failed != 1 else ''} failed"
        return "All rules passed"
    return ""


def scans_for_run(run):
    """Flatten one run into scan rows (one per executed scan stage).

    Skipped stages produce no row - nothing was scanned.
    """
    stages = {s["key"]: s for s in run["stages"]}
    rows = []
    for key in ("gitleaks", "trivy", "policy"):
        st = stages.get(key)
        if not st or st["status"] == "skipped":
            continue
        status = _norm(st["status"])
        rows.append({
            "id": f"{run['run_id']}-{key}",
            "run_id": run["run_id"],
            "branch": run["branch"],
            "commit": run["commit"],
            "type": key,
            "type_label": SCAN_TYPES[key],
            "status": status,
            "started_at": st.get("started_at") or run["timestamp"],
            "details": _scan_summary_text(key, status, run),
            "run": run,
        })
    return rows


def list_scans():
    scans = []
    for run in list_runs():
        scans.extend(scans_for_run(run))
    return sorted(scans, key=lambda s: s["started_at"], reverse=True)


def summarise(scans):
    """Counts for the summary cards.

    Running and pending scans count towards Total only, so Passed + Failed +
    Warnings + Blocked can be lower than Total while scans are in flight.
    """
    out = {"total": len(scans), "passed": 0, "failed": 0, "warning": 0, "blocked": 0}
    for s in scans:
        if s["status"] in out:
            out[s["status"]] += 1
    return out


def summaries_by_tab(scans):
    """Summary per tab, e.g. {"all": {...}, "gitleaks": {...}}.

    The status dropdown is deliberately NOT applied here: cards follow the tab
    only, so the numbers stay meaningful while a status filter is active.
    """
    result = {"all": summarise(scans)}
    for key in SCAN_TYPES:
        result[key] = summarise([s for s in scans if s["type"] == key])
    return result
