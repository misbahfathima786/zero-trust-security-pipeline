"""Smoke and safety tests for the Scan Results and Pipeline pages."""
import json
import re

from app.services import runs as run_service


# ---- access control -------------------------------------------------------

def test_pages_require_login(client):
    for url in ("/scans/", "/pipeline/", "/pipeline/42"):
        response = client.get(url)
        assert response.status_code == 302
        assert "/login" in response.headers["Location"]


# ---- Scan Results ---------------------------------------------------------

def test_scan_results_renders(logged_in):
    response = logged_in.get("/scans/")
    html = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "Scan Results" in html
    assert 'role="tablist"' in html
    assert "Sample data" in html
    assert 'aria-current="page"' in html          # sidebar active state


def test_every_status_is_present_in_sample_scans(logged_in):
    statuses = {s["status"] for s in run_service.list_scans()}
    assert {"passed", "failed", "warning", "running", "pending", "blocked"} <= statuses


def test_blocked_scan_never_reads_as_clean(logged_in):
    blocked = [s for s in run_service.list_scans() if s["status"] == "blocked"]
    assert blocked
    for scan in blocked:
        text = scan["details"].lower()
        assert "no vulnerabilities" not in text and "no secrets" not in text
        assert "unavailable" in text


def test_summary_counts_match_rows(logged_in):
    scans = run_service.list_scans()
    summaries = run_service.summaries_by_tab(scans)
    assert summaries["all"]["total"] == len(scans)
    assert summaries["all"]["total"] == sum(
        summaries[t]["total"] for t in run_service.SCAN_TYPES
    )
    for key in ("passed", "failed", "warning", "blocked"):
        assert summaries["all"][key] == sum(1 for s in scans if s["status"] == key)


def test_unknown_status_fails_closed():
    assert run_service._norm("totally-fine") == "blocked"


# ---- Pipeline / Build Details --------------------------------------------

def test_pipeline_link_redirects_to_latest(logged_in):
    response = logged_in.get("/pipeline/")
    assert response.status_code == 302
    assert response.headers["Location"].endswith(f"/pipeline/{run_service.latest_run()['run_id']}")


def test_build_details_renders_for_every_sample_run(logged_in):
    for run in run_service.list_runs():
        response = logged_in.get(f"/pipeline/{run['run_id']}")
        html = response.get_data(as_text=True)
        assert response.status_code == 200, run["run_id"]
        assert f"Build #{run['run_id']} Details" in html
        assert html.count('class="stepper__step ') == 5


def test_blocked_build_shows_warning_banner(logged_in):
    blocked = next(r for r in run_service.list_runs() if r["overall_status"] == "blocked")
    html = logged_in.get(f"/pipeline/{blocked['run_id']}").get_data(as_text=True)
    assert "This build is blocked" in html


def test_unknown_and_malicious_ids_give_404_page(logged_in):
    for bad in ("9999", "abc", "..", "42%20OR%201=1", "<script>"):
        response = logged_in.get(f"/pipeline/{bad}")
        assert response.status_code == 404, bad
        assert "Build not found" in response.get_data(as_text=True)
    # An encoded slash never even reaches the route: plain 404, equally safe.
    assert logged_in.get("/pipeline/..%2Fetc%2Fpasswd").status_code == 404


def test_get_run_rejects_path_tricks():
    for bad in ("../42", "42/../..", "-1", "4 2", "", "1e3"):
        assert run_service.get_run(bad) is None


def test_log_content_is_escaped(logged_in, monkeypatch):
    evil = "<script>alert(1)</script>"
    run = run_service.get_run(42)
    run = json.loads(json.dumps(run))
    run["logs"]["build"].append({"time": "00:00:00", "level": "info", "message": evil})
    monkeypatch.setattr(run_service, "get_run", lambda _id: run)
    html = logged_in.get("/pipeline/42").get_data(as_text=True)
    assert evil not in html
    assert "&lt;script&gt;" in html


# ---- Sample data safety ---------------------------------------------------

def test_sample_data_has_no_real_looking_secrets():
    raw = run_service.SAMPLE_FILE.read_text(encoding="utf-8")
    patterns = [r"AKIA[0-9A-Z]{16}", r"ghp_[A-Za-z0-9]{20,}", r"sk_(live|test)_", r"-----BEGIN", r"xox[bp]-"]
    for pattern in patterns:
        assert not re.search(pattern, raw), pattern
    for run in json.loads(raw)["runs"]:
        for finding in run["secrets"]["findings"]:
            assert finding["value"] == "[REDACTED]"


def test_detail_never_prints_secret_value(logged_in, monkeypatch):
    run = json.loads(json.dumps(run_service.get_run(38)))
    run["secrets"]["findings"][0]["value"] = "SHOULD-NEVER-APPEAR"
    monkeypatch.setattr(run_service, "list_runs", lambda: [run])
    html = logged_in.get("/scans/").get_data(as_text=True)
    assert "SHOULD-NEVER-APPEAR" not in html
    assert "[REDACTED]" in html
