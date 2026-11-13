"""Comprehensive tests for Pages 5, 6, and 7 and regression verification for Pages 1-4."""
import json
import pytest
from app.services import runs as run_service
from app.services import vulnerabilities as vuln_service
from app.services import sbom as sbom_service
from app.services import history as history_service


# -------------------------------------------------------------------------
# 1. Access Control Tests
# -------------------------------------------------------------------------

def test_new_pages_require_login(client):
    """Verify that unauthenticated access redirects to login for all new routes."""
    protected_urls = [
        "/vulnerabilities/",
        "/vulnerabilities/download",
        "/vulnerabilities/api/findings",
        "/sbom/",
        "/sbom/export",
        "/sbom/api/components",
        "/history/",
        "/history/api/trends",
    ]
    for url in protected_urls:
        response = client.get(url)
        assert response.status_code == 302
        assert "/login" in response.headers["Location"]


# -------------------------------------------------------------------------
# 2. PAGE 5: Trivy Vulnerability Scan Results Tests
# -------------------------------------------------------------------------

def test_page5_vulnerabilities_renders(logged_in):
    """Test that Page 5 renders correctly with headers, tabs, cards, and active nav."""
    response = logged_in.get("/vulnerabilities/")
    assert response.status_code == 200
    html = response.get_data(as_text=True)

    # Header & Titles
    assert "Trivy Vulnerability Scan" in html
    assert "Dependencies &amp; Container Image Scan" in html or "Dependencies & Container Image Scan" in html
    assert "Download Report" in html

    # Active sidebar state
    assert 'class="nav-item active"' in html
    assert 'aria-current="page"' in html

    # Tabs
    assert "Dependencies (" in html
    assert "Container Image (" in html

    # 5 Severity Cards
    assert "Critical" in html
    assert "High" in html
    assert "Medium" in html
    assert "Low" in html
    assert "Info" in html

    # Table columns
    assert "Package" in html
    assert "Version" in html
    assert "Severity" in html
    assert "Fixed Version" in html
    assert "Details" in html

    # Packages from actual scan data
    assert "flask" in html.lower()
    assert "werkzeug" in html.lower()


def test_page5_download_report_returns_valid_json(logged_in):
    """Test that the Download Report button provides a valid Trivy JSON file."""
    response = logged_in.get("/vulnerabilities/download")
    assert response.status_code == 200
    assert "application/json" in response.headers["Content-Type"]
    assert "attachment;filename=" in response.headers["Content-Disposition"]

    data = json.loads(response.get_data(as_text=True))
    assert data["SchemaVersion"] == 2
    assert "Results" in data
    assert len(data["Results"]) > 0
    vulns = data["Results"][0]["Vulnerabilities"]
    assert len(vulns) > 0
    # Verify expected fields in vulnerability findings
    first = vulns[0]
    assert "VulnerabilityID" in first
    assert "PkgName" in first
    assert "InstalledVersion" in first
    assert "Severity" in first


def test_page5_api_findings_filtering(logged_in):
    """Test the JSON API endpoint for findings and severity filtering."""
    # All
    res_all = logged_in.get("/vulnerabilities/api/findings?severity=all")
    assert res_all.status_code == 200
    data_all = res_all.get_json()
    assert "findings" in data_all
    assert len(data_all["findings"]) > 0

    # Filter High
    res_high = logged_in.get("/vulnerabilities/api/findings?severity=high")
    assert res_high.status_code == 200
    data_high = res_high.get_json()
    for f in data_high["findings"]:
        assert f["severity"] == "high"


# -------------------------------------------------------------------------
# 3. PAGE 6: Software Bill of Materials (SBOM) Tests
# -------------------------------------------------------------------------

def test_page6_sbom_renders(logged_in):
    """Test that Page 6 renders SBOM inventory, summary cards, and Export action."""
    response = logged_in.get("/sbom/")
    assert response.status_code == 200
    html = response.get_data(as_text=True)

    # Header
    assert "Software Bill of Materials (SBOM)" in html
    assert "Complete list of software components" in html
    assert "Export SBOM" in html

    # Summary cards
    assert "Total Components" in html
    assert "Direct Dependencies" in html
    assert "Transitive Dependencies" in html

    # Table columns
    assert "Component" in html
    assert "License" in html
    assert "Type" in html

    # Components list matches prototype
    assert "flask" in html.lower()
    assert "werkzeug" in html.lower()
    assert "jinja2" in html.lower()
    assert "requests" in html.lower()
    assert "urllib3" in html.lower()


def test_page6_export_cyclonedx_sbom(logged_in):
    """Test that Export SBOM produces a valid CycloneDX 1.5 standard JSON file."""
    response = logged_in.get("/sbom/export")
    assert response.status_code == 200
    assert "application/json" in response.headers["Content-Type"]
    assert "attachment;filename=" in response.headers["Content-Disposition"]

    sbom = json.loads(response.get_data(as_text=True))
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.5"
    assert "metadata" in sbom
    assert "components" in sbom
    assert len(sbom["components"]) > 0
    # Verify package properties
    first = sbom["components"][0]
    assert "name" in first
    assert "version" in first
    assert "purl" in first
    assert "licenses" in first


def test_page6_api_components(logged_in):
    """Test SBOM components API endpoint with filter support."""
    res = logged_in.get("/sbom/api/components?type=Direct")
    assert res.status_code == 200
    data = res.get_json()
    assert data["direct_count"] > 0
    for comp in data["components"]:
        assert comp["type"] == "Direct"


# -------------------------------------------------------------------------
# 4. PAGE 7: Security History & Trends Tests
# -------------------------------------------------------------------------

def test_page7_history_renders(logged_in):
    """Test that Page 7 renders trend charts, risk trends, and recent builds."""
    response = logged_in.get("/history/")
    assert response.status_code == 200
    html = response.get_data(as_text=True)

    # Header & Range dropdown
    assert "Security History &amp; Trends" in html or "Security History & Trends" in html
    assert "Track your security posture over time" in html
    assert "Last 30 Days" in html
    assert "Last 7 Days" in html
    assert "Last 90 Days" in html

    # Chart & Legends
    assert "Findings Trend" in html
    assert "Critical" in html
    assert "High" in html
    assert "Medium" in html
    assert "Low" in html

    # Risk Trend
    assert "Risk Trend" in html
    assert "Current Avg" in html
    assert "Previous Period" in html
    assert "Weighted Risk Index" in html

    # Recent Builds table
    assert "Recent Builds" in html
    assert "Build #" in html


def test_page7_api_trends(logged_in):
    """Test history API endpoint returns valid series data."""
    response = logged_in.get("/history/api/trends?range=30d")
    assert response.status_code == 200
    data = response.get_json()
    assert "labels" in data
    assert "critical_series" in data
    assert "high_series" in data
    assert "medium_series" in data
    assert "low_series" in data
    assert "risk_metric" in data
    assert "recent_builds" in data
    assert len(data["recent_builds"]) > 0


# -------------------------------------------------------------------------
# 5. REGRESSION TESTS: PAGES 1 - 4 PRESERVED
# -------------------------------------------------------------------------

def test_page1_auth_preserved(client):
    """Regression test: Page 1 (Login/Signup) is functional and unchanged."""
    res_login = client.get("/login")
    assert res_login.status_code == 200
    html_login = res_login.get_data(as_text=True)
    assert "Welcome Back" in html_login or "Sign In" in html_login

    res_signup = client.get("/signup")
    assert res_signup.status_code == 200
    html_signup = res_signup.get_data(as_text=True)
    assert "Create" in html_signup or "Account" in html_signup


def test_page2_dashboard_preserved(logged_in):
    """Regression test: Page 2 (Dashboard Overview) is functional and unchanged."""
    res = logged_in.get("/dashboard/")
    assert res.status_code == 200
    html = res.get_data(as_text=True)
    assert "Dashboard" in html
    assert "Security Overview" in html
    assert 'class="nav-item active"' in html


def test_page3_pipeline_preserved(logged_in):
    """Regression test: Page 3 (Pipeline / Build Details) is functional and unchanged."""
    res_latest = logged_in.get("/pipeline/")
    assert res_latest.status_code == 302

    res_build = logged_in.get("/pipeline/42")
    assert res_build.status_code == 200
    html = res_build.get_data(as_text=True)
    assert "Build #42 Details" in html
    assert html.count('class="stepper__step ') == 5


def test_page4_scan_results_preserved(logged_in):
    """Regression test: Page 4 (Scan Results) is functional and unchanged."""
    res = logged_in.get("/scans/")
    assert res.status_code == 200
    html = res.get_data(as_text=True)
    assert "Scan Results" in html
    assert 'role="tablist"' in html
    assert "Scan Summary" in html
    assert "All Scans" in html
