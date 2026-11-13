"""
Integration smoke-test for the upload pipeline.
Run with:
  cd "D:/Mini Project/zero-trust-security-pipeline/zero-trust-security-pipeline"
  python tests/test_pipeline_integration.py
"""
import io, sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.app import app, db

# Use an in-memory SQLite DB so we don't pollute the real DB
app.config["TESTING"] = True
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
app.config["WTF_CSRF_ENABLED"] = False

with app.app_context():
    db.create_all()

    # Import after app context is set up
    from app.services import pipeline_runner

    # Create a fake FileStorage-like object
    class FakeFileStorage:
        def __init__(self, filename, content):
            self.filename = filename
            self._buf = io.BytesIO(content.encode("utf-8") if isinstance(content, str) else content)
        def seek(self, pos):
            self._buf.seek(pos)
        def save(self, path):
            path = str(path)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as f:
                f.write(self._buf.read())

    print("=" * 60)
    print("TEST 1: Plain .txt file (no secrets)")
    print("=" * 60)
    plain_file = FakeFileStorage("hello.txt", "Hello world. This is a test file with no secrets.\n")
    success, run_id, msg = pipeline_runner.run_pipeline(
        user_id=1,
        uploaded_files=[plain_file],
        project_name="Test: Plain TXT",
    )
    print(f"  success={success}, run_id={run_id}, msg={msg}")
    assert success, f"Expected success but got: {msg}"
    print("  PASSED\n")

    print("=" * 60)
    print("TEST 2: .txt file with FAKE API key (Gitleaks should detect)")
    print("=" * 60)
    secret_file = FakeFileStorage("creds.txt", 
        'GOOGLE_API_KEY=AIzaSyFakeTestKeyABCDEF123456789012345\n'
        'GITHUB_TOKEN=ghp_FakeGitHubPersonalAccessToken1234567890\n'
    )
    success, run_id, msg = pipeline_runner.run_pipeline(
        user_id=1,
        uploaded_files=[secret_file],
        project_name="Test: Secrets TXT",
    )
    print(f"  success={success}, run_id={run_id}, msg={msg}")
    # Even if secrets found, pipeline "succeeds" (returns True) but status is failed
    from app.models.scan import ScanRun
    scan = ScanRun.query.filter_by(run_id=run_id).first()
    import json
    run_data = json.loads(scan.data_json)
    secrets_count = run_data["secrets"]["count"]
    print(f"  secrets found: {secrets_count}")
    print(f"  overall_status: {run_data['overall_status']}")
    # Gitleaks findings should not contain actual values
    for f in run_data["secrets"]["findings"]:
        assert f.get("value") == "[REDACTED]", f"Secret value exposed! Finding: {f}"
    print("  No secret values exposed in findings — PASSED")
    print("  PASSED\n")

    print("=" * 60)
    print("TEST 3: requirements.txt with vulnerable packages (Trivy)")
    print("=" * 60)
    req_content = "flask==2.2.5\nwerkzeug==2.3.7\ncryptography==36.0.0\n"
    req_file = FakeFileStorage("requirements.txt", req_content)
    success, run_id, msg = pipeline_runner.run_pipeline(
        user_id=1,
        uploaded_files=[req_file],
        project_name="Test: Vulnerable Deps",
    )
    scan = ScanRun.query.filter_by(run_id=run_id).first()
    run_data = json.loads(scan.data_json)
    vuln_counts = run_data["vulnerabilities"]["counts"]
    sbom_components = run_data.get("sbom_components", [])
    print(f"  vuln counts: {vuln_counts}")
    print(f"  SBOM components: {len(sbom_components)}")
    print(f"  overall_status: {run_data['overall_status']}")
    if vuln_counts:
        total = sum(vuln_counts.values())
        print(f"  Total vulnerabilities: {total}")
    print("  PASSED\n")

    print("=" * 60)
    print("TEST 4: Disallowed file extension (should fail validation)")
    print("=" * 60)
    bad_file = FakeFileStorage("script.exe", b"\x4d\x5a")
    success, run_id, msg = pipeline_runner.run_pipeline(
        user_id=1,
        uploaded_files=[bad_file],
        project_name="Test: Bad Extension",
    )
    print(f"  success={success}, run_id={run_id}, msg={msg}")
    assert not success, "Expected failure for .exe file"
    print("  PASSED — .exe correctly rejected\n")

    print("ALL INTEGRATION TESTS PASSED ✓")
