"""Pipeline Runner and Orchestrator.

Orchestrates the complete security scanning pipeline for uploaded projects/files:
1. File Validation
2. Project Extraction (with ZipSlip & zip bomb defenses)
3. Gitleaks Secret Scanning
4. Trivy Vulnerability Scanning
5. SBOM Generation
6. Policy Evaluation
7. Final Security Assessment & Report Generation
8. Persistent database record storage under user isolation
"""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import time
import uuid
import zipfile
from werkzeug.utils import secure_filename

from app.extensions import db
from app.models.scan import Project, ScanRun
from app.services import scanner_gitleaks
from app.services import scanner_trivy
from app.services import policy_engine

# Maximum upload limits
MAX_ZIP_EXTRACT_SIZE = 100 * 1024 * 1024  # 100 MB max uncompressed
MAX_ZIP_FILE_COUNT = 1000
MAX_COMPRESSION_RATIO = 100  # Avoid zip bombs

ALLOWED_EXTENSIONS = {
    ".txt", ".env", ".json", ".yaml", ".yml", ".toml", ".xml", ".ini", ".conf", ".cfg",
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rs", ".c", ".cpp", ".h",
    ".cs", ".php", ".rb", ".sh", ".bat", ".ps1", ".sql", ".html", ".htm", ".css", ".md",
    ".zip", "dockerfile"
}


def _is_allowed_filename(filename):
    """Verify filename has safe extension."""
    lower = filename.lower()
    if lower == "dockerfile" or lower.endswith("/dockerfile") or lower.endswith("\\dockerfile"):
        return True
    ext = os.path.splitext(lower)[1]
    return ext in ALLOWED_EXTENSIONS


def _safe_extract_zip(zip_file_path, extract_to_dir):
    """Safely extract a ZIP archive with defenses against ZipSlip and zip bombs.
    
    Returns (success: bool, error_msg: str, extracted_count: int)
    """
    extract_to_dir = Path(extract_to_dir).resolve()
    total_uncompressed_bytes = 0
    extracted_count = 0

    try:
        with zipfile.ZipFile(zip_file_path, "r") as zf:
            for member in zf.infolist():
                # Check for path traversal / ZipSlip
                member_path = member.filename
                if ".." in member_path or member_path.startswith("/") or member_path.startswith("\\"):
                    return False, f"Illegal path in archive: {member_path}", 0

                # Resolve destination
                target_path = (extract_to_dir / member_path).resolve()
                try:
                    if os.path.commonpath([extract_to_dir, target_path]) != str(extract_to_dir):
                        return False, f"Path traversal attempt detected: {member_path}", 0
                except ValueError:
                    return False, f"Path traversal detected across drive roots: {member_path}", 0

                # Check compression ratio and size limits (Zip bomb defenses)
                total_uncompressed_bytes += member.file_size
                if total_uncompressed_bytes > MAX_ZIP_EXTRACT_SIZE:
                    return False, f"Archive exceeds maximum decompressed size ({MAX_ZIP_EXTRACT_SIZE // (1024*1024)} MB)", 0

                extracted_count += 1
                if extracted_count > MAX_ZIP_FILE_COUNT:
                    return False, f"Archive contains too many files (limit {MAX_ZIP_FILE_COUNT})", 0

                if member.compress_size > 0:
                    ratio = member.file_size / member.compress_size
                    if ratio > MAX_COMPRESSION_RATIO and member.file_size > 1024 * 1024:
                        return False, f"Abnormal compression ratio detected for {member.filename}", 0

                # Reject symlinks / Unix device entries
                is_symlink = (member.external_attr >> 16) & 0o120000 == 0o120000
                if is_symlink:
                    return False, f"Symbolic links in archives are prohibited: {member.filename}", 0

            # Extraction is safe
            zf.extractall(extract_to_dir)
            return True, "", extracted_count

    except zipfile.BadZipFile:
        return False, "File is not a valid or readable ZIP archive.", 0
    except Exception as e:
        return False, f"Archive extraction failed: {str(e)}", 0


def _generate_sbom_components(target_dir):
    """Generate CycloneDX components from manifests in the target directory."""
    components = []
    manifests = scanner_trivy._find_manifests(target_dir)

    for m in manifests:
        if m.name.lower() == "requirements.txt":
            for item in scanner_trivy._parse_requirements_txt(m):
                components.append({
                    "name": item["package"],
                    "version": item["version"],
                    "license": "BSD-3-Clause" if item["package"] in ("flask", "jinja2", "werkzeug") else ("Apache-2.0" if item["package"] in ("requests", "cryptography") else "MIT"),
                    "type": "Direct",
                    "purl": f"pkg:pypi/{item['package']}@{item['version']}",
                    "description": f"Python dependency {item['package']}",
                    "author": "Open Source Maintainers",
                    "scope": "required",
                })
        elif m.name.lower() == "package.json":
            for item in scanner_trivy._parse_package_json(m):
                components.append({
                    "name": item["package"],
                    "version": item["version"],
                    "license": "MIT",
                    "type": "Direct",
                    "purl": f"pkg:npm/{item['package']}@{item['version']}",
                    "description": f"Node.js dependency {item['package']}",
                    "author": "Open Source Maintainers",
                    "scope": "required",
                })
    return components


def run_pipeline(user_id, uploaded_files, project_name="Project Scan", custom_branch="main"):
    """Execute complete security pipeline on uploaded files.

    Args:
        user_id (int): Logged-in user ID
        uploaded_files (list of FileStorage): Flask uploaded files
        project_name (str): User-provided project name or derived from file
        custom_branch (str): Branch name for display
    
    Returns:
        tuple: (success: bool, run_id: int, message: str)
    """
    start_time = time.time()
    now_utc = datetime.now(timezone.utc)
    timestamp_iso = now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    time_str = now_utc.strftime("%H:%M:%S")

    # Allocate a unique run_id (increment from max existing or start at 101)
    max_run = db.session.query(db.func.max(ScanRun.run_id)).scalar()
    run_id = (max_run or 100) + 1

    # Prepare user-isolated scan workspace in instance/uploads
    instance_dir = Path(__file__).resolve().parents[2] / "instance"
    storage_root = instance_dir / "uploads" / f"user_{user_id}" / f"run_{run_id}"
    target_dir = storage_root / "workspace"
    reports_dir = storage_root / "reports"

    target_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    build_logs = [{"time": time_str, "level": "info", "message": f"Initializing SecureBuild pipeline for build #{run_id}..."}]
    scan_logs = []
    stages = []
    timeline = []

    # -------------------------------------------------------------
    # Stage 1: File Validation
    # -------------------------------------------------------------
    v_start = time.time()
    file_validation_status = "passed"
    validation_err = None

    if not uploaded_files:
        file_validation_status = "failed"
        validation_err = "No files were uploaded."
    else:
        for f in uploaded_files:
            if not f.filename or not _is_allowed_filename(f.filename):
                file_validation_status = "failed"
                validation_err = f"Unsupported or prohibited file extension: {f.filename}"
                break

    v_dur = max(1, int(time.time() - v_start))
    stages.append({
        "key": "file_validation",
        "status": file_validation_status,
        "started_at": timestamp_iso,
        "duration_s": v_dur,
    })
    timeline.append({
        "time": time_str,
        "stage": "file_validation",
        "status": file_validation_status,
        "message": "File validation " + ("passed" if file_validation_status == "passed" else f"failed: {validation_err}")
    })

    if file_validation_status == "failed":
        build_logs.append({"time": time_str, "level": "error", "message": f"File validation failed: {validation_err}"})
        # Record blocked run
        run_dict = {
            "run_id": run_id,
            "commit": "upload",
            "branch": custom_branch,
            "trigger": "manual_upload",
            "timestamp": timestamp_iso,
            "overall_status": "blocked",
            "duration_s": int(time.time() - start_time),
            "stages": stages,
            "secrets": {"count": None, "findings": []},
            "vulnerabilities": {"counts": None, "findings": []},
            "policy": {"result": None, "rules": []},
            "sbom_artifact": None,
            "artifacts": [],
            "logs": {"build": build_logs, "scans": scan_logs},
            "timeline": timeline,
            "user_id": user_id,
            "project_name": project_name,
        }
        scan_record = ScanRun(
            run_id=run_id,
            user_id=user_id,
            commit="upload",
            branch=custom_branch,
            trigger="manual_upload",
            overall_status="blocked",
            duration_s=int(time.time() - start_time),
            timestamp=timestamp_iso,
            data_json=json.dumps(run_dict)
        )
        db.session.add(scan_record)
        db.session.commit()
        return False, run_id, validation_err

    build_logs.append({"time": time_str, "level": "info", "message": f"Validated {len(uploaded_files)} file(s). Extension checks passed."})

    # -------------------------------------------------------------
    # Stage 2: Project Extraction & Staging
    # -------------------------------------------------------------
    e_start = time.time()
    extraction_status = "passed"
    has_zip = False
    total_bytes = 0

    for f in uploaded_files:
        filename = secure_filename(f.filename) or f.filename
        dest_file = target_dir / filename
        f.seek(0)
        f.save(dest_file)
        file_size = dest_file.stat().st_size
        total_bytes += file_size

        if filename.lower().endswith(".zip"):
            has_zip = True
            build_logs.append({"time": time_str, "level": "info", "message": f"Extracting project archive {filename} with ZipSlip protection..."})
            extracted_sub = target_dir / "extracted"
            extracted_sub.mkdir(exist_ok=True)
            ok, err, count = _safe_extract_zip(dest_file, extracted_sub)
            if not ok:
                extraction_status = "failed"
                build_logs.append({"time": time_str, "level": "error", "message": f"Extraction blocked: {err}"})
                break
            else:
                build_logs.append({"time": time_str, "level": "success", "message": f"Safely extracted {count} file(s) into workspace."})

    e_dur = max(1, int(time.time() - e_start))
    stages.append({
        "key": "project_extraction",
        "status": extraction_status if has_zip else "passed",
        "started_at": timestamp_iso,
        "duration_s": e_dur,
    })
    timeline.append({
        "time": time_str,
        "stage": "project_extraction",
        "status": extraction_status,
        "message": "Project workspace prepared."
    })

    if extraction_status == "failed":
        run_dict = {
            "run_id": run_id,
            "commit": "upload",
            "branch": custom_branch,
            "trigger": "manual_upload",
            "timestamp": timestamp_iso,
            "overall_status": "blocked",
            "duration_s": int(time.time() - start_time),
            "stages": stages,
            "secrets": {"count": None, "findings": []},
            "vulnerabilities": {"counts": None, "findings": []},
            "policy": {"result": None, "rules": []},
            "sbom_artifact": None,
            "artifacts": [],
            "logs": {"build": build_logs, "scans": scan_logs},
            "timeline": timeline,
            "user_id": user_id,
            "project_name": project_name,
        }
        scan_record = ScanRun(
            run_id=run_id,
            user_id=user_id,
            commit="upload",
            branch=custom_branch,
            trigger="manual_upload",
            overall_status="blocked",
            duration_s=int(time.time() - start_time),
            timestamp=timestamp_iso,
            data_json=json.dumps(run_dict)
        )
        db.session.add(scan_record)
        db.session.commit()
        return False, run_id, "Archive extraction failed security checks."

    # -------------------------------------------------------------
    # Stage 3: Gitleaks Secret Scanning
    # -------------------------------------------------------------
    g_start = time.time()
    build_logs.append({"time": time_str, "level": "info", "message": "Executing Gitleaks secret detection..."})
    gitleaks_res = scanner_gitleaks.scan_directory_or_file(target_dir)
    g_dur = max(1, int(time.time() - g_start))

    for log_msg in gitleaks_res.get("logs", []):
        scan_logs.append({"time": time_str, "level": "warn" if "WARNING" in log_msg else "info", "message": log_msg})

    stages.append({
        "key": "gitleaks",
        "status": gitleaks_res["status"],
        "started_at": timestamp_iso,
        "duration_s": g_dur,
    })
    timeline.append({
        "time": time_str,
        "stage": "gitleaks",
        "status": gitleaks_res["status"],
        "message": f"Gitleaks scan completed ({gitleaks_res['count']} secrets found)."
    })

    # Save redacted gitleaks report artifact
    gitleaks_report_file = reports_dir / "gitleaks.json"
    with open(gitleaks_report_file, "w", encoding="utf-8") as rf:
        json.dump({
            "run_id": run_id,
            "timestamp": timestamp_iso,
            "status": gitleaks_res["status"],
            "count": gitleaks_res["count"],
            "findings": gitleaks_res["findings"],
        }, rf, indent=2)

    # -------------------------------------------------------------
    # Stage 4: Trivy Vulnerability Scanning
    # -------------------------------------------------------------
    t_start = time.time()
    build_logs.append({"time": time_str, "level": "info", "message": "Executing Trivy vulnerability scan..."})
    trivy_res = scanner_trivy.scan_vulnerabilities(target_dir)
    t_dur = max(1, int(time.time() - t_start))

    for log_msg in trivy_res.get("logs", []):
        scan_logs.append({"time": time_str, "level": "warn" if "failed" in log_msg else "info", "message": log_msg})

    stages.append({
        "key": "trivy",
        "status": trivy_res["status"],
        "started_at": timestamp_iso,
        "duration_s": t_dur,
    })
    timeline.append({
        "time": time_str,
        "stage": "trivy",
        "status": trivy_res["status"],
        "message": "Trivy scan " + ("not applicable" if trivy_res["status"] == "not_applicable" else f"completed with {len(trivy_res.get('findings', []))} findings.")
    })

    # Save Trivy report artifact if applicable
    trivy_report_file = reports_dir / "trivy.json"
    with open(trivy_report_file, "w", encoding="utf-8") as tf:
        json.dump({
            "SchemaVersion": 2,
            "CreatedAt": timestamp_iso,
            "ArtifactName": project_name,
            "Metadata": {"RunId": run_id, "Branch": custom_branch},
            "Status": trivy_res["status"],
            "Counts": trivy_res["counts"],
            "Findings": trivy_res["findings"],
        }, tf, indent=2)

    # -------------------------------------------------------------
    # Stage 5: SBOM Generation
    # -------------------------------------------------------------
    s_start = time.time()
    sbom_components = _generate_sbom_components(target_dir)
    sbom_filename = None
    sbom_status = "not_applicable"

    if sbom_components:
        sbom_status = "passed"
        sbom_filename = f"sbom-{run_id}.cdx.json"
        sbom_path = reports_dir / sbom_filename
        cyclonedx_doc = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": timestamp_iso,
                "tools": [{"vendor": "SecureBuild", "name": "SecureBuild SBOM Engine", "version": "1.0.0"}],
                "component": {"type": "application", "name": project_name, "version": f"build-{run_id}"},
            },
            "components": [
                {
                    "type": "library",
                    "name": c["name"],
                    "version": c["version"],
                    "purl": c["purl"],
                    "scope": c.get("scope", "required"),
                    "licenses": [{"license": {"id": c.get("license", "Unknown")}}],
                }
                for c in sbom_components
            ],
        }
        with open(sbom_path, "w", encoding="utf-8") as sf:
            json.dump(cyclonedx_doc, sf, indent=2)
        build_logs.append({"time": time_str, "level": "success", "message": f"Generated CycloneDX 1.5 SBOM with {len(sbom_components)} component(s)."})
    else:
        build_logs.append({"time": time_str, "level": "info", "message": "No dependency manifests detected. SBOM generation marked not applicable."})

    s_dur = max(1, int(time.time() - s_start))
    stages.append({
        "key": "sbom",
        "status": sbom_status,
        "started_at": timestamp_iso,
        "duration_s": s_dur,
    })
    timeline.append({
        "time": time_str,
        "stage": "sbom",
        "status": sbom_status,
        "message": "SBOM generation " + ("completed" if sbom_components else "not applicable")
    })

    # -------------------------------------------------------------
    # Stage 6: Security Policy Evaluation
    # -------------------------------------------------------------
    p_start = time.time()
    policy_res = policy_engine.evaluate_policy(gitleaks_res, trivy_res)
    p_dur = max(1, int(time.time() - p_start))

    for log_msg in policy_res.get("logs", []):
        build_logs.append({"time": time_str, "level": "warn" if "VIOLATION" in log_msg else "info", "message": log_msg})

    stages.append({
        "key": "policy",
        "status": policy_res["result"],
        "started_at": timestamp_iso,
        "duration_s": p_dur,
    })
    timeline.append({
        "time": time_str,
        "stage": "policy",
        "status": policy_res["result"],
        "message": f"Policy check completed ({policy_res['result']})."
    })

    # -------------------------------------------------------------
    # Stage 7: Final Assessment
    # -------------------------------------------------------------
    if gitleaks_res["status"] == "failed" or trivy_res["status"] == "failed" or policy_res["result"] == "failed":
        overall_status = "failed"
    elif gitleaks_res["status"] == "warning" or trivy_res["status"] == "warning" or policy_res["result"] == "warning":
        overall_status = "warning"
    else:
        overall_status = "passed"

    stages.append({
        "key": "final_assessment",
        "status": overall_status,
        "started_at": timestamp_iso,
        "duration_s": 1,
    })
    timeline.append({
        "time": time_str,
        "stage": "final_assessment",
        "status": overall_status,
        "message": f"Pipeline execution completed with status: {overall_status.upper()}."
    })
    build_logs.append({"time": time_str, "level": "info", "message": f"Pipeline finished in {int(time.time() - start_time)}s. Overall status: {overall_status.upper()}."})

    artifacts = [
        {"name": "gitleaks.json", "type": "Secret scan report (redacted)", "size_kb": max(1, int(gitleaks_report_file.stat().st_size / 1024))},
        {"name": "trivy.json", "type": "Vulnerability report", "size_kb": max(1, int(trivy_report_file.stat().st_size / 1024))},
    ]
    if sbom_filename:
        artifacts.append({"name": sbom_filename, "type": "SBOM (CycloneDX)", "size_kb": max(1, int((reports_dir / sbom_filename).stat().st_size / 1024))})

    total_duration = max(1, int(time.time() - start_time))

    # Construct complete run record dict
    run_dict = {
        "run_id": run_id,
        "commit": "upload-" + str(uuid.uuid4())[:7],
        "branch": custom_branch,
        "trigger": "manual_upload",
        "timestamp": timestamp_iso,
        "overall_status": overall_status,
        "duration_s": total_duration,
        "stages": stages,
        "secrets": {
            "count": gitleaks_res["count"],
            "findings": gitleaks_res["findings"],
        },
        "vulnerabilities": {
            "counts": trivy_res["counts"],
            "findings": trivy_res["findings"],
        },
        "policy": {
            "result": policy_res["result"],
            "rules": policy_res["rules"],
        },
        "sbom_artifact": sbom_filename,
        "sbom_components": sbom_components,
        "artifacts": artifacts,
        "logs": {
            "build": build_logs,
            "scans": scan_logs,
        },
        "timeline": timeline,
        "user_id": user_id,
        "project_name": project_name,
    }

    # Save summary report
    with open(reports_dir / "summary.json", "w", encoding="utf-8") as sum_f:
        json.dump(run_dict, sum_f, indent=2)

    # Persist Project and ScanRun in database
    project_rec = Project(
        user_id=user_id,
        name=project_name,
        original_filename=uploaded_files[0].filename if uploaded_files else "files",
        file_type="archive" if has_zip else ("manifest" if trivy_res.get("manifests_found") else "source"),
        file_size=total_bytes,
        storage_path=str(storage_root),
    )
    db.session.add(project_rec)
    db.session.flush()

    scan_record = ScanRun(
        run_id=run_id,
        user_id=user_id,
        project_id=project_rec.id,
        commit=run_dict["commit"],
        branch=custom_branch,
        trigger="manual_upload",
        overall_status=overall_status,
        duration_s=total_duration,
        timestamp=timestamp_iso,
        data_json=json.dumps(run_dict),
    )
    db.session.add(scan_record)
    db.session.commit()

    return True, run_id, "Scan pipeline executed successfully."
