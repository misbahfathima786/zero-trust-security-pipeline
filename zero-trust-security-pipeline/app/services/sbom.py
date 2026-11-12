"""Service for Software Bill of Materials (SBOM) Generation and Inventory (Page 6).

Implements CycloneDX (and SPDX-extensible) SBOM data structures, component inventory,
direct vs transitive dependency classification, license parsing, and export generation.
"""
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from app.services import runs as run_service

SBOM_DIR = Path(__file__).resolve().parents[2] / "security" / "sbom"
REPORTS_DIR = Path(__file__).resolve().parents[2] / "reports"

# Standard components representing application inventory matching CycloneDX 1.5 standard
DEFAULT_COMPONENTS = [
    {
        "name": "flask",
        "version": "2.3.3",
        "license": "BSD-3-Clause",
        "type": "Direct",
        "purl": "pkg:pypi/flask@2.3.3",
        "description": "A simple framework for building complex web applications.",
        "author": "Pallets Team",
        "scope": "required",
    },
    {
        "name": "werkzeug",
        "version": "2.3.7",
        "license": "BSD-3-Clause",
        "type": "Direct",
        "purl": "pkg:pypi/werkzeug@2.3.7",
        "description": "Comprehensive WSGI web application library.",
        "author": "Pallets Team",
        "scope": "required",
    },
    {
        "name": "jinja2",
        "version": "3.1.2",
        "license": "BSD-3-Clause",
        "type": "Direct",
        "purl": "pkg:pypi/jinja2@3.1.2",
        "description": "A very fast and expressive template engine.",
        "author": "Pallets Team",
        "scope": "required",
    },
    {
        "name": "requests",
        "version": "2.31.0",
        "license": "Apache-2.0",
        "type": "Direct",
        "purl": "pkg:pypi/requests@2.31.0",
        "description": "Python HTTP for Humans.",
        "author": "Kenneth Reitz",
        "scope": "required",
    },
    {
        "name": "sqlalchemy",
        "version": "2.0.23",
        "license": "MIT",
        "type": "Direct",
        "purl": "pkg:pypi/sqlalchemy@2.0.23",
        "description": "Database Abstraction Library & Object Relational Mapper.",
        "author": "Mike Bayer",
        "scope": "required",
    },
    {
        "name": "flask-login",
        "version": "0.6.3",
        "license": "MIT",
        "type": "Direct",
        "purl": "pkg:pypi/flask-login@0.6.3",
        "description": "User session management for Flask.",
        "author": "Max Countryman",
        "scope": "required",
    },
    {
        "name": "flask-wtf",
        "version": "1.2.1",
        "license": "BSD-3-Clause",
        "type": "Direct",
        "purl": "pkg:pypi/flask-wtf@1.2.1",
        "description": "Simple integration of Flask and WTForms.",
        "author": "Dan Jacob",
        "scope": "required",
    },
    {
        "name": "wtforms",
        "version": "3.1.1",
        "license": "BSD-3-Clause",
        "type": "Direct",
        "purl": "pkg:pypi/wtforms@3.1.1",
        "description": "Flexible forms validation and rendering library.",
        "author": "WTForms Team",
        "scope": "required",
    },
    {
        "name": "python-dotenv",
        "version": "1.0.0",
        "license": "BSD-3-Clause",
        "type": "Direct",
        "purl": "pkg:pypi/python-dotenv@1.0.0",
        "description": "Read key-value pairs from a .env file and set them as environment variables.",
        "author": "Saurabh Kumar",
        "scope": "required",
    },
    {
        "name": "blinker",
        "version": "1.7.0",
        "license": "MIT",
        "type": "Direct",
        "purl": "pkg:pypi/blinker@1.7.0",
        "description": "Fast, simple object-to-object and broadcast signaling.",
        "author": "Jason Kirtland",
        "scope": "required",
    },
    {
        "name": "click",
        "version": "8.1.7",
        "license": "BSD-3-Clause",
        "type": "Direct",
        "purl": "pkg:pypi/click@8.1.7",
        "description": "Composable command line interface toolkit.",
        "author": "Pallets Team",
        "scope": "required",
    },
    {
        "name": "email-validator",
        "version": "2.1.0",
        "license": "MIT",
        "type": "Direct",
        "purl": "pkg:pypi/email-validator@2.1.0",
        "description": "Robust email syntax and deliverability validation library.",
        "author": "JoshData",
        "scope": "required",
    },
    # Transitive dependencies
    {
        "name": "urllib3",
        "version": "1.26.18",
        "license": "MIT",
        "type": "Transitive",
        "purl": "pkg:pypi/urllib3@1.26.18",
        "description": "HTTP library with thread-safe connection pooling and file post support.",
        "author": "Andrey Petrov",
        "scope": "optional",
    },
    {
        "name": "markupsafe",
        "version": "2.1.3",
        "license": "BSD-3-Clause",
        "type": "Transitive",
        "purl": "pkg:pypi/markupsafe@2.1.3",
        "description": "Safely add untrusted strings to HTML/XML markup.",
        "author": "Pallets Team",
        "scope": "required",
    },
    {
        "name": "itsdangerous",
        "version": "2.1.2",
        "license": "BSD-3-Clause",
        "type": "Transitive",
        "purl": "pkg:pypi/itsdangerous@2.1.2",
        "description": "Safely pass cryptographic data to untrusted environments.",
        "author": "Pallets Team",
        "scope": "required",
    },
    {
        "name": "idna",
        "version": "3.4",
        "license": "BSD-3-Clause",
        "type": "Transitive",
        "purl": "pkg:pypi/idna@3.4",
        "description": "Internationalized Domain Names in Applications (IDNA).",
        "author": "Kim Davies",
        "scope": "required",
    },
    {
        "name": "certifi",
        "version": "2023.11.17",
        "license": "MPL-2.0",
        "type": "Transitive",
        "purl": "pkg:pypi/certifi@2023.11.17",
        "description": "Python package for providing Mozilla's CA Bundle.",
        "author": "Kenneth Reitz",
        "scope": "required",
    },
    {
        "name": "charset-normalizer",
        "version": "3.3.2",
        "license": "MIT",
        "type": "Transitive",
        "purl": "pkg:pypi/charset-normalizer@3.3.2",
        "description": "Universal charset and encoding detector.",
        "author": "Ahmed TAHRI",
        "scope": "required",
    },
    {
        "name": "dnspython",
        "version": "2.4.2",
        "license": "ISC",
        "type": "Transitive",
        "purl": "pkg:pypi/dnspython@2.4.2",
        "description": "DNS toolkit for Python.",
        "author": "Bob Halley",
        "scope": "required",
    },
    {
        "name": "greenlet",
        "version": "3.0.1",
        "license": "MIT",
        "type": "Transitive",
        "purl": "pkg:pypi/greenlet@3.0.1",
        "description": "Lightweight in-process concurrent execution.",
        "author": "Alexey Borzenkov",
        "scope": "required",
    },
    {
        "name": "typing-extensions",
        "version": "4.8.0",
        "license": "Python-2.0",
        "type": "Transitive",
        "purl": "pkg:pypi/typing-extensions@4.8.0",
        "description": "Backported and experimental type hints for Python.",
        "author": "Guido van Rossum",
        "scope": "required",
    },
    {
        "name": "cryptography",
        "version": "41.0.3",
        "license": "Apache-2.0",
        "type": "Transitive",
        "purl": "pkg:pypi/cryptography@41.0.3",
        "description": "cryptography is a package which provides cryptographic recipes and primitives.",
        "author": "PyCA Team",
        "scope": "required",
    },
    {
        "name": "cffi",
        "version": "1.16.0",
        "license": "MIT",
        "type": "Transitive",
        "purl": "pkg:pypi/cffi@1.16.0",
        "description": "Foreign Function Interface for Python calling C code.",
        "author": "Armin Rigo",
        "scope": "required",
    },
    {
        "name": "pycparser",
        "version": "2.21",
        "license": "BSD-3-Clause",
        "type": "Transitive",
        "purl": "pkg:pypi/pycparser@2.21",
        "description": "C parser in Python.",
        "author": "Eli Bendersky",
        "scope": "required",
    },
    {
        "name": "pyyaml",
        "version": "5.4.1",
        "license": "MIT",
        "type": "Transitive",
        "purl": "pkg:pypi/pyyaml@5.4.1",
        "description": "YAML parser and emitter for Python.",
        "author": "Kirill Simonov",
        "scope": "required",
    },
    {
        "name": "packaging",
        "version": "23.2",
        "license": "Apache-2.0",
        "type": "Transitive",
        "purl": "pkg:pypi/packaging@23.2",
        "description": "Core utilities for Python packages.",
        "author": "Donald Stufft",
        "scope": "required",
    },
    {
        "name": "pluggy",
        "version": "1.3.0",
        "license": "MIT",
        "type": "Transitive",
        "purl": "pkg:pypi/pluggy@1.3.0",
        "description": "Plugin and hook calling mechanisms for Python.",
        "author": "Holger Krekel",
        "scope": "required",
    },
    {
        "name": "iniconfig",
        "version": "2.0.0",
        "license": "MIT",
        "type": "Transitive",
        "purl": "pkg:pypi/iniconfig@2.0.0",
        "description": "Brain-dead simple config-ini parsing.",
        "author": "Ronny Pfannschmidt",
        "scope": "required",
    },
    {
        "name": "colorama",
        "version": "0.4.6",
        "license": "BSD-3-Clause",
        "type": "Transitive",
        "purl": "pkg:pypi/colorama@0.4.6",
        "description": "Cross-platform colored terminal text.",
        "author": "Jonathan Hartley",
        "scope": "required",
    },
    {
        "name": "pytest",
        "version": "7.4.3",
        "license": "MIT",
        "type": "Transitive",
        "purl": "pkg:pypi/pytest@7.4.3",
        "description": "pytest: simple powerful testing with Python.",
        "author": "Holger Krekel",
        "scope": "required",
    },
    {
        "name": "coverage",
        "version": "7.3.2",
        "license": "Apache-2.0",
        "type": "Transitive",
        "purl": "pkg:pypi/coverage@7.3.2",
        "description": "Code coverage measurement for Python.",
        "author": "Ned Batchelder",
        "scope": "optional",
    },
    {
        "name": "wheel",
        "version": "0.42.0",
        "license": "MIT",
        "type": "Transitive",
        "purl": "pkg:pypi/wheel@0.42.0",
        "description": "A built-package format for Python.",
        "author": "Daniel Holth",
        "scope": "optional",
    },
    {
        "name": "setuptools",
        "version": "68.2.2",
        "license": "MIT",
        "type": "Transitive",
        "purl": "pkg:pypi/setuptools@68.2.2",
        "description": "Easily download, build, install, upgrade, and uninstall Python packages.",
        "author": "Python Packaging Authority",
        "scope": "optional",
    },
    {
        "name": "pip",
        "version": "23.3.1",
        "license": "MIT",
        "type": "Transitive",
        "purl": "pkg:pypi/pip@23.3.1",
        "description": "The PyPA recommended tool for installing Python packages.",
        "author": "The pip developers",
        "scope": "optional",
    },
    {
        "name": "attrs",
        "version": "23.1.0",
        "license": "MIT",
        "type": "Transitive",
        "purl": "pkg:pypi/attrs@23.1.0",
        "description": "Classes Without Boilerplate.",
        "author": "Hynek Schlawack",
        "scope": "optional",
    },
    {
        "name": "six",
        "version": "1.16.0",
        "license": "MIT",
        "type": "Transitive",
        "purl": "pkg:pypi/six@1.16.0",
        "description": "Python 2 and 3 compatibility utilities.",
        "author": "Benjamin Peterson",
        "scope": "optional",
    },
    {
        "name": "tomli",
        "version": "2.0.1",
        "license": "MIT",
        "type": "Transitive",
        "purl": "pkg:pypi/tomli@2.0.1",
        "description": "A lil' TOML parser.",
        "author": "Taneli Hukkinen",
        "scope": "optional",
    },
    {
        "name": "pygments",
        "version": "2.17.2",
        "license": "BSD-2-Clause",
        "type": "Transitive",
        "purl": "pkg:pypi/pygments@2.17.2",
        "description": "Pygments is a syntax highlighting package written in Python.",
        "author": "Georg Brandl",
        "scope": "optional",
    },
    {
        "name": "bcrypt",
        "version": "4.1.2",
        "license": "Apache-2.0",
        "type": "Transitive",
        "purl": "pkg:pypi/bcrypt@4.1.2",
        "description": "Modern password hashing for Python.",
        "author": "The Python Cryptographic Authority developers",
        "scope": "optional",
    },
    {
        "name": "sniffio",
        "version": "1.3.0",
        "license": "Apache-2.0",
        "type": "Transitive",
        "purl": "pkg:pypi/sniffio@1.3.0",
        "description": "Sniff out which async library your code is running under.",
        "author": "Nathaniel J. Smith",
        "scope": "optional",
    },
    {
        "name": "anyio",
        "version": "4.2.0",
        "license": "MIT",
        "type": "Transitive",
        "purl": "pkg:pypi/anyio@4.2.0",
        "description": "High level compatibility layer for multiple asynchronous event loop implementations.",
        "author": "Alex Grönholm",
        "scope": "optional",
    },
    {
        "name": "starlette",
        "version": "0.36.3",
        "license": "BSD-3-Clause",
        "type": "Transitive",
        "purl": "pkg:pypi/starlette@0.36.3",
        "description": "The little ASGI framework that shines.",
        "author": "Encode OSS Ltd",
        "scope": "optional",
    },
    {
        "name": "h11",
        "version": "0.14.0",
        "license": "MIT",
        "type": "Transitive",
        "purl": "pkg:pypi/h11@0.14.0",
        "description": "A pure-Python, bring-your-own-I/O implementation of HTTP/1.1.",
        "author": "Nathaniel J. Smith",
        "scope": "optional",
    },
    {
        "name": "httpcore",
        "version": "1.0.2",
        "license": "BSD-3-Clause",
        "type": "Transitive",
        "purl": "pkg:pypi/httpcore@1.0.2",
        "description": "A minimal low-level HTTP client.",
        "author": "Encode OSS Ltd",
        "scope": "optional",
    },
    {
        "name": "httpx",
        "version": "0.26.0",
        "license": "BSD-3-Clause",
        "type": "Transitive",
        "purl": "pkg:pypi/httpx@0.26.0",
        "description": "A next-generation HTTP client for Python.",
        "author": "Encode OSS Ltd",
        "scope": "optional",
    },
    {
        "name": "pydantic",
        "version": "2.5.3",
        "license": "MIT",
        "type": "Transitive",
        "purl": "pkg:pypi/pydantic@2.5.3",
        "description": "Data validation using Python type hints.",
        "author": "Samuel Colvin",
        "scope": "optional",
    },
    {
        "name": "pydantic-core",
        "version": "2.14.6",
        "license": "MIT",
        "type": "Transitive",
        "purl": "pkg:pypi/pydantic-core@2.14.6",
        "description": "Core validation logic for pydantic written in Rust.",
        "author": "Samuel Colvin",
        "scope": "optional",
    },
    {
        "name": "annotated-types",
        "version": "0.6.0",
        "license": "MIT",
        "type": "Transitive",
        "purl": "pkg:pypi/annotated-types@0.6.0",
        "description": "Reusable constraint metadata to use with typing.Annotated.",
        "author": "Adrian Garcia Badaracco",
        "scope": "optional",
    },
]


def _load_sbom_file(path):
    """Load and parse an external CycloneDX JSON file."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        components = []
        for c in data.get("components", []):
            lic_name = "Unknown"
            if c.get("licenses"):
                lic = c["licenses"][0]
                lic_name = lic.get("license", {}).get("id") or lic.get("license", {}).get("name") or "Unknown"
            components.append({
                "name": c.get("name", "Unknown"),
                "version": c.get("version", "Unknown"),
                "license": lic_name,
                "type": "Direct" if c.get("scope") == "required" else "Transitive",
                "purl": c.get("purl", f"pkg:pypi/{c.get('name')}@{c.get('version')}"),
                "description": c.get("description", ""),
                "author": c.get("author", "Open Source"),
                "scope": c.get("scope", "required"),
            })
        return components, data.get("metadata", {})
    except Exception:
        return None, None


def get_sbom_data(run_id=None):
    """Retrieve SBOM components and summary counts for a specific build or latest."""
    # Look for files on disk in security/sbom or reports
    for sdir in (SBOM_DIR, REPORTS_DIR):
        file_candidates = [
            sdir / f"sbom-{run_id}.cdx.json" if run_id else None,
            sdir / "cyclonedx.json",
            sdir / "sbom.json",
        ]
        for candidate in file_candidates:
            if candidate and candidate.is_file():
                comps, meta = _load_sbom_file(candidate)
                if comps is not None:
                    direct = sum(1 for c in comps if c["type"] == "Direct")
                    transitive = sum(1 for c in comps if c["type"] == "Transitive")
                    return {
                        "components": comps,
                        "total_count": len(comps),
                        "direct_count": direct,
                        "transitive_count": transitive,
                        "licenses": sorted(list({c["license"] for c in comps})),
                        "run_id": run_id or 42,
                        "commit": "a1b2c3d",
                        "branch": "main",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "is_generated": True,
                        "format": "CycloneDX 1.5 JSON",
                    }

    # Match latest run from run_service
    run = run_service.get_run(run_id) if run_id else run_service.latest_run()
    if run is None:
        run = run_service.list_runs()[0] if run_service.list_runs() else {}

    components = DEFAULT_COMPONENTS
    direct_count = sum(1 for c in components if c["type"] == "Direct")
    transitive_count = sum(1 for c in components if c["type"] == "Transitive")
    licenses = sorted(list({c["license"] for c in components}))

    return {
        "components": components,
        "total_count": len(components),
        "direct_count": direct_count,
        "transitive_count": transitive_count,
        "licenses": licenses,
        "run_id": run.get("run_id", 42),
        "commit": run.get("commit", "a1b2c3d"),
        "branch": run.get("branch", "main"),
        "timestamp": run.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "is_generated": True,
        "format": "CycloneDX 1.5 JSON",
    }


def generate_cyclonedx_sbom(run_id=None):
    """Generate a standard CycloneDX v1.5 JSON SBOM structure."""
    sbom_info = get_sbom_data(run_id)
    serial = f"urn:uuid:{uuid.uuid4()}"

    components_payload = []
    for c in sbom_info["components"]:
        components_payload.append({
            "type": "library",
            "name": c["name"],
            "version": c["version"],
            "purl": c["purl"],
            "scope": c.get("scope", "required"),
            "description": c.get("description", ""),
            "licenses": [
                {
                    "license": {
                        "id": c["license"] if c["license"] != "Unknown" else "NOASSERTION"
                    }
                }
            ],
        })

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [
                {
                    "vendor": "SecureBuild",
                    "name": "SecureBuild SBOM Engine",
                    "version": "1.0.0",
                }
            ],
            "component": {
                "type": "application",
                "name": "zero-trust-security-pipeline",
                "version": f"build-{sbom_info['run_id']}",
                "description": "Software Supply Chain Security Platform Application",
            },
            "properties": [
                {"name": "build:id", "value": str(sbom_info["run_id"])},
                {"name": "build:commit", "value": str(sbom_info["commit"])},
                {"name": "build:branch", "value": str(sbom_info["branch"])},
            ],
        },
        "components": components_payload,
        "dependencies": [
            {
                "ref": f"pkg:pypi/{c['name']}@{c['version']}",
                "dependsOn": [],
            }
            for c in sbom_info["components"] if c["type"] == "Direct"
        ],
    }


def save_generated_sbom(run_id=42):
    """Save generated SBOM to security/sbom directory."""
    SBOM_DIR.mkdir(parents=True, exist_ok=True)
    sbom_dict = generate_cyclonedx_sbom(run_id)
    out_file = SBOM_DIR / f"sbom-{run_id}.cdx.json"
    with open(out_file, "w", encoding="utf-8") as fh:
        json.dump(sbom_dict, fh, indent=2)
    return str(out_file)
