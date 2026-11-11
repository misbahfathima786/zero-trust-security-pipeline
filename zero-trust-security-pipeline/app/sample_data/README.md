# Sample data = proposed data contract

`runs.json` is placeholder data for the Pipeline and Scan Results pages. It is
also the **proposed shape of the per-run report** that CI should produce, so the
backend only has to replace `_load()` in `app/services/runs.py`.

Top level: `{ "schema_version": 1, "is_sample": true, "runs": [ ... ] }`
(the real loader must set `is_sample` to false / omit it - the "Sample data" banner depends on it).

## Per-run summary fields (proposed `summary.json`)

| field | notes |
|---|---|
| `run_id` | integer, digits only (validated before any file lookup) |
| `commit`, `branch`, `trigger` | e.g. `a1b2c3d`, `main`, `push` |
| `timestamp` | UTC, `YYYY-MM-DDTHH:MM:SSZ` |
| `overall_status` | one of the statuses below |
| `duration_s` | null while running |
| `stages[]` | `key` (`code_push`, `build`, `gitleaks`, `trivy`, `policy`), `status`, `started_at`, `duration_s` |
| `secrets.count` | **null** when the scan did not complete - never 0 |
| `vulnerabilities.counts` | `critical/high/medium/low/info`; **null** when the scan did not complete |
| `policy.result`, `policy.rules[]` | rule `name`, `result`, `detail` |
| `sbom_artifact` | file name or null |

## Detail fields (come from raw reports, redacted)

`secrets.findings[]` (`rule`, `file`, `line`, `value` = always `"[REDACTED]"`),
`vulnerabilities.findings[]` (`package`, `version`, `severity`, `vuln_id`, `fixed_version`),
`artifacts[]`, `logs.build[]`, `logs.scans[]`, `timeline[]`.

## Statuses

`passed`, `failed`, `warning`, `running`, `pending`, `blocked` (scanner/database/pipeline error),
`skipped` (stages only). Any unknown value is displayed as **Blocked / Unknown**, never green.

## Rules

* A blocked or errored scan is never shown as clean or zero.
* Secret values never appear in any report passed to the UI.
* Everything here is fake (`SAMPLE-0001` ids, `[REDACTED]` markers).
