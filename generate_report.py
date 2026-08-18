#!/usr/bin/env python3
"""Generate one searchable HTML report from Trivy JSON files."""

from __future__ import annotations

import argparse
import html
import json
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "UNKNOWN": 4,
}


@dataclass(frozen=True)
class Vulnerability:
    image: str
    target: str
    package_type: str
    vulnerability_id: str
    package_name: str
    installed_version: str
    fixed_version: str
    severity: str
    title: str
    primary_url: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create a consolidated HTML report from Trivy JSON files."
    )
    parser.add_argument("--input-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return ", ".join(str(item) for item in value)
    return str(value)


def image_name(document: dict[str, Any], source: Path) -> str:
    metadata = document.get("Metadata") or {}
    repo_tags = metadata.get("RepoTags") or []
    repo_digests = metadata.get("RepoDigests") or []

    if repo_tags:
        return text(repo_tags[0])
    if repo_digests:
        return text(repo_digests[0])

    # Filesystem scans use a temporary extraction path as ArtifactName. The
    # report filename is the stable image identifier chosen by run_scan.sh.
    return source.stem


def load_vulnerabilities(
    paths: Iterable[Path],
) -> tuple[list[Vulnerability], set[str], list[str]]:
    vulnerabilities: list[Vulnerability] = []
    images: set[str] = set()
    errors: list[str] = []

    for path in paths:
        try:
            with path.open("r", encoding="utf-8") as handle:
                document = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"{path.name}: {exc}")
            continue

        image = image_name(document, path)
        images.add(image)
        for result in document.get("Results") or []:
            target = text(result.get("Target"))
            package_type = text(result.get("Type"))
            for item in result.get("Vulnerabilities") or []:
                severity = text(item.get("Severity") or "UNKNOWN").upper()
                vulnerability_id = text(item.get("VulnerabilityID"))
                primary_url = text(item.get("PrimaryURL"))
                if not primary_url and vulnerability_id.startswith("CVE-"):
                    primary_url = f"https://nvd.nist.gov/vuln/detail/{vulnerability_id}"

                vulnerabilities.append(
                    Vulnerability(
                        image=image,
                        target=target,
                        package_type=package_type,
                        vulnerability_id=vulnerability_id,
                        package_name=text(item.get("PkgName")),
                        installed_version=text(item.get("InstalledVersion")),
                        fixed_version=text(item.get("FixedVersion")),
                        severity=severity,
                        title=text(item.get("Title")),
                        primary_url=primary_url,
                    )
                )

    vulnerabilities.sort(
        key=lambda item: (
            SEVERITY_ORDER.get(item.severity, 99),
            item.image.lower(),
            item.vulnerability_id.lower(),
            item.package_name.lower(),
        )
    )
    return vulnerabilities, images, errors


def esc(value: str) -> str:
    return html.escape(value, quote=True)


def make_report(
    vulnerabilities: list[Vulnerability], images: set[str], errors: list[str]
) -> str:
    counts = Counter(item.severity for item in vulnerabilities)

    rows: list[str] = []
    for item in vulnerabilities:
        vuln_label = esc(item.vulnerability_id or "Unknown")
        if item.primary_url:
            vuln_cell = (
                f'<a href="{esc(item.primary_url)}" target="_blank" '
                f'rel="noopener noreferrer">{vuln_label}</a>'
            )
        else:
            vuln_cell = vuln_label

        rows.append(
            "<tr>"
            f'<td data-sort="{esc(item.severity)}"><span class="badge severity-{esc(item.severity.lower())}">{esc(item.severity)}</span></td>'
            f"<td>{esc(item.image)}</td>"
            f"<td>{esc(item.target)}</td>"
            f"<td>{esc(item.package_type)}</td>"
            f"<td>{vuln_cell}</td>"
            f"<td>{esc(item.package_name)}</td>"
            f"<td>{esc(item.installed_version)}</td>"
            f"<td>{esc(item.fixed_version or 'Not fixed')}</td>"
            f"<td>{esc(item.title)}</td>"
            "</tr>"
        )

    error_html = ""
    if errors:
        items = "".join(f"<li>{esc(error)}</li>" for error in errors)
        error_html = f'<section class="warning"><strong>Files skipped:</strong><ul>{items}</ul></section>'

    if not rows:
        message = (
            f"No vulnerabilities found in {len(images)} scanned image virtualenv(s)."
            if images
            else "No image virtualenvs were scanned."
        )
        rows.append(f'<tr><td colspan="9" class="empty">{message}</td></tr>')

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Trivy Podman Vulnerability Report</title>
<style>
:root {{ color-scheme: light dark; font-family: Arial, sans-serif; }}
body {{ margin: 0; padding: 24px; background: #f5f6f8; color: #202124; }}
main {{ max-width: 1600px; margin: auto; }}
h1 {{ margin-bottom: 6px; }}
.subtitle {{ margin-top: 0; color: #5f6368; }}
.cards {{ display: grid; grid-template-columns: repeat(5, minmax(120px, 1fr)); gap: 12px; margin: 24px 0; }}
.card {{ background: white; border-radius: 10px; padding: 16px; box-shadow: 0 1px 4px rgba(0,0,0,.12); }}
.card strong {{ display: block; font-size: 1.7rem; margin-top: 6px; }}
.controls {{ display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 16px; }}
input, select {{ padding: 10px; border: 1px solid #c7c7c7; border-radius: 6px; background: white; color: #202124; }}
input {{ flex: 1; min-width: 280px; }}
.table-wrap {{ overflow-x: auto; background: white; border-radius: 10px; box-shadow: 0 1px 4px rgba(0,0,0,.12); }}
table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
th, td {{ padding: 10px; border-bottom: 1px solid #e5e5e5; text-align: left; vertical-align: top; }}
th {{ position: sticky; top: 0; background: #202124; color: white; cursor: pointer; white-space: nowrap; }}
tr:hover td {{ background: #f7f9fc; }}
.badge {{ display: inline-block; min-width: 72px; text-align: center; border-radius: 999px; padding: 4px 8px; font-weight: 700; color: white; }}
.severity-critical {{ background: #7b1fa2; }}
.severity-high {{ background: #c62828; }}
.severity-medium {{ background: #ef6c00; }}
.severity-low {{ background: #2e7d32; }}
.severity-unknown {{ background: #546e7a; }}
.warning {{ padding: 14px; margin-bottom: 16px; background: #fff3cd; border: 1px solid #ffe69c; border-radius: 8px; }}
.empty {{ text-align: center; padding: 30px; }}
a {{ color: #1565c0; }}
@media (prefers-color-scheme: dark) {{
  body {{ background: #111315; color: #e8eaed; }}
  .subtitle {{ color: #bdc1c6; }}
  .card, .table-wrap {{ background: #202124; }}
  input, select {{ background: #202124; color: #e8eaed; border-color: #5f6368; }}
  tr:hover td {{ background: #292a2d; }}
  td {{ border-color: #3c4043; }}
  a {{ color: #8ab4f8; }}
  .warning {{ background: #4a3b00; border-color: #806600; }}
}}
</style>
</head>
<body>
<main>
<h1>Trivy Podman Vulnerability Report</h1>
<p class="subtitle">Unique running images: {len(images)} &middot; Total vulnerabilities: {len(vulnerabilities)}</p>
<div class="cards">
  <div class="card">Critical<strong>{counts.get('CRITICAL', 0)}</strong></div>
  <div class="card">High<strong>{counts.get('HIGH', 0)}</strong></div>
  <div class="card">Medium<strong>{counts.get('MEDIUM', 0)}</strong></div>
  <div class="card">Low<strong>{counts.get('LOW', 0)}</strong></div>
  <div class="card">Unknown<strong>{counts.get('UNKNOWN', 0)}</strong></div>
</div>
{error_html}
<div class="controls">
  <input id="search" type="search" placeholder="Search image, CVE, package, version, or title">
  <select id="severity">
    <option value="">All severities</option>
    <option>CRITICAL</option>
    <option>HIGH</option>
    <option>MEDIUM</option>
    <option>LOW</option>
    <option>UNKNOWN</option>
  </select>
</div>
<div class="table-wrap">
<table id="report-table">
<thead>
<tr>
<th>Severity</th><th>Image</th><th>Target</th><th>Type</th><th>Vulnerability</th>
<th>Package</th><th>Installed</th><th>Fixed</th><th>Title</th>
</tr>
</thead>
<tbody>
{''.join(rows)}
</tbody>
</table>
</div>
</main>
<script>
const table = document.getElementById('report-table');
const search = document.getElementById('search');
const severity = document.getElementById('severity');

function filterRows() {{
  const query = search.value.toLowerCase().trim();
  const selected = severity.value;
  for (const row of table.tBodies[0].rows) {{
    if (row.cells.length < 9) continue;
    const text = row.innerText.toLowerCase();
    const rowSeverity = row.cells[0].innerText.trim();
    row.hidden = !(text.includes(query) && (!selected || rowSeverity === selected));
  }}
}}
search.addEventListener('input', filterRows);
severity.addEventListener('change', filterRows);

for (const [index, header] of [...table.tHead.rows[0].cells].entries()) {{
  header.addEventListener('click', () => {{
    const rows = [...table.tBodies[0].rows];
    const ascending = header.dataset.order !== 'asc';
    for (const other of table.tHead.rows[0].cells) delete other.dataset.order;
    header.dataset.order = ascending ? 'asc' : 'desc';
    rows.sort((a, b) => {{
      const left = a.cells[index]?.innerText.trim() || '';
      const right = b.cells[index]?.innerText.trim() || '';
      return left.localeCompare(right, undefined, {{ numeric: true }}) * (ascending ? 1 : -1);
    }});
    rows.forEach(row => table.tBodies[0].appendChild(row));
  }});
}}
</script>
</body>
</html>
"""


def main() -> int:
    args = parse_args()
    input_dir = args.input_dir.expanduser().resolve()
    output = args.output.expanduser().resolve()

    if not input_dir.is_dir():
        print(f"ERROR: Input directory does not exist: {input_dir}", file=sys.stderr)
        return 1

    json_files = sorted(input_dir.glob("*.json"))
    if not json_files:
        print(f"ERROR: No JSON files found in {input_dir}", file=sys.stderr)
        return 2

    vulnerabilities, images, errors = load_vulnerabilities(json_files)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(make_report(vulnerabilities, images, errors), encoding="utf-8")

    print(f"Processed {len(json_files)} JSON file(s).")
    print(f"Found {len(images)} scanned image virtualenv(s).")
    print(f"Found {len(vulnerabilities)} vulnerability record(s).")
    print(f"Wrote HTML report to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
