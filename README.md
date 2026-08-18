# Trivy Podman Running-Image Report

This project scans only the Python virtual environments in images used by currently running Podman containers and creates one searchable HTML vulnerability report. System Python packages outside the virtual environment are not included.

## Requirements

- Bash
- Python 3
- Podman
- Trivy

## Files

- `run_scan.sh`: finds running Podman images, extracts and scans their virtual environments with Trivy, and starts the report generator.
- `generate_report.py`: combines all Trivy JSON files into one HTML report.

## Run

Run directly from GitHub:

```bash
curl -fsSL https://raw.githubusercontent.com/vipin-surfly/On-Prem-Security-scan/refs/heads/main/run_scan.sh | bash
```

Alternatively, download both scripts and run them locally:

```bash
curl -fsSLO https://raw.githubusercontent.com/vipin-surfly/On-Prem-Security-scan/refs/heads/main/run_scan.sh
curl -fsSLO https://raw.githubusercontent.com/vipin-surfly/On-Prem-Security-scan/refs/heads/main/generate_report.py
chmod +x run_scan.sh generate_report.py
./run_scan.sh
```

Default output directory:

```text
$HOME/trivy-image-reports
```

Final report:

```text
$HOME/trivy-image-reports/consolidated-trivy-report.html
```

## Custom output directory

```bash
./run_scan.sh --report-dir /home/client/trivy-image-reports
```

or:

```bash
REPORT_DIR=/home/client/trivy-image-reports ./run_scan.sh
```

## Virtual environment path

By default, the scanner reads `VIRTUAL_ENV` from each running container. If it
is not set, the scanner asks the container's `python3` or `python` interpreter
for its active virtualenv. You can set one path explicitly when all containers
use the same virtual environment:

```bash
VENV_PATH=/opt/venv ./run_scan.sh
```

The path must be absolute. A non-Python container or a container whose Python
interpreter is not in a virtualenv is skipped; the scanner never falls back to
scanning its entire image.

## Generate HTML without rescanning

```bash
./run_scan.sh --skip-scan --report-dir /home/client/trivy-image-reports
```

## Keep previous JSON reports

By default, old JSON files are removed so that the report represents only the current running Podman images.

To keep existing files:

```bash
./run_scan.sh --keep-json
```

## Upload to GitHub

```bash
git init
git add .
git commit -m "Add Trivy Podman report tool"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/YOUR-REPOSITORY.git
git push -u origin main
```

## Notes

The script uses the container ID and image reported by:

```bash
podman ps --format '{{.ID}} {{.Image}}'
```

It copies only `VIRTUAL_ENV` (or `VENV_PATH`) from one running container per
unique image and invokes `trivy fs --pkg-types library` on that copy. Therefore,
packages installed in the image's system Python do not affect the results.
