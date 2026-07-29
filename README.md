# Trivy Podman Running-Image Report

This project scans only the images used by currently running Podman containers and creates one searchable HTML vulnerability report.

## Requirements

- Bash
- Python 3
- Podman
- Trivy

## Files

- `run_scan.sh`: finds running Podman images, scans them with Trivy, and starts the report generator.
- `generate_report.py`: combines all Trivy JSON files into one HTML report.

## Run

```bash
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

The script uses:

```bash
podman ps --format '{{.Image}}'
```

Therefore, it scans images referenced by running containers only. It scans each unique image once, even when several running containers use the same image.
