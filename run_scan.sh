#!/usr/bin/env bash
set -euo pipefail

REPORT_DIR="${REPORT_DIR:-$HOME/trivy-image-reports}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<USAGE
Usage: $0 [--keep-json] [--skip-scan] [--report-dir DIR]

Scans images used by currently running Podman containers with Trivy,
then generates a consolidated HTML report.

Options:
  --keep-json       Do not delete old JSON files before scanning.
  --skip-scan       Skip Trivy scanning and only rebuild HTML from existing JSON.
  --report-dir DIR  Directory for JSON and HTML output.
  -h, --help        Show this help message.

Environment variables:
  REPORT_DIR         Same as --report-dir.
  PYTHON_BIN         Python executable, default: python3.
USAGE
}

KEEP_JSON=0
SKIP_SCAN=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --keep-json)
      KEEP_JSON=1
      shift
      ;;
    --skip-scan)
      SKIP_SCAN=1
      shift
      ;;
    --report-dir)
      [[ $# -ge 2 ]] || { echo "ERROR: --report-dir requires a value" >&2; exit 1; }
      REPORT_DIR="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

for cmd in podman trivy "$PYTHON_BIN"; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ERROR: Required command not found: $cmd" >&2
    exit 1
  fi
done

mkdir -p "$REPORT_DIR"

if [[ "$SKIP_SCAN" -eq 0 ]]; then
  if [[ "$KEEP_JSON" -eq 0 ]]; then
    rm -f "$REPORT_DIR"/*.json
  fi

  mapfile -t images < <(podman ps --format '{{.Image}}' | sed '/^[[:space:]]*$/d' | sort -u)

  if [[ ${#images[@]} -eq 0 ]]; then
    echo "ERROR: No running Podman containers were found." >&2
    exit 2
  fi

  echo "Found ${#images[@]} unique image(s) used by running containers."

  failed=0
  for image in "${images[@]}"; do
    safe_name=$(printf '%s' "$image" | sed 's#[/:@]#_#g; s#[^A-Za-z0-9._-]#_#g')
    output_file="$REPORT_DIR/${safe_name}.json"

    echo "Scanning: $image"
    if ! trivy image \
      --image-src podman \
      --scanners vuln \
      --format json \
      --output "$output_file" \
      "$image"; then
      echo "WARNING: Scan failed for $image" >&2
      failed=$((failed + 1))
    fi
  done

  if [[ "$failed" -gt 0 ]]; then
    echo "WARNING: $failed image scan(s) failed; generating report from successful scans." >&2
  fi
fi

if ! compgen -G "$REPORT_DIR/*.json" >/dev/null; then
  echo "ERROR: No Trivy JSON files found in $REPORT_DIR" >&2
  exit 3
fi

OUTPUT_HTML="$REPORT_DIR/consolidated-trivy-report.html"
"$PYTHON_BIN" "$SCRIPT_DIR/generate_report.py" \
  --input-dir "$REPORT_DIR" \
  --output "$OUTPUT_HTML"

echo
echo "Report created: $OUTPUT_HTML"
