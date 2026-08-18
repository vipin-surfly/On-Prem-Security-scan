#!/usr/bin/env bash
set -euo pipefail

REPORT_DIR="${REPORT_DIR:-$HOME/trivy-image-reports}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
VENV_PATH="${VENV_PATH:-}"
GENERATOR_URL="${GENERATOR_URL:-https://raw.githubusercontent.com/vipin-surfly/On-Prem-Security-scan/refs/heads/main/generate_report.py}"
SCRIPT_PATH="${BASH_SOURCE[0]:-}"
if [[ -n "$SCRIPT_PATH" ]]; then
  SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"
else
  SCRIPT_DIR=""
fi

scan_root=""
generator_temp=""
cleanup() {
  [[ -z "$scan_root" ]] || rm -rf -- "$scan_root"
  [[ -z "$generator_temp" ]] || rm -f -- "$generator_temp"
}
trap cleanup EXIT

usage() {
  cat <<USAGE
Usage: $0 [--keep-json] [--skip-scan] [--report-dir DIR]

Scans the Python virtual environments used by running Podman containers with Trivy,
then generates a consolidated HTML report.

Options:
  --keep-json       Do not delete old JSON files before scanning.
  --skip-scan       Skip Trivy scanning and only rebuild HTML from existing JSON.
  --report-dir DIR  Directory for JSON and HTML output.
  -h, --help        Show this help message.

Environment variables:
  REPORT_DIR         Same as --report-dir.
  PYTHON_BIN         Python executable, default: python3.
  VENV_PATH          Virtualenv path in each container. By default, use its
                     VIRTUAL_ENV environment variable or detect the active
                     Python interpreter's virtualenv.
  GENERATOR_URL      Report generator URL used when this script is piped to Bash.
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

  mapfile -t containers < <(podman ps --format '{{.ID}} {{.Image}}' | sed '/^[[:space:]]*$/d')

  if [[ ${#containers[@]} -eq 0 ]]; then
    echo "ERROR: No running Podman containers were found." >&2
    exit 2
  fi

  declare -A scanned_images=()
  scan_root=$(mktemp -d "${TMPDIR:-/tmp}/trivy-venv-scan.XXXXXX")
  failed=0
  scanned=0
  for container_entry in "${containers[@]}"; do
    container=${container_entry%% *}
    image=${container_entry#* }
    if [[ -n "${scanned_images[$image]+set}" ]]; then
      continue
    fi
    scanned_images[$image]=1

    container_venv=$VENV_PATH
    if [[ -z "$container_venv" ]]; then
      container_venv=$(podman inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$container" \
        | sed -n 's/^VIRTUAL_ENV=//p' | head -n 1)
    fi

    if [[ -z "$container_venv" ]]; then
      for python_command in python3 python; do
        container_venv=$(podman exec "$container" "$python_command" -c \
          'import sys; print(sys.prefix if sys.prefix != sys.base_prefix else "")' \
          2>/dev/null || true)
        [[ -z "$container_venv" ]] || break
      done
    fi

    if [[ -z "$container_venv" || "$container_venv" != /* ]]; then
      echo "WARNING: $image has no active Python virtualenv; skipping it." >&2
      failed=$((failed + 1))
      continue
    fi

    safe_name=$(printf '%s' "$image" | sed 's#[/:@]#_#g; s#[^A-Za-z0-9._-]#_#g')
    output_file="$REPORT_DIR/${safe_name}.json"
    scan_dir="$scan_root/$safe_name"
    mkdir -p "$scan_dir"

    echo "Scanning virtualenv: $image ($container_venv)"
    if ! podman cp "$container:$container_venv/." "$scan_dir"; then
      echo "WARNING: Could not copy virtualenv from $image" >&2
      failed=$((failed + 1))
      continue
    fi

    if ! trivy rootfs \
      --scanners vuln \
      --pkg-types library \
      --list-all-pkgs \
      --format json \
      --output "$output_file" \
      "$scan_dir"; then
      echo "WARNING: Scan failed for $image" >&2
      failed=$((failed + 1))
    elif ! "$PYTHON_BIN" -c \
      'import json, sys; d=json.load(open(sys.argv[1])); raise SystemExit(not any(r.get("Packages") for r in d.get("Results", [])))' \
      "$output_file"; then
      echo "WARNING: Trivy detected no installed packages in $image; discarding the empty scan." >&2
      rm -f -- "$output_file"
      failed=$((failed + 1))
    else
      scanned=$((scanned + 1))
    fi
  done

  echo "Scanned $scanned unique image virtualenv(s) with detected packages."

  if [[ "$failed" -gt 0 ]]; then
    echo "WARNING: $failed image scan(s) failed; generating report from successful scans." >&2
  fi
fi

if ! compgen -G "$REPORT_DIR/*.json" >/dev/null; then
  echo "ERROR: No Trivy JSON files found in $REPORT_DIR" >&2
  exit 3
fi

OUTPUT_HTML="$REPORT_DIR/consolidated-trivy-report.html"
generator_file="$SCRIPT_DIR/generate_report.py"
if [[ -z "$SCRIPT_DIR" || ! -f "$generator_file" ]]; then
  if ! command -v curl >/dev/null 2>&1; then
    echo "ERROR: curl is required when generate_report.py is not beside run_scan.sh." >&2
    exit 4
  fi
  generator_temp=$(mktemp "${TMPDIR:-/tmp}/generate-trivy-report.XXXXXX.py")
  curl -fsSL "$GENERATOR_URL" --output "$generator_temp"
  generator_file=$generator_temp
fi

"$PYTHON_BIN" "$generator_file" \
  --input-dir "$REPORT_DIR" \
  --output "$OUTPUT_HTML"

echo
echo "Report created: $OUTPUT_HTML"
