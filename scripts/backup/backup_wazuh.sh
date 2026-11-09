#!/usr/bin/env bash
set -euo pipefail
source_dir="/var/ossec"
output_dir="${HOME}/thesis-experiments/data/raw"
label="wazuh_snapshot"
while (( $# )); do
  case "$1" in
    --source) source_dir="$2"; shift 2 ;;
    --output) output_dir="$2"; shift 2 ;;
    --label) label="$2"; shift 2 ;;
    --help|-h) echo 'Usage: bash backup_wazuh.sh [--source DIR] [--output DIR] [--label PREFIX]'; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done
for path in logs/alerts logs/archives etc/rules/thesis_insider_rules.xml; do
  test -e "$source_dir/$path" || { echo "Missing source: $path" >&2; exit 1; }
done
mkdir -p "$output_dir"
archive="$output_dir/${label}_$(date -u +%Y%m%dT%H%M%SZ).tar.gz"
test ! -e "$archive" || { echo "Refusing to overwrite $archive" >&2; exit 1; }
echo "Creating $archive"
set +e
tar -czf "$archive" -C "$source_dir" logs/alerts logs/archives etc/rules/thesis_insider_rules.xml
tar_result=$?
set -e
if (( tar_result != 0 )); then
  echo "WARNING: tar exited $tar_result (possibly active log changed); examine coverage." >&2
fi
gzip -t "$archive"
tar -tzf "$archive" > "$archive.members.txt"
sha256sum "$archive" > "$archive.sha256"
echo "Created $archive and checksum."
echo "WARNING: This live capture is not atomic. Validate log completeness separately."
