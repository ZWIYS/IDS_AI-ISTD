#!/usr/bin/env bash
# =============================================================================
# import_pcaps.sh — копирование своих PCAP в data/pcap/uploaded/
# =============================================================================
# Использование:
#   bash scripts/import_pcaps.sh capture1.pcap ./captures/*.pcap
#   Rscript run_pipeline.R --pcap-dir data/pcap/uploaded
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$ROOT/data/pcap/uploaded"
mkdir -p "$DEST"

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <file.pcap> [more files...]"
  exit 1
fi

n=0
for src in "$@"; do
  [ -f "$src" ] || { echo "[SKIP] not a file: $src"; continue; }
  base="$(basename "$src")"
  case "$base" in
    *.pcap|*.pcapng|*.pcap.gz|*.PCAP|*.PCAPNG) ;;
    *) echo "[SKIP] unsupported extension: $base"; continue ;;
  esac
  cp -f "$src" "$DEST/$base"
  echo "[OK] $base"
  n=$((n + 1))
done

echo
echo "[DONE] $n file(s) in $DEST"
ls -lh "$DEST"
