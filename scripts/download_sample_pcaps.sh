#!/usr/bin/env bash
# =============================================================================
# download_sample_pcaps.sh — заполнение data/pcap/ тестовыми трейсами Zeek
# =============================================================================
# Использует pcap-файлы, которые поставляются с самим Zeek (Homebrew/btest).
# Для реальных данных скачайте датасеты:
#   - IoT-23:    https://www.stratosphereips.org/datasets-iot23
#   - CIC-IDS:   https://www.unb.ca/cic/datasets/ids-2017.html
#   - BoT-IoT:   https://research.unsw.edu.au/projects/bot-iot-dataset
# =============================================================================
set -euo pipefail

PCAP_DIR="$(cd "$(dirname "$0")"/../data/pcap && pwd)"

# Ищем директорию с тестовыми трейсами Zeek
CANDIDATES=(
  "/opt/homebrew/Cellar/zeek/*/share/btest/data/pcaps"   # macOS Apple Silicon
  "/usr/local/Cellar/zeek/*/share/btest/data/pcaps"      # macOS Intel
  "/opt/zeek/share/btest/data/pcaps"                     # source build
  "/usr/share/zeek/btest/data/pcaps"                     # Linux package
)

ZEEK_PCAPS=""
for pattern in "${CANDIDATES[@]}"; do
  for dir in $pattern; do
    if [ -d "$dir" ]; then ZEEK_PCAPS="$dir"; break 2; fi
  done
done

if [ -z "$ZEEK_PCAPS" ]; then
  echo "ERROR: Не нашёл папку с тестовыми pcap от Zeek."
  echo "Установите Zeek: brew install zeek (или apt install zeek)"
  exit 1
fi

echo "[INFO] Источник: $ZEEK_PCAPS"

# Берём 4 разных типа трафика
declare -a SAMPLES=(
  "web.trace:web.pcap"
  "dns-spf.pcap:dns.pcap"
  "irc-basic.trace:irc.pcap"
  "socks.trace:socks.pcap"
)

for pair in "${SAMPLES[@]}"; do
  src="${pair%%:*}"
  dst="${pair##*:}"
  if [ -f "$ZEEK_PCAPS/$src" ]; then
    cp "$ZEEK_PCAPS/$src" "$PCAP_DIR/$dst"
    echo "[OK] $dst"
  else
    echo "[SKIP] $src not found"
  fi
done

echo
echo "[DONE] $(ls -1 $PCAP_DIR | wc -l | tr -d ' ') файлов в $PCAP_DIR"
ls -lh "$PCAP_DIR"
