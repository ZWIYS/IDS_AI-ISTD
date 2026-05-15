#!/usr/bin/env bash
# =============================================================================
# block_ip.sh — заглушка для блокировки IP. Вызывается из 04_detect.R, если
# DETECT_PARAMS$enable_blocking = TRUE. Аргументы: IP, REASON.
#
# В проде замени на свою команду:
#   - Linux:  iptables -I INPUT -s "$IP" -j DROP
#   - macOS:  pfctl + anchor (нужны root)
#   - роутер: ssh + конфиг через API провайдера
#
# Сейчас просто пишет в лог.
# =============================================================================
set -euo pipefail

IP="${1:?usage: block_ip.sh <ip> <reason>}"
REASON="${2:-no_reason}"
TS="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

LOG_DIR="$(cd "$(dirname "$0")"/../alerts && pwd)"
mkdir -p "$LOG_DIR"
echo "${TS} BLOCK ${IP} reason=${REASON}" >> "${LOG_DIR}/blocks.log"

# === Раскомментируй одну из строк под свою платформу ===
# sudo iptables -I INPUT -s "$IP" -j DROP
# echo "block in quick from $IP" | sudo pfctl -a ids_v2 -f -

echo "[block_ip.sh] ${TS} would block ${IP} (${REASON})"
