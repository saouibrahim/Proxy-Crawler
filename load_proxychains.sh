#!/usr/bin/env bash
# =============================================================================
#  load_proxychains.sh
#  Loads SOCKS5 proxies from a txt file (host:port) into /etc/proxychains4.conf
#  Designed for Kali Linux (proxychains4 / proxychains-ng)
# =============================================================================

set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────

PROXYCHAINS_CONF="/etc/proxychains4.conf"
BACKUP_DIR="/etc/proxychains_backups"
DEFAULT_INPUT="output/alive.txt"

# ── Colors ────────────────────────────────────────────────────────────────────

RED=$'\e[0;31m'
GREEN=$'\e[0;32m'
YELLOW=$'\e[1;33m'
CYAN=$'\e[0;36m'
BOLD=$'\e[1m'
RESET=$'\e[0m'

info()    { echo -e "${CYAN}[*]${RESET} $*"; }
ok()      { echo -e "${GREEN}[✓]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
die()     { echo -e "${RED}[✗]${RESET} $*" >&2; exit 1; }

# ── Usage ─────────────────────────────────────────────────────────────────────

usage() {
  printf '%b\n' "
${BOLD}Usage:${RESET}
  sudo $0 [OPTIONS] [proxy_list.txt]

${BOLD}Arguments:${RESET}
  proxy_list.txt     Path to file with SOCKS5 proxies (host:port, one per line)
                     Default: ${DEFAULT_INPUT}

${BOLD}Options:${RESET}
  -m, --mode MODE    proxychains chain mode:
                       dynamic  - skip dead proxies (recommended)   [default]
                       strict   - all proxies must respond
                       random   - random proxy from list
                       round_robin - rotate through list
  -n, --max N        Max proxies to load (default: all)
  -c, --conf PATH    Path to proxychains config (default: ${PROXYCHAINS_CONF})
  -r, --random-port  Enable proxy_dns and random_chain together
  -q, --quiet        Suppress proxy list output
  -h, --help         Show this help

${BOLD}Examples:${RESET}
  sudo $0 output/alive.txt
  sudo $0 --mode strict --max 5 output/alive.txt
  sudo $0 --mode dynamic /tmp/proxies.txt

${BOLD}After running:${RESET}
  proxychains4 curl https://ifconfig.me
  proxychains4 nmap -sT -Pn target.com
  proxychains4 firefox
  "
  exit 0
}

# ── Parse args ────────────────────────────────────────────────────────────────

MODE="dynamic"
MAX_PROXIES=0          # 0 = unlimited
CONF="${PROXYCHAINS_CONF}"
QUIET=false
INPUT_FILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -m|--mode)        MODE="$2"; shift 2 ;;
    -n|--max)         MAX_PROXIES="$2"; shift 2 ;;
    -c|--conf)        CONF="$2"; shift 2 ;;
    -q|--quiet)       QUIET=true; shift ;;
    -h|--help)        usage ;;
    -*)               die "Unknown option: $1" ;;
    *)                INPUT_FILE="$1"; shift ;;
  esac
done

[[ -z "$INPUT_FILE" ]] && INPUT_FILE="$DEFAULT_INPUT"

# ── Validate mode ─────────────────────────────────────────────────────────────

case "$MODE" in
  dynamic|strict|random|round_robin) ;;
  *) die "Invalid mode '${MODE}'. Use: dynamic, strict, random, round_robin" ;;
esac

# ── Checks ────────────────────────────────────────────────────────────────────

[[ $EUID -ne 0 ]] && die "Must run as root (use sudo)"

[[ -f "$INPUT_FILE" ]] || die "Proxy file not found: ${INPUT_FILE}"

[[ -f "$CONF" ]] || die "proxychains config not found: ${CONF}
  Install with: sudo apt install proxychains4"

# ── Parse proxy file ──────────────────────────────────────────────────────────

# Accept formats: 1.2.3.4:1080  or  1.2.3.4 1080  or  socks5 1.2.3.4 1080
mapfile -t RAW_LINES < <(grep -Ev '^\s*#|^\s*$' "$INPUT_FILE")

PROXY_LINES=()
for line in "${RAW_LINES[@]}"; do
  line="${line//$'\r'/}"   # strip CR (Windows line endings)
  # Extract ip:port pattern
  if [[ "$line" =~ ^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})[: ]([0-9]{2,5})$ ]]; then
    ip="${BASH_REMATCH[1]}"
    port="${BASH_REMATCH[2]}"
    if [[ "$port" -ge 1 && "$port" -le 65535 ]]; then
      PROXY_LINES+=("socks5  ${ip}  ${port}")
    fi
  fi
done

TOTAL="${#PROXY_LINES[@]}"
[[ "$TOTAL" -eq 0 ]] && die "No valid host:port entries found in ${INPUT_FILE}"

# Apply --max limit
if [[ "$MAX_PROXIES" -gt 0 && "$TOTAL" -gt "$MAX_PROXIES" ]]; then
  PROXY_LINES=("${PROXY_LINES[@]:0:$MAX_PROXIES}")
  USED="${MAX_PROXIES}"
else
  USED="$TOTAL"
fi

# ── Backup existing config ────────────────────────────────────────────────────

mkdir -p "$BACKUP_DIR"
BACKUP="${BACKUP_DIR}/proxychains4.conf.$(date +%Y%m%d_%H%M%S).bak"
cp "$CONF" "$BACKUP"
ok "Backup saved → ${BACKUP}"

# ── Build new config ──────────────────────────────────────────────────────────

info "Writing ${USED}/${TOTAL} proxies in '${MODE}' mode → ${CONF}"

# Build the [ProxyList] block
PROXY_BLOCK=""
for entry in "${PROXY_LINES[@]}"; do
  PROXY_BLOCK+="${entry}"$'\n'
done

# Rewrite the config:
#   1. Strip all existing chain-mode lines (we'll add the chosen one)
#   2. Strip everything from [ProxyList] to end of file
#   3. Append our new chain mode + ProxyList
HEADER=$(awk '
  /^(dynamic_chain|strict_chain|random_chain|round_robin_chain)/ { next }
  /^\[ProxyList\]/ { exit }
  { print }
' "$CONF")

# Ensure exactly one chain mode directive is active
CHAIN_DIRECTIVE="${MODE}_chain"

NEW_CONF="${HEADER}
# Chain mode set by load_proxychains.sh on $(date)
${CHAIN_DIRECTIVE}

# Quiet mode — suppress proxychains output
quiet_mode

# Proxy DNS requests through the proxy
proxy_dns

[ProxyList]
# Loaded from: ${INPUT_FILE}
# Loaded at:   $(date)
# Total:        ${USED} proxies
${PROXY_BLOCK}"

printf '%s\n' "$NEW_CONF" > "$CONF"

ok "Config updated: ${CONF}"

# ── Show result ────────────────────────────────────────────────────────────────

if [[ "$QUIET" == false ]]; then
  echo ""
  echo -e "${BOLD}─── Loaded proxies ──────────────────────────────${RESET}"
  for entry in "${PROXY_LINES[@]}"; do
    echo "  $entry"
  done
  echo -e "${BOLD}─────────────────────────────────────────────────${RESET}"
fi

echo ""
echo -e "${BOLD}Mode    :${RESET} ${MODE}"
echo -e "${BOLD}Proxies :${RESET} ${USED} loaded"
echo -e "${BOLD}Config  :${RESET} ${CONF}"
echo ""
echo -e "${GREEN}${BOLD}Done. Test with:${RESET}"
echo "  proxychains4 curl -s https://ifconfig.me"
echo "  proxychains4 curl -s https://api.ipify.org"