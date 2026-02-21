#!/usr/bin/env bash
# WebGuard URL Scanner v1.0 — Frontend security scanner (Mac/Linux)
# Usage: bash scan-url.sh <url>
# Example: bash scan-url.sh https://example.com

set -euo pipefail

URL="${1:-}"
if [[ -z "$URL" ]]; then
    echo "Usage: bash scan-url.sh <url>"
    exit 1
fi

URL="${URL%/}"
HOST=$(python3 -c "from urllib.parse import urlparse; print(urlparse('$URL').netloc)" 2>/dev/null || \
       echo "$URL" | sed 's|https\?://||' | cut -d'/' -f1)

FINDINGS_CRIT=()
FINDINGS_HIGH=()
FINDINGS_MED=()
FINDINGS_LOW=()
PASSED=()

# ── Helpers ───────────────────────────────────────────────────────────────────

fetch_headers() {
    curl -sI --max-time 10 --location "$1" 2>/dev/null
}

fetch_body() {
    curl -sL --max-time 15 "$1" 2>/dev/null
}

fetch_status() {
    curl -so /dev/null -w "%{http_code}" --max-time 8 --location "$1" 2>/dev/null || echo "0"
}

fetch_body_status() {
    # Returns body to stdout, writes status to $TMPSTATUS
    TMPSTATUS=$(mktemp)
    BODY=$(curl -sL --max-time 10 -w "%{http_code}" -o /dev/null "$1" 2>/dev/null || echo "0")
    echo "$BODY"
}

header_value() {
    local headers="$1"
    local name="$2"
    echo "$headers" | grep -i "^${name}:" | head -1 | sed 's/^[^:]*: *//' | tr -d '\r'
}

echo ""
echo "🔍 WebGuard Report — $HOST"
echo "━━━━━━━━━━━━━━━━━━━"
echo "  Scanning $URL ..."
echo ""

# ── 1. SSL / HTTPS ────────────────────────────────────────────────────────────

if [[ "$URL" != https://* ]]; then
    FINDINGS_CRIT+=("Site not served over HTTPS — traffic can be intercepted")
else
    PASSED+=("HTTPS is enforced on the main URL")
    # Check HTTP -> HTTPS redirect
    HTTP_URL="${URL/https:\/\//http://}"
    REDIR_URL=$(curl -sI --max-time 8 -L "$HTTP_URL" 2>/dev/null | grep -i "^location:" | tail -1 | sed 's/^[Ll]ocation: *//' | tr -d '\r')
    if [[ "$REDIR_URL" == https://* ]]; then
        PASSED+=("HTTP correctly redirects to HTTPS")
    else
        FINDINGS_HIGH+=("HTTP does not redirect to HTTPS — plaintext access possible")
    fi
fi

# ── 2. Fetch main page ────────────────────────────────────────────────────────

HEADERS=$(fetch_headers "$URL")
HTML=$(fetch_body "$URL")

if [[ -z "$HTML" ]]; then
    echo "[CRITICAL] Could not fetch $URL — scanner aborted"
    exit 1
fi

# ── 3. Security Headers ───────────────────────────────────────────────────────

check_header() {
    local hname="$1"
    local label="$2"
    local level="$3"
    local val
    val=$(header_value "$HEADERS" "$hname")
    if [[ -z "$val" ]]; then
        case "$level" in
            CRITICAL) FINDINGS_CRIT+=("Missing $label header") ;;
            HIGH)     FINDINGS_HIGH+=("Missing $label header") ;;
            MEDIUM)   FINDINGS_MED+=("Missing $label header") ;;
            LOW)      FINDINGS_LOW+=("Missing $label header") ;;
        esac
    else
        PASSED+=("$label header present")
    fi
}

check_header "Content-Security-Policy"   "Content-Security-Policy (CSP)"        "HIGH"
check_header "Strict-Transport-Security" "HTTP Strict-Transport-Security (HSTS)" "HIGH"
check_header "X-Frame-Options"           "X-Frame-Options"                       "MEDIUM"
check_header "X-Content-Type-Options"    "X-Content-Type-Options"                "LOW"
check_header "Referrer-Policy"           "Referrer-Policy"                       "LOW"

# ── 4. JS Library Version Detection ──────────────────────────────────────────

detect_lib() {
    local name="$1"
    local pattern="$2"
    local cve="$3"
    local safe="$4"
    local level="$5"
    local ver
    ver=$(echo "$HTML" | grep -oiE "$pattern" | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    if [[ -n "$ver" ]]; then
        if [[ -n "$cve" ]]; then
            case "$level" in
                HIGH)   FINDINGS_HIGH+=("$name $ver detected — check against $cve (safe: v${safe}+)") ;;
                MEDIUM) FINDINGS_MED+=("$name $ver detected — check against $cve (safe: v${safe}+)") ;;
                LOW)    FINDINGS_LOW+=("$name $ver detected — check against $cve (safe: v${safe}+)") ;;
            esac
        else
            PASSED+=("$name $ver detected (no known critical CVE flagged)")
        fi
    fi
}

detect_lib "jQuery"    'jquery[.-][0-9]+\.[0-9]+\.[0-9]+'    "CVE-2020-11022" "3.5.0"   "HIGH"
detect_lib "Bootstrap" 'bootstrap[.-][0-9]+\.[0-9]+\.[0-9]+' "CVE-2019-8331"  "4.3.1"   "MEDIUM"
detect_lib "lodash"    'lodash[.-][0-9]+\.[0-9]+\.[0-9]+'    "CVE-2021-23337" "4.17.21" "HIGH"
detect_lib "Angular"   'angular[.-][0-9]+\.[0-9]+\.[0-9]+'   "CVE-2019-14863" "2.0.0"   "HIGH"
detect_lib "React"     'react[.-][0-9]+\.[0-9]+\.[0-9]+'     ""               ""         "LOW"

# ── 5. Exposed Sensitive Files ────────────────────────────────────────────────

check_exposed() {
    local path="$1"
    local label="$2"
    local test_url="${URL%/}${path}"
    local status
    status=$(curl -so /dev/null -w "%{http_code}" --max-time 8 "$test_url" 2>/dev/null || echo "0")
    local body_size
    body_size=$(curl -sL --max-time 8 "$test_url" 2>/dev/null | wc -c)
    if [[ "$status" == "200" && "$body_size" -gt 10 ]]; then
        FINDINGS_CRIT+=("$label publicly accessible at $test_url — may expose credentials/config")
    fi
}

check_exposed "/.env"        ".env file"
check_exposed "/.git/config" ".git/config"
check_exposed "/.htaccess"   ".htaccess"
check_exposed "/backup.zip"  "backup.zip"
check_exposed "/config.php"  "config.php"

# ── 6. Mixed Content ──────────────────────────────────────────────────────────

if [[ "$URL" == https://* ]]; then
    MIXED=$(echo "$HTML" | grep -oiE '(src|href|url)\s*=\s*['"'"'"]?http://[^\s'"'"'"<>]+' | head -5)
    if [[ -n "$MIXED" ]]; then
        COUNT=$(echo "$MIXED" | wc -l | tr -d ' ')
        EXAMPLE=$(echo "$MIXED" | head -1 | sed 's/.*http:\/\//http:\/\//' | cut -c1-80)
        FINDINGS_MED+=("Mixed content detected — $COUNT HTTP asset(s) on HTTPS page (e.g. $EXAMPLE)")
    else
        PASSED+=("No mixed content detected")
    fi
fi

# ── 7. Build Report ───────────────────────────────────────────────────────────

RED='\033[0;31m'
YELLOW='\033[1;33m'
ORANGE='\033[0;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

print_section() {
    local icon="$1"
    local level="$2"
    local color="$3"
    shift 3
    local items=("$@")
    if [[ ${#items[@]} -gt 0 ]]; then
        echo -e "${color}${icon} ${level} (${#items[@]})${NC}"
        for item in "${items[@]}"; do
            echo "  • $item"
        done
        echo ""
    fi
}

echo "🔍 WebGuard Report — $HOST"
echo "━━━━━━━━━━━━━━━━━━━"
echo ""

HAS_FINDINGS=0
[[ ${#FINDINGS_CRIT[@]} -gt 0 ]] && HAS_FINDINGS=1
[[ ${#FINDINGS_HIGH[@]} -gt 0 ]] && HAS_FINDINGS=1
[[ ${#FINDINGS_MED[@]} -gt 0 ]]  && HAS_FINDINGS=1
[[ ${#FINDINGS_LOW[@]} -gt 0 ]]  && HAS_FINDINGS=1

print_section "🔴" "CRITICAL" "$RED"    "${FINDINGS_CRIT[@]+"${FINDINGS_CRIT[@]}"}"
print_section "🟠" "HIGH"     "$ORANGE" "${FINDINGS_HIGH[@]+"${FINDINGS_HIGH[@]}"}"
print_section "🟡" "MEDIUM"   "$YELLOW" "${FINDINGS_MED[@]+"${FINDINGS_MED[@]}"}"
print_section "🟢" "LOW"      "$GREEN"  "${FINDINGS_LOW[@]+"${FINDINGS_LOW[@]}"}"

if [[ $HAS_FINDINGS -eq 0 ]]; then
    echo -e "${GREEN}✅ No vulnerabilities found!${NC}"
    echo ""
fi

if [[ ${#PASSED[@]} -gt 0 ]]; then
    echo -e "${GREEN}✅ PASSED${NC}"
    for p in "${PASSED[@]}"; do
        echo -e "  • ${GREEN}$p${NC}"
    done
    echo ""
fi

# Top fixes
ALL_FINDINGS=("${FINDINGS_CRIT[@]+"${FINDINGS_CRIT[@]}"}" \
              "${FINDINGS_HIGH[@]+"${FINDINGS_HIGH[@]}"}" \
              "${FINDINGS_MED[@]+"${FINDINGS_MED[@]}"}" \
              "${FINDINGS_LOW[@]+"${FINDINGS_LOW[@]}"}")

if [[ ${#ALL_FINDINGS[@]} -gt 0 ]]; then
    echo "📋 Top Fix:"
    for i in "${!ALL_FINDINGS[@]}"; do
        [[ $i -ge 2 ]] && break
        echo -e "${CYAN}→ ${ALL_FINDINGS[$i]}${NC}"
    done
    echo ""
fi

echo "━━━━━━━━━━━━━━━━━━━"
echo "by cybersecurity experts | WebGuard v1.0"
