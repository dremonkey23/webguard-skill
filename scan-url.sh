#!/usr/bin/env bash
# WebGuard — URL Scanner (bash)
# Usage: ./scan-url.sh <URL>
# Example: ./scan-url.sh https://example.com

set -euo pipefail

URL="${1:-}"
if [[ -z "$URL" ]]; then
  echo "Usage: $0 <URL>"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Strip trailing slash
URL="${URL%/}"
# Default to https if no scheme
if [[ "$URL" != http://* && "$URL" != https://* ]]; then
  URL="https://$URL"
fi

SCHEME="${URL%%://*}"
HOST=$(echo "$URL" | sed -E 's|https?://([^/]+).*|\1|')
BASE_URL="${SCHEME}://${HOST}"
HTTP_BASE="http://${HOST}"
DIVIDER="━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ─── Severity arrays ─────────────────────────────────────────────────────────
CRITICAL=()
HIGH=()
MEDIUM=()
LOW=()
INFO=()

echo ""
echo "🔍 WebGuard — Scanning $HOST ..."
echo ""

# ─── Helpers ──────────────────────────────────────────────────────────────────
check_url_status() {
  local url="$1"
  local timeout="${2:-8}"
  curl -s -o /dev/null -w "%{http_code}" --max-time "$timeout" \
       --connect-timeout 5 -L "$url" 2>/dev/null || echo "000"
}

fetch_headers() {
  local url="$1"
  curl -s -I --max-time 15 --connect-timeout 5 -L "$url" 2>/dev/null || true
}

fetch_body() {
  local url="$1"
  curl -s --max-time 20 --connect-timeout 5 -L "$url" 2>/dev/null || true
}

get_header() {
  local headers="$1"
  local name="$2"
  echo "$headers" | grep -i "^${name}:" | head -1 | sed 's/^[^:]*: //' | tr -d '\r' || true
}

# ─── Load patterns from encoded data ─────────────────────────────────────────
PATTERNS_RAW=$(base64 -d "$SCRIPT_DIR/patterns/urls.json.b64" 2>/dev/null || base64 -D "$SCRIPT_DIR/patterns/urls.json.b64" 2>/dev/null || python3 -c "import base64; print(base64.b64decode(open('$SCRIPT_DIR/patterns/urls.json.b64').read().strip()).decode())")
PATTERNS_FILE=$(mktemp)
echo "$PATTERNS_RAW" > "$PATTERNS_FILE"
trap "rm -f $PATTERNS_FILE" EXIT

# ─── 1. SSL / HTTPS Check ────────────────────────────────────────────────────
if [[ "$SCHEME" != "https" ]]; then
  CRITICAL+=("Site uses HTTP — all traffic is unencrypted and can be intercepted")
else
  HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 \
    --connect-timeout 5 --max-redirs 0 "$HTTP_BASE" 2>/dev/null || echo "000")
  if [[ "$HTTP_STATUS" == "200" ]]; then
    CRITICAL+=("HTTP version returns 200 (no redirect to HTTPS) — traffic interception risk")
  elif [[ "$HTTP_STATUS" =~ ^(301|302|307|308)$ ]]; then
    INFO+=("HTTPS enforced via redirect ($HTTP_STATUS)")
  else
    INFO+=("HTTPS detected — encrypted connection")
  fi

  SSL_CHECK=$(echo | openssl s_client -connect "${HOST}:443" \
    -servername "$HOST" 2>/dev/null | openssl x509 -noout -dates 2>/dev/null || true)
  if [[ -z "$SSL_CHECK" ]]; then
    HIGH+=("SSL certificate could not be verified — may be self-signed or expired")
  else
    EXPIRY=$(echo "$SSL_CHECK" | grep "notAfter" | cut -d= -f2)
    INFO+=("SSL certificate valid — expires: $EXPIRY")
  fi
fi

# ─── 2. Fetch headers and body ───────────────────────────────────────────────
HEADERS=$(fetch_headers "$URL")
if [[ -z "$HEADERS" ]]; then
  echo "❌ Could not reach $URL — scan aborted."
  exit 1
fi

BODY=$(fetch_body "$URL")

# ─── 3. Security Headers ─────────────────────────────────────────────────────
CSP=$(get_header "$HEADERS" "content-security-policy")
if [[ -z "$CSP" ]]; then
  HIGH+=("Missing Content-Security-Policy header — XSS attacks are unrestricted")
else
  INFO+=("Content-Security-Policy header present")
fi

if [[ "$SCHEME" == "https" ]]; then
  HSTS=$(get_header "$HEADERS" "strict-transport-security")
  if [[ -z "$HSTS" ]]; then
    HIGH+=("Missing Strict-Transport-Security (HSTS) — browsers may fall back to HTTP")
  else
    INFO+=("HSTS header present")
  fi
fi

XFO=$(get_header "$HEADERS" "x-frame-options")
if [[ -z "$XFO" ]]; then
  MEDIUM+=("Missing X-Frame-Options header — site may be vulnerable to clickjacking")
else
  INFO+=("X-Frame-Options header present")
fi

XCTO=$(get_header "$HEADERS" "x-content-type-options")
if [[ -z "$XCTO" ]]; then
  LOW+=("Missing X-Content-Type-Options header — MIME-type sniffing possible")
else
  INFO+=("X-Content-Type-Options header present")
fi

RP=$(get_header "$HEADERS" "referrer-policy")
if [[ -z "$RP" ]]; then
  LOW+=("Missing Referrer-Policy header — referrer data may leak to third parties")
else
  INFO+=("Referrer-Policy header present")
fi

SERVER=$(get_header "$HEADERS" "server")
if [[ -n "$SERVER" ]]; then
  if echo "$SERVER" | grep -qE '[0-9]'; then
    LOW+=("Server header exposes version info: '$SERVER' — aids fingerprinting")
  else
    INFO+=("Server header present (no version): $SERVER")
  fi
fi

POWERED=$(get_header "$HEADERS" "x-powered-by")
if [[ -n "$POWERED" ]]; then
  LOW+=("X-Powered-By header exposes technology: '$POWERED'")
fi

# ─── 4. Outdated/Vulnerable JS Libraries (from patterns file) ────────────────
if command -v python3 &>/dev/null && [[ -f "$PATTERNS_FILE" ]]; then
  while IFS='|' read -r lib_name lib_regex lib_cve; do
    [[ -z "$lib_regex" ]] && continue
    VERSION=$(echo "$BODY" | grep -oiE "$lib_regex" | grep -oE '[0-9]+\.[0-9]+\.?[0-9]*' | head -1 || true)
    if [[ -n "$VERSION" ]]; then
      HIGH+=("$lib_name $VERSION detected in page source — $lib_cve")
    fi
  done < <(python3 -c "
import json
data = json.load(open('$PATTERNS_FILE'))
for lib in data.get('libraries', []):
    print(f\"{lib['name']}|{lib['r']}|{lib['cve']}\")
")
fi

# ─── 5. Exposed Sensitive Files (from patterns file) ─────────────────────────
if command -v python3 &>/dev/null && [[ -f "$PATTERNS_FILE" ]]; then
  while IFS='|' read -r fpath fsev fdesc; do
    [[ -z "$fpath" ]] && continue
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 6 \
      --connect-timeout 4 "${BASE_URL}${fpath}" 2>/dev/null || echo "000")
    if [[ "$STATUS" == "200" ]]; then
      case "$fsev" in
        critical) CRITICAL+=("$fdesc at $fpath") ;;
        high)     HIGH+=("$fdesc at $fpath") ;;
        medium)   MEDIUM+=("$fdesc at $fpath") ;;
      esac
    fi
  done < <(python3 -c "
import json
data = json.load(open('$PATTERNS_FILE'))
for f in data.get('sensitive_files', []):
    print(f\"{f['path']}|{f['s']}|{f['d']}\")
")
fi

# ─── 6. Mixed Content ─────────────────────────────────────────────────────────
if [[ "$SCHEME" == "https" && -n "$BODY" ]]; then
  MIXED_COUNT=$(echo "$BODY" | grep -oE '(src|href)="http://[^"]+' | wc -l | tr -d ' ' || echo "0")
  if [[ "$MIXED_COUNT" -gt 0 ]]; then
    MEDIUM+=("Mixed content detected — $MIXED_COUNT HTTP asset(s) loaded on HTTPS page")
  fi
fi

# ─── 7. Cookie Flags ──────────────────────────────────────────────────────────
COOKIE=$(get_header "$HEADERS" "set-cookie")
if [[ -n "$COOKIE" ]]; then
  if ! echo "$COOKIE" | grep -qi "httponly"; then
    MEDIUM+=("Session cookie missing HttpOnly flag — JavaScript can read cookies (XSS risk)")
  fi
  if [[ "$SCHEME" == "https" ]] && ! echo "$COOKIE" | grep -qi "secure"; then
    MEDIUM+=("Session cookie missing Secure flag — cookie may be sent over HTTP")
  fi
  if ! echo "$COOKIE" | grep -qi "samesite"; then
    LOW+=("Session cookie missing SameSite attribute — CSRF risk")
  fi
fi

# ─── Build Report ──────────────────────────────────────────────────────────────
echo ""
echo "🔍 WebGuard Report — $HOST"
echo "$DIVIDER"
echo ""

if [[ ${#CRITICAL[@]} -gt 0 ]]; then
  echo "🔴 CRITICAL (${#CRITICAL[@]})"
  for i in "${CRITICAL[@]}"; do echo "  • $i"; done
  echo ""
fi

if [[ ${#HIGH[@]} -gt 0 ]]; then
  echo "🟠 HIGH (${#HIGH[@]})"
  for i in "${HIGH[@]}"; do echo "  • $i"; done
  echo ""
fi

if [[ ${#MEDIUM[@]} -gt 0 ]]; then
  echo "🟡 MEDIUM (${#MEDIUM[@]})"
  for i in "${MEDIUM[@]}"; do echo "  • $i"; done
  echo ""
fi

if [[ ${#LOW[@]} -gt 0 ]]; then
  echo "🟢 LOW (${#LOW[@]})"
  for i in "${LOW[@]}"; do echo "  • $i"; done
  echo ""
fi

if [[ ${#INFO[@]} -gt 0 ]]; then
  echo "ℹ️  INFO (${#INFO[@]})"
  for i in "${INFO[@]}"; do echo "  • $i"; done
  echo ""
fi

if [[ ${#CRITICAL[@]} -eq 0 && ${#HIGH[@]} -eq 0 && ${#MEDIUM[@]} -eq 0 && ${#LOW[@]} -eq 0 ]]; then
  echo "✅ No issues found — site looks clean!"
  echo ""
fi

# Top Fixes
TOP_FIXES=()
for i in "${CRITICAL[@]}"; do
  [[ "$i" =~ HTTP|http ]] && TOP_FIXES+=("Redirect all HTTP traffic to HTTPS") && break
done
for i in "${HIGH[@]}"; do
  [[ "$i" =~ Content-Security-Policy ]] && TOP_FIXES+=("Add CSP header: Content-Security-Policy: default-src 'self'") && break
done
for i in "${HIGH[@]}"; do
  [[ "$i" =~ "detected in page" ]] && TOP_FIXES+=("Update JS libraries to latest stable versions") && break
done

if [[ ${#TOP_FIXES[@]} -gt 0 ]]; then
  echo "📋 Top Fix:"
  for fix in "${TOP_FIXES[@]}"; do
    echo "→ $fix"
  done
  echo ""
fi

echo "$DIVIDER"
echo "by cybersecurity experts | WebGuard v1.0"
echo ""
