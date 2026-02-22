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

# ─── 1. SSL / HTTPS Check ────────────────────────────────────────────────────
if [[ "$SCHEME" != "https" ]]; then
  CRITICAL+=("Site uses HTTP — all traffic is unencrypted and can be intercepted")
else
  # Check if HTTP redirects to HTTPS
  HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 \
    --connect-timeout 5 --max-redirs 0 "$HTTP_BASE" 2>/dev/null || echo "000")
  if [[ "$HTTP_STATUS" == "200" ]]; then
    CRITICAL+=("HTTP version returns 200 (no redirect to HTTPS) — traffic interception risk")
  elif [[ "$HTTP_STATUS" =~ ^(301|302|307|308)$ ]]; then
    INFO+=("HTTPS enforced via redirect ($HTTP_STATUS)")
  else
    INFO+=("HTTPS detected — encrypted connection")
  fi

  # SSL certificate check
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

# Server header fingerprinting
SERVER=$(get_header "$HEADERS" "server")
if [[ -n "$SERVER" ]]; then
  if echo "$SERVER" | grep -qE '[0-9]'; then
    LOW+=("Server header exposes version info: '$SERVER' — aids fingerprinting")
  else
    INFO+=("Server header present (no version): $SERVER")
  fi
fi

# X-Powered-By
POWERED=$(get_header "$HEADERS" "x-powered-by")
if [[ -n "$POWERED" ]]; then
  LOW+=("X-Powered-By header exposes technology: '$POWERED'")
fi

# ─── 4. Outdated/Vulnerable JS Libraries ─────────────────────────────────────
declare -A LIBS=(
  ["jQuery"]='jquery[.-]([0-9]+\.[0-9]+\.?[0-9]*)(\.min)?\.js'
  ["Angular"]='angular[.-]([0-9]+\.[0-9]+\.?[0-9]*)(\.min)?\.js'
  ["React"]='react[.-]([0-9]+\.[0-9]+\.?[0-9]*)(\.min)?\.js'
  ["Bootstrap"]='bootstrap[.-]([0-9]+\.[0-9]+\.?[0-9]*)(\.min)?\.js'
  ["Lodash"]='lodash[.-]([0-9]+\.[0-9]+\.?[0-9]*)(\.min)?\.js'
  ["Moment.js"]='moment[.-]([0-9]+\.[0-9]+\.?[0-9]*)(\.min)?\.js'
)

declare -A LIB_CVE=(
  ["jQuery"]="1.x/2.x: CVE-2019-11358 (XSS), CVE-2020-11022"
  ["Angular"]="<1.8: multiple XSS CVEs"
  ["React"]="<16.9: CVE-2018-6341"
  ["Bootstrap"]="<3.4.1: CVE-2019-8331 (XSS)"
  ["Lodash"]="<4.17.21: CVE-2021-23337 (injection)"
  ["Moment.js"]="<2.29.2: CVE-2022-24785 (path traversal)"
)

for lib in "${!LIBS[@]}"; do
  VERSION=$(echo "$BODY" | grep -oiE "${LIBS[$lib]}" | grep -oE '[0-9]+\.[0-9]+\.?[0-9]*' | head -1 || true)
  if [[ -n "$VERSION" ]]; then
    HIGH+=("$lib $VERSION detected in page source — ${LIB_CVE[$lib]}")
  fi
done

# ─── 5. Exposed Sensitive Files ───────────────────────────────────────────────
declare -A SENSITIVE_FILES=(
  ["/.env"]="critical|.env file accessible — may expose credentials and API keys"
  ["/.git/config"]="critical|.git/config accessible — source code structure exposed"
  ["/.htaccess"]="medium|.htaccess accessible — server config may be readable"
  ["/backup.zip"]="high|backup.zip accessible — full site backup may be downloadable"
  ["/backup.tar.gz"]="high|backup.tar.gz accessible"
  ["/config.php"]="high|config.php accessible — database credentials may be exposed"
  ["/wp-config.php"]="high|wp-config.php accessible — WordPress DB credentials exposed"
  ["/.DS_Store"]="medium|.DS_Store accessible — directory structure revealed"
  ["/phpinfo.php"]="high|phpinfo.php accessible — full PHP environment info exposed"
  ["/server-status"]="medium|Apache server-status accessible — internal stats visible"
)

for path in "${!SENSITIVE_FILES[@]}"; do
  IFS='|' read -r sev desc <<< "${SENSITIVE_FILES[$path]}"
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 6 \
    --connect-timeout 4 "${BASE_URL}${path}" 2>/dev/null || echo "000")
  if [[ "$STATUS" == "200" ]]; then
    case "$sev" in
      critical) CRITICAL+=("$desc at $path") ;;
      high)     HIGH+=("$desc at $path") ;;
      medium)   MEDIUM+=("$desc at $path") ;;
    esac
  fi
done

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
  [[ "$i" =~ HTTP|http ]] && TOP_FIXES+=("Redirect all HTTP traffic to HTTPS in your server config") && break
done
for i in "${CRITICAL[@]}"; do
  [[ "$i" =~ \.env ]] && TOP_FIXES+=("Block .env access in your web server config (deny from all)") && break
done
for i in "${CRITICAL[@]}"; do
  [[ "$i" =~ \.git ]] && TOP_FIXES+=("Block .git directory access from the public web server") && break
done
for i in "${HIGH[@]}"; do
  [[ "$i" =~ CSP|Content-Security ]] && TOP_FIXES+=("Add CSP header: Content-Security-Policy: default-src 'self'") && break
done
for i in "${HIGH[@]}"; do
  [[ "$i" =~ HSTS|Strict-Transport ]] && TOP_FIXES+=("Add HSTS: Strict-Transport-Security: max-age=31536000; includeSubDomains") && break
done
for i in "${HIGH[@]}"; do
  [[ "$i" =~ jQuery|Angular|Bootstrap|Lodash|React|Moment ]] && TOP_FIXES+=("Update all JS libraries to their latest stable versions") && break
done

if [[ ${#TOP_FIXES[@]} -gt 0 ]]; then
  echo "📋 Top Fix:"
  COUNT=0
  for fix in "${TOP_FIXES[@]}"; do
    echo "→ $fix"
    COUNT=$((COUNT+1))
    [[ $COUNT -ge 3 ]] && break
  done
  echo ""
fi

echo "$DIVIDER"
echo "by cybersecurity experts | WebGuard v1.0"
echo ""
