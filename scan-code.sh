#!/usr/bin/env bash
# WebGuard Code Scanner v1.0 — Local code security scanner (Mac/Linux)
# Usage: bash scan-code.sh /path/to/project
# Example: bash scan-code.sh /home/user/myapp

set -euo pipefail

PATH_ARG="${1:-}"
if [[ -z "$PATH_ARG" ]]; then
    echo "Usage: bash scan-code.sh <folder>"
    exit 1
fi

if [[ ! -d "$PATH_ARG" ]]; then
    echo "Error: Directory not found: $PATH_ARG"
    exit 1
fi

SCAN_PATH=$(cd "$PATH_ARG" && pwd)
LABEL=$(basename "$SCAN_PATH")

FINDINGS_CRIT=()
FINDINGS_HIGH=()
FINDINGS_MED=()
FINDINGS_LOW=()
PASSED=()

# Colors
RED='\033[0;31m'
ORANGE='\033[0;33m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
GRAY='\033[0;90m'
NC='\033[0m'

echo ""
echo "🔍 WebGuard Code Report — $SCAN_PATH"
echo "━━━━━━━━━━━━━━━━━━━"
echo -e "${GRAY}  Scanning files...${NC}"

# ── Build file list ───────────────────────────────────────────────────────────

TMPFILES=$(mktemp)
find "$SCAN_PATH" \( \
    -name "*.js" -o -name "*.ts" -o -name "*.py" -o -name "*.php" -o \
    -name "*.rb" -o -name "*.env" -o -name "*.json" -o -name "*.yaml" -o \
    -name "*.yml" -o -name "*.toml" -o -name "*.config" -o -name "*.cfg" -o \
    -name "*.ini" -o -name "*.sh" -o -name "*.bash" \
\) \
    -not -path "*/node_modules/*" \
    -not -path "*/.git/*" \
    -not -path "*/vendor/*" \
    -not -path "*/dist/*" \
    -not -path "*/build/*" \
    > "$TMPFILES" 2>/dev/null || true

TOTAL=$(wc -l < "$TMPFILES" | tr -d ' ')
echo -e "${GRAY}  Found $TOTAL files to scan${NC}"

# ── Helper: grep file for pattern, add to findings ────────────────────────────

scan_for_secret() {
    local pattern="$1"
    local label="$2"
    local file="$3"
    if grep -qiE "$pattern" "$file" 2>/dev/null; then
        local lines
        lines=$(grep -niE "$pattern" "$file" 2>/dev/null | head -3)
        while IFS= read -r hit; do
            local linenum
            linenum=$(echo "$hit" | cut -d':' -f1)
            local relpath="${file#$SCAN_PATH/}"
            FINDINGS_CRIT+=("$label found in $relpath (line $linenum)")
        done <<< "$lines"
    fi
}

scan_for_danger() {
    local pattern="$1"
    local label="$2"
    local file="$3"
    if grep -qE "$pattern" "$file" 2>/dev/null; then
        local lines
        lines=$(grep -nE "$pattern" "$file" 2>/dev/null | head -3)
        while IFS= read -r hit; do
            local linenum
            linenum=$(echo "$hit" | cut -d':' -f1)
            local relpath="${file#$SCAN_PATH/}"
            FINDINGS_HIGH+=("$label used in $relpath (line $linenum)")
        done <<< "$lines"
    fi
}

scan_for_sql() {
    local pattern="$1"
    local label="$2"
    local file="$3"
    if grep -qiE "$pattern" "$file" 2>/dev/null; then
        local lines
        lines=$(grep -niE "$pattern" "$file" 2>/dev/null | head -3)
        while IFS= read -r hit; do
            local linenum
            linenum=$(echo "$hit" | cut -d':' -f1)
            local relpath="${file#$SCAN_PATH/}"
            FINDINGS_HIGH+=("$label in $relpath (line $linenum) — possible SQL injection")
        done <<< "$lines"
    fi
}

SECRET_HITS=0
DANGER_HITS=0
SQL_HITS=0

while IFS= read -r file; do
    [[ -z "$file" ]] && continue
    # Skip minified files
    [[ "$file" =~ \.min\.(js|css)$ ]] && continue

    # 1. Secrets
    PREV_CRIT=${#FINDINGS_CRIT[@]}
    scan_for_secret 'sk-[A-Za-z0-9]{32,}'                      "OpenAI API key"       "$file"
    scan_for_secret 'AKIA[0-9A-Z]{16}'                          "AWS access key"       "$file"
    scan_for_secret 'ghp_[A-Za-z0-9]{36,}'                      "GitHub PAT"           "$file"
    scan_for_secret 'gho_[A-Za-z0-9]{36,}'                      "GitHub OAuth token"   "$file"
    scan_for_secret 'password\s*[=:]\s*['"'"'"][^'"'"'"]{4,}'  "Hardcoded password"   "$file"
    scan_for_secret 'api_key\s*[=:]\s*['"'"'"][^'"'"'"]{4,}'   "Hardcoded API key"    "$file"
    scan_for_secret 'secret\s*[=:]\s*['"'"'"][^'"'"'"]{4,}'    "Hardcoded secret"     "$file"
    scan_for_secret '\btoken\s*[=:]\s*['"'"'"][^'"'"'"]{8,}'   "Hardcoded token"      "$file"
    scan_for_secret 'Bearer [A-Za-z0-9\-._~+\/]{20,}'           "Bearer token in code" "$file"
    scan_for_secret 'sk_live_[A-Za-z0-9]{24,}'                  "Stripe live key"      "$file"
    scan_for_secret 'xox[baprs]-[A-Za-z0-9\-]{10,}'             "Slack token"          "$file"
    NEW_CRIT=${#FINDINGS_CRIT[@]}
    (( NEW_CRIT > PREV_CRIT )) && (( SECRET_HITS++ )) || true

    # 2. Dangerous functions
    PREV_HIGH=${#FINDINGS_HIGH[@]}
    scan_for_danger '\beval\s*\('              "eval()"                    "$file"
    scan_for_danger '\bexec\s*\('             "exec()"                    "$file"
    scan_for_danger '\bsystem\s*\('           "system()"                  "$file"
    scan_for_danger 'shell_exec\s*\('         "shell_exec()"              "$file"
    scan_for_danger 'subprocess\.call\s*\('   "subprocess.call()"         "$file"
    scan_for_danger 'subprocess\.Popen\s*\('  "subprocess.Popen()"        "$file"
    scan_for_danger 'innerHTML\s*='           "innerHTML assignment"      "$file"
    scan_for_danger 'dangerouslySetInnerHTML' "dangerouslySetInnerHTML"   "$file"
    scan_for_danger 'document\.write\s*\('   "document.write()"          "$file"
    NEW_HIGH=${#FINDINGS_HIGH[@]}
    (( NEW_HIGH > PREV_HIGH )) && (( DANGER_HITS++ )) || true

    # 3. SQL injection
    PREV_HIGH2=${#FINDINGS_HIGH[@]}
    case "$file" in *.py|*.php|*.rb|*.js|*.ts)
        scan_for_sql '(SELECT|INSERT|UPDATE|DELETE).{0,60}["'"'"']\s*\+' "String concat in SQL"   "$file"
        scan_for_sql 'f["'"'"'](SELECT|INSERT|UPDATE|DELETE)'             "f-string SQL query"     "$file"
        scan_for_sql '\.execute\s*\(\s*[^,)]*\+'                          "execute() with concat"  "$file"
        scan_for_sql '(SELECT|INSERT|UPDATE|DELETE).{0,40}\.format\s*\(' "format() in SQL"        "$file"
        ;;
    esac
    NEW_HIGH2=${#FINDINGS_HIGH[@]}
    (( NEW_HIGH2 > PREV_HIGH2 )) && (( SQL_HITS++ )) || true

done < "$TMPFILES"
rm -f "$TMPFILES"

[[ $SECRET_HITS -eq 0 ]] && PASSED+=("No hardcoded secrets detected")
[[ $DANGER_HITS -eq 0 ]] && PASSED+=("No dangerous function patterns detected")
[[ $SQL_HITS    -eq 0 ]] && PASSED+=("No obvious SQL injection patterns detected")

# ── 4. Dependency Audits ──────────────────────────────────────────────────────

PKG_JSON=$(find "$SCAN_PATH" -name "package.json" -not -path "*/node_modules/*" 2>/dev/null | head -1)
if [[ -n "$PKG_JSON" ]]; then
    echo -e "${GRAY}  Running npm audit...${NC}"
    PKG_DIR=$(dirname "$PKG_JSON")
    if command -v npm &>/dev/null; then
        NPM_OUT=$(cd "$PKG_DIR" && npm audit --json 2>/dev/null || true)
        if [[ -n "$NPM_OUT" ]]; then
            CRIT_N=$(echo "$NPM_OUT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('metadata',{}).get('vulnerabilities',{}).get('critical',0))" 2>/dev/null || echo "0")
            HIGH_N=$(echo "$NPM_OUT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('metadata',{}).get('vulnerabilities',{}).get('high',0))" 2>/dev/null || echo "0")
            MOD_N=$(echo "$NPM_OUT"  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('metadata',{}).get('vulnerabilities',{}).get('moderate',0))" 2>/dev/null || echo "0")
            LOW_N=$(echo "$NPM_OUT"  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('metadata',{}).get('vulnerabilities',{}).get('low',0))" 2>/dev/null || echo "0")
            [[ "$CRIT_N" -gt 0 ]] && FINDINGS_CRIT+=("npm audit: $CRIT_N CRITICAL vulnerabilities — run 'npm audit fix'")
            [[ "$HIGH_N" -gt 0 ]] && FINDINGS_HIGH+=("npm audit: $HIGH_N HIGH vulnerabilities — run 'npm audit fix'")
            [[ "$MOD_N"  -gt 0 ]] && FINDINGS_MED+=("npm audit: $MOD_N MODERATE vulnerabilities")
            [[ "$LOW_N"  -gt 0 ]] && FINDINGS_LOW+=("npm audit: $LOW_N LOW vulnerabilities")
            [[ "$CRIT_N" -eq 0 && "$HIGH_N" -eq 0 ]] && PASSED+=("npm audit: no critical/high vulnerabilities")
        fi
    else
        FINDINGS_LOW+=("npm audit could not run (npm not installed)")
    fi
fi

REQ_TXT=$(find "$SCAN_PATH" -name "requirements.txt" 2>/dev/null | head -1)
if [[ -n "$REQ_TXT" ]]; then
    echo -e "${GRAY}  Running pip audit...${NC}"
    if command -v pip-audit &>/dev/null || command -v pip &>/dev/null; then
        if command -v pip-audit &>/dev/null; then
            PIP_OUT=$(pip-audit -r "$REQ_TXT" --format=json 2>/dev/null || true)
        elif pip show pip-audit &>/dev/null 2>&1; then
            PIP_OUT=$(python3 -m pip_audit -r "$REQ_TXT" --format=json 2>/dev/null || true)
        else
            FINDINGS_LOW+=("pip audit could not run — install with: pip install pip-audit")
            PIP_OUT=""
        fi
        if [[ -n "$PIP_OUT" ]]; then
            VULN_COUNT=$(echo "$PIP_OUT" | python3 -c "import sys,json; data=json.load(sys.stdin); print(sum(1 for p in data.get('dependencies',[]) if p.get('vulns')))" 2>/dev/null || echo "0")
            if [[ "$VULN_COUNT" -gt 0 ]]; then
                FINDINGS_HIGH+=("pip audit: $VULN_COUNT package(s) with known vulnerabilities — run 'pip-audit -r requirements.txt'")
            else
                PASSED+=("pip audit: no vulnerabilities found")
            fi
        fi
    else
        FINDINGS_LOW+=("pip audit could not run — install with: pip install pip-audit")
    fi
fi

# ── 5. Report ─────────────────────────────────────────────────────────────────

echo ""
echo "🔍 WebGuard Code Report — $LABEL"
echo "  📁 $TOTAL files scanned"
echo "━━━━━━━━━━━━━━━━━━━"
echo ""

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
