#!/usr/bin/env bash
# WebGuard — Code Scanner (bash)
# Usage: ./scan-code.sh <FOLDER_PATH>
# Example: ./scan-code.sh /home/user/projects/myapp

set -euo pipefail

FOLDER="${1:-}"
if [[ -z "$FOLDER" ]]; then
  echo "Usage: $0 <FOLDER_PATH>"
  exit 1
fi

if [[ ! -d "$FOLDER" ]]; then
  echo "❌ Folder not found: $FOLDER"
  exit 1
fi

FOLDER=$(cd "$FOLDER" && pwd)
DIVIDER="━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
TARGET_LABEL=$(basename "$FOLDER")

echo ""
echo "🔍 WebGuard — Scanning code at: $FOLDER"
echo ""

# ─── Severity arrays ─────────────────────────────────────────────────────────
CRITICAL=()
HIGH=()
MEDIUM=()
LOW=()
INFO=()

# ─── Excluded dirs ───────────────────────────────────────────────────────────
EXCLUDE_PRUNE='( -name node_modules -o -name .git -o -name vendor -o -name dist -o -name build -o -name .next -o -name __pycache__ ) -prune -o'

# ─── Count scanned files ─────────────────────────────────────────────────────
FILE_COUNT=$(find "$FOLDER" $EXCLUDE_PRUNE -type f \
  \( -name "*.js" -o -name "*.ts" -o -name "*.py" -o -name "*.php" -o -name "*.rb" \
     -o -name "*.env" -o -name "*.yaml" -o -name "*.yml" \) \
  -print 2>/dev/null | wc -l | tr -d ' ')
INFO+=("$FILE_COUNT source file(s) scanned")

# ─── Helper: grep files safely ───────────────────────────────────────────────
scan_pattern() {
  local pattern="$1"
  local extensions="$2"  # e.g., "js ts py php rb"
  local result=""

  local ext_args=()
  local first=true
  for ext in $extensions; do
    if $first; then
      ext_args+=(-name "*.${ext}")
      first=false
    else
      ext_args+=(-o -name "*.${ext}")
    fi
  done

  result=$(find "$FOLDER" $EXCLUDE_PRUNE -type f \( "${ext_args[@]}" \) -print0 2>/dev/null | \
    xargs -0 grep -nE --include="" "$pattern" 2>/dev/null || true)
  echo "$result"
}

# ─── 1. Hardcoded Secrets ────────────────────────────────────────────────────
declare -a SECRET_PATTERNS=(
  "sk-[a-zA-Z0-9]{20,}|CRITICAL|OpenAI API key pattern (sk-...)"
  "AKIA[0-9A-Z]{16}|CRITICAL|AWS Access Key ID (AKIA...)"
  "ghp_[a-zA-Z0-9]{36}|CRITICAL|GitHub Personal Access Token (ghp_...)"
  "xox[baprs]-[a-zA-Z0-9-]{10,}|CRITICAL|Slack token (xox...)"
  "AIza[0-9A-Za-z_-]{35}|CRITICAL|Google API key (AIza...)"
  "-----BEGIN (RSA |EC )?PRIVATE KEY-----|CRITICAL|Private key material in source"
  "(?i)password\s*[=:]\s*[\"'][^\"']{4,}[\"']|CRITICAL|Hardcoded password"
  "(?i)api_key\s*[=:]\s*[\"'][^\"']{6,}[\"']|CRITICAL|Hardcoded API key"
  "(?i)secret\s*[=:]\s*[\"'][^\"']{6,}[\"']|CRITICAL|Hardcoded secret"
  "(?i)db_password\s*[=:]\s*[\"'][^\"']{1,}[\"']|CRITICAL|Hardcoded database password"
  "(?i)token\s*[=:]\s*[\"'][^\"']{8,}[\"']|HIGH|Hardcoded token"
)

ALL_SOURCE_EXTS="js ts py php rb yaml yml env"

for entry in "${SECRET_PATTERNS[@]}"; do
  IFS='|' read -r regex sev desc <<< "$entry"
  matches=$(find "$FOLDER" $EXCLUDE_PRUNE -type f \
    \( -name "*.js" -o -name "*.ts" -o -name "*.py" -o -name "*.php" -o -name "*.rb" \
       -o -name "*.env" -o -name "*.yaml" -o -name "*.yml" \) \
    -print0 2>/dev/null | \
    xargs -0 grep -nE "$regex" 2>/dev/null | \
    grep -vE '^\s*#|^\s*//' | \
    head -5 || true)

  if [[ -n "$matches" ]]; then
    while IFS= read -r match; do
      if [[ -n "$match" ]]; then
        # Extract relative path + line
        rel=$(echo "$match" | sed "s|^$FOLDER/||" | cut -d: -f1-2)
        msg="$desc — $rel"
        if [[ "$sev" == "CRITICAL" ]]; then
          CRITICAL+=("$msg")
        else
          HIGH+=("$msg")
        fi
      fi
    done <<< "$matches"
  fi
done

# ─── 2. Dangerous Functions ──────────────────────────────────────────────────
declare -a DANGEROUS_PATTERNS=(
  "\beval\s*\(|HIGH|eval() usage — arbitrary code execution risk"
  "\bexec\s*\(|HIGH|exec() usage — shell injection risk"
  "\bsystem\s*\(|HIGH|system() call — shell injection risk"
  "\.innerHTML\s*=|HIGH|innerHTML assignment — XSS risk"
  "dangerouslySetInnerHTML|HIGH|dangerouslySetInnerHTML usage — XSS risk (React)"
  "\bshell_exec\s*\(|HIGH|shell_exec() usage — shell injection risk (PHP)"
  "subprocess\.(call|run|Popen).*shell\s*=\s*True|HIGH|subprocess with shell=True — shell injection risk"
  "\bdocument\.write\s*\(|MEDIUM|document.write() usage — XSS risk"
  "\bpickle\.loads?\s*\(|MEDIUM|pickle.load() with untrusted data — deserialization risk"
)

for entry in "${DANGEROUS_PATTERNS[@]}"; do
  IFS='|' read -r regex sev desc <<< "$entry"
  matches=$(find "$FOLDER" $EXCLUDE_PRUNE -type f \
    \( -name "*.js" -o -name "*.ts" -o -name "*.py" -o -name "*.php" -o -name "*.rb" \) \
    -print0 2>/dev/null | \
    xargs -0 grep -nE "$regex" 2>/dev/null | \
    grep -vE '^\s*#|^\s*//' | \
    head -5 || true)

  if [[ -n "$matches" ]]; then
    while IFS= read -r match; do
      if [[ -n "$match" ]]; then
        rel=$(echo "$match" | sed "s|^$FOLDER/||" | cut -d: -f1-2)
        msg="$desc — $rel"
        if [[ "$sev" == "HIGH" ]]; then
          HIGH+=("$msg")
        else
          MEDIUM+=("$msg")
        fi
      fi
    done <<< "$matches"
  fi
done

# ─── 3. SQL Injection Patterns ───────────────────────────────────────────────
declare -a SQL_PATTERNS=(
  "(SELECT|INSERT|UPDATE|DELETE|DROP).*\+\s*[\$\w]|SQL query with string concatenation — injection risk"
  "query\s*\(.*\+\s*[\$\w]|DB query() with concatenated variable — injection risk"
  'execute\s*\(\s*["\x27].*\+|DB execute() with string concatenation — injection risk'
  '\$_(GET|POST|REQUEST|COOKIE)\[.*\].*sql|User input directly in SQL context (PHP) — injection risk'
)

for entry in "${SQL_PATTERNS[@]}"; do
  IFS='|' read -r regex desc <<< "$entry"
  matches=$(find "$FOLDER" $EXCLUDE_PRUNE -type f \
    \( -name "*.js" -o -name "*.ts" -o -name "*.py" -o -name "*.php" -o -name "*.rb" \) \
    -print0 2>/dev/null | \
    xargs -0 grep -niE "$regex" 2>/dev/null | \
    grep -vE '^\s*#|^\s*//' | \
    head -5 || true)

  if [[ -n "$matches" ]]; then
    while IFS= read -r match; do
      if [[ -n "$match" ]]; then
        rel=$(echo "$match" | sed "s|^$FOLDER/||" | cut -d: -f1-2)
        HIGH+=("$desc — $rel")
      fi
    done <<< "$matches"
  fi
done

# ─── 4. Dependency Audit ─────────────────────────────────────────────────────
PKG_JSON="$FOLDER/package.json"
if [[ -f "$PKG_JSON" ]]; then
  if command -v npm &>/dev/null; then
    echo "  Running npm audit..." >&2
    NPM_OUT=$(cd "$FOLDER" && npm audit --json 2>/dev/null || true)
    if [[ -n "$NPM_OUT" ]]; then
      CRIT_COUNT=$(echo "$NPM_OUT" | python3 -c "import sys,json; d=json.load(sys.stdin); v=d.get('metadata',{}).get('vulnerabilities',{}); print(v.get('critical',0))" 2>/dev/null || echo "0")
      HIGH_COUNT=$(echo "$NPM_OUT" | python3 -c "import sys,json; d=json.load(sys.stdin); v=d.get('metadata',{}).get('vulnerabilities',{}); print(v.get('high',0))" 2>/dev/null || echo "0")
      MOD_COUNT=$(echo "$NPM_OUT"  | python3 -c "import sys,json; d=json.load(sys.stdin); v=d.get('metadata',{}).get('vulnerabilities',{}); print(v.get('moderate',0))" 2>/dev/null || echo "0")
      LOW_COUNT=$(echo "$NPM_OUT"  | python3 -c "import sys,json; d=json.load(sys.stdin); v=d.get('metadata',{}).get('vulnerabilities',{}); print(v.get('low',0))" 2>/dev/null || echo "0")
      [[ "$CRIT_COUNT" -gt 0 ]] && CRITICAL+=("npm audit: $CRIT_COUNT critical vulnerability(-ies) — run 'npm audit fix'")
      [[ "$HIGH_COUNT" -gt 0 ]] && HIGH+=("npm audit: $HIGH_COUNT high vulnerability(-ies) in dependencies")
      [[ "$MOD_COUNT"  -gt 0 ]] && MEDIUM+=("npm audit: $MOD_COUNT moderate vulnerability(-ies) in dependencies")
      [[ "$LOW_COUNT"  -gt 0 ]] && LOW+=("npm audit: $LOW_COUNT low vulnerability(-ies) in dependencies")
      TOTAL=$((CRIT_COUNT + HIGH_COUNT + MOD_COUNT + LOW_COUNT))
      [[ "$TOTAL" -eq 0 ]] && INFO+=("npm audit: no known vulnerabilities found")
    fi
  else
    INFO+=("package.json found but npm not installed — skipping npm audit")
  fi
fi

REQ_TXT="$FOLDER/requirements.txt"
if [[ -f "$REQ_TXT" ]]; then
  if command -v pip-audit &>/dev/null; then
    echo "  Running pip-audit..." >&2
    PIP_OUT=$(pip-audit --requirement "$REQ_TXT" --format=json 2>/dev/null || true)
    VULN_COUNT=$(echo "$PIP_OUT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d))" 2>/dev/null || echo "0")
    if [[ "$VULN_COUNT" -gt 0 ]]; then
      HIGH+=("pip-audit: $VULN_COUNT vulnerable Python package(s) — run 'pip-audit -r requirements.txt'")
    else
      INFO+=("pip-audit: no known Python vulnerabilities found")
    fi
  else
    INFO+=("requirements.txt found but pip-audit not installed — run 'pip install pip-audit'")
  fi
fi

# ─── Deduplicate ─────────────────────────────────────────────────────────────
dedup() {
  printf '%s\n' "$@" | sort -u
}

# ─── Build Report ─────────────────────────────────────────────────────────────
echo ""
echo "🔍 WebGuard Report — $TARGET_LABEL"
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
  echo "✅ No issues found — code looks clean!"
  echo ""
fi

# Top Fixes
TOP_FIXES=()
for i in "${CRITICAL[@]}"; do
  if [[ "$i" =~ password|secret|api_key|token|key|private ]]; then
    TOP_FIXES+=("Move all secrets to environment variables or a secrets manager (never hardcode)")
    break
  fi
done
for i in "${CRITICAL[@]}"; do
  if [[ "$i" =~ "npm audit" ]]; then
    TOP_FIXES+=("Run 'npm audit fix' to auto-remediate vulnerable dependencies")
    break
  fi
done
for i in "${HIGH[@]}"; do
  if [[ "$i" =~ eval|exec|system|innerHTML ]]; then
    TOP_FIXES+=("Replace dangerous functions: use safe alternatives (e.g., textContent instead of innerHTML)")
    break
  fi
done
for i in "${HIGH[@]}"; do
  if [[ "$i" =~ SQL|injection ]]; then
    TOP_FIXES+=("Use parameterized queries / prepared statements for all database operations")
    break
  fi
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
