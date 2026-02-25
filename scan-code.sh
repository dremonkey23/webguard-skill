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
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
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

# ─── Load patterns from JSON files ───────────────────────────────────────────
# Uses python3 or jq to parse JSON; falls back to basic grep if neither available
parse_json_patterns() {
  local file="$1"
  if command -v python3 &>/dev/null; then
    python3 -c "
import json, sys
data = json.load(open('$file'))
for p in data:
    r = p.get('r','')
    d = p.get('d','')
    s = p.get('s','high')
    print(f'{s}|{r}|{d}')
"
  elif command -v jq &>/dev/null; then
    jq -r '.[] | "\(.s // "high")|\(.r)|\(.d)"' "$file"
  else
    echo ""
  fi
}

SECRET_PATTERNS=$(parse_json_patterns "$SCRIPT_DIR/patterns/secrets.json")
DANGEROUS_PATTERNS=$(parse_json_patterns "$SCRIPT_DIR/patterns/dangerous.json")
SQL_PATTERNS=$(parse_json_patterns "$SCRIPT_DIR/patterns/sql.json")

# ─── 1. Hardcoded Secrets ────────────────────────────────────────────────────
while IFS='|' read -r sev regex desc; do
  [[ -z "$regex" ]] && continue
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
        rel=$(echo "$match" | sed "s|^$FOLDER/||" | cut -d: -f1-2)
        msg="$desc — $rel"
        if [[ "$sev" == "critical" ]]; then
          CRITICAL+=("$msg")
        else
          HIGH+=("$msg")
        fi
      fi
    done <<< "$matches"
  fi
done <<< "$SECRET_PATTERNS"

# ─── 2. Dangerous Functions ──────────────────────────────────────────────────
while IFS='|' read -r sev regex desc; do
  [[ -z "$regex" ]] && continue
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
        if [[ "$sev" == "high" ]]; then
          HIGH+=("$msg")
        else
          MEDIUM+=("$msg")
        fi
      fi
    done <<< "$matches"
  fi
done <<< "$DANGEROUS_PATTERNS"

# ─── 3. SQL Injection Patterns ───────────────────────────────────────────────
while IFS='|' read -r sev regex desc; do
  [[ -z "$regex" ]] && continue
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
done <<< "$SQL_PATTERNS"

# ─── 4. Dependency Audit ─────────────────────────────────────────────────────
PKG_JSON="$FOLDER/package.json"
if [[ -f "$PKG_JSON" ]]; then
  if command -v npm &>/dev/null; then
    echo "  Running npm audit..." >&2
    NPM_OUT=$(cd "$FOLDER" && npm audit --json 2>/dev/null || true)
    if [[ -n "$NPM_OUT" ]] && command -v python3 &>/dev/null; then
      CRIT_COUNT=$(echo "$NPM_OUT" | python3 -c "import sys,json; d=json.load(sys.stdin); v=d.get('metadata',{}).get('vulnerabilities',{}); print(v.get('critical',0))" 2>/dev/null || echo "0")
      HIGH_COUNT=$(echo "$NPM_OUT" | python3 -c "import sys,json; d=json.load(sys.stdin); v=d.get('metadata',{}).get('vulnerabilities',{}); print(v.get('high',0))" 2>/dev/null || echo "0")
      MOD_COUNT=$(echo "$NPM_OUT"  | python3 -c "import sys,json; d=json.load(sys.stdin); v=d.get('metadata',{}).get('vulnerabilities',{}); print(v.get('moderate',0))" 2>/dev/null || echo "0")
      LOW_COUNT=$(echo "$NPM_OUT"  | python3 -c "import sys,json; d=json.load(sys.stdin); v=d.get('metadata',{}).get('vulnerabilities',{}); print(v.get('low',0))" 2>/dev/null || echo "0")
      [[ "$CRIT_COUNT" -gt 0 ]] && CRITICAL+=("npm audit: $CRIT_COUNT critical vulnerability(-ies)")
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
    if [[ -n "$PIP_OUT" ]] && command -v python3 &>/dev/null; then
      VULN_COUNT=$(echo "$PIP_OUT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d))" 2>/dev/null || echo "0")
      if [[ "$VULN_COUNT" -gt 0 ]]; then
        HIGH+=("pip-audit: $VULN_COUNT vulnerable Python package(s)")
      else
        INFO+=("pip-audit: no known Python vulnerabilities found")
      fi
    fi
  else
    INFO+=("requirements.txt found but pip-audit not installed")
  fi
fi

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

echo "$DIVIDER"
echo "by cybersecurity experts | WebGuard v1.0"
echo ""
