# WebGuard Skill

**Find vulnerabilities before attackers do.**

WebGuard is a two-mode security scanner. Give it a URL or a local code folder — it returns a prioritized report of security issues with actionable fixes.

---

## Modes

### Mode 1 — URL Scanner (Frontend)
Scans any public URL for frontend security vulnerabilities.

**Trigger phrases:**
- "scan [URL]"
- "check [URL] for vulnerabilities"
- "webguard [URL]"
- "security scan [URL]"

**What it checks:**
1. **SSL/HTTPS** — Is HTTPS enforced? Is the certificate valid?
2. **Security headers** — CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy
3. **Outdated JS libraries** — Detects jQuery, React, lodash, Angular, Bootstrap versions in HTML/JS
4. **Exposed sensitive files** — Tests for `.env`, `.git/config`, `.htaccess`, `backup.zip`, `config.php`
5. **Mixed content** — HTTP assets loaded on HTTPS pages

**Run:** `scan-url.ps1 <URL>` (Windows) or `scan-url.sh <URL>` (Mac/Linux)

---

### Mode 2 — Code Scanner (Local Folder)
Scans a local codebase for security vulnerabilities.

**Trigger phrases:**
- "scan code in [path]"
- "audit [folder path]"
- "webguard code [path]"
- "scan my code at [path]"

**What it checks:**
1. **Hardcoded secrets** — API keys, passwords, tokens (patterns: `sk-`, `AKIA`, `ghp_`, `password=`, `api_key=`, `secret=`, `token=`)
2. **Dangerous functions** — `eval()`, `exec()`, `system()`, `innerHTML=`, `dangerouslySetInnerHTML`
3. **SQL injection patterns** — String concatenation in SQL queries
4. **Dependency vulnerabilities** — `npm audit` (if `package.json` found), `pip audit` (if `requirements.txt` found)

**File types scanned:** `.js`, `.ts`, `.py`, `.php`, `.rb` (recursive)

**Run:** `scan-code.ps1 <FOLDER>` (Windows) or `scan-code.sh <FOLDER>` (Mac/Linux)

---

## Output Format

All reports follow this severity structure:

```
🔍 WebGuard Report — <target>
━━━━━━━━━━━━━━━━━━━

🔴 CRITICAL (n)
  • <issue description>

🟠 HIGH (n)
  • <issue description>

🟡 MEDIUM (n)
  • <issue description>

🟢 LOW (n)
  • <issue description>

ℹ️ INFO (n)
  • <observation, no action required>

📋 Top Fix:
→ <most important fix>
→ <second most important fix>

━━━━━━━━━━━━━━━━━━━
by cybersecurity experts | WebGuard v1.0
```

**Severity Definitions:**
- 🔴 CRITICAL — Active exploitation risk, no HTTPS, credentials exposed
- 🟠 HIGH — Missing critical headers, known CVE libraries, secrets in code
- 🟡 MEDIUM — Sensitive file exposure, dangerous functions, mixed content
- 🟢 LOW — Missing defensive headers, minor best-practice gaps
- ℹ️ INFO — Observations that don't require immediate action

---

## Agent Instructions

### When user provides a URL:
1. Detect if the URL starts with `http://` or `https://` to determine protocol
2. Run `scan-url.ps1` (Windows) or `scan-url.sh` (Mac/Linux) against the URL
3. Parse the script output and format it into the severity report above
4. Lead with the most critical finding in plain English
5. Always include the "Top Fix" section with 1–3 actionable steps

### When user provides a folder path:
1. Verify the path exists before scanning
2. Run `scan-code.ps1` (Windows) or `scan-code.sh` (Mac/Linux) against the path
3. Group findings by severity and file location
4. If `npm audit` or `pip audit` is available, include those results
5. Include file path + line number for every finding when available

### General:
- Never modify the target files during a scan — read-only
- If a scan takes >30 seconds, notify the user you're still working
- If a URL is unreachable, report it as a scan failure (not a security issue)
- Truncate very large reports (>50 findings) to top 20 by severity
- Always end with the WebGuard credit line

---

## Dependencies

| Tool | Required For | Notes |
|------|-------------|-------|
| `curl` or `Invoke-WebRequest` | Mode 1 | Pre-installed on most systems |
| `PowerShell 5+` | `.ps1` scripts | Windows built-in |
| `bash` | `.sh` scripts | Mac/Linux built-in |
| `npm` | Dependency audit | Optional — skip if not installed |
| `pip` | Dependency audit | Optional — skip if not installed |

---

## Examples

**Scan a URL:**
```
scan https://example.com
webguard https://myapp.com
check https://shop.example.com for vulnerabilities
```

**Scan code:**
```
scan code in C:\Projects\myapp
webguard code /home/user/projects/backend
audit /var/www/html
```

---

*WebGuard v1.0 — by cybersecurity experts*
