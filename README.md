# 🛡️ WebGuard

**Find vulnerabilities before attackers do.**

> A two-mode security scanner for OpenClaw agents. Scan any live URL for frontend vulnerabilities, or audit a local codebase for secrets, dangerous patterns, and dependency CVEs.

**Version:** 1.0  
**Categories:** 🔒 Security · 🛠️ Dev Tools  
**Platform:** Windows (PowerShell) + Mac/Linux (Bash)  
**Author:** by cybersecurity experts

---

## What It Does

### 🌐 Mode 1 — URL Scanner

Point WebGuard at any URL and it checks:

| Check | What It Catches |
|---|---|
| **SSL/HTTPS** | Missing HTTPS, no HTTP→HTTPS redirect |
| **Security Headers** | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| **JS Library CVEs** | jQuery, Bootstrap, lodash, Angular, React version detection |
| **Exposed Files** | `.env`, `.git/config`, `.htaccess`, `backup.zip`, `config.php` |
| **Mixed Content** | HTTP assets on HTTPS pages |

### 🗂️ Mode 2 — Code Scanner

Point WebGuard at a local folder and it checks:

| Check | What It Catches |
|---|---|
| **Hardcoded Secrets** | OpenAI keys, AWS keys, GitHub tokens, passwords, API keys, Bearer tokens |
| **Dangerous Functions** | `eval()`, `exec()`, `innerHTML=`, `dangerouslySetInnerHTML`, `system()` |
| **SQL Injection** | String concatenation in queries, f-string SQL, `.format()` in SQL |
| **npm audit** | Runs `npm audit` if `package.json` is found |
| **pip audit** | Runs `pip-audit` if `requirements.txt` is found |

---

## Output

Every scan produces a severity-graded report:

```
🔍 WebGuard Report — example.com
━━━━━━━━━━━━━━━━━━━

🔴 CRITICAL (1)
  • No HTTPS enforced — traffic can be intercepted

🟠 HIGH (2)
  • Missing Content-Security-Policy header
  • jQuery 1.9.1 detected — CVE-2019-11358 (XSS)

🟡 MEDIUM (1)
  • .env file accessible at /.env — may expose credentials

🟢 LOW (1)
  • Missing Referrer-Policy header

✅ PASSED
  • X-Content-Type-Options header present

📋 Top Fix:
→ Redirect all HTTP to HTTPS in your server config
→ Add CSP header: Content-Security-Policy: default-src 'self'

━━━━━━━━━━━━━━━━━━━
by cybersecurity experts | WebGuard v1.0
```

---

## Installation (OpenClaw)

Clone or copy this skill into your OpenClaw workspace:

```
skills/
  webguard/
    SKILL.md
    scan-url.ps1
    scan-url.sh
    scan-code.ps1
    scan-code.sh
    README.md
```

The agent will automatically use `SKILL.md` to know how to invoke the scanners.

---

## Usage

### URL Scan

**Windows (PowerShell):**
```powershell
.\scan-url.ps1 -Url "https://example.com"
```

**Mac/Linux (Bash):**
```bash
bash scan-url.sh https://example.com
```

### Code Scan

**Windows (PowerShell):**
```powershell
.\scan-code.ps1 -Path "C:\Projects\myapp"
```

**Mac/Linux (Bash):**
```bash
bash scan-code.sh /home/user/myapp
```

### Via OpenClaw Agent

Just tell your agent:
- `"Scan https://mysite.com for security vulnerabilities"`
- `"Check my code at C:\Projects\app for secrets and SQLi"`

The agent reads `SKILL.md`, picks the right mode, runs the scanner, and presents the formatted report.

---

## Files

| File | Purpose |
|---|---|
| `SKILL.md` | Agent instructions — how to use both modes |
| `scan-url.ps1` | PowerShell URL scanner (Windows) |
| `scan-url.sh` | Bash URL scanner (Mac/Linux) |
| `scan-code.ps1` | PowerShell code scanner (Windows) |
| `scan-code.sh` | Bash code scanner (Mac/Linux) |
| `README.md` | This file |

---

## Requirements

### URL Scanner
- `curl` (Mac/Linux) or `Invoke-WebRequest` (Windows — built-in)
- No additional packages required

### Code Scanner  
- PowerShell 5.1+ (Windows) or Bash 4+ (Mac/Linux)
- `npm` — for npm audit (optional, auto-detected)
- `pip-audit` — for Python dependency audit (optional, install via `pip install pip-audit`)
- `python3` — used in the Bash scanner for JSON parsing of audit results

---

## Privacy

WebGuard **never** stores, logs, or sends the content of scanned files or URLs anywhere. It reads locally, reports locally. Credential matches are reported by file path and line number only — the actual secret value is not echoed.

---

## Severity Reference

| Level | Icon | When Applied |
|---|---|---|
| Critical | 🔴 | Data exposure, accessible secrets, no HTTPS |
| High | 🟠 | Missing CSP/HSTS, known CVE libraries, dangerous functions, SQLi |
| Medium | 🟡 | Missing X-Frame-Options, mixed content, moderate vulns |
| Low | 🟢 | Missing minor headers, low-severity deps |

---

*WebGuard v1.0 — by cybersecurity experts*
