# 🛡️ WebGuard

**Find vulnerabilities before attackers do.**

WebGuard is a two-mode security scanner for OpenClaw agents. Point it at a URL or a local code folder — it returns a clear, prioritized report of security issues with actionable fixes.

---

## 🔍 What It Does

| Mode | Input | What It Checks |
|------|-------|----------------|
| **URL Scanner** | Any public URL | Security headers, outdated JS libs, exposed files, HTTPS enforcement, mixed content, cookie flags |
| **Code Scanner** | Local folder path | Hardcoded secrets, dangerous functions, SQL injection patterns, npm/pip dependency audits |

---

## ⚡ Quick Start

### Scan a URL
```bash
# Mac/Linux
./scan-url.sh https://example.com

# Windows
.\scan-url.ps1 https://example.com
```

### Scan a code folder
```bash
# Mac/Linux
./scan-code.sh /path/to/your/project

# Windows
.\scan-code.ps1 C:\Projects\myapp
```

---

## 📊 Sample Output

```
🔍 WebGuard Report — example.com
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔴 CRITICAL (1)
  • No HTTPS enforced — traffic can be intercepted

🟠 HIGH (2)
  • Missing Content-Security-Policy header — XSS attacks are unrestricted
  • jQuery 1.9.1 detected in page source — 1.x/2.x: CVE-2019-11358 (XSS), CVE-2020-11022

🟡 MEDIUM (1)
  • .env file accessible — may expose credentials and API keys at /.env

🟢 LOW (1)
  • Missing Referrer-Policy header — referrer data may leak to third parties

📋 Top Fix:
→ Redirect all HTTP traffic to HTTPS in your server config
→ Add CSP header: Content-Security-Policy: default-src 'self'
→ Update JS libraries to their latest stable versions

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
by cybersecurity experts | WebGuard v1.0
```

---

## 🔴 Mode 1: URL Scanner

**Checks performed:**

- ✅ **SSL/HTTPS enforcement** — detects HTTP-only sites and missing redirects
- ✅ **Security headers** — CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy
- ✅ **Outdated JS libraries** — jQuery, React, Angular, Bootstrap, Lodash, Moment.js with CVE refs
- ✅ **Exposed sensitive files** — `.env`, `.git/config`, `wp-config.php`, `phpinfo.php`, backups
- ✅ **Mixed content** — HTTP assets on HTTPS pages
- ✅ **Cookie security flags** — HttpOnly, Secure, SameSite
- ✅ **Server fingerprinting** — version disclosure via Server/X-Powered-By headers

---

## 🔴 Mode 2: Code Scanner

**Checks performed:**

- ✅ **Hardcoded secrets** — OpenAI keys (`sk-`), AWS keys (`AKIA`), GitHub tokens (`ghp_`), Slack tokens, Google API keys, passwords, API keys, private keys
- ✅ **Dangerous functions** — `eval()`, `exec()`, `system()`, `innerHTML=`, `dangerouslySetInnerHTML`, `shell_exec()`, `subprocess(shell=True)`
- ✅ **SQL injection** — string concatenation in queries, unsanitized user input in DB calls
- ✅ **npm audit** — runs automatically if `package.json` is present
- ✅ **pip-audit** — runs automatically if `requirements.txt` is present

**File types scanned:** `.js` `.ts` `.py` `.php` `.rb` `.env` `.yaml` `.yml`

**Excluded from scan:** `node_modules`, `.git`, `vendor`, `dist`, `build`, `__pycache__`

---

## 🎯 Severity Levels

| Level | Emoji | Meaning |
|-------|-------|---------|
| CRITICAL | 🔴 | Active exploitation risk — fix immediately |
| HIGH | 🟠 | Significant vulnerability — fix ASAP |
| MEDIUM | 🟡 | Moderate risk — plan to fix |
| LOW | 🟢 | Best-practice gap — fix when possible |
| INFO | ℹ️ | Observation — no action needed |

---

## 🤖 Agent Integration (OpenClaw)

Add WebGuard to your agent by including `SKILL.md` in your agent's skill set. The agent will:

1. Detect whether the user provided a URL or a folder path
2. Run the appropriate scanner script for the platform (Windows/Mac/Linux)
3. Format results using the severity report structure
4. Provide prioritized fix recommendations

**Example prompts that trigger WebGuard:**
- `"scan https://myapp.com"`
- `"check https://example.com for vulnerabilities"`
- `"scan code in /home/user/project"`
- `"audit C:\Projects\backend"`

---

## 📦 Files

| File | Description |
|------|-------------|
| `SKILL.md` | Agent instructions for both scan modes |
| `scan-url.ps1` | URL scanner — Windows PowerShell |
| `scan-url.sh` | URL scanner — Mac/Linux bash |
| `scan-code.ps1` | Code scanner — Windows PowerShell |
| `scan-code.sh` | Code scanner — Mac/Linux bash |
| `README.md` | This file |

---

## ⚙️ Requirements

**URL Scanner:**
- `curl` (Mac/Linux) or `Invoke-WebRequest` (Windows) — pre-installed on most systems
- `openssl` for SSL certificate check (optional, Mac/Linux only)

**Code Scanner:**
- `npm` — for dependency audit (optional)
- `pip-audit` — for Python dependency audit (`pip install pip-audit`, optional)

---

## 🏷️ Categories

`Security` · `Dev Tools` · `Code Quality` · `Auditing`

---

## 📄 License

MIT — free to use, modify, and distribute.

---

*WebGuard v1.0 — by cybersecurity experts*
