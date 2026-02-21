# WebGuard — Security Scanner Skill

> Find vulnerabilities before attackers do.

**Version:** 1.0  
**Categories:** Security, Dev Tools  
**Platform:** Windows (PowerShell) + Mac/Linux (Bash)

---

## What You Do

WebGuard is a two-mode security scanner:

- **Mode 1 — URL Scanner:** Fetch a live URL and check its frontend security posture (headers, exposed files, library versions, SSL, mixed content).
- **Mode 2 — Code Scanner:** Scan a local folder recursively for hardcoded secrets, dangerous functions, SQL injection patterns, and dependency vulnerabilities.

---

## When to Use Which Mode

| Trigger | Use |
|---|---|
| User gives you a URL | Mode 1 (URL scan) |
| User gives you a folder path | Mode 2 (Code scan) |
| User says "scan my site" | Ask: URL or local code? |
| User says "check for secrets" | Mode 2 |
| User says "check headers / SSL" | Mode 1 |

---

## Mode 1: Frontend URL Scanner

### What to Check

1. **SSL/HTTPS**
   - Is the URL served over HTTPS?
   - Does HTTP redirect to HTTPS?
   - Is the cert valid (not expired, hostname matches)?

2. **Security Headers** (inspect response headers)
   - `Content-Security-Policy` — missing = HIGH
   - `Strict-Transport-Security` — missing = HIGH
   - `X-Frame-Options` — missing = MEDIUM
   - `X-Content-Type-Options` — missing = LOW
   - `Referrer-Policy` — missing = LOW

3. **Outdated / Vulnerable JS Libraries**
   - Fetch the HTML source, find `<script>` tags
   - Detect version strings for: jQuery, React, lodash, Angular, Bootstrap
   - Flag versions known to have CVEs (see reference table below)

4. **Exposed Sensitive Files**
   - Attempt to fetch these paths (expect 403/404 for safe sites):
     - `/.env`
     - `/.git/config`
     - `/.htaccess`
     - `/backup.zip`
     - `/config.php`
   - If response is 200 and body is non-empty → flag as CRITICAL or HIGH

5. **Mixed Content**
   - If page is HTTPS, check HTML for `http://` in `src=`, `href=`, `url(` attributes
   - Flag any HTTP asset loaded on an HTTPS page → MEDIUM

### Vulnerable Library Reference

| Library | Vulnerable Version | CVE | Severity |
|---|---|---|---|
| jQuery | < 1.9.0 | CVE-2011-4969 | HIGH |
| jQuery | 1.x–3.4.x | CVE-2019-11358 | HIGH |
| jQuery | < 3.5.0 | CVE-2020-11022 | HIGH |
| Bootstrap | < 3.4.1 | CVE-2019-8331 | MEDIUM |
| Bootstrap | < 4.3.1 | CVE-2019-8331 | MEDIUM |
| Angular | 1.x (AngularJS) | CVE-2019-14863 | HIGH |
| lodash | < 4.17.21 | CVE-2021-23337 | HIGH |

### Running Mode 1

**Windows:**
```
.\scan-url.ps1 -Url "https://example.com"
```

**Mac/Linux:**
```
bash scan-url.sh https://example.com
```

---

## Mode 2: Code Scanner

### What to Scan

Recursively scan all `.js`, `.ts`, `.py`, `.php`, `.rb`, `.env`, `.json`, `.yaml`, `.yml`, `.toml` files.

1. **Hardcoded Secrets** (CRITICAL)
   - Patterns to flag:
     - `sk-[A-Za-z0-9]{32,}` — OpenAI keys
     - `AKIA[0-9A-Z]{16}` — AWS access keys
     - `ghp_[A-Za-z0-9]{36}` — GitHub personal access tokens
     - `password\s*=\s*['"][^'"]{4,}` — hardcoded passwords
     - `api_key\s*=\s*['"][^'"]{4,}` — hardcoded API keys
     - `secret\s*=\s*['"][^'"]{4,}` — hardcoded secrets
     - `token\s*=\s*['"][^'"]{4,}` — hardcoded tokens
     - `Bearer [A-Za-z0-9\-._~+\/]{20,}` — Bearer tokens in code

2. **Dangerous Functions** (HIGH)
   - `eval(` — arbitrary code execution
   - `exec(` — shell execution (Python/PHP)
   - `system(` — OS command execution
   - `innerHTML =` / `innerHTML=` — XSS risk
   - `dangerouslySetInnerHTML` — XSS risk in React
   - `document.write(` — XSS risk
   - `subprocess.call(` — shell execution
   - `shell_exec(` — PHP shell exec

3. **SQL Injection Patterns** (HIGH)
   - String concatenation in SQL queries:
     - `"SELECT.*" + ` or `'SELECT.*' + `
     - `query = ".*" + variable`
     - `execute(".*" +` or `execute('.*' +`
     - `.format(` inside SQL strings
     - f-strings containing SQL keywords (`f"SELECT`, `f'INSERT`)

4. **Dependency Audits** (run if files exist)
   - `package.json` → run `npm audit --json`
   - `requirements.txt` → run `pip audit` (if installed) or `safety check`
   - Report HIGH/CRITICAL findings from audit output

### Running Mode 2

**Windows:**
```
.\scan-code.ps1 -Path "C:\MyProject"
```

**Mac/Linux:**
```
bash scan-code.sh /path/to/project
```

---

## Output Format

Always use this exact format:

```
🔍 WebGuard Report — <target>
━━━━━━━━━━━━━━━━━━━

🔴 CRITICAL (n)
  • <finding description>

🟠 HIGH (n)
  • <finding description>

🟡 MEDIUM (n)
  • <finding description>

🟢 LOW (n)
  • <finding description>

✅ PASSED
  • <things that were checked and are fine>

📋 Top Fix:
→ <most important fix, one line>
→ <second most important fix, one line>

━━━━━━━━━━━━━━━━━━━
by cybersecurity experts | WebGuard v1.0
```

### Severity Rules

| Level | When to Use |
|---|---|
| 🔴 CRITICAL | Data exposure, accessible secrets/configs, no HTTPS |
| 🟠 HIGH | Missing critical headers (CSP, HSTS), known CVE libraries, dangerous functions, SQL injection |
| 🟡 MEDIUM | Missing moderate headers (X-Frame-Options), mixed content, outdated deps |
| 🟢 LOW | Missing minor headers (Referrer-Policy, X-Content-Type-Options) |

### Skip Empty Sections

If no findings exist for a severity level, omit that section entirely. Do not print `🔴 CRITICAL (0)`.

---

## Agent Instructions

1. **Detect mode** from user input (URL → Mode 1, folder path → Mode 2, ambiguous → ask).
2. **Run the appropriate script** using `exec` tool with the target.
3. **Parse the output** and present it formatted in the report structure above.
4. **Offer next steps:** Explain the top fix in plain language, offer to re-scan after they fix it.
5. **Do not guess** — only report what the scanner actually found. Do not hallucinate CVEs.

### Example Agent Invocations

```
User: "Scan https://mysite.com for security issues"
→ Run: scan-url.ps1 -Url https://mysite.com (Windows) or scan-url.sh https://mysite.com (Linux/Mac)
→ Parse output → Present report

User: "Check my code at C:\Projects\myapp for secrets"
→ Run: scan-code.ps1 -Path "C:\Projects\myapp"
→ Parse output → Present report
```

---

## Notes

- Always use the scripts for scanning — do not attempt manual HTTP requests in the agent.
- Scripts output structured text with severity prefixes (`[CRITICAL]`, `[HIGH]`, `[MEDIUM]`, `[LOW]`, `[PASS]`) — parse these to build the report.
- If a script fails (missing tools, permissions), report the error gracefully and suggest what the user needs to install.
- Never store or log credentials found during scanning — report the location only (file + line number).
