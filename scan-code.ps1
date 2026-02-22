# WebGuard — Code Scanner (PowerShell)
# Usage: .\scan-code.ps1 <FOLDER_PATH>
# Example: .\scan-code.ps1 C:\Projects\myapp

param(
    [Parameter(Mandatory=$true)]
    [string]$FolderPath
)

$ErrorActionPreference = "SilentlyContinue"

# ─── Validate path ───────────────────────────────────────────────────────────
if (-not (Test-Path $FolderPath -PathType Container)) {
    Write-Host "❌ Folder not found: $FolderPath" -ForegroundColor Red
    exit 1
}

$FolderPath = (Resolve-Path $FolderPath).Path
$DIVIDER = "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

Write-Host ""
Write-Host "🔍 WebGuard — Scanning code at: $FolderPath" -ForegroundColor Cyan
Write-Host ""

# ─── Severity buckets ────────────────────────────────────────────────────────
$critical = @()
$high     = @()
$medium   = @()
$low      = @()
$info     = @()

# ─── Get all target files ────────────────────────────────────────────────────
$extensions = @("*.js","*.ts","*.py","*.php","*.rb","*.env","*.yaml","*.yml","*.json")
$excludeDirs = @("node_modules",".git","vendor","dist","build",".next","__pycache__")

$allFiles = Get-ChildItem -Path $FolderPath -Recurse -Include $extensions -File |
    Where-Object {
        $path = $_.FullName
        $exclude = $false
        foreach ($dir in $excludeDirs) {
            if ($path -match [regex]::Escape("\$dir\")) { $exclude = $true; break }
        }
        -not $exclude
    }

$fileCount = $allFiles.Count
$info += "$fileCount source file(s) scanned"

# ─── 1. Hardcoded Secrets ────────────────────────────────────────────────────
$secretPatterns = @(
    @{ Regex = 'sk-[a-zA-Z0-9]{20,}';                     Desc = "OpenAI API key pattern (sk-...)";              Sev = "critical" },
    @{ Regex = 'AKIA[0-9A-Z]{16}';                         Desc = "AWS Access Key ID (AKIA...)";                 Sev = "critical" },
    @{ Regex = 'ghp_[a-zA-Z0-9]{36}';                      Desc = "GitHub Personal Access Token (ghp_...)";     Sev = "critical" },
    @{ Regex = 'xox[baprs]-[a-zA-Z0-9\-]{10,}';           Desc = "Slack token (xox...)";                       Sev = "critical" },
    @{ Regex = 'AIza[0-9A-Za-z\-_]{35}';                   Desc = "Google API key (AIza...)";                   Sev = "critical" },
    @{ Regex = 'ey[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*'; Desc = "JWT token hardcoded"; Sev = "high" },
    @{ Regex = '(?i)password\s*[=:]\s*["\x27][^"\x27]{4,}["\x27]';  Desc = "Hardcoded password";              Sev = "critical" },
    @{ Regex = '(?i)api_key\s*[=:]\s*["\x27][^"\x27]{6,}["\x27]';   Desc = "Hardcoded API key";               Sev = "critical" },
    @{ Regex = '(?i)secret\s*[=:]\s*["\x27][^"\x27]{6,}["\x27]';    Desc = "Hardcoded secret";                Sev = "critical" },
    @{ Regex = '(?i)token\s*[=:]\s*["\x27][^"\x27]{8,}["\x27]';     Desc = "Hardcoded token";                 Sev = "high" },
    @{ Regex = '(?i)db_password\s*[=:]\s*["\x27][^"\x27]+["\x27]';  Desc = "Hardcoded database password";     Sev = "critical" },
    @{ Regex = '(?i)private_key\s*[=:]\s*["\x27][^"\x27]{10,}["\x27]'; Desc = "Hardcoded private key";       Sev = "critical" },
    @{ Regex = '-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----';         Desc = "Private key material in source"; Sev = "critical" }
)

foreach ($file in $allFiles) {
    try {
        $lines = Get-Content $file.FullName -ErrorAction Stop
        $lineNum = 0
        foreach ($line in $lines) {
            $lineNum++
            # Skip comment-only lines
            $trimmed = $line.Trim()
            if ($trimmed.StartsWith("#") -or $trimmed.StartsWith("//") -or $trimmed.StartsWith("*")) { continue }

            foreach ($pattern in $secretPatterns) {
                if ($line -match $pattern.Regex) {
                    $relPath = $file.FullName.Replace($FolderPath, "").TrimStart("\")
                    $msg = "$($pattern.Desc) in $relPath line $lineNum"
                    switch ($pattern.Sev) {
                        "critical" { $critical += $msg }
                        "high"     { $high     += $msg }
                    }
                    break  # one finding per line
                }
            }
        }
    } catch {}
}

# ─── 2. Dangerous Functions ──────────────────────────────────────────────────
$dangerousPatterns = @(
    @{ Regex = '\beval\s*\(';                     Desc = "eval() usage — arbitrary code execution risk";     Sev = "high" },
    @{ Regex = '\bexec\s*\(';                     Desc = "exec() usage — shell injection risk";              Sev = "high" },
    @{ Regex = '\bsystem\s*\(';                   Desc = "system() call — shell injection risk";             Sev = "high" },
    @{ Regex = '\.innerHTML\s*=';                 Desc = "innerHTML assignment — XSS risk";                  Sev = "high" },
    @{ Regex = 'dangerouslySetInnerHTML';          Desc = "dangerouslySetInnerHTML usage — XSS risk (React)"; Sev = "high" },
    @{ Regex = '\bshell_exec\s*\(';               Desc = "shell_exec() usage — shell injection risk (PHP)";  Sev = "high" },
    @{ Regex = '\bpassthru\s*\(';                 Desc = "passthru() usage — shell injection risk (PHP)";    Sev = "high" },
    @{ Regex = '\bpickle\.loads?\s*\(';           Desc = "pickle.load() with untrusted data — deserialization risk (Python)"; Sev = "medium" },
    @{ Regex = '\bdeserialize\s*\(';              Desc = "deserialize() usage — potential deserialization attack"; Sev = "medium" },
    @{ Regex = '\bdocument\.write\s*\(';          Desc = "document.write() usage — XSS risk";               Sev = "medium" },
    @{ Regex = 'subprocess\.(call|run|Popen).*shell\s*=\s*True'; Desc = "subprocess with shell=True — shell injection risk"; Sev = "high" }
)

foreach ($file in ($allFiles | Where-Object { $_.Extension -in ".js",".ts",".py",".php",".rb" })) {
    try {
        $lines = Get-Content $file.FullName -ErrorAction Stop
        $lineNum = 0
        foreach ($line in $lines) {
            $lineNum++
            $trimmed = $line.Trim()
            if ($trimmed.StartsWith("#") -or $trimmed.StartsWith("//") -or $trimmed.StartsWith("*")) { continue }

            foreach ($pattern in $dangerousPatterns) {
                if ($line -match $pattern.Regex) {
                    $relPath = $file.FullName.Replace($FolderPath, "").TrimStart("\")
                    $msg = "$($pattern.Desc) — $relPath line $lineNum"
                    switch ($pattern.Sev) {
                        "high"   { $high   += $msg }
                        "medium" { $medium += $msg }
                    }
                    break
                }
            }
        }
    } catch {}
}

# ─── 3. SQL Injection Patterns ───────────────────────────────────────────────
$sqlPatterns = @(
    @{ Regex = '(?i)(SELECT|INSERT|UPDATE|DELETE|DROP).*\+\s*[\$\w]';    Desc = "SQL query with string concatenation — injection risk" },
    @{ Regex = '(?i)(SELECT|INSERT|UPDATE|DELETE).*\bWHERE\b.*\+';       Desc = "SQL WHERE clause with concatenation — injection risk" },
    @{ Regex = '(?i)query\s*\(.*\+\s*[\$\w]';                            Desc = "DB query() with concatenated variable — injection risk" },
    @{ Regex = '(?i)execute\s*\(\s*["\x27].*\+';                         Desc = "DB execute() with string concatenation — injection risk" },
    @{ Regex = '(?i)\$_(GET|POST|REQUEST|COOKIE)\[.*\].*sql';            Desc = "User input directly used in SQL context (PHP) — injection risk" }
)

foreach ($file in ($allFiles | Where-Object { $_.Extension -in ".js",".ts",".py",".php",".rb" })) {
    try {
        $lines = Get-Content $file.FullName -ErrorAction Stop
        $lineNum = 0
        foreach ($line in $lines) {
            $lineNum++
            $trimmed = $line.Trim()
            if ($trimmed.StartsWith("#") -or $trimmed.StartsWith("//") -or $trimmed.StartsWith("*")) { continue }

            foreach ($pattern in $sqlPatterns) {
                if ($line -match $pattern.Regex) {
                    $relPath = $file.FullName.Replace($FolderPath, "").TrimStart("\")
                    $high += "$($pattern.Desc) — $relPath line $lineNum"
                    break
                }
            }
        }
    } catch {}
}

# ─── 4. Dependency Audit ─────────────────────────────────────────────────────
# npm audit
$packageJson = Join-Path $FolderPath "package.json"
if (Test-Path $packageJson) {
    $npmCmd = Get-Command npm -ErrorAction SilentlyContinue
    if ($npmCmd) {
        Write-Host "  Running npm audit..." -ForegroundColor Gray
        $npmOutput = & npm audit --json 2>&1 | Out-String
        try {
            $npmJson = $npmOutput | ConvertFrom-Json
            $vulnCount = $npmJson.metadata.vulnerabilities
            if ($vulnCount) {
                $crit  = if ($vulnCount.critical) { $vulnCount.critical } else { 0 }
                $hig   = if ($vulnCount.high)     { $vulnCount.high     } else { 0 }
                $mod   = if ($vulnCount.moderate)  { $vulnCount.moderate } else { 0 }
                $lo    = if ($vulnCount.low)       { $vulnCount.low      } else { 0 }
                if ($crit -gt 0) { $critical += "npm audit: $crit critical vulnerability(-ies) in dependencies — run 'npm audit fix'" }
                if ($hig  -gt 0) { $high     += "npm audit: $hig high vulnerability(-ies) in dependencies" }
                if ($mod  -gt 0) { $medium   += "npm audit: $mod moderate vulnerability(-ies) in dependencies" }
                if ($lo   -gt 0) { $low      += "npm audit: $lo low vulnerability(-ies) in dependencies" }
                if ($crit + $hig + $mod + $lo -eq 0) { $info += "npm audit: no known vulnerabilities found" }
            }
        } catch {
            $info += "npm audit ran but output could not be parsed"
        }
    } else {
        $info += "package.json found but npm not installed — skipping npm audit"
    }
}

# pip audit
$requirementsTxt = Join-Path $FolderPath "requirements.txt"
if (Test-Path $requirementsTxt) {
    $pipAuditCmd = Get-Command pip-audit -ErrorAction SilentlyContinue
    if ($pipAuditCmd) {
        Write-Host "  Running pip-audit..." -ForegroundColor Gray
        $pipOutput = & pip-audit --requirement $requirementsTxt --format=json 2>&1 | Out-String
        try {
            $pipJson = $pipOutput | ConvertFrom-Json
            if ($pipJson.Count -gt 0) {
                $high += "pip-audit: $($pipJson.Count) vulnerable Python package(s) found — run 'pip-audit -r requirements.txt'"
            } else {
                $info += "pip-audit: no known Python vulnerabilities found"
            }
        } catch {
            $info += "pip-audit ran but output could not be parsed (check manually)"
        }
    } else {
        $info += "requirements.txt found but pip-audit not installed — run 'pip install pip-audit' to enable"
    }
}

# ─── Build Report ────────────────────────────────────────────────────────────
# Deduplicate
$critical = $critical | Select-Object -Unique
$high     = $high     | Select-Object -Unique
$medium   = $medium   | Select-Object -Unique
$low      = $low      | Select-Object -Unique
$info     = $info     | Select-Object -Unique

# Truncate if over 20
if ($critical.Count + $high.Count + $medium.Count + $low.Count -gt 20) {
    $info += "(Results truncated to top findings by severity)"
    $critical = $critical | Select-Object -First 5
    $high     = $high     | Select-Object -First 8
    $medium   = $medium   | Select-Object -First 5
    $low      = $low      | Select-Object -First 2
}

$targetLabel = Split-Path $FolderPath -Leaf

Write-Host ""
Write-Host "🔍 WebGuard Report — $targetLabel"
Write-Host $DIVIDER
Write-Host ""

if ($critical.Count -gt 0) {
    Write-Host "🔴 CRITICAL ($($critical.Count))" -ForegroundColor Red
    foreach ($i in $critical) { Write-Host "  • $i" }
    Write-Host ""
}
if ($high.Count -gt 0) {
    Write-Host "🟠 HIGH ($($high.Count))" -ForegroundColor DarkYellow
    foreach ($i in $high) { Write-Host "  • $i" }
    Write-Host ""
}
if ($medium.Count -gt 0) {
    Write-Host "🟡 MEDIUM ($($medium.Count))" -ForegroundColor Yellow
    foreach ($i in $medium) { Write-Host "  • $i" }
    Write-Host ""
}
if ($low.Count -gt 0) {
    Write-Host "🟢 LOW ($($low.Count))" -ForegroundColor Green
    foreach ($i in $low) { Write-Host "  • $i" }
    Write-Host ""
}
if ($info.Count -gt 0) {
    Write-Host "ℹ️  INFO ($($info.Count))" -ForegroundColor Gray
    foreach ($i in $info) { Write-Host "  • $i" }
    Write-Host ""
}

if ($critical.Count -eq 0 -and $high.Count -eq 0 -and $medium.Count -eq 0 -and $low.Count -eq 0) {
    Write-Host "✅ No issues found — code looks clean!" -ForegroundColor Green
    Write-Host ""
}

# Top Fixes
$topFixes = @()
if ($critical | Where-Object { $_ -match "password|secret|api_key|token|key" }) {
    $topFixes += "Move all secrets to environment variables or a secrets manager (never hardcode)"
}
if ($critical | Where-Object { $_ -match "npm audit" }) {
    $topFixes += "Run 'npm audit fix' to auto-remediate vulnerable dependencies"
}
if ($high | Where-Object { $_ -match "eval|exec|system|innerHTML" }) {
    $topFixes += "Replace dangerous functions: use safe alternatives (e.g., textContent instead of innerHTML)"
}
if ($high | Where-Object { $_ -match "SQL|injection" }) {
    $topFixes += "Use parameterized queries / prepared statements for all database operations"
}

if ($topFixes.Count -gt 0) {
    Write-Host "📋 Top Fix:" -ForegroundColor Cyan
    foreach ($fix in ($topFixes | Select-Object -First 3)) {
        Write-Host "→ $fix"
    }
    Write-Host ""
}

Write-Host $DIVIDER
Write-Host "by cybersecurity experts | WebGuard v1.0"
Write-Host ""
