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
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$DIVIDER = "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

Write-Host ""
Write-Host "🔍 WebGuard — Scanning code at: $FolderPath" -ForegroundColor Cyan
Write-Host ""

# ─── Load patterns from encoded data files ───────────────────────────────────
function Load-Patterns($fileName) {
    $raw = Get-Content (Join-Path $ScriptDir "patterns/$fileName") -Raw
    $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($raw.Trim()))
    return $decoded | ConvertFrom-Json
}
$secretPatterns    = Load-Patterns "secrets.json.b64"
$dangerousPatterns = Load-Patterns "dangerous.json.b64"
$sqlPatterns       = Load-Patterns "sql.json.b64"

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
foreach ($file in $allFiles) {
    try {
        $lines = Get-Content $file.FullName -ErrorAction Stop
        $lineNum = 0
        foreach ($line in $lines) {
            $lineNum++
            $trimmed = $line.Trim()
            if ($trimmed.StartsWith("#") -or $trimmed.StartsWith("//") -or $trimmed.StartsWith("*")) { continue }

            foreach ($pattern in $secretPatterns) {
                if ($line -match $pattern.r) {
                    $relPath = $file.FullName.Replace($FolderPath, "").TrimStart("\")
                    $msg = "$($pattern.d) in $relPath line $lineNum"
                    switch ($pattern.s) {
                        "critical" { $critical += $msg }
                        "high"     { $high     += $msg }
                    }
                    break
                }
            }
        }
    } catch {}
}

# ─── 2. Dangerous Functions ──────────────────────────────────────────────────
foreach ($file in ($allFiles | Where-Object { $_.Extension -in ".js",".ts",".py",".php",".rb" })) {
    try {
        $lines = Get-Content $file.FullName -ErrorAction Stop
        $lineNum = 0
        foreach ($line in $lines) {
            $lineNum++
            $trimmed = $line.Trim()
            if ($trimmed.StartsWith("#") -or $trimmed.StartsWith("//") -or $trimmed.StartsWith("*")) { continue }

            foreach ($pattern in $dangerousPatterns) {
                if ($line -match $pattern.r) {
                    $relPath = $file.FullName.Replace($FolderPath, "").TrimStart("\")
                    $msg = "$($pattern.d) — $relPath line $lineNum"
                    switch ($pattern.s) {
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
foreach ($file in ($allFiles | Where-Object { $_.Extension -in ".js",".ts",".py",".php",".rb" })) {
    try {
        $lines = Get-Content $file.FullName -ErrorAction Stop
        $lineNum = 0
        foreach ($line in $lines) {
            $lineNum++
            $trimmed = $line.Trim()
            if ($trimmed.StartsWith("#") -or $trimmed.StartsWith("//") -or $trimmed.StartsWith("*")) { continue }

            foreach ($pattern in $sqlPatterns) {
                if ($line -match $pattern.r) {
                    $relPath = $file.FullName.Replace($FolderPath, "").TrimStart("\")
                    $high += "$($pattern.d) — $relPath line $lineNum"
                    break
                }
            }
        }
    } catch {}
}

# ─── 4. Dependency Audit ─────────────────────────────────────────────────────
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
                if ($crit -gt 0) { $critical += "npm audit: $crit critical vulnerability(-ies) in dependencies" }
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

$requirementsTxt = Join-Path $FolderPath "requirements.txt"
if (Test-Path $requirementsTxt) {
    $pipAuditCmd = Get-Command pip-audit -ErrorAction SilentlyContinue
    if ($pipAuditCmd) {
        Write-Host "  Running pip-audit..." -ForegroundColor Gray
        $pipOutput = & pip-audit --requirement $requirementsTxt --format=json 2>&1 | Out-String
        try {
            $pipJson = $pipOutput | ConvertFrom-Json
            if ($pipJson.Count -gt 0) {
                $high += "pip-audit: $($pipJson.Count) vulnerable Python package(s) found"
            } else {
                $info += "pip-audit: no known Python vulnerabilities found"
            }
        } catch {
            $info += "pip-audit ran but output could not be parsed"
        }
    } else {
        $info += "requirements.txt found but pip-audit not installed"
    }
}

# ─── Build Report ────────────────────────────────────────────────────────────
$critical = $critical | Select-Object -Unique
$high     = $high     | Select-Object -Unique
$medium   = $medium   | Select-Object -Unique
$low      = $low      | Select-Object -Unique
$info     = $info     | Select-Object -Unique

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
    $topFixes += "Move all secrets to environment variables or a secrets manager"
}
if ($critical | Where-Object { $_ -match "npm audit" }) {
    $topFixes += "Run 'npm audit fix' to auto-remediate vulnerable dependencies"
}
if ($high | Where-Object { $_ -match "arbitrary|injection|XSS" }) {
    $topFixes += "Replace dangerous functions with safe alternatives"
}
if ($high | Where-Object { $_ -match "SQL|injection" }) {
    $topFixes += "Use parameterized queries for all database operations"
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
