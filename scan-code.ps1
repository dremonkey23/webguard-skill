<#
.SYNOPSIS
    WebGuard Code Scanner v1.0 — Local code security scanner
.DESCRIPTION
    Recursively scans a local folder for hardcoded secrets, dangerous functions,
    SQL injection patterns, and dependency vulnerabilities.
.PARAMETER Path
    The folder path to scan (e.g. C:\Projects\myapp)
.EXAMPLE
    .\scan-code.ps1 -Path "C:\Projects\myapp"
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$Path
)

if (-not (Test-Path $Path)) {
    Write-Error "Path not found: $Path"
    exit 1
}

$Path = (Resolve-Path $Path).Path

$findings_crit = [System.Collections.Generic.List[string]]::new()
$findings_high = [System.Collections.Generic.List[string]]::new()
$findings_med  = [System.Collections.Generic.List[string]]::new()
$findings_low  = [System.Collections.Generic.List[string]]::new()
$passed        = [System.Collections.Generic.List[string]]::new()

Write-Host ""
Write-Host "🔍 WebGuard Code Report — $Path"
Write-Host "━━━━━━━━━━━━━━━━━━━"
Write-Host "  Scanning files..." -ForegroundColor DarkGray

# ── File Extensions to Scan ───────────────────────────────────────────────────

$scanExts = @('*.js','*.ts','*.py','*.php','*.rb','*.env','*.json','*.yaml','*.yml','*.toml','*.config','*.cfg','*.ini','*.sh','*.bash')

$allFiles = @()
foreach ($ext in $scanExts) {
    $allFiles += Get-ChildItem -Path $Path -Filter $ext -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch '\\(node_modules|\.git|vendor|dist|build)\\' }
}

$totalFiles = $allFiles.Count
Write-Host "  Found $totalFiles files to scan" -ForegroundColor DarkGray

# ── 1. Hardcoded Secrets ──────────────────────────────────────────────────────

$secretPatterns = @(
    @{ name="OpenAI API key";         regex='sk-[A-Za-z0-9]{32,}' },
    @{ name="AWS access key";         regex='AKIA[0-9A-Z]{16}' },
    @{ name="GitHub PAT";             regex='ghp_[A-Za-z0-9]{36,}' },
    @{ name="GitHub OAuth token";     regex='gho_[A-Za-z0-9]{36,}' },
    @{ name="Hardcoded password";     regex='(?i)password\s*[=:]\s*[''"][^''"]{4,}' },
    @{ name="Hardcoded API key";      regex='(?i)api_key\s*[=:]\s*[''"][^''"]{4,}' },
    @{ name="Hardcoded secret";       regex='(?i)secret\s*[=:]\s*[''"][^''"]{4,}' },
    @{ name="Hardcoded token";        regex='(?i)\btoken\s*[=:]\s*[''"][^''"]{8,}' },
    @{ name="Bearer token in code";   regex='Bearer [A-Za-z0-9\-._~+\/]{20,}' },
    @{ name="Stripe key";             regex='sk_live_[A-Za-z0-9]{24,}' },
    @{ name="Slack token";            regex='xox[baprs]-[A-Za-z0-9\-]{10,}' }
)

$secretHits = 0
foreach ($file in $allFiles) {
    try {
        $content = Get-Content $file.FullName -ErrorAction Stop
        $lineNum = 0
        foreach ($line in $content) {
            $lineNum++
            foreach ($pat in $secretPatterns) {
                if ($line -match $pat.regex) {
                    $relPath = $file.FullName.Replace($Path, '').TrimStart('\','/')
                    $findings_crit.Add("$($pat.name) found in $relPath (line $lineNum)")
                    $secretHits++
                    break  # one finding per line
                }
            }
        }
    } catch { }
}

if ($secretHits -eq 0) { $passed.Add("No hardcoded secrets detected") }

# ── 2. Dangerous Functions ────────────────────────────────────────────────────

$dangerPatterns = @(
    @{ name="eval()";                       regex='(?<!\w)eval\s*\(' },
    @{ name="exec()";                       regex='(?<!\w)exec\s*\(' },
    @{ name="system()";                     regex='(?<!\w)system\s*\(' },
    @{ name="shell_exec()";                 regex='shell_exec\s*\(' },
    @{ name="subprocess.call()";            regex='subprocess\.call\s*\(' },
    @{ name="subprocess.Popen()";           regex='subprocess\.Popen\s*\(' },
    @{ name="innerHTML assignment";         regex='innerHTML\s*=' },
    @{ name="dangerouslySetInnerHTML";      regex='dangerouslySetInnerHTML' },
    @{ name="document.write()";            regex='document\.write\s*\(' }
)

$dangerHits = 0
foreach ($file in $allFiles) {
    # Skip minified files (very long single lines)
    if ($file.Name -match '\.min\.(js|css)$') { continue }
    try {
        $content = Get-Content $file.FullName -ErrorAction Stop
        $lineNum = 0
        foreach ($line in $content) {
            $lineNum++
            foreach ($pat in $dangerPatterns) {
                if ($line -match $pat.regex) {
                    $relPath = $file.FullName.Replace($Path, '').TrimStart('\','/')
                    $findings_high.Add("$($pat.name) used in $relPath (line $lineNum)")
                    $dangerHits++
                }
            }
        }
    } catch { }
}

if ($dangerHits -eq 0) { $passed.Add("No dangerous function patterns detected") }

# ── 3. SQL Injection Patterns ─────────────────────────────────────────────────

$sqlPatterns = @(
    @{ name="String concat in SQL";   regex='(?i)(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE).{0,60}["'']\s*\+' },
    @{ name="f-string SQL query";     regex='(?i)f["''](SELECT|INSERT|UPDATE|DELETE)' },
    @{ name="execute() with concat";  regex='(?i)\.execute\s*\(\s*[^,)]*\+' },
    @{ name="format() in SQL";        regex='(?i)(SELECT|INSERT|UPDATE|DELETE).{0,40}\.format\s*\(' }
)

$sqlHits = 0
foreach ($file in $allFiles) {
    if ($file.Extension -notin @('.py','.php','.rb','.js','.ts')) { continue }
    try {
        $content = Get-Content $file.FullName -ErrorAction Stop
        $lineNum = 0
        foreach ($line in $content) {
            $lineNum++
            foreach ($pat in $sqlPatterns) {
                if ($line -match $pat.regex) {
                    $relPath = $file.FullName.Replace($Path, '').TrimStart('\','/')
                    $findings_high.Add("$($pat.name) in $relPath (line $lineNum) — possible SQL injection")
                    $sqlHits++
                }
            }
        }
    } catch { }
}

if ($sqlHits -eq 0) { $passed.Add("No obvious SQL injection patterns detected") }

# ── 4. Dependency Audits ──────────────────────────────────────────────────────

# npm audit
$pkgJson = Get-ChildItem -Path $Path -Filter "package.json" -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notmatch '\\node_modules\\' } | Select-Object -First 1

if ($pkgJson) {
    Write-Host "  Running npm audit..." -ForegroundColor DarkGray
    $npmDir = $pkgJson.DirectoryName
    try {
        $npmOut = & npm audit --json 2>$null | ConvertFrom-Json -ErrorAction Stop
        $vulns  = $npmOut.metadata.vulnerabilities
        if ($vulns) {
            if ($vulns.critical -gt 0) { $findings_crit.Add("npm audit: $($vulns.critical) CRITICAL vulnerabilities found — run 'npm audit fix'") }
            if ($vulns.high    -gt 0) { $findings_high.Add("npm audit: $($vulns.high) HIGH vulnerabilities found — run 'npm audit fix'") }
            if ($vulns.moderate -gt 0) { $findings_med.Add("npm audit: $($vulns.moderate) MODERATE vulnerabilities found") }
            if ($vulns.low     -gt 0) { $findings_low.Add("npm audit: $($vulns.low) LOW vulnerabilities found") }
            if ($vulns.critical -eq 0 -and $vulns.high -eq 0) { $passed.Add("npm audit: no critical/high vulnerabilities") }
        }
    } catch {
        $findings_low.Add("npm audit could not run (npm not installed or node_modules missing)")
    }
} 

# pip audit
$reqTxt = Get-ChildItem -Path $Path -Filter "requirements.txt" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1

if ($reqTxt) {
    Write-Host "  Running pip audit..." -ForegroundColor DarkGray
    try {
        $pipOut = & pip audit --requirement $reqTxt.FullName --format json 2>$null | ConvertFrom-Json -ErrorAction Stop
        if ($pipOut.Count -gt 0) {
            $critical = $pipOut | Where-Object { $_.vulns.Count -gt 0 }
            if ($critical.Count -gt 0) {
                foreach ($pkg in $critical) {
                    $cveList = ($pkg.vulns | Select-Object -First 2 | ForEach-Object { $_.id }) -join ", "
                    $findings_high.Add("pip audit: $($pkg.name) $($pkg.version) has known vulnerabilities ($cveList)")
                }
            } else {
                $passed.Add("pip audit: no vulnerabilities found")
            }
        } else {
            $passed.Add("pip audit: no vulnerabilities found")
        }
    } catch {
        $findings_low.Add("pip audit could not run (install with: pip install pip-audit)")
    }
}

# ── 5. Report ─────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "🔍 WebGuard Code Report — $(Split-Path $Path -Leaf)"
Write-Host "  📁 $totalFiles files scanned"
Write-Host "━━━━━━━━━━━━━━━━━━━"
Write-Host ""

$sections = @(
    @{ list=$findings_crit; icon="🔴"; label="CRITICAL"; color="Red" },
    @{ list=$findings_high; icon="🟠"; label="HIGH";     color="DarkYellow" },
    @{ list=$findings_med;  icon="🟡"; label="MEDIUM";   color="Yellow" },
    @{ list=$findings_low;  icon="🟢"; label="LOW";      color="Green" }
)

$hasFindings = $false
foreach ($sec in $sections) {
    if ($sec.list.Count -gt 0) {
        $hasFindings = $true
        Write-Host "$($sec.icon) $($sec.label) ($($sec.list.Count))" -ForegroundColor $sec.color
        foreach ($f in $sec.list) {
            Write-Host "  • $f"
        }
        Write-Host ""
    }
}

if (-not $hasFindings) {
    Write-Host "✅ No vulnerabilities found!" -ForegroundColor Green
    Write-Host ""
}

if ($passed.Count -gt 0) {
    Write-Host "✅ PASSED"
    foreach ($p in $passed) {
        Write-Host "  • $p" -ForegroundColor Green
    }
    Write-Host ""
}

# Top fixes
$allFindings = @($findings_crit) + @($findings_high) + @($findings_med) + @($findings_low)
if ($allFindings.Count -gt 0) {
    Write-Host "📋 Top Fix:"
    $allFindings | Select-Object -First 2 | ForEach-Object { Write-Host "→ $_" -ForegroundColor Cyan }
    Write-Host ""
}

Write-Host "━━━━━━━━━━━━━━━━━━━"
Write-Host "by cybersecurity experts | WebGuard v1.0"
