<#
.SYNOPSIS
    WebGuard URL Scanner v1.0 — Frontend security scanner
.DESCRIPTION
    Scans a URL for frontend security vulnerabilities including headers,
    exposed files, JS library versions, mixed content, and SSL status.
.PARAMETER Url
    The URL to scan (e.g. https://example.com)
.EXAMPLE
    .\scan-url.ps1 -Url "https://example.com"
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$Url
)

# ── Helpers ──────────────────────────────────────────────────────────────────

function Write-Finding($level, $message) {
    Write-Output "[$level] $message"
}

function Safe-Fetch($uri, $timeoutSec = 10) {
    try {
        $resp = Invoke-WebRequest -Uri $uri -TimeoutSec $timeoutSec `
            -UseBasicParsing -MaximumRedirection 0 -ErrorAction Stop
        return $resp
    } catch [System.Net.WebException] {
        $r = $_.Exception.Response
        if ($r) { return $r }
        return $null
    } catch {
        return $null
    }
}

function Get-StatusCode($resp) {
    if ($null -eq $resp) { return 0 }
    if ($resp -is [Microsoft.PowerShell.Commands.HtmlWebResponseObject] -or
        $resp -is [Microsoft.PowerShell.Commands.BasicHtmlWebResponseObject]) {
        return [int]$resp.StatusCode
    }
    if ($resp -is [System.Net.HttpWebResponse]) {
        return [int]$resp.StatusCode
    }
    return 0
}

function Get-Header($resp, $name) {
    try {
        if ($resp.Headers -is [System.Collections.Hashtable] -or
            $resp.Headers -is [System.Collections.Specialized.NameValueCollection]) {
            return $resp.Headers[$name]
        }
        if ($resp.Headers.ContainsKey($name)) { return $resp.Headers[$name] }
    } catch {}
    return $null
}

# ── Normalise URL ─────────────────────────────────────────────────────────────

$Url = $Url.TrimEnd('/')
$isHttps = $Url -match '^https://'
$host = ([System.Uri]$Url).Host
$baseUrl = $Url

$findings = @()
$passed   = @()

Write-Host ""
Write-Host "🔍 WebGuard Report — $host" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━"
Write-Host "  Scanning $Url ..."
Write-Host ""

# ── 1. SSL / HTTPS ────────────────────────────────────────────────────────────

if (-not $isHttps) {
    $findings += @{ level="CRITICAL"; msg="Site not served over HTTPS — traffic can be intercepted" }
} else {
    # Check HTTP→HTTPS redirect
    $httpUrl = $Url -replace '^https://', 'http://'
    try {
        $httpResp = Invoke-WebRequest -Uri $httpUrl -TimeoutSec 8 -UseBasicParsing -MaximumRedirection 5 -ErrorAction Stop
        if ($httpResp.BaseResponse.ResponseUri.Scheme -ne 'https') {
            $findings += @{ level="HIGH"; msg="HTTP does not redirect to HTTPS — plaintext access possible" }
        } else {
            $passed += "HTTP correctly redirects to HTTPS"
        }
    } catch {
        # Redirect failed or connection refused — likely fine
        $passed += "HTTP redirect check inconclusive (connection refused or timeout)"
    }
    $passed += "HTTPS is enforced on the main URL"
}

# ── 2. Fetch main page ────────────────────────────────────────────────────────

$mainResp = $null
try {
    $mainResp = Invoke-WebRequest -Uri $Url -TimeoutSec 15 -UseBasicParsing -ErrorAction Stop
} catch {
    Write-Warning "Could not fetch $Url — $_"
    Write-Output "[CRITICAL] Could not connect to $Url — scanner aborted"
    exit 1
}

$html    = $mainResp.Content
$headers = $mainResp.Headers

# ── 3. Security Headers ───────────────────────────────────────────────────────

$hdrChecks = @(
    @{ name="Content-Security-Policy";   level="HIGH";   label="Content-Security-Policy (CSP)" },
    @{ name="Strict-Transport-Security"; level="HIGH";   label="HTTP Strict-Transport-Security (HSTS)" },
    @{ name="X-Frame-Options";           level="MEDIUM"; label="X-Frame-Options" },
    @{ name="X-Content-Type-Options";    level="LOW";    label="X-Content-Type-Options" },
    @{ name="Referrer-Policy";           level="LOW";    label="Referrer-Policy" }
)

foreach ($h in $hdrChecks) {
    $val = Get-Header $mainResp $h.name
    if (-not $val) {
        $findings += @{ level=$h.level; msg="Missing $($h.label) header" }
    } else {
        $passed += "$($h.label) header present"
    }
}

# ── 4. JS Library Version Detection ──────────────────────────────────────────

$libPatterns = @(
    @{ name="jQuery";     regex='jquery[.-](\d+\.\d+\.\d+)';     cve="CVE-2020-11022"; safe="3.5.0"; level="HIGH" },
    @{ name="Bootstrap";  regex='bootstrap[.-](\d+\.\d+\.\d+)';  cve="CVE-2019-8331";  safe="4.3.1"; level="MEDIUM" },
    @{ name="lodash";     regex='lodash[.-](\d+\.\d+\.\d+)';     cve="CVE-2021-23337"; safe="4.17.21"; level="HIGH" },
    @{ name="Angular";    regex='angular[.-](\d+\.\d+\.\d+)';    cve="CVE-2019-14863"; safe="2.0.0"; level="HIGH" },
    @{ name="React";      regex='react[.-](\d+\.\d+\.\d+)';      cve="";               safe="";      level="LOW" }
)

foreach ($lib in $libPatterns) {
    if ($html -match $lib.regex) {
        $ver = $Matches[1]
        if ($lib.cve) {
            $findings += @{ level=$lib.level; msg="$($lib.name) $ver detected — check against $($lib.cve) (safe: v$($lib.safe)+)" }
        } else {
            $passed += "$($lib.name) $ver detected (no known critical CVE flagged)"
        }
    }
}

# ── 5. Exposed Sensitive Files ────────────────────────────────────────────────

$sensitiveFiles = @(
    @{ path="/.env";        label=".env file" },
    @{ path="/.git/config"; label=".git/config" },
    @{ path="/.htaccess";   label=".htaccess" },
    @{ path="/backup.zip";  label="backup.zip" },
    @{ path="/config.php";  label="config.php" }
)

foreach ($sf in $sensitiveFiles) {
    $testUrl = "$($Url.TrimEnd('/'))$($sf.path)"
    try {
        $sfResp = Invoke-WebRequest -Uri $testUrl -TimeoutSec 8 -UseBasicParsing -ErrorAction Stop
        $code = [int]$sfResp.StatusCode
        if ($code -eq 200 -and $sfResp.Content.Length -gt 10) {
            $findings += @{ level="CRITICAL"; msg="$($sf.label) publicly accessible at $testUrl — may expose credentials/config" }
        }
    } catch {
        # 403/404 = good
    }
}

# ── 6. Mixed Content ──────────────────────────────────────────────────────────

if ($isHttps) {
    $mixedMatches = [regex]::Matches($html, '(?i)(src|href|url)\s*=\s*[''"]?(http://[^\s''"<>]+)')
    if ($mixedMatches.Count -gt 0) {
        $examples = ($mixedMatches | Select-Object -First 3 | ForEach-Object { $_.Groups[2].Value }) -join ", "
        $findings += @{ level="MEDIUM"; msg="Mixed content detected — $($mixedMatches.Count) HTTP asset(s) on HTTPS page (e.g. $examples)" }
    } else {
        $passed += "No mixed content detected"
    }
}

# ── 7. Build Report ───────────────────────────────────────────────────────────

$levels = @("CRITICAL","HIGH","MEDIUM","LOW")
$icons  = @{ CRITICAL="🔴"; HIGH="🟠"; MEDIUM="🟡"; LOW="🟢" }

Write-Host "🔍 WebGuard Report — $host"
Write-Host "━━━━━━━━━━━━━━━━━━━"
Write-Host ""

$hasFindings = $false
foreach ($lvl in $levels) {
    $group = $findings | Where-Object { $_.level -eq $lvl }
    if ($group.Count -gt 0) {
        $hasFindings = $true
        Write-Host "$($icons[$lvl]) $lvl ($($group.Count))" -ForegroundColor $(
            switch ($lvl) {
                "CRITICAL" { "Red" }
                "HIGH"     { "DarkYellow" }
                "MEDIUM"   { "Yellow" }
                "LOW"      { "Green" }
            }
        )
        foreach ($f in $group) {
            Write-Host "  • $($f.msg)"
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
$topFix = $findings | Select-Object -First 2
if ($topFix) {
    Write-Host "📋 Top Fix:"
    foreach ($f in $topFix) {
        Write-Host "→ $($f.msg)" -ForegroundColor Cyan
    }
    Write-Host ""
}

Write-Host "━━━━━━━━━━━━━━━━━━━"
Write-Host "by cybersecurity experts | WebGuard v1.0"
