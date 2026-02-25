# WebGuard — URL Scanner (PowerShell)
# Usage: .\scan-url.ps1 <URL>
# Example: .\scan-url.ps1 https://example.com

param(
    [Parameter(Mandatory=$true)]
    [string]$Url
)

$ErrorActionPreference = "SilentlyContinue"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# ─── Load patterns from encoded data files ───────────────────────────────────
function Load-Patterns($fileName) {
    $raw = Get-Content (Join-Path $ScriptDir "patterns/$fileName") -Raw
    $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($raw.Trim()))
    return $decoded | ConvertFrom-Json
}
$urlPatterns = Load-Patterns "urls.json.b64"

# ─── Severity buckets ───────────────────────────────────────────────────────
$critical = @()
$high     = @()
$medium   = @()
$low      = @()
$info     = @()

# ─── Helpers ────────────────────────────────────────────────────────────────
function Try-Fetch {
    param([string]$TargetUrl, [int]$TimeoutSec = 10)
    try {
        $response = Invoke-WebRequest -Uri $TargetUrl `
            -UseBasicParsing `
            -TimeoutSec $TimeoutSec `
            -MaximumRedirection 0 `
            -ErrorAction Stop
        return $response
    } catch {
        return $null
    }
}

function Try-FetchFollow {
    param([string]$TargetUrl, [int]$TimeoutSec = 15)
    try {
        $response = Invoke-WebRequest -Uri $TargetUrl `
            -UseBasicParsing `
            -TimeoutSec $TimeoutSec `
            -ErrorAction Stop
        return $response
    } catch {
        return $null
    }
}

function Get-Header {
    param($Headers, [string]$Name)
    if ($Headers -and $Headers[$Name]) { return $Headers[$Name] }
    return $null
}

# ─── Normalize URL ──────────────────────────────────────────────────────────
$Url = $Url.TrimEnd("/")
if ($Url -notmatch "^https?://") { $Url = "https://$Url" }
$uri      = [System.Uri]$Url
$hostName = $uri.Host
$isHttps  = $uri.Scheme -eq "https"
$baseUrl  = "$($uri.Scheme)://$($uri.Host)"
$httpBase = "http://$($uri.Host)"
$DIVIDER  = "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

Write-Host ""
Write-Host "🔍 WebGuard — Scanning $hostName ..." -ForegroundColor Cyan
Write-Host ""

# ─── 1. SSL / HTTPS Check ───────────────────────────────────────────────────
if (-not $isHttps) {
    $critical += "Site uses HTTP — all traffic is unencrypted and can be intercepted"
} else {
    $httpResp = Try-Fetch -TargetUrl $httpBase
    if ($httpResp -and $httpResp.StatusCode -eq 200) {
        $critical += "HTTP version returns 200 (no redirect to HTTPS) — traffic interception risk"
    } elseif ($httpResp -and $httpResp.StatusCode -in 301, 302, 307, 308) {
        $info += "HTTPS enforced via redirect ($($httpResp.StatusCode))"
    } else {
        $info += "HTTPS detected — encrypted connection"
    }
}

# ─── 2. Fetch Main Page ─────────────────────────────────────────────────────
$mainResp = Try-FetchFollow -TargetUrl $Url
if (-not $mainResp) {
    Write-Host "❌ Could not reach $Url — scan aborted." -ForegroundColor Red
    exit 1
}

$headers = $mainResp.Headers
$html    = $mainResp.Content

# ─── 3. Security Headers ────────────────────────────────────────────────────
if (-not (Get-Header $headers "Content-Security-Policy")) {
    $high += "Missing Content-Security-Policy header — XSS attacks are unrestricted"
} else {
    $info += "Content-Security-Policy header present"
}

if ($isHttps) {
    if (-not (Get-Header $headers "Strict-Transport-Security")) {
        $high += "Missing Strict-Transport-Security (HSTS) — browsers may fall back to HTTP"
    } else {
        $info += "HSTS header present"
    }
}

if (-not (Get-Header $headers "X-Frame-Options")) {
    $medium += "Missing X-Frame-Options header — site may be vulnerable to clickjacking"
} else {
    $info += "X-Frame-Options header present"
}

if (-not (Get-Header $headers "X-Content-Type-Options")) {
    $low += "Missing X-Content-Type-Options header — MIME-type sniffing possible"
} else {
    $info += "X-Content-Type-Options header present"
}

if (-not (Get-Header $headers "Referrer-Policy")) {
    $low += "Missing Referrer-Policy header — referrer data may leak to third parties"
} else {
    $info += "Referrer-Policy header present"
}

$serverHdr = Get-Header $headers "Server"
if ($serverHdr) {
    if ($serverHdr -match "\d") {
        $low += "Server header exposes version info: '$serverHdr' — aids fingerprinting"
    } else {
        $info += "Server header present (no version): $serverHdr"
    }
}

$poweredBy = Get-Header $headers "X-Powered-By"
if ($poweredBy) {
    $low += "X-Powered-By header exposes technology: '$poweredBy'"
}

# ─── 4. Outdated/Vulnerable JS Libraries (from patterns file) ───────────────
foreach ($lib in $urlPatterns.libraries) {
    if ($html -match $lib.r) {
        $version = if ($Matches[1]) { $Matches[1] } elseif ($Matches[3]) { $Matches[3] } else { "unknown version" }
        $high += "$($lib.name) $version detected in page source — $($lib.cve)"
    }
}

# ─── 5. Exposed Sensitive Files (from patterns file) ────────────────────────
foreach ($file in $urlPatterns.sensitive_files) {
    $testUrl = "$baseUrl$($file.path)"
    try {
        $r = Invoke-WebRequest -Uri $testUrl -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
        if ($r.StatusCode -eq 200) {
            switch ($file.s) {
                "critical" { $critical += "$($file.d) at $($file.path)" }
                "high"     { $high     += "$($file.d) at $($file.path)" }
                "medium"   { $medium   += "$($file.d) at $($file.path)" }
            }
        }
    } catch {}
}

# ─── 6. Mixed Content ───────────────────────────────────────────────────────
if ($isHttps -and $html) {
    $httpAssets = [regex]::Matches($html, 'src=["''][h][t][t][p]://[^"]+["'']|href=["''][h][t][t][p]://[^"]+["'']')
    if ($httpAssets.Count -gt 0) {
        $medium += "Mixed content detected — $($httpAssets.Count) HTTP asset(s) loaded on HTTPS page"
    }
}

# ─── 7. Cookie Flags ────────────────────────────────────────────────────────
$setCookie = Get-Header $headers "Set-Cookie"
if ($setCookie) {
    if ($setCookie -notmatch "HttpOnly") {
        $medium += "Session cookie missing HttpOnly flag — JavaScript can read cookies (XSS risk)"
    }
    if ($isHttps -and $setCookie -notmatch "Secure") {
        $medium += "Session cookie missing Secure flag — cookie may be sent over HTTP"
    }
    if ($setCookie -notmatch "SameSite") {
        $low += "Session cookie missing SameSite attribute — CSRF risk"
    }
}

# ─── Build Report ───────────────────────────────────────────────────────────
Write-Host ""
Write-Host "🔍 WebGuard Report — $hostName"
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
    Write-Host "✅ No issues found — site looks clean!" -ForegroundColor Green
    Write-Host ""
}

# Top Fixes
$topFixes = @()
if ($critical | Where-Object { $_ -match "HTTP|http" }) {
    $topFixes += "Redirect all HTTP traffic to HTTPS in your server config"
}
if ($critical | Where-Object { $_ -match "\.env" }) {
    $topFixes += "Block .env access in your web server config"
}
if ($high | Where-Object { $_ -match "Content-Security-Policy" }) {
    $topFixes += "Add CSP header: Content-Security-Policy: default-src 'self'"
}
if ($high | Where-Object { $_ -match "detected in page" }) {
    $topFixes += "Update JS libraries to their latest stable versions"
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
