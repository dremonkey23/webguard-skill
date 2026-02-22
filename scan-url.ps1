# WebGuard — URL Scanner (PowerShell)
# Usage: .\scan-url.ps1 <URL>
# Example: .\scan-url.ps1 https://example.com

param(
    [Parameter(Mandatory=$true)]
    [string]$Url
)

$ErrorActionPreference = "SilentlyContinue"

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
$host     = $uri.Host
$isHttps  = $uri.Scheme -eq "https"
$baseUrl  = "$($uri.Scheme)://$($uri.Host)"
$httpBase = "http://$($uri.Host)"

Write-Host ""
Write-Host "🔍 WebGuard — Scanning $host ..." -ForegroundColor Cyan
Write-Host ""

# ─── 1. SSL / HTTPS Check ───────────────────────────────────────────────────
if (-not $isHttps) {
    $critical += "Site uses HTTP — all traffic is unencrypted and can be intercepted"
} else {
    # Check if HTTP redirects to HTTPS
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
# CSP
if (-not (Get-Header $headers "Content-Security-Policy")) {
    $high += "Missing Content-Security-Policy header — XSS attacks are unrestricted"
} else {
    $info += "Content-Security-Policy header present"
}

# HSTS
if ($isHttps) {
    if (-not (Get-Header $headers "Strict-Transport-Security")) {
        $high += "Missing Strict-Transport-Security (HSTS) — browsers may fall back to HTTP"
    } else {
        $info += "HSTS header present"
    }
}

# X-Frame-Options
if (-not (Get-Header $headers "X-Frame-Options")) {
    $medium += "Missing X-Frame-Options header — site may be vulnerable to clickjacking"
} else {
    $info += "X-Frame-Options header present"
}

# X-Content-Type-Options
if (-not (Get-Header $headers "X-Content-Type-Options")) {
    $low += "Missing X-Content-Type-Options header — MIME-type sniffing possible"
} else {
    $info += "X-Content-Type-Options header present"
}

# Referrer-Policy
if (-not (Get-Header $headers "Referrer-Policy")) {
    $low += "Missing Referrer-Policy header — referrer data may leak to third parties"
} else {
    $info += "Referrer-Policy header present"
}

# Server header info leak
$serverHdr = Get-Header $headers "Server"
if ($serverHdr) {
    if ($serverHdr -match "\d") {
        $low += "Server header exposes version info: '$serverHdr' — aids fingerprinting"
    } else {
        $info += "Server header present (no version): $serverHdr"
    }
}

# X-Powered-By
$poweredBy = Get-Header $headers "X-Powered-By"
if ($poweredBy) {
    $low += "X-Powered-By header exposes technology: '$poweredBy'"
}

# ─── 4. Outdated/Vulnerable JS Libraries ────────────────────────────────────
$libPatterns = @(
    @{ Name = "jQuery";     Regex = 'jquery[.-](\d+\.\d+\.?\d*)(\.min)?\.js|jquery.*version["\s:]+["\x27](\d+\.\d+\.?\d*)'; CVE = "1.x/2.x: CVE-2019-11358 (XSS), CVE-2020-11022" },
    @{ Name = "Angular";    Regex = 'angular[.-](\d+\.\d+\.?\d*)(\.min)?\.js|angularjs.*version["\s:]+["\x27](\d+\.\d+\.?\d*)'; CVE = "<1.8: multiple XSS CVEs" },
    @{ Name = "React";      Regex = 'react[.-](\d+\.\d+\.?\d*)(\.min)?\.js'; CVE = "<16.9: CVE-2018-6341" },
    @{ Name = "Bootstrap";  Regex = 'bootstrap[.-](\d+\.\d+\.?\d*)(\.min)?\.js|bootstrap[.-](\d+\.\d+\.?\d*)(\.min)?\.css'; CVE = "<3.4.1: CVE-2019-8331 (XSS)" },
    @{ Name = "Lodash";     Regex = 'lodash[.-](\d+\.\d+\.?\d*)(\.min)?\.js'; CVE = "<4.17.21: CVE-2021-23337 (injection)" },
    @{ Name = "Moment.js";  Regex = 'moment[.-](\d+\.\d+\.?\d*)(\.min)?\.js'; CVE = "<2.29.2: CVE-2022-24785 (path traversal)" }
)

foreach ($lib in $libPatterns) {
    if ($html -match $lib.Regex) {
        $version = if ($Matches[1]) { $Matches[1] } elseif ($Matches[3]) { $Matches[3] } else { "unknown version" }
        $high += "$($lib.Name) $version detected in page source — $($lib.CVE)"
    }
}

# ─── 5. Exposed Sensitive Files ─────────────────────────────────────────────
$sensitiveFiles = @(
    @{ Path = "/.env";          Severity = "critical"; Desc = ".env file accessible — may expose credentials and API keys" },
    @{ Path = "/.git/config";   Severity = "critical"; Desc = ".git/config accessible — source code structure exposed" },
    @{ Path = "/.htaccess";     Severity = "medium";   Desc = ".htaccess accessible — server config may be readable" },
    @{ Path = "/backup.zip";    Severity = "high";     Desc = "backup.zip accessible — full site backup may be downloadable" },
    @{ Path = "/backup.tar.gz"; Severity = "high";     Desc = "backup.tar.gz accessible" },
    @{ Path = "/config.php";    Severity = "high";     Desc = "config.php accessible — database credentials may be exposed" },
    @{ Path = "/wp-config.php"; Severity = "high";     Desc = "wp-config.php accessible — WordPress DB credentials exposed" },
    @{ Path = "/.DS_Store";     Severity = "medium";   Desc = ".DS_Store accessible — directory structure revealed (macOS artifact)" },
    @{ Path = "/phpinfo.php";   Severity = "high";     Desc = "phpinfo.php accessible — full PHP environment info exposed" },
    @{ Path = "/server-status"; Severity = "medium";   Desc = "Apache server-status accessible — internal stats visible" }
)

foreach ($file in $sensitiveFiles) {
    $testUrl = "$baseUrl$($file.Path)"
    try {
        $r = Invoke-WebRequest -Uri $testUrl -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
        if ($r.StatusCode -eq 200) {
            switch ($file.Severity) {
                "critical" { $critical += "$($file.Desc) at $($file.Path)" }
                "high"     { $high     += "$($file.Desc) at $($file.Path)" }
                "medium"   { $medium   += "$($file.Desc) at $($file.Path)" }
            }
        }
    } catch {}
}

# ─── 6. Mixed Content ───────────────────────────────────────────────────────
if ($isHttps -and $html) {
    $httpAssets = [regex]::Matches($html, 'src=["\x27](http://[^"]+)["\x27]|href=["\x27](http://[^"]+)["\x27]')
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
$divider = "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
Write-Host ""
Write-Host "🔍 WebGuard Report — $host"
Write-Host $divider
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
if ($critical | Where-Object { $_ -match "HTTP" })      { $topFixes += "Redirect all HTTP traffic to HTTPS in your server config" }
if ($critical | Where-Object { $_ -match "\.env" })     { $topFixes += "Block .env access: add 'deny from all' in .htaccess or nginx equivalent" }
if ($critical | Where-Object { $_ -match "\.git" })     { $topFixes += "Block .git directory access from public web server" }
if ($high     | Where-Object { $_ -match "CSP|Content-Security-Policy" }) { $topFixes += "Add CSP header: Content-Security-Policy: default-src 'self'" }
if ($high     | Where-Object { $_ -match "HSTS|Strict-Transport" })       { $topFixes += "Add HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains" }
if ($high     | Where-Object { $_ -match "jQuery|Angular|Bootstrap|Lodash|React|Moment" }) { $topFixes += "Update JS libraries to latest stable versions" }

if ($topFixes.Count -gt 0) {
    Write-Host "📋 Top Fix:" -ForegroundColor Cyan
    foreach ($fix in ($topFixes | Select-Object -First 3)) {
        Write-Host "→ $fix"
    }
    Write-Host ""
}

Write-Host $divider
Write-Host "by cybersecurity experts | WebGuard v1.0"
Write-Host ""
