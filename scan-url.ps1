param(
    [Parameter(Mandatory=$true)]
    [string]$Url
)

function Get-Header($resp, $name) {
    try {
        if ($resp.Headers.ContainsKey($name)) { return $resp.Headers[$name] }
    } catch {}
    return $null
}

$Url = $Url.TrimEnd('/')
$isHttps = $Url -match '^https://'
$targetHost = ([System.Uri]$Url).Host
$findings = @()
$passed   = @()

Write-Host ""
Write-Host "WebGuard URL Report -- $targetHost"
Write-Host "-----------------------------------"
Write-Host "Scanning $Url ..."
Write-Host ""

# 1. SSL / HTTPS
if (-not $isHttps) {
    $findings += @{ level="CRITICAL"; msg="Site not served over HTTPS - traffic can be intercepted" }
} else {
    $httpUrl = $Url -replace '^https://', 'http://'
    try {
        $httpResp = Invoke-WebRequest -Uri $httpUrl -TimeoutSec 8 -UseBasicParsing -MaximumRedirection 5 -ErrorAction Stop
        if ($httpResp.BaseResponse.ResponseUri.Scheme -ne 'https') {
            $findings += @{ level="HIGH"; msg="HTTP does not redirect to HTTPS - plaintext access possible" }
        } else {
            $passed += "HTTP correctly redirects to HTTPS"
        }
    } catch {
        $passed += "HTTP redirect check inconclusive"
    }
    $passed += "HTTPS enforced on main URL"
}

# 2. Fetch main page
$mainResp = $null
try {
    $mainResp = Invoke-WebRequest -Uri $Url -TimeoutSec 15 -UseBasicParsing -ErrorAction Stop
} catch {
    Write-Warning "Could not fetch $Url - $_"
    exit 1
}

$html = $mainResp.Content

# 3. Security Headers
$hdrChecks = @(
    @{ name="Content-Security-Policy";   level="HIGH";   label="Content-Security-Policy (CSP)" },
    @{ name="Strict-Transport-Security"; level="HIGH";   label="HSTS" },
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

# 4. JS Library Detection
$libPatterns = @(
    @{ name="jQuery";    regex='jquery[.-](\d+\.\d+\.\d+)';    cve="CVE-2020-11022"; safe="3.5.0"; level="HIGH" },
    @{ name="Bootstrap"; regex='bootstrap[.-](\d+\.\d+\.\d+)'; cve="CVE-2019-8331";  safe="4.3.1"; level="MEDIUM" },
    @{ name="lodash";    regex='lodash[.-](\d+\.\d+\.\d+)';    cve="CVE-2021-23337"; safe="4.17.21"; level="HIGH" },
    @{ name="Angular";   regex='angular[.-](\d+\.\d+\.\d+)';   cve="CVE-2019-14863"; safe="2.0.0"; level="HIGH" }
)
foreach ($lib in $libPatterns) {
    if ($html -match $lib.regex) {
        $ver = $Matches[1]
        $findings += @{ level=$lib.level; msg="$($lib.name) $ver detected - check $($lib.cve) (safe: v$($lib.safe)+)" }
    }
}

# 5. Exposed Sensitive Files
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
        if ([int]$sfResp.StatusCode -eq 200 -and $sfResp.Content.Length -gt 10) {
            $findings += @{ level="CRITICAL"; msg="$($sf.label) publicly accessible at $testUrl - may expose credentials" }
        }
    } catch { }
}

# 6. Mixed Content
if ($isHttps) {
    $mixedMatches = [regex]::Matches($html, '(?i)(src|href|url)\s*=\s*["'']?(http://[^\s"''<>]+)')
    if ($mixedMatches.Count -gt 0) {
        $findings += @{ level="MEDIUM"; msg="Mixed content - $($mixedMatches.Count) HTTP asset(s) on HTTPS page" }
    } else {
        $passed += "No mixed content detected"
    }
}

# 7. Report
$levels = @("CRITICAL","HIGH","MEDIUM","LOW")
$icons  = @{ CRITICAL="[CRITICAL]"; HIGH="[HIGH]"; MEDIUM="[MEDIUM]"; LOW="[LOW]" }

$hasFindings = $false
foreach ($lvl in $levels) {
    $group = $findings | Where-Object { $_.level -eq $lvl }
    if ($group.Count -gt 0) {
        $hasFindings = $true
        Write-Host "$($icons[$lvl]) ($($group.Count))"
        foreach ($f in $group) { Write-Host "  * $($f.msg)" }
        Write-Host ""
    }
}

if (-not $hasFindings) {
    Write-Host "No vulnerabilities found!"
    Write-Host ""
}

if ($passed.Count -gt 0) {
    Write-Host "PASSED:"
    foreach ($p in $passed) { Write-Host "  * $p" }
    Write-Host ""
}

Write-Host "-----------------------------------"
Write-Host "by cybersecurity experts | WebGuard v1.0"
