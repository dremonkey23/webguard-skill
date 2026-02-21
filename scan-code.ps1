param(
    [Parameter(Mandatory=$true)]
    [string]$Path
)

if (-not (Test-Path $Path)) {
    Write-Error "Path not found: $Path"
    exit 1
}

$findings_critical = [System.Collections.Generic.List[string]]::new()
$findings_high     = [System.Collections.Generic.List[string]]::new()
$findings_medium   = [System.Collections.Generic.List[string]]::new()
$findings_low      = [System.Collections.Generic.List[string]]::new()
$passed            = [System.Collections.Generic.List[string]]::new()

Write-Host ""
Write-Host "WebGuard Code Report -- $Path"
Write-Host "-----------------------------------"
Write-Host ""

# 1. Collect files
$extensions = @("*.js","*.ts","*.py","*.php","*.rb","*.cs","*.java","*.go","*.rs")
$allFiles = @()
foreach ($ext in $extensions) {
    $allFiles += Get-ChildItem -Path $Path -Recurse -Filter $ext -ErrorAction SilentlyContinue
}
Write-Host "Scanning $($allFiles.Count) source files..."
Write-Host ""

# 2. Secret patterns
$secretPatterns = @(
    @{ name="OpenAI API Key";    regex='sk-[A-Za-z0-9]{32,}';        level="CRITICAL" },
    @{ name="AWS Access Key";    regex='AKIA[0-9A-Z]{16}';            level="CRITICAL" },
    @{ name="GitHub Token";      regex='ghp_[A-Za-z0-9]{36}';        level="CRITICAL" },
    @{ name="Stripe Secret Key"; regex='sk_live_[A-Za-z0-9]{24,}';   level="CRITICAL" },
    @{ name="Generic API Key";   regex='api[_-]?key\s*[=:]\s*["\x27][A-Za-z0-9\-_]{16,}'; level="HIGH" },
    @{ name="Hardcoded Password";regex='password\s*[=:]\s*["\x27][^"\x27\s]{6,}'; level="HIGH" },
    @{ name="Bearer Token";      regex='Bearer\s+[A-Za-z0-9\-._~+/]+=*'; level="HIGH" },
    @{ name="Private Key Block"; regex='-----BEGIN.*PRIVATE KEY-----'; level="CRITICAL" }
)

# 3. Dangerous function patterns
$dangerPatterns = @(
    @{ name="eval()";                  regex='\beval\s*\(';             level="HIGH" },
    @{ name="innerHTML assignment";    regex='innerHTML\s*=';           level="MEDIUM" },
    @{ name="dangerouslySetInnerHTML"; regex='dangerouslySetInnerHTML'; level="MEDIUM" },
    @{ name="exec() shell call";       regex='\bexec\s*\(';             level="HIGH" },
    @{ name="system() call";           regex='\bsystem\s*\(';           level="HIGH" },
    @{ name="document.write()";        regex='document\.write\s*\(';   level="MEDIUM" },
    @{ name="setTimeout(string)";      regex='setTimeout\s*\(\s*["\x27]'; level="LOW" }
)

# 4. SQL injection patterns
$sqlPatterns = @(
    @{ name="String concat in query"; regex='(query|sql|execute)\s*\+\s*["\x27\$]'; level="HIGH" },
    @{ name="Format string in SQL";   regex='(query|sql)\s*%\s*\(';                 level="HIGH" },
    @{ name="Raw SQL f-string";       regex='f["\x27]SELECT.*WHERE.*\{';            level="HIGH" }
)

$secretFound = $false
$dangerFound = $false
$sqlFound    = $false

foreach ($file in $allFiles) {
    $relPath = $file.FullName.Replace($Path, "").TrimStart("\\/")
    try {
        $content = Get-Content $file.FullName -ErrorAction Stop

        $lineNum = 0
        foreach ($line in $content) {
            $lineNum++

            # Secrets
            foreach ($pat in $secretPatterns) {
                if ($line -match $pat.regex) {
                    $secretFound = $true
                    if ($pat.level -eq "CRITICAL") {
                        $findings_critical.Add("$($pat.name) in $relPath (line $lineNum)")
                    } else {
                        $findings_high.Add("$($pat.name) in $relPath (line $lineNum)")
                    }
                }
            }

            # Dangerous functions
            foreach ($pat in $dangerPatterns) {
                if ($line -match $pat.regex) {
                    $dangerFound = $true
                    if ($pat.level -eq "HIGH") {
                        $findings_high.Add("$($pat.name) in $relPath (line $lineNum)")
                    } elseif ($pat.level -eq "MEDIUM") {
                        $findings_medium.Add("$($pat.name) in $relPath (line $lineNum)")
                    } else {
                        $findings_low.Add("$($pat.name) in $relPath (line $lineNum)")
                    }
                }
            }

            # SQL injection
            foreach ($pat in $sqlPatterns) {
                if ($line -match $pat.regex) {
                    $sqlFound = $true
                    $findings_high.Add("$($pat.name) in $relPath (line $lineNum) - possible SQL injection")
                }
            }
        }
    } catch { }
}

if (-not $secretFound) { $passed.Add("No hardcoded secrets detected") }
if (-not $dangerFound) { $passed.Add("No dangerous functions detected") }
if (-not $sqlFound)    { $passed.Add("No SQL injection patterns detected") }

# 5. Dependency audit
$pkgJson = Join-Path $Path "package.json"
$reqTxt  = Join-Path $Path "requirements.txt"

if (Test-Path $pkgJson) {
    Write-Host "Running npm audit..."
    $npmOut = npm audit --json 2>$null | ConvertFrom-Json -ErrorAction SilentlyContinue
    if ($npmOut -and $npmOut.metadata) {
        $vulns = $npmOut.metadata.vulnerabilities
        $total = $vulns.critical + $vulns.high + $vulns.moderate + $vulns.low
        if ($total -gt 0) {
            if ($vulns.critical -gt 0) {
                $findings_critical.Add("npm audit: $($vulns.critical) CRITICAL vulnerabilities - run 'npm audit fix'")
            }
            if ($vulns.high -gt 0) {
                $findings_high.Add("npm audit: $($vulns.high) HIGH vulnerabilities")
            }
        } else {
            $passed.Add("npm audit: no vulnerabilities found")
        }
    }
}

if (Test-Path $reqTxt) {
    if (Get-Command pip -ErrorAction SilentlyContinue) {
        Write-Host "Running pip audit..."
        $pipOut = pip audit 2>&1
        if ($pipOut -match "No known vulnerabilities") {
            $passed.Add("pip audit: no vulnerabilities found")
        } else {
            $findings_medium.Add("pip audit found issues - run 'pip audit' for details")
        }
    }
}

# 6. Report
Write-Host "[CRITICAL] ($($findings_critical.Count))"
foreach ($f in $findings_critical) { Write-Host "  * $f" }
if ($findings_critical.Count -gt 0) { Write-Host "" }

Write-Host "[HIGH] ($($findings_high.Count))"
foreach ($f in $findings_high) { Write-Host "  * $f" }
if ($findings_high.Count -gt 0) { Write-Host "" }

Write-Host "[MEDIUM] ($($findings_medium.Count))"
foreach ($f in $findings_medium) { Write-Host "  * $f" }
if ($findings_medium.Count -gt 0) { Write-Host "" }

Write-Host "[LOW] ($($findings_low.Count))"
foreach ($f in $findings_low) { Write-Host "  * $f" }
if ($findings_low.Count -gt 0) { Write-Host "" }

if ($passed.Count -gt 0) {
    Write-Host "PASSED:"
    foreach ($p in $passed) { Write-Host "  * $p" }
    Write-Host ""
}

Write-Host "-----------------------------------"
Write-Host "by cybersecurity experts | WebGuard v1.0"
