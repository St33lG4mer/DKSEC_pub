param(
    [string[]]$Commits = @(),
    [string]$ReportPath = "gitleaks-history-automated.json",
    [switch]$FailOnAnyCommitMatch
)

$ErrorActionPreference = "Stop"

function Resolve-GitleaksPath {
    $cmd = Get-Command gitleaks -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }

    $known = Join-Path $env:LOCALAPPDATA "Microsoft\WinGet\Packages\Gitleaks.Gitleaks_Microsoft.Winget.Source_8wekyb3d8bbwe\gitleaks.exe"
    if (Test-Path $known) { return $known }

    throw "Gitleaks not found. Install with: winget install --id Gitleaks.Gitleaks -e"
}

function Normalize-CommitHashes {
    param([string[]]$InputCommits)

    $normalized = @()
    foreach ($item in $InputCommits) {
        if ([string]::IsNullOrWhiteSpace($item)) { continue }
        foreach ($part in ($item -split ',')) {
            $h = $part.Trim()
            if (-not [string]::IsNullOrWhiteSpace($h)) { $normalized += $h }
        }
    }
    return $normalized | Select-Object -Unique
}

function Run-Gitleaks {
    param([string]$Exe, [string]$OutputPath)

    Write-Host "[1/3] Running full history scan with Gitleaks..."
    & $Exe detect --source . --redact --log-opts="--all" --config .gitleaks.toml --report-format json --report-path $OutputPath
    $code = $LASTEXITCODE
    if ($code -ne 0 -and $code -ne 1) {
        throw "Gitleaks failed with exit code $code"
    }

    if (-not (Test-Path $OutputPath)) { return 0 }
    $raw = Get-Content $OutputPath -Raw
    if ([string]::IsNullOrWhiteSpace($raw)) { return 0 }

    $json = $raw | ConvertFrom-Json
    if ($json -is [array]) { return $json.Count }
    if ($null -ne $json.findings) { return $json.findings.Count }
    return 1
}

function Inspect-Commits {
    param([string[]]$Hashes)

    if (-not $Hashes -or $Hashes.Count -eq 0) { return @() }

    $pattern = '(?i)password|passwd|secret|api[_-]?key|token|authorization|bearer|private key|aws_secret_access_key|aws_access_key_id|th_es_pass|th_opnsense_pass|th_es_user|th_opnsense_user|ssh\s+root@|os\.environ\.get\("TH_ES_USER"|os\.environ\.get\("TH_OPNSENSE_USER"'
    $results = @()

    foreach ($hash in $Hashes) {
        git cat-file -e "$hash^{commit}" 2>$null
        if ($LASTEXITCODE -ne 0) {
            $results += [PSCustomObject]@{ Commit=$hash; Reachable=$false; File=""; Change=""; Confidence="n/a"; Line="Commit not found" }
            continue
        }

        $refs = git for-each-ref --contains $hash --format="%(refname)" refs/heads refs/remotes refs/tags 2>$null
        $reachable = $LASTEXITCODE -eq 0 -and $refs -and $refs.Count -gt 0

        $currentFile = ""
        $lines = git show --no-color --pretty=format:"" $hash
        foreach ($line in $lines) {
            if ($line -match '^diff --git a/(.+?) b/(.+)$') {
                $currentFile = $Matches[2]
                continue
            }
            if ($line -match '^[+-]' -and $line -notmatch '^(\+\+\+|---)' -and $line -match $pattern) {
                $chg = $line.Substring(0,1)
                $high = $line -match '(?i)(th_es_pass|th_opnsense_pass|aws_secret_access_key|os\.environ\.get\([^,]+,\s*"[^"]{2,}"\)|ssh\s+root@)'
                $conf = if ($chg -eq '+' -and $high) { 'high' } elseif ($chg -eq '-' -and $high) { 'low' } else { 'medium' }
                $results += [PSCustomObject]@{ Commit=$hash; Reachable=$reachable; File=$currentFile; Change=$chg; Confidence=$conf; Line=$line.Trim() }
            }
        }
    }

    return $results
}

$gitleaks = Resolve-GitleaksPath
$commitList = Normalize-CommitHashes -InputCommits $Commits

Write-Host "Using Gitleaks: $gitleaks"
$gitleaksCount = Run-Gitleaks -Exe $gitleaks -OutputPath $ReportPath
Write-Host "Gitleaks findings in history: $gitleaksCount"
Write-Host "Report file: $ReportPath"

Write-Host "[2/3] Optional commit inspection..."
$results = Inspect-Commits -Hashes $commitList
if ($results.Count -eq 0) {
    Write-Host "No commit hashes provided (or no regex matches in provided commits)."
} else {
    $results | Format-Table Commit,Reachable,File,Change,Confidence,Line -AutoSize
}

$reachableHighAdds = @($results | Where-Object { $_.Reachable -eq $true -and $_.Change -eq '+' -and $_.Confidence -eq 'high' })
$unreachableMatches = @($results | Where-Object { $_.Reachable -eq $false })

if ($results.Count -gt 0) {
    Write-Host "Commit matches: $($results.Count)"
    Write-Host "Reachable high-confidence additions: $($reachableHighAdds.Count)"
    Write-Host "Unreachable commit matches: $($unreachableMatches.Count)"
}

Write-Host "[3/3] Done."
if ($gitleaksCount -gt 0 -or $reachableHighAdds.Count -gt 0 -or ($FailOnAnyCommitMatch -and $results.Count -gt 0)) {
    exit 1
}
exit 0
