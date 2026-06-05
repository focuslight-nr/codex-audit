$ErrorActionPreference = "Stop"

$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$script = Join-Path $root "codex_audit.ps1"
$fixture = Join-Path $root "tests\fixtures\basic\.codex"
$tmp = Join-Path $env:TEMP ("codex-audit-tests-" + [guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $tmp | Out-Null

try {
    $summary = (& powershell -NoProfile -ExecutionPolicy Bypass -File $script --codex-dir $fixture --summary) -join [Environment]::NewLine
    if ($summary -notmatch "WARN=") { throw "summary output did not include WARN count" }

    $auditPath = Join-Path $tmp "audit.json"
    & powershell -NoProfile -ExecutionPolicy Bypass -File $script --codex-dir $fixture --json --output $auditPath
    $audit = Get-Content -LiteralPath $auditPath -Raw | ConvertFrom-Json

    if ($audit.summary.warn -lt 1 -or $audit.summary.review -lt 1) { throw "expected WARN and REVIEW findings" }
    if (-not ($audit.mcp_servers | Where-Object { $_.name -eq "local_shell" })) { throw "missing local_shell MCP server" }
    if (-not ($audit.plugin_cache | Where-Object { $_.provenance -eq "local-or-third-party" })) { throw "missing plugin provenance finding" }
    if (-not ($audit.plugin_cache | Where-Object { $_.signature_artifacts -eq "custom-plugin.sig" })) { throw "missing signature artifact" }
    if (-not ($audit.findings | Where-Object { $_.message -like "*Signature-related artifact*" })) { throw "missing signature finding" }
    if (-not ($audit.automations | Where-Object { $_.id -eq "daily" -and $_.risk_tags -like "*external-data*" })) { throw "missing automation risk tag" }
    if (-not ($audit.retention | Where-Object { $_.name -eq "sessions" -and $_.file_count -eq "1" })) { throw "missing retention count" }

    $redactedPath = Join-Path $tmp "redacted.json"
    & powershell -NoProfile -ExecutionPolicy Bypass -File $script --codex-dir $fixture --json --redact-paths --output $redactedPath
    Get-Content -LiteralPath $redactedPath -Raw | ConvertFrom-Json | Out-Null

    $baselinePath = Join-Path $tmp "baseline.json"
    & powershell -NoProfile -ExecutionPolicy Bypass -File $script --codex-dir $fixture --json --output $baselinePath
    $diffJson = & powershell -NoProfile -ExecutionPolicy Bypass -File $script --codex-dir $fixture --diff $baselinePath --diff-json
    $diff = $diffJson | ConvertFrom-Json
    if ($diff.has_changes) { throw "expected no baseline differences" }

    & powershell -NoProfile -ExecutionPolicy Bypass -File $script --codex-dir $fixture --fail-on warn --json --output (Join-Path $tmp "fail.json")
    if ($LASTEXITCODE -ne 2) { throw "expected --fail-on warn to exit 2" }

    $htmlPath = Join-Path $tmp "report.html"
    & powershell -NoProfile -ExecutionPolicy Bypass -File $script --codex-dir $fixture --html --output $htmlPath | Out-Null
    if (-not (Test-Path -LiteralPath $htmlPath) -or (Get-Item -LiteralPath $htmlPath).Length -le 0) { throw "HTML report was not written" }

    Write-Output "All PowerShell tests passed."
} finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
