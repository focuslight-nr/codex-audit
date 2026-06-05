# CODEX-AUDIT - Codex local security audit tool (Windows/PowerShell)
# Read-only audit for ~/.codex configuration, plugins, skills, MCP servers, and automations.
# Unofficial project. Not affiliated with, endorsed by, sponsored by, or maintained by OpenAI.

$Script:Version = "0.7.0"
$Script:CodexDirName = ".codex"
$Script:DangerousMcpHints = @("bash", "sh", "zsh", "python", "python3", "node", "ruby", "perl", "osascript", "sqlite3", "psql", "mysql", "curl", "wget", "nc", "ncat", "ssh", "scp", "powershell", "pwsh", "cmd")
$Script:SensitiveNamePattern = "(token|secret|password|passwd|api[_-]?key|credential|auth|session|cookie)"

$Script:OptJson = $false
$Script:OptQuiet = $false
$Script:OptHtml = ""
$Script:OptAllUsers = $false
$Script:OptRedactPaths = $false
$Script:OptDiff = ""
$Script:OptDiffJson = $false
$Script:OptFailOn = ""
$Script:OptOutput = ""
$Script:OptSummary = $false
$Script:OptCodexDir = ""
$Script:AuditUser = ""
$Script:FinalExit = 0

function Show-Usage {
    Write-Output "CODEX-AUDIT v$Script:Version - Codex local security audit"
    Write-Output "Usage: .\codex_audit.ps1 [--html [FILE]] [--json] [--summary] [--output FILE] [--diff BASELINE.json] [--diff-json] [--fail-on warn|review] [--redact-paths] [--user USER] [--all-users] [--codex-dir DIR] [-q|--quiet] [--version] [-h|--help]"
}

function Read-Args {
    for ($i = 0; $i -lt $args.Count; $i++) {
        switch ($args[$i]) {
            "--json" { $Script:OptJson = $true }
            "--diff" { $i++; $Script:OptDiff = $args[$i] }
            "--diff-json" { $Script:OptDiffJson = $true }
            "--fail-on" { $i++; $Script:OptFailOn = $args[$i] }
            "--output" { $i++; $Script:OptOutput = $args[$i] }
            "--summary" { $Script:OptSummary = $true }
            "--codex-dir" { $i++; $Script:OptCodexDir = $args[$i] }
            "--redact-paths" { $Script:OptRedactPaths = $true }
            "--html" {
                if (($i + 1) -lt $args.Count -and -not $args[$i + 1].StartsWith("-")) {
                    $i++
                    $Script:OptHtml = $args[$i]
                } else {
                    $Script:OptHtml = "AUTO"
                }
            }
            { $_ -eq "-q" -or $_ -eq "--quiet" } { $Script:OptQuiet = $true }
            "--user" { $i++; $Script:AuditUser = $args[$i] }
            "--all-users" { $Script:OptAllUsers = $true }
            "--version" { Write-Output "CODEX-AUDIT v$Script:Version"; exit 0 }
            { $_ -eq "-h" -or $_ -eq "--help" } { Show-Usage; exit 0 }
            default {
                Write-Error "Unknown option: $($args[$i])"
                Show-Usage
                exit 1
            }
        }
    }
}

function Assert-Options {
    if ($Script:OptDiff -and $Script:OptHtml) { throw "--diff and --html are mutually exclusive" }
    if ($Script:OptDiff -and $Script:OptJson -and -not $Script:OptDiffJson) { throw "--diff and --json are mutually exclusive; use --diff-json for JSON diff output" }
    if ($Script:OptDiffJson -and -not $Script:OptDiff) { throw "--diff-json requires --diff BASELINE.json" }
    if ($Script:OptJson -and $Script:OptHtml) { throw "--json and --html are mutually exclusive" }
    if ($Script:OptAllUsers -and $Script:AuditUser) { throw "--user and --all-users are mutually exclusive" }
    if ($Script:OptCodexDir -and $Script:OptAllUsers) { throw "--codex-dir and --all-users are mutually exclusive" }
    if ($Script:OptCodexDir -and -not (Test-Path -LiteralPath $Script:OptCodexDir -PathType Container)) { throw "--codex-dir does not exist: $Script:OptCodexDir" }
    if (-not $Script:OptHtml -and $Script:OptOutput -like "*.html") { throw "--output .html requires --html" }
    if ($Script:OptFailOn -and $Script:OptFailOn -notin @("warn", "review")) { throw "--fail-on must be 'warn' or 'review'" }
}

function Reset-State {
    $Script:Findings = New-Object System.Collections.Generic.List[object]
    $Script:McpNames = New-Object System.Collections.Generic.List[string]
    $Script:McpCmds = @{}
    $Script:McpArgs = @{}
    $Script:McpEnvKeys = @{}
    $Script:Plugins = New-Object System.Collections.Generic.List[object]
    $Script:PluginDetails = New-Object System.Collections.Generic.List[object]
    $Script:Marketplaces = New-Object System.Collections.Generic.List[object]
    $Script:Apps = New-Object System.Collections.Generic.List[object]
    $Script:TrustedProjects = New-Object System.Collections.Generic.List[object]
    $Script:Skills = New-Object System.Collections.Generic.List[object]
    $Script:Automations = New-Object System.Collections.Generic.List[object]
    $Script:RuntimeItems = New-Object System.Collections.Generic.List[object]
    $Script:SensitiveFiles = New-Object System.Collections.Generic.List[object]
    $Script:RetentionItems = New-Object System.Collections.Generic.List[object]
    $Script:WarnCount = 0
    $Script:InfoCount = 0
    $Script:ReviewCount = 0
}

function Add-Finding([string]$Severity, [string]$Section, [string]$Message, [string]$Detail = "") {
    $Script:Findings.Add([pscustomobject]@{ severity = $Severity; section = $Section; message = $Message; detail = $Detail }) | Out-Null
    switch ($Severity) {
        "WARN" { $Script:WarnCount++ }
        "REVIEW" { $Script:ReviewCount++ }
        default { $Script:InfoCount++ }
    }
}

function Strip-Quotes([string]$Value) {
    if ($null -eq $Value) { return "" }
    $s = $Value.Trim()
    if ($s.StartsWith('"')) { $s = $s.Substring(1) }
    if ($s.EndsWith('"')) { $s = $s.Substring(0, $s.Length - 1) }
    return $s
}

function Redact-Value([string]$Key, [string]$Value) {
    if ($Key.ToLowerInvariant() -match $Script:SensitiveNamePattern -or $Value.ToLowerInvariant() -match "(sk-|bearer |token=|secret=|password=|api[_-]?key=)") {
        return "[REDACTED]"
    }
    return $Value
}

function Display-Text([string]$Value) {
    $s = [string]$Value
    if ($Script:OptRedactPaths) {
        if ($Script:HomeDir) { $s = $s.Replace($Script:HomeDir, "~") }
        if ($Script:AuditUser) {
            $s = $s.Replace("\Users\$Script:AuditUser", "\Users\[USER]")
            $s = $s.Replace("/Users/$Script:AuditUser", "/Users/[USER]")
        }
    }
    return $s
}

function Html-Escape([string]$Value) {
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Format-Bytes([long]$Bytes) {
    if ($Bytes -lt 1KB) { return "$Bytes B" }
    if ($Bytes -lt 1MB) { return "{0:N1} KB" -f ($Bytes / 1KB) }
    if ($Bytes -lt 1GB) { return "{0:N1} MB" -f ($Bytes / 1MB) }
    return "{0:N1} GB" -f ($Bytes / 1GB)
}

function Get-FileMode([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return "" }
    try {
        $acl = Get-Acl -LiteralPath $Path
        $owner = $acl.Owner
        $broad = $acl.Access | Where-Object {
            $_.IdentityReference -match "Everyone|Users|Authenticated Users" -and
            $_.FileSystemRights.ToString() -match "Read|FullControl|Modify" -and
            $_.AccessControlType -eq "Allow"
        }
        if ($broad) { return "windows-acl-broad" }
        return "windows-acl-owner=$owner"
    } catch {
        return "windows-acl-unknown"
    }
}

function Get-DirFileCount([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return 0 }
    return @((Get-ChildItem -LiteralPath $Path -Recurse -File -Force -ErrorAction SilentlyContinue)).Count
}

function Get-DirTotalBytes([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return 0 }
    $sum = 0L
    Get-ChildItem -LiteralPath $Path -Recurse -File -Force -ErrorAction SilentlyContinue | ForEach-Object { $sum += $_.Length }
    return $sum
}

function Get-DirLatestMtime([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return "" }
    $latest = Get-ChildItem -LiteralPath $Path -Recurse -File -Force -ErrorAction SilentlyContinue | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
    if ($latest) { return $latest.LastWriteTimeUtc.ToString("yyyy-MM-ddTHH:mm:ssZ") }
    return ""
}

function Get-AutomationRiskTags([string]$Prompt) {
    $tags = New-Object System.Collections.Generic.List[string]
    $lower = $Prompt.ToLowerInvariant()
    if ($lower -match "google drive|spreadsheet|document") { $tags.Add("external-data") }
    if ($lower -match "send|upload|post |write|append") { $tags.Add("writes-or-sends") }
    if ($lower -match "delete|remove") { $tags.Add("delete") }
    if ($lower -match "download|browser|web|public") { $tags.Add("web-or-download") }
    if ($lower -match "shell|command|commit|push") { $tags.Add("code-or-shell") }
    return ($tags -join ",")
}

function Get-McpEnvRiskTags([string]$Keys) {
    $tags = New-Object System.Collections.Generic.List[string]
    $lower = $Keys.ToLowerInvariant()
    if ($lower -match "(token|secret|password|passwd|api[_-]?key|credential|auth|cookie)") { $tags.Add("secret-like-env") }
    if ($lower -match "trusted|allowlist") { $tags.Add("trust-or-allowlist") }
    if ($lower -match "path|dirs|home") { $tags.Add("filesystem-scope") }
    if ($lower -match "browser|backend") { $tags.Add("browser-scope") }
    return ($tags -join ",")
}

function Get-PluginProvenance([string]$Marketplace, [string]$Publisher) {
    switch ($Marketplace) {
        "openai-bundled" { return "openai-bundled" }
        "openai-curated" { return "openai-curated" }
        "openai-primary-runtime" { return "openai-runtime" }
        default {
            if ($Publisher.ToLowerInvariant() -like "*openai*") { return "openai-other" }
            if (-not $Marketplace -or $Marketplace -eq "unknown") { return "unknown" }
            return "local-or-third-party"
        }
    }
}

function Get-SignatureArtifacts([string]$PluginDir) {
    $exts = @(".sig", ".signature", ".pem", ".crt", ".cer", ".pub", ".asc", ".minisig", ".cosign")
    $prefix = $PluginDir.TrimEnd("\", "/") + [System.IO.Path]::DirectorySeparatorChar
    $items = Get-ChildItem -LiteralPath $PluginDir -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object { ($_.PSIsContainer -and $_.Name -eq ".sigstore") -or (-not $_.PSIsContainer -and $exts -contains $_.Extension) } |
        ForEach-Object {
            if ($_.FullName.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                $_.FullName.Substring($prefix.Length)
            } else {
                $_.Name
            }
        }
    return (@($items) -join ",")
}

function Get-UserHome([string]$UserName) {
    if (-not $UserName -or $UserName -eq $env:USERNAME) { return $HOME }
    $candidate = Join-Path (Split-Path $HOME -Parent) $UserName
    if (Test-Path -LiteralPath $candidate -PathType Container) { return $candidate }
    return ""
}

function Get-CodexUsers {
    $root = Split-Path $HOME -Parent
    if (-not (Test-Path -LiteralPath $root -PathType Container)) { return @() }
    Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction SilentlyContinue |
        Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName $Script:CodexDirName) -PathType Container } |
        ForEach-Object { $_.Name }
}

function Parse-SkillFrontmatter([string]$Path) {
    $fallback = Split-Path (Split-Path $Path -Parent) -Leaf
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return [pscustomobject]@{ name = $fallback; description = "" } }
    $lines = Get-Content -LiteralPath $Path -TotalCount 80 -ErrorAction SilentlyContinue
    if (-not $lines -or $lines[0] -notlike "---*") { return [pscustomobject]@{ name = $fallback; description = "" } }
    $name = ""
    $desc = ""
    $inDesc = $false
    foreach ($line in $lines) {
        if ($line -eq "---" -and ($name -or $desc) ) { break }
        if ($line -like "name:*") {
            $name = Strip-Quotes ($line.Substring(5))
            $inDesc = $false
        } elseif ($line -like "description:*") {
            $desc = Strip-Quotes ($line.Substring(12))
            if ($desc -in @(">", "|")) { $desc = "" }
            $inDesc = $true
        } elseif ($inDesc -and $line.StartsWith("  ")) {
            $desc = (($desc, $line.Substring(2)) | Where-Object { $_ }) -join " "
        } elseif ($line -ne "---") {
            $inDesc = $false
        }
    }
    if (-not $name) { $name = $fallback }
    return [pscustomobject]@{ name = $name; description = $desc }
}

function Collect-Config {
    $cfg = Join-Path $Script:CodexDir "config.toml"
    if (-not (Test-Path -LiteralPath $cfg -PathType Leaf)) {
        Add-Finding "INFO" "Config" "config.toml not found" $cfg
        return
    }

    $mode = Get-FileMode $cfg
    $Script:SensitiveFiles.Add([pscustomobject]@{ name = "config.toml"; mode = $mode; path = $cfg }) | Out-Null
    if ($mode -eq "windows-acl-broad" -or $mode -eq "windows-acl-unknown") {
        Add-Finding "REVIEW" "Config" "config.toml ACL should be reviewed" "mode=$mode"
    }

    $section = ""; $mcp = ""; $plugin = ""; $project = ""; $marketplace = ""; $app = ""
    $unknownSections = New-Object System.Collections.Generic.List[string]
    foreach ($rawLine in Get-Content -LiteralPath $cfg -ErrorAction SilentlyContinue) {
        $raw = ($rawLine -replace "#.*$", "").Trim()
        if (-not $raw) { continue }

        if ($raw -match "^\[(.+)\]$") {
            $section = $Matches[1]
            $mcp = ""; $plugin = ""; $project = ""; $marketplace = ""; $app = ""
            if ($section -match '^mcp_servers\.([^.]*)$') {
                $mcp = $Matches[1].Trim('"')
                $Script:McpNames.Add($mcp) | Out-Null
            } elseif ($section -match '^mcp_servers\.([^.]*)\.env$') {
                $mcp = $Matches[1].Trim('"')
            } elseif ($section -match '^plugins\."(.+)"$') {
                $plugin = $Matches[1]
            } elseif ($section -match '^projects\."(.+)"$') {
                $project = $Matches[1]
            } elseif ($section -match '^marketplaces\.([^.]*)$') {
                $marketplace = $Matches[1]
            } elseif ($section -match '^apps\.([^.]*)$') {
                $app = $Matches[1]
            } elseif ($section -notin @("features", "desktop") -and $section -notlike "marketplaces.*" -and $section -notlike "plugins.*" -and $section -notlike "projects.*" -and $section -notlike "mcp_servers.*" -and $section -notlike "apps.*") {
                $unknownSections.Add($section) | Out-Null
            }
            continue
        }

        if ($raw -notlike "*=*") { continue }
        $key = ($raw -split "=", 2)[0].Trim()
        $val = Strip-Quotes (($raw -split "=", 2)[1])

        if ($mcp) {
            if ($section -like "mcp_servers.*.env") {
                $existing = [string]$Script:McpEnvKeys[$mcp]
                $Script:McpEnvKeys[$mcp] = (($existing, $key) | Where-Object { $_ }) -join ", "
            } elseif ($key -eq "command") {
                $Script:McpCmds[$mcp] = Redact-Value $key $val
            } elseif ($key -eq "args") {
                $Script:McpArgs[$mcp] = Redact-Value $key $val
            }
        } elseif ($plugin -and $key -eq "enabled") {
            $Script:Plugins.Add([pscustomobject]@{ id = $plugin; enabled = $val }) | Out-Null
            if ($val -eq "true") { Add-Finding "REVIEW" "Plugins" "Enabled Codex plugin: $plugin" }
        } elseif ($project -and $key -eq "trust_level") {
            $Script:TrustedProjects.Add([pscustomobject]@{ path = $project; trust_level = $val }) | Out-Null
            if ($val -eq "trusted") { Add-Finding "WARN" "Projects" "Trusted project grants Codex broader workspace autonomy" $project }
        } elseif ($marketplace -and $key -eq "source") {
            $Script:Marketplaces.Add([pscustomobject]@{ name = $marketplace; source = (Redact-Value $key $val) }) | Out-Null
        } elseif ($app -and $key -eq "enabled") {
            $Script:Apps.Add([pscustomobject]@{ id = $app; enabled = $val }) | Out-Null
            if ($val -eq "true") { Add-Finding "REVIEW" "Connectors" "Enabled app connector: $app" }
        } elseif ($section -eq "desktop" -and $key -eq "keepRemoteControlAwakeWhilePluggedIn" -and $val -eq "true") {
            Add-Finding "WARN" "Desktop" "Remote control keep-awake is enabled" "keepRemoteControlAwakeWhilePluggedIn=true"
        } elseif ($section -eq "features") {
            Add-Finding "INFO" "Features" "$key=$val"
        } elseif ($key -eq "notify") {
            Add-Finding "INFO" "Config" "Notification hook configured" (Redact-Value $key $val)
        } elseif ($key -eq "model") {
            Add-Finding "INFO" "Config" "Default model: $val"
        }
    }

    if ($unknownSections.Count -gt 0) {
        Add-Finding "INFO" "Config" "Unknown config section(s) present" (($unknownSections | Sort-Object -Unique) -join ", ")
    }

    foreach ($name in $Script:McpNames) {
        $cmd = [string]$Script:McpCmds[$name]
        $envKeys = [string]$Script:McpEnvKeys[$name]
        Add-Finding "REVIEW" "MCP Servers" "MCP server configured: $name" "command=$($(if ($cmd) { $cmd } else { "unknown" })); env_keys=$($(if ($envKeys) { $envKeys } else { "none" }))"
        $envRisks = Get-McpEnvRiskTags $envKeys
        if ($envRisks) { Add-Finding "REVIEW" "MCP Servers" "MCP server env keys imply elevated scope: $name" $envRisks }
        $base = [System.IO.Path]::GetFileNameWithoutExtension($cmd)
        if ($base -in $Script:DangerousMcpHints) { Add-Finding "WARN" "MCP Servers" "MCP server uses command-capable runtime: $name" $cmd }
    }
}

function Collect-PluginCache {
    $cache = Join-Path $Script:CodexDir "plugins\cache"
    if (-not (Test-Path -LiteralPath $cache -PathType Container)) { return }
    Get-ChildItem -LiteralPath $cache -Recurse -Force -Filter "plugin.json" -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match "\\\.codex-plugin\\plugin\.json$" } |
        ForEach-Object {
            $manifest = $_.FullName
            $pluginDir = Split-Path (Split-Path $manifest -Parent) -Parent
            if ((Split-Path $pluginDir -Leaf) -eq "latest") { return }
            $name = Split-Path $pluginDir -Leaf
            $version = "unknown"
            $publisher = "unknown"
            try {
                $json = Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json
                if ($json.name) { $name = $json.name } elseif ($json.id) { $name = $json.id }
                if ($json.version) { $version = $json.version }
                if ($json.publisher) {
                    if ($json.publisher -is [string]) { $publisher = $json.publisher }
                    else { $publisher = (($json.publisher.name, $json.publisher.email, $json.publisher.url) | Where-Object { $_ } | Select-Object -First 1) }
                } elseif ($json.author) {
                    if ($json.author -is [string]) { $publisher = $json.author }
                    else { $publisher = (($json.author.name, $json.author.email, $json.author.url) | Where-Object { $_ } | Select-Object -First 1) }
                }
            } catch {}
            $marketplace = Split-Path (Split-Path (Split-Path $pluginDir -Parent) -Parent) -Leaf
            $provenance = Get-PluginProvenance $marketplace $publisher
            $sigArtifacts = Get-SignatureArtifacts $pluginDir
            $Script:PluginDetails.Add([pscustomobject]@{ name = $name; version = $version; publisher = $publisher; marketplace = $marketplace; path = $pluginDir; provenance = $provenance; signature_artifacts = $sigArtifacts }) | Out-Null
            if ($provenance -in @("unknown", "local-or-third-party")) { Add-Finding "REVIEW" "Plugins" "Plugin provenance requires review: $name" "$provenance; marketplace=$marketplace; publisher=$publisher" }
            if ($sigArtifacts) { Add-Finding "INFO" "Plugins" "Signature-related artifact(s) present for plugin: $name" $sigArtifacts }
            else { Add-Finding "INFO" "Plugins" "No signature-related artifacts found for plugin: $name" "existence check only; no signature verification performed" }
        }
    if ($Script:PluginDetails.Count -gt 0) { Add-Finding "INFO" "Plugins" "$($Script:PluginDetails.Count) cached plugin package(s) found" }
}

function Collect-Skills {
    foreach ($root in @((Join-Path $Script:CodexDir "skills"), (Join-Path $Script:CodexDir "plugins\cache"))) {
        if (-not (Test-Path -LiteralPath $root -PathType Container)) { continue }
        Get-ChildItem -LiteralPath $root -Recurse -Force -Filter "SKILL.md" -ErrorAction SilentlyContinue | ForEach-Object {
            $parsed = Parse-SkillFrontmatter $_.FullName
            $source = "user"
            if ($_.FullName -like "*\plugins\cache\*") {
                $beforeSkills = ($_.FullName -split "\\skills\\", 2)[0]
                $source = "plugin:$(Split-Path $beforeSkills -Leaf)"
            }
            $Script:Skills.Add([pscustomobject]@{ name = $parsed.name; source = $source; description = $parsed.description; path = $_.FullName }) | Out-Null
        }
    }
    if ($Script:Skills.Count -gt 0) { Add-Finding "INFO" "Skills" "$($Script:Skills.Count) Codex skill(s) found" }
}

function Collect-Automations {
    $root = Join-Path $Script:CodexDir "automations"
    if (-not (Test-Path -LiteralPath $root -PathType Container)) { return }
    Get-ChildItem -LiteralPath $root -Recurse -Force -Filter "automation.toml" -ErrorAction SilentlyContinue | ForEach-Object {
        $vals = @{}
        foreach ($rawLine in Get-Content -LiteralPath $_.FullName -ErrorAction SilentlyContinue) {
            $raw = ($rawLine -replace "#.*$", "").Trim()
            if ($raw -notlike "*=*") { continue }
            $key = ($raw -split "=", 2)[0].Trim()
            $vals[$key] = Strip-Quotes (($raw -split "=", 2)[1])
        }
        $id = if ($vals.id) { $vals.id } else { Split-Path (Split-Path $_.FullName -Parent) -Leaf }
        $name = if ($vals.name) { $vals.name } else { "unnamed" }
        $status = if ($vals.status) { $vals.status } else { "unknown" }
        $riskTags = Get-AutomationRiskTags ([string]$vals.prompt)
        $row = [pscustomobject]@{
            id = $id; name = $name; kind = if ($vals.kind) { $vals.kind } else { "unknown" }
            status = $status; rrule = if ($vals.rrule) { $vals.rrule } else { "none" }
            model = if ($vals.model) { $vals.model } else { "unknown" }
            execution_environment = if ($vals.execution_environment) { $vals.execution_environment } else { "unknown" }
            cwds = [string]$vals.cwds; risk_tags = $riskTags
        }
        $Script:Automations.Add($row) | Out-Null
        if ($status -eq "ACTIVE") {
            Add-Finding "WARN" "Automations" "Active automation: $name" "kind=$($row.kind); rrule=$($row.rrule); cwd=$($row.cwds)"
            if ($row.cwds.ToLowerInvariant() -match "documents|github") { Add-Finding "REVIEW" "Automations" "Active automation has access to a broad working directory" $row.cwds }
            if ($riskTags) { Add-Finding "REVIEW" "Automations" "Active automation prompt contains higher-risk actions: $name" $riskTags }
        } else {
            Add-Finding "INFO" "Automations" "Automation present: $name" "status=$status"
        }
    }
}

function Collect-SensitiveFiles {
    foreach ($name in @("auth.json", ".codex-global-state.json", "installation_id", "session_index.jsonl")) {
        $path = Join-Path $Script:CodexDir $name
        if (-not (Test-Path -LiteralPath $path)) { continue }
        $mode = Get-FileMode $path
        $Script:SensitiveFiles.Add([pscustomobject]@{ name = $name; mode = $mode; path = $path }) | Out-Null
        if ($name -eq "auth.json" -and ($mode -eq "windows-acl-broad" -or $mode -eq "windows-acl-unknown")) {
            Add-Finding "WARN" "Sensitive Files" "auth.json ACL should be reviewed" "mode=$mode"
        } else {
            Add-Finding "INFO" "Sensitive Files" "$name present" "mode=$mode"
        }
    }
    Get-ChildItem -LiteralPath $Script:CodexDir -File -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like "*.sqlite" -or $_.Name -like "*.sqlite-wal" } |
        ForEach-Object {
            Add-Finding "INFO" "Local Data" "$($_.Name) present" (Format-Bytes $_.Length)
            if ($_.Length -gt 100MB) { Add-Finding "REVIEW" "Local Data" "$($_.Name) is larger than 100 MB" (Format-Bytes $_.Length) }
        }
}

function Collect-Retention {
    foreach ($name in @("sessions", "archived_sessions", "shell_snapshots", "ambient-suggestions")) {
        $dir = Join-Path $Script:CodexDir $name
        if (-not (Test-Path -LiteralPath $dir -PathType Container)) { continue }
        $count = Get-DirFileCount $dir
        $bytes = Get-DirTotalBytes $dir
        $latest = Get-DirLatestMtime $dir
        $Script:RetentionItems.Add([pscustomobject]@{ name = $name; file_count = [string]$count; bytes = [string]$bytes; latest_mtime = $latest; path = $dir }) | Out-Null
        Add-Finding "INFO" "Retention" "$name contains $count file(s)" "size=$(Format-Bytes $bytes); latest=$($(if ($latest) { $latest } else { "none" }))"
        if ($bytes -gt 100MB) { Add-Finding "REVIEW" "Retention" "$name retained data is larger than 100 MB" (Format-Bytes $bytes) }
        if ($count -gt 1000) { Add-Finding "REVIEW" "Retention" "$name contains more than 1000 files" "$count files" }
    }
}

function Collect-Runtime {
    $procs = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -match "Codex|codex" })
    if ($procs.Count -gt 0) {
        $Script:RuntimeItems.Add([pscustomobject]@{ name = "processes"; value = [string]$procs.Count }) | Out-Null
        Add-Finding "INFO" "Runtime" "Codex-related process(es) running: $($procs.Count)"
    }
    try {
        $tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -match "Codex|codex" -or $_.TaskPath -match "Codex|codex" })
        foreach ($task in $tasks) { Add-Finding "WARN" "Runtime" "Codex-related scheduled task found" "$($task.TaskPath)$($task.TaskName)" }
    } catch {}
}

function Audit-OneUser([string]$UserName) {
    Reset-State
    $Script:AuditUser = $UserName
    $Script:HomeDir = Get-UserHome $Script:AuditUser
    if (-not $Script:HomeDir -or -not (Test-Path -LiteralPath $Script:HomeDir -PathType Container)) {
        Add-Finding "WARN" "General" "Unable to resolve home directory" $Script:AuditUser
        $Script:CodexDir = ""
        return
    }
    if ($Script:OptCodexDir) {
        $Script:CodexDir = (Resolve-Path -LiteralPath $Script:OptCodexDir).Path
        $Script:HomeDir = Split-Path $Script:CodexDir -Parent
    } else {
        $Script:CodexDir = Join-Path $Script:HomeDir $Script:CodexDirName
    }
    $Script:Timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $Script:HostnameVal = $env:COMPUTERNAME

    if (-not (Test-Path -LiteralPath $Script:CodexDir -PathType Container)) {
        Add-Finding "INFO" "General" "Codex directory not found" $Script:CodexDir
    } else {
        Collect-Config
        Collect-PluginCache
        Collect-Skills
        Collect-Automations
        Collect-SensitiveFiles
        Collect-Retention
        Collect-Runtime
    }
}

function Convert-ReportForOutput {
    $findings = @($Script:Findings | ForEach-Object { [pscustomobject]@{ severity = $_.severity; section = $_.section; message = (Display-Text ($_.message)); detail = (Display-Text ($_.detail)) } })
    $mcp = @($Script:McpNames | ForEach-Object {
        $envKeys = [string]$Script:McpEnvKeys[$_]
        [pscustomobject]@{ name = (Display-Text ($_)); command = (Display-Text ([string]$Script:McpCmds[$_])); args = (Display-Text ([string]$Script:McpArgs[$_])); env_keys = $envKeys; env_risk_tags = (Get-McpEnvRiskTags $envKeys) }
    })
    $pluginCache = @()
    foreach ($pd in $Script:PluginDetails) {
        $pluginCache += [pscustomobject]@{
            name = (Display-Text ([string]$pd.name))
            version = [string]$pd.version
            publisher = [string]$pd.publisher
            marketplace = [string]$pd.marketplace
            path = (Display-Text ([string]$pd.path))
            provenance = [string]$pd.provenance
            signature_artifacts = (Display-Text ([string]$pd.signature_artifacts))
        }
    }
    $plugins = @()
    foreach ($p in $Script:Plugins) {
        $plugins += [pscustomobject]@{ id = (Display-Text ([string]$p.id)); enabled = [string]$p.enabled }
    }
    $trustedProjects = @()
    foreach ($tp in $Script:TrustedProjects) {
        $trustedProjects += [pscustomobject]@{ path = (Display-Text ([string]$tp.path)); trust_level = [string]$tp.trust_level }
    }
    $skills = @()
    foreach ($skill in $Script:Skills) {
        $skills += [pscustomobject]@{ name = (Display-Text ([string]$skill.name)); source = (Display-Text ([string]$skill.source)); description = [string]$skill.description; path = (Display-Text ([string]$skill.path)) }
    }
    $automations = @()
    foreach ($auto in $Script:Automations) {
        $automations += [pscustomobject]@{ id = (Display-Text ([string]$auto.id)); name = (Display-Text ([string]$auto.name)); kind = [string]$auto.kind; status = [string]$auto.status; rrule = [string]$auto.rrule; model = [string]$auto.model; execution_environment = [string]$auto.execution_environment; cwds = (Display-Text ([string]$auto.cwds)); risk_tags = [string]$auto.risk_tags }
    }
    $marketplaces = @()
    foreach ($market in $Script:Marketplaces) {
        $marketplaces += [pscustomobject]@{ name = (Display-Text ([string]$market.name)); source = (Display-Text ([string]$market.source)) }
    }
    $apps = @()
    foreach ($app in $Script:Apps) {
        $apps += [pscustomobject]@{ id = (Display-Text ([string]$app.id)); enabled = [string]$app.enabled }
    }
    $sensitiveFiles = @()
    foreach ($sf in $Script:SensitiveFiles) {
        $sensitiveFiles += [pscustomobject]@{ name = [string]$sf.name; mode = [string]$sf.mode; path = (Display-Text ([string]$sf.path)) }
    }
    $retention = @()
    foreach ($ri in $Script:RetentionItems) {
        $retention += [pscustomobject]@{ name = [string]$ri.name; file_count = [string]$ri.file_count; bytes = [string]$ri.bytes; latest_mtime = [string]$ri.latest_mtime; path = (Display-Text ([string]$ri.path)) }
    }
    $report = [ordered]@{}
    $report["timestamp"] = $Script:Timestamp
    $report["hostname"] = $Script:HostnameVal
    $report["username"] = (Display-Text ($Script:AuditUser))
    $report["codex_dir"] = (Display-Text ($Script:CodexDir))
    $report["summary"] = [ordered]@{ warn = $Script:WarnCount; review = $Script:ReviewCount; info = $Script:InfoCount }
    $report["findings"] = $findings
    $report["mcp_servers"] = $mcp
    $report["plugins"] = $plugins
    $report["plugin_cache"] = $pluginCache
    $report["marketplaces"] = $marketplaces
    $report["apps"] = $apps
    $report["trusted_projects"] = $trustedProjects
    $report["skills"] = $skills
    $report["automations"] = $automations
    $report["sensitive_files"] = $sensitiveFiles
    $report["retention"] = $retention
    return $report
}

function Write-TerminalReport {
    Write-Output ""
    Write-Output "CODEX-AUDIT v$Script:Version - Codex local security audit"
    Write-Output "User: $(Display-Text $Script:AuditUser)"
    Write-Output "Codex home: $(Display-Text $Script:CodexDir)"
    Write-Output "Findings: WARN=$Script:WarnCount REVIEW=$Script:ReviewCount INFO=$Script:InfoCount"
    Write-Output ""
    if (-not $Script:OptQuiet -or $Script:WarnCount -gt 0 -or $Script:ReviewCount -gt 0) {
        Write-Output "Findings"
        foreach ($f in $Script:Findings) {
            if ($Script:OptQuiet -and $f.severity -eq "INFO") { continue }
            Write-Output ("  [{0}] {1,-16} {2}" -f $f.severity, $f.section, (Display-Text $f.message))
            if ($f.detail) { Write-Output "       $(Display-Text $f.detail)" }
        }
        Write-Output ""
    }
    Write-Output "MCP Servers"
    if ($Script:McpNames.Count -eq 0) { Write-Output "  none" }
    else { foreach ($name in $Script:McpNames) { Write-Output ("  {0,-18} {1}" -f $name, (Display-Text "cmd=$([string]$Script:McpCmds[$name]) env=$([string]$Script:McpEnvKeys[$name])")) } }
    Write-Output ""
    Write-ListSection "Plugins" (@($Script:Plugins | ForEach-Object { "$($_.id)|enabled=$($_.enabled)" }) + @($Script:PluginDetails | ForEach-Object { "$($_.name)|$($_.version)|$($_.publisher)|$($_.marketplace)|$($_.path)|$($_.provenance)|$($_.signature_artifacts)" }))
    Write-ListSection "Trusted Projects" @($Script:TrustedProjects | ForEach-Object { "$(Display-Text $_.path)|trust_level=$($_.trust_level)" })
    Write-ListSection "Automations" @($Script:Automations | ForEach-Object { "$($_.id)|$($_.name)|$($_.kind)|$($_.status)|$($_.rrule)|$($_.model)|$($_.execution_environment)|$(Display-Text $_.cwds)|$($_.risk_tags)" })
    Write-ListSection "Skills" @($Script:Skills | ForEach-Object { "$($_.name)|$($_.source)|$($_.description)|$(Display-Text $_.path)" })
    Write-ListSection "Retention" @($Script:RetentionItems | ForEach-Object { "$($_.name)|$($_.file_count)|$($_.bytes)|$($_.latest_mtime)|$(Display-Text $_.path)" })
}

function Write-ListSection([string]$Title, [object[]]$Rows) {
    Write-Output $Title
    if (-not $Rows -or $Rows.Count -eq 0) { Write-Output "  none" }
    else {
        foreach ($row in $Rows) {
            $parts = ([string]$row).Split("|", 2)
            $first = $parts[0]
            $rest = if ($parts.Count -gt 1) { $parts[1] } else { "" }
            Write-Output ("  {0,-18} {1}" -f $first, (Display-Text $rest))
        }
    }
    Write-Output ""
}

function Write-SummaryReport {
    Write-Output "$(Display-Text $Script:AuditUser)  WARN=$Script:WarnCount REVIEW=$Script:ReviewCount INFO=$Script:InfoCount  $(Display-Text $Script:CodexDir)"
    $shown = 0
    foreach ($f in $Script:Findings) {
        if ($f.severity -eq "INFO") { continue }
        Write-Output "  [$($f.severity)] $($f.section): $(Display-Text $f.message)"
        $shown++
        if ($shown -ge 8) { break }
    }
}

function Get-ReportsForUsers([string[]]$Users) {
    $reports = foreach ($user in $Users) {
        Audit-OneUser $user
        Convert-ReportForOutput
    }
    if ($reports.Count -eq 1) { return $reports[0] }
    return @($reports)
}

function Get-SummaryReportsForUsers([string[]]$Users) {
    $reports = foreach ($user in $Users) {
        Audit-OneUser $user
        [pscustomobject]@{
            timestamp = $Script:Timestamp
            hostname = $Script:HostnameVal
            username = (Display-Text ($Script:AuditUser))
            codex_dir = (Display-Text ($Script:CodexDir))
            summary = [pscustomobject]@{ warn = $Script:WarnCount; review = $Script:ReviewCount; info = $Script:InfoCount }
        }
    }
    if ($reports.Count -eq 1) { return $reports[0] }
    return @($reports)
}

function Get-KeySet($Doc, [string]$ArrayName, [string]$FieldName) {
    $items = @()
    foreach ($d in @($Doc)) {
        if ($d.$ArrayName) { $items += @($d.$ArrayName | ForEach-Object { $_.$FieldName } | Where-Object { $_ }) }
    }
    return @($items | Sort-Object -Unique)
}

function Get-SkillKeySet($Doc) {
    $items = @()
    foreach ($d in @($Doc)) {
        if ($d.skills) { $items += @($d.skills | ForEach-Object { "$($_.source):$($_.name)" }) }
    }
    return @($items | Sort-Object -Unique)
}

function Compare-KeySet([string]$Name, [object[]]$Old, [object[]]$New) {
    $added = @($New | Where-Object { $_ -notin $Old } | Sort-Object)
    $removed = @($Old | Where-Object { $_ -notin $New } | Sort-Object)
    return [pscustomobject]@{ section = $Name; added = $added; removed = $removed }
}

function Render-Diff([string]$Baseline, [string[]]$Users) {
    if (-not (Test-Path -LiteralPath $Baseline -PathType Leaf)) { throw "cannot read baseline: $Baseline" }
    $base = Get-Content -LiteralPath $Baseline -Raw | ConvertFrom-Json
    $current = Get-ReportsForUsers $Users
    $sections = @(
        Compare-KeySet "mcp_servers" (Get-KeySet $base "mcp_servers" "name") (Get-KeySet $current "mcp_servers" "name")
        Compare-KeySet "plugins" (Get-KeySet $base "plugins" "id") (Get-KeySet $current "plugins" "id")
        Compare-KeySet "apps" (Get-KeySet $base "apps" "id") (Get-KeySet $current "apps" "id")
        Compare-KeySet "trusted_projects" (Get-KeySet $base "trusted_projects" "path") (Get-KeySet $current "trusted_projects" "path")
        Compare-KeySet "automations" (Get-KeySet $base "automations" "id") (Get-KeySet $current "automations" "id")
        Compare-KeySet "skills" (Get-SkillKeySet $base) (Get-SkillKeySet $current)
    )
    $changed = @($sections | Where-Object { $_.added.Count -gt 0 -or $_.removed.Count -gt 0 })
    $diff = [pscustomobject]@{ changed = $changed; has_changes = ($changed.Count -gt 0) }
    if ($Script:OptDiffJson) { return ($diff | ConvertTo-Json -Depth 8) }
    if (-not $diff.has_changes) { return "No baseline differences detected." }
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($section in $changed) {
        $lines.Add("## $($section.section)") | Out-Null
        if ($section.added.Count -gt 0) {
            $lines.Add("Added:") | Out-Null
            $section.added | ForEach-Object { $lines.Add("  + $_") | Out-Null }
        }
        if ($section.removed.Count -gt 0) {
            $lines.Add("Removed:") | Out-Null
            $section.removed | ForEach-Object { $lines.Add("  - $_") | Out-Null }
        }
    }
    return ($lines -join [Environment]::NewLine)
}

function Render-Html([string[]]$Users) {
    $parts = New-Object System.Collections.Generic.List[string]
    $parts.Add('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>CODEX-AUDIT Report</title><style>body{margin:0;background:#101317;color:#e7edf3;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}main{max-width:1180px;margin:0 auto;padding:32px 20px}h1{margin:0 0 8px;font-size:28px}h2{margin:28px 0 10px;font-size:18px}.report{border-top:1px solid #2a3340;padding:24px 0}.meta{color:#aab6c4;margin:4px 0}code{color:#d7e7ff;white-space:pre-wrap;word-break:break-word}.summary{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;margin:20px 0}.summary div{background:#171d24;border:1px solid #2a3340;border-radius:6px;padding:12px}.summary span{display:block;color:#aab6c4;font-size:12px}.summary strong{font-size:24px}table{width:100%;border-collapse:collapse;background:#141920;border:1px solid #2a3340}th,td{padding:9px 10px;border-bottom:1px solid #2a3340;text-align:left;vertical-align:top;font-size:13px}th{color:#aab6c4;background:#171d24}.badge{display:inline-block;border-radius:4px;padding:2px 6px;font-weight:700;font-size:12px}.warn{background:#5c2e12;color:#ffd7b0}.review{background:#51450f;color:#fff0a3}.info{background:#173956;color:#bfe4ff}</style></head><body><main>') | Out-Null
    foreach ($user in $Users) {
        Audit-OneUser $user
        $parts.Add('<section class="report">') | Out-Null
        $parts.Add("<h1>CODEX-AUDIT</h1><p class=`"meta`">User: <strong>$(Html-Escape (Display-Text $Script:AuditUser))</strong> &middot; Host: <strong>$(Html-Escape $Script:HostnameVal)</strong> &middot; Generated: <strong>$(Html-Escape $Script:Timestamp)</strong></p><p class=`"meta`">Codex home: <code>$(Html-Escape (Display-Text $Script:CodexDir))</code></p>") | Out-Null
        $parts.Add("<div class=`"summary`"><div><span>WARN</span><strong>$Script:WarnCount</strong></div><div><span>REVIEW</span><strong>$Script:ReviewCount</strong></div><div><span>INFO</span><strong>$Script:InfoCount</strong></div></div>") | Out-Null
        $parts.Add('<h2>Findings</h2><table><thead><tr><th>Severity</th><th>Section</th><th>Finding</th><th>Detail</th></tr></thead><tbody>') | Out-Null
        foreach ($f in $Script:Findings) {
            if ($Script:OptQuiet -and $f.severity -eq "INFO") { continue }
            $parts.Add("<tr><td><span class=`"badge $($f.severity.ToLowerInvariant())`">$(Html-Escape $f.severity)</span></td><td>$(Html-Escape $f.section)</td><td>$(Html-Escape (Display-Text $f.message))</td><td><code>$(Html-Escape (Display-Text $f.detail))</code></td></tr>") | Out-Null
        }
        $parts.Add('</tbody></table></section>') | Out-Null
    }
    $parts.Add('</main></body></html>') | Out-Null
    return ($parts -join [Environment]::NewLine)
}

function Apply-FailOn {
    if (-not $Script:OptFailOn) { return }
    if ($Script:OptFailOn -eq "warn" -and $Script:WarnCount -gt 0) { $Script:FinalExit = 2 }
    elseif ($Script:OptFailOn -eq "review" -and $Script:ReviewCount -gt 0 -and $Script:FinalExit -eq 0) { $Script:FinalExit = 1 }
}

try {
    Read-Args @args
    Assert-Options

    if ($Script:OptAllUsers) {
        $users = @(Get-CodexUsers)
        if ($users.Count -eq 0) { Write-Error "No users with Codex data found."; exit 1 }
    } else {
        if (-not $Script:AuditUser) { $Script:AuditUser = $env:USERNAME }
        $users = @($Script:AuditUser)
    }

    if ($Script:OptDiff) {
        $content = Render-Diff $Script:OptDiff $users
    } elseif ($Script:OptJson) {
        $doc = if ($Script:OptSummary) { Get-SummaryReportsForUsers $users } else { Get-ReportsForUsers $users }
        $content = $doc | ConvertTo-Json -Depth 10
    } elseif ($Script:OptHtml) {
        $content = Render-Html $users
    } else {
        $lines = New-Object System.Collections.Generic.List[string]
        foreach ($user in $users) {
            Audit-OneUser $user
            if ($Script:OptSummary) { $out = Write-SummaryReport } else { $out = Write-TerminalReport }
            $out | ForEach-Object { $lines.Add($_) | Out-Null }
            Apply-FailOn
        }
        $content = $lines -join [Environment]::NewLine
    }

    if ($Script:OptHtml) {
        $htmlFile = if ($Script:OptOutput) { $Script:OptOutput } elseif ($Script:OptHtml -ne "AUTO") { $Script:OptHtml } else { "codex_audit_{0}.html" -f (Get-Date -Format "yyyyMMdd_HHmmss") }
        Set-Content -LiteralPath $htmlFile -Value $content -Encoding UTF8
        Write-Output "HTML report written: $htmlFile"
    } elseif ($Script:OptOutput) {
        Set-Content -LiteralPath $Script:OptOutput -Value $content -Encoding UTF8
    } else {
        Write-Output $content
    }

    if ($Script:OptJson -or $Script:OptHtml -or $Script:OptDiff) {
        foreach ($user in $users) {
            Audit-OneUser $user
            Apply-FailOn
        }
    }
    exit $Script:FinalExit
} catch {
    $where = if ($_.InvocationInfo -and $_.InvocationInfo.ScriptLineNumber) { " at line $($_.InvocationInfo.ScriptLineNumber)" } else { "" }
    Write-Error "Error${where}: $($_.Exception.Message)"
    exit 1
}
