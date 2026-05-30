# CODEX-AUDIT Findings Reference

This document explains the findings emitted by `codex_audit.sh`. The tool is read-only and audits local Codex state under `~/.codex`.

## Severity

| Severity | Meaning |
| --- | --- |
| WARN | A setting or state expands Codex's execution surface and should be reviewed promptly. |
| REVIEW | Human judgement is needed. The item may be expected, but it can affect security posture. |
| INFO | Inventory or context. Useful for baselining and troubleshooting. |

## Config

### Notification hook configured

Codex has a notification hook configured in `config.toml`.

Why it matters: notification commands can invoke local binaries after turns. Confirm the path is expected.

### Default model

Reports the configured default model.

Why it matters: model choice affects behavior, cost, and compatibility, but is not a security issue by itself.

### config.toml permissions

Emitted when `config.toml` is readable beyond the owner.

Why it matters: the config can reveal enabled integrations, trusted projects, MCP commands, and local paths.

### Unknown config section(s) present

`config.toml` contains section names that CODEX-AUDIT does not currently classify.

Why it matters: Codex configuration formats may evolve. Unknown sections are not treated as suspicious by default, but they are surfaced so collector coverage gaps are visible.

## Features

Reports feature flags from `[features]`.

Why it matters: enabled features can change persistence, tool availability, or workflow behavior.

## Desktop

### Remote control keep-awake is enabled

`keepRemoteControlAwakeWhilePluggedIn=true` is enabled.

Why it matters: Codex-related remote-control sessions may keep the machine awake while plugged in.

## Projects

### Trusted project grants Codex broader workspace autonomy

A project entry has `trust_level = "trusted"`.

Why it matters: trusted workspaces generally allow more autonomous file and command activity. Confirm each trusted path is intentional, especially broad paths such as a whole GitHub directory.

## Plugins

### Enabled Codex plugin

A plugin is enabled under `[plugins]`.

Why it matters: plugins can expose tools, skills, app connectors, or browser/computer-use capabilities. Confirm each enabled plugin is expected.

### Cached plugin package found

A plugin package exists under `~/.codex/plugins/cache`.

Why it matters: cached plugins indicate available local plugin code and skills. Cached does not always mean currently enabled.

### Plugin provenance requires review

A cached plugin package is not classified as `openai-bundled`, `openai-curated`, or `openai-runtime`.

Why it matters: local, third-party, or unknown plugin packages should be reviewed because plugins can ship tools, skills, scripts, and integration behavior. The audit classifies provenance using marketplace and publisher metadata only; it does not perform signature verification.

### Signature-related artifact(s) present for plugin

A cached plugin directory contains files with signature-like names or extensions, such as `.sig`, `.signature`, `.pem`, `.crt`, `.cer`, `.pub`, `.asc`, `.minisig`, `.cosign`, or `.sigstore`.

Why it matters: this shows that signature-related material may be present. CODEX-AUDIT does not validate these artifacts or decide whether they are trustworthy.

### No signature-related artifacts found for plugin

No signature-like files were found in the plugin directory.

Why it matters: absence of signature artifacts is useful inventory context, but it does not prove the plugin is unsafe. The package may use a different integrity mechanism or no visible local signature material.

## Connectors

### Enabled app connector

An app connector is enabled under `[apps]`.

Why it matters: connectors can provide access to external accounts or services. Confirm the connector ID maps to an expected integration.

## MCP Servers

### MCP server configured

An MCP server is configured under `[mcp_servers]`.

Why it matters: MCP servers run local commands and expose tools to Codex. The audit prints env var names only, not values.

### MCP server env keys imply elevated scope

An MCP server has env var names that imply sensitive values, filesystem scope, trust/allowlist behavior, or browser scope.

Risk tags:

- `secret-like-env`: env key name looks like it may hold a token, secret, password, credential, auth value, or cookie.
- `trust-or-allowlist`: env key name suggests trusted paths, allowlists, or similar policy controls.
- `filesystem-scope`: env key name suggests filesystem paths, directories, or home-directory scope.
- `browser-scope`: env key name suggests browser or backend control.

Why it matters: values are intentionally not printed, but key names can still show whether the MCP server may receive sensitive authority.

### MCP server uses command-capable runtime

The MCP command basename matches a command-capable runtime such as `bash`, `python`, `node`, `osascript`, `curl`, or similar.

Why it matters: these runtimes can execute arbitrary code or interact with network/system resources. Confirm command, args, and env keys.

## Skills

### Codex skill found

A user or plugin `SKILL.md` was found.

Why it matters: skills influence Codex behavior and tool usage. Review custom/user skills more closely than bundled plugin skills.

## Automations

### Active automation

An automation has `status = "ACTIVE"`.

Why it matters: active automations run without an immediate user prompt at scheduled times. Review prompt, schedule, model, execution environment, and working directories.

### Active automation has access to a broad working directory

An active automation references a working directory containing broad path terms such as `Documents` or `GitHub`.

Why it matters: broad working directories increase the amount of local data available to automated runs.

### Active automation prompt contains higher-risk actions

An active automation prompt contains terms associated with external data access, writes/sends, deletion, web/download activity, or code/shell activity.

Risk tags:

- `external-data`: prompt references services or documents such as Google Drive, spreadsheets, or docs.
- `writes-or-sends`: prompt suggests writing, appending, uploading, posting, or sending.
- `delete`: prompt suggests deletion.
- `web-or-download`: prompt suggests web research, browser use, public information gathering, or downloads.
- `code-or-shell`: prompt suggests shell, command, commit, or push activity.

Why it matters: scheduled prompts with these behaviors deserve closer review because they may act on external services or local workspaces without immediate user interaction.

## Baseline Diff

`--diff baseline.json` compares the current audit against a previous JSON report.

Compared areas:

- MCP servers by name
- enabled plugins by ID
- app connectors by ID
- trusted projects by path
- automations by ID
- skills by `source:name`

Why it matters: configuration drift is often more useful than a single snapshot. New MCP servers, trusted projects, or automations should be explicitly reviewed.

Use `--diff-json` with `--diff` to emit machine-readable diff output.

## Fail-On

`--fail-on warn` exits with code `2` if any WARN findings exist.

`--fail-on review` exits with code `1` if any REVIEW findings exist.

Why it matters: non-zero exits make the tool usable from scheduled checks, MDM jobs, or CI-style policy gates.

## Summary Output

`--summary` emits only the count summary and top non-INFO findings.

With `--json`, it emits only timestamp, host, username, Codex directory, and counts.

Why it matters: summary output is suitable for scheduled checks where full inventory output would be too noisy.

## Output Files

`--output FILE` writes the selected output mode directly to a file.

Examples:

- `--json --output audit.json`
- `--summary --output summary.txt`
- `--html --output audit.html`

Why it matters: direct output avoids shell redirection in MDM or scheduled execution environments.

## Fixture Audits

`--codex-dir DIR` audits a specific Codex home directory instead of `~/.codex`.

Why it matters: this supports fixture tests and offline inspection of copied Codex data. It is mutually exclusive with `--all-users`.

## Scope Boundaries

CODEX-AUDIT is macOS/Zsh only and performs read-only local filesystem/runtime inspection.

It does not:

- verify plugin signatures,
- call network services,
- modify Codex configuration,
- support Windows in this shell implementation.

Plugin provenance findings are metadata-based review signals, not proof of trust or compromise.

## Redaction

`--redact-paths` redacts user-specific home paths in terminal, JSON, and HTML output.

Example: `/Users/alice/.codex` becomes `~/.codex`.

Why it matters: reports can otherwise reveal usernames, project names, and local directory layout.

## Sensitive Files

### auth.json present

Codex auth state exists.

Why it matters: this file should be owner-only. `codex_audit.sh` emits a WARN if permissions are broader than `600` or `400`.

### Global state, installation ID, session index

Inventory findings for local Codex metadata.

Why it matters: these files can reveal local usage metadata or identifiers. They are usually not secrets, but should still be treated as local application data.

## Local Data

### SQLite DB/WAL present

Reports local Codex SQLite databases and WAL files.

Why it matters: these files can contain local state, logs, or session metadata.

### SQLite DB/WAL larger than 100 MB

Large local data file detected.

Why it matters: large state/log files may indicate long retention or substantial local history. Review retention expectations.

## Retention

### sessions contains files

Reports file count, total bytes, latest modification time, and path for `~/.codex/sessions`.

Why it matters: session files may contain local conversation or workflow history. Size and latest mtime help assess retention behavior.

### archived_sessions contains files

Reports file count, total bytes, latest modification time, and path for `~/.codex/archived_sessions`.

Why it matters: archived sessions are still retained local data and should be considered when sharing or decommissioning a machine.

### shell_snapshots contains files

Reports shell snapshot retention.

Why it matters: shell snapshots can reveal command context or workspace paths.

### ambient-suggestions contains files

Reports ambient suggestion cache retention.

Why it matters: suggestion state can reveal workspace context or recent activity.

### Retained data larger than 100 MB

A retention directory has more than 100 MB of files.

Why it matters: large retained data increases local exposure and may indicate logs or sessions are not being pruned as expected.

### Retention directory contains more than 1000 files

A retention directory has more than 1000 files.

Why it matters: high file counts can indicate excessive local history or operational churn.

## Runtime

### Codex-related processes running

Codex processes are currently running.

Why it matters: runtime state helps distinguish dormant config from active use.

### Codex-related sleep assertion found

macOS reports a sleep-prevention assertion related to Codex.

Why it matters: the app may keep the machine awake. Confirm this is expected.

### Codex LaunchAgent found

A user LaunchAgent matching Codex was found.

Why it matters: LaunchAgents can start processes automatically.

### Codex-related crontab entry found

A crontab line references Codex.

Why it matters: cron can run local commands on a schedule outside Codex's own automation system.
