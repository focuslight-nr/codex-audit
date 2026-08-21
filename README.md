# CODEX-AUDIT

Unofficial, read-only local security audit tool for Codex on macOS.

> CODEX-AUDIT is an independent project. It is not affiliated with, endorsed by, sponsored by, or maintained by OpenAI. "OpenAI", "Codex", and related product names may be trademarks of OpenAI and are referenced only to describe interoperability with local Codex configuration.

日本語版 README: [README.ja.md](README.ja.md)

`codex_audit.sh` inspects local Codex state under `~/.codex` and reports configuration that affects Codex's execution surface: config profiles, permission and sandbox policies, MCP servers, enabled plugins, app connectors, hooks, command rules, trusted project config, skills, automations, browser/computer-use state, sensitive files, local retention, and runtime state.

The script is read-only. It does not modify audited files.

## Why

Codex can connect to local MCP servers, plugins, app connectors, browser/computer-use tooling, trusted project directories, and scheduled automations. Those capabilities are useful, but they also create local endpoint state that should be visible and reviewable.

CODEX-AUDIT gives you a single-command inventory and review signal for that local state.

## Quick Start

```bash
git clone https://github.com/focuslight-nr/codex-audit.git
cd codex-audit
chmod +x codex_audit.sh
./codex_audit.sh
```

Summary view:

```bash
./codex_audit.sh --summary
```

JSON:

```bash
./codex_audit.sh --json | jq .
```

HTML report:

```bash
./codex_audit.sh --html --output codex-audit.html
```

## Example Output

Summary output looks like this:

```text
esp  WARN=9 REVIEW=12 INFO=24  ~/.codex
  [REVIEW] Plugins: Enabled Codex plugin: notion@openai-curated
  [REVIEW] Plugins: Enabled Codex plugin: google-drive@openai-curated
  [WARN] Desktop: Remote control keep-awake is enabled
  [WARN] Projects: Trusted project grants Codex broader workspace autonomy
```

Fixture output with a local test plugin looks like this:

```text
esp  WARN=4 REVIEW=6 INFO=6  ~/.codex
  [REVIEW] Config: config.toml is readable beyond the owner
  [REVIEW] Plugins: Enabled Codex plugin: custom-plugin@local-marketplace
  [WARN] MCP Servers: MCP server uses command-capable runtime: local_shell
  [REVIEW] Plugins: Plugin provenance requires review: custom-plugin
```

## What It Checks

| Area | Checks |
| --- | --- |
| Config | User, profile, and trusted-project config layers; model, features, notification hooks, unknown sections |
| Permissions | Approval policy, auto-review, sandbox mode, writable roots, permission profiles, command network access |
| MCP Servers | Server names, commands/URLs, enabled state, tool approval modes, env var keys, env-key risk tags |
| Plugins | Enabled plugins, cached packages, metadata provenance, plugin MCP approval modes |
| Signature Artifacts | Presence of signature-like files such as `.sig`, `.asc`, `.pem`, `.crt`, `.minisig`, `.sigstore` |
| Connectors | Enabled app entries, per-app/per-tool approvals, destructive and open-world tool policy |
| Hooks and Rules | Inline and `hooks.json` command hooks, persistent `.rules` files |
| Projects | `trusted` project entries and trusted project-local `.codex` layers |
| Skills | User and plugin `SKILL.md` files |
| Automations | `~/.codex/automations/*/automation.toml`, ACTIVE schedules, prompt risk tags |
| Sensitive Files | `auth.json`, global state, installation ID, session index |
| Execution Config | Browser, Computer Use, and Chrome native-host configuration files |
| Local Data | SQLite/DB and WAL presence up to two levels below `~/.codex`, including memories and current state stores |
| Retention | Session, archived session, shell snapshot, and ambient suggestion counts/sizes/latest mtimes |
| Runtime | Running Codex processes, sleep assertions, LaunchAgents, crontab |

## Severity Model

| Severity | Meaning |
| --- | --- |
| WARN | Expands Codex's execution surface or indicates state that should be reviewed promptly. |
| REVIEW | Needs human judgement. Often expected, but relevant to security posture. |
| INFO | Inventory or baseline context. Useful for comparison and troubleshooting. |

Findings are review signals, not automatic proof of compromise. For example, an enabled plugin or trusted project can be expected and appropriate; CODEX-AUDIT makes it visible so it can be reviewed.

## Usage

Default terminal report:

```bash
./codex_audit.sh
```

Quiet mode shows WARN and REVIEW findings first while still printing inventory sections:

```bash
./codex_audit.sh -q
```

Summary-only output:

```bash
./codex_audit.sh --summary
./codex_audit.sh --summary --json
```

Write output directly:

```bash
./codex_audit.sh --json --output audit.json
./codex_audit.sh --summary --output summary.txt
./codex_audit.sh --html --output audit.html
```

Redact user-specific paths for shared reports:

```bash
./codex_audit.sh --json --redact-paths
./codex_audit.sh --html --output audit.html --redact-paths
```

Audit another local user:

```bash
./codex_audit.sh --user USERNAME
```

Audit all local users with `~/.codex` data:

```bash
sudo ./codex_audit.sh --all-users
```

Audit a copied or fixture Codex directory:

```bash
./codex_audit.sh --codex-dir /path/to/.codex
```

## Baseline Diff

Create a baseline:

```bash
./codex_audit.sh --json > baseline.json
```

Compare current state against the baseline:

```bash
./codex_audit.sh --diff baseline.json
```

Machine-readable diff:

```bash
./codex_audit.sh --diff baseline.json --diff-json | jq .
```

Diff compares:

- MCP servers by name
- enabled plugins by ID
- app connectors by ID
- app approval policies
- trusted projects by path
- config layers, hooks, and command rules
- automations by ID
- skills by `source:name`

`--diff` and `--diff-json` require `jq`.

## Policy Gate Mode

Use `--fail-on` for scheduled checks, MDM jobs, or CI-style policy gates:

```bash
./codex_audit.sh --fail-on warn
./codex_audit.sh --fail-on review
```

Exit codes:

- `0`: no threshold findings
- `1`: REVIEW threshold met
- `2`: WARN threshold met

## Requirements

- macOS
- zsh
- `jq` optional for normal audits
- `jq` required for `--diff`, `--diff-json`, and the fixture test runner

Install `jq` with Homebrew if needed:

```bash
brew install jq
```

## Testing

Run the fixture-based smoke test:

```bash
tests/run.sh
```

The test runner uses `--codex-dir tests/fixtures/basic/.codex` so it does not depend on the current user's real Codex configuration.

## Security Properties

- Read-only by design
- No network calls
- Sensitive-looking config values are redacted where displayed
- MCP environment values are not printed, only env var names
- HTML output is written with owner-only permissions through `umask 077`
- Path redaction is available with `--redact-paths`
- Plugin provenance is heuristic metadata classification, not cryptographic signature verification
- Signature artifact detection only reports files with signature-like names; it does not validate signatures

## Current Scope And Limitations

Resolved or mitigated limitations:

- Normal audits do not require `jq`; plugin metadata falls back to path-derived values when `jq` is unavailable.
- macOS-only behavior is enforced with an explicit preflight check.
- Current documented config section families are classified; genuinely unknown sections are reported as INFO so future format drift remains visible.
- Fixture testing is supported through `--codex-dir`.

Remaining limitations:

- macOS/Zsh only. Windows would require a separate PowerShell port.
- `--diff` and `--diff-json` require `jq`.
- Plugin provenance is heuristic only; CODEX-AUDIT does not verify signatures.
- Signature-related artifact detection is an existence check only.
- The TOML collector intentionally focuses on security-relevant scalar settings and section structure; complex inline TOML values may require future collector updates.

## Documentation

- [Findings Reference](docs/findings-reference.md)
- [License](LICENSE)
- [Notice](NOTICE)

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
