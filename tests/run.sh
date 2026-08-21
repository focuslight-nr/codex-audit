#!/bin/zsh
set -euo pipefail

ROOT="${0:A:h:h}"
SCRIPT="$ROOT/codex_audit.sh"
FIXTURE="$ROOT/tests/fixtures/basic/.codex"
TMPDIR="${TMPDIR:-/tmp}/codex-audit-tests.$$"
mkdir -p "$TMPDIR"
trap 'rm -rf "$TMPDIR"' EXIT

zsh -n "$SCRIPT"

"$SCRIPT" --codex-dir "$FIXTURE" --json > "$TMPDIR/audit.json"
jq -e '.summary.warn >= 1 and .summary.review >= 1' "$TMPDIR/audit.json" >/dev/null
jq -e '.mcp_servers[] | select(.name == "local_shell")' "$TMPDIR/audit.json" >/dev/null
jq -e '.mcp_servers[] | select(.name == "local_shell" and (.approval_modes | contains("approve")))' "$TMPDIR/audit.json" >/dev/null
jq -e '.apps[] | select(.id == "test_connector" and .enabled == "true")' "$TMPDIR/audit.json" >/dev/null
jq -e '.app_policies[] | select(.id == "test_connector" and (.policy | contains("approval_mode=approve")))' "$TMPDIR/audit.json" >/dev/null
jq -e '.hooks | length >= 2' "$TMPDIR/audit.json" >/dev/null
jq -e '.rules[] | select(.path | endswith("default.rules"))' "$TMPDIR/audit.json" >/dev/null
jq -e '.config_layers[] | select(.path | endswith("review.config.toml"))' "$TMPDIR/audit.json" >/dev/null
jq -e '.findings[] | select(.message == "Approval prompts are disabled")' "$TMPDIR/audit.json" >/dev/null
jq -e '.findings[] | select(.message | contains("Command hook configured"))' "$TMPDIR/audit.json" >/dev/null
jq -e '.plugin_cache[] | select(.provenance == "local-or-third-party")' "$TMPDIR/audit.json" >/dev/null
jq -e '.plugin_cache[] | select(.signature_artifacts == "custom-plugin.sig")' "$TMPDIR/audit.json" >/dev/null
jq -e '.findings[] | select(.message | contains("Signature-related artifact"))' "$TMPDIR/audit.json" >/dev/null
jq -e '.automations[] | select(.id == "daily" and (.risk_tags | contains("external-data")))' "$TMPDIR/audit.json" >/dev/null
jq -e '.retention[] | select(.name == "sessions" and .file_count == "1")' "$TMPDIR/audit.json" >/dev/null

"$SCRIPT" --codex-dir "$FIXTURE" --json --redact-paths > "$TMPDIR/redacted.json"
jq empty "$TMPDIR/redacted.json" >/dev/null

"$SCRIPT" --codex-dir "$FIXTURE" --summary > "$TMPDIR/summary.txt"
grep -q 'WARN=' "$TMPDIR/summary.txt"

"$SCRIPT" --codex-dir "$FIXTURE" --json > "$TMPDIR/baseline.json"
"$SCRIPT" --codex-dir "$FIXTURE" --diff "$TMPDIR/baseline.json" --diff-json > "$TMPDIR/diff.json"
jq -e '.has_changes == false' "$TMPDIR/diff.json" >/dev/null

set +e
"$SCRIPT" --codex-dir "$FIXTURE" --fail-on warn --json > "$TMPDIR/fail.json"
code=$?
set -e
[[ "$code" -eq 2 ]]
jq empty "$TMPDIR/fail.json" >/dev/null

"$SCRIPT" --codex-dir "$FIXTURE" --html --output "$TMPDIR/report.html" >/dev/null
[[ -s "$TMPDIR/report.html" ]]

echo "All tests passed."
