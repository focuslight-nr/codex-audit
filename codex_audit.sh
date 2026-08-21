#!/bin/zsh
# CODEX-AUDIT - Codex local security audit tool (macOS/Zsh)
# Read-only audit for ~/.codex configuration, plugins, skills, MCP servers, and automations.
# Unofficial project. Not affiliated with, endorsed by, sponsored by, or maintained by OpenAI.
setopt PIPE_FAIL KSH_ARRAYS BASH_REMATCH TYPESET_SILENT NULL_GLOB

VERSION="0.8.0"
SCRIPT_NAME="${0:t}"
CODEX_DIR_NAME=".codex"
DANGEROUS_MCP_HINTS="bash sh zsh python python3 node ruby perl osascript sqlite3 psql mysql curl wget nc ncat ssh scp"
SENSITIVE_NAME_RE='(token|secret|password|passwd|api[_-]?key|credential|auth|session|cookie)'
HAS_JQ=false

AUDIT_USER=""
HOME_DIR=""
CODEX_DIR=""
TIMESTAMP=""
HOSTNAME_VAL=""
OPT_JSON=false
OPT_QUIET=false
OPT_HTML=""
OPT_ALL_USERS=false
OPT_REDACT_PATHS=false
OPT_DIFF=""
OPT_DIFF_JSON=false
OPT_FAIL_ON=""
OPT_OUTPUT=""
OPT_SUMMARY=false
OPT_CODEX_DIR=""

FINDING_SEV=()
FINDING_SECT=()
FINDING_MSG=()
FINDING_DET=()

MCP_NAMES=()
declare -A MCP_CMDS MCP_ARGS MCP_ENVKEYS MCP_URLS MCP_ENABLED MCP_APPROVALS

PLUGINS=()
PLUGIN_DETAILS=()
MARKETPLACES=()
APPS=()
APP_POLICIES=()
TRUSTED_PROJECTS=()
SKILLS=()
AUTOMATIONS=()
CONFIG_LAYERS=()
HOOK_SOURCES=()
RULE_FILES=()
INSTRUCTION_FILES=()
RUNTIME_ITEMS=()
SENSITIVE_FILES=()
RETENTION_ITEMS=()

WARN_COUNT=0
INFO_COUNT=0
REVIEW_COUNT=0

preflight() {
    if [[ "$(uname -s 2>/dev/null)" != "Darwin" ]]; then
        print -r -- "CODEX-AUDIT currently supports macOS only. Detected: $(uname -s 2>/dev/null || echo unknown)" >&2
        exit 1
    fi
    command -v jq >/dev/null 2>&1 && HAS_JQ=true || HAS_JQ=false
}

add_finding() {
    local sev="$1" sect="$2" msg="$3" det="${4:-}"
    FINDING_SEV+=("$sev")
    FINDING_SECT+=("$sect")
    FINDING_MSG+=("$msg")
    FINDING_DET+=("$det")
    case "$sev" in
        WARN) ((WARN_COUNT++)) ;;
        REVIEW) ((REVIEW_COUNT++)) ;;
        *) ((INFO_COUNT++)) ;;
    esac
}

json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\t'/\\t}"
    s="${s//$'\r'/\\r}"
    printf '%s' "$s"
}

jstr() {
    printf '"%s"' "$(json_escape "$1")"
}

display_text() {
    local s="$1"
    if [[ "$OPT_REDACT_PATHS" == "true" ]]; then
        [[ -n "$HOME_DIR" ]] && s="${s//${HOME_DIR}/~}"
        [[ -n "$AUDIT_USER" ]] && s="${s//\/Users\/${AUDIT_USER}/\/Users\/[USER]}"
    fi
    printf '%s' "$s"
}

jstr_out() {
    jstr "$(display_text "$1")"
}

html_escape() {
    local s="$1"
    s="${s//&/&amp;}"
    s="${s//</&lt;}"
    s="${s//>/&gt;}"
    s="${s//\"/&quot;}"
    s="${s//\'/&#39;}"
    printf '%s' "$s"
}

html_out() {
    html_escape "$(display_text "$1")"
}

strip_quotes() {
    local s="$1"
    s="${s#"${s%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    s="${s#\"}"
    s="${s%\"}"
    printf '%s' "$s"
}

redact_value() {
    local key="$1" val="$2"
    if [[ "${(L)key}" =~ "$SENSITIVE_NAME_RE" || "${(L)val}" =~ '(sk-|bearer |token=|secret=|password=|api[_-]?key=)' ]]; then
        printf '[REDACTED]'
    else
        printf '%s' "$val"
    fi
}

tag_if_present() {
    local text="$1" needle="$2" tag="$3"
    [[ "${(L)text}" == *"$needle"* ]] && printf '%s' "$tag"
}

automation_risk_tags() {
    local prompt="$1" tags=() lower
    lower="${(L)prompt}"
    [[ "$lower" == *"google drive"* || "$lower" == *"spreadsheet"* || "$lower" == *"スプレッドシート"* || "$lower" == *"ドキュメント"* ]] && tags+=("external-data")
    [[ "$lower" == *"send"* || "$lower" == *"upload"* || "$lower" == *"post "* || "$lower" == *"追記"* || "$lower" == *"書き込"* ]] && tags+=("writes-or-sends")
    [[ "$lower" == *"delete"* || "$lower" == *"削除"* ]] && tags+=("delete")
    [[ "$lower" == *"download"* || "$lower" == *"browser"* || "$lower" == *"web"* || "$lower" == *"公開情報"* ]] && tags+=("web-or-download")
    [[ "$lower" == *"shell"* || "$lower" == *"command"* || "$lower" == *"commit"* || "$lower" == *"push"* ]] && tags+=("code-or-shell")
    local IFS=","
    printf '%s' "${tags[*]}"
}

mcp_env_risk_tags() {
    local keys="$1" tags=() lower
    lower="${(L)keys}"
    [[ "$lower" =~ '(token|secret|password|passwd|api[_-]?key|credential|auth|cookie)' ]] && tags+=("secret-like-env")
    [[ "$lower" == *"trusted"* || "$lower" == *"allowlist"* ]] && tags+=("trust-or-allowlist")
    [[ "$lower" == *"path"* || "$lower" == *"dirs"* || "$lower" == *"home"* ]] && tags+=("filesystem-scope")
    [[ "$lower" == *"browser"* || "$lower" == *"backend"* ]] && tags+=("browser-scope")
    local IFS=","
    printf '%s' "${tags[*]}"
}

fmt_bytes() {
    local n="$1"
    if ((n < 1024)); then printf '%d B' "$n"
    elif ((n < 1048576)); then printf '%.1f KB' "$((n / 1024.0))"
    elif ((n < 1073741824)); then printf '%.1f MB' "$((n / 1048576.0))"
    else printf '%.1f GB' "$((n / 1073741824.0))"; fi
}

file_mode() {
    local p="$1"
    stat -f '%Lp' "$p" 2>/dev/null || printf ''
}

dir_file_count() {
    local d="$1"
    [[ -d "$d" ]] || { printf '0'; return 0; }
    find "$d" -type f 2>/dev/null | wc -l | tr -d ' '
}

dir_total_bytes() {
    local d="$1"
    [[ -d "$d" ]] || { printf '0'; return 0; }
    find "$d" -type f -print0 2>/dev/null | xargs -0 stat -f '%z' 2>/dev/null | awk '{s+=$1} END {print s+0}'
}

dir_latest_mtime() {
    local d="$1"
    [[ -d "$d" ]] || { printf ''; return 0; }
    find "$d" -type f -print0 2>/dev/null | xargs -0 stat -f '%m' 2>/dev/null | sort -nr | head -1 | while read -r ts; do
        [[ -n "$ts" ]] && date -r "$ts" '+%Y-%m-%dT%H:%M:%S%z'
    done
}

plugin_provenance() {
    local marketplace="$1" publisher="$2"
    case "$marketplace" in
        openai-bundled) printf 'openai-bundled' ;;
        openai-curated) printf 'openai-curated' ;;
        openai-primary-runtime) printf 'openai-runtime' ;;
        *)
            if [[ "${(L)publisher}" == *openai* ]]; then
                printf 'openai-other'
            elif [[ -z "$marketplace" || "$marketplace" == "unknown" ]]; then
                printf 'unknown'
            else
                printf 'local-or-third-party'
            fi
            ;;
    esac
}

signature_artifacts() {
    local plugin_dir="$1" artifacts=() f rel
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        rel="${f#$plugin_dir/}"
        artifacts+=("$rel")
    done < <(find "$plugin_dir" -maxdepth 4 \( -name '*.sig' -o -name '*.signature' -o -name '*.pem' -o -name '*.crt' -o -name '*.cer' -o -name '*.pub' -o -name '*.asc' -o -name '*.minisig' -o -name '*.cosign' -o -name '.sigstore' \) -print 2>/dev/null | sort)
    local IFS=","
    printf '%s' "${artifacts[*]}"
}

get_user_home() {
    local user="$1"
    if [[ -z "$user" || "$user" == "$(id -un)" ]]; then
        printf '%s' "$HOME"
        return 0
    fi
    if command -v dscl >/dev/null 2>&1; then
        dscl . -read "/Users/$user" NFSHomeDirectory 2>/dev/null | awk '{print $2}'
    fi
}

discover_codex_users() {
    local user home
    if ! command -v dscl >/dev/null 2>&1; then
        return 0
    fi
    dscl . -list /Users 2>/dev/null | while IFS= read -r user; do
        [[ "$user" == _* || "$user" == "." || "$user" == "daemon" || "$user" == "nobody" || "$user" == "root" ]] && continue
        home=$(get_user_home "$user")
        [[ -d "$home/$CODEX_DIR_NAME" ]] && print -r -- "$user"
    done
}

reset_state() {
    FINDING_SEV=()
    FINDING_SECT=()
    FINDING_MSG=()
    FINDING_DET=()
    MCP_NAMES=()
    MCP_CMDS=()
    MCP_ARGS=()
    MCP_ENVKEYS=()
    MCP_URLS=()
    MCP_ENABLED=()
    MCP_APPROVALS=()
    PLUGINS=()
    PLUGIN_DETAILS=()
    MARKETPLACES=()
    APPS=()
    APP_POLICIES=()
    TRUSTED_PROJECTS=()
    SKILLS=()
    AUTOMATIONS=()
    CONFIG_LAYERS=()
    HOOK_SOURCES=()
    RULE_FILES=()
    INSTRUCTION_FILES=()
    RUNTIME_ITEMS=()
    SENSITIVE_FILES=()
    RETENTION_ITEMS=()
    WARN_COUNT=0
    INFO_COUNT=0
    REVIEW_COUNT=0
}

parse_skill_frontmatter() {
    local file="$1" name="" desc="" line in_desc=false
    [[ -r "$file" ]] || { printf '%s|%s' "$(basename "$(dirname "$file")")" ""; return 0; }
    local first
    first=$(sed -n '1p' "$file" 2>/dev/null)
    if [[ "$first" != "---"* ]]; then
        printf '%s|%s' "$(basename "$(dirname "$file")")" ""
        return 0
    fi
    while IFS= read -r line; do
        [[ "$line" == "---" && -n "$name$desc" ]] && break
        if [[ "$line" == name:* ]]; then
            name=$(strip_quotes "${line#name:}")
            in_desc=false
        elif [[ "$line" == description:* ]]; then
            desc=$(strip_quotes "${line#description:}")
            [[ "$desc" == ">" || "$desc" == "|" ]] && desc=""
            in_desc=true
        elif [[ "$in_desc" == "true" && "$line" == "  "* ]]; then
            desc="${desc}${desc:+ }${line#  }"
        elif [[ "$line" != "---" ]]; then
            in_desc=false
        fi
    done < "$file"
    [[ -z "$name" ]] && name="$(basename "$(dirname "$file")")"
    printf '%s|%s' "$name" "$desc"
}

array_contains() {
    local needle="$1" item
    shift
    for item in "$@"; do
        [[ "$item" == "$needle" ]] && return 0
    done
    return 1
}

known_config_section() {
    local root="${1%%.*}"
    case "$root" in
        agents|analytics|apps|auto_review|computer_use|desktop|features|feedback|history|hooks|marketplaces|mcp_servers|memories|model_providers|notice|otel|permissions|plugins|profiles|projects|sandbox_workspace_write|shell_environment_policy|skills|tool_suggest|tools|tui|windows) return 0 ;;
        *) return 1 ;;
    esac
}

record_config_policy() {
    local full_key="$1" val="$2" layer="$3"
    case "$full_key" in
        approval_policy)
            [[ "$val" == "never" ]] && add_finding "WARN" "Permissions" "Approval prompts are disabled" "approval_policy=never; layer=$layer"
            [[ "$val" == "on-failure" ]] && add_finding "INFO" "Permissions" "Deprecated approval policy configured" "layer=$layer"
            ;;
        approvals_reviewer|apps.*.approvals_reviewer)
            [[ "$val" == "auto_review" ]] && add_finding "REVIEW" "Permissions" "Approval prompts use automatic review" "$full_key=auto_review; layer=$layer"
            ;;
        sandbox_mode)
            [[ "$val" == "danger-full-access" ]] && add_finding "WARN" "Permissions" "Full-access sandbox mode configured" "layer=$layer"
            ;;
        default_permissions)
            [[ "$val" == ":danger-full-access" ]] && add_finding "WARN" "Permissions" "Danger-full-access permission profile is the default" "layer=$layer"
            ;;
        sandbox_workspace_write.network_access)
            [[ "$val" == "true" ]] && add_finding "WARN" "Permissions" "Workspace-write sandbox has network access" "layer=$layer"
            ;;
        sandbox_workspace_write.writable_roots)
            add_finding "REVIEW" "Permissions" "Additional writable roots configured" "$(redact_value "$full_key" "$val"); layer=$layer"
            ;;
        web_search)
            [[ "$val" == "live" ]] && add_finding "REVIEW" "Network" "Live web search is enabled" "layer=$layer"
            ;;
        model_instructions_file|developer_instructions|agents.*.config_file)
            add_finding "REVIEW" "Instructions" "Custom instruction source configured" "$full_key=$(redact_value "$full_key" "$val"); layer=$layer"
            ;;
        otel.log_user_prompt)
            [[ "$val" == "true" ]] && add_finding "WARN" "Telemetry" "Raw user prompt export is enabled" "layer=$layer"
            ;;
        openai_base_url|chatgpt_base_url|mcp_oauth_callback_url)
            add_finding "REVIEW" "Network" "Service endpoint override configured" "$full_key=$(redact_value "$full_key" "$val"); layer=$layer"
            ;;
        model_providers.*.experimental_bearer_token)
            add_finding "WARN" "Providers" "Model provider stores a bearer token directly in config" "$full_key=[REDACTED]; layer=$layer"
            ;;
        model_providers.*.http_headers.*)
            add_finding "REVIEW" "Providers" "Static model-provider HTTP header configured" "$full_key=[REDACTED]; layer=$layer"
            ;;
        features.network_proxy.dangerously_allow_all_unix_sockets|permissions.*.network.dangerously_allow_all_unix_sockets)
            [[ "$val" == "true" ]] && add_finding "WARN" "Network" "Arbitrary Unix socket access is enabled" "$full_key=true; layer=$layer"
            ;;
        features.network_proxy.dangerously_allow_non_loopback_proxy|permissions.*.network.dangerously_allow_non_loopback_proxy)
            [[ "$val" == "true" ]] && add_finding "WARN" "Network" "Non-loopback proxy binding is enabled" "$full_key=true; layer=$layer"
            ;;
        permissions.*.network.mode)
            [[ "$val" == "full" ]] && add_finding "WARN" "Network" "Permission profile grants full network mode" "$full_key=full; layer=$layer"
            ;;
        permissions.*.network.enabled)
            [[ "$val" == "true" ]] && add_finding "REVIEW" "Network" "Permission profile enables command network access" "$full_key=true; layer=$layer"
            ;;
    esac
}

collect_config_file() {
    local cfg="$1" layer="$2" owner_sensitive="${3:-true}" mode
    [[ -r "$cfg" ]] || return 0
    CONFIG_LAYERS+=("$layer|$cfg")
    mode=$(file_mode "$cfg")
    SENSITIVE_FILES+=("$(basename "$cfg")|$mode|$cfg")
    [[ "$owner_sensitive" == "true" && -n "$mode" && "$mode" != "600" && "$mode" != "400" ]] && add_finding "REVIEW" "Config" "Config layer is readable beyond the owner" "layer=$layer; mode=$mode"

    local section="" mcp="" mcp_base=false key="" val="" raw="" plugin="" project="" marketplace="" app="" full_key="" existing="" unknown_sections=()
    while IFS= read -r raw; do
        raw="${raw%%#*}"
        [[ -z "${raw//[[:space:]]/}" ]] && continue

        if [[ "$raw" =~ '^\[\[(.+)\]\]$' ]]; then
            section="${BASH_REMATCH[1]}"
        elif [[ "$raw" =~ '^\[(.+)\]$' ]]; then
            section="${BASH_REMATCH[1]}"
        fi
        if [[ "$raw" == \[* ]]; then
            mcp=""; mcp_base=false; plugin=""; project=""; marketplace=""; app=""
            if [[ "$section" =~ '^mcp_servers\."([^"]+)"($|\.)' ]]; then
                mcp="${BASH_REMATCH[1]}"
            elif [[ "$section" =~ '^mcp_servers\.([^.]*)($|\.)' ]]; then
                mcp="${BASH_REMATCH[1]}"
            fi
            if [[ -n "$mcp" && ( "$section" == "mcp_servers.$mcp" || "$section" == "mcp_servers.\"$mcp\"" ) ]]; then
                mcp_base=true
                array_contains "$mcp" "${MCP_NAMES[@]}" || MCP_NAMES+=("$mcp")
            fi
            [[ "$section" =~ '^plugins\."([^"]+)"($|\.)' ]] && plugin="${BASH_REMATCH[1]}"
            if [[ "$section" =~ '^projects\."(.+)"$' ]]; then
                project="${BASH_REMATCH[1]}"
            elif [[ "$section" =~ '^marketplaces\.([^.]*)$' ]]; then
                marketplace="${BASH_REMATCH[1]}"
            elif [[ "$section" =~ '^apps\."([^"]+)"($|\.)' ]]; then
                app="${BASH_REMATCH[1]}"
            elif [[ "$section" =~ '^apps\.([^.]*)($|\.)' ]]; then
                app="${BASH_REMATCH[1]}"
            fi
            if [[ "$section" == permissions.* && "$section" != permissions.*.* ]]; then
                add_finding "REVIEW" "Permissions" "Custom permission profile configured" "$section; layer=$layer"
            elif [[ "$section" == model_providers.* && "$section" != model_providers.*.* ]]; then
                add_finding "REVIEW" "Providers" "Custom model provider configured" "$section; layer=$layer"
            elif ! known_config_section "$section"; then
                unknown_sections+=("$section")
            fi
            continue
        fi

        [[ "$raw" == *"="* ]] || continue
        key="${raw%%=*}"; val="${raw#*=}"
        key="${key//[[:space:]]/}"; val="$(strip_quotes "$val")"
        full_key="${section:+$section.}$key"
        record_config_policy "$full_key" "$val" "$layer"

        if [[ -n "$mcp" ]]; then
            if [[ "$section" == mcp_servers.*.env || "$section" == mcp_servers.*.env_http_headers ]]; then
                existing="${MCP_ENVKEYS[$mcp]}"
                MCP_ENVKEYS[$mcp]="${existing}${existing:+, }$key"
            elif [[ "$section" == mcp_servers.*.http_headers ]]; then
                existing="${MCP_ENVKEYS[$mcp]}"
                MCP_ENVKEYS[$mcp]="${existing}${existing:+, }header:$key"
                add_finding "REVIEW" "MCP Servers" "Static MCP HTTP header configured: $mcp" "header=$key; layer=$layer"
            elif [[ "$mcp_base" == "true" && "$key" == "command" ]]; then
                MCP_CMDS[$mcp]="$(redact_value "$key" "$val")"
            elif [[ "$mcp_base" == "true" && "$key" == "args" ]]; then
                MCP_ARGS[$mcp]="$(redact_value "$key" "$val")"
            elif [[ "$mcp_base" == "true" && "$key" == "url" ]]; then
                MCP_URLS[$mcp]="$(redact_value "$key" "$val")"
            elif [[ "$mcp_base" == "true" && "$key" == "enabled" ]]; then
                MCP_ENABLED[$mcp]="$val"
            elif [[ "$key" == "default_tools_approval_mode" || "$key" == "approval_mode" ]]; then
                MCP_APPROVALS[$mcp]="${MCP_APPROVALS[$mcp]}${MCP_APPROVALS[$mcp]:+; }$full_key=$val"
                [[ "$val" == "approve" ]] && add_finding "WARN" "MCP Servers" "MCP tool approval is bypassed: $mcp" "$full_key=approve; layer=$layer"
            elif [[ "$mcp_base" == "true" && "$key" == "bearer_token_env_var" ]]; then
                existing="${MCP_ENVKEYS[$mcp]}"
                MCP_ENVKEYS[$mcp]="${existing}${existing:+, }$val"
            fi
        elif [[ -n "$plugin" && "$section" == "plugins.\"$plugin\"" && "$key" == "enabled" ]]; then
            PLUGINS+=("$plugin|$val")
            [[ "$val" == "true" ]] && add_finding "REVIEW" "Plugins" "Enabled Codex plugin: $plugin"
        elif [[ -n "$plugin" && ( "$key" == "default_tools_approval_mode" || "$key" == "approval_mode" ) ]]; then
            [[ "$val" == "approve" ]] && add_finding "WARN" "Plugins" "Plugin MCP tool approval is bypassed: $plugin" "$full_key=approve; layer=$layer"
        elif [[ -n "$project" && "$key" == "trust_level" ]]; then
            TRUSTED_PROJECTS+=("$project|$val")
            [[ "$val" == "trusted" ]] && add_finding "WARN" "Projects" "Trusted project grants Codex broader workspace autonomy" "$project"
        elif [[ -n "$marketplace" && "$key" == "source" ]]; then
            MARKETPLACES+=("$marketplace|$(redact_value "$key" "$val")")
        elif [[ -n "$app" && "$app" != "_default" && ( "$section" == "apps.$app" || "$section" == "apps.\"$app\"" ) && "$key" == "enabled" ]]; then
            APPS+=("$app|$val")
            [[ "$val" == "true" ]] && add_finding "REVIEW" "Connectors" "Enabled app connector: $app"
        elif [[ -n "$app" && ( "$key" == "approval_mode" || "$key" == "default_tools_approval_mode" || "$key" == "approvals_reviewer" || "$key" == "destructive_enabled" || "$key" == "open_world_enabled" ) ]]; then
            APP_POLICIES+=("$app|$full_key=$val")
            [[ ( "$key" == "approval_mode" || "$key" == "default_tools_approval_mode" ) && "$val" == "approve" ]] && add_finding "WARN" "Connectors" "App tool approval is bypassed: $app" "$full_key=approve; layer=$layer"
            [[ "$key" == "destructive_enabled" && "$val" == "true" ]] && add_finding "WARN" "Connectors" "Destructive app tools are enabled: $app" "layer=$layer"
            [[ "$key" == "open_world_enabled" && "$val" == "true" ]] && add_finding "REVIEW" "Connectors" "Open-world app tools are enabled: $app" "layer=$layer"
        elif [[ "$section" == "desktop" && "$key" == "keepRemoteControlAwakeWhilePluggedIn" && "$val" == "true" ]]; then
            add_finding "WARN" "Desktop" "Remote control keep-awake is enabled" "keepRemoteControlAwakeWhilePluggedIn=true"
        elif [[ "$section" == "features" ]]; then
            add_finding "INFO" "Features" "$key=$val"
        elif [[ -z "$section" && "$key" == "notify" ]]; then
            add_finding "INFO" "Config" "Notification hook configured" "$(redact_value "$key" "$val")"
        elif [[ -z "$section" && "$key" == "model" ]]; then
            add_finding "INFO" "Config" "Default model: $val"
        elif [[ "$section" == hooks.* && "$key" == "command" ]]; then
            local hook_event="${section#hooks.}"
            hook_event="${hook_event%%.*}"
            HOOK_SOURCES+=("$layer|inline:$hook_event|$(redact_value "$key" "$val")")
            add_finding "WARN" "Hooks" "Command hook configured: $hook_event" "layer=$layer; command=$(redact_value "$key" "$val")"
        elif [[ "$section" == model_providers.*.auth && "$key" == "command" ]]; then
            add_finding "WARN" "Providers" "Model provider uses a command-backed credential" "$section; command=$(redact_value "$key" "$val"); layer=$layer"
        elif [[ "$section" == shell_environment_policy.set ]]; then
            if [[ "${(L)key}" =~ "$SENSITIVE_NAME_RE" ]]; then
                add_finding "REVIEW" "Environment" "Sensitive-looking variable is injected into shell tools" "$key; layer=$layer"
            else
                add_finding "INFO" "Environment" "Shell environment variable is explicitly injected" "$key; layer=$layer"
            fi
        fi
    done < "$cfg"

    if ((${#unknown_sections[@]} > 0)); then
        local uniq_unknown
        uniq_unknown="$(printf '%s\n' "${unknown_sections[@]}" | sort -u | paste -sd ', ' -)"
        add_finding "INFO" "Config" "Unknown config section(s) present" "$uniq_unknown; layer=$layer"
    fi
}

collect_config() {
    local cfg="$CODEX_DIR/config.toml" profile name
    if [[ ! -f "$cfg" ]]; then
        add_finding "INFO" "Config" "config.toml not found" "$cfg"
    else
        collect_config_file "$cfg" "user"
    fi
    for profile in "$CODEX_DIR"/*.config.toml; do
        [[ "$profile" == "$cfg" ]] && continue
        collect_config_file "$profile" "profile:$(basename "$profile")"
        add_finding "REVIEW" "Config" "Codex config profile found" "$profile"
    done

}

finalize_config_findings() {
    local name
    for name in "${MCP_NAMES[@]}"; do
        local cmd="${MCP_CMDS[$name]:-}" endpoint="${MCP_URLS[$name]:-${cmd:-unknown}}"
        add_finding "REVIEW" "MCP Servers" "MCP server configured: $name" "endpoint=$endpoint; enabled=${MCP_ENABLED[$name]:-true}; env_keys=${MCP_ENVKEYS[$name]:-none}"
        local env_risks
        env_risks="$(mcp_env_risk_tags "${MCP_ENVKEYS[$name]:-}")"
        [[ -n "$env_risks" ]] && add_finding "REVIEW" "MCP Servers" "MCP server env keys imply elevated scope: $name" "$env_risks"
        for hint in ${(z)DANGEROUS_MCP_HINTS}; do
            [[ "$(basename "$cmd")" == "$hint" ]] && add_finding "WARN" "MCP Servers" "MCP server uses command-capable runtime: $name" "$cmd"
        done
    done
}

record_hook_file() {
    local file="$1" layer="$2" command found=false
    [[ -r "$file" ]] || return 0
    HOOK_SOURCES+=("$layer|hooks.json|$file")
    if [[ "$HAS_JQ" == "true" ]]; then
        while IFS= read -r command; do
            [[ -n "$command" ]] || continue
            found=true
            add_finding "WARN" "Hooks" "Command hook configured in hooks.json" "layer=$layer; command=$(redact_value command "$command")"
        done < <(jq -r '.. | objects | .command? // empty' "$file" 2>/dev/null)
    fi
    [[ "$found" == "false" ]] && add_finding "REVIEW" "Hooks" "Hook configuration file found" "layer=$layer; path=$file"
}

record_rule_file() {
    local file="$1" layer="$2" allow_count=0
    [[ -r "$file" ]] || return 0
    RULE_FILES+=("$layer|$file")
    allow_count=$(grep -Eo 'decision[[:space:]]*=[[:space:]]*"?allow"?' "$file" 2>/dev/null | wc -l | tr -d ' ')
    if ((allow_count > 0)); then
        add_finding "REVIEW" "Rules" "Persistent allow rule(s) configured" "layer=$layer; count=$allow_count; path=$file"
    else
        add_finding "INFO" "Rules" "Command rule file found" "layer=$layer; path=$file"
    fi
}

collect_policy_files() {
    local file row project trust project_codex

    record_hook_file "$CODEX_DIR/hooks.json" "user"
    for file in "$CODEX_DIR"/rules/*.rules; do
        record_rule_file "$file" "user"
    done
    if [[ -r "$CODEX_DIR/AGENTS.md" ]]; then
        INSTRUCTION_FILES+=("user|$CODEX_DIR/AGENTS.md")
        add_finding "REVIEW" "Instructions" "Global AGENTS.md found" "$CODEX_DIR/AGENTS.md"
    fi

    local trusted_rows=("${TRUSTED_PROJECTS[@]}")
    for row in "${trusted_rows[@]}"; do
        project="${row%%|*}"; trust="${row#*|}"
        [[ "$trust" == "trusted" && -d "$project" ]] || continue
        project_codex="$project/.codex"
        if [[ -r "$project_codex/config.toml" ]]; then
            collect_config_file "$project_codex/config.toml" "project:$project" false
            add_finding "REVIEW" "Config" "Trusted project config layer found" "$project_codex/config.toml"
        fi
        record_hook_file "$project_codex/hooks.json" "project:$project"
        for file in "$project_codex"/rules/*.rules; do
            record_rule_file "$file" "project:$project"
        done
    done

    for file in "$CODEX_DIR"/plugins/cache/*/*/*/hooks/hooks.json; do
        [[ -r "$file" ]] || continue
        HOOK_SOURCES+=("plugin-cache|hooks.json|$file")
        add_finding "INFO" "Hooks" "Cached plugin hook configuration found" "$file"
    done
}

collect_plugin_cache() {
    local manifest name version publisher source plugin_dir provenance sig_artifacts
    for manifest in "$CODEX_DIR"/plugins/cache/*/*/*/.codex-plugin/plugin.json; do
        [[ -r "$manifest" ]] || continue
        plugin_dir="${manifest:h:h}"
        [[ "$(basename "$plugin_dir")" == "latest" ]] && continue
        if [[ "$HAS_JQ" == "true" ]]; then
            name=$(jq -r '.name // .id // empty' "$manifest" 2>/dev/null)
            version=$(jq -r '.version // empty' "$manifest" 2>/dev/null)
            publisher=$(jq -r '(.publisher // .author // "") | if type == "object" then (.name // .email // .url // "") else . end' "$manifest" 2>/dev/null)
        else
            name="$(basename "$plugin_dir")"; version=""; publisher=""
        fi
        source="$(basename "${plugin_dir:h:h}")"
        provenance="$(plugin_provenance "$source" "$publisher")"
        sig_artifacts="$(signature_artifacts "$plugin_dir")"
        PLUGIN_DETAILS+=("${name:-unknown}|${version:-unknown}|${publisher:-unknown}|$source|$plugin_dir|$provenance|$sig_artifacts")
        [[ "$provenance" == "unknown" || "$provenance" == "local-or-third-party" ]] && add_finding "REVIEW" "Plugins" "Plugin provenance requires review: ${name:-unknown}" "$provenance; marketplace=$source; publisher=${publisher:-unknown}"
        if [[ -n "$sig_artifacts" ]]; then
            add_finding "INFO" "Plugins" "Signature-related artifact(s) present for plugin: ${name:-unknown}" "$sig_artifacts"
        else
            add_finding "INFO" "Plugins" "No signature-related artifacts found for plugin: ${name:-unknown}" "existence check only; no signature verification performed"
        fi
    done
    ((${#PLUGIN_DETAILS[@]} > 0)) && add_finding "INFO" "Plugins" "${#PLUGIN_DETAILS[@]} cached plugin package(s) found"
}

collect_skills() {
    local file parsed name desc source plugin_path
    for file in "$CODEX_DIR"/skills/*/*/SKILL.md "$CODEX_DIR"/skills/*/SKILL.md; do
        [[ -r "$file" ]] || continue
        parsed=$(parse_skill_frontmatter "$file")
        name="${parsed%%|*}"
        desc="${parsed#*|}"
        SKILLS+=("$name|user|$desc|$file")
    done
    for file in "$CODEX_DIR"/plugins/cache/*/*/*/skills/*/SKILL.md; do
        [[ -r "$file" ]] || continue
        parsed=$(parse_skill_frontmatter "$file")
        name="${parsed%%|*}"
        desc="${parsed#*|}"
        plugin_path="${file%/skills/*}"
        SKILLS+=("$name|plugin:$(basename "$plugin_path")|$desc|$file")
    done
    ((${#SKILLS[@]} > 0)) && add_finding "INFO" "Skills" "${#SKILLS[@]} Codex skill(s) found"
}

collect_automations() {
    local file id name kind auto_status rrule model env cwds prompt risk_tags raw key val
    for file in "$CODEX_DIR"/automations/*/automation.toml; do
        [[ -r "$file" ]] || continue
        id=""; name=""; kind=""; auto_status=""; rrule=""; model=""; env=""; cwds=""; prompt=""; risk_tags=""
        while IFS= read -r raw; do
            raw="${raw%%#*}"
            [[ "$raw" == *"="* ]] || continue
            key="${raw%%=*}"; key="${key//[[:space:]]/}"
            val="$(strip_quotes "${raw#*=}")"
            case "$key" in
                id) id="$val" ;;
                name) name="$val" ;;
                kind) kind="$val" ;;
                status) auto_status="$val" ;;
                rrule) rrule="$val" ;;
                model) model="$val" ;;
                execution_environment) env="$val" ;;
                cwds) cwds="$val" ;;
                prompt) prompt="$val" ;;
            esac
        done < "$file"
        risk_tags="$(automation_risk_tags "$prompt")"
        AUTOMATIONS+=("${id:-$(basename "${file:h}")}|${name:-unnamed}|${kind:-unknown}|${auto_status:-unknown}|${rrule:-none}|${model:-unknown}|${env:-unknown}|$cwds|$risk_tags")
        if [[ "$auto_status" == "ACTIVE" ]]; then
            add_finding "WARN" "Automations" "Active automation: ${name:-$id}" "kind=${kind:-unknown}; rrule=${rrule:-none}; cwd=${cwds:-none}"
            [[ "${(L)cwds}" == *documents* || "${(L)cwds}" == *github* ]] && add_finding "REVIEW" "Automations" "Active automation has access to a broad working directory" "${cwds:-none}"
            [[ -n "$risk_tags" ]] && add_finding "REVIEW" "Automations" "Active automation prompt contains higher-risk actions: ${name:-$id}" "$risk_tags"
        else
            add_finding "INFO" "Automations" "Automation present: ${name:-$id}" "status=${auto_status:-unknown}"
        fi
    done
}

collect_sensitive_files() {
    local p mode size
    for p in "$CODEX_DIR"/auth.json "$CODEX_DIR"/.codex-global-state.json "$CODEX_DIR"/.codex-global-state.json.bak "$CODEX_DIR"/installation_id "$CODEX_DIR"/session_index.jsonl; do
        [[ -e "$p" ]] || continue
        mode=$(file_mode "$p")
        SENSITIVE_FILES+=("$(basename "$p")|$mode|$p")
        if [[ "$(basename "$p")" == "auth.json" && "$mode" != "600" && "$mode" != "400" ]]; then
            add_finding "WARN" "Sensitive Files" "auth.json permissions are broader than owner-only" "mode=$mode"
        else
            add_finding "INFO" "Sensitive Files" "$(basename "$p") present" "mode=$mode"
        fi
    done
    for p in "$CODEX_DIR"/browser/config.toml "$CODEX_DIR"/computer-use/config.json "$CODEX_DIR"/chrome-native-hosts.json "$CODEX_DIR"/chrome-native-hosts-v2.json; do
        [[ -e "$p" ]] || continue
        mode=$(file_mode "$p")
        SENSITIVE_FILES+=("$(basename "$p")|$mode|$p")
        add_finding "REVIEW" "Execution Config" "Browser or Computer Use configuration found" "$p; mode=$mode"
    done
    while IFS= read -r p; do
        [[ -e "$p" ]] || continue
        size=$(stat -f '%z' "$p" 2>/dev/null || echo 0)
        add_finding "INFO" "Local Data" "$(basename "$p") present" "$(fmt_bytes "$size")"
        ((size > 104857600)) && add_finding "REVIEW" "Local Data" "$(basename "$p") is larger than 100 MB" "$(fmt_bytes "$size")"
    done < <(find "$CODEX_DIR" -maxdepth 2 -type f \( -name '*.sqlite' -o -name '*.sqlite-wal' -o -name '*.db' -o -name '*.db-wal' \) -print 2>/dev/null | sort)
}

collect_retention() {
    local name dir count bytes latest
    for name in sessions archived_sessions shell_snapshots ambient-suggestions; do
        dir="$CODEX_DIR/$name"
        [[ -d "$dir" ]] || continue
        count="$(dir_file_count "$dir")"
        bytes="$(dir_total_bytes "$dir")"
        latest="$(dir_latest_mtime "$dir")"
        RETENTION_ITEMS+=("$name|$count|$bytes|$latest|$dir")
        add_finding "INFO" "Retention" "$name contains $count file(s)" "size=$(fmt_bytes "$bytes"); latest=${latest:-none}"
        ((bytes > 104857600)) && add_finding "REVIEW" "Retention" "$name retained data is larger than 100 MB" "$(fmt_bytes "$bytes")"
        ((count > 1000)) && add_finding "REVIEW" "Retention" "$name contains more than 1000 files" "$count files"
    done
}

collect_runtime() {
    local out count line la_dir plist crons
    out=$(pgrep -fl 'Codex|codex' 2>/dev/null) || true
    if [[ -n "$out" ]]; then
        count=$(printf '%s\n' "$out" | sed '/^[[:space:]]*$/d' | wc -l | tr -d ' ')
        RUNTIME_ITEMS+=("processes|$count")
        add_finding "INFO" "Runtime" "Codex-related process(es) running: $count"
    fi

    if command -v pmset >/dev/null 2>&1; then
        pmset -g assertions 2>/dev/null | while IFS= read -r line; do
            [[ "${(L)line}" == *codex* ]] && add_finding "WARN" "Runtime" "Codex-related sleep assertion found" "$line"
        done
    fi

    la_dir="$HOME_DIR/Library/LaunchAgents"
    for plist in "$la_dir"/*codex* "$la_dir"/*Codex*; do
        [[ -e "$plist" ]] || continue
        add_finding "WARN" "Runtime" "Codex LaunchAgent found" "$(basename "$plist")"
    done

    crons=$(crontab -l 2>/dev/null) || true
    if [[ -n "$crons" ]]; then
        while IFS= read -r line; do
            [[ "${(L)line}" == *codex* ]] && add_finding "WARN" "Runtime" "Codex-related crontab entry found" "$line"
        done <<< "$crons"
    fi
}

print_table_line() {
    printf '  %-18s %s\n' "$1" "$2"
}

render_terminal() {
    print -r -- ""
    print -r -- "CODEX-AUDIT v$VERSION - Codex local security audit"
    print -r -- "User: $(display_text "$AUDIT_USER")"
    print -r -- "Codex home: $(display_text "$CODEX_DIR")"
    print -r -- "Findings: WARN=$WARN_COUNT REVIEW=$REVIEW_COUNT INFO=$INFO_COUNT"
    print -r -- ""

    if [[ "$OPT_QUIET" != "true" || $WARN_COUNT -gt 0 || $REVIEW_COUNT -gt 0 ]]; then
        print -r -- "Findings"
        for ((i=0; i<${#FINDING_SEV[@]}; i++)); do
            [[ "$OPT_QUIET" == "true" && "${FINDING_SEV[$i]}" == "INFO" ]] && continue
            printf '  [%s] %-16s %s\n' "${FINDING_SEV[$i]}" "${FINDING_SECT[$i]}" "$(display_text "${FINDING_MSG[$i]}")"
            [[ -n "${FINDING_DET[$i]}" ]] && printf '       %s\n' "$(display_text "${FINDING_DET[$i]}")"
        done
        print -r -- ""
    fi

    print -r -- "MCP Servers"
    if ((${#MCP_NAMES[@]} == 0)); then
        print -r -- "  none"
    else
        for name in "${MCP_NAMES[@]}"; do
            print_table_line "$name" "$(display_text "cmd=${MCP_CMDS[$name]:-unknown} env=${MCP_ENVKEYS[$name]:-none}")"
        done
    fi
    print -r -- ""

    print -r -- "Plugins"
    if ((${#PLUGINS[@]} == 0 && ${#PLUGIN_DETAILS[@]} == 0)); then
        print -r -- "  none"
    else
        for row in "${PLUGINS[@]}"; do print_table_line "${row%%|*}" "$(display_text "enabled=${row#*|}")"; done
        for row in "${PLUGIN_DETAILS[@]}"; do
            local n="${row%%|*}" rest="${row#*|}"
            print_table_line "$n" "$(display_text "$rest")"
        done
    fi
    print -r -- ""

    print -r -- "App Policies"
    if ((${#APP_POLICIES[@]} == 0)); then print -r -- "  none"; else
        for row in "${APP_POLICIES[@]}"; do print_table_line "${row%%|*}" "$(display_text "${row#*|}")"; done
    fi
    print -r -- ""

    print -r -- "Trusted Projects"
    if ((${#TRUSTED_PROJECTS[@]} == 0)); then print -r -- "  none"; else
        for row in "${TRUSTED_PROJECTS[@]}"; do print_table_line "$(display_text "${row%%|*}")" "$(display_text "trust_level=${row#*|}")"; done
    fi
    print -r -- ""

    print -r -- "Hooks and Rules"
    if ((${#HOOK_SOURCES[@]} == 0 && ${#RULE_FILES[@]} == 0)); then print -r -- "  none"; else
        for row in "${HOOK_SOURCES[@]}"; do print_table_line "hook" "$(display_text "$row")"; done
        for row in "${RULE_FILES[@]}"; do print_table_line "rule" "$(display_text "$row")"; done
    fi
    print -r -- ""

    print -r -- "Automations"
    if ((${#AUTOMATIONS[@]} == 0)); then print -r -- "  none"; else
        for row in "${AUTOMATIONS[@]}"; do
            local id="${row%%|*}" rest="${row#*|}"
            print_table_line "$id" "$(display_text "$rest")"
        done
    fi
    print -r -- ""

    print -r -- "Skills"
    if ((${#SKILLS[@]} == 0)); then print -r -- "  none"; else
        for row in "${SKILLS[@]}"; do
            local n="${row%%|*}" rest="${row#*|}"
            print_table_line "$n" "$(display_text "$rest")"
        done
    fi
    print -r -- ""

    print -r -- "Retention"
    if ((${#RETENTION_ITEMS[@]} == 0)); then print -r -- "  none"; else
        for row in "${RETENTION_ITEMS[@]}"; do
            local n="${row%%|*}" rest="${row#*|}"
            print_table_line "$n" "$(display_text "$rest")"
        done
    fi
    print -r -- ""
}

render_summary_terminal() {
    printf '%s  WARN=%d REVIEW=%d INFO=%d  %s\n' "$(display_text "$AUDIT_USER")" "$WARN_COUNT" "$REVIEW_COUNT" "$INFO_COUNT" "$(display_text "$CODEX_DIR")"
    local i shown=0
    for ((i=0; i<${#FINDING_SEV[@]}; i++)); do
        [[ "${FINDING_SEV[$i]}" == "INFO" ]] && continue
        printf '  [%s] %s: %s\n' "${FINDING_SEV[$i]}" "${FINDING_SECT[$i]}" "$(display_text "${FINDING_MSG[$i]}")"
        ((shown++))
        ((shown >= 8)) && break
    done
}

json_array_rows() {
    local -a rows
    rows=("$@")
    local out="[" row idx=0
    for row in "${rows[@]}"; do
        ((idx > 0)) && out+=","
        out+="$(jstr "$row")"
        ((idx++))
    done
    out+="]"
    printf '%s' "$out"
}

json_split_field() {
    local row="$1" n="$2" rest="$row" part i
    for ((i=1; i<n; i++)); do
        part="${rest%%|*}"
        rest="${rest#*|}"
    done
    printf '%s' "${rest%%|*}"
}

json_plugins_enabled() {
    local out="[" idx=0 row name enabled
    for row in "${PLUGINS[@]}"; do
        name="${row%%|*}"
        enabled="${row#*|}"
        ((idx > 0)) && out+=","
        out+="{\"id\":$(jstr_out "$name"),\"enabled\":$(jstr "$enabled")}"
        ((idx++))
    done
    out+="]"
    printf '%s' "$out"
}

json_plugin_cache() {
    local out="[" idx=0 row
    for row in "${PLUGIN_DETAILS[@]}"; do
        ((idx > 0)) && out+=","
        out+="{\"name\":$(jstr_out "$(json_split_field "$row" 1)"),\"version\":$(jstr "$(json_split_field "$row" 2)"),\"publisher\":$(jstr "$(json_split_field "$row" 3)"),\"marketplace\":$(jstr "$(json_split_field "$row" 4)"),\"path\":$(jstr_out "$(json_split_field "$row" 5)"),\"provenance\":$(jstr "$(json_split_field "$row" 6)"),\"signature_artifacts\":$(jstr_out "$(json_split_field "$row" 7)")}"
        ((idx++))
    done
    out+="]"
    printf '%s' "$out"
}

json_key_values() {
    local out="[" idx=0 row key val key_name="$1" val_name="$2"
    shift 2
    for row in "$@"; do
        key="${row%%|*}"
        val="${row#*|}"
        ((idx > 0)) && out+=","
        out+="{\"$key_name\":$(jstr_out "$key"),\"$val_name\":$(jstr_out "$val")}"
        ((idx++))
    done
    out+="]"
    printf '%s' "$out"
}

json_skills() {
    local out="[" idx=0 row
    for row in "${SKILLS[@]}"; do
        ((idx > 0)) && out+=","
        out+="{\"name\":$(jstr_out "$(json_split_field "$row" 1)"),\"source\":$(jstr_out "$(json_split_field "$row" 2)"),\"description\":$(jstr "$(json_split_field "$row" 3)"),\"path\":$(jstr_out "$(json_split_field "$row" 4)")}"
        ((idx++))
    done
    out+="]"
    printf '%s' "$out"
}

json_automations() {
    local out="[" idx=0 row
    for row in "${AUTOMATIONS[@]}"; do
        ((idx > 0)) && out+=","
        out+="{\"id\":$(jstr_out "$(json_split_field "$row" 1)"),\"name\":$(jstr_out "$(json_split_field "$row" 2)"),\"kind\":$(jstr "$(json_split_field "$row" 3)"),\"status\":$(jstr "$(json_split_field "$row" 4)"),\"rrule\":$(jstr "$(json_split_field "$row" 5)"),\"model\":$(jstr "$(json_split_field "$row" 6)"),\"execution_environment\":$(jstr "$(json_split_field "$row" 7)"),\"cwds\":$(jstr_out "$(json_split_field "$row" 8)"),\"risk_tags\":$(jstr "$(json_split_field "$row" 9)")}"
        ((idx++))
    done
    out+="]"
    printf '%s' "$out"
}

json_hook_sources() {
    local out="[" idx=0 row
    for row in "${HOOK_SOURCES[@]}"; do
        ((idx > 0)) && out+=","
        out+="{\"layer\":$(jstr_out "$(json_split_field "$row" 1)"),\"kind\":$(jstr "$(json_split_field "$row" 2)"),\"detail\":$(jstr_out "$(json_split_field "$row" 3)")}"
        ((idx++))
    done
    out+="]"
    printf '%s' "$out"
}

json_sensitive_files() {
    local out="[" idx=0 row
    for row in "${SENSITIVE_FILES[@]}"; do
        ((idx > 0)) && out+=","
        out+="{\"name\":$(jstr "$(json_split_field "$row" 1)"),\"mode\":$(jstr "$(json_split_field "$row" 2)"),\"path\":$(jstr_out "$(json_split_field "$row" 3)")}"
        ((idx++))
    done
    out+="]"
    printf '%s' "$out"
}

json_retention() {
    local out="[" idx=0 row
    for row in "${RETENTION_ITEMS[@]}"; do
        ((idx > 0)) && out+=","
        out+="{\"name\":$(jstr "$(json_split_field "$row" 1)"),\"file_count\":$(jstr "$(json_split_field "$row" 2)"),\"bytes\":$(jstr "$(json_split_field "$row" 3)"),\"latest_mtime\":$(jstr "$(json_split_field "$row" 4)"),\"path\":$(jstr_out "$(json_split_field "$row" 5)")}"
        ((idx++))
    done
    out+="]"
    printf '%s' "$out"
}

render_json() {
    local findings="[" idx=0
    for ((i=0; i<${#FINDING_SEV[@]}; i++)); do
        ((idx > 0)) && findings+=","
        findings+="{\"severity\":$(jstr "${FINDING_SEV[$i]}"),\"section\":$(jstr "${FINDING_SECT[$i]}"),\"message\":$(jstr_out "${FINDING_MSG[$i]}"),\"detail\":$(jstr_out "${FINDING_DET[$i]}")}"
        ((idx++))
    done
    findings+="]"

    local mcp="["
    idx=0
    for name in "${MCP_NAMES[@]}"; do
        ((idx > 0)) && mcp+=","
        mcp+="{\"name\":$(jstr_out "$name"),\"command\":$(jstr_out "${MCP_CMDS[$name]:-}"),\"args\":$(jstr_out "${MCP_ARGS[$name]:-}"),\"url\":$(jstr_out "${MCP_URLS[$name]:-}"),\"enabled\":$(jstr "${MCP_ENABLED[$name]:-true}"),\"approval_modes\":$(jstr "${MCP_APPROVALS[$name]:-}"),\"env_keys\":$(jstr "${MCP_ENVKEYS[$name]:-}"),\"env_risk_tags\":$(jstr "$(mcp_env_risk_tags "${MCP_ENVKEYS[$name]:-}")")}"
        ((idx++))
    done
    mcp+="]"

    printf '{"timestamp":%s,"hostname":%s,"username":%s,"codex_dir":%s,"summary":{"warn":%d,"review":%d,"info":%d},"findings":%s,"config_layers":%s,"mcp_servers":%s,"plugins":%s,"plugin_cache":%s,"marketplaces":%s,"apps":%s,"app_policies":%s,"trusted_projects":%s,"hooks":%s,"rules":%s,"instruction_files":%s,"skills":%s,"automations":%s,"sensitive_files":%s,"retention":%s}' \
        "$(jstr "$TIMESTAMP")" "$(jstr "$HOSTNAME_VAL")" "$(jstr_out "$AUDIT_USER")" "$(jstr_out "$CODEX_DIR")" \
        "$WARN_COUNT" "$REVIEW_COUNT" "$INFO_COUNT" "$findings" "$(json_key_values layer path "${CONFIG_LAYERS[@]}")" "$mcp" \
        "$(json_plugins_enabled)" "$(json_plugin_cache)" "$(json_key_values name source "${MARKETPLACES[@]}")" \
        "$(json_key_values id enabled "${APPS[@]}")" "$(json_key_values id policy "${APP_POLICIES[@]}")" "$(json_key_values path trust_level "${TRUSTED_PROJECTS[@]}")" \
        "$(json_hook_sources)" "$(json_key_values layer path "${RULE_FILES[@]}")" "$(json_key_values layer path "${INSTRUCTION_FILES[@]}")" "$(json_skills)" \
        "$(json_automations)" "$(json_sensitive_files)" "$(json_retention)"
}

html_rows_findings() {
    local i
    for ((i=0; i<${#FINDING_SEV[@]}; i++)); do
        [[ "$OPT_QUIET" == "true" && "${FINDING_SEV[$i]}" == "INFO" ]] && continue
        printf '<tr><td><span class="badge %s">%s</span></td><td>%s</td><td>%s</td><td><code>%s</code></td></tr>\n' \
            "$(html_escape "${(L)FINDING_SEV[$i]}")" "$(html_escape "${FINDING_SEV[$i]}")" "$(html_escape "${FINDING_SECT[$i]}")" "$(html_out "${FINDING_MSG[$i]}")" "$(html_out "${FINDING_DET[$i]}")"
    done
}

html_list_rows() {
    local title="$1"
    shift
    printf '<h2>%s</h2>\n<table><tbody>\n' "$(html_escape "$title")"
    local row first rest
    if (($# == 0)); then
        print -r -- '<tr><td>none</td><td></td></tr>'
    else
        for row in "$@"; do
            first="${row%%|*}"
            rest="${row#*|}"
            printf '<tr><td>%s</td><td><code>%s</code></td></tr>\n' "$(html_out "$first")" "$(html_out "$rest")"
        done
    fi
    print -r -- '</tbody></table>'
}

render_html_body() {
    cat <<EOF
<section class="report">
<h1>CODEX-AUDIT</h1>
<p class="meta">User: <strong>$(html_out "$AUDIT_USER")</strong> · Host: <strong>$(html_escape "$HOSTNAME_VAL")</strong> · Generated: <strong>$(html_escape "$TIMESTAMP")</strong></p>
<p class="meta">Codex home: <code>$(html_out "$CODEX_DIR")</code></p>
<div class="summary">
  <div><span>WARN</span><strong>$WARN_COUNT</strong></div>
  <div><span>REVIEW</span><strong>$REVIEW_COUNT</strong></div>
  <div><span>INFO</span><strong>$INFO_COUNT</strong></div>
</div>
<h2>Findings</h2>
<table><thead><tr><th>Severity</th><th>Section</th><th>Finding</th><th>Detail</th></tr></thead><tbody>
EOF
    html_rows_findings
    cat <<EOF
</tbody></table>
<h2>MCP Servers</h2>
<table><thead><tr><th>Name</th><th>Command</th><th>Args</th><th>Env Keys</th></tr></thead><tbody>
EOF
    if ((${#MCP_NAMES[@]} == 0)); then
        print -r -- '<tr><td>none</td><td></td><td></td><td></td></tr>'
    else
        local name
        for name in "${MCP_NAMES[@]}"; do
            printf '<tr><td>%s</td><td><code>%s</code></td><td><code>%s</code></td><td><code>%s</code></td></tr>\n' \
                "$(html_out "$name")" "$(html_out "${MCP_CMDS[$name]:-}")" "$(html_out "${MCP_ARGS[$name]:-}")" "$(html_escape "${MCP_ENVKEYS[$name]:-}")"
        done
    fi
    print -r -- '</tbody></table>'
    html_list_rows "Enabled Plugins" "${PLUGINS[@]}"
    html_list_rows "Plugin Cache" "${PLUGIN_DETAILS[@]}"
    html_list_rows "App Policies" "${APP_POLICIES[@]}"
    html_list_rows "Trusted Projects" "${TRUSTED_PROJECTS[@]}"
    html_list_rows "Config Layers" "${CONFIG_LAYERS[@]}"
    html_list_rows "Hooks" "${HOOK_SOURCES[@]}"
    html_list_rows "Rules" "${RULE_FILES[@]}"
    html_list_rows "Instruction Files" "${INSTRUCTION_FILES[@]}"
    html_list_rows "Automations" "${AUTOMATIONS[@]}"
    html_list_rows "Skills" "${SKILLS[@]}"
    html_list_rows "Sensitive Files" "${SENSITIVE_FILES[@]}"
    html_list_rows "Retention" "${RETENTION_ITEMS[@]}"
    print -r -- '</section>'
}

render_html_doc_start() {
    cat <<'EOF'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CODEX-AUDIT Report</title>
<style>
body{margin:0;background:#101317;color:#e7edf3;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
main{max-width:1180px;margin:0 auto;padding:32px 20px}
h1{margin:0 0 8px;font-size:28px}
h2{margin:28px 0 10px;font-size:18px}
.report{border-top:1px solid #2a3340;padding:24px 0}
.meta{color:#aab6c4;margin:4px 0}
code{color:#d7e7ff;white-space:pre-wrap;word-break:break-word}
.summary{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;margin:20px 0}
.summary div{background:#171d24;border:1px solid #2a3340;border-radius:6px;padding:12px}
.summary span{display:block;color:#aab6c4;font-size:12px}
.summary strong{font-size:24px}
table{width:100%;border-collapse:collapse;background:#141920;border:1px solid #2a3340}
th,td{padding:9px 10px;border-bottom:1px solid #2a3340;text-align:left;vertical-align:top;font-size:13px}
th{color:#aab6c4;background:#171d24}
.badge{display:inline-block;border-radius:4px;padding:2px 6px;font-weight:700;font-size:12px}
.warn{background:#5c2e12;color:#ffd7b0}.review{background:#51450f;color:#fff0a3}.info{background:#173956;color:#bfe4ff}
</style>
</head>
<body><main>
EOF
}

render_html_doc_end() {
    print -r -- '</main></body></html>'
}

render_json_for_users() {
    if ((${#USERS[@]} == 1)); then
        audit_one_user "${USERS[0]}"
        render_json
    else
        printf '['
        for ((ui=0; ui<${#USERS[@]}; ui++)); do
            ((ui > 0)) && printf ','
            audit_one_user "${USERS[$ui]}"
            render_json
        done
        printf ']'
    fi
}

render_summary_json_for_users() {
    if ((${#USERS[@]} == 1)); then
        audit_one_user "${USERS[0]}"
        printf '{"timestamp":%s,"hostname":%s,"username":%s,"codex_dir":%s,"summary":{"warn":%d,"review":%d,"info":%d}}\n' \
            "$(jstr "$TIMESTAMP")" "$(jstr "$HOSTNAME_VAL")" "$(jstr_out "$AUDIT_USER")" "$(jstr_out "$CODEX_DIR")" "$WARN_COUNT" "$REVIEW_COUNT" "$INFO_COUNT"
    else
        printf '['
        for ((ui=0; ui<${#USERS[@]}; ui++)); do
            ((ui > 0)) && printf ','
            audit_one_user "${USERS[$ui]}"
            printf '{"timestamp":%s,"hostname":%s,"username":%s,"codex_dir":%s,"summary":{"warn":%d,"review":%d,"info":%d}}' \
                "$(jstr "$TIMESTAMP")" "$(jstr "$HOSTNAME_VAL")" "$(jstr_out "$AUDIT_USER")" "$(jstr_out "$CODEX_DIR")" "$WARN_COUNT" "$REVIEW_COUNT" "$INFO_COUNT"
        done
        printf ']\n'
    fi
}

render_diff_json() {
    local baseline="$1"
    if [[ "$HAS_JQ" != "true" ]]; then
        print -r -- "Error: --diff requires jq" >&2
        return 1
    fi
    if [[ ! -r "$baseline" ]]; then
        print -r -- "Error: cannot read baseline: $baseline" >&2
        return 1
    fi
    local current_json
    current_json="$(render_json_for_users)"
    jq --argjson current "$current_json" '
      def arr(x): if x == null then [] elif (x|type) == "array" then x else [x] end;
      def keys_for($doc; $path; $field):
        [arr($doc)[] | getpath($path)? // [] | .[]? | .[$field] // empty] | unique;
      def skill_keys($doc):
        [arr($doc)[] | .skills[]? | ((.source // "") + ":" + (.name // ""))] | unique;
      def pair_keys($doc; $path; $a; $b):
        [arr($doc)[] | getpath($path)? // [] | .[]? | ((.[$a] // "") + ":" + (.[$b] // ""))] | unique;
      def section($name; $old; $new):
        {
          section: $name,
          added: (($new - $old) | sort),
          removed: (($old - $new) | sort)
        };
      . as $base
      | [
          section("mcp_servers"; keys_for($base; ["mcp_servers"]; "name"); keys_for($current; ["mcp_servers"]; "name")),
          section("plugins"; keys_for($base; ["plugins"]; "id"); keys_for($current; ["plugins"]; "id")),
          section("apps"; keys_for($base; ["apps"]; "id"); keys_for($current; ["apps"]; "id")),
          section("app_policies"; pair_keys($base; ["app_policies"]; "id"; "policy"); pair_keys($current; ["app_policies"]; "id"; "policy")),
          section("trusted_projects"; keys_for($base; ["trusted_projects"]; "path"); keys_for($current; ["trusted_projects"]; "path")),
          section("config_layers"; keys_for($base; ["config_layers"]; "path"); keys_for($current; ["config_layers"]; "path")),
          section("hooks"; pair_keys($base; ["hooks"]; "layer"; "detail"); pair_keys($current; ["hooks"]; "layer"; "detail")),
          section("rules"; keys_for($base; ["rules"]; "path"); keys_for($current; ["rules"]; "path")),
          section("automations"; keys_for($base; ["automations"]; "id"); keys_for($current; ["automations"]; "id")),
          section("skills"; skill_keys($base); skill_keys($current))
        ]
      | {changed: map(select((.added|length) > 0 or (.removed|length) > 0))}
      | . + {has_changes: ((.changed | length) > 0)}
    ' "$baseline"
}

render_diff() {
    local diff_json
    diff_json="$(render_diff_json "$1")" || return 1
    if [[ "$OPT_DIFF_JSON" == "true" ]]; then
        print -r -- "$diff_json"
        return 0
    fi
    jq -r '
      .changed
      | if length == 0 then
          "No baseline differences detected."
        else
          .[] | (
            "## " + .section,
            (if (.added|length) > 0 then "Added:\n" + (.added | map("  + " + .) | join("\n")) else empty end),
            (if (.removed|length) > 0 then "Removed:\n" + (.removed | map("  - " + .) | join("\n")) else empty end)
          )
        end
    ' <<< "$diff_json"
}

usage() {
    print -r -- "CODEX-AUDIT v$VERSION - Codex local security audit"
    print -r -- "Usage: $SCRIPT_NAME [--html [FILE]] [--json] [--summary] [--output FILE] [--diff BASELINE.json] [--diff-json] [--fail-on warn|review] [--redact-paths] [--user USER] [--all-users] [--codex-dir DIR] [-q|--quiet] [--version] [-h|--help]"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --json) OPT_JSON=true ;;
        --diff) shift; OPT_DIFF="${1:-}" ;;
        --diff-json) OPT_DIFF_JSON=true ;;
        --fail-on) shift; OPT_FAIL_ON="${1:-}" ;;
        --output) shift; OPT_OUTPUT="${1:-}" ;;
        --summary) OPT_SUMMARY=true ;;
        --codex-dir) shift; OPT_CODEX_DIR="${1:-}" ;;
        --redact-paths) OPT_REDACT_PATHS=true ;;
        --html)
            if [[ -n "${2:-}" && "$2" != -* ]]; then
                OPT_HTML="$2"
                shift
            else
                OPT_HTML="AUTO"
            fi
            ;;
        -q|--quiet) OPT_QUIET=true ;;
        --user) shift; AUDIT_USER="${1:-}" ;;
        --all-users) OPT_ALL_USERS=true ;;
        --version) print -r -- "CODEX-AUDIT v$VERSION"; exit 0 ;;
        -h|--help) usage; exit 0 ;;
        *) print -r -- "Unknown option: $1" >&2; usage >&2; exit 1 ;;
    esac
    shift
done

preflight

if [[ -n "$OPT_DIFF" && -n "$OPT_HTML" ]]; then
    print -r -- "Error: --diff and --html are mutually exclusive" >&2
    exit 1
fi
if [[ -n "$OPT_DIFF" && "$OPT_JSON" == "true" ]]; then
    if [[ "$OPT_DIFF_JSON" != "true" ]]; then
        print -r -- "Error: --diff and --json are mutually exclusive; use --diff-json for JSON diff output" >&2
        exit 1
    fi
fi
if [[ "$OPT_DIFF_JSON" == "true" && -z "$OPT_DIFF" ]]; then
    print -r -- "Error: --diff-json requires --diff BASELINE.json" >&2
    exit 1
fi
if [[ "$OPT_JSON" == "true" && -n "$OPT_HTML" ]]; then
    print -r -- "Error: --json and --html are mutually exclusive" >&2
    exit 1
fi
if [[ "$OPT_ALL_USERS" == "true" && -n "$AUDIT_USER" ]]; then
    print -r -- "Error: --user and --all-users are mutually exclusive" >&2
    exit 1
fi
if [[ -n "$OPT_CODEX_DIR" && "$OPT_ALL_USERS" == "true" ]]; then
    print -r -- "Error: --codex-dir and --all-users are mutually exclusive" >&2
    exit 1
fi
if [[ -n "$OPT_CODEX_DIR" && ! -d "$OPT_CODEX_DIR" ]]; then
    print -r -- "Error: --codex-dir does not exist: $OPT_CODEX_DIR" >&2
    exit 1
fi
if [[ -z "$OPT_HTML" && -n "$OPT_OUTPUT" && "$OPT_OUTPUT" == *.html ]]; then
    print -r -- "Error: --output .html requires --html" >&2
    exit 1
fi
case "$OPT_FAIL_ON" in
    ""|warn|review) ;;
    *) print -r -- "Error: --fail-on must be 'warn' or 'review'" >&2; exit 1 ;;
esac

audit_one_user() {
    local user="$1"
    reset_state
    AUDIT_USER="$user"
    HOME_DIR="$(get_user_home "$AUDIT_USER")"
    if [[ -z "$HOME_DIR" || ! -d "$HOME_DIR" ]]; then
        add_finding "WARN" "General" "Unable to resolve home directory" "$AUDIT_USER"
        CODEX_DIR=""
        return 0
    fi

    if [[ -n "$OPT_CODEX_DIR" ]]; then
        CODEX_DIR="$OPT_CODEX_DIR"
        HOME_DIR="${CODEX_DIR:h}"
    else
        CODEX_DIR="$HOME_DIR/$CODEX_DIR_NAME"
    fi
    TIMESTAMP="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    HOSTNAME_VAL="$(hostname)"

    if [[ ! -d "$CODEX_DIR" ]]; then
        add_finding "INFO" "General" "Codex directory not found" "$CODEX_DIR"
    else
        collect_config
        collect_plugin_cache
        collect_policy_files
        finalize_config_findings
        collect_skills
        collect_automations
        collect_sensitive_files
        collect_retention
        collect_runtime
    fi
}

USERS=()
if [[ "$OPT_ALL_USERS" == "true" ]]; then
    USERS=("${(@f)$(discover_codex_users)}")
    if ((${#USERS[@]} == 0)); then
        print -r -- "No users with Codex data found." >&2
        exit 1
    fi
else
    [[ -z "$AUDIT_USER" ]] && AUDIT_USER="$(id -un)"
    USERS=("$AUDIT_USER")
fi

FINAL_EXIT=0
apply_fail_on() {
    [[ -z "$OPT_FAIL_ON" ]] && return 0
    if [[ "$OPT_FAIL_ON" == "warn" && "$WARN_COUNT" -gt 0 ]]; then
        FINAL_EXIT=2
    elif [[ "$OPT_FAIL_ON" == "review" && "$REVIEW_COUNT" -gt 0 && "$FINAL_EXIT" -eq 0 ]]; then
        FINAL_EXIT=1
    fi
}

run_output() {
    if [[ -n "$OPT_DIFF" ]]; then
        render_diff "$OPT_DIFF"
    elif [[ "$OPT_JSON" == "true" ]]; then
        if [[ "$OPT_SUMMARY" == "true" ]]; then
            render_summary_json_for_users
        else
            render_json_for_users
            print -r -- ""
        fi
    elif [[ -n "$OPT_HTML" ]]; then
        render_html_doc_start
        for user in "${USERS[@]}"; do
            audit_one_user "$user"
            render_html_body
        done
        render_html_doc_end
    else
        for user in "${USERS[@]}"; do
            audit_one_user "$user"
            if [[ "$OPT_SUMMARY" == "true" ]]; then
                render_summary_terminal
            else
                render_terminal
            fi
            apply_fail_on
        done
    fi
}

if [[ -n "$OPT_HTML" ]]; then
    local_html_file="${OPT_OUTPUT:-$OPT_HTML}"
    if [[ "$local_html_file" == "AUTO" ]]; then
        local_html_file="codex_audit_$(date '+%Y%m%d_%H%M%S').html"
    fi
    umask 077
    run_output > "$local_html_file"
    print -r -- "HTML report written: $local_html_file"
elif [[ -n "$OPT_OUTPUT" ]]; then
    run_output > "$OPT_OUTPUT"
else
    run_output
fi

if [[ "$OPT_JSON" == "true" || -n "$OPT_HTML" ]]; then
    for user in "${USERS[@]}"; do
        audit_one_user "$user"
        apply_fail_on
    done
fi

exit "$FINAL_EXIT"
