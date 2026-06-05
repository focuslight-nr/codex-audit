# CODEX-AUDIT

Codex のローカル設定を読み取り専用で監査する、macOS / Windows 向けの非公式ツールです。

> CODEX-AUDIT は独立した非公式プロジェクトです。OpenAI による提供、承認、スポンサー、保守を受けているものではありません。"OpenAI"、"Codex" および関連する製品名は OpenAI の商標である可能性があります。本 README では、ユーザーのローカル Codex 設定との相互運用性を説明する目的でのみ参照しています。

`codex_audit.sh` / `codex_audit.ps1` は `~/.codex` 配下のローカル状態を確認し、Codex の実行面に関係する設定をレポートします。対象には MCP サーバー、有効化されたプラグイン、アプリ連携、trusted project、skill、自動化、機密性の高いローカルファイル、ローカル履歴、実行中の状態などが含まれます。

このスクリプトは読み取り専用です。監査対象ファイルを変更しません。

## なぜ必要か

Codex は、ローカル MCP サーバー、プラグイン、アプリ連携、ブラウザ操作、Computer Use、trusted project、自動化タスクなどと接続できます。これらは便利な機能ですが、同時にローカル端末上にレビューすべき設定や状態を作ります。

CODEX-AUDIT は、そのローカル状態を 1 コマンドで一覧化し、確認すべきポイントを示します。

## クイックスタート

macOS:

```bash
git clone https://github.com/focuslight-nr/codex-audit.git
cd codex-audit
chmod +x codex_audit.sh
./codex_audit.sh
```

Windows PowerShell:

```powershell
git clone https://github.com/focuslight-nr/codex-audit.git
cd codex-audit
powershell -NoProfile -ExecutionPolicy Bypass -File .\codex_audit.ps1
```

サマリ表示:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\codex_audit.ps1 --summary
```

JSON 出力:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\codex_audit.ps1 --json
```

HTML レポート:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\codex_audit.ps1 --html --output codex-audit.html
```

## 出力例

サマリ出力の例:

```text
esp  WARN=9 REVIEW=12 INFO=24  ~/.codex
  [REVIEW] Plugins: Enabled Codex plugin: notion@openai-curated
  [REVIEW] Plugins: Enabled Codex plugin: google-drive@openai-curated
  [WARN] Desktop: Remote control keep-awake is enabled
  [WARN] Projects: Trusted project grants Codex broader workspace autonomy
```

テスト fixture の出力例:

```text
esp  WARN=4 REVIEW=6 INFO=6  ~/.codex
  [REVIEW] Config: config.toml is readable beyond the owner
  [REVIEW] Plugins: Enabled Codex plugin: custom-plugin@local-marketplace
  [WARN] MCP Servers: MCP server uses command-capable runtime: local_shell
  [REVIEW] Plugins: Plugin provenance requires review: custom-plugin
```

## 監査対象

| 領域 | 確認内容 |
| --- | --- |
| Config | `~/.codex/config.toml`、model、features、notification hook、未知 section |
| MCP Servers | サーバー名、command、args、env var key、env-key risk tag |
| Plugins | 有効化 plugin、cached package、metadata provenance |
| Signature Artifacts | `.sig`、`.asc`、`.pem`、`.crt`、`.minisig`、`.sigstore` など署名関連らしいファイルの有無 |
| Connectors | 有効化された app connector |
| Projects | `trusted` project |
| Skills | user / plugin の `SKILL.md` |
| Automations | `~/.codex/automations/*/automation.toml`、ACTIVE schedule、prompt risk tag |
| Sensitive Files | `auth.json`、global state、installation ID、session index |
| Local Data | SQLite DB / WAL file の存在、大きいファイルの REVIEW |
| Retention | session、archived session、shell snapshot、ambient suggestion の件数、サイズ、最新更新日時 |
| Runtime | 実行中 Codex process、macOS の sleep assertion / LaunchAgents / crontab、Windows scheduled task |

## Severity Model

| Severity | 意味 |
| --- | --- |
| WARN | Codex の実行面を広げる、または早めに確認すべき状態 |
| REVIEW | 人間の判断が必要な状態。正常な設定でもセキュリティ姿勢に関係するもの |
| INFO | inventory や baseline 用の文脈情報 |

finding はレビュー用のシグナルであり、侵害や脆弱性の証明ではありません。たとえば、有効化された plugin や trusted project は正当な設定であることもあります。CODEX-AUDIT は、それらを見えるようにして確認しやすくします。

## 使い方

通常の terminal report:

```bash
./codex_audit.sh
```

WARN / REVIEW を先に見たい場合:

```bash
./codex_audit.sh -q
```

サマリのみ:

```bash
./codex_audit.sh --summary
./codex_audit.sh --summary --json
```

ファイルへ直接出力:

```bash
./codex_audit.sh --json --output audit.json
./codex_audit.sh --summary --output summary.txt
./codex_audit.sh --html --output audit.html
```

共有用にユーザー固有 path を伏せる:

```bash
./codex_audit.sh --json --redact-paths
./codex_audit.sh --html --output audit.html --redact-paths
```

別のローカルユーザーを監査:

```bash
./codex_audit.sh --user USERNAME
```

`~/.codex` がある全ローカルユーザーを監査:

```bash
sudo ./codex_audit.sh --all-users
```

コピー済みまたは fixture の Codex directory を監査:

```bash
./codex_audit.sh --codex-dir /path/to/.codex
```

## Baseline Diff

baseline を作成:

```bash
./codex_audit.sh --json > baseline.json
```

現在の状態と比較:

```bash
./codex_audit.sh --diff baseline.json
```

機械処理しやすい JSON diff:

```bash
./codex_audit.sh --diff baseline.json --diff-json | jq .
```

diff の比較対象:

- MCP server name
- enabled plugin ID
- app connector ID
- trusted project path
- automation ID
- skill の `source:name`

`codex_audit.sh` の `--diff` と `--diff-json` には `jq` が必要です。PowerShell 版は標準の JSON 機能を使います。

## Policy Gate Mode

定期チェック、MDM、CI 風の policy gate では `--fail-on` を使えます。

```bash
./codex_audit.sh --fail-on warn
./codex_audit.sh --fail-on review
```

exit code:

- `0`: threshold finding なし
- `1`: REVIEW threshold に到達
- `2`: WARN threshold に到達

## 必要条件

- macOS: zsh
- Windows: Windows PowerShell 5.1 以降、または PowerShell 7 以降
- macOS 版の `--diff`、`--diff-json`、fixture test runner には `jq` が必要
- Windows PowerShell 版は JSON / diff に PowerShell 標準の JSON 機能を使うため、`jq` は不要

Homebrew で `jq` を入れる場合:

```bash
brew install jq
```

## テスト

fixture を使った smoke test:

```bash
tests/run.sh
```

Windows PowerShell:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\run.ps1
```

test runner は `--codex-dir tests/fixtures/basic/.codex` を使います。そのため、現在ユーザーの実際の Codex 設定には依存しません。

## セキュリティ特性

- 読み取り専用
- ネットワーク通信なし
- sensitive らしい config value は表示時に redaction
- MCP env value は表示せず、env var name のみ表示
- HTML output は `umask 077` により owner-only permission で作成
- `--redact-paths` による path redaction
- plugin provenance は metadata に基づく heuristic 分類であり、暗号学的な署名検証ではない
- signature artifact detection は署名関連らしいファイル名の存在確認のみであり、署名の妥当性は検証しない

## 現在のスコープと制限

解消または緩和済み:

- macOS の通常監査は `jq` なしでも動作。plugin metadata は path 由来の値に fallback
- `codex_audit.ps1` により Windows PowerShell での監査に対応
- 未知の `config.toml` section を INFO として表示し、format drift に気づけるようにしている
- `--codex-dir` により fixture / コピー済み Codex directory の監査に対応

残る制限:

- macOS と Windows の collector は別スクリプトで、OS 固有の runtime check には差分がある
- macOS 版の `--diff` と `--diff-json` には `jq` が必要
- plugin provenance は heuristic。CODEX-AUDIT は署名検証をしない
- signature-related artifact detection は存在確認のみ
- Codex の設定形式が変わる可能性がある。未知 section は表示するが、新しい意味づけには collector 更新が必要な場合がある

## ドキュメント

- [Findings Reference](docs/findings-reference.md)
- [License](LICENSE)
- [Notice](NOTICE)
- [English README](README.md)

## ライセンス

Apache License 2.0。詳細は [LICENSE](LICENSE) と [NOTICE](NOTICE) を参照してください。
