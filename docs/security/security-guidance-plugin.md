# security-guidance プラグイン (in-session コードレビュー層)

Anthropic 公式プラグイン `security-guidance@claude-plugins-official` の導入記録と、
既存セキュリティ実装との棲み分けの正典。対象は 3 リポ共通
(`obsidian-ai-pipeline` / `pipeline-youtube` / `pipeline-youtube-SDK`)。

公式ドキュメント: <https://code.claude.com/docs/en/security-guidance>

## 何をするプラグインか

**Claude Code が書いたコードの脆弱性を、Claude 自身に同一セッション内で
レビュー・修正させる**。hooks のみで構成され、導入後は自動で動く (呼び出し不要)。

| タイミング | 内容 | コスト |
|---|---|---|
| 各ファイル編集時 (PostToolUse) | 危険パターンの文字列マッチ (`eval` / `child_process.exec` / `os.system` / `pickle` / `innerHTML` / `.github/workflows/` 編集 等) | モデル呼び出しなし (無料) |
| 各ターン終了時 (Stop) | そのターンの git diff 全体を**別コンテキストの Claude** がバックグラウンドでレビュー (認可バイパス / IDOR / injection / SSRF / 弱い暗号等)。最大 30 ファイル/ターン、連続 3 回まで | モデル課金あり |
| Claude の git commit/push 時 | 周辺コード (呼び出し元・サニタイザ) まで読む agentic レビュー。20 回/時上限。**人間が自分のシェルから行う commit は対象外** | モデル課金あり |

## 各リポでの有効化 (導入済み)

各リポの `.claude/settings.json` (checked-in) に宣言済み。ユーザースコープの
`/plugin install` と違い、**Claude Code on the web のセッションでも有効になる**:

```json
{
  "enabledPlugins": {
    "security-guidance@claude-plugins-official": true
  }
}
```

ローカル CLI で使う場合は初回に marketplace の追加が要ることがある:
`/plugin marketplace add anthropics/claude-plugins-official`。

## リポ固有の脅威モデル注入 (導入済み)

各リポの `.claude/claude-security-guidance.md` が、モデルレビュー (ターン終了時 /
commit 時) に追加コンテキストとして読み込まれる (合計 8KB 上限・追加のみ):

- `obsidian-ai-pipeline`: nonce デリミタによる untrusted テキスト隔離 /
  ゲートの fail-closed 不変条件 / span_sha1 のみのログ / SHA pin 済み workflows
- `pipeline-youtube`: `wrap_untrusted` サニタイズ境界 / フィンガープリントのみのログ /
  Docker capture サンドボックス / `.githooks` 管理
- `pipeline-youtube-SDK`: 上記 + `providers/registry.py` 経由のキー払い出し /
  CODEOWNERS 保護パス

**メンテナンス**: 新しい trust boundary・サニタイズ関数・サンドボックスを追加した PR では、
同じ PR で該当リポの `claude-security-guidance.md` も更新する
(CLAUDE.md の secret-pattern 3 系統同期 SLA と同じ発想)。

## 既存セキュリティ実装との棲み分け (置き換えではない)

プラグインは**助言のみでブロックしない** (公式明記: "None of the layers block writes
or commits" / "not a complete security solution")。既存の機械的 deny 層とは守備範囲が
異なり、**全て維持する**:

| 防御 | 担当 | プラグインで代替可? |
|---|---|---|
| Claude が書くアプリコードの脆弱性 (injection / XSS / unsafe eval 等) | **本プラグイン** (新設層) | — |
| secret egress の実行前 deny | `block-secret-egress.{cjs,py}` (PreToolUse) | 不可 (プラグインは非ブロッキング) |
| 秘密ファイルの add/commit・`git add -A`・`--no-verify` の deny | `block-secret-git.cjs` / `block-git-add-all.cjs` / gitleaks | 不可 |
| 脅威レポート取込の injection ゲート | `scan-threat-report` + `gate_decision.py` | 不可 |
| Gmail MCP の都度承認バリア | CLAUDE.md ハードルール | 不可 |
| サプライチェーン (SHA pin / pip-audit / Trivy / CodeQL / CODEOWNERS) | CI + リポ設定 | 不可 (公式が「試みない領域」と明記) |
| メディア処理の実行分離 | Docker capture backend | 不可 |

段階の関係 (公式の defense-in-depth スタック): 本プラグイン (in-session) →
`/security-review` (on-demand) → Code Review (PR) → CI スキャナ。

## 動作要件・調整

- git リポ内でのみモデルレビューが動く。Python 3.8+ が必要 (初回に
  `~/.claude/security/` へ venv を作成)。診断ログ: `~/.claude/security/log.txt`
- レビューモデル既定は Opus 系。`SECURITY_REVIEW_MODEL` (ターン終了時) /
  `SG_AGENTIC_MODEL` (commit 時) で変更可
- 層別の無効化: `ENABLE_PATTERN_RULES=0` / `ENABLE_STOP_REVIEW=0` /
  `ENABLE_COMMIT_REVIEW=0`、全停止は `SECURITY_GUIDANCE_DISABLE=1`
- 独自の決定論パターンを足す場合は `.claude/security-patterns.yaml`
  (regex/substring、50 件まで)。ただし**非ブロッキングの警告**であり、
  deny が要る規則は既存の PreToolUse hooks 側に足すこと
