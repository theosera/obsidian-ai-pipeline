---
name: ops-logging
description: Claude Code UI で実行した git / shell / GitHub(MCP) 操作を「コマンド＋意図」だけ (secret 全マスク) 学習ログとして専用 private リポ (terminal-ops-logs) に push する仕組みの正典。PostToolUse hook で追記 → Stop hook で 1 回 push。**コマンド学習ログ機能を新リポへ導入する / hook 設定 (settings.json) を書く・直す / マスキング規則やログ出力先を変える / capture-command.sh・push-log.sh を触る前に必ずこの Skill をロードしてから**着手せよ。実際の自動実行は hook が担い、本 Skill は設定の母艦 (手順・規則・スニペット)。
# allowed-tools: 本 skill 自身のディレクトリ (hook スクリプト) の編集だけを事前許可する。
# `.claude/settings.json` (= ガード設定そのもの) の編集と Bash 実行は**通常の都度承認**に戻す
# — 「hook 設定を書く skill」をロードしただけでガード設定の書換えが無承認になるのを防ぐ。
allowed-tools: Read, Edit(./.claude/skills/ops-logging/**), Write(./.claude/skills/ops-logging/**)
---

# ops-logging

Claude Code UI 上で私が打つ **git / shell / GitHub(MCP) 操作**を、学習用の
**コマンド履歴**として Obsidian vault とは分離した専用 private リポ
**`terminal-ops-logs`** に貯める仕組み。CLAUDE.md の発火表から発火条件付きで
分離した「設定の正典」。**自動実行は hook が担う** (Skill は自動実行できない —
本 Skill は手順・規則・スニペットの母艦)。

## 設計の要点 (なぜこの形か)

- **記録は「コマンド＋意図」だけ。出力 (stdout) は記録しない。** `env` ダンプや
  token がログに乗る事故を構造的に防ぐ (3 リポ共通の「secret を絶対 commit しない」
  ハードルールの具体化)。
- **「意図」は無料で手に入る:** Bash ツールの `description` フィールド (私が毎回書く
  「何をするか」) を hook がそのまま意図として拾う。追加入力は不要。
- **push は Stop で 1 回だけ。** PostToolUse は追記のみ (push しない=軽い)、ターン
  終了時に Stop hook がまとめて commit & push。コミットが細切れにならない。
- **vault と分離。** 学習ログは git リポで完結させ、重い Obsidian vault に混ぜない。
  (必要なら `terminal-ops-logs` を Obsidian で別 vault として開けば Dataview 可。)

## 仕組み (1 セッションの流れ)

```
私が作業中…
 ├─ git switch -c ...        ┐ PostToolUse hook (matcher: Bash, mcp__github__*)
 ├─ git add classifier.ts   │→ capture-command.sh が
 ├─ git commit -m ...        │   <target_repo>/<date>.md に「コマンド＋意図」を 1 行追記
 └─ mcp__github__create_pr   ┘   (Bash=token/key/bearer をマスク / MCP=安全な
                                  メタデータ allowlist のみ。body/title/本文は捨てる)
私の応答が終わる
 └─ Stop hook → push-log.sh が変更を commit して terminal-ops-logs へ push
                (差分が無ければ no-op。push 失敗はターンをブロックしない)
```

## ログリポの構成 (`terminal-ops-logs`)

```
terminal-ops-logs/
├── README.md                         # コマンド早見表 (学習の母艦)
├── obsidian-ai-pipeline/<date>.md
├── claude_openai_mcp_connector/<date>.md
├── pipeline-youtube-SDK/<date>.md
└── misc/<date>.md                    # 上記以外の cwd
```

各 `<date>.md` 先頭の frontmatter: `date` / `target_repo` / `branch` / `tags`。
本文は `| time | branch | command | intent |` の Markdown テーブル。
→ Obsidian で開けば Dataview で「リポ別・ブランチ別」に一覧可。

## 新リポへの導入手順

1. **ログリポを clone** しておき、パスを環境変数で指す:
   `export OPS_LOG_REPO=/path/to/terminal-ops-logs` (既定 `$HOME/terminal-ops-logs`)。
   このリポが clone されていなければ hook は **何もしない (no-op)** ので安全。
2. **hook スクリプトを配置** (本 Skill 同梱の 2 本をそのまま使う):
   - `.claude/skills/ops-logging/capture-command.sh` (PostToolUse)
   - `.claude/skills/ops-logging/push-log.sh` (Stop)
3. **対象リポの `.claude/settings.json` に hook を登録** (下記スニペット)。
   配置方針は「対象リポ側」(そのリポで作業した時だけ発火)。
4. `jq` が必要 (hook が JSON payload を解析するため)。

### settings.json スニペット (対象リポ側に追記)

```jsonc
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Bash|mcp__github__.*",
        "hooks": [
          { "type": "command",
            "command": "bash \"$CLAUDE_PROJECT_DIR/.claude/skills/ops-logging/capture-command.sh\"",
            "timeout": 10 }
        ]
      }
    ],
    "Stop": [
      {
        "hooks": [
          { "type": "command",
            "command": "bash \"$CLAUDE_PROJECT_DIR/.claude/skills/ops-logging/push-log.sh\"",
            "timeout": 120 }
        ]
      }
    ]
  }
}
```

> `permissions.deny[]` (既存の secret 読取ブロック) とは別セクション。既存
> `settings.json` の `permissions` は残したまま `hooks` を**追加**する。

## マスキング規則 (capture-command.sh 内)

コマンド文字列に含まれうる以下を `***MASKED***` に置換してから記録する
(出力は元々記録しないが、コマンド自体に token が混ざる場合の保険):

- GitHub token: `gh[pousr]_…` / `github_pat_…`
- URL 埋め込み credential: `://user:pass@`
- `Bearer <token>` は**単位でマスク** (`Authorization: Bearer xxx` の token を残さない)
- `token=` / `key=` / `secret=` / `password=` / `authorization …`
- AWS `AKIA…` / OpenAI・Anthropic `sk-…` (`sk-proj-` 等のハイフン形含む)
- Google API key `AIza…` (Gmail / YouTube) / Slack `xox[baprs]-…`

新しい token 形式が増えたらこの規則とスクリプトの `mask()` を更新する
(マスク漏れはこの Skill の回帰なので、追加時は必ずここに 1 行追記)。

> **GitHub MCP 呼び出し (`mcp__github__*`) は別扱い**: `tool_input` 全体は記録せず、
> 構造メタデータの allowlist (`owner` / `repo` / `pullNumber` / `branch` / `path` /
> `method` 等) **のみ**を残す。PR/issue body・コメント・file contents 等の自由文は
> 正規表現マスクで守り切れないため、そもそもログに載せない (「コマンド＋意図のみ」保証)。

## 1 行の切り詰めと改行の畳み (capture-command.sh 内)

**記録の 1 行は、打ったコマンドそのままではない。**2 つの変形が必ず掛かる。
母集団を数えるときは、この 2 つが数え方の前提になる。

> このログは学習用の記録で、監査の証拠ではない。守りの判定 (PreToolUse の hook) は
> このログを使わず、ツールに渡る前のコマンドの全文を受け取って行う。

### 切り詰め (`clip`)

| 何 | 値・形 |
|---|---|
| 予算 | `CLIP_BYTES` = **2,000 B** (環境変数 `OPS_LOG_CLIP_BYTES` で変えられる) |
| 掛ける単位 | **行 1 本** (⛔ フィールドごとではない — 両方が上限に達した行が上限の 2 倍になるため。実測: 2,000 B を超える intent が 26 行 実在) |
| intent の取り分 | 予算の **1/4** (= 500 B)。残りが command (実測 2026-09-09・6,056 行: intent の中央値 24 B / 90% 点 86 B ⇒ 実運用ではほぼ全額が command に回る) |
| 切り方 | `head -c <max>` で **byte 単位**に切り、`iconv -f UTF-8 -t UTF-8 -c` で末尾の不完全な列を落とす ⇒ locale に依存しない (実測: C / en_US.UTF-8 / ja_JP.UTF-8 の 3 つで同じ出力) |
| 切った印 | **`…(N B 省略)`** を必ず付ける ⇒ 「短いコマンドだった」と「切られた」を後から区別できる |
| 失うもの | **長いコマンドの末尾** |

### 改行の畳み

- `tr '\r\n' '  '` で **LF と単独の CR の両方**を空白に替える (#246)。CommonMark は
  CR も行末とみなすので、LF だけを畳むと表の行が途中で終わり、残りが表の外の地の文
  として描画された。
- ⛔ **U+2028 / U+2029 / 改ページは畳まない** (CommonMark の行末ではないため。畳むと、
  読み手が 1 行と見るものを書き手が変えることになる)。
- 置換は**文字単位**なので、**改行の数だけ空白が増える** (⛔ 1 つにまとめはしない)。

### ⚠️ 数えるときの前提 (これがこの節を書く理由)

1. **1 行 = 1 コマンドとは限らない。** 改行が空白になるので、複数行のコマンドが 1 行に
   畳まれる ⇒ **先頭の語で数えると 2 段目以降が見えない。**
2. **切られた行は末尾が無い。** 行末にある語 (リダイレクトの行き先・パイプの後段) は
   数えられない ⇒ 「無い」ではなく「**見えない**」。
3. ⭕ **切られた行は数えられる。** `…(N B 省略)` の印で絞れる (実測 2026-10-29・obs の
   14 本 3,200 行のうち、印が在る行は **5 行**。⛔ ただしその行がどの予算の下で切られた
   かは測っていない)。
4. 数を出すときは **どの変形の後の数か**を必ず添える (⛔ 「コマンド数」とだけ書かない)。

## 環境による発火可否 (重要)

| 環境 | 発火 | 条件 |
|---|---|---|
| ローカル Claude Code CLI | ◯ | `OPS_LOG_REPO` が clone 済みなら常時 |
| Claude Code on the web (コンテナ) | △ | **`terminal-ops-logs` をそのセッションのスコープに含め、コンテナ内に clone されている時のみ** push 可。スコープ外だと push 段階で拒否される |

> コンテナは ephemeral。web セッションでログを残すには `terminal-ops-logs` を
> セッションスコープに追加して起動する必要がある (3 リポ既定 + 要望時追加の方針に従う)。

## ハードルール (退行させない)

- **出力 (stdout/stderr) はログに含めない。** コマンドと意図のみ。
- **`push-log.sh` の add は生成された日付ログのみ** (`find … -name
  'YYYY-MM-DD.md'`)。`README.md` 等の手書き markdown や `git add -A` を巻き込まない
  (中途半端な手書きノートを勝手に publish しない / 3 リポ共通文化)。
- **hook はツール実行をブロックしない** (`exit 0` で抜ける) — ログ機構の失敗が
  本来の作業を止めてはいけない。
- マスキング規則を緩めない。token 形式追加時は規則＋スクリプト＋テストを更新。

## See also

- `capture-command.sh` / `push-log.sh` — 同梱 hook スクリプト (実体)
- `terminal-ops-logs/README.md` — コマンド早見表 (git/gh/shell の学習索引)
- CLAUDE.md スキル発火表 — 本 Skill の発火条件 (導入・設定変更時にロード)
- `docs/skills-design.md` — Skills 構成規約 (フラット固定 / 命名 / カテゴリ索引)
