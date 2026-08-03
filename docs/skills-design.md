# Skills / Commands 構成規約 (obsidian-ai-pipeline)

このリポの Claude Code **skills** (`.claude/skills/`) と **commands**
(`.claude/commands/`) のディレクトリ構成・命名・グループ化方針の原本。
CLAUDE.md「スキル発火表」直後の圧縮版がこの doc を参照する (DRY)。

## 結論 (設計原則)

> **1 skill = 1 フラットディレクトリ + 1 `SKILL.md`**
> (`.claude/skills/<name>/SKILL.md`)。
> **中間の「カテゴリディレクトリ」で機能グループ化しない。**
> グループ化は**ディレクトリでなくドキュメント**(本 doc の索引 + 発火表)で表現する。
> 真の namespace が必要になったら**プラグイン化** (`plugin:skill`) を検討する。

## なぜフラット固定か (nested grouping を採用しない理由)

Claude Code 公式 docs には "Automatic discovery from nested directories" の記述が
あるが、**実装が追いついておらず信頼できない** (2026-06 時点で確認):

- `.claude/skills/<group>/<skill>/SKILL.md` のようなネスト検出は **公式に未サポート /
  既知の不具合**。検出されるのは原則フラットな `.claude/skills/<skill>/SKILL.md`
  のみ。
  - GitHub Issue [#28266](https://github.com/anthropics/claude-code/issues/28266)
    (nested skills not discovered)
  - GitHub Issue [#40640](https://github.com/anthropics/claude-code/issues/40640)
    (docs の "nested discovery" が実挙動と乖離)
  - GitHub Issue [#39138](https://github.com/anthropics/claude-code/issues/39138)
    (3 階層ネストは確実に壊れる)
- 呼び出し名は **直上の親ディレクトリ名**から導出され、中間グループ名は
  **namespace にならない** (`/group:skill` 形式は未実装)。

→ このリポの **CLAUDE.md「スキル発火表」は決定論的な“必ずロード”機構**であり、
スキルが名前で**確実に**引けることに依存している。「環境やバージョンで検出されたり
されなかったり」する nested grouping に乗せると発火表の信頼性が崩れるため、
**確実性を最優先してフラット固定**とする。

## グループ化したいときの正規の手段

1. **ドキュメントでの論理グループ化 (既定)** — 物理構造を変えず、本 doc の
   カテゴリ索引 + CLAUDE.md 発火表でグルーピングを表現する。
2. **プラグイン化** — Claude Code が公式サポートする唯一の namespace は
   プラグイン (`plugin:skill`)。スキル群を 1 プラグインにまとめれば
   `myplugin:pr-workflow` のように呼べる。配布・管理コストが増えるため、
   社内 1 リポでは過剰。真に必要になった段階で検討する。

## 命名 / 配置規約

- ディレクトリ名 = skill 名 = `SKILL.md` frontmatter の `name`。**kebab-case**。
- skill 本体は `.claude/skills/<name>/SKILL.md`。補助資料は同ディレクトリ配下
  (`references/` / `scripts/`) に置き、SKILL.md からの相対パスで参照する。
- メニュー駆動の固定タスク等は **command** として `.claude/commands/<name>.md`
  に置く (skill との使い分けは「再利用される作業知識 = skill / 起動トリガ・
  固定フロー = command」)。

## カテゴリ索引 (論理グループ = ディレクトリではない)

| カテゴリ | 種別 | 名前 | 役割 |
|---|---|---|---|
| Security / 脅威レポート | skill | `scan-threat-report` | 取込前 injection ゲート (L0〜L3) |
| Security / リポ取込 | skill | `untrusted-repo-intake` | clone した外部リポの隔離・設定レビュー手順 (clone リポの CLAUDE.md/hooks は untrusted) |
| Security / 脅威レポート | command | `sec-mode` | Security-only mode 起動 + 取込メニュー |
| Security / 脅威レポート | command | `sec-audit` | 自リポの運用セキュリティ姿勢監査 (読み取り専用) |
| Security / 脅威レポート | command | `sec-review` | 取込済みレポートを対象リポに照らして走査し、該当する実装推奨を提示 (Level 2 / per-repo フラグで既レビューをスキップ) |
| Dev workflow | skill | `pr-workflow` | PR 作成 / auto-merge 判断 / CI 期待値 |
| Dev workflow | skill | `ts-coding-conventions` | このリポの TS を書く/直す前の規約 |
| Ops / 運用ログ | skill | `ops-logging` | git/shell/MCP 操作を「コマンド＋意図」(secret 全マスク) で専用 private リポに push する設定の正典 (hook の母艦) |
| Ops / vault 書込安全 | skill | `vault-ops` | 二重書き込み vault repo への安全 push (pre-push hook / 自動 rebase / secret ゲート / installer) の正典 |
| Feature 知識 | skill | `x-bookmarks` | X bookmarks 機能の実装知識 |

## 新規 skill 追加チェックリスト

1. `.claude/skills/<name>/SKILL.md` を**フラットに**作る (中間ディレクトリ禁止)。
2. frontmatter `name` をディレクトリ名と一致させる (kebab-case)。
3. 発火条件があるなら **CLAUDE.md「スキル発火表」に 1 行追加**する。
4. 本 doc の**カテゴリ索引に 1 行追加**する。
5. 補助資料は同ディレクトリ配下に置き、相対パス参照にする。

## See also

- `CLAUDE.md` — スキル発火表 (どのタスクでどの skill をロードするか)
- `docs/ai-coding-conventions.md` — `ts-coding-conventions` skill の原本
