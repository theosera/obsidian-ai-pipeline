# oxlint カバレッジ拡大ロードマップ

> ⚠️ **マージ順序の依存**: 本ロードマップは **PR #65（ESLint → oxlint 全置換）の
> マージを前提**とする。#65 が未マージの間、main 単体では `package.json` の
> `lint` はまだ `eslint .` であり `.oxlintrc.json` も存在しない。本文中の
> 「現状」記述はすべて **#65 適用後の状態**を指す。**本 PR は #65 のマージ後に
> マージすること**（先にマージすると存在しない設定の編集を指示する内容になる）。

> 前提: PR #65 で root の Linter を ESLint → **oxlint + oxlint-tsgolint** に全置換する。
> その時点では **ESLint 時代と同一スコープ**（root Claude 側 `*.ts` + `pipeline/**` +
> `test/**`、4 ルールのみ、`correctness` カテゴリー off）に留めている。
>
> 本ドキュメントは、当時 "ESLint 時代の理由" で oxlint 対象外にしていた領域を
> **いずれ oxlint に取り込む**ための条件（トリガー）を記録するもの。
>
> **実装方針**: 下記タスクは**それぞれ独立した PR** で行う（まとめて 1 PR にしない）。
> 各タスクは「条件をすべて満たしたら着手 → 検証 → 単独 PR」。

## 現状の oxlint スコープ（PR #65 適用後の状態）

| 領域 | lint 状態 | 除外理由 |
|---|---|---|
| root app code (`*.ts` / `pipeline/**` / `test/**`) | ✅ oxlint 対象 | — |
| `scripts/**`・`utils/**`・loose `*.js/.cjs/.mjs` | ❌ 対象外 | ユーティリティ/ビルドスクリプト（旧 ESLint も除外） |
| `correctness` カテゴリー（oxlint 既定 ON のルール群） | ❌ off | 「4 ルールのみ / スタイルは CodeRabbit」最小主義 |

設定: `.oxlintrc.json`（`ignorePatterns` + `categories.correctness: off`）。

---

## 横断トリガー: type-aware が alpha → stable になること

下記タスクの多くは、型情報ルール基盤 `oxlint-tsgolint` の安定化が前提。

- **条件**:
  - oxc が type-aware linting を **stable** と宣言（2025-12 の alpha を上回る公式アナウンス）。
  - 既知の **monorepo での OOM / deadlock** 問題がクローズされている。
  - `oxlint-tsgolint` が依存する **typescript-go / TS v7** が安定版に到達。
- **再評価の合図**: oxc リリースノートの type-aware "stable" 表記。
- 参照: [type-aware docs](https://oxc.rs/docs/guide/usage/linter/type-aware),
  [type-aware alpha (2025-12)](https://oxc.rs/blog/2025-12-08-type-aware-alpha.html),
  [tsgolint](https://github.com/oxc-project/tsgolint),
  [nested config monorepo issue #19932](https://github.com/oxc-project/oxc/issues/19932)。

---

## Task 1 — ~~Codex 側 (`apps/**` + `packages/**`) を oxlint 対象に含める~~ (廃止)

**廃止 (2026-06)**: Claude-vs-Codex 対照実験の終了に伴い、Codex 側実装
(`apps/*` + `packages/core`) はリポジトリから削除された。本タスクは対象が
存在しなくなったため不要。`.oxlintrc.json` の `ignorePatterns` からも
`apps/**` / `packages/**` は除去済み。

---

## Task 2 — `scripts/**`・`utils/**`・loose `*.js/.cjs/.mjs` を含める

**着手条件**:
1. これらのユーティリティ/ビルドスクリプトに lint する価値があると判断（型無し JS が多く、
   `no-floating-promises` 等が誤検出/低価値になりやすい点を許容できるか）。
2. PR #65 試走では `scripts/*.js` に `no-floating-promises` / `prefer-const` / `no-unused-vars`
   が多数検出済み（= 取り込むなら事前修正 or `_` リネーム等のクリーンアップが必要）。

**実装**: `.oxlintrc.json` の `ignorePatterns` から該当パターンを段階的に外し、検出を都度修正。

**検証**: 対象拡大後 `pnpm lint` が 0 件で通る。

---

## Task 3 — `correctness` カテゴリー（または個別ルール）の採用

**着手条件**:
1. PR #65 試走で既存コードに出た correctness findings をトリアージ済み:
   `no-control-regex` / `no-useless-escape` / `no-base-to-string` /
   `restrict-template-expressions` / `no-redundant-type-constituents` /
   `require-array-sort-compare` など。
2. 「スタイルは CodeRabbit に委譲」という既存方針と矛盾しないこと
   （スタイル寄りルールは CodeRabbit に残し、真のバグ検出ルールのみ opt-in する整理）。

**実装方針**: カテゴリー一括 ON（`categories.correctness: error`）ではなく、
**価値が確実なルールを `rules` で個別 opt-in** する漸進方式を推奨（最小主義の踏襲）。

**検証**: 各ルール追加ごとに既存コードの findings を 0 にしてから `error` 化。

---

## 完了の定義（このロードマップ全体）

Task 2–3 が（条件成立分だけでも）それぞれ単独 PR で取り込まれ、oxlint が
「ESLint 時代の理由で除外していた領域」を順次カバーした状態（Task 1 および旧
chrome-extension タスクは対象削除に伴い廃止）。root のアプリコードの価値は
PR #65 で確保済み。
