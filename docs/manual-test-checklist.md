# 手動実行テストチェックリスト

このドキュメントは CI（`pnpm test` / `pnpm typecheck` / JSON lint / Chrome 拡張ジョブ）
で担保できない、**実環境が必要なため手動で実行検証すべきテスト**を機能別にまとめたものです。
実 X 認可・実 Obsidian vault・各種プラグイン・API キー・`ffmpeg`・Claude Code CLI・
対話プロンプトなどが必要な項目が対象です。

掲載しているのは現行 `cli.ts` で**実装済みのコマンド・フラグのみ**です
（`--config` / `--dry-run` / `--sync-rules` / `--x-auth` / `--x-bookmarks` /
`--x-pick` / `--x-limit=N` / `--hands-on=<folder>` / `--since=YYYY-MM-DD`）。
基本は `--dry-run` / `--x-limit` で小さく確認してから本番、を推奨します。

---

## 1. OAuth 認証（`--x-auth`）

- [ ] **前提**: `.env` に `X_CLIENT_ID` / `X_CLIENT_SECRET` / `X_REDIRECT_URI` /
      `X_AUTH_PORT`、X Developer Portal に Redirect URI 登録済み
- [ ] `pnpm start -- --x-auth` でブラウザに認可画面が開く
- [ ] 許可後 `<vault>/__skills/pipeline/x_tokens.json` が生成される
      （`scope` に `bookmark.read offline.access` を含む）
- [ ] access_token 失効後、他コマンドが refresh_token で自動更新される
- [ ] refresh_token も失効した場合は `--x-auth` で再認証できる

## 2. X ブックマーク取込（`--x-bookmarks`）

- [ ] **前提**: 認証済み（手順 1 完了）
- [ ] `pnpm start -- --x-bookmarks --x-limit=20 --dry-run` で書き込みが
      発生しないことを確認
- [ ] `--dry-run` を外すと X ブックマークフォルダ配下に `.md` が生成される
- [ ] SQLite `<vault>/__skills/pipeline/x_bookmarks.db` が生成・更新される
- [ ] 2 回目実行で既知ツイートがスキップされ差分のみ取得される

## 3. 対話選択モード（`--x-pick`）

- [ ] `pnpm start -- --x-pick --x-limit=10 --dry-run` で Stage 1 のフォルダ
      Tree 表示（強制親 / 動的検出 / その他 / `_Unfiled`）
- [ ] Stage 2 の選択構文 `1` / `1.2` / `1,3.1` / `1-3` / `all` が
      想定どおり対象を絞る
- [ ] `q` で中止できる

## 4. 強制親・フォルダマッピング設定

- [ ] `<vault>/__skills/pipeline/x_forced_parents.json` にキーワードを追加
- [ ] `--x-pick` の Stage 1 Tree でそのキーワードが親フォルダとして
      階層化される（単語境界マッチ・部分一致は不可）
- [ ] `<vault>/__skills/pipeline/x_folder_mapping.json` に明示マップを追記
      → 該当フォルダが指定の親パス配下に配置される

## 5. 動画キーフレーム抽出（opt-in）

- [ ] **前提**: `ffmpeg -version` が通る
- [ ] `X_VIDEO_FRAMES=true pnpm start -- --x-bookmarks --x-limit=5` を実行
- [ ] 動画付きツイートで `_attachments/x-bookmarks/<post_id>/frame-NN.webp` が
      抽出され `## キーフレーム` セクションが埋め込まれる
- [ ] 長尺 / 大容量の動画は skip される
- [ ] ffmpeg 不在時は警告のみで本文保存は継続する
- [ ] `X_VIDEO_FRAMES` 未設定時は本セクションが生成されない

## 6. ハンズオン生成（`--hands-on`）

- [ ] **前提**: Claude Code CLI が OAuth 認証済み（`claude --version`）、
      対象フォルダが `--x-bookmarks` 実行で `x_bookmarks.db` に投入済み
- [ ] `pnpm start -- --hands-on="Clippings/X-Bookmarks/Claude Code" --dry-run`
      で `<出力先>.prompt.txt` のみが出力される（`claude` は呼ばれない）
- [ ] `--dry-run` を外すと
      `<vault>/__skills/context/ハンズオン/<folder-slug>-YYYYMMDD.md`
      が生成される
- [ ] `--since=YYYY-MM-DD` で `created_at` 前方一致の期間絞り込みが効く

## 7. その他の補助コマンド

- [ ] `pnpm run sync-rules` で最新 `snippets_YYYYMMDD.xml` から
      `folder_rules.json` に昇格マージされる（昇格のみ・降格なし）
- [ ] 通常パイプライン（OneTab 取込）の分析後 `Command [y/e/q]:` で
      `y`（全承認）/ `e`（パス修正）/ `q`（書込なし）の各挙動
- [ ] `pnpm exec tsx merge-articles.ts "<dir>"` で複数記事のナレッジ統合が走る
