# 手動実行テストチェックリスト

このドキュメントは CI（`pnpm test` / `pnpm typecheck` / JSON lint / Chrome 拡張ジョブ）
で担保できない、**実環境が必要なため手動で実行検証すべきテスト**を機能別にまとめたものです。
実 X 認可・実 Obsidian vault・各種プラグイン・API キー・`ffmpeg`・Claude Code CLI・
対話プロンプトなどが必要な項目が対象です。

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

## 2. X ブックマーク差分同期（`--x-bookmarks`）

- [ ] **前提**: 認証済み、Obsidian vault に Dataview プラグイン導入済み
- [ ] `pnpm start -- --x-bookmarks --x-limit=20 --dry-run` で書き込みなし確認
- [ ] `--dry-run` を外し `<vault>/X_Bookmarks/<フォルダ名>/<group>.md` が
      1 グループ 1 枚で生成される
- [ ] `.x_bookmarks.json` と SQLite `x_bookmarks.db` が生成される
- [ ] 2 回目実行で既知ツイートがスキップされ差分のみ取得
      （既知 3 連続でページング打ち切り）
- [ ] フォルダ数保存則の警告が出ない

## 3. 対話選択モード（`--x-pick`）

- [ ] `pnpm start -- --x-pick --x-limit=10 --dry-run` で Stage 1 の 2 階層 Tree
      表示（強制親 / 動的検出 / その他 / `_Unfiled`）
- [ ] Stage 2 の選択構文 `1` / `1.2` / `1,3.1` / `1-3` / `all` が
      想定どおり対象を絞る
- [ ] `--no-sync` で Sync Phase が抑止される

## 4. Sync Phase / Folder Session 追跡

- [ ] `pnpm start -- --x-sync-folders` で手動 Sync が走る
- [ ] Obsidian でフォルダを移動 → 次回 sync で `_session.json` 経由で追従
- [ ] `.md` を別フォルダへドラッグ → frontmatter `session_id` で移動検知・再 bind
- [ ] X 側でフォルダ削除 → `orphan_on_x` の AI 判定プロンプト（`k`/`a`/`s`）が表示
- [ ] `k`=保持 / `a`=`_archived/` 退避 / `s`=スキップの各挙動を確認
- [ ] `X_SESSION_AI_DISABLE=true` で AI 非呼び出し・常に keep 推奨になる

## 5. AI 要約（provider ウィザード）

- [ ] **前提**: 選んだ provider の API キー（cloud）または LM Studio 起動（local）
- [ ] 初回 `--x-bookmarks` で要約ウィザードが起動し、選択が
      `pipeline_config.json::xSummary` に永続化される
- [ ] `--x-summary-reconfig` で再選択できる
- [ ] `--x-resummarize-all` で全要約クリア＆再生成（0 件でも実行、
      `--dry-run` 併用時はスキップ）
- [ ] 出力が日本語・200 グラフェム以内・改行なし
- [ ] local=batch / cloud=inline にモード自動切替

## 6. 強制親・マッピング（`--x-derive-rules`）

- [ ] `pnpm start -- --x-derive-rules` で現 vault 構造から
      `x_forced_parents.json` の提案 diff が出力される
- [ ] `.bak` が残り、y/N 確認が効く
- [ ] `x_folder_mapping.json` 追記後に階層化が反映される

## 7. レガシー移行（`--x-migrate-legacy`）

- [ ] 旧 `Clippings/X-Bookmarks/` がある環境で
      `pnpm start -- --x-migrate-legacy` を実行
- [ ] 一度きりで `_Archived/` へ退避される
- [ ] 再実行で二重移動しない

## 8. 動画キーフレーム抽出（opt-in）

- [ ] **前提**: `ffmpeg -version` が通る
- [ ] `X_VIDEO_FRAMES=true pnpm start -- --x-bookmarks --x-limit=5` を実行
- [ ] 動画付きツイートで `_attachments/x-bookmarks/<post_id>/frame-NN.webp` が
      4 枚生成され `## キーフレーム` セクションが埋め込まれる
- [ ] 60 秒超 / 30MB 超の動画は skip される
- [ ] ffmpeg 不在時は警告のみで本文保存は継続する

## 9. Dataview テーブルビュー（Obsidian 上）

- [ ] グループ `<group>.md` を Obsidian で開き HTML `<table>` が描画される
- [ ] 列ヘッダクリックで昇順 / 降順ソートが切り替わる
- [ ] デフォルトソートが `added_at` desc
- [ ] sentinel 外のユーザー文章が再生成で保持される

## 10. ハンズオン生成（`--hands-on`）

- [ ] **前提**: Claude Code CLI が OAuth 認証済み（`claude --version`）、
      対象フォルダが取り込み済み
- [ ] `pnpm start -- --hands-on="X_Bookmarks/Claude Code" --dry-run` で
      `.prompt.txt` を確認
- [ ] `--dry-run` を外し `Permanent Note/09_X_Bookmarks/<folder>-YYYYMMDD.md`
      が生成される
- [ ] `--since` で期間絞り込みが効く

## 11. その他の対話 / 補助コマンド

- [ ] `pnpm run sync-rules` で `folder_rules.json` に昇格マージ（降格なし）
- [ ] `pnpm start -- --rescue "<レポート>"` で API コスト 0 で再開できる
- [ ] 分析後の `Command [y/e/q]:` で `y`（全承認）/ `e`（パス修正）/
      `q`（書込なし）の各挙動
- [ ] `pnpm exec tsx merge-articles.ts "<dir>"` でナレッジ統合が走る
