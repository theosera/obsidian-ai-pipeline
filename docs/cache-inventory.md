# キャッシュ／派生データ インベントリ (cache inventory)

> 目的: 本リポ (obsidian-ai-pipeline) に存在する**キャッシュ・派生データ**を 1 か所に
> 棚卸しし、**今後のリファクタリング時の点検観点**を共有する。
> **本ドキュメントは現状の最適化を要求しない** — 「どこに何があるか」「壊れ方・無効化の
> 有無」を可視化し、変更時に踏むべきチェックリストを提供するだけ。
>
> ここでの「キャッシュ」は広義: **別のどこかにある真実 (source of truth) から導出され、
> 速度・コスト・利便のために保持される全データ**を指す (in-memory / SQLite / JSON ビュー /
> HTTP キャッシュ / LLM prompt cache)。

## 0. 早見表

| # | キャッシュ | 種別 | source of truth | 無効化手段 | 永続性 / gitignore | 主なリスク |
|---|---|---|---|---|---|---|
| A1 | `storage.ts` `cachedFolders` | in-memory | Vault の実フォルダ構造 | `getVaultFolders(forceRefresh=true)` | プロセス内 | 長命プロセスで stale |
| A2 | `storage.ts` `cachedKnownUrls` | in-memory | Vault 内 `.md` の URL | `addKnownUrl()` (**本番更新口**) / `resetKnownUrlsCache()` (テスト全破棄) | プロセス内 | ~~本番に無効化口なし~~ → **解消** (保存直後に集合へ反映) |
| A3 | `classifier.ts` `cachedSnippetsArr` | in-memory | `_分析コンテキスト/snippets_*.xml` | なし (プロセス起動毎に 1 回) | プロセス内 | snippets 更新が同一プロセス内で反映されない |
| A4 | `fetcher.ts` `browserContext`/`initPromise` | in-memory (resource) | — (Playwright インスタンス) | `closeBrowser()` | プロセス内 | 二重 init は initPromise で防御済 |
| B1 | `threat-reports/db.ts` `_instance` | DB ハンドル singleton | (DB 自体) | `closeDb()` | プロセス内 | 破損時 `.corrupted_*` 退避 → 空 DB 続行 |
| B2 | `x-bookmarks/db.ts` `_instance` | DB ハンドル singleton | (DB 自体) | `closeDb()` | プロセス内 | migrate 順序ミスで**誤って破損退避** (既知/対処済) |
| C1 | `x_bookmarks.db` | on-disk SQLite (**transactional core**) | (実質 DB 自身) | 再スクレイプ / JSON import | `<repo>/` / **gitignore** | per-tweet MD 廃止で **MD 再構築は不可** |
| C2 | `threat_reports.db` | on-disk SQLite (派生) | `raw/<week>.md` | 再 ingest / **`--rebuild-threat-reports-db`** | `<vault>/__skills/pipeline/` | rebuild **実装済** (human note は非復元) |
| D1 | `.threat_reports.json` (v4) | on-disk JSON ビュー | `threat_reports.db` | ingest/analyze/mark 毎に再生成 | vault 内 dotfile / gitignore (`.*`) | DB と JSON のスキーマ版ズレ |
| D2 | `.x_bookmarks.json` | on-disk JSON ビュー | `x_bookmarks.db` | sync 毎に再生成 | vault 内 dotfile / gitignore (`.*`) | 同上 |
| E1 | `.html_cache/<md5(url)>.html` | on-disk HTTP/レンダ | 取得元 URL | **なし (TTL 無し)** | `<repo>/` / **gitignore** | URL のみキー・**永続** → 内容変化に追従しない |
| E2 | `.chromium-data/` | on-disk ブラウザ状態 | (ログインセッション) | 手動削除 | `<repo>/` / **gitignore** | 肥大・古いセッション |
| F1 | Anthropic `cache_control: ephemeral` | LLM prompt cache | system prompt 文字列 | 5 分 TTL (Anthropic 側) | サーバ側 | system に時刻/乱数を混ぜると cache miss |
| G1 | `x_folder_mapping.json` / `x_forced_parents.json` | 派生マッピング/規則 | Vault 構造 + 規則 | `--x-derive-rules` 等 | vault 内 | x-bookmarks skill 管轄 (本書では参照のみ) |

---

## A. In-memory (module-level) キャッシュ — プロセス寿命

### A1. `cachedFolders` (`storage.ts:214`)
- `getVaultFolders(forceRefresh=false)` が Vault のフォルダ一覧を 1 度スキャンして保持。
- 無効化: 引数 `forceRefresh=true` を渡したときのみ再スキャン。
- 点検: 長命プロセス (将来 daemon 化等) でフォルダ追加が反映されない懸念。CLI 単発実行
  では問題にならない。

### A2. `cachedKnownUrls` (`storage.ts:268`)
- `getKnownUrls()` が Vault 内 `.md` から既知 URL 集合 (重複検出用) を構築・保持。
- 無効化/更新: **本番更新口 `addKnownUrl()` を追加済**。`saveMarkdown()` が `.md` を書き出した
  直後に呼び、保存 URL を即 dedup 集合へ反映する (走査 `getKnownUrls` と同じ正規化を共有)。
  テスト用の全破棄は `resetKnownUrlsCache()`。
- 旧懸念 (解消): かつては reset がテスト専用しか無く「同一プロセス内で新規保存した URL が
  dedup 集合に載らない」潜在 stale があった。`addKnownUrl` の保存直後 hook で塞いだ。
  (call site 実測では `getKnownUrls` は実行毎 1 回 = memo 自体は inert、欠陥は無効化口の不在
  だったため、memo 削除でなく更新口の追加で対処した。)

### A3. `cachedSnippetsArr` (`classifier.ts:32`)
- `loadSnippetsStructured()` が最新 `snippets_YYYYMMDD.xml` をパースして保持。
- 無効化: なし (プロセス起動毎に最新ファイルを 1 度読む)。
- 点検: snippets を更新しても同一プロセスでは旧データ。CLI 単発なら無害。

### A4. `browserContext` / `initPromise` (`fetcher.ts:6,17`)
- Playwright の永続ブラウザを singleton 化。`initPromise` で**並行 init の二重起動を防御**。
- 無効化: `closeBrowser()`。データキャッシュではなくリソースのメモ化。

---

## B. DB ハンドル singleton (破損リカバリ付き)

### B1. `threat-reports/db.ts` `getDb()`/`_instance` (`:496`)
- SQLite ハンドルを singleton 化。**破損時は `<file>.corrupted_<ts>` に退避し空 DB で続行**。
- 点検観点: 退避は「開けない」ケースの救済だが、**スキーマ migration の順序ミスを破損と
  誤認すると正常 DB を退避してしまう** (B2 の既知事例参照)。新列追加時は
  `migrate()` (ALTER TABLE) が index 作成より**先**に走ることを必ず確認。

### B2. `x-bookmarks/db.ts` `getDb()`/`_instance` (`:426`)
- 同パターン。コメント (`x-bookmarks/db.ts:108`) に既知バグの教訓:
  > 旧 DB (列なし) を開いた瞬間 "no such column" で throw → catch が DB を corrupted 退避
  > → **ユーザーのキャッシュ消失**。column 追加が終わってから index を張ること。
- 点検: DB シングルトン 2 つが**同じ corruption-recovery パターンの別実装**。リファクタ候補
  (共通基底へ抽出すれば migrate 順序の不変条件を 1 か所で担保できる)。

---

## C. On-disk 派生 SQLite (raw が source of truth)

### C1. `x_bookmarks.db`
- `<repo>/x_bookmarks.db` (gitignore: `x_bookmarks.db` / `x_bookmarks.db-*` / `*.corrupted_*`)。
- source of truth は Vault の `.md`。DB は dedupe O(1) / 差分スクレイプ / 件数モニタの派生。

### C2. `threat_reports.db`
- `<vault>/__skills/pipeline/threat_reports.db` (vault 配下・repo 外)。
- source of truth は `raw/<week>.md`。DB は横串検索 / risk 順表示の派生インデックス。

> **両 DB の再構築可能性 (2026-06 更新 — コメントと実装を一致させた)**:
> - **threat_reports (C2)**: `raw/<week>.md` が真実 →
>   `threat-reports/ingest.ts::rebuildThreatReportsDbFromVault()` **実装済**
>   (CLI `--rebuild-threat-reports-db`)。破損退避 / 手動削除後に raw から派生インデックスを
>   復旧する明示コマンド。⚠ ただし per-repo ノート (`relevance_notes`) / per-repo レビュー済み
>   フラグ (`report_repo_reviews`) は raw に無い human 入力なので **再構築では復元されない**
>   (reports 削除 → CASCADE で連動削除。退避 `<db>.corrupted_*` から手動サルベージ)。
>   破壊性ゆえ破損時に**自動起動はしない**。
> - **x_bookmarks (C1)**: group-page 移行 (2026-05) で **per-tweet MD は廃止**され、Vault に
>   残るのは Dataview レンダ済みビューのみ。個々のツイート全データは持たないため
>   **MD からの無損失再構築は原理的に不可** (DB が実質 transactional core)。復旧経路は
>   再スクレイプ (全件) or 直近 `.x_bookmarks.json` (全行エクスポート) からの import。
>   旧ヘッダコメントの「.md が source of truth / rebuildFromVault は Phase 2」は実態と乖離
>   していたため**撤回**した。

---

## D. On-disk 派生 JSON ビュー (Dataview 用 / 同期毎に再生成)

### D1. `.threat_reports.json` (`threat-reports/json_export.ts`)
- `threat_reports.db` → JSON。`version: 4` (rows / implementation_checks / **reports[]**、
  per-repo 化で `rows[].repo_notes[]` + `reports[].reviews[]`)。
  ingest / `--analyze-threat-relevance` / `--mark-threat-reviewed` の度に上書き再生成。
- 点検: **JSON schema version (4) と Dataview script (`threat-reports/index_writer.ts`) の整合**
  がズレると表が壊れる。フィールド変更時は Dataview 側の参照キー (`repo_notes` 等) も合わせること。

### D2. `.x_bookmarks.json` (`x-bookmarks/json_export.ts`)
- `x_bookmarks.db` → JSON。sync 毎に上書き。設計コメント: 「SQLite=内部キャッシュ /
  JSON=ユーザーに見える DB ビュー」。
- 点検: D1 と同じく **DB スキーマ ↔ JSON ↔ Dataview テンプレ**の三者整合。

> D1/D2 は dotfile (`.threat_reports.json` / `.x_bookmarks.json`) なので `.gitignore` の
> `.*` 規則で自動的に追跡外。意図的に commit しない (派生データ)。

---

## E. On-disk HTTP / レンダリングキャッシュ

### E1. `.html_cache/` (`fetcher.ts:8,52`)
- `md5(url).html` でレンダ済み HTML を保存。**`fetchRenderedHtml` はキャッシュ存在時に
  即返す**。
- **点検観点 (最重要)**: **TTL も無効化も無い** = URL をキーに**永続キャッシュ**。同じ URL の
  内容が更新されても古い HTML を返し続ける。再取得したいときは手動で `.html_cache/` を削除
  するしかない。リファクタ候補: TTL / `--no-cache` フラグ / ETag 等。

### E2. `.chromium-data/` (`fetcher.ts:24`)
- Playwright `launchPersistentContext` の永続プロファイル (ログイン状態保持)。
- 点検: 肥大・古いセッション。データキャッシュではなくブラウザ状態。

---

## F. LLM prompt キャッシュ (Anthropic ephemeral)

### F1. `cache_control: { type: 'ephemeral' }` (`classifier.ts:325,370,482`)
- `askAI` (JSON) と `askAIText` の **system プロンプトに ephemeral cache を付与** (5 分 TTL)。
  分類のシステムプロンプトを使い回す呼び出しで input トークンを削減する。
- 規約との関係: `docs/ai-coding-conventions.md` §4「**キャッシュ維持: システムプロンプトに
  時刻/乱数を入れない**」が前提条件。system に可変要素を混ぜると毎回 cache miss になる。
- 点検観点: `threat-reports/relevance.ts` は `askAIText` 経由でこの prompt cache の恩恵を
  受けうるが、**per-call の `nonce` は user prompt 側に注入**しており system (`SYSTEM_PROMPT`)
  は不変なので cache は効く。新たに system 側へ動的値を入れる変更は cache hit 率を壊すので
  避ける (= prompt cache の不変条件)。

---

## G. 派生マッピング / 設定 (本書では参照のみ)

- `x_folder_mapping.json` / `x_forced_parents.json` は Vault 構造から導出される
  フォルダマッピング/規則。狭義の runtime キャッシュとは別カテゴリだが「派生データ」として
  関連する。詳細・無効化 (`--x-derive-rules` 等) は **x-bookmarks skill** が正典。

---

## 運用上の評価 (3 分類) — システム運用視点のメタ評価

「キャッシュ」と一括りにせず、**運用規律が異なる 3 種**に分けて扱う。下に行くほど
「捨てられる建前」が弱く、実質プライマリ状態に近い。

| 性質 | 該当 | 壊れたときの影響 | 規律 |
|---|---|---|---|
| **純粋な揮発メモ** | A1 folders / A3 snippets | 再計算で復元 (無害) | 無効化責務は最小。`_classifyInternal` で **per-item 呼び出し**のため memo は性能上**正当** (削除は回帰) |
| **揮発メモ (once/run)** | A2 known URLs | 同上 | memo 自体は inert。欠陥は「本番更新口の不在」だった → `addKnownUrl` で解消 |
| **再生成可能な派生ストア** | C2 / D1 / D2 | source から作り直せる | C2 は `--rebuild-threat-reports-db` で建前を実装化。human 入力 (note) は source 外 = 非復元 |
| **実体に近い状態** | C1 / E1 / E2 | 作り直し困難 / 鮮度・信頼境界に直結 | C1 は transactional core (MD 再構築不可)。E1 は TTL 無し永続 (鮮度バグ温床) |

**今回 (2026-06) の対応**: 上 2 行のうち実害ある欠陥 (A2 の更新口不在) を塞ぎ、C2 の
「再構築できる建前」を実装化し、C1 の誤ったコメント (MD 再構築可) を実態へ是正した。
**A1/A3 の memo は削除しない** — call site 実測で per-item と判明し、削除は性能回帰になるため。

> 未対応 (将来の候補, 優先度順): E1 `.html_cache` の TTL/無効化 + 信頼境界明示 →
> キャッシュ hit/miss の最小観測 → prompt cache 不変条件の lint 固定。

## H. リファクタリング時の点検チェックリスト (今は実行不要)

キャッシュ周りを触る PR では以下を確認する:

1. **無効化口はあるか** — このキャッシュを意図的に捨てる手段 (引数 / reset 関数 / TTL /
   ファイル削除) が**本番経路**に存在するか。A2 のように「テスト専用 reset しか無い」状態を
   増やさない。
2. **source of truth は何か** — 派生先だけ更新して raw を更新し忘れる / 逆に raw を更新して
   派生再生成を忘れる経路が無いか。C2 (threat_reports) は `--rebuild-threat-reports-db` で
   raw から再構築できる (human note は非復元)。C1 (x_bookmarks) は **MD 再構築不可** (DB が
   transactional core) な点を踏まえ、復旧は再スクレイプ / JSON import で考える。
3. **スキーマ版の三者整合** — DB スキーマ ↔ JSON export (version) ↔ Dataview script。
   フィールド追加は「追加のみ・古い consumer は無視して壊れない」を維持する (D1/D2)。
4. **migration は破損退避より先か** — DB 列追加時、`migrate()` (ALTER TABLE) が index 作成や
   クエリより前に走り、旧 DB を**破損と誤認して退避しない**ことを確認 (B1/B2)。
5. **prompt cache の不変条件** — Anthropic system プロンプトに時刻/乱数/per-call 可変値を
   入れない (F1)。動的部分は user メッセージ側へ。
6. **永続キャッシュの陳腐化** — E1 の HTTP キャッシュのように TTL 無しで古い内容を返し続け
   ないか。再取得手段を用意する。
7. **gitignore 整合** — 新しい派生データ/キャッシュファイルは `.gitignore` 済みか
   (派生物・個人データ・secret を commit しない)。
8. **legacy 重複** — `scripts/*.js` (`classifier.js` / `fetcher.js` / `storage.js`) は TS の
   旧 JS コピーで、同種のキャッシュ実装 (`cache_control` / `.html_cache` 等) を**二重持ち**
   する。TS 側を直したら scripts/ 側との乖離 (= どちらが生きているか) を確認する。

---

## See also

- `storage.ts` / `classifier.ts` / `fetcher.ts` — in-memory & on-disk キャッシュ実装
- `threat-reports/db.ts` / `x-bookmarks/db.ts` — DB singleton + 破損リカバリ
- `threat-reports/json_export.ts` / `x-bookmarks/json_export.ts` — JSON ビュー再生成
- `docs/ai-coding-conventions.md` §4 — prompt cache の不変条件 (system に可変要素を入れない)
- `.gitignore` — 派生データ/キャッシュの除外規則
- `.claude/skills/x-bookmarks/SKILL.md` — `x_folder_mapping.json` 等 派生マッピングの正典
