# Gate Decision Architecture — 意思決定の決定論化 (L2 軸分解 + L3 コード化)

週次 LLM 脅威レポート取込ゲート (L0–L3) の**判断設計**の正典。
実装は `.claude/skills/scan-threat-report/scripts/gate_decision.py` (L3) と
同 `SKILL.md` (L2 判定器仕様)。本ドキュメントとコードは 1:1 を維持する
(判定表を変えるときは両方 + `tests/run_gate_tests.py` を同一 PR で更新)。

## 1. なぜこの設計か (背景)

旧設計は L2 (隔離 LLM 判定) に「本文全体を見て live injection か」という
**単一の holistic な問い**を立て、その出力を SKILL.md の**散文判定表**を
Claude が解釈して最終 verdict にしていた。base rate が低い (真の攻撃が稀な)
環境で判定基準が抽象的だと、同じ recall でも FP が支配的になり precision が
崩壊する。結果、halt の大半が過剰解釈で、その全件が人間の即時裁定を要求する
ボトルネックになっていた。

対策は 3 点:
1. **判定境界をゲート側が定義する** — L2 は直交 5 軸の狭い yes/no +
   確信度 + アンカー付き証拠のみ。各軸のプロンプトに陽性/陰性例を埋め込む。
2. **ルーティングを決定論コードに移す** — needs_human (= suspicious) は
   `gate_decision.py` の機械的基準でのみ発火。LLM の「なんとなく不安」では
   発火しない。
3. **同期停止をやめる** — non-clean は隔離キューへ退避してバッチ継続。
   人間の裁定はスループットから分離する。

FN (すり抜け) 方向は逆に強化する: 全 verdict の判断トレース永続化 /
heightened モード / FN 回帰フィクスチャ (§7)。

## 2. レイヤ構成と汚染境界

| 層 | 実体 | 決定論? | untrusted 本文を読む? |
|---|---|---|---|
| L0 契約 + L1 signal | `scan-threat-report.py` | ✅ | ✅ (純データ走査・出力は redact 済み) |
| L2 軸別判定 | 隔離 subagent (narrow Read 1 件のみ) | ❌ (助言のみ) | ✅ |
| L3 決定 | `gate_decision.py` | ✅ | ❌ (--body は quote 照合のみ) |
| オーケストレーター | sec-mode main セッション | — | **❌ (保持しない)** |

**汚染フロー一方向の原則**: raw の untrusted バイト列を読んだコンテキスト
(intake subagent / L2 判定器 / 隔離レビュー補助) に決定権を持たせない。返せる
のは厳格スキーマ + redact 済み出力のみで、検証・統合は L3 コードが行う。
人間へ判断を提示する main セッションは本文を保持しない。

### subagent の役割分担 (メリットの有無)

| 役割 | 判断 | 理由 |
|---|---|---|
| intake (get_thread → raw 保存 → L1) | **導入** | main の非汚染。redact 済み L1 JSON + メタデータのみ返す |
| L2 軸別判定器 | **維持・強化** | 本文はパス渡し + 対象 raw 1 件の narrow Read (書込み・ネットワークなし = 漏洩経路なし)。SKILL.md §判定器の自己防衛 |
| 軸ごとの個別判定器 | **不採用** | Task 都度承認 × N 軸 = 承認疲れ。隔離強度は上がらない |
| L3 | **subagent なし** | 決定論 Python。LLM コンテキスト自体を排除 |
| 隔離レビュー補助 | **導入** | 隔離本文の再読を隔離し、人間向けセッションに redact 済みサマリのみ返す |

## 3. L3 判定表 (`gate_decision.py decide` — コードと 1:1)

上から順に評価し、最初に該当した行の verdict で確定する (`final_rule` に記録)。

| # | 条件 | verdict | routing | 備考 |
|---|---|---|---|---|
| 1 | L0 `contract_violations` あり | **blocked** | quarantine | L2 不要。KSP/heightened 適用外 (ルール順で構造的に保証) |
| 2 | invisible-char / homoglyph / hidden-comment、または multiline-injection ∧ live | **blocked** | quarantine | 隠蔽に正当理由なし。KSP 構造的に不可 |
| 2' | multiline-injection ∧ ¬live (説明フレーム降格済み) | **suspicious** | queue | 隠蔽系で最も FP が出やすい経路のみ軟化。clean には決して到達しない。KSP 不可 |
| 3 | interactive で L2 欠落/abort、L2 スキーマ逸脱、tool-use 痕跡 (`--l2-tool-use`) | **suspicious** | queue | 判定器侵害/環境不備は内容に関わらず人間へ |
| 4 | `concealment` 軸 reject (確信度不問) | **blocked** | quarantine | KSP 永久適用不可 |
| 5 | 他軸 reject ∧ confidence=high ∧ アンカー済み証拠 ≥1 | **blocked** | quarantine | 自動確定の唯一の LLM 経路 (高確信 + 検証可能な根拠) |
| 6 | 他軸 reject ∧ (confidence≠high ∨ 証拠未アンカー) | **suspicious** | queue | **幻覚ガード**: 未アンカー reject は自動 blocked にしない。アンカー済み証拠の全 signal が KSP 一致なら解除 |
| 7 | いずれかの軸 pass ∧ confidence≠high | **suspicious** | queue | FP→人間の主経路。該当軸の L1 signal (≥1 件) が**全て** KSP 一致なら解除 (signal 0 件の空虚な真は不可) |
| 8 | live L1 signal (非隠蔽) の対応軸が pass ∧ KSP 不一致 | **suspicious** | queue | L1/L2 相互検証 (L2 の見逃し方向の защита) |
| 9 | `section_shape_ok = false` (契約は OK) | **suspicious** | queue | 定型逸脱 |
| 10 | heightened ∧ (signal>0 ∨ 軸 confidence≠high ∨ KSP 該当があった) | **suspicious** | queue | heightened 中は KSP 全停止。signal 0 ∧ 全軸 pass-high のみ通る |
| 11 | それ以外 (契約 OK ∧ 全軸 pass-high ∧ 不一致なし) | **clean** | ingest | |

exit code: `0`=clean / `2`=suspicious / `3`=blocked / `4`=入力エラー。
**4 は fail-closed** — 呼び出し側 (sec-mode / fetcher) は suspicious 相当として
隔離する。

**CI プロファイル** (`--profile ci`, L2 なし): rule 1 / 2 / 2' のみ +
heightened 時は `flagged` 全件 suspicious。旧 workflow pre-scan
(CONCEAL∪contract の auto-block) と同義を同一コードパスで再現する。
非隠蔽 signal は CI では素通りし、L2 を伴う interactive (/sec-mode) 側が担う。

### 調整ノブ (観測データで見直す)

- rule 7 は L2 の確信度較正に依存する。`decisions.jsonl` で medium-pass の
  実 FP 率を観測し、恒常的にノイズなら「medium pass ∧ live signal 0 → clean」
  への緩和を**判定表・コード・テストの同一 PR** で検討する。
- 1 起動 5 軸の交差汚染が疑われる兆候 (特定軸だけ系統的に崩れる等) が trace に
  出たら、軸の分割起動 (承認コスト増) を再検討する。

## 4. 記録スキーマ

### 4.1 判断トレース `gate-decision@1` — `TR/_gate/decisions.jsonl`

**clean を含む全 run** を 1 行ずつ追記 (JSONL)。「その判断に至った理由」の
機械可読な監査証跡で、FN 事後監査・確信度較正・KSP 候補抽出の一次データ。
redact 徹底: L1 preview は伏字済み / L2 quote は span_sha1 化して破棄 /
本文は `body_sha1` のみ → git 追跡可。

```json
{"schema":"gate-decision@1","decision_id":"gd-<period_end>-<ts>-<sha4>",
 "ts":"…","profile":"interactive|ci","file":"raw/….md","period_end":"…",
 "body_sha1":"…","heightened_mode":false,
 "l0":{"contract_violations":[],"section_shape_ok":true},
 "l1":{"counts":{…},"signals":[{"id":1,"kind":"…","line":27,"context_class":"…",
        "live":false,"preview":"…⟦▮▮▮▮⟧…","span_sha1":"ab12cd34ef"}]},
 "l2":{"present":true,"schema_ok":true,"tool_use_observed":false,
       "axes":[{"axis":"role_override","verdict":"pass","confidence":"high",
                "evidence":[{"anchored":true,"signal_id":1,"line":27,
                             "span_sha1":"ab12cd34ef"}],"reason":"…"}]},
 "known_safe_hits":[{"pattern_id":"ksp-…","signal_id":1,"span_sha1":"…"}],
 "rules_fired":["…"],"verdict":"clean","final_rule":"all-axes-pass-high",
 "routing":"ingest"}
```

### 4.2 known_safe_patterns `known-safe-patterns@1` — リポ内 (PR レビュー必須)

`.claude/skills/scan-threat-report/policy/known_safe_patterns.json`。
人間が「取込 (FP)」と裁定した span を仕様に還元し、**同じ過検知を二度と人間に
聞かない**ための allowlist。

```json
{"schema":"known-safe-patterns@1","patterns":[
  {"id":"ksp-2026-07-10-001",
   "signal_kind":"reader-imperative","context_class":"table-cell",
   "match":{"span_sha1":"ab12cd34ef"},
   "rationale":"Section-4 検証観点表の定番文言の引用。gd-… で human が FP 裁定。",
   "added":"2026-07-10","expires":"2027-07-10","review_pr":"#131",
   "source_decision_id":"gd-…"}]}
```

**統治 (attack surface 化を防ぐ)**:
- 追加は **Default mode の PR のみ** (sec-mode からは編集しない)。隔離キューの
  `ksp_candidate` がスニペットを提供する。
- `match` は `span_sha1` (推奨・完全一致) か `regex` (≤120 字。**redact 済み
  preview に対して**適用 — 生 payload は L1 出力に存在しない) のどちらか一方。
- **隠蔽系 kind (`invisible-char`/`homoglyph`/`hidden-comment`/
  `multiline-injection`) と契約違反には永久に適用不可** (ローダが登録自体を
  拒否 + 判定表のルール順で構造的に先に blocked)。
- KSP の効果は「特定 span 1 件の needs_human トリガを中和する」ことだけ。
  rule 5 の確定 reject / rule 1・2・4 には決して作用しない。
- 不正エントリ (欠落フィールド / 不正 regex / 隠蔽 kind) は**黙殺せず exit 4
  で loud-fail** (壊れた allowlist が効いているように見える穴を作らない)。
- `expires` (推奨 1 年) で棚卸しを強制。失効は自動的に不適用。

### 4.3 隔離キュー `quarantine-queue@1` — `TR/_gate/quarantine_queue.json`

redact 済みメタデータのみ (git 追跡可)。**本文**は従来通り同期除外の
`TR/_quarantine/<period_end>.md`。SQLite にしない理由: 書き手が Python L3 /
読み手が sec-mode と CI で、TS の `threat_reports.db` (better-sqlite3 / WAL)
と結合させる必然がなく、週次数件の規模に JSON で十分。CI と対話の併走書込みは
`queue_id` キーで git 競合解決可能 (設計で回避せず運用で吸収)。

```json
{"schema":"quarantine-queue@1","items":[
  {"queue_id":"q-<period_end>-<sha4>","period_end":"…","file":"raw/….md",
   "decision_id":"gd-…","verdict":"suspicious","reasons":["<final_rule>"],
   "queued_at":"…","source":"interactive|ci|manual","status":"pending",
   "adjudicated_at":null,"adjudication_note":null,
   "ksp_candidate":{"signal_kind":"…","context_class":"…","span_sha1":"…"}}]}
```

裁定は `gate_decision.py queue --resolve <queue_id> --status ingested|rejected
--note "<理由>"` (sec-mode メニュー「隔離キュー review」から)。

### 4.4 heightened 状態 `gate-state@1` — `TR/_gate/gate_state.json`

```json
{"schema":"gate-state@1","heightened":false,"since":null,"reason":null,
 "history":[{"set_at":"…","reason":"fn-…","cleared_at":"…","ack":"…"}]}
```

## 5. 人間タッチポイント予算 (Tier 分類)

| 承認/判断 | Tier | Before | After |
|---|---|---|---|
| Gmail search_threads | A (ハードルール) | 都度 | バッチ冒頭 1 回 |
| Gmail get_thread | A (維持) | レポート毎 | intake subagent 内・レポート毎 |
| L1 スキャナ Bash | C | 都度承認 | **allowlist (0 回)** |
| L2 判定器 Task 起動 | A (injection バリア本体) | 都度 | レポート毎 1 回 (維持) |
| L3 判定・verdict 統合 | B | Claude の散文解釈 + 全 halt 即時裁定 | **決定論コード (0 回)** |
| gate_decision.py Bash | C | — | **allowlist (0 回)** |
| raw Write / 隔離移動 | C 寄り | 都度 | intake 内 Write 承認 / 移動は non-clean 時のみ |
| ingest CLI | C | allowlist 済み | 変更なし |
| label_thread | A (Gmail ハードルール) | 都度 | バッチ末尾にまとめて (成功分のみ) |
| コンテンツ裁定 | A | 全 halt 即時 | **機械的 needs_human のみ・隔離キューで後日バッチ** |

Tier A = セキュリティ不変条件 (常に人間) / Tier B = ポリシーで決められる
(決定論コードへ) / Tier C = 機械的 (allowlist へ)。リファクタ後、**Tier B/C が
人間に質問することはない**。

## 6. CI (Level 1 自動取込) との関係

`scripts/llm_sec_weekly_fetcher.ts` が thread ごとに
`scan-threat-report.py --json` → `gate_decision.py decide --profile ci` を
実行し (固定引数 `execFileSync`)、non-clean (exit 2/3/4) は raw を
`_quarantine/` へ rename + キュー登録して**他 thread の処理を継続**する
(旧: run 全体を fail)。隔離 thread は `pending-labels.json` に入れない =
`processed` が付かない。ただし再 ingest ループはキューの pending エントリで
防ぐ (sec-mode 側も同じガードを持つ)。workflow の pre-scan step は fetcher 側
ゲートの回帰検知用の不変条件再チェック (belt-and-braces) として同じ CLI を
呼ぶ。`_gate/` (trace/queue/state) は vault リポに commit される。

## 7. FN (すり抜け) 対応 — セキュリティを上げる方向の運用

1. **即時**: `gate_decision.py mode --set-heightened --reason fn-<id>`。
   以後、KSP 全停止 + signal/低確信度は全件 suspicious (判定表 rule 10)。
   CI も同じ state を読むため自動取込も厳格化される。
2. **監査**: `_gate/decisions.jsonl` の該当 `decision_id` で「なぜ clean に
   なったか」を層別に追う (どのルールが通し、どの軸が pass-high だったか)。
3. **恒久対策**: `tests/fixtures/fn_regression/README.md` の手順で redact 済み
   最小再現をフィクスチャ化 (L1 で守るべきなら scanner にパターン追加、L2 で
   守るべきなら sidecar `.l2.json` + SKILL.md の該当軸へ陽性例を追記)。
4. **解除**: 回帰が green になってから、人間の明示 ack でのみ
   `mode --clear --ack "<確認文>"`。コードは自動解除しない。

## 8. 変更しないもの (ハードルール)

- Gmail MCP (`search_threads`/`get_thread`/`label_thread`) は都度承認・
  allowlist 化しない (CLAUDE.md ハードルール)。
- L2 判定器の Task 起動は都度承認 (injection バリア本体)。
- ゲートは検知 + 報告のみ (remediation しない)。`processed` は ingest 成功後のみ。
- redaction 規律: payload 全文を verdict/ログ/トレースに書かない。
- `_quarantine/` は git/iCloud 同期除外のまま (`_gate/` は redact 済みのため追跡)。
- L1 スキーマ `l1@2` / parser 契約 / `threat_reports.db` スキーマは無変更。
