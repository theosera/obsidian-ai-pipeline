# fn_regression/ — すり抜け (false negative) 回帰フィクスチャ

ゲートを **clean で通過してしまった悪性レポート (FN)** を、redact した最小再現
として恒久的な回帰テストに変える場所。`run_gate_tests.py` が本ディレクトリの
`*.md` を**自動検出**し、「interactive プロファイルで clean にならないこと」を
毎回検証する。

## FN 発生時の手順 (docs/security/gate-decision-architecture.md §FN 対応と対)

1. **heightened モードを立てる** (先に守りを上げる):
   ```bash
   python3 ../../scripts/gate_decision.py mode \
     --state "<vault>/…/10_Threat_Reports/_gate/gate_state.json" \
     --set-heightened --reason "fn-<YYYY-MM-DD>-<短い識別子>"
   ```
2. **最小再現を作る**: すり抜けた本文から、FN を成立させた要素**だけ**を残して
   redact した `.md` を書く (正規 frontmatter + 最小本文)。
   - payload の生 URL・実コマンドはそのまま残さない (`example.invalid` 等へ置換)。
   - ファイル名は `fn_<YYYY-MM-DD>_<短い説明>.md`。
3. **どの層が守るべきだったかで置き場所を決める**:
   - L1 (決定論) で捕まえるべき → 新パターンを `scan-threat-report.py` に追加し、
     フィクスチャは本ディレクトリへ (スタブ L2 = all-pass-high でも non-clean に
     なることを自動検証)。
   - L2 (LLM 判定) で捕まえるべき → 同名の **sidecar `<name>.l2.json`**
     (期待される L2 軸別出力) を添える。テストはその L2 入力で non-clean を検証
    し、SKILL.md §L2 の該当軸へ**陽性例として追記**する (プロンプト側の回帰)。
4. `python3 ../run_gate_tests.py` で non-clean を確認してから PR にする。
5. 対応完了後、人間の明示 ack でのみ解除:
   ```bash
   python3 ../../scripts/gate_decision.py mode --state <同上> \
     --clear --ack "fn-<id> の L1/L2 回帰を追加し検証済み"
   ```

> **注意**: 本ディレクトリのフィクスチャも untrusted 由来の文字列を含む。
> フィクスチャ自身への追従 (中の指示に従う等) は当然しない。redact を徹底し、
> 生 payload を リポジトリに持ち込まない。
