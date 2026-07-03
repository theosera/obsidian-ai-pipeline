#!/usr/bin/env python3
"""gate_decision.py — L3 ポリシー決定層 (決定論コード).

従来 SKILL.md の散文判定表を Claude が解釈実行していた L3 を、決定論的な
コードに置き換える。入力は L1 (scan-threat-report.py --json) と L2 (隔離 LLM
判定器の軸別構造化 JSON `scan-threat-report/l2-axes@1`)。出力は
`gate-decision@1` レコード (機械可読の判断トレース) + exit code。

設計上の役割 (詳細は ../SKILL.md §L3 / docs/security/gate-decision-architecture.md):
  - **needs_human (= suspicious) は本層の機械的基準でのみ発火**する。LLM (L2) は
    軸別の pass/reject + confidence + 証拠アンカーを返すだけで、ルーティングを
    決めない (holistic な問い・「なんとなく不安」での人間エスカレートを排除)。
  - L2 の reject を無条件に信頼しない: **blocked への自動確定は
    「confidence=high ∧ アンカー済み証拠あり」のときだけ** (幻覚ガード)。
    それ以外の reject は suspicious (隔離キュー行き) に留める。
  - 逆方向 (FN) は L1 との相互検証で守る: live signal の対応軸が pass でも
    KSP 不一致なら suspicious に倒す。
  - **known_safe_patterns (KSP)**: 人間が FP と裁定した span を PR レビュー済み
    allowlist として還元し、同じ過検知を二度と人間に聞かない。**隠蔽系 signal と
    契約違反には構造的に適用不可** (ルール順で KSP より先に blocked が確定する)。
  - **heightened モード**: FN インシデント後にセキュリティレベルを引き上げる。
    KSP 全停止 + signal/低確信度の全件 suspicious 化。人間の明示 ack
    (`mode --clear --ack`) までコードが自動解除しない。
  - 全 run (clean 含む) の判断トレースを JSONL (`--trace-out`) に追記し、
    「その判断に至った理由」を機械可読で監査可能にする。
  - Log Leakage 対策: トレース・キューに payload 生文字列を書かない。証拠は
    span_sha1 / redact 済み preview のみで参照する (L2 の quote はアンカー照合
    にのみ使い、永続化しない)。

exit code (decide):
  0 = clean / 2 = suspicious / 3 = blocked / 4 = 入力・使用法エラー (fail-closed:
  呼び出し側は 4 を suspicious 相当として扱う)
"""

import argparse
import datetime
import hashlib
import json
import os
import re
import sys

# ── スキーマ識別子 ──────────────────────────────────────────────────────
L1_SCHEMA = "scan-threat-report/l1@2"
L2_SCHEMA = "scan-threat-report/l2-axes@1"
DECISION_SCHEMA = "gate-decision@1"
KSP_SCHEMA = "known-safe-patterns@1"
QUEUE_SCHEMA = "quarantine-queue@1"
STATE_SCHEMA = "gate-state@1"

# ── L2 軸 ⇔ L1 signal kind の対応 (SKILL.md §L2 軸セット) ─────────────────
AXES = (
    "role_override",
    "reader_directed_command",
    "tool_call_forgery",
    "exfiltration_lure",
    "concealment",
)
AXIS_KINDS = {
    "role_override": {"role-marker"},
    "reader_directed_command": {"reader-imperative", "embedded-command"},
    "tool_call_forgery": {"fake-tool-call"},
    "exfiltration_lure": {"exfil-url"},
    "concealment": {"invisible-char", "homoglyph", "hidden-comment",
                    "multiline-injection"},
}
KIND_TO_AXIS = {k: a for a, ks in AXIS_KINDS.items() for k in ks}

# 隠蔽系。multiline-injection のみ live 降格 (説明フレーム) の余地があり、
# 降格済みは rule 2' で suspicious (人間キュー行き。clean には決して到達しない)。
CONCEALMENT_KINDS = {"invisible-char", "homoglyph", "hidden-comment",
                     "multiline-injection"}
HARD_CONCEALMENT_KINDS = {"invisible-char", "homoglyph", "hidden-comment"}

VERDICTS = ("pass", "reject")
CONFIDENCES = ("high", "medium", "low")
MAX_QUOTE_LEN = 40
MAX_REASON_LEN = 80
MAX_KSP_REGEX_LEN = 120

DEFAULT_KSP_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "policy",
    "known_safe_patterns.json")


class GateInputError(Exception):
    """入力 (L1/L2/KSP/state) が読めない・スキーマ不正。exit 4 (fail-closed)。"""


def sha1(s):
    """span 照合用の短縮 SHA1 (scan-threat-report.py と同一形式)。"""
    return hashlib.sha1(s.encode("utf-8", "replace")).hexdigest()[:10]


def utc_now():
    """ISO8601 UTC タイムスタンプ (秒精度)。"""
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


def load_json(path_or_dash, label):
    """path (または '-'=stdin) から JSON を読む。失敗は GateInputError。"""
    try:
        if path_or_dash == "-":
            return json.load(sys.stdin)
        with open(path_or_dash, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        raise GateInputError(f"{label} を読めない: {e}") from e


# ───────────────────────── known_safe_patterns ─────────────────────────
def load_known_safe(path):
    """KSP allowlist を検証つきで読む。**不正エントリは黙殺せず loud-fail** (exit 4)。

    検証: schema 固定値 / 必須フィールド / 隠蔽系 kind の混入禁止 /
    regex はコンパイル可能かつ MAX_KSP_REGEX_LEN 以下 / match は span_sha1 か
    regex のどちらか一方。silent skip は「allowlist が壊れているのに効いている
    ように見える」穴になるため全て例外にする。
    """
    if not os.path.exists(path):
        return []
    data = load_json(path, f"known_safe_patterns ({path})")
    if not isinstance(data, dict) or data.get("schema") != KSP_SCHEMA:
        raise GateInputError(f"KSP schema が {KSP_SCHEMA} でない: {path}")
    pats = data.get("patterns")
    if not isinstance(pats, list):
        raise GateInputError("KSP `patterns` が配列でない")
    out = []
    for i, p in enumerate(pats):
        where = f"KSP patterns[{i}]"
        if not isinstance(p, dict):
            raise GateInputError(f"{where} がオブジェクトでない")
        for k in ("id", "signal_kind", "context_class", "match", "rationale",
                  "added"):
            if not p.get(k):
                raise GateInputError(f"{where} 必須フィールド `{k}` が無い/空")
        if p["signal_kind"] in CONCEALMENT_KINDS:
            raise GateInputError(
                f"{where} 隠蔽系 kind `{p['signal_kind']}` は KSP に登録不可 "
                "(隠蔽に正当理由なし — SKILL.md §L3)")
        m = p["match"]
        if not isinstance(m, dict) or not (bool(m.get("span_sha1")) ^
                                           bool(m.get("regex"))):
            raise GateInputError(
                f"{where} `match` は span_sha1 / regex のどちらか一方のみ")
        if m.get("regex"):
            if len(m["regex"]) > MAX_KSP_REGEX_LEN:
                raise GateInputError(
                    f"{where} regex が {MAX_KSP_REGEX_LEN} 文字を超える")
            try:
                re.compile(m["regex"])
            except re.error as e:
                raise GateInputError(f"{where} regex がコンパイル不能: {e}") from e
        out.append(p)
    return out


def ksp_expired(pattern, today=None):
    """`expires` (YYYY-MM-DD) を過ぎていれば True。無指定は無期限。"""
    exp = pattern.get("expires")
    if not exp:
        return False
    try:
        d = datetime.date.fromisoformat(str(exp))
    except ValueError:
        return True  # 不正な expires は失効扱い (安全側)
    return (today or datetime.date.today()) > d


def match_signal_to_ksp(signal, patterns, today=None):
    """L1 signal 1 件に対する KSP 一致を探す。一致した pattern か None を返す。

    一致条件 (全て AND): kind / context_class / (span_sha1 一致 or regex が
    redact 済み preview に一致) / 未失効。隠蔽系 kind はローダで排除済みだが
    二重に防御する。regex は生 payload ではなく **redact 済み preview** に
    当てる (L1 出力に生 span は無い — Log Leakage 対策の帰結)。
    """
    if signal["kind"] in CONCEALMENT_KINDS:
        return None
    for p in patterns:
        if p["signal_kind"] != signal["kind"]:
            continue
        if p["context_class"] != signal["context_class"]:
            continue
        if ksp_expired(p, today):
            continue
        m = p["match"]
        if m.get("span_sha1"):
            if m["span_sha1"] == signal.get("span_sha1"):
                return p
        elif m.get("regex") and re.search(m["regex"], signal.get("preview", "")):
            return p
    return None


# ───────────────────────── L2 スキーマ検証 ──────────────────────────────
def validate_l2(l2):
    """L2 出力の厳格スキーマ検証。violation メッセージ list を返す (空 = OK)。

    逸脱 = 判定器侵害の兆候として扱う (→ suspicious)。全 5 軸必須 / 余計な
    キー禁止 / reject には証拠 1 件以上 / quote は MAX_QUOTE_LEN 以下。
    """
    v = []
    if not isinstance(l2, dict):
        return ["L2 出力がオブジェクトでない"]
    if l2.get("schema") != L2_SCHEMA:
        v.append(f"schema が {L2_SCHEMA} でない")
    extra_top = set(l2.keys()) - {"schema", "axes"}
    if extra_top:
        v.append(f"想定外の top-level キー: {sorted(extra_top)}")
    axes = l2.get("axes")
    if not isinstance(axes, dict):
        return v + ["`axes` がオブジェクトでない"]
    missing = set(AXES) - set(axes.keys())
    extra = set(axes.keys()) - set(AXES)
    if missing:
        v.append(f"軸が欠落: {sorted(missing)}")
    if extra:
        v.append(f"想定外の軸: {sorted(extra)}")
    for name in AXES:
        ax = axes.get(name)
        if ax is None:
            continue
        if not isinstance(ax, dict):
            v.append(f"軸 {name} がオブジェクトでない")
            continue
        extra_keys = set(ax.keys()) - {"verdict", "confidence", "evidence",
                                       "reason"}
        if extra_keys:
            v.append(f"軸 {name} に想定外キー: {sorted(extra_keys)}")
        if ax.get("verdict") not in VERDICTS:
            v.append(f"軸 {name} verdict が pass/reject でない")
        if ax.get("confidence") not in CONFIDENCES:
            v.append(f"軸 {name} confidence が high/medium/low でない")
        ev = ax.get("evidence", [])
        if not isinstance(ev, list):
            v.append(f"軸 {name} evidence が配列でない")
            ev = []
        for j, e in enumerate(ev):
            if not isinstance(e, dict):
                v.append(f"軸 {name} evidence[{j}] がオブジェクトでない")
                continue
            if set(e.keys()) - {"signal_id", "line", "quote"}:
                v.append(f"軸 {name} evidence[{j}] に想定外キー")
            q = e.get("quote")
            if q is not None and (not isinstance(q, str) or
                                  len(q) > MAX_QUOTE_LEN):
                v.append(f"軸 {name} evidence[{j}] quote が不正/長すぎる")
        if ax.get("verdict") == "reject" and not ev:
            v.append(f"軸 {name} reject なのに証拠 0 件")
        r = ax.get("reason")
        if r is not None and (not isinstance(r, str) or len(r) > MAX_REASON_LEN):
            v.append(f"軸 {name} reason が不正/長すぎる")
    return v


def anchor_evidence(evidence, signals_by_id, body_lines):
    """証拠 1 件のアンカー解決。{'anchored', 'signal_id', 'line', 'span_sha1'}。

    第一アンカー: signal_id → L1 signal (span_sha1 を継承)。
    第二アンカー: line + quote が本文の該当行に**逐語一致** (--body 必須)。
    quote は照合にのみ使い、返り値には sha1 だけ残す (Log Leakage 対策)。
    どちらも成立しなければ anchored=False (= 幻覚の可能性。自動 blocked 不可)。
    """
    sid = evidence.get("signal_id")
    if isinstance(sid, int) and sid in signals_by_id:
        return {"anchored": True, "signal_id": sid,
                "line": signals_by_id[sid]["line"],
                "span_sha1": signals_by_id[sid]["span_sha1"]}
    line = evidence.get("line")
    quote = evidence.get("quote")
    if (body_lines is not None and isinstance(line, int) and quote and
            1 <= line <= len(body_lines) and quote in body_lines[line - 1]):
        return {"anchored": True, "signal_id": None, "line": line,
                "span_sha1": sha1(quote)}
    return {"anchored": False, "signal_id": sid if isinstance(sid, int) else None,
            "line": line if isinstance(line, int) else None, "span_sha1": None}


# ───────────────────────── 判定本体 ─────────────────────────────────────
def decide(l1, l2, known_safe, heightened, profile, body_text=None,
           l2_tool_use=False, now=None, today=None):
    """L0+L1+L2 を統合し gate-decision@1 レコードを返す (決定論)。

    判定表 (上から順に評価。詳細根拠は docs/security/gate-decision-architecture.md):
      1   L0 契約違反                                → blocked (KSP/heightened 適用外)
      2   ハード隠蔽 / multiline∧live               → blocked (KSP 構造的に不可)
      2'  multiline∧¬live (説明フレーム降格済み)     → suspicious
      3   interactive で L2 欠落 / 整合性違反 / tool-use → suspicious
      4   concealment 軸 reject (確信度不問)          → blocked
      5   他軸 reject ∧ high ∧ アンカー済み証拠       → blocked (自動確定)
      6   他軸 reject ∧ (≠high ∨ 未アンカー)          → suspicious (KSP 全一致で解除)
      7   軸 pass ∧ ≠high                            → suspicious (KSP 全一致で解除)
      8   live signal の対応軸 pass ∧ KSP 不一致      → suspicious (L1/L2 相互検証)
      9   定型逸脱 (契約 OK)                          → suspicious
      10  heightened ∧ (signal>0 ∨ ≠high ∨ KSP 該当) → suspicious (KSP 全停止)
      11  それ以外                                    → clean
    CI profile (L2 なし) は 1/2/2' (+10) のみ = 現行 workflow pre-scan と同義。
    """
    if not isinstance(l1, dict) or l1.get("schema") != L1_SCHEMA:
        raise GateInputError(f"L1 入力の schema が {L1_SCHEMA} でない")
    if profile not in ("interactive", "ci"):
        raise GateInputError(f"不明な profile: {profile}")

    structural = l1.get("structural", {})
    contract = structural.get("contract_violations", [])
    shape_ok = structural.get("section_shape_ok", True)
    signals = l1.get("signals", [])
    signals_by_id = {s["id"]: s for s in signals if isinstance(s.get("id"), int)}
    body_lines = body_text.splitlines() if body_text is not None else None

    rules_fired = []
    known_safe_hits = []
    l2_summary = {"present": l2 is not None, "schema_ok": None,
                  "tool_use_observed": bool(l2_tool_use), "axes": []}

    def record(verdict, final_rule, routing):
        return _build_record(
            l1=l1, l2_summary=l2_summary, verdict=verdict,
            final_rule=final_rule, routing=routing, rules_fired=rules_fired,
            known_safe_hits=known_safe_hits, heightened=heightened,
            profile=profile, body_text=body_text, now=now)

    # ── rule 1: L0 契約違反 (KSP/heightened より先に確定 = 適用外を構造で保証) ──
    if contract:
        rules_fired.append("l0-contract")
        return record("blocked", "l0-contract", "quarantine")

    # ── rule 2 / 2': 隠蔽系 signal ─────────────────────────────────────
    for s in signals:
        if s["kind"] in HARD_CONCEALMENT_KINDS or (
                s["kind"] == "multiline-injection" and s.get("live")):
            rules_fired.append(f"l1-concealment:{s['kind']}")
            return record("blocked", f"l1-concealment:{s['kind']}", "quarantine")
    for s in signals:
        if s["kind"] == "multiline-injection" and not s.get("live"):
            rules_fired.append("l1-multiline-demoted")
            return record("suspicious", "l1-multiline-demoted", "queue")

    # ── CI profile: L2 を持たない。ここまでのハードルール + heightened のみ ──
    if profile == "ci":
        if heightened and l1.get("flagged"):
            rules_fired.append("heightened-ci-flagged")
            return record("suspicious", "heightened-ci-flagged", "queue")
        rules_fired.append("ci-l0l1-only")
        return record("clean", "ci-l0l1-only", "ingest")

    # ── rule 3: L2 欠落 / 整合性違反 / tool-use 痕跡 ───────────────────
    if l2 is None:
        rules_fired.append("l2-missing")
        return record("suspicious", "l2-missing", "queue")
    violations = validate_l2(l2)
    l2_summary["schema_ok"] = not violations
    if l2_tool_use:
        rules_fired.append("l2-tool-use-observed")
        return record("suspicious", "l2-tool-use-observed", "queue")
    if violations:
        rules_fired.append("l2-integrity")
        l2_summary["violations"] = violations
        return record("suspicious", "l2-integrity", "queue")

    # ── KSP 一致の計算 (heightened 中は「適用」しない — rule 10 用に記録のみ) ──
    ksp_by_signal = {}
    for s in signals:
        p = match_signal_to_ksp(s, known_safe, today)
        if p:
            ksp_by_signal[s["id"]] = p
    if not heightened:
        known_safe_hits.extend(
            {"pattern_id": p["id"], "signal_id": sid,
             "span_sha1": signals_by_id[sid]["span_sha1"]}
            for sid, p in sorted(ksp_by_signal.items()))
    ksp_applicable = bool(ksp_by_signal)
    apply_ksp = (not heightened) and ksp_applicable

    # ── 軸別サマリ (trace 用) + アンカー解決 ────────────────────────────
    axes = l2["axes"]
    anchored_by_axis = {}
    for name in AXES:
        ax = axes[name]
        resolved = [anchor_evidence(e, signals_by_id, body_lines)
                    for e in ax.get("evidence", [])]
        anchored_by_axis[name] = resolved
        l2_summary["axes"].append({
            "axis": name, "verdict": ax["verdict"],
            "confidence": ax["confidence"], "evidence": resolved,
            "reason": ax.get("reason", "")})

    def axis_ksp_cleared(name):
        """軸に紐づく L1 signal が 1 件以上あり、その全てが KSP 一致なら True。

        signal 0 件での空虚な真は認めない — allowlist すべき span が存在しない
        低確信度は KSP では解除できず、人間キューへ行くべき。
        """
        mapped = [s for s in signals if KIND_TO_AXIS.get(s["kind"]) == name]
        return bool(mapped) and all(s["id"] in ksp_by_signal for s in mapped)

    # ── rule 4: concealment 軸 reject (KSP 永久適用不可) ────────────────
    if axes["concealment"]["verdict"] == "reject":
        rules_fired.append("l2-axis-concealment-reject")
        return record("blocked", "l2-axis-concealment-reject", "quarantine")

    # ── rule 5/6: 他軸 reject ──────────────────────────────────────────
    for name in AXES:
        if name == "concealment" or axes[name]["verdict"] != "reject":
            continue
        anchored = [a for a in anchored_by_axis[name] if a["anchored"]]
        if axes[name]["confidence"] == "high" and anchored:
            rules_fired.append(f"l2-axis-reject-confirmed:{name}")
            return record("blocked", f"l2-axis-reject-confirmed:{name}",
                          "quarantine")
        # KSP 解除: アンカー済み証拠が 1 件以上あり、その全 signal が KSP 一致
        ev_sids = [a["signal_id"] for a in anchored if a["signal_id"] is not None]
        if (apply_ksp and anchored and len(ev_sids) == len(anchored) and
                all(sid in ksp_by_signal for sid in ev_sids)):
            rules_fired.append(f"ksp-cleared-reject:{name}")
            continue
        rules_fired.append(f"l2-axis-reject-unconfirmed:{name}")
        return record("suspicious", f"l2-axis-reject-unconfirmed:{name}",
                      "queue")

    # ── rule 7: 軸 pass ∧ 低確信度 ─────────────────────────────────────
    for name in AXES:
        ax = axes[name]
        if ax["verdict"] == "pass" and ax["confidence"] != "high":
            if apply_ksp and axis_ksp_cleared(name):
                rules_fired.append(f"ksp-cleared-confidence:{name}")
                continue
            rules_fired.append(f"l2-axis-low-confidence:{name}")
            return record("suspicious", f"l2-axis-low-confidence:{name}",
                          "queue")

    # ── rule 8: live signal と L2 pass の不一致 (相互検証) ──────────────
    for s in signals:
        if not s.get("live") or s["kind"] in CONCEALMENT_KINDS:
            continue
        axis = KIND_TO_AXIS.get(s["kind"])
        if axis and axes[axis]["verdict"] == "pass":
            if apply_ksp and s["id"] in ksp_by_signal:
                rules_fired.append(f"ksp-cleared-disagreement:{s['id']}")
                continue
            rules_fired.append(f"l1-l2-disagreement:{s['kind']}")
            return record("suspicious", f"l1-l2-disagreement:{s['kind']}",
                          "queue")

    # ── rule 9: 定型逸脱 ───────────────────────────────────────────────
    if not shape_ok:
        rules_fired.append("l0-shape")
        return record("suspicious", "l0-shape", "queue")

    # ── rule 10: heightened 残余 (KSP 停止の帰結を含む) ─────────────────
    if heightened and (l1.get("counts", {}).get("total", 0) > 0 or
                       any(axes[n]["confidence"] != "high" for n in AXES) or
                       ksp_applicable):
        rules_fired.append("heightened-mode")
        return record("suspicious", "heightened-mode", "queue")

    # ── rule 11: clean ─────────────────────────────────────────────────
    rules_fired.append("all-axes-pass-high")
    return record("clean", "all-axes-pass-high", "ingest")


def _extract_period_end(body_text, l1_file):
    """decision_id 用の period_end。frontmatter → ファイル名 → 'unknown'。"""
    if body_text:
        m = re.search(r"^period_end:\s*[\"']?(\d{4}-\d{2}-\d{2})[\"']?\s*$",
                      body_text, re.MULTILINE)
        if m:
            return m.group(1)
    base = os.path.basename(l1_file or "")
    m = re.match(r"^(\d{4}-\d{2}-\d{2})\.md$", base)
    return m.group(1) if m else "unknown"


def _build_record(l1, l2_summary, verdict, final_rule, routing, rules_fired,
                  known_safe_hits, heightened, profile, body_text, now):
    """gate-decision@1 レコードを組む。payload 生文字列は含めない。"""
    ts = now or utc_now()
    body_sha = sha1(body_text) if body_text is not None else None
    period_end = _extract_period_end(body_text, l1.get("file"))
    compact_ts = ts.replace("-", "").replace(":", "")
    return {
        "schema": DECISION_SCHEMA,
        "decision_id": f"gd-{period_end}-{compact_ts}-{(body_sha or 'nobody')[:4]}",
        "ts": ts,
        "profile": profile,
        "file": l1.get("file"),
        "period_end": period_end,
        "body_sha1": body_sha,
        "heightened_mode": bool(heightened),
        "l0": {
            "contract_violations": l1.get("structural", {}).get(
                "contract_violations", []),
            "section_shape_ok": l1.get("structural", {}).get(
                "section_shape_ok", True),
        },
        "l1": {
            "counts": l1.get("counts", {}),
            "signals": [
                {"id": s.get("id"), "kind": s.get("kind"),
                 "line": s.get("line"),
                 "context_class": s.get("context_class"),
                 "live": s.get("live"), "preview": s.get("preview"),
                 "span_sha1": s.get("span_sha1")}
                for s in l1.get("signals", [])],
        },
        "l2": l2_summary,
        "known_safe_hits": known_safe_hits,
        "rules_fired": rules_fired,
        "verdict": verdict,
        "final_rule": final_rule,
        "routing": routing,
    }


EXIT_BY_VERDICT = {"clean": 0, "suspicious": 2, "blocked": 3}


# ───────────────────────── state / queue / trace I/O ────────────────────
def read_state(path):
    """gate_state.json を読む。無ければ既定 (heightened=False)。"""
    if not path or not os.path.exists(path):
        return {"schema": STATE_SCHEMA, "heightened": False, "since": None,
                "reason": None, "history": []}
    st = load_json(path, f"gate_state ({path})")
    if not isinstance(st, dict) or st.get("schema") != STATE_SCHEMA:
        raise GateInputError(f"gate_state schema が {STATE_SCHEMA} でない: {path}")
    return st


def write_json(path, obj):
    """親ディレクトリを作って JSON を書く。"""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
        f.write("\n")


def append_trace(path, rec):
    """判断トレース (JSONL) に 1 行追記する。"""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def read_queue(path):
    """quarantine_queue.json を読む。無ければ空キュー。"""
    if not os.path.exists(path):
        return {"schema": QUEUE_SCHEMA, "items": []}
    q = load_json(path, f"quarantine_queue ({path})")
    if not isinstance(q, dict) or q.get("schema") != QUEUE_SCHEMA:
        raise GateInputError(f"queue schema が {QUEUE_SCHEMA} でない: {path}")
    return q


def queue_add(path, rec, source):
    """suspicious/blocked の decision record から queue entry を追記する。

    ksp_candidate: 人間が「取込 (FP)」と裁定した場合に KSP へ還元しやすいよう、
    KSP 未一致の非隠蔽 signal から候補を 1 件添える (無ければ null)。
    """
    q = read_queue(path)
    if any(it.get("decision_id") == rec["decision_id"] for it in q["items"]):
        return  # 同一 decision の二重登録を防ぐ (idempotent)
    candidate = None
    hit_sids = {h["signal_id"] for h in rec.get("known_safe_hits", [])}
    for s in rec["l1"]["signals"]:
        if s["kind"] not in CONCEALMENT_KINDS and s["id"] not in hit_sids:
            candidate = {"signal_kind": s["kind"],
                         "context_class": s["context_class"],
                         "span_sha1": s["span_sha1"]}
            break
    q["items"].append({
        "queue_id": f"q-{rec['period_end']}-{rec['decision_id'][-4:]}",
        "period_end": rec["period_end"],
        "file": rec["file"],
        "decision_id": rec["decision_id"],
        "verdict": rec["verdict"],
        "reasons": [rec["final_rule"]],
        "queued_at": rec["ts"],
        "source": source,
        "status": "pending",
        "adjudicated_at": None,
        "adjudication_note": None,
        "ksp_candidate": candidate,
    })
    write_json(path, q)


# ───────────────────────── CLI サブコマンド ─────────────────────────────
def cmd_decide(args):
    """decide: L1(+L2) を統合して verdict を返し、trace/queue/state を更新する。"""
    l1 = load_json(args.l1, "--l1")
    l2 = load_json(args.l2, "--l2") if args.l2 else None
    body = None
    if args.body:
        try:
            with open(args.body, "r", encoding="utf-8", errors="replace") as f:
                body = f.read()
        except OSError as e:
            raise GateInputError(f"--body を読めない: {e}") from e
    known_safe = load_known_safe(args.known_safe)
    state = read_state(args.state)
    rec = decide(l1, l2, known_safe, heightened=bool(state.get("heightened")),
                 profile=args.profile, body_text=body,
                 l2_tool_use=args.l2_tool_use)
    if args.trace_out:
        append_trace(args.trace_out, rec)
    if args.queue and rec["verdict"] in ("suspicious", "blocked"):
        queue_add(args.queue, rec, source=args.profile)
    if args.json:
        print(json.dumps(rec, ensure_ascii=False, indent=2))
    else:
        icon = {"clean": "✅", "suspicious": "🟡", "blocked": "🚫"}[rec["verdict"]]
        print(f"{icon} verdict={rec['verdict']} final_rule={rec['final_rule']} "
              f"routing={rec['routing']} (decision_id={rec['decision_id']})")
        for r in rec["rules_fired"]:
            print(f"   - {r}")
    return EXIT_BY_VERDICT[rec["verdict"]]


def cmd_mode(args):
    """mode: heightened フラグの表示/設定/解除。解除は人間の --ack 必須。"""
    state = read_state(args.state)
    if args.show or not (args.set_heightened or args.clear):
        print(json.dumps(state, ensure_ascii=False, indent=2))
        return 0
    if args.set_heightened:
        if not args.reason:
            raise GateInputError("--set-heightened には --reason <incident-id> が必須")
        state.update({"heightened": True, "since": utc_now(),
                      "reason": args.reason})
        state.setdefault("history", []).append(
            {"set_at": state["since"], "reason": args.reason,
             "cleared_at": None, "ack": None})
    if args.clear:
        if not args.ack:
            raise GateInputError("--clear には --ack \"<確認文>\" が必須 "
                                 "(FN 後の解除は人間の明示 ack のみ)")
        state.update({"heightened": False, "since": None, "reason": None})
        hist = state.setdefault("history", [])
        if hist and hist[-1].get("cleared_at") is None:
            hist[-1].update({"cleared_at": utc_now(), "ack": args.ack})
    write_json(args.state, state)
    print(f"heightened = {state['heightened']}")
    return 0


def cmd_queue(args):
    """queue: 隔離キューの一覧 / 手動追加 / 裁定反映。"""
    if args.list:
        q = read_queue(args.queue)
        pending = [it for it in q["items"] if it["status"] == "pending"]
        print(json.dumps({"pending": len(pending), "items": q["items"]},
                         ensure_ascii=False, indent=2))
        return 0
    if args.add:
        rec = load_json(args.add, "--add (decision record)")
        if rec.get("schema") != DECISION_SCHEMA:
            raise GateInputError(f"--add は {DECISION_SCHEMA} レコードのみ")
        queue_add(args.queue, rec, source="manual")
        print("queued")
        return 0
    if args.resolve:
        if args.status not in ("ingested", "rejected"):
            raise GateInputError("--resolve には --status ingested|rejected が必須")
        q = read_queue(args.queue)
        for it in q["items"]:
            if it["queue_id"] == args.resolve:
                it.update({"status": args.status,
                           "adjudicated_at": utc_now(),
                           "adjudication_note": args.note or None})
                write_json(args.queue, q)
                print(f"resolved {args.resolve} → {args.status}")
                return 0
        raise GateInputError(f"queue_id が見つからない: {args.resolve}")
    raise GateInputError("queue には --list / --add / --resolve のいずれかが必須")


def build_parser():
    """CLI 定義。"""
    p = argparse.ArgumentParser(
        prog="gate_decision.py",
        description="L3 ポリシー決定 (決定論)。SKILL.md §L3 の実装。")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("decide", help="L1(+L2) から verdict を決定")
    d.add_argument("--l1", required=True, help="L1 JSON のパス ('-'=stdin)")
    d.add_argument("--l2", help="L2 軸別 JSON のパス ('-'=stdin)。ci では省略")
    d.add_argument("--profile", required=True, choices=["interactive", "ci"])
    d.add_argument("--body", help="raw レポート本文 (quote アンカー照合用)")
    d.add_argument("--known-safe", default=DEFAULT_KSP_PATH,
                   help="known_safe_patterns.json のパス")
    d.add_argument("--state", help="gate_state.json のパス (heightened 読取)")
    d.add_argument("--trace-out", help="判断トレース JSONL の追記先")
    d.add_argument("--queue", help="quarantine_queue.json (suspicious/blocked を追記)")
    d.add_argument("--l2-tool-use", action="store_true",
                   help="呼び出し側が L2 実行トレースに tool-use を観測した")
    d.add_argument("--json", action="store_true", help="レコード全体を JSON 出力")
    d.set_defaults(fn=cmd_decide)

    m = sub.add_parser("mode", help="heightened モードの表示/設定/解除")
    m.add_argument("--state", required=True, help="gate_state.json のパス")
    m.add_argument("--show", action="store_true")
    m.add_argument("--set-heightened", action="store_true")
    m.add_argument("--reason", help="FN インシデント ID 等")
    m.add_argument("--clear", action="store_true")
    m.add_argument("--ack", help="解除の明示確認文 (人間が書く)")
    m.set_defaults(fn=cmd_mode)

    q = sub.add_parser("queue", help="隔離キューの一覧/追加/裁定")
    q.add_argument("--queue", required=True, help="quarantine_queue.json のパス")
    q.add_argument("--list", action="store_true")
    q.add_argument("--add", help="decision record JSON のパス")
    q.add_argument("--resolve", help="裁定する queue_id")
    q.add_argument("--status", help="ingested | rejected")
    q.add_argument("--note", help="裁定メモ")
    q.set_defaults(fn=cmd_queue)
    return p


def main(argv=None):
    """CLI エントリ。入力不備は exit 4 (fail-closed — 呼び出し側は suspicious 扱い)。"""
    try:
        args = build_parser().parse_args(argv)
        return args.fn(args)
    except GateInputError as e:
        print(f"🚫 gate_decision: {e}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    sys.exit(main())
