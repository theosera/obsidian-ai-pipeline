#!/usr/bin/env python3
"""run_gate_tests.py — L3 (gate_decision.py) の決定論回帰テスト.

L3 は決定論コードなので判定表の**全行**を期待値で固定できる。L2 は非決定の
LLM だが、本テストでは L2 の**出力 JSON** (fixtures/l2/*.json) を入力として
扱うため決定論に落ちる (= L2 スキーマ契約のテストでもある)。

検証する不変条件 (SKILL.md §L3 判定表 / docs/security/gate-decision-architecture.md):
  rule 1   契約違反 → blocked (L2 不要 / KSP 適用外)
  rule 2   ハード隠蔽 (invisible/homoglyph/hidden-comment/multiline∧live) → blocked
  rule 2'  multiline∧¬live (説明フレーム降格) → suspicious (clean には到達しない)
  rule 3   L2 欠落 / スキーマ逸脱 / tool-use 痕跡 → suspicious
  rule 4   concealment 軸 reject → blocked (確信度不問 / KSP 不可)
  rule 5   他軸 reject ∧ high ∧ アンカー済み → blocked (自動確定)
  rule 6   reject ∧ (≠high ∨ 未アンカー) → suspicious (幻覚ガード)
  rule 7   pass ∧ ≠high → suspicious / KSP 全一致でのみ解除 (空虚な真は不可)
  rule 8   live signal と L2 pass の不一致 → suspicious / KSP 一致でのみ解除
  rule 9   定型逸脱 → suspicious
  rule 10  heightened 中は KSP 停止 + signal/低確信度は全て suspicious
  rule 11  契約 OK ∧ 全軸 pass-high → clean
  CI プロファイルは rule 1/2/2' のみ (= 現行 workflow pre-scan と同義)
  exit code / trace 追記 / queue round-trip / KSP loud-fail
"""
import importlib.util
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(HERE, "..", "scripts")
FIX = os.path.join(HERE, "fixtures")
L2FIX = os.path.join(FIX, "l2")
FN_FIX = os.path.join(FIX, "fn_regression")


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


gd = load_module("gd", os.path.join(SCRIPTS, "gate_decision.py"))
st = load_module("st", os.path.join(SCRIPTS, "scan-threat-report.py"))

PASS, FAIL = "✅ PASS", "❌ FAIL"
failures = 0


def check(name, cond, detail=""):
    global failures
    print(f"  {PASS if cond else FAIL}  {name}" + (f" — {detail}" if detail else ""))
    if not cond:
        failures += 1


def l2(name):
    with open(os.path.join(L2FIX, name), "r", encoding="utf-8") as f:
        return json.load(f)


# ── 合成 L1 ビルダ ──────────────────────────────────────────────────────
def l1_base(signals=(), contract=(), shape_ok=True, file="raw/2026-06-08.md"):
    sig = list(signals)
    return {
        "schema": "scan-threat-report/l1@2",
        "file": file,
        "structural": {"frontmatter_present": True,
                       "section_shape_ok": shape_ok,
                       "contract_violations": list(contract)},
        "signals": sig,
        "counts": {"live": sum(1 for s in sig if s["live"]),
                   "example": sum(1 for s in sig if not s["live"]),
                   "total": len(sig)},
        "l2_required": not contract,
        "flagged": bool(sig) or bool(contract) or not shape_ok,
        "suggested_signal_level": "none",
    }


def sig(kind, ctx="table-cell", live=False, sid=1, sha="ab12cd34ef", line=27):
    return {"id": sid, "kind": kind, "line": line, "context_class": ctx,
            "live": live, "preview": "…⟦▮▮▮▮▮▮▮▮⟧…", "span_sha1": sha}


KSP_MATCHING = [{
    "id": "ksp-test-001", "signal_kind": "reader-imperative",
    "context_class": "table-cell", "match": {"span_sha1": "ab12cd34ef"},
    "rationale": "テスト用", "added": "2026-07-01",
}]
ALL_PASS = l2("all_pass_high.json")


def decide(l1, l2_doc, ksp=(), heightened=False, profile="interactive", **kw):
    return gd.decide(l1, l2_doc, list(ksp), heightened, profile, **kw)


print("== rule 1: 契約違反 → blocked (L2 不要 / KSP 適用外) ==")
r = decide(l1_base(contract=[{"code": "missing-forbidden-token", "message": "x"}]),
           None, ksp=KSP_MATCHING)
check("verdict = blocked", r["verdict"] == "blocked", r["final_rule"])
check("final_rule = l0-contract (KSP より先に確定)", r["final_rule"] == "l0-contract")
check("routing = quarantine", r["routing"] == "quarantine")

print("\n== rule 2: ハード隠蔽 → blocked ==")
for kind in ("invisible-char", "homoglyph", "hidden-comment"):
    r = decide(l1_base(signals=[sig(kind, live=True)]), ALL_PASS)
    check(f"{kind} → blocked", r["verdict"] == "blocked", r["final_rule"])
r = decide(l1_base(signals=[sig("multiline-injection", ctx="prose-collapsed",
                                live=True)]), ALL_PASS)
check("multiline∧live → blocked", r["verdict"] == "blocked", r["final_rule"])

print("\n== rule 2': multiline∧¬live (説明フレーム降格) → suspicious ==")
r = decide(l1_base(signals=[sig("multiline-injection", ctx="prose-collapsed",
                                live=False)]), ALL_PASS)
check("verdict = suspicious", r["verdict"] == "suspicious", r["final_rule"])
check("final_rule = l1-multiline-demoted", r["final_rule"] == "l1-multiline-demoted")
check("routing = queue (clean には到達しない)", r["routing"] == "queue")

print("\n== rule 3: L2 欠落 / スキーマ逸脱 / tool-use → suspicious ==")
r = decide(l1_base(), None)
check("L2 欠落 → suspicious (l2-missing)", r["verdict"] == "suspicious" and
      r["final_rule"] == "l2-missing")
r = decide(l1_base(), l2("schema_violation_missing_axis.json"))
check("軸欠落 → suspicious (l2-integrity)", r["verdict"] == "suspicious" and
      r["final_rule"] == "l2-integrity")
bad = json.loads(json.dumps(ALL_PASS))
bad["axes"]["role_override"]["extra"] = "x"
r = decide(l1_base(), bad)
check("想定外キー → suspicious", r["final_rule"] == "l2-integrity")
bad2 = json.loads(json.dumps(ALL_PASS))
bad2["axes"]["role_override"]["verdict"] = "reject"  # reject なのに証拠 0 件
r = decide(l1_base(), bad2)
check("reject ∧ 証拠 0 件 → suspicious", r["final_rule"] == "l2-integrity")
r = decide(l1_base(), ALL_PASS, l2_tool_use=True)
check("tool-use 痕跡 → suspicious", r["final_rule"] == "l2-tool-use-observed")

print("\n== rule 4: concealment 軸 reject → blocked (確信度不問) ==")
r = decide(l1_base(), l2("concealment_reject_low.json"))
check("low confidence でも blocked", r["verdict"] == "blocked",
      r["final_rule"])
check("final_rule = l2-axis-concealment-reject",
      r["final_rule"] == "l2-axis-concealment-reject")

print("\n== rule 5: reject ∧ high ∧ アンカー済み → blocked (自動確定) ==")
r = decide(l1_base(signals=[sig("reader-imperative", ctx="prose", live=True)]),
           l2("reject_high_anchored.json"))
check("verdict = blocked", r["verdict"] == "blocked", r["final_rule"])
check("final_rule = confirmed",
      r["final_rule"] == "l2-axis-reject-confirmed:reader_directed_command")

print("\n== rule 6: reject ∧ (≠high ∨ 未アンカー) → suspicious (幻覚ガード) ==")
r = decide(l1_base(signals=[sig("reader-imperative")]), l2("reject_medium.json"))
check("medium reject → suspicious", r["verdict"] == "suspicious", r["final_rule"])
r = decide(l1_base(), l2("reject_high_unanchored.json"))
check("high だが未アンカー → suspicious (自動 blocked しない)",
      r["verdict"] == "suspicious", r["final_rule"])
# KSP 解除: アンカー済み証拠の全 signal が KSP 一致 → reject を pass-high 扱い
r = decide(l1_base(signals=[sig("reader-imperative")]), l2("reject_medium.json"),
           ksp=KSP_MATCHING)
check("KSP 全一致で reject 解除 → clean", r["verdict"] == "clean",
      r["final_rule"])
check("KSP ヒットが記録される", any(
    h["pattern_id"] == "ksp-test-001" for h in r["known_safe_hits"]))

print("\n== rule 7: pass ∧ ≠high → suspicious / KSP で解除 / 空虚な真は不可 ==")
r = decide(l1_base(signals=[sig("reader-imperative")]),
           l2("pass_medium_confidence.json"))
check("medium pass → suspicious", r["verdict"] == "suspicious",
      r["final_rule"])
r = decide(l1_base(signals=[sig("reader-imperative")]),
           l2("pass_medium_confidence.json"), ksp=KSP_MATCHING)
check("KSP 全一致で解除 → clean", r["verdict"] == "clean", r["final_rule"])
r = decide(l1_base(), l2("pass_medium_confidence.json"), ksp=KSP_MATCHING)
check("signal 0 件の軸は KSP で解除不可 (空虚な真) → suspicious",
      r["verdict"] == "suspicious", r["final_rule"])
expired = [dict(KSP_MATCHING[0], expires="2020-01-01")]
r = decide(l1_base(signals=[sig("reader-imperative")]),
           l2("pass_medium_confidence.json"), ksp=expired)
check("失効 KSP は適用されない → suspicious", r["verdict"] == "suspicious")

print("\n== rule 8: live signal と L2 pass の不一致 → suspicious ==")
r = decide(l1_base(signals=[sig("reader-imperative", ctx="prose", live=True)]),
           ALL_PASS)
check("live ∧ L2 pass → suspicious", r["verdict"] == "suspicious",
      r["final_rule"])
check("final_rule = l1-l2-disagreement",
      r["final_rule"] == "l1-l2-disagreement:reader-imperative")
prose_ksp = [dict(KSP_MATCHING[0], context_class="prose")]
r = decide(l1_base(signals=[sig("reader-imperative", ctx="prose", live=True)]),
           ALL_PASS, ksp=prose_ksp)
check("KSP 一致で不一致解除 → clean", r["verdict"] == "clean", r["final_rule"])

print("\n== rule 9: 定型逸脱 → suspicious ==")
r = decide(l1_base(shape_ok=False), ALL_PASS)
check("shape NG → suspicious (l0-shape)", r["verdict"] == "suspicious" and
      r["final_rule"] == "l0-shape")

print("\n== rule 10: heightened — KSP 停止 / signal・低確信度は全て suspicious ==")
r = decide(l1_base(signals=[sig("reader-imperative")]),
           l2("pass_medium_confidence.json"), ksp=KSP_MATCHING, heightened=True)
check("heightened 中は KSP が効かない → suspicious",
      r["verdict"] == "suspicious", r["final_rule"])
check("heightened 中は KSP ヒットを『適用』しない",
      not r["known_safe_hits"])
r = decide(l1_base(signals=[sig("reader-imperative")]), ALL_PASS,
           heightened=True)
check("example signal のみでも heightened → suspicious",
      r["verdict"] == "suspicious" and r["final_rule"] == "heightened-mode")
r = decide(l1_base(), ALL_PASS, heightened=True)
check("signal 0 ∧ 全軸 pass-high は heightened でも clean",
      r["verdict"] == "clean", r["final_rule"])

print("\n== rule 11: clean (契約 OK ∧ 全軸 pass-high) ==")
r = decide(l1_base(), ALL_PASS)
check("verdict = clean", r["verdict"] == "clean", r["final_rule"])
check("routing = ingest", r["routing"] == "ingest")
check("heightened_mode が記録される", r["heightened_mode"] is False)

print("\n== CI プロファイル (L2 なし = 現行 workflow pre-scan と同義) ==")
r = decide(l1_base(), None, profile="ci")
check("signal 0 → clean (ci-l0l1-only)", r["verdict"] == "clean" and
      r["final_rule"] == "ci-l0l1-only")
r = decide(l1_base(signals=[sig("reader-imperative", ctx="prose", live=True)]),
           None, profile="ci")
check("非隠蔽 signal は CI では素通り (現行同義。/sec-mode の L2 が担う)",
      r["verdict"] == "clean")
r = decide(l1_base(contract=[{"code": "x", "message": "y"}]), None, profile="ci")
check("契約違反 → blocked", r["verdict"] == "blocked")
r = decide(l1_base(signals=[sig("homoglyph", live=True)]), None, profile="ci")
check("ハード隠蔽 → blocked", r["verdict"] == "blocked")
r = decide(l1_base(signals=[sig("multiline-injection", ctx="prose-collapsed",
                                live=False)]), None, profile="ci")
check("降格済み multiline → suspicious (隔離キュー行き)",
      r["verdict"] == "suspicious")
r = decide(l1_base(signals=[sig("reader-imperative")]), None, profile="ci",
           heightened=True)
check("heightened ∧ flagged → suspicious", r["verdict"] == "suspicious" and
      r["final_rule"] == "heightened-ci-flagged")

print("\n== quote アンカー (--body 照合) ==")
body = "\n".join(f"line {i}" for i in range(1, 30))
body = body.replace("line 12", "line 12 実行してください")
anchored_l2 = json.loads(json.dumps(l2("reject_high_unanchored.json")))
anchored_l2["axes"]["reader_directed_command"]["evidence"] = [
    {"line": 12, "quote": "実行してください"}]
r = decide(l1_base(), anchored_l2, body_text=body)
check("quote が本文該当行に逐語一致 → アンカー成立 → blocked",
      r["verdict"] == "blocked", r["final_rule"])
check("trace に quote 生文字列を残さない (sha1 のみ)",
      "実行してください" not in json.dumps(r, ensure_ascii=False))

print("\n== KSP ローダ: loud-fail (黙殺しない) ==")
tmpdir = tempfile.mkdtemp()
try:
    bad_ksp = os.path.join(tmpdir, "ksp.json")

    def write_ksp(patterns):
        with open(bad_ksp, "w", encoding="utf-8") as f:
            json.dump({"schema": "known-safe-patterns@1",
                       "patterns": patterns}, f, ensure_ascii=False)

    def loader_fails(patterns):
        write_ksp(patterns)
        try:
            gd.load_known_safe(bad_ksp)
            return False
        except gd.GateInputError:
            return True

    check("隠蔽系 kind の登録は拒否", loader_fails(
        [dict(KSP_MATCHING[0], signal_kind="homoglyph")]))
    check("必須フィールド欠落は拒否", loader_fails(
        [{"id": "x", "match": {"span_sha1": "a"}}]))
    check("regex 121 文字超は拒否", loader_fails(
        [dict(KSP_MATCHING[0], match={"regex": "a" * 121})]))
    check("コンパイル不能 regex は拒否", loader_fails(
        [dict(KSP_MATCHING[0], match={"regex": "("})]))
    check("span_sha1 と regex の同時指定は拒否", loader_fails(
        [dict(KSP_MATCHING[0], match={"span_sha1": "a", "regex": "b"})]))
    write_ksp([dict(KSP_MATCHING[0],
                    match={"regex": r"⟦▮+⟧", "max_len": 20})])
    pats = gd.load_known_safe(bad_ksp)
    r = decide(l1_base(signals=[sig("reader-imperative")]),
               l2("pass_medium_confidence.json"), ksp=pats)
    check("regex は redact 済み preview に当たる → 解除",
          r["verdict"] == "clean", r["final_rule"])

    print("\n== exit code / trace / queue round-trip (CLI 経由) ==")
    l1_path = os.path.join(tmpdir, "l1.json")
    l2_path = os.path.join(tmpdir, "l2.json")
    trace = os.path.join(tmpdir, "_gate", "decisions.jsonl")
    queue = os.path.join(tmpdir, "_gate", "quarantine_queue.json")
    state = os.path.join(tmpdir, "_gate", "gate_state.json")
    with open(l1_path, "w", encoding="utf-8") as f:
        json.dump(l1_base(), f)
    with open(l2_path, "w", encoding="utf-8") as f:
        json.dump(ALL_PASS, f)
    code = gd.main(["decide", "--l1", l1_path, "--l2", l2_path,
                    "--profile", "interactive", "--trace-out", trace,
                    "--queue", queue, "--json"])
    check("clean → exit 0", code == 0)
    with open(trace, encoding="utf-8") as f:
        lines = [json.loads(x) for x in f.read().splitlines()]
    check("clean でも trace に 1 行追記される",
          len(lines) == 1 and lines[0]["schema"] == "gate-decision@1")
    check("clean は queue に入らない", not os.path.exists(queue))

    with open(l1_path, "w", encoding="utf-8") as f:
        json.dump(l1_base(signals=[sig("reader-imperative")]), f)
    with open(l2_path, "w", encoding="utf-8") as f:
        json.dump(l2("pass_medium_confidence.json"), f)
    code = gd.main(["decide", "--l1", l1_path, "--l2", l2_path,
                    "--profile", "interactive", "--trace-out", trace,
                    "--queue", queue])
    check("suspicious → exit 2", code == 2)
    q = json.load(open(queue, encoding="utf-8"))
    check("suspicious は queue に pending で入る",
          len(q["items"]) == 1 and q["items"][0]["status"] == "pending")
    check("ksp_candidate が添えられる",
          q["items"][0]["ksp_candidate"]["signal_kind"] == "reader-imperative")
    qid = q["items"][0]["queue_id"]
    code = gd.main(["queue", "--queue", queue, "--resolve", qid,
                    "--status", "ingested", "--note", "FP: 表セル内の引用"])
    q = json.load(open(queue, encoding="utf-8"))
    check("resolve で status/note が更新される", code == 0 and
          q["items"][0]["status"] == "ingested" and
          q["items"][0]["adjudication_note"])

    with open(l1_path, "w", encoding="utf-8") as f:
        json.dump(l1_base(contract=[{"code": "x", "message": "y"}]), f)
    code = gd.main(["decide", "--l1", l1_path, "--profile", "ci"])
    check("blocked → exit 3", code == 3)
    code = gd.main(["decide", "--l1", os.path.join(tmpdir, "missing.json"),
                    "--profile", "ci"])
    check("入力不備 → exit 4 (fail-closed)", code == 4)
    write_ksp([dict(KSP_MATCHING[0], signal_kind="homoglyph")])
    code = gd.main(["decide", "--l1", l1_path, "--profile", "ci",
                    "--known-safe", bad_ksp])
    check("不正 KSP → exit 4 (黙殺しない)", code == 4)

    print("\n== mode (heightened) round-trip ==")
    code = gd.main(["mode", "--state", state, "--set-heightened",
                    "--reason", "fn-2026-test"])
    st_doc = json.load(open(state, encoding="utf-8"))
    check("set-heightened で state が立つ", code == 0 and st_doc["heightened"])
    code = gd.main(["mode", "--state", state, "--clear"])
    check("ack なしの clear は拒否 (exit 4)", code == 4)
    code = gd.main(["mode", "--state", state, "--clear",
                    "--ack", "FN 対応完了を確認した"])
    st_doc = json.load(open(state, encoding="utf-8"))
    check("ack 付き clear で解除 + 履歴に ack が残る",
          code == 0 and not st_doc["heightened"] and
          st_doc["history"][-1]["ack"])
finally:
    shutil.rmtree(tmpdir)

print("\n== end-to-end: 既存 L1 フィクスチャ → scan_file → decide ==")
e2e = [
    ("benign_explains_injection.md", "ci", None, "clean"),
    ("benign_explains_injection.md", "interactive", ALL_PASS, "clean"),
    ("malicious_live_instructions.md", "ci", None, "blocked"),
    ("malicious_multiline_split.md", "ci", None, "blocked"),
    # 例:接頭辞ロンダリングは L1 で live 降格されるため、検知責務は L2 の
    # 埋め込み陽性例 (SKILL.md §L2) にある。all-pass-high スタブでは clean に
    # なる = L3 単独では守らないことを明示する回帰 (L2 プロンプトの責務境界)。
    ("malicious_example_prefix.md", "ci", None, "clean"),
]
for fname, profile, l2_doc, expected in e2e:
    rep = st.scan_file(os.path.join(FIX, fname))
    r = gd.decide(rep, l2_doc, [], False, profile)
    check(f"{fname} [{profile}] → {expected}", r["verdict"] == expected,
          f"actual={r['verdict']} rule={r['final_rule']}")

print("\n== FN 回帰フィクスチャ (fn_regression/ 自動検出) ==")
fn_files = sorted(f for f in (os.listdir(FN_FIX) if os.path.isdir(FN_FIX) else [])
                  if f.endswith(".md") and f != "README.md")
if not fn_files:
    print("  (フィクスチャなし — FN 発生時に README.md の手順で追加する)")
for fname in fn_files:
    rep = st.scan_file(os.path.join(FN_FIX, fname))
    sidecar = os.path.join(FN_FIX, fname[:-3] + ".l2.json")
    l2_doc = (json.load(open(sidecar, encoding="utf-8"))
              if os.path.exists(sidecar) else ALL_PASS)
    r = gd.decide(rep, l2_doc, [], False, "interactive")
    check(f"fn_regression/{fname} は clean にならない",
          r["verdict"] != "clean", f"actual={r['verdict']}")

print(f"\n{'=' * 52}\n結果: {'全テスト PASS 🎉' if failures == 0 else f'{failures} 件 FAIL'}")
sys.exit(1 if failures else 0)
