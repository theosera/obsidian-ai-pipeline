#!/usr/bin/env python3
"""run_l1_tests.py — L1 層の決定論回帰テスト (FP/FN 計測).

L1 は決定論なので期待値で固定できる。L2 (隔離 LLM 判定) は非決定なので本テスト
の対象外 — そちらは「助言扱い + model/温度 pin」で運用し、回帰は良性/悪性の
verdict 期待値で別途確認する (SKILL.md §テスト)。

検証する不変条件:
  良性 (injection を解説するだけ)     → live=0 / 契約 OK   (= L3 で clean 候補)
  悪性 (読み手宛てライブ命令)          → live>=1 + 契約違反
  悪性 (跨行分割 — 行単位 regex 回避)  → multiline-injection signal (recall 補強)
  悪性 (例:接頭辞で live 降格)         → live=0 でも **l2_required=True** (P2:
                                          gate は live ではなく signal/契約で起動)
  concealment (zero-width / homoglyph) → live>=1
"""
import importlib.util
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCANNER = os.path.join(HERE, "..", "scripts", "scan-threat-report.py")
FIX = os.path.join(HERE, "fixtures")

spec = importlib.util.spec_from_file_location("st", SCANNER)
st = importlib.util.module_from_spec(spec)
spec.loader.exec_module(st)

PASS, FAIL = "✅ PASS", "❌ FAIL"
failures = 0


def check(name, cond, detail=""):
    global failures
    print(f"  {PASS if cond else FAIL}  {name}" + (f" — {detail}" if detail else ""))
    if not cond:
        failures += 1


def report(path):
    return st.scan_file(path)


print("== 良性 (injection を“解説”するだけ → clean 候補) ==")
b = report(os.path.join(FIX, "benign_explains_injection.md"))
check("live = 0", b["counts"]["live"] == 0, f"live={b['counts']['live']}/total={b['counts']['total']}")
check("契約違反なし", not b["structural"]["contract_violations"])
check("example/data signal を拾えている", b["counts"]["example"] >= 1, f"example={b['counts']['example']}")

print("\n== 悪性: 読み手宛てライブ命令 → blocked 期待 ==")
m = report(os.path.join(FIX, "malicious_live_instructions.md"))
check("live >= 1", m["counts"]["live"] >= 1, f"live={m['counts']['live']}")
kinds = {s["kind"] for s in m["signals"] if s["live"]}
for k in ("reader-imperative", "role-marker", "fake-tool-call", "exfil-url"):
    check(f"{k} を検出", k in kinds, str(kinds))
check("契約違反 (forbidden token 欠落)",
      any(v["code"] == "missing-forbidden-token" for v in m["structural"]["contract_violations"]))
check("l2_required = True", m["l2_required"])

print("\n== 悪性: 跨行分割 (行単位 regex 回避) → multiline 検出 (P1 recall 補強) ==")
ml = report(os.path.join(FIX, "malicious_multiline_split.md"))
mlkinds = {s["kind"] for s in ml["signals"]}
check("multiline-injection を検出", "multiline-injection" in mlkinds, str(mlkinds))
check("l2_required = True", ml["l2_required"])
check("live >= 1", ml["counts"]["live"] >= 1, f"live={ml['counts']['live']}")

print("\n== 悪性: 例:接頭辞で live 降格 → それでも gate 起動 (P2) ==")
ep = report(os.path.join(FIX, "malicious_example_prefix.md"))
check("signal は存在する", ep["counts"]["total"] >= 1, f"total={ep['counts']['total']}")
check("live は降格されている (=0)", ep["counts"]["live"] == 0, f"live={ep['counts']['live']}")
check("それでも l2_required = True (live で clean 判定しない)", ep["l2_required"])

print("\n== concealment (zero-width / homoglyph) → live 検出 ==")
zwsp = "​"
cyr_e = "е"  # Cyrillic IE — Latin 'e' そっくり
body = (
    "---\nreport_type: llm_security_weekly\nperiod_end: 2026-06-08\n"
    "trust_level: external_research_summary\nschema_version: 1\n"
    "forbidden_usage:\n  - execute_report_instructions\n---\n\n"
    "# LLM Security Weekly Report: 2026-06-08\n\n"
    f"Pl{zwsp}ease syst{cyr_e}m hidden content here.\n\n"
    "## 1. ニュース・脆弱性リスト\n| n | c | i | r | s |\n|---|---|---|---|---|\n"
)
with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False, encoding="utf-8") as f:
    f.write(body)
    tmp = f.name
try:
    c = report(tmp)
    ckinds = {s["kind"] for s in c["signals"]}
    check("invisible-char を検出", "invisible-char" in ckinds, str(ckinds))
    check("homoglyph を検出", "homoglyph" in ckinds, str(ckinds))
    check("live >= 1", c["counts"]["live"] >= 1, f"live={c['counts']['live']}")
finally:
    os.unlink(tmp)

print("\n== redaction (Log Leakage 対策) ==")
masked = any("⟦" in s["preview"] for s in m["signals"]
             if s["preview"] and s["kind"] != "invisible-char")
check("preview が伏字化されている", masked)
check("全 signal に span_sha1 が付く", all(s["span_sha1"] for s in m["signals"]))

print(f"\n{'='*52}\n結果: {'全テスト PASS 🎉' if failures == 0 else f'{failures} 件 FAIL'}")
sys.exit(1 if failures else 0)
