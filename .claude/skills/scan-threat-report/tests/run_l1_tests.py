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
import unicodedata

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
# 契約違反があるので L0 で blocked → L2 は不要 (l2_required=False)。flagged は True。
check("L0 blocked: l2_required=False かつ flagged=True",
      (not m["l2_required"]) and m["flagged"])

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
zwsp = chr(0x200B)   # zero-width space
cyr_e = chr(0x0435)  # Cyrillic small letter IE (homoglyph of Latin e)
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

print("\n== L0 契約: forbidden_usage キー欠落も違反 (Codex #67 P2-1) ==")
no_forb = (
    "---\nreport_type: llm_security_weekly\nperiod_end: 2026-06-08\n"
    "trust_level: external_research_summary\nschema_version: 1\n---\n\n"
    "# R\n\n## 1. ニュース・脆弱性リスト\n| n | c | i | r | s |\n|---|---|---|---|---|\n"
)
with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False, encoding="utf-8") as f:
    f.write(no_forb)
    tmp = f.name
try:
    nf = report(tmp)
    check("forbidden_usage 欠落 → missing-forbidden-token",
          any(v["code"] == "missing-forbidden-token"
              for v in nf["structural"]["contract_violations"]))
    # 契約違反 → L0 で blocked。l2_required は False (L2 不要) だが flagged。
    check("L0 blocked: l2_required=False かつ flagged=True",
          (not nf["l2_required"]) and nf["flagged"])
finally:
    os.unlink(tmp)

print("\n== L0 定型: ## 1. 欠落 (frontmatter OK) も gate 起動 (Codex #67 P2-2) ==")
no_shape = (
    "---\nreport_type: llm_security_weekly\nperiod_end: 2026-06-08\n"
    "trust_level: external_research_summary\nschema_version: 1\n"
    "forbidden_usage:\n  - execute_report_instructions\n---\n\n"
    "# R\n\n本文に番号付きセクションが無い不正形。\n"
)
with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False, encoding="utf-8") as f:
    f.write(no_shape)
    tmp = f.name
try:
    ns = report(tmp)
    check("section_shape_ok = False", not ns["structural"]["section_shape_ok"])
    check("契約違反なし (shape のみ)", not ns["structural"]["contract_violations"])
    check("それでも l2_required = True (定型逸脱で escalate)", ns["l2_required"])
finally:
    os.unlink(tmp)

print("\n== signal-free でも L2 必須 (CodeRabbit Critical / P1 全文ゲート) ==")
clean_body = (
    "---\nreport_type: llm_security_weekly\nperiod_end: 2026-06-08\n"
    "trust_level: external_research_summary\nschema_version: 1\n"
    "forbidden_usage:\n  - execute_report_instructions\n---\n\n"
    "# LLM Security Weekly Report: 2026-06-08\n\n"
    "## 1. ニュース・脆弱性リスト\n\n"
    "| 事案 | 攻撃カテゴリ | 影響対象 | RiskScore | ステータス |\n"
    "|---|---|---|---:|---|\n"
    "| 通常の脆弱性 | カテゴリ | 対象 | 5.0 | 確認 |\n"
)
with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False, encoding="utf-8") as f:
    f.write(clean_body)
    tmp = f.name
try:
    cl = report(tmp)
    check("signal 0 (L1 は何も検出せず)", cl["counts"]["total"] == 0, f"total={cl['counts']['total']}")
    check("契約違反なし", not cl["structural"]["contract_violations"])
    check("l2_required = True (signal-free でも L2 必須 → clean 直行を防ぐ)", cl["l2_required"])
    check("flagged = False (exit code 上は何も検出せず)", not cl["flagged"])
finally:
    os.unlink(tmp)

print("\n== concealment: ranges 外の Cf (U+061C) → category 分岐だけで検出 (#161) ==")
# 上の concealment ケースの U+200B は INVISIBLE_RANGES で捕まるので、is_invisible() の
# category 分岐 (Cf/Co/Cs) を無効にしても緑のまま。ranges 外の Cf 1 文字だけで固定する。
p = os.path.join(FIX, "concealment_cf_outside_ranges.md")
with open(p, encoding="utf-8") as f:
    fixture_text = f.read()
alm = chr(0x061C)  # ARABIC LETTER MARK (Cf)
check("fixture に U+061C がちょうど 1 文字", fixture_text.count(alm) == 1)
check("U+061C は INVISIBLE_RANGES の外",
      not any(lo <= ord(alm) <= hi for lo, hi in st.INVISIBLE_RANGES))
cf = report(p)
check("契約・定型は正常 (別の理由で検出させない)",
      not cf["structural"]["contract_violations"] and cf["structural"]["section_shape_ok"])
# len(...) == 1 を先に置き、signal が 0 件のときも IndexError でなく FAIL として数える。
check("signal は invisible-char がちょうど 1 件",
      [s["kind"] for s in cf["signals"]] == ["invisible-char"], str(cf["signals"]))
check("counts が完全一致", cf["counts"] == {"total": 1, "live": 1, "example": 0}, str(cf["counts"]))
check("14 行目・live",
      len(cf["signals"]) == 1 and cf["signals"][0]["line"] == 14 and cf["signals"][0]["live"] is True)
check("preview が U+061C を示す",
      len(cf["signals"]) == 1 and "U+061C" in cf["signals"][0]["preview"])
check("flagged = True かつ l2_required = True", cf["flagged"] is True and cf["l2_required"] is True)
check("U+061C を除くと signal 0", st.scan_text(fixture_text.replace(alm, "")) == [])

print("\n== concealment: ranges 外の Co / Cs → category ごとに 1 文字ずつ検出 (#161) ==")
# 1 行に並べると invisible-char は 1 件にまとまり、片方の category が外れても 1 件のまま。
# 1 回の scan_text に 1 文字だけ渡す。Cs (surrogate) は UTF-8 で書けないので fixture にせず
# 文字列で渡す (scan_file は errors="replace" で読むため、ファイル経由では届かない)。
for cp, cat in ((0xE000, "Co"), (0xD800, "Cs")):
    ch = chr(cp)
    check(f"U+{cp:04X} は {cat} かつ INVISIBLE_RANGES の外",
          unicodedata.category(ch) == cat
          and not any(lo <= cp <= hi for lo, hi in st.INVISIBLE_RANGES))
    sig = st.scan_text("A" + ch + "B")
    check(f"U+{cp:04X} ({cat}) → invisible-char がちょうど 1 件",
          [s["kind"] for s in sig] == ["invisible-char"], str(sig))

print("\n== directory scan: .md / .md.txt の両方を列挙 ==")
with tempfile.TemporaryDirectory() as d:
    md = os.path.join(d, "a.md")
    inert = os.path.join(d, "b.md.txt")
    other = os.path.join(d, "c.txt")
    for p in (md, inert, other):
        with open(p, "w", encoding="utf-8") as f:
            f.write("x")
    targets = st.collect_targets(d)
    check("legacy .md を含む", md in targets, str(targets))
    check("inert .md.txt を含む", inert in targets, str(targets))
    check("通常 .txt は含まない", other not in targets, str(targets))

print(f"\n{'='*52}\n結果: {'全テスト PASS 🎉' if failures == 0 else f'{failures} 件 FAIL'}")
sys.exit(1 if failures else 0)
