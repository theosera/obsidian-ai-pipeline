#!/usr/bin/env python3
"""run_threat_report_views_tests.py — scripts/threat_report_views.py の決定論回帰テスト.

週次取込の workflow が --write で回す「読む用の写し」(raw/<date>-view.md) の器具を、
一時ディレクトリだけで確かめる (network / vault / pnpm 不要・stdlib のみ)。

検証する不変条件:
  対象は YYYY-MM-DD.md.txt だけ (legacy .md・-view.md・他の名は触らない)
  原文 .md.txt は替えない
  写しは本文全体を 1 つの fence に閉じ込め、fence は本文のどの backtick 列より長い
  他の plugin が動く印 (<%) は書き替える
  2 回目は unchanged (冪等)・--write なしでは何も書かない
  UTF-8 でない・NUL を含む・symlink の原文や写し先は error で、写しを書かない
  書き込みに失敗しても一時ファイルを残さない
  終了コード: error があれば 1・引数や dir が不正なら 2・それ以外は 0
"""
import importlib.util
import io
import os
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "..", "threat_report_views.py")

spec = importlib.util.spec_from_file_location("trv", TOOL)
trv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trv)

PASS, FAIL = "✅ PASS", "❌ FAIL"
failures = 0


def check(name, cond, detail=""):
    global failures
    print(f"  {PASS if cond else FAIL}  {name}" + (f" — {detail}" if detail else ""))
    if not cond:
        failures += 1


def run_main(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = trv.main(argv)
    return code, out.getvalue(), err.getvalue()


BODY = "---\nreport_type: llm_security_weekly\n---\n\n## 1. list\n\ntext `inline` and ```` four ```` here\n<% tp.file.title %>\n"

print("== render: 見出し・fence・印の書き替え ==")
view = trv.render("2026-11-23", BODY)
check("見出しは日付と「読む用」", view.startswith("# 2026-11-23 週報（読む用）\n\n"), view[:40])
check("原文の名を示す", "`2026-11-23.md.txt`" in view)
check("fence は本文の最長の backtick 列 (4) より長い 5 本", "\n`````\n" in view and view.endswith("`````\n"))
check("<% は < % に書き替える", "<%" not in view and "< % tp.file.title %>" in view)
check("本文の他の字は替えない", "text `inline` and ```` four ```` here" in view)
check("backtick の無い本文でも fence は 3 本", trv.fence_for("plain\n") == "```")
check("末尾に改行が無い本文にも改行を足して閉じる",
      trv.render("2026-01-01", "no newline").endswith("no newline\n```\n"))

print("\n== build_all: 対象の名・冪等・dry run ==")
with tempfile.TemporaryDirectory() as d:
    raw = Path(d)
    src = raw / "2026-11-23.md.txt"
    src.write_text(BODY, encoding="utf-8")
    (raw / "2026-11-16.md").write_text("legacy", encoding="utf-8")
    (raw / "notes.md.txt").write_text("other", encoding="utf-8")
    (raw / "2026-11-09-view.md").write_text("old view", encoding="utf-8")
    before = src.read_bytes()

    code, out, _ = run_main([str(raw)])
    check("dry run は exit 0", code == 0, out)
    check("dry run は created 1 と数える", "'created': 1" in out, out)
    check("dry run は何も書かない", not (raw / "2026-11-23-view.md").exists())

    code, out, _ = run_main([str(raw), "--write"])
    target = raw / "2026-11-23-view.md"
    check("--write は exit 0", code == 0, out)
    check("写しができる", target.is_file())
    check("写しの中身は render と同じ", target.read_text(encoding="utf-8") == trv.render("2026-11-23", BODY))
    check("原文 .md.txt は替わらない", src.read_bytes() == before)
    check("legacy .md・他の名・既存の -view.md からは写しを作らない",
          sorted(p.name for p in raw.iterdir()) == sorted([
              "2026-11-16.md", "2026-11-23-view.md", "2026-11-23.md.txt",
              "notes.md.txt", "2026-11-09-view.md"]),
          str(sorted(p.name for p in raw.iterdir())))
    check("一時ファイルが残らない", not any(p.name.endswith(".tmp") for p in raw.iterdir()))

    code, out, _ = run_main([str(raw), "--write"])
    check("2 回目は unchanged 1 (冪等)", code == 0 and "'unchanged': 1" in out and "'created': 0" in out, out)

    target.write_text("stale", encoding="utf-8")
    code, out, _ = run_main([str(raw), "--write"])
    check("古い写しは updated で書き直す",
          code == 0 and "'updated': 1" in out and target.read_text(encoding="utf-8") == trv.render("2026-11-23", BODY), out)

print("\n== error: 写しを書かず exit 1 ==")
with tempfile.TemporaryDirectory() as d:
    raw = Path(d)
    (raw / "2026-01-01.md.txt").write_bytes(b"\xff\xfe not utf-8")
    (raw / "2026-01-02.md.txt").write_text("has \x00 nul", encoding="utf-8")
    outside = Path(d).parent / f"{Path(d).name}-outside.txt"
    outside.write_text("outside", encoding="utf-8")
    try:
        (raw / "2026-01-03.md.txt").symlink_to(outside)
        (raw / "2026-01-04.md.txt").write_text("ok", encoding="utf-8")
        (raw / "2026-01-04-view.md").symlink_to(outside)
        (raw / "2026-01-05.md.txt").write_text("fine", encoding="utf-8")
        code, out, _ = run_main([str(raw), "--write"])
        check("error があれば exit 1", code == 1, out)
        check("UTF-8 でない原文は error", "error 2026-01-01.md.txt source is not UTF-8" in out, out)
        check("NUL を含む原文は error", "error 2026-01-02.md.txt source holds a NUL" in out, out)
        check("symlink の原文は error", "error 2026-01-03.md.txt source is not a regular file" in out, out)
        check("symlink の写し先は error", "error 2026-01-04.md.txt target is not a regular file" in out, out)
        check("error の原文からは写しを作らない",
              not any((raw / f"2026-01-0{i}-view.md").exists() for i in (1, 2, 3)))
        check("symlink の先の中身は替わらない", outside.read_text(encoding="utf-8") == "outside")
        check("正常な原文の写しは作る (error と同じ run でも)", (raw / "2026-01-05-view.md").is_file())
    finally:
        outside.unlink()

print("\n== 一時ファイルの名に置かれた symlink の先へ書かない ==")
with tempfile.TemporaryDirectory() as d:
    raw = Path(d)
    (raw / "2026-03-01.md.txt").write_text("body", encoding="utf-8")
    outside = Path(d).parent / f"{Path(d).name}-temp-outside.txt"
    outside.write_text("outside", encoding="utf-8")
    try:
        # 前の版が使っていた決まった名 (.<写しの名>.tmp) に、bot が symlink を置いた形。
        planted = raw / ".2026-03-01-view.md.tmp"
        planted.symlink_to(outside)
        code, out, _ = run_main([str(raw), "--write"])
        check("--write は exit 0", code == 0, out)
        check("symlink の先の中身は替わらない", outside.read_text(encoding="utf-8") == "outside")
        check("写しは raw の中に通常のファイルとしてできる",
              (raw / "2026-03-01-view.md").is_file() and not (raw / "2026-03-01-view.md").is_symlink())
        check("置かれた symlink はそのまま (器具は他人の名を消さない)", planted.is_symlink())
        check("器具の一時ファイルは残らない",
              not any(p.name.endswith(".tmp") and not p.is_symlink() for p in raw.iterdir()),
              str(sorted(p.name for p in raw.iterdir())))
        check("写しの権限は 0644", ((raw / "2026-03-01-view.md").stat().st_mode & 0o777) == 0o644,
              oct((raw / "2026-03-01-view.md").stat().st_mode & 0o777))
    finally:
        outside.unlink()

print("\n== 書き込みの失敗: 一時ファイルを残さない ==")
with tempfile.TemporaryDirectory() as d:
    raw = Path(d)
    (raw / "2026-02-01.md.txt").write_text("body", encoding="utf-8")
    real_replace = trv.os.replace

    def failing_replace(src, dst):
        raise OSError("simulated replace failure")

    trv.os.replace = failing_replace
    try:
        raised = False
        try:
            trv.build_one(raw / "2026-02-01.md.txt", "2026-02-01", write=True)
        except OSError:
            raised = True
    finally:
        trv.os.replace = real_replace
    check("失敗は呼び手へ上がる (workflow の段が赤になる)", raised)
    check("一時ファイルも写しも残らない",
          sorted(p.name for p in raw.iterdir()) == ["2026-02-01.md.txt"],
          str(sorted(p.name for p in raw.iterdir())))

print("\n== 引数と dir ==")
with tempfile.TemporaryDirectory() as d:
    code, _, err = run_main([])
    check("引数なしは exit 2", code == 2, err[:40])
    code, _, err = run_main([os.path.join(d, "missing")])
    check("無い dir は exit 2", code == 2, err)
    link = Path(d) / "link"
    link.symlink_to(d)
    code, _, err = run_main([str(link)])
    check("symlink の dir は exit 2", code == 2, err)

print(f"\n{'='*52}\n結果: {'全テスト PASS 🎉' if failures == 0 else f'{failures} 件 FAIL'}")
sys.exit(1 if failures else 0)
