#!/usr/bin/env python3
"""scan-threat-report.py — L1 安価ヒューリスティック層 (signal 出力のみ).

/sec-mode が Gmail から取り込む週次 LLM 脅威レポート (LLM-Sec-Weekly) 本文を、
ingest が **何も書き込む前に** 走査し、直接/間接プロンプトインジェクションの
「signal」を行番号・文脈クラスつきで列挙する。

設計上の役割 (詳細は ../SKILL.md):
  - 本層は **断定しない / block しない**。signal を出すだけ。最終 verdict は
    L2 (隔離 LLM 判定) + L3 (ポリシー) が決める。
  - キーワード一致 = injection ではない。脅威レポートは injection を **解説**
    として正当に含む (例: `## 4. 実装検証観点` 表の "ignore previous
    instructions")。そこで各 signal に **context_class** と **live** 推定を付け、
    「データ/例示」か「読み手宛てのライブ命令」かを区別できるようにする。
  - `live` は **advisory**。clean 判定には使わない (P2)。clean は
    「signal が 0 かつ契約違反なし」のときのみ。それ以外は L2 が全 signal を
    精査する (SKILL §L2/§L3)。
  - L1 は line-based regex なので recall に限界がある (行分割・新規表現は
    取りこぼす)。そこで (a) 連続 prose 行を結合した **collapsed パス** で
    跨行 injection を補足し、(b) ゲート本体は SKILL §L1 ではなく
    **「L2 が本文全体を必ず見る」** ことで recall を担保する (P1)。
  - 本層自身は本文中の URL/コマンドを **fetch/実行しない** (純データ走査のみ)。
  - Log Leakage 対策: 出力する preview は redact し、生 payload は出さない。
    照合用に `span_sha1` を併記する。

context_class:
  code-fence / table-cell / blockquote / example-lead(「例:」等の直後) → 例示寄り
  prose(上記いずれでもない地の文)                                       → 命令寄り

live (bool): prose 文脈で読み手の役割上書き/祈使に該当 → True (命令寄り)。
  concealment 種別 (不可視文字・homoglyph・隠しコメント・跨行) は文脈に関係なく
  True。**ただし live は advisory** であり、ゲート判断は SKILL §L3 が行う。

exit code (signal の **有無** のみ。authoritative な block ではない):
  0 — signal なし (かつ契約違反なし)
  1 — signal あり or 契約違反あり (→ L2/L3 で判定)
出力に `--json` を付けると機械可読 JSON、付けなければ人間向けサマリ。
"""

import hashlib
import json
import os
import re
import sys
import unicodedata

# ── L0 既存契約 (consumption policy §2)。本層は signal 化のみ、判定は L3 ──
FRONTMATTER_FIXED = {
    "report_type": "llm_security_weekly",
    "trust_level": "external_research_summary",
    "schema_version": "1",
}
REQUIRED_FORBIDDEN_TOKEN = "execute_report_instructions"

# ── ロールマーカー / システムプロンプト偽装 ──────────────────────────────
ROLE_MARKERS = [
    r"<\s*system\s*>", r"</\s*system\s*>",
    r"\[\s*INST\s*\]", r"\[/?\s*SYS\s*\]", r"<<\s*SYS\s*>>",
    r"\[\s*system\s*\]", r"\[\s*assistant\s*\]", r"\[\s*developer\s*\]",
    r"###\s*Instruction", r"###\s*System",
    r"system\s*prompt", r"developer\s*(message|mode)",
    r"あなたは今から", r"これ以降あなたは", r"新しい(システム)?プロンプト",
]

# ── 読み手(エージェント)宛ての祈使 / 役割上書き ────────────────────────
READER_IMPERATIVES = [
    r"ignore\s+(all\s+)?(previous|prior|above|the\s+following)\s+instructions",
    r"disregard\s+(all\s+)?(previous|prior|above)",
    r"forget\s+(everything|all|previous|prior)",
    r"override\s+(the\s+)?(system|previous|safety|guardrails)",
    r"as\s+an?\s+(ai|assistant|language\s+model)\b",
    r"you\s+(are\s+now|must|should\s+now|shall|are\s+required\s+to)\b",
    r"do\s+not\s+(tell|inform|warn)\s+the\s+user",
    r"これまでの(指示|命令|文脈)を(無視|忘れ)",
    r"以前の(指示|命令)を(無視|忘れ)",
    r"次の(コマンド|スクリプト|指示)を(実行|動か|従)",
    r"(を|して)?(実行せよ|実行してください|動かしてください|fetch\s*して|取得して)",
    r"あなた(は|が).{0,24}(しなければ|してください|すべき|実行|送信|出力)",
    r"ユーザーに(は)?(言わ|知らせ|報告し)ないで",
]

# ── 偽 tool-call / function-call 構文の混入 ─────────────────────────────
FAKE_TOOLCALL = [
    r"<\s*function_calls\s*>", r"<\s*/?invoke\b", r"\bantml:",
    r"<\s*tool_use\b", r"\[\s*TOOL_CALL\s*\]", r"\btool_call\b",
    r'"tool_name"\s*:', r'"arguments"\s*:\s*\{', r"\bfunctions\.\w+\(",
    r"<\s*/?tool_call\s*>",
]

# ── 実行されうる埋め込みコマンド ───────────────────────────────────────
EMBEDDED_COMMAND = [
    r"curl\s+[^\n|]*\|\s*(ba)?sh", r"wget\s+[^\n|]*\|\s*(ba)?sh",
    r"\bbase64\s+-d\b[^\n]*\|\s*(ba)?sh", r"\beval\s*\(",
    r"rm\s+-rf\s+[~/]", r":\(\)\s*\{.*\};:",
    r"\bgit\s+config\b.*hooksPath", r"\bchmod\s+777\b",
    r"\bcurl\b[^\n]*\b-d\b", r"\bcurl\b[^\n]*--data",  # POST 持ち出し
]

# ── データ持ち出し誘導 URL ─────────────────────────────────────────────
EXFIL_URL = [
    r"https?://(127\.0\.0\.1|localhost|0\.0\.0\.0|169\.254\.169\.254)\b",
    r"\bdata:text/", r"\bfile://",
    r"https?://[^\s)]*\.(?:tk|gq|ml|cf)\b",
    r"https?://[^\s)]*[?&](token|secret|key|cred|env|aws|cookie)=",  # local 情報を載せる
]

# ── 不可視 / ステガノグラフィ文字 ──────────────────────────────────────
INVISIBLE_RANGES = [
    (0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x2064),
    (0x2066, 0x206F), (0xFEFF, 0xFEFF), (0xE0000, 0xE007F),
]

# 跨行 collapsed パスで使う「読み手宛て命令」系 (concealment 種別は行内で拾える)
CROSS_LINE_PATS = ROLE_MARKERS + READER_IMPERATIVES + FAKE_TOOLCALL


# ── homoglyph 判定用 (混在で偽装) ──────────────────────────────────────
def char_script(ch):
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return None
    for s in ("LATIN", "CYRILLIC", "GREEK"):
        if name.startswith(s):
            return s
    return None


def is_invisible(ch):
    cp = ord(ch)
    for lo, hi in INVISIBLE_RANGES:
        if lo <= cp <= hi:
            return True
    if ch in "\n\r\t":
        return False
    return unicodedata.category(ch) in ("Cf", "Co", "Cs")


def sha1(s):
    return hashlib.sha1(s.encode("utf-8", "replace")).hexdigest()[:10]


def redact(line, pos, span_len, ctx=12):
    """前後 ctx 文字だけ残し、ヒット本体は伏字化 (Log Leakage 対策)."""
    seg = line[pos:pos + span_len]
    lead = line[max(0, pos - ctx):pos]
    tail = line[pos + span_len:pos + span_len + ctx]
    masked = "▮" * min(len(seg), 8)
    pre = "…" if pos - ctx > 0 else ""
    return f"{pre}{lead}⟦{masked}⟧{tail}".replace("\n", " ").strip()


# ───────────────────────── 文脈クラス判定 ─────────────────────────────
EXAMPLE_LEAD = re.compile(
    r"(例\s*[:：]|以下は.{0,8}(攻撃|例|サンプル)|攻撃例|e\.?g\.?[:：]?|for\s+example|"
    r"危険な兆候|sample|payload\s+example)", re.IGNORECASE)


def classify_context(line, in_code_block, prev_line):
    stripped = line.lstrip()
    if in_code_block:
        return "code-fence"
    if stripped.startswith("|"):
        return "table-cell"
    if stripped.startswith((">",)):
        return "blockquote"
    if "`" in line:
        return "code-fence"  # インラインコードも例示寄り扱い
    if EXAMPLE_LEAD.search(line) or (prev_line and EXAMPLE_LEAD.search(prev_line)):
        return "example-lead"
    return "prose"


EXAMPLE_CONTEXTS = {"code-fence", "table-cell", "blockquote", "example-lead"}
CONCEALMENT_KINDS = {"invisible-char", "homoglyph", "hidden-comment",
                     "multiline-injection"}

# 同一行内の「解説フレーミング」= injection 文字列を“説明・引用”しているだけの兆候。
# prose 文脈でもこれがあれば live を降格する (脅威の解説を誤検知しないため)。
# 注: live は advisory。降格しても signal 自体は残り、L2 が全 signal を再確認する。
EXPLAIN_FRAME = re.compile(
    r"(のような|のように|の例|という(文字列|記述|指示|語)|と(書か|記載)|"
    r"を(埋め|除去|弾|無害化|検出|解釈|載せ|含)|外部文書(内)?|payload|攻撃例|"
    r"危険な兆候|文字列を|サンプル|のケース|を混ぜ)", re.IGNORECASE)

# 引用符で括られた語 (「…」 / "…" / '…' 等) も解説扱いの兆候。
QUOTE_CHARS = "「」『』“”\"'＂｢｣"


def scan_text(text):
    lines = text.splitlines()
    signals = []
    sid = 0
    in_code_block = False

    def quote_enclosed(line, start, end):
        """match 周辺に引用符の開き/閉じがあれば True (引用= 解説寄り)."""
        before = line[:start]
        after = line[end:]
        return any(q in before for q in QUOTE_CHARS) and \
               any(q in after for q in QUOTE_CHARS)

    def add(kind, lineno, line, m, ctx_class):
        nonlocal sid
        sid += 1
        explanatory = bool(EXPLAIN_FRAME.search(line)) or \
            (m is not None and quote_enclosed(line, m.start(), m.end()))
        live = (kind in CONCEALMENT_KINDS) or \
               (ctx_class not in EXAMPLE_CONTEXTS and not explanatory and
                kind in ("role-marker", "reader-imperative", "fake-tool-call",
                         "embedded-command", "exfil-url"))
        span = line[m.start():m.end()] if m else ""
        signals.append({
            "id": sid, "kind": kind, "line": lineno,
            "context_class": ctx_class, "live": live,
            "preview": redact(line, m.start(), m.end() - m.start()) if m else "",
            "span_sha1": sha1(span) if span else "",
        })

    grouped = [
        ("role-marker", ROLE_MARKERS),
        ("reader-imperative", READER_IMPERATIVES),
        ("fake-tool-call", FAKE_TOOLCALL),
        ("embedded-command", EMBEDDED_COMMAND),
        ("exfil-url", EXFIL_URL),
    ]

    # ── (1) 行単位パス ──────────────────────────────────────────────
    prev = ""
    line_ctx = []  # (lineno, ctx) — collapsed パスの除外判定に再利用
    for i, line in enumerate(lines, 1):
        if line.lstrip().startswith(("```", "~~~")):
            in_code_block = not in_code_block
            line_ctx.append((i, "code-fence"))
            prev = line
            continue
        ctx = classify_context(line, in_code_block, prev)
        line_ctx.append((i, ctx))

        for kind, pats in grouped:
            for pat in pats:
                for m in re.finditer(pat, line, re.IGNORECASE):
                    add(kind, i, line, m, ctx)

        # 隠しコメント内ペイロード
        for cm in re.finditer(r"<!--(.*?)-->", line):
            body = cm.group(1)
            if any(re.search(p, body, re.IGNORECASE)
                   for p in CROSS_LINE_PATS + EMBEDDED_COMMAND + EXFIL_URL):
                add("hidden-comment", i, line, cm, ctx)

        # homoglyph: 1 トークン内で Latin と (Cyrillic|Greek) が混在
        for tok in re.finditer(r"[^\s|`]+", line):
            scripts = {char_script(c) for c in tok.group() if char_script(c)}
            scripts.discard(None)
            if "LATIN" in scripts and (scripts & {"CYRILLIC", "GREEK"}):
                add("homoglyph", i, line, tok, ctx)

        prev = line

    # ── (2) collapsed パス: 連続 prose 行を結合し「跨行 injection」を補足 ──
    #     行単位 regex の recall 限界 (case "行分割") への補強。
    #     例示寄り文脈 (code/table/blockquote/example-lead) の行は混ぜない。
    #     単一行で既に拾える match は除外し、**跨行でしか成立しない** match のみ
    #     "multiline-injection" として出す (跨行=隠蔽の一種なので live=True、
    #     ただし解説フレーミングがあれば advisory として live を降格)。
    ctx_by_line = dict(line_ctx)
    para = []  # list of (lineno, line)
    paragraphs = []

    def flush_para():
        if len(para) >= 2:
            paragraphs.append(list(para))
        para.clear()

    for i, line in enumerate(lines, 1):
        ctx = ctx_by_line.get(i, "prose")
        if ctx == "prose" and line.strip():
            para.append((i, line))
        else:
            flush_para()
    flush_para()

    for plines in paragraphs:
        nums = [n for n, _ in plines]
        joined = " ".join(t for _, t in plines)
        for pat in CROSS_LINE_PATS:
            for m in re.finditer(pat, joined, re.IGNORECASE):
                seg = joined[m.start():m.end()]
                # 単一行で既に成立する match は (1) が拾っているので除外
                if any(re.search(pat, t, re.IGNORECASE) for _, t in plines):
                    continue
                explanatory = bool(EXPLAIN_FRAME.search(joined))
                sid += 1
                signals.append({
                    "id": sid, "kind": "multiline-injection",
                    "line": nums[0], "context_class": "prose-collapsed",
                    "live": not explanatory,
                    "preview": redact(joined, m.start(), m.end() - m.start()),
                    "span_sha1": sha1(seg),
                })

    # ── (3) 不可視文字 (桁特定) ─────────────────────────────────────
    for i, line in enumerate(lines, 1):
        invs = [(j, ch) for j, ch in enumerate(line) if is_invisible(ch)]
        if invs:
            names = ", ".join(sorted({f"U+{ord(ch):04X}" for _, ch in invs}))[:80]
            sid += 1
            signals.append({
                "id": sid, "kind": "invisible-char", "line": i,
                "context_class": "any", "live": True,
                "preview": f"{len(invs)} 個の不可視/制御文字: {names}",
                "span_sha1": sha1("".join(ch for _, ch in invs)),
            })
    return signals


def parse_frontmatter(text):
    if not text.startswith("---"):
        return None
    end = text.find("\n---", 3)
    if end == -1:
        return None
    fm, cur = {}, None
    for raw in text[3:end].splitlines():
        if not raw.strip():
            continue
        if re.match(r"^\s*-\s+", raw) and cur:
            fm[cur].append(raw.strip()[1:].strip())
            continue
        m = re.match(r"^([A-Za-z0-9_]+):\s*(.*)$", raw)
        if m:
            k, v = m.group(1), m.group(2).strip()
            if v == "":
                fm[k] = []
                cur = k
            else:
                fm[k] = v
                cur = None
    return fm


def check_contract(text):
    out = []
    fm = parse_frontmatter(text)
    if fm is None:
        return [{"code": "no-frontmatter", "message": "frontmatter (--- ブロック) が無い/不正"}]
    for k, exp in FRONTMATTER_FIXED.items():
        act = fm.get(k)
        if act is None:
            out.append({"code": "missing-key", "message": f"必須キー `{k}` が無い"})
        elif str(act).strip().strip("\"'") != exp:
            out.append({"code": "fixed-value", "message": f"`{k}` 固定値違反: 期待 `{exp}` / 実際 `{act}`"})
    pe = fm.get("period_end")
    if pe is None:
        out.append({"code": "missing-key", "message": "必須キー `period_end` が無い"})
    elif not re.match(r"^\d{4}-\d{2}-\d{2}$", str(pe).strip().strip("\"'")):
        out.append({"code": "bad-period_end", "message": f"`period_end` が YYYY-MM-DD でない: `{pe}`"})
    forb = fm.get("forbidden_usage")
    if isinstance(forb, list) and forb and \
       not any(REQUIRED_FORBIDDEN_TOKEN in str(x) for x in forb):
        out.append({"code": "missing-forbidden-token",
                    "message": f"`forbidden_usage` に必須トークン `{REQUIRED_FORBIDDEN_TOKEN}` 欠落"})
    return out


def section_shape_ok(text):
    """正規レポートは番号付きセクション (## 1. … / ## 4. …) を持つ定型."""
    return bool(re.search(r"^##\s*1\.", text, re.MULTILINE))


def suggested_level(contract, signals):
    """advisory のみ。L3 が最終決定する。clean 判断は『signal 0 かつ契約 OK』."""
    if contract:
        return "high"
    if any(s["live"] for s in signals):
        return "high"
    if signals:
        return "low"
    return "none"


def scan_file(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()
    signals = scan_text(text)
    contract = check_contract(text)
    return {
        "schema": "scan-threat-report/l1@2",
        "file": path,
        "structural": {
            "frontmatter_present": text.startswith("---"),
            "section_shape_ok": section_shape_ok(text),
            "contract_violations": contract,
        },
        "signals": signals,
        "counts": {
            "live": sum(1 for s in signals if s["live"]),
            "example": sum(1 for s in signals if not s["live"]),
            "total": len(signals),
        },
        # gate 用: L2 を起動すべきか (= clean 即決できないか)。
        # P2: live ではなく『signal の有無 ∨ 契約違反』で決める。
        "l2_required": bool(signals) or bool(contract),
        "suggested_signal_level": suggested_level(contract, signals),
    }


def collect_targets(arg):
    if os.path.isdir(arg):
        return sorted(os.path.join(r, fn)
                      for r, _, fs in os.walk(arg) for fn in fs if fn.endswith(".md"))
    return [arg]


def print_human(rep):
    print(f"\n================ {rep['file']} ================")
    st = rep["structural"]
    cv = st["contract_violations"]
    if cv:
        print("【L0 構造/契約 signal】")
        for v in cv:
            print(f"  🚫 [{v['code']}] {v['message']}")
    if not st["frontmatter_present"] or not st["section_shape_ok"]:
        print(f"  ⚠️  定型逸脱: frontmatter={st['frontmatter_present']} "
              f"section_shape={st['section_shape_ok']}")
    sigs = rep["signals"]
    if sigs:
        print(f"【L1 signal】live={rep['counts']['live']} "
              f"example/data={rep['counts']['example']}")
        for s in sorted(sigs, key=lambda x: (not x["live"], x["line"])):
            icon = "🔴" if s["live"] else "🔵"
            print(f"  {icon} L{s['line']:<4} [{s['kind']}/{s['context_class']}] "
                  f"{s['preview']}  (sha:{s['span_sha1']})")
    else:
        print("【L1 signal】なし")
    print(f"  → l2_required = {rep['l2_required']} / "
          f"suggested_signal_level = {rep['suggested_signal_level']} "
          f"(advisory。最終 verdict は L2+L3)")


def main():
    args = [a for a in sys.argv[1:] if a != "--json"]
    as_json = "--json" in sys.argv
    if len(args) != 1:
        print("usage: scan-threat-report.py [--json] <report.md|dir>", file=sys.stderr)
        return 2
    targets = collect_targets(args[0])
    if not targets:
        print(f"⚠️  対象 .md が見つからない: {args[0]}", file=sys.stderr)
        return 2

    reports, any_signal = [], False
    for p in targets:
        try:
            rep = scan_file(p)
        except FileNotFoundError:
            print(f"🚫 ファイルが無い: {p}", file=sys.stderr)
            continue
        reports.append(rep)
        if rep["l2_required"]:
            any_signal = True

    if as_json:
        print(json.dumps(reports if len(reports) > 1 else reports[0],
                         ensure_ascii=False, indent=2))
    else:
        for rep in reports:
            print_human(rep)
        print(f"\n[exit code = {1 if any_signal else 0}]  "
              f"# signal/契約違反の有無のみ。block 判断は L3 (SKILL.md 参照)")
    return 1 if any_signal else 0


if __name__ == "__main__":
    sys.exit(main())
