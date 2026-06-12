#!/usr/bin/env node
'use strict';
/**
 * PreToolUse(Bash) ガード ②: `git add -A` / `git add .` / `--all` と、あらゆる `--no-verify`
 * をブロックする。CLAUDE.md のハードルール:
 *   - 「`git add -A` / `git add .` は使わない — 具体的なファイル名を列挙する」
 *     (untracked secret の巻き込み事故防止)
 *   - 「`--no-verify` で commit hook をスキップしない」(secret-scan hook の bypass 文化を作らない)
 *
 * 入力: stdin に PreToolUse の JSON。出力: ブロック時 permissionDecision="deny"。
 */
const fs = require('node:fs');
function readStdin() {
  try { return fs.readFileSync(0, 'utf8'); } catch { return ''; }
}
function deny(reason) {
  process.stdout.write(JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: reason,
    },
  }));
  process.exit(0);
}

let cmd = '';
try {
  const j = JSON.parse(readStdin() || '{}');
  cmd = (j.tool_input && j.tool_input.command) || '';
} catch { process.exit(0); }
if (!cmd) process.exit(0);

// --no-verify はどの git サブコマンドでも禁止（commit / push の hook バイパス防止）。
if (/(^|\s)--no-verify(\s|=|$)/.test(cmd)) {
  deny('`--no-verify` は禁止です（commit / secret-scan hook をバイパスしない / CLAUDE.md）。フックを通して実行してください。');
}

// `git add` の blanket 形を禁止: -A / --all / 単独の "." / "./"（複合短縮フラグ -Av 等も A を含めば対象）。
// シェルのクォートを剥がしてから判定する（`git add "."` / `git add '.'` のすり抜け防止 / Codex P2）。
const m = cmd.match(/git\s+add\b([^;&|]*)/);
if (m) {
  const args = m[1].trim().split(/\s+/).filter(Boolean).map((a) => a.replace(/['"]/g, ''));
  const blanket = args.some(
    (a) => a === '.' || a === './' || a === '--all' || (/^-[a-z]*$/i.test(a) && a.includes('A')),
  );
  if (blanket) {
    deny('`git add -A` / `git add .` / `--all` は禁止です。CLAUDE.md の規約に従い、ファイルを個別に列挙して add してください（untracked secret の巻き込み防止）。');
  }
}

process.exit(0);
