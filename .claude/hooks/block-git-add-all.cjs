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

// `git` と subcommand の間には global option (`-c k=v` / `-C <dir>` / `--git-dir=…`) を
// 挟めるため、素の /git\s+add\b/ では `git -c … add .` にすり抜けられる。subcommand の
// 検出は必ずこのヘルパを通す（捕獲 group 1 = 引数列）。
const GIT_OPTS = '(?:\\s+(?:-[cC]\\s*\\S+|--(?:git-dir|work-tree|exec-path|namespace)=\\S+|--no-pager|--bare|--paginate))*';
const gitSubRe = (sub) => new RegExp(`\\bgit${GIT_OPTS}\\s+(?:${sub})\\b([^;&|]*)`);
// クォートで囲まれた文字列を落とす（`git commit -m "-n を直す"` の誤検知避け）。
const unquote = (s) => s.replace(/'[^']*'|"[^"]*"/g, ' ');

let cmd = '';
try {
  const j = JSON.parse(readStdin() || '{}');
  cmd = (j.tool_input && j.tool_input.command) || '';
} catch {
  deny('hook 入力を解釈できませんでした (fail-closed)。git ガードを通せないため実行をブロックします。');
}
if (!cmd) process.exit(0);

// --no-verify はどの git サブコマンドでも禁止（commit / push の hook バイパス防止）。
if (/(^|\s)--no-verify(\s|=|$)/.test(cmd)) {
  deny('`--no-verify` は禁止です（commit / secret-scan hook をバイパスしない / CLAUDE.md）。フックを通して実行してください。');
}

// `-n` は `git commit` では `--no-verify` の短縮形（束ね短縮フラグ `-an` 等も同様）。
// `grep -n` / `tail -n` / `git add -n`(=--dry-run) を巻き込まないよう、対象は
// `git commit` / `git push` / `git merge` の引数だけに限定する。
const nMatch = cmd.match(gitSubRe('commit|push|merge'));
if (nMatch) {
  const nArgs = unquote(nMatch[1]).trim().split(/\s+/).filter(Boolean);
  if (nArgs.some((a) => /^-[a-zA-Z]*n[a-zA-Z]*$/.test(a))) {
    deny('`-n` は `git commit` の `--no-verify` 短縮形なので禁止です（hook バイパス防止 / CLAUDE.md）。dry-run が目的なら `--dry-run` と明示してください。');
  }
}

// `core.hooksPath` の差し替えは committed hook を丸ごと無効化する（= --no-verify の一般化）。
// 読取 (`git config --get core.hooksPath`) は許可し、代入形だけを禁止する。
if (/core\.hooksPath\s*=/i.test(cmd) || /git\s+config\b[^;&|]*\bcore\.hooksPath\s+[^\s;&|<>]/i.test(cmd)) {
  deny('`core.hooksPath` の変更は禁止です（リポジトリの committed hook を丸ごと無効化するため / CLAUDE.md）。');
}

// `git add` の blanket 形を禁止: -A / --all（`--al` 等の省略形含む）/ 単独の "." "./" ".."
// "*" ":/" ":(top)" "$PWD" / リポジトリ root の絶対パス（複合短縮フラグ -Av 等も A を含めば対象）。
// シェルのクォートを剥がしてから判定する（`git add "."` / `git add '.'` のすり抜け防止 / Codex P2）。
const projectDir = (process.env.CLAUDE_PROJECT_DIR || process.cwd()).replace(/\/+$/, '');
const m = cmd.match(gitSubRe('add'));
if (m) {
  const args = m[1].trim().split(/\s+/).filter(Boolean).map((a) => a.replace(/['"]/g, ''));
  const blanket = args.some(
    (a) => a === '.' || a === './' || a === '..' || a === '../' || a === '*'
      || a === ':/' || a === ':(top)' || a === '$PWD' || a === '$PWD/' || a === '${PWD}'
      || a === projectDir || a === `${projectDir}/`
      // `--all` は git の一意接頭辞規則で `--al` 等に省略できる（`--a` は曖昧でエラー）。
      || (a.startsWith('--a') && '--all'.startsWith(a))
      || (/^-[a-z]*$/i.test(a) && a.includes('A')),
  );
  if (blanket) {
    deny('`git add -A` / `git add .` / `--all`（`.` `..` `*` `:/` `:(top)` `$PWD` / リポジトリ root の絶対パス含む）は禁止です。CLAUDE.md の規約に従い、ファイルを個別に列挙して add してください（untracked secret の巻き込み防止）。');
  }
}

process.exit(0);
