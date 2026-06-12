#!/usr/bin/env node
'use strict';
/**
 * PreToolUse(Bash) ガード ①: secret-looking file の `git add` / `git commit` をブロックする。
 *
 * `.claude/settings.json` の deny は **読取**経路 (Read / cat / grep …) しか塞がない。
 * 本フックはその穴を埋めて **add / commit（=履歴への書込）**経路を塞ぐ。CLAUDE.md の
 * 「絶対に commit しないファイル」を tool-permission 層で機械的に強制する。
 *
 * 入力: stdin に PreToolUse の JSON ({ tool_input: { command } })。
 * 出力: ブロック時は hookSpecificOutput.permissionDecision="deny" を返す。許可時は無出力。
 * 副作用: `git commit` のときだけ `git diff --cached --name-only` を読む（読取のみ）。
 */
const fs = require('node:fs');
const { execFileSync } = require('node:child_process');

function readStdin() {
  try { return fs.readFileSync(0, 'utf8'); } catch { return ''; }
}

// CLAUDE.md / settings.json の secret 一覧に対応。basename・相対パスのどちらでも当たる。
const SECRET_RE = [
  /(^|\/)\.env(\.|$)/i,             // .env / .env.local / .env.production ...
  /(^|\/)x_tokens\.json$/i,
  /(^|\/)data\/tokens\.json$/i,
  /(^|\/)pkce_state\.json$/i,
  /(^|\/)credentials[^/]*\.json$/i,
  /(^|\/)service-account[^/]*\.json$/i,
  /[^/]*token[^/]*\.json$/i,        // *token*.json
  /(^|\/)pipeline_config\.json$/i,
  /\.(key|pem)$/i,
  /(^|\/)id_(rsa|ed25519)$/i,
  /(^|\/)secrets\.(json|ya?ml)$/i,
  /(^|\/)secrets\//i,
];

// .env.example だけは許可（テンプレート）。
const isAllowlisted = (p) => /(^|\/)\.env\.example$/i.test(p);
const isSecret = (p) => !!p && !isAllowlisted(p) && SECRET_RE.some((re) => re.test(p));

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
if (!cmd || !/(^|[;&|(]\s*)git\b/.test(cmd)) process.exit(0);

// ① `git add <paths>` — 明示パス引数を検査。
const addMatch = cmd.match(/git\s+add\b([^;&|]*)/);
if (addMatch) {
  const paths = addMatch[1].trim().split(/\s+/).filter((a) => a && !a.startsWith('-'));
  const bad = paths.filter(isSecret);
  if (bad.length) {
    deny(
      `secret-looking file を git add しようとしています: ${bad.join(', ')}\n` +
      'CLAUDE.md の Secrets 境界によりブロックしました（.gitignore 済みのはず）。本当に追跡が必要か再検討してください。',
    );
  }
}

// ② `git commit` — 現在 staged のファイルを検査（add 経由でなくても漏れを止める）。
if (/git\s+commit\b/.test(cmd)) {
  let staged = '';
  try {
    staged = execFileSync('git', ['diff', '--cached', '--name-only'], {
      cwd: process.env.CLAUDE_PROJECT_DIR || process.cwd(),
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    });
  } catch { staged = ''; }
  const bad = staged.split('\n').map((s) => s.trim()).filter(isSecret);
  if (bad.length) {
    deny(
      `staged に secret-looking file が含まれています: ${bad.join(', ')}\n` +
      'このまま commit すると機密が履歴に入ります。`git restore --staged <file>` で外してから commit してください（CLAUDE.md ハードルール）。',
    );
  }
}

process.exit(0);
