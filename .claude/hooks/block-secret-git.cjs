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
const path = require('node:path');
const { execFileSync } = require('node:child_process');

function readStdin() {
  try { return fs.readFileSync(0, 'utf8'); } catch { return ''; }
}

// CLAUDE.md / settings.json の secret 一覧に対応。basename・相対パスのどちらでも当たる。
const SECRET_RE = [
  /(^|\/)\.env($|[.*?\s])/i,        // .env / .env.local / .env.production / glob の .env* ...
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
  /(^|\/)secrets(\/|$)/i,           // secrets/ 配下（末尾 / を伴わない裸のディレクトリ名も）
];

// .env.example だけは許可（テンプレート）。
const isAllowlisted = (p) => /(^|\/)\.env\.example$/i.test(p);
const isSecret = (p) => !!p && !isAllowlisted(p) && SECRET_RE.some((re) => re.test(p));

// `git` と subcommand の間には global option (`-c k=v` / `-C <dir>` / `--git-dir=…`) を
// 挟めるため、素の /git\s+commit\b/ では `git -c core.hooksPath=/dev/null commit` に
// すり抜けられる。subcommand の検出は必ずこのヘルパを通す（捕獲 group 1 = 引数列）。
const GIT_OPTS = '(?:\\s+(?:-[cC]\\s*\\S+|--(?:git-dir|work-tree|exec-path|namespace)=\\S+|--no-pager|--bare|--paginate))*';
const gitSubRe = (sub) => new RegExp(`\\bgit${GIT_OPTS}\\s+(?:${sub})\\b([^;&|]*)`);

// クォートに加えて**末尾のシェルメタ文字**も剥がしてからパス判定する
// （`(cd sub && git add .env)` の `.env)` が secret 判定をすり抜けるのを防ぐ）。
const stripToken = (a) => a.replace(/['"`]/g, '').replace(/[);&|]+$/, '');
// クォートで囲まれた文字列を落としたコマンド（`git commit -m "git add した"` の誤検知避け）。
// ただし **option 形のトークンは保持する**: シェルは `git commit "-a"` を `-a` として渡すので、
// 丸ごと落とすと `-a` 判定をすり抜ける（クォートするだけでガードが外れてしまう）。
const unquote = (s) => s.replace(/'([^']*)'|"([^"]*)"/g, (_m, sq, dq) => {
  const inner = sq !== undefined ? sq : dq;
  return /^--?[A-Za-z0-9][A-Za-z0-9-]*$/.test(inner) ? inner : ' ';
});

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
} catch {
  deny('hook 入力を解釈できませんでした (fail-closed)。secret ガードを通せないため実行をブロックします。');
}
// `git` を含まないコマンドだけを素通しする。先頭・区切り直後に限定すると改行 /
// `FOO=1 git …` / `command git …` / `xargs git …` でフック全体が無効化されるため
// （実際の判定は下の `git add` / `git commit` 側で行う）。
if (!cmd || !/\bgit\b/.test(cmd)) process.exit(0);

// ① `git add <paths>` — 明示パス引数を検査。シェルのクォートを剥がしてから判定する
//    （`git add ".env"` のすり抜け防止 / Codex P2）。フラグ除外はクォート除去後に行う。
const addMatch = cmd.match(gitSubRe('add'));
if (addMatch) {
  // 追加パスが stdin 側にある形は本フックから検査できない → 検査不能として拒否する。
  if (/--pathspec-(from-file|file-nul)\b/.test(addMatch[1])) {
    deny(
      '`git add --pathspec-from-file` / `--pathspec-file-nul` は追加パスが stdin 側にあり、\n' +
      'secret ガードから検査できません（検査不能なのでブロック）。追加するファイルをコマンドラインに列挙してください。',
    );
  }
  const paths = addMatch[1].trim().split(/\s+/)
    .map(stripToken)
    .filter((a) => a && !a.startsWith('-'));
  const bad = paths.filter(isSecret);
  if (bad.length) {
    deny(
      `secret-looking file を git add しようとしています: ${bad.join(', ')}\n` +
      'CLAUDE.md の Secrets 境界によりブロックしました（.gitignore 済みのはず）。本当に追跡が必要か再検討してください。',
    );
  }
}

// ② `git commit` — 現在 staged のファイルを検査（add 経由でなくても漏れを止める）。
//    ただし PreToolUse は**コマンド実行前**に走るため `git diff --cached` は「実行前の
//    index」しか見えない。同一コマンドで stage してから commit する形と `git commit -a`
//    はこの検査をすり抜けるので、形そのものを先に拒否し、staged 検査は backstop に残す。
const commitMatch = cmd.match(gitSubRe('commit'));
if (commitMatch) {
  if (gitSubRe('add|stage|rm|mv').test(unquote(cmd))) {
    deny(
      '同一コマンド内で staging (`git add` 等) と `git commit` を連結しています。\n' +
      'PreToolUse フックは**実行前**の index しか読めず staged secret 検査がすり抜けるためブロックしました。' +
      '`git add <files>` と `git commit …` を別々のコマンドとして実行してください（CLAUDE.md ハードルール）。',
    );
  }
  const commitArgs = unquote(commitMatch[1]).trim().split(/\s+/).filter(Boolean);
  if (commitArgs.some((a) => a === '--all' || /^-[a-zA-Z]*a[a-zA-Z]*$/.test(a))) {
    deny(
      '`git commit -a` / `-am` / `--all` はブロックしました。追跡済みファイルを commit 時に stage するため、\n' +
      '実行前の staged 検査をすり抜けます。`git add <files>` で明示的に stage してから commit してください。',
    );
  }
  // 検査対象は **そのコマンドが commit するリポ**。`git -C <dir> commit` を固定 cwd で
  // 検査すると別リポの index を見て素通しするので、global option を検査側にも反映する。
  const gitOptsPart = (cmd.match(new RegExp(`\\bgit(${GIT_OPTS})\\s+commit\\b`)) || [])[1] || '';
  if (/--git-dir=|--work-tree=/.test(gitOptsPart)) {
    deny(
      '`git --git-dir=… / --work-tree=… commit` は staged 検査の対象リポを一意に決められないため\n' +
      'ブロックしました (fail-closed)。対象リポの中で直接 commit してください。',
    );
  }
  const cDir = (gitOptsPart.match(/-C\s*(\S+)/) || [])[1];
  const baseDir = process.env.CLAUDE_PROJECT_DIR || process.cwd();
  const inspectCwd = cDir ? path.resolve(baseDir, stripToken(cDir)) : baseDir;
  let staged = '';
  try {
    staged = execFileSync('git', ['diff', '--cached', '--name-only'], {
      cwd: inspectCwd,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    });
  } catch {
    // 従来は staged='' として素通ししていた（fail-open）。存在しない `-C` 先を指すだけで
    // 検査を無効化できてしまうため、検査できないときは通さない。
    deny(
      `staged ファイルの検査に失敗しました (対象: ${inspectCwd})。\n` +
      '検査できない状態で commit を通すと staged secret を見逃すためブロックしました (fail-closed)。',
    );
  }
  const bad = staged.split('\n').map((s) => s.trim()).filter(isSecret);
  if (bad.length) {
    deny(
      `staged に secret-looking file が含まれています: ${bad.join(', ')}\n` +
      'このまま commit すると機密が履歴に入ります。`git restore --staged <file>` で外してから commit してください（CLAUDE.md ハードルール）。',
    );
  }
}

process.exit(0);
