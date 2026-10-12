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
 * コマンドの読み取り（シェルの語・git の global option と subcommand）は
 * lib/git-guard-common.cjs にあり、git ガード 3 本で共有する。
 */
const path = require('node:path');
let guard;
try {
  guard = require('./lib/git-guard-common.cjs');
} catch {
  process.stdout.write(JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: 'git ガードの共通の部品 (lib/git-guard-common.cjs) を読み込めませんでした (fail-closed)。git ガードを通せないため実行をブロックします。',
    },
  }));
  process.exit(0);
}
const { deny } = guard;

const { cmd, baseDir } = guard.readInput('git ガード');
if (!cmd) process.exit(0);

// --no-verify はどの git サブコマンドでも禁止（commit / push の hook バイパス防止）。
if (/(^|\s)--no-verify(\s|=|$)/.test(cmd)) {
  deny('`--no-verify` は禁止です（commit / secret-scan hook をバイパスしない / CLAUDE.md）。フックを通して実行してください。');
}

const insp = guard.inspect(cmd);
if (insp.problems.length) deny(guard.problemMessage(insp.problems, 'git ガード'));

// shell の引用・escape を戻した語でも見る（--no-'verify' なども同じ option）。
for (const g of insp.gits) {
  const noVerify = g.sub === 'commit' ? guard.parseCommitArgs(g.args).noVerify :
    g.args.some((w) => /^--no-verify(?:=|$)/.test(w.text));
  if (noVerify) {
    deny('`--no-verify` は禁止です（commit / secret-scan hook をバイパスしない / CLAUDE.md）。フックを通して実行してください。');
  }
}

// `-n` が `--no-verify` の短縮形になるのは **`git commit` だけ**。
// `git push -n` は `--dry-run`、`git merge -n` は diffstat 抑制で、どちらも hook を
// バイパスしない (git の help で確認)。`grep -n` / `tail -n` / `git add -n` も同様に無関係。
// ⇒ 短縮形の判定は `git commit` の引数だけに限定する (長い `--no-verify` は上で全 git 禁止)。
for (const g of insp.gits) {
  if (g.sub !== 'commit') continue;
  if (g.args.some((w) => /^-[a-zA-Z]*n[a-zA-Z]*$/.test(w.text))) {
    deny('`-n` は `git commit` の `--no-verify` 短縮形なので禁止です（hook バイパス防止 / CLAUDE.md）。dry-run が目的なら `--dry-run` と明示してください。');
  }
}

// `core.hooksPath` の差し替えは committed hook を丸ごと無効化する（= --no-verify の一般化）。
// 読取 (`git config --get core.hooksPath`) は許可し、代入形だけを禁止する。
if (/core\.hooksPath\s*=/i.test(cmd) || /git\s+config\b[^;&|]*\bcore\.hooksPath\s+[^\s;&|<>]/i.test(cmd)) {
  deny('`core.hooksPath` の変更は禁止です（リポジトリの committed hook を丸ごと無効化するため / CLAUDE.md）。');
}

// `git add` / `git stage` の blanket 形を禁止: -A / --all（`--al` 等の省略形含む）/ 単独の "." "./"
// ".." "*" ":/" ":(top)" "$PWD" / リポジトリ root の絶対パス（複合短縮フラグ -Av 等も A を含めば対象）。
// root は CLAUDE_PROJECT_DIR に加えて、コマンドが走る場所（入力の cwd と `-C`）も見る。
const projectDir = (process.env.CLAUDE_PROJECT_DIR || process.cwd()).replace(/\/+$/, '');
for (const g of insp.gits) {
  if (g.sub !== 'add' && g.sub !== 'stage') continue;
  const inspectCwd = guard.resolveDir(baseDir, g.cdirs);
  const roots = new Set([projectDir, baseDir, inspectCwd].map((p) => path.resolve(p)));
  // `"$PWD"` のような変数の語は、引用符を外した元の文字で見る。
  const args = g.args.map((w) => (w.dynamic ? w.raw.replace(/['"]/g, '') : w.text));
  const blanket = args.some(
    (a) => a === '.' || a === './' || a === '..' || a === '../' || a === '*'
      || a === ':/' || a === ':(top)' || a === '$PWD' || a === '$PWD/' || a === '${PWD}'
      || roots.has(a.replace(/\/+$/, ''))
      // `--all` は git の一意接頭辞規則で `--al` 等に省略できる（`--a` は曖昧でエラー）。
      || (a.startsWith('--a') && '--all'.startsWith(a))
      || (/^-[a-z]*$/i.test(a) && a.includes('A')),
  );
  const normalizedRoot = g.args.some((w) => {
    let value = w.text;
    if (w.dynamic) {
      const raw = w.raw.replace(/['"]/g, '');
      if (!/^(?:\$PWD|\$\{PWD\})(?=\/|$)/.test(raw)) return false;
      // prefix は source で PWD と確かめ、suffix は shell が escape を戻した text から取る。
      // $PWD/\. は root、"$PWD/\." は backslash を含む別の path。
      if (!w.text.startsWith(guard.DYN)) return false;
      const suffix = w.text.slice(guard.DYN.length);
      if (suffix.includes(guard.DYN) || (suffix && !suffix.startsWith('/'))) return false;
      value = path.resolve(baseDir, `.${suffix}`);
    }
    if (!value || value.startsWith('-') || value.startsWith(':')) return false;
    return roots.has(path.resolve(inspectCwd, value));
  });
  if (blanket || normalizedRoot) {
    deny('`git add -A` / `git add .` / `--all`（`.` `..` `*` `:/` `:(top)` `$PWD` / リポジトリ root の絶対パス含む）は禁止です。CLAUDE.md の規約に従い、ファイルを個別に列挙して add してください（untracked secret の巻き込み防止）。');
  }
}

// v3.5.3: 今の main（ae10261）の同じ検査を、コマンドの文字の全体にもう一度当てる（和をとる）。
// 上の読み方が取りこぼしても、今の main より緩めないため。ブロックの中は main の文字のまま（空行のほかは main の行と同じ）。
const RECHECK_AS_MAIN = true;
if (RECHECK_AS_MAIN) {
// `git` と subcommand の間には global option (`-c k=v` / `-C <dir>` / `--git-dir=…`) を
// 挟めるため、素の /git\s+add\b/ では `git -c … add .` にすり抜けられる。subcommand の
// 検出は必ずこのヘルパを通す（捕獲 group 1 = 引数列）。
const GIT_OPTS = '(?:\\s+(?:-[cC]\\s*\\S+|--(?:git-dir|work-tree|exec-path|namespace)=\\S+|--no-pager|--bare|--paginate))*';
const gitSubRe = (sub) => new RegExp(`\\bgit${GIT_OPTS}\\s+(?:${sub})\\b([^;&|]*)`);
// クォートで囲まれた文字列を落とす（`git commit -m "-n を直す"` の誤検知避け）。
// option 形のトークンは保持する: シェルは `git commit "-n"` を `-n` として渡すので、
// 丸ごと落とすとクォートするだけでガードが外れる (block-secret-git.cjs と同一の扱い)。
const unquote = (s) => s.replace(/'([^']*)'|"([^"]*)"/g, (_m, sq, dq) => {
  const inner = sq !== undefined ? sq : dq;
  return /^--?[A-Za-z0-9][A-Za-z0-9-]*$/.test(inner) ? inner : ' ';
});

// `-n` が `--no-verify` の短縮形になるのは **`git commit` だけ**。
// `git push -n` は `--dry-run`、`git merge -n` は diffstat 抑制で、どちらも hook を
// バイパスしない (git の help で確認)。`grep -n` / `tail -n` / `git add -n` も同様に無関係。
// ⇒ 短縮形の判定は `git commit` の引数だけに限定する (長い `--no-verify` は上で全 git 禁止)。
const nMatch = cmd.match(gitSubRe('commit'));
if (nMatch) {
  const nArgs = unquote(nMatch[1]).trim().split(/\s+/).filter(Boolean);
  if (nArgs.some((a) => /^-[a-zA-Z]*n[a-zA-Z]*$/.test(a))) {
    deny('`-n` は `git commit` の `--no-verify` 短縮形なので禁止です（hook バイパス防止 / CLAUDE.md）。dry-run が目的なら `--dry-run` と明示してください。');
  }
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
}

process.exit(0);
