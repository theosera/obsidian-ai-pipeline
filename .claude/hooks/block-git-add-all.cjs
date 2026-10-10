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
  const roots = new Set([projectDir, baseDir.replace(/\/+$/, ''), guard.resolveDir(baseDir, g.cdirs).replace(/\/+$/, '')]);
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
  if (blanket) {
    deny('`git add -A` / `git add .` / `--all`（`.` `..` `*` `:/` `:(top)` `$PWD` / リポジトリ root の絶対パス含む）は禁止です。CLAUDE.md の規約に従い、ファイルを個別に列挙して add してください（untracked secret の巻き込み防止）。');
  }
}

process.exit(0);
