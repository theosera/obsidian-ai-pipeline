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
      permissionDecisionReason: '[判断不能] git ガードの共通の部品 (lib/git-guard-common.cjs) を読み込めませんでした (fail-closed)。git ガードを通せないため実行をブロックします。',
    },
  }));
  process.exit(0);
}
const { deny } = guard;

const { cmd, baseDir } = guard.readInput('git ガード');
if (!cmd) process.exit(0);

// --no-verify はどの git サブコマンドでも禁止（commit / push の hook バイパス防止）。
if (/(^|\s)--no-verify(\s|=|$)/.test(cmd)) {
  deny('入力に `--no-verify` の文字列候補があります。実際の option か DATA かをこの旧判定で確定できないため停止します。hook を無効にせず、対応済みの入力を確認してください。');
}

const insp = guard.inspect(cmd);
if (insp.problems.length) deny(guard.problemMessage(insp.problems, 'git ガード'));

/** Match no-verify and its guarded long-option prefixes, while leaving no-verbose intact. */
function isNoVerifyOption(text) {
  const option = text.split('=')[0];
  return option.length >= '--no-ver'.length && '--no-verify'.startsWith(option);
}

/**
 * Find no-verify options in non-commit calls without confusing known push/merge/config values with flags.
 * Required option values stay values even when quoted text begins with --no-veri; -- ends options.
 * Other subcommands retain conservative checking where no option-value grammar is available.
 */
function hasNoVerifyOption(g) {
  const longValues = g.sub === 'push' ? ['repo', 'receive-pack', 'exec', 'recurse-submodules', 'push-option']
    : g.sub === 'merge' ? ['message', 'file', 'strategy', 'strategy-option', 'cleanup', 'into-name']
      : g.sub === 'config' ? ['default'] : [];
  const shortValues = g.sub === 'push' ? 'o' : g.sub === 'merge' ? 'mFsX' : '';
  for (let k = 0; k < g.args.length; k++) {
    const text = g.args[k].text;
    if (text === '--') break;
    if (isNoVerifyOption(text)) return true;
    if (text.startsWith('--')) {
      const eq = text.indexOf('=');
      const name = text.slice(2, eq < 0 ? undefined : eq);
      const matches = longValues.filter((option) => option.startsWith(name));
      if (eq < 0 && (longValues.includes(name) || matches.length === 1)) k++;
      continue;
    }
    if (text.startsWith('-')) {
      for (let p = 1; p < text.length; p++) {
        // merge -S consumes an optional attached key, so later letters are not short flags.
        if (g.sub === 'merge' && text[p] === 'S') break;
        if (shortValues.includes(text[p])) {
          if (p === text.length - 1) k++;
          break;
        }
      }
    }
  }
  return false;
}

// shell の引用・escape を戻した語でも見る（--no-'verify' なども同じ option）。
// 読取 subcommand の検索文字列等は hook 回避 option ではない。既存の raw 判定は上に残す。
for (const g of insp.gits) {
  const noVerify = g.sub === 'commit' ? guard.parseCommitArgs(g.args).noVerify :
    !guard.READ_ONLY_SUBS.has(g.sub) && hasNoVerifyOption(g);
  if (noVerify) {
    deny('解析した `--no-verify` option は禁止です（hook バイパス防止 / CLAUDE.md）。フックを通して実行してください。', 'FORBIDDEN');
  }
}

// `-n` が `--no-verify` の短縮形になるのは **`git commit` だけ**。
// `git push -n` は `--dry-run`、`git merge -n` は diffstat 抑制で、どちらも hook を
// バイパスしない (git の help で確認)。`grep -n` / `tail -n` / `git add -n` も同様に無関係。
// ⇒ 短縮形の判定は `git commit` の引数だけに限定する (長い `--no-verify` は上で全 git 禁止)。
for (const g of insp.gits) {
  if (g.sub !== 'commit') continue;
  if (g.args.some((w) => /^-[a-zA-Z]*n[a-zA-Z]*$/.test(w.text))) {
    deny('commit の語に `-n` の候補がありますが、option と消費値の境界をこの判定で確定できないため停止します。dry-run は対応済みの `--dry-run` を確認してください。');
  }
}

// `core.hooksPath` の差し替えは committed hook を丸ごと無効化する（= --no-verify の一般化）。
// 読取 (`git config --get core.hooksPath`) は許可し、代入形だけを禁止する。
if (/core\.hooksPath\s*=/i.test(cmd) || /git\s+config\b[^;&|]*\bcore\.hooksPath\s+[^\s;&|<>]/i.test(cmd)) {
  deny('入力の文字列が `core.hooksPath` の変更候補に一致しました。実際の変更か DATA かをこの旧判定で確定できないため停止します。hook の変更は個別操作の了承と別に owner へ確認してください。');
}

/** Read reconstructed config operands while preserving getters and consumed option values. */
function changesHooksPath(g) {
  if (g.configs.concat(g.configEnvs).some((value) => value.split('=')[0].toLowerCase() === 'core.hookspath')) return 'FORBIDDEN';
  if (g.sub !== 'config' || g.terminal) return null;
  const valueOptions = ['file', 'blob', 'type', 'default', 'value', 'url', 'comment'];
  const readOptions = ['get', 'get-all', 'get-regexp', 'get-urlmatch', 'get-color', 'get-colorbool', 'list'];
  const writeOptions = ['add', 'replace-all', 'unset', 'unset-all', 'rename-section', 'remove-section', 'edit'];
  const actions = new Set(['get', 'list', 'set', 'unset', 'rename-section', 'remove-section', 'edit']);
  const operands = [];
  let action = null;
  let read = false;
  let afterDD = false;
  for (let k = 0; k < g.args.length; k++) {
    const word = g.args[k];
    const t = word.text;
    if (!afterDD && t === '--') { afterDD = true; continue; }
    if (!afterDD && (t === '--help' || t === '-h')) return null;
    if (!afterDD && t.startsWith('--')) {
      const eq = t.indexOf('=');
      const name = t.slice(2, eq < 0 ? undefined : eq);
      const known = valueOptions.concat(readOptions, writeOptions);
      const matches = known.includes(name) ? [name] : known.filter((option) => option.startsWith(name));
      if (matches.length === 1) {
        if (valueOptions.includes(matches[0])) { if (eq < 0) k++; }
        else { action = matches[0]; read = readOptions.includes(action); }
      }
      continue;
    }
    if (!afterDD && t.startsWith('-')) {
      if (t === '-l') { action = 'list'; read = true; }
      else if (t === '-e') action = 'edit';
      else if (/^-[z]*[fbt]$/.test(t)) k++;
      continue;
    }
    if (!afterDD && !action && actions.has(t)) { action = t; read = t === 'get' || t === 'list'; continue; }
    operands.push(word);
    afterDD = true; // A value such as "--get" after the key remains data.
  }
  if (read) return null;
  if (action === 'edit') return 'UNKNOWN'; // An editor can change the hook path without inspectable operands.
  if (action === 'rename-section' || action === 'remove-section') {
    return operands.some((word) => word.dynamic || /^core$/i.test(word.text)) ? 'UNKNOWN' : null;
  }
  const key = operands[0];
  const writes = operands.length > 1 || ['set', 'add', 'replace-all', 'unset', 'unset-all'].includes(action);
  if (!writes || !key || (!key.dynamic && !/^core\.hookspath$/i.test(key.text))) return null;
  return key.dynamic || g.incomplete || g.args.some((word) => word.dynamic && word.dynamicMaySplit !== false)
    ? 'UNKNOWN' : 'FORBIDDEN';
}
for (const g of insp.gits) {
  const category = changesHooksPath(g);
  if (category) deny(category === 'FORBIDDEN'
    ? '解析した git config が禁止された `core.hooksPath` の変更・削除を指定しています。対応済みの getter を使ってください。'
    : 'git config が hook の設定を変えるか、編集内容や引数から確定できません。対象・操作・不明な条件を owner へ確認してください。', category);
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
    const parsed = guard.parseAddArgs(g.args);
    const confirmed = !parsed.terminal && !parsed.unsafePathspec && (parsed.actualBlanket ||
      parsed.pathspecs.some((word) => ['.', './', '..', '../'].includes(word.literalPath) ||
        roots.has(path.resolve(inspectCwd, word.literalPath))));
    deny(confirmed
      ? '解析した git add / stage が禁止された一括追加を指定しています。確認済みの個別ファイルを列挙してください。'
      : '一括追加の候補がありますが、実際の option / pathspec と消費値の境界や対象を確定できません。確認済みの個別ファイルを指定し、無理なら owner へ確認してください。',
    confirmed ? 'FORBIDDEN' : 'UNKNOWN');
  }
}

// v3.5.3: main（ae10261）の停止条件を文字列全体へもう一度当てる（和をとる）。
// 条件と順序を保ち、raw-only の候補は UNKNOWN の理由で記録する。
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
    deny('旧文字列判定に commit の `-n` 候補があります。実際の option か DATA かを確定できないため停止します。dry-run は対応済みの `--dry-run` を確認してください。');
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
    deny('旧文字列判定に一括追加の候補があります。実際の add 対象か DATA かを確定できないため停止します。確認済みの個別ファイルを列挙し、無理なら owner へ確認してください。');
  }
}
}

process.exit(0);
