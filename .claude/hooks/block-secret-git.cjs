#!/usr/bin/env node
'use strict';
/**
 * PreToolUse(Bash) ガード ①: secret-looking file の `git add` / `git commit` をブロックする。
 *
 * `.claude/settings.json` の deny は **読取**経路 (Read / cat / grep …) しか塞がない。
 * 本フックはその穴を埋めて **add / commit（=履歴への書込）**経路を塞ぐ。CLAUDE.md の
 * 「絶対に commit しないファイル」を tool-permission 層で機械的に強制する。
 *
 * 入力: stdin に PreToolUse の JSON ({ tool_input: { command }, cwd })。
 * 出力: ブロック時は hookSpecificOutput.permissionDecision="deny" を返す。許可時は無出力。
 * 副作用: `git commit` のときだけ `git diff --cached --name-only -z` と `git ls-files` を、
 * builtin でない subcommand のときだけ `git config --get alias.<name>` を読む（読取のみ）。
 * コマンドの読み取り（シェルの語・git の global option と subcommand）は
 * lib/git-guard-common.cjs にあり、git ガード 3 本で共有する。
 */
const { execFileSync } = require('node:child_process');

let guard;
try {
  guard = require('./lib/git-guard-common.cjs');
} catch {
  process.stdout.write(JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: '[判断不能] git ガードの共通の部品 (lib/git-guard-common.cjs) を読み込めませんでした (fail-closed)。secret ガードを通せないため実行をブロックします。',
    },
  }));
  process.exit(0);
}
const { deny } = guard;

// staging と egress が同じ secret 一覧・.env.example 例外を使う。
const isSecret = guard.isSecretPath;

const { cmd, baseDir } = guard.readInput('secret ガード');
if (!cmd) process.exit(0);

const insp = guard.inspect(cmd);
if (insp.problems.length) deny(guard.problemMessage(insp.problems, 'secret ガード'));
const gits = insp.gits;
for (const g of gits) {
  const decision = guard.gitObjectInputDecision(g);
  if (decision) deny(decision.reason, decision.category);
}

/**
 * config / branch / remote の、引数で決まる読取 action を判定する。
 * 知っている読取 action / option の組合せだけ通し、書込 option や option にも
 * 展開されうる動的な語が交じる場合は書込側に残す（commit 前の状態を保証するため）。
 * @param {object} g inspect が返す git の呼び出し。
 * @returns {boolean} index・ref・作業木・設定を書き換えないと判断できるか。
 */
function readOnlyMode(g) {
  // unquoted expansion や "$@" は追加の action / option を作れる。古い metadata も安全と決めつけない。
  if (g.incomplete || g.args.some((w) => w.dynamic && w.dynamicMaySplit !== false)) return false;
  let args = g.args;
  let reader = false;
  const values = new Set();
  let flags;
  if (g.sub === 'config') {
    flags = new Set([
      '--get', '--get-all', '--get-regexp', '--get-urlmatch', '--list', '-l',
      '--get-color', '--get-colorbool', '--global', '--system', '--local', '--worktree',
      '--includes', '--no-includes', '--show-origin', '--show-scope', '--name-only',
      '--null', '-z', '--bool', '--int', '--bool-or-int', '--bool-or-str', '--path',
      '--expiry-date', '--no-type', '--fixed-value', '--all', '--regexp',
    ]);
    for (const v of ['--file', '-f', '--blob', '-b', '--type', '-t', '--default', '--value']) values.add(v);
  } else if (g.sub === 'branch') {
    flags = new Set([
      '--list', '-l', '--show-current', '--all', '-a', '--remotes', '-r',
      '--verbose', '-v', '-vv', '--quiet', '-q', '--no-color', '--column', '--no-column',
      '--color', '--abbrev', '--no-abbrev', '--ignore-case', '-i', '--omit-empty',
    ]);
    for (const v of ['--format', '--sort', '--contains', '--no-contains', '--merged', '--no-merged', '--points-at']) values.add(v);
  } else if (g.sub === 'remote') {
    // remote の action は option でなく最初の位置引数。get-url と show は設定を変えない。
    const rest = args.slice();
    while (rest.length && ['-v', '--verbose'].includes(rest[0].text) && !rest[0].dynamic) rest.shift();
    if (!rest.length) return true;
    if (rest[0].dynamic || !['get-url', 'show'].includes(rest[0].text)) return false;
    const action = rest.shift().text;
    args = rest;
    flags = new Set(action === 'get-url' ? ['--push', '--all'] : ['-n']);
    reader = true;
  } else return false;

  let positional = 0;
  let endOptions = false;
  for (let k = 0; k < args.length; k++) {
    const w = args[k];
    const t = w.text;
    if (endOptions) { positional++; continue; }
    if (w.dynamic) return false;
    if (t === '--') { endOptions = true; continue; }
    if (!t.startsWith('-')) {
      if (g.sub === 'config' && !reader && positional === 0 && ['get', 'list'].includes(t)) reader = true;
      else positional++;
      continue;
    }
    const eq = t.indexOf('=');
    const option = eq < 0 ? t : t.slice(0, eq);
    if (values.has(option)) {
      if (eq < 0) {
        const optional = g.sub === 'branch' && ['--contains', '--no-contains', '--merged', '--no-merged'].includes(option);
        const value = args[k + 1];
        // branch の filter は値なしなら HEAD。次の action option を値として飛ばさない。
        if (!optional || (value && !value.text.startsWith('-'))) {
          if (!value || (optional && value.dynamic) || (g.sub === 'branch' && value.text.startsWith('-'))) return false;
          k++;
        }
      }
      if (g.sub === 'branch' && ['--contains', '--no-contains', '--merged', '--no-merged', '--points-at'].includes(option)) reader = true;
      continue;
    }
    if (g.sub === 'branch' && eq >= 0 && ['--abbrev', '--color', '--column'].includes(option)) continue;
    if (!flags.has(t)) return false;
    if (g.sub === 'config' && /^(?:--get(?:-all|-regexp|-urlmatch|-color|-colorbool)?|--list|-l)$/.test(t)) reader = true;
    if (g.sub === 'branch' && ['--list', '-l', '--show-current'].includes(t)) reader = true;
  }
  // branch の引数なし / 表示 option だけの形は一覧。裸の名前は branch 作成。
  return reader || (g.sub === 'branch' && positional === 0);
}
// 読むだけでない git（index・ref・作業木・設定を書きうるもの）。
/** Return whether this invocation may change state used by the pre-commit inspection. */
const writesRepo = (g) => g.sub && !g.terminal && !guard.READ_ONLY_SUBS.has(g.sub) && !readOnlyMode(g);

const READ_ONLY_COMMANDS = new Set([
  ':', 'true', 'false', 'test', '[', 'echo', 'printf', 'pwd', 'cat', 'head', 'tail', 'wc', 'ls',
  'cd', 'pushd', 'popd', 'export', 'declare', 'typeset', 'local', 'readonly', 'unset',
]);
const READ_ONLY_PROGRAMS = new Set(['true', 'false', 'test', '[', 'echo', 'printf', 'pwd', 'cat', 'head', 'tail', 'wc', 'ls']);
const STATE_BUILTINS = new Set(['export', 'declare', 'typeset', 'local', 'readonly', 'unset']);
/**
 * Recognize simple commands whose effects before commit cannot replace the inspected index.
 * Directory/environment builtins rely on the parser's per-invocation target checks. Launchers,
 * unknown executables, output redirections, and printf's variable-assignment forms stay blocked.
 */
function readOnlyInvocation(invocation) {
  if (invocation.pathChangedBefore) return false;
  const wrappers = invocation.wrapperNames;
  if (!Array.isArray(wrappers) || wrappers.some((name) => !['command', 'builtin', 'env'].includes(name))) return false;
  if (invocation.dynamicName) return false;
  if (!invocation.name) return true; // assignment-only; redirections are checked separately
  if (invocation.nonExec && invocation.name === 'command') return true; // command -v / -V
  const executable = invocation.nameWord && invocation.nameWord.text;
  if (invocation.name === 'git') return true; // Git's writes and executable identity are checked separately.
  if (!executable) return false;
  if (executable.includes('/')) {
    if (!['/bin/', '/usr/bin/'].some((prefix) => executable === prefix + invocation.name) || !READ_ONLY_PROGRAMS.has(invocation.name)) return false;
  } else if (!READ_ONLY_COMMANDS.has(executable)) return false;
  const args = invocation.args;
  if (STATE_BUILTINS.has(invocation.name) && args.some((w) => w.dynamic &&
      (w.dynamicMaySplit !== false || !/^[A-Za-z_][A-Za-z0-9_]*=/.test(w.text)))) return false;
  if (invocation.name === 'printf') {
    const first = args[0];
    if (first && (first.dynamic || /^-v/.test(first.text))) return false;
    const format = first && first.text === '--' ? args[1] : first;
    if (format && (format.dynamic || /%[-+# 0]*(?:\*|\d+)?(?:\.(?:\*|\d+))?n/.test(format.text))) return false;
  }
  return true;
}

/** Shell file-opening output and read/write redirections can replace the inspected index. */
function writesViaRedirection(redirection) {
  if (!redirection.op.includes('>') || redirection.op === '<<<') return false;
  const word = redirection.word;
  const literal = word && word.dynamic === false && word.dynamicMaySplit === false &&
    !word.ansiCUnknown && !word.braceExpanded && !word.globExpanded && !word.tildeExpanded;
  if (!literal) return true;
  // `>&1` duplicates an FD, while `>1` opens an ordinary file named 1.
  if (redirection.op === '>&' && /^(?:\d+|-)$/.test(word.text)) return false;
  // Only the exact device path is supported; no expansion or path normalization proves it.
  if (word.text === '/dev/null' && ['>', '>>', '>|', '&>', '&>>', '>&'].includes(redirection.op)) return false;
  return true;
}

// builtin でない subcommand が alias なら拒む（alias の中身は検査できない）。
for (const g of gits) {
  const p = guard.aliasProblem(g, baseDir);
  if (p) deny(`${p}。alias を使わず、git の subcommand をそのまま書いてください (fail-closed)。`);
}

// commit や ref を index を通さずに作る plumbing は、エージェントの経路では使わない。
for (const g of gits) {
  // fast-import の単独 help は stdin を import せずに終了する。値・stream 内の文字は見ない。
  const importHelp = g.sub === 'fast-import' && g.args.length === 1 && !g.args[0].dynamic &&
    ['-h', '--help'].includes(g.args[0].text);
  if (importHelp) g.terminal = true;
  if (g.sub === 'commit-tree' || g.sub === 'mktree' || g.sub === 'update-ref' ||
      (g.sub === 'fast-import' && !importHelp)) {
    deny(
      `\`git ${g.sub}\` はブロックしました。staged 検査を通らずに commit や ref を作れるためです。\n` +
      'commit は `git add <files>` → `git commit` で作ってください（plumbing が要る作業は人が実行します）。',
    );
  }
}

// 対象のリポ・index・設定を変える変数だけを、その変数が作用する git に対して拒む。
// GIT_EDITOR / GIT_AUTHOR_DATE などでは staged 検査の対象は変わらない。
// helper を選ぶ変数は、commit 前にその helper を呼べる読取コマンドも後段で調べる。
/** Return whether a Git environment variable redirects inspection state or changes pathspec matching. */
const changesGitTarget = (n) => /^(?:GIT_(?:DIR|WORK_TREE|COMMON_DIR|INDEX_FILE|OBJECT_DIRECTORY|ALTERNATE_OBJECT_DIRECTORIES|NAMESPACE|CEILING_DIRECTORIES|DISCOVERY_ACROSS_FILESYSTEM|EXEC_PATH|(?:LITERAL|GLOB|NOGLOB|ICASE)_PATHSPECS)|GIT_CONFIG(?:_.*)?)$/.test(n);
const envWriter = gits.find((g) => writesRepo(g) && g.gitEnvNames.some(changesGitTarget));
if (envWriter) {
  deny(
    `環境変数 ${envWriter.gitEnvNames.find(changesGitTarget)} を、読むだけでない git に設定しています。\n` +
    'secret ガードが検査する対象のリポや index を決めきれないためブロックしました (fail-closed)。環境変数を付けずに実行してください。',
  );
}

/** Detect whether an external-diff command may execute, honoring explicit disable flags. */
function externalDiffCanRun(g) {
  if (!['diff', 'diff-index', 'diff-files', 'diff-tree', 'log', 'show', 'whatchanged', 'rev-list'].includes(g.sub)) return false;
  let enabled = g.sub === 'diff';
  let unknown = false;
  // Required diff values may themselves look like flags. Optional values are attached only.
  const diffValues = [
    '--stat-width', '--stat-name-width', '--stat-graph-width', '--stat-count', '--ws-error-highlight',
    '--src-prefix', '--dst-prefix', '--line-prefix', '--inter-hunk-context', '--output-indicator-new',
    '--output-indicator-old', '--output-indicator-context', '--ignore-matching-lines', '--diff-algorithm',
    '--anchored', '--word-diff-regex', '--color-moved-ws', '--rotate-to', '--skip-to', '--find-object',
    '--diff-filter', '--max-depth', '--output',
  ];
  const optionalDiffValues = [
    '--unified', '--dirstat', '--dirstat-by-file', '--stat', '--abbrev', '--color', '--break-rewrites',
    '--find-renames', '--find-copies', '--word-diff', '--color-words', '--color-moved', '--relative',
    '--ignore-submodules', '--submodule',
  ];
  const revisionValues = new Set([
    '--grep', '--grep-reflog', '--author', '--committer', '--encoding', '--date', '--max-count', '--skip',
    '--max-age', '--min-age', '--since', '--since-as-filter', '--after', '--before', '--until', '--default',
  ]);
  const revision = ['log', 'show', 'whatchanged', 'rev-list'].includes(g.sub);
  for (let k = 0; k < g.args.length; k++) {
    const word = g.args[k];
    const text = word.text;
    if (text === '--') break;
    const eq = text.indexOf('=');
    const option = eq < 0 ? text : text.slice(0, eq);
    const diffMatches = option.startsWith('--') ? [...diffValues, ...optionalDiffValues].filter((name) => name.startsWith(option)) : [];
    const requiredLong = diffValues.includes(option) || (diffMatches.length === 1 && diffValues.includes(diffMatches[0])) ||
      (revision && revisionValues.has(option));
    // Short diff bundles stop at their first value; B/M/C/U/X take only an attached optional value.
    let requiredShort = false;
    let attachedShortValue = false;
    if (/^-[^-]/.test(text)) {
      for (let j = 1; j < text.length; j++) {
        if ('GSIOl'.includes(text[j]) || (revision && 'nL'.includes(text[j]))) {
          requiredShort = j === text.length - 1;
          attachedShortValue = !requiredShort;
          break;
        }
        if ('BMCUX'.includes(text[j])) { attachedShortValue = j < text.length - 1; break; }
      }
    }
    if ((requiredLong && eq < 0) || requiredShort) {
      const value = g.args[++k];
      if (!value || (value.dynamic && value.dynamicMaySplit !== false) || (word.dynamic && word.dynamicMaySplit !== false)) unknown = true;
      continue;
    }
    // An attached scalar value cannot introduce another argument, including format/pattern text.
    if (word.dynamic) {
      if (word.dynamicMaySplit !== false || (!attachedShortValue &&
          (eq < 0 || !(requiredLong || optionalDiffValues.includes(option) ||
          (revision && ['--format', '--pretty'].includes(option)))))) unknown = true;
      continue;
    }
    if (option.startsWith('--ext') && '--ext-diff'.startsWith(option)) enabled = true;
    if (option.startsWith('--no-ext') && '--no-ext-diff'.startsWith(option)) enabled = false;
  }
  return unknown || enabled;
}

/** Determine pager use from the invocation's global flags and known paginated commands. */
function pagerCanRun(g, invocation) {
  let enabled = ['diff', 'log', 'show', 'blame', 'shortlog', 'grep', 'whatchanged', 'reflog'].includes(g.sub);
  if (g.sub === 'branch' && readOnlyMode(g) && !g.args.some((w) => w.text === '--show-current')) enabled = true;
  const globals = invocation.args.slice(0, invocation.args.length - g.args.length - 1);
  const values = new Set(['-C', '-c', '--git-dir', '--work-tree', '--namespace', '--config-env', '--attr-source']);
  for (let k = 0; k < globals.length; k++) {
    const word = globals[k];
    if (values.has(word.text)) { k++; continue; }
    if (word.text === '-p' || word.text === '--paginate') enabled = true;
    if (word.text === '-P' || word.text === '--no-pager') enabled = false;
  }
  return enabled;
}

/** Identify unsupported configuration effects separately from selected helper environment variables. */
function helperVariable(g, invocation) {
  const config = guard.preCommitConfigKey(g);
  if (config) return { kind: 'config', name: config };
  if (g.terminal) return null;
  if (g.gitEnvNames.includes('GIT_EXTERNAL_DIFF') && externalDiffCanRun(g)) return { kind: 'env', name: 'GIT_EXTERNAL_DIFF' };
  if (g.gitEnvNames.includes('GIT_PAGER') && pagerCanRun(g, invocation)) return { kind: 'env', name: 'GIT_PAGER' };
  return null;
}

// ① `git add <paths>` / `git stage <paths>` — 明示パス引数を検査（同じコマンドの add はすべて）。
const addGits = gits.filter((g) => g.sub === 'add' || g.sub === 'stage');
for (const g of addGits) {
  const add = guard.parseAddArgs(g.args);
  if (add.terminal) { g.terminal = true; continue; }
  if (add.unsafePathspec) {
    deny(
      `git add / stage の pathspec を実行前に検査できません（${add.reason}）(fail-closed)。\n` +
      '変数・glob・pathspec magic・ファイル入力を使わず、追加するファイルを literal なパスで列挙してください。',
    );
  }
  if (!Array.isArray(add.pathspecs) || add.pathspecs.some((word) => typeof word.literalPath !== 'string')) {
    deny('git add / stage の literal pathspec を共通 parser から取得できないためブロックしました (fail-closed)。');
  }
  // Git が解く backslash escape の後の literal を見る。option の消費値は pathspec ではない。
  const bad = add.pathspecs.map((word) => word.literalPath).filter(isSecret);
  if (bad.length) {
    deny(
      `secret-looking file を git add しようとしています: ${bad.join(', ')}\n` +
      'CLAUDE.md が追加を禁止するファイル名に当たります。対象を外して、確認済みの個別ファイルを指定してください。',
      'FORBIDDEN',
    );
  }
}

// ② `git commit` — 現在 staged のファイルを検査（add 経由でなくても漏れを止める）。
//    ただし PreToolUse は**コマンド実行前**に走るため `git diff --cached` は「実行前の
//    index」しか見えない。そのため commit と同じコマンドでは、読むだけの git 以外を
//    走らせない・commit のときに stage する形（`-a` / `-p` / pathspec）を先に見る、とし、
//    staged 検査は backstop に残す。
const commits = gits.filter((g) => g.sub === 'commit' && !g.terminal);
if (commits.length) {
  if (commits.length > 1) {
    deny(
      '同一コマンド内で複数の `git commit` を実行する形はブロックしました。\n' +
      'PreToolUse フックは最初の commit より前の index しか検査できないため、commit は別々のコマンドとして実行してください。',
    );
  }
  const commit = commits[0];
  if (commit.pipelineParticipant !== false) {
    deny('commit をパイプラインに含める形は、ほかの処理が同時に index を書き換えうるためブロックしました (fail-closed)。commit はパイプラインから分けて実行してください。');
  }
  if (commit.unsafeGroupSetup !== false) {
    deny('commit を囲む command group のリダイレクトや置換が、検査後に index を書き換えうるためブロックしました (fail-closed)。リダイレクトと commit は別々のコマンドとして実行してください。');
  }
  if (insp.async) {
    deny('background 実行と commit を同じコマンドに含める形は、index を commit 前に書き換える可能性があるためブロックしました (fail-closed)。別々のコマンドとして実行してください。');
  }
  if (!Array.isArray(insp.invocations) || !Number.isInteger(commit.invocationOrder)) {
    deny('commit より前のコマンドの実行順を検査できないためブロックしました (fail-closed)。');
  }
  const beforeCommit = insp.invocations.filter((invocation) => invocation.order <= commit.invocationOrder);
  for (const g of gits.filter((git) => git.invocationOrder <= commit.invocationOrder)) {
    const invocation = insp.invocations.find((entry) => entry.order === g.invocationOrder);
    const variable = invocation && helperVariable(g, invocation);
    if (variable) {
      const selected = variable.kind === 'config' ? `設定 key ${variable.name}` : `環境変数 ${variable.name}`;
      deny(
        `commit 前の git に ${selected} を指定しています。外部 source や設定の効果を確認できず、検査後の index が維持されるか判断できないため停止しました (fail-closed)。\n` +
        '同じ目的・対象・条件を保てる場合だけ、設定を使う読取を commit と分け、後の commit で再検査してください。それ以外は owner に対象・操作・cwd・env/config/source と不明点を確認してください。個別操作の承認は hook 無効化の承認ではありません。',
      );
    }
    const grep = guard.grepPagerEffect(g);
    if (grep.opensFiles || grep.unknown) {
      deny(
        (grep.unknown
          ? 'commit 前の git grep の argv から、file-opening pager の選択・実行条件を確かめられません。検査後の index が維持されるか判断できないため停止しました。'
          : 'commit 前の git grep が matching file を開く外部 pager の副作用を検査できません。検査後の index が維持されるか判断できないため停止しました。') +
        '\n検索結果を読む同じ目的を保てる場合だけ、pager を開かない対応形に直してください。それ以外は対象・操作・cwd・env/config/source と不明点を owner に確認してください。個別操作の承認は hook 無効化の許可ではありません。',
        'UNKNOWN',
      );
    }
  }
  const redirect = beforeCommit.find((invocation) => invocation.redirs.some(writesViaRedirection));
  if (redirect) {
    deny('commit の実行前に出力リダイレクトがあります。検査後に index などを書き換えうるためブロックしました。リダイレクトと commit は別々のコマンドとして実行してください。');
  }
  const effect = beforeCommit.find((invocation) => !readOnlyInvocation(invocation));
  if (effect) {
    deny(
      `commit より前のコマンド（${effect.name || '動的なコマンド'}）の副作用を検査できないためブロックしました (fail-closed)。\n` +
      'PreToolUse フックが読んだ index を、そのコマンドが commit 前に書き換えうるためです。別々のコマンドとして実行してください。',
    );
  }
  const others = gits.filter((g) => g !== commits[0]);
  if (others.some((g) => ['add', 'stage', 'rm', 'mv'].includes(g.sub))) {
    deny(
      '同一コマンド内で staging (`git add` 等) と `git commit` を連結しています。\n' +
      'PreToolUse フックは**実行前**の index しか読めず staged secret 検査がすり抜けるためブロックしました。' +
      '`git add <files>` と `git commit …` を別々のコマンドとして実行してください（CLAUDE.md ハードルール）。',
    );
  }
  const writer = others.find(writesRepo);
  if (writer) {
    deny(
      `同一コマンド内で \`git commit\` と \`git ${writer.sub}\` を連結しています。\n` +
      'PreToolUse フックは**実行前**の index しか読めないため、commit と同じコマンドでは読むだけの git ' +
      '(status / log / diff / show など) 以外をブロックします。別々のコマンドとして実行してください。',
    );
  }
  // 検査対象は **そのコマンドが commit するリポ**。場所を変えるコマンドの後ではそれを決めきれない。
  if (commits.some((g) => g.cdLikeBefore)) {
    deny(
      '`cd` / `pushd` などで場所を変えてから `git commit` する形は、staged 検査の対象リポを決めきれないため\n' +
      'ブロックしました (fail-closed)。`git -C <dir> commit …` の形で対象リポを明示してください。',
    );
  }
}

for (const g of commits) {
  if (g.incomplete) {
    deny('`xargs` / `find -exec` から `git commit` を走らせる形は、引数を検査できないためブロックしました (fail-closed)。');
  }
  const ca = guard.parseCommitArgs(g.args);
  if (ca.all) {
    deny(
      '`git commit -a` / `-am` / `--all` はブロックしました。追跡済みファイルを commit 時に stage するため、\n' +
      '実行前の staged 検査をすり抜けます。`git add <files>` で明示的に stage してから commit してください。',
    );
  }
  if (ca.patch) {
    deny(
      '`git commit -p` / `--patch` / `--interactive` はブロックしました。commit 時に stage するため、\n' +
      '実行前の staged 検査をすり抜けます。`git add <files>` で明示的に stage してから commit してください。',
    );
  }
  if (ca.unknown.length) {
    deny(`\`git commit\` の知らない option（${ca.unknown[0]}）は、commit 時に stage するかを決められないためブロックしました (fail-closed)。`);
  }
  if (ca.dynamic) {
    deny(
      '`git commit` の引数が変数や置換で作られていて、option か pathspec かを決められないためブロックしました (fail-closed)。\n' +
      '`-m` / `-F` などの値は変数でもかまいません。option と pathspec はそのまま書いてください。',
    );
  }
  if (ca.fromFile) {
    deny('`git commit --pathspec-from-file` は pathspec が stdin / ファイル側にあり、secret ガードから検査できないためブロックしました (fail-closed)。');
  }
  if (g.gitDir || g.workTree) {
    deny(
      '`git --git-dir=… / --work-tree=… commit` は staged 検査の対象リポを一意に決められないため\n' +
      'ブロックしました (fail-closed)。対象リポの中で直接 commit してください。',
    );
  }
  // 検査対象は **そのコマンドが commit するリポ**（入力の cwd と `-C` の並びから決める）。
  const inspectCwd = guard.resolveDir(baseDir, g.cdirs);
  let staged = '';
  try {
    staged = execFileSync('git', ['diff', '--cached', '--name-only', '-z'], {
      cwd: inspectCwd,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    });
  } catch {
    // 検査できないときは通さない（存在しない `-C` 先などで検査を無効化させない）。
    deny(
      `staged ファイルの検査に失敗しました (対象: ${inspectCwd})。\n` +
      '検査できない状態で commit を通すと staged secret を見逃すためブロックしました (fail-closed)。',
    );
  }
  const bad = staged.split('\0').filter(isSecret);
  if (bad.length) {
    deny(
      `staged に secret-looking file が含まれています: ${bad.join(', ')}\n` +
      'CLAUDE.md が commit を禁止するファイル名に当たります。`git restore --staged <file>` で外してから commit してください。',
      'FORBIDDEN',
    );
  }
  // pathspec を付けた commit（`-o` / `-i` / 素の pathspec）は、作業木の中身をその場で commit する。
  // pathspec が当たる追跡済みのファイルを検査する。
  if (ca.pathspecs.length) {
    const badSpec = ca.pathspecs.filter(isSecret);
    if (badSpec.length) {
      deny(`commit の pathspec が禁止されたファイル名に当たります: ${badSpec.join(', ')}（CLAUDE.md ハードルール）。`, 'FORBIDDEN');
    }
    const magic = ca.pathspecs.find((p) => p.startsWith(':') || /[*?[]/.test(p));
    if (magic) {
      deny(`pathspec の magic / glob（${magic}）は、commit されるファイルを検査できないためブロックしました (fail-closed)。ファイルを列挙してください。`);
    }
    let listed = '';
    try {
      listed = execFileSync('git', ['ls-files', '-z', '--', ...ca.pathspecs], {
        cwd: inspectCwd,
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
      });
    } catch {
      deny(`pathspec が当たるファイルの検査に失敗しました (対象: ${inspectCwd})。検査できないためブロックしました (fail-closed)。`);
    }
    const badListed = listed.split('\0').filter(isSecret);
    if (badListed.length) {
      deny(`pathspec の照合結果が commit 禁止のファイル名に当たります: ${badListed.join(', ')}（CLAUDE.md ハードルール）。`, 'FORBIDDEN');
    }
  }
}

// v3.5.3 の raw-text backstop を継続し、旧 main 由来の option / path 判定も当てる。
// staged 照合は NUL 区切りへ変更し、実行しない commit の help を除いた。
// 実行する commit を parser が読めた場合は、その呼び出しの cwd で staged を照合する。
// main の「git の文字が無ければ exit」はブロックの条件にした。ファイル名 inventory は共通 isSecretPath を使う。
const RECHECK_AS_MAIN = true;
if (RECHECK_AS_MAIN && /\bgit\b/.test(cmd)) {
const path = require('node:path');

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
      '旧判定の文字列候補が禁止ファイル名に一致しました。実際の add 対象か DATA かを確定できないため停止します。',
    );
  }
}

// ② `git commit` — 現在 staged のファイルを検査（add 経由でなくても漏れを止める）。
//    ただし PreToolUse は**コマンド実行前**に走るため `git diff --cached` は「実行前の
//    index」しか見えない。同一コマンドで stage してから commit する形と `git commit -a`
//    はこの検査をすり抜けるので、形そのものを先に拒否し、staged 検査は backstop に残す。
const commitMatch = cmd.match(gitSubRe('commit'));
// 実際の commit がすべて help なら index を読まない。コメント等だけの旧判定は保つ。
if (commitMatch && (!gits.some((g) => g.sub === 'commit') || commits.length)) {
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
  const legacyBaseDir = process.env.CLAUDE_PROJECT_DIR || process.cwd();
  // 最初の raw match が help でも、実行する commit の対象は上で読んだ呼び出しから取る。
  const inspectCwd = commits.length ? guard.resolveDir(baseDir, commits[0].cdirs)
    : cDir ? path.resolve(legacyBaseDir, stripToken(cDir)) : legacyBaseDir;
  let staged = '';
  try {
    staged = execFileSync('git', ['diff', '--cached', '--name-only', '-z'], {
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
  const bad = staged.split('\0').filter(isSecret);
  if (bad.length) {
    deny(
      `staged に secret-looking file が含まれています: ${bad.join(', ')}\n` +
      (commits.length ? '実行対象の commit の index が禁止ファイル名を含みます。対象を staged から外してください。'
        : '旧文字列判定の commit 候補と index の禁止名が一致しましたが、実際の commit 対象か確定できないため停止します。'),
      commits.length ? 'FORBIDDEN' : 'UNKNOWN',
    );
  }
}
}

process.exit(0);
