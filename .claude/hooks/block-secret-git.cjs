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
 * 副作用: `git commit` のときだけ `git diff --cached --name-only` と `git ls-files` を、
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
      permissionDecisionReason: 'git ガードの共通の部品 (lib/git-guard-common.cjs) を読み込めませんでした (fail-closed)。secret ガードを通せないため実行をブロックします。',
    },
  }));
  process.exit(0);
}
const { deny } = guard;

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

const { cmd, baseDir } = guard.readInput('secret ガード');
if (!cmd) process.exit(0);

const insp = guard.inspect(cmd);
if (insp.problems.length) deny(guard.problemMessage(insp.problems, 'secret ガード'));
const gits = insp.gits;
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

// builtin でない subcommand が alias なら拒む（alias の中身は検査できない）。
for (const g of gits) {
  const p = guard.aliasProblem(g, baseDir);
  if (p) deny(`${p}。alias を使わず、git の subcommand をそのまま書いてください (fail-closed)。`);
}

// commit や ref を index を通さずに作る plumbing は、エージェントの経路では使わない。
for (const g of gits) {
  if (g.sub === 'commit-tree' || g.sub === 'mktree' || g.sub === 'update-ref') {
    deny(
      `\`git ${g.sub}\` はブロックしました。staged 検査を通らずに commit や ref を作れるためです。\n` +
      'commit は `git add <files>` → `git commit` で作ってください（plumbing が要る作業は人が実行します）。',
    );
  }
}

// 対象のリポ・index・設定を変える変数だけを、その変数が作用する git に対して拒む。
// GIT_EDITOR / GIT_AUTHOR_DATE / GIT_PAGER などでは staged 検査の対象は変わらない。
/** Return whether a Git environment variable redirects inspection state or changes pathspec matching. */
const changesGitTarget = (n) => /^(?:GIT_(?:DIR|WORK_TREE|COMMON_DIR|INDEX_FILE|OBJECT_DIRECTORY|ALTERNATE_OBJECT_DIRECTORIES|NAMESPACE|CEILING_DIRECTORIES|DISCOVERY_ACROSS_FILESYSTEM|EXEC_PATH|(?:LITERAL|GLOB|NOGLOB|ICASE)_PATHSPECS)|GIT_CONFIG(?:_.*)?)$/.test(n);
const envWriter = gits.find((g) => writesRepo(g) && g.gitEnvNames.some(changesGitTarget));
if (envWriter) {
  deny(
    `環境変数 ${envWriter.gitEnvNames.find(changesGitTarget)} を、読むだけでない git に設定しています。\n` +
    'secret ガードが検査する対象のリポや index を決めきれないためブロックしました (fail-closed)。環境変数を付けずに実行してください。',
  );
}

// ① `git add <paths>` / `git stage <paths>` — 明示パス引数を検査（同じコマンドの add はすべて）。
const addGits = gits.filter((g) => g.sub === 'add' || g.sub === 'stage');
for (const g of addGits) {
  const words = g.args.map((w) => w.text);
  // 追加パスが stdin 側にある形は本フックから検査できない → 検査不能として拒否する。
  if (words.some((a) => /^--pathspec-(from-file|file-nul)\b/.test(a))) {
    deny(
      '`git add --pathspec-from-file` / `--pathspec-file-nul` は追加パスが stdin 側にあり、\n' +
      'secret ガードから検査できません（検査不能なのでブロック）。追加するファイルをコマンドラインに列挙してください。',
    );
  }
  const bad = words.filter((a) => a && !a.startsWith('-')).filter(isSecret);
  if (bad.length) {
    deny(
      `secret-looking file を git add しようとしています: ${bad.join(', ')}\n` +
      'CLAUDE.md の Secrets 境界によりブロックしました（.gitignore 済みのはず）。本当に追跡が必要か再検討してください。',
    );
  }
}

// ② `git commit` — 現在 staged のファイルを検査（add 経由でなくても漏れを止める）。
//    ただし PreToolUse は**コマンド実行前**に走るため `git diff --cached` は「実行前の
//    index」しか見えない。そのため commit と同じコマンドでは、読むだけの git 以外を
//    走らせない・commit のときに stage する形（`-a` / `-p` / pathspec）を先に見る、とし、
//    staged 検査は backstop に残す。
const commits = gits.filter((g) => g.sub === 'commit');
if (commits.length) {
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
    staged = execFileSync('git', ['diff', '--cached', '--name-only'], {
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
  const bad = staged.split('\n').map((s) => s.trim()).filter(isSecret);
  if (bad.length) {
    deny(
      `staged に secret-looking file が含まれています: ${bad.join(', ')}\n` +
      'このまま commit すると機密が履歴に入ります。`git restore --staged <file>` で外してから commit してください（CLAUDE.md ハードルール）。',
    );
  }
  // pathspec を付けた commit（`-o` / `-i` / 素の pathspec）は、作業木の中身をその場で commit する。
  // pathspec が当たる追跡済みのファイルを検査する。
  if (ca.pathspecs.length) {
    const badSpec = ca.pathspecs.filter(isSecret);
    if (badSpec.length) {
      deny(`secret-looking file を pathspec に付けて commit しようとしています: ${badSpec.join(', ')}（CLAUDE.md ハードルール）。`);
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
      deny(`pathspec が secret-looking file に当たります: ${badListed.join(', ')}\nこのまま commit すると機密が履歴に入ります（CLAUDE.md ハードルール）。`);
    }
  }
}

// v3.5.3: 今の main（ae10261）の同じ検査を、コマンドの文字の全体にもう一度当てる（和をとる）。
// 上の読み方が取りこぼしても、今の main より緩めないため。ブロックの中は main の文字のまま（空行と、頭の
// `require('node:path')` の 1 行のほかは main の行と同じ）。
// main の「git の文字が無ければ exit」はブロックの条件にした。SECRET_RE と isSecret は上の同じもの（main と同じ文字）。
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
}

process.exit(0);
