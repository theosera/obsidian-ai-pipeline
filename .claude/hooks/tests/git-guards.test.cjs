#!/usr/bin/env node
'use strict';
/**
 * .claude/hooks の git ガード 3 本（block-secret-git / block-git-add-all / block-secret-egress）の試験。
 *
 * 各 case のコマンドを PreToolUse の JSON にして 3 本に渡し、1 本でも deny を返せば deny とみる
 * （Claude Code は PreToolUse の hook をすべて回し、1 本でも deny なら止める）。hook が落ちたり
 * JSON でない出力を返したりしたら、その case は失敗にする（落ちた hook は止めないため）。
 * 使い捨ての git リポを os.tmpdir() に作る。秘密の形の名前のファイルは中身の無いダミー。
 * git の global / system の設定は読まない（GIT_CONFIG_GLOBAL を空のファイルにする）。
 *
 *   node .claude/hooks/tests/git-guards.test.cjs                      # 緑なら exit 0
 *   node .claude/hooks/tests/git-guards.test.cjs --hooks-dir <dir>    # 別の場所の hook を回す
 *   node .claude/hooks/tests/git-guards.test.cjs --json               # 結果を JSON で出す
 */
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync, spawnSync } = require('node:child_process');

const HOOKS = ['block-secret-git.cjs', 'block-git-add-all.cjs', 'block-secret-egress.cjs'];

// cwd / project: case が使うリポ（既定は clean）。{clean} などはリポの絶対パスに置き換える。
const CASES = [
  // --- 通すもの -------------------------------------------------------------
  { id: 'N01', expect: 'allow', cmd: 'git status && git log -1' },
  { id: 'N02', expect: 'allow', cmd: 'git --no-optional-locks status' },
  { id: 'N03', expect: 'allow', cmd: 'git commit -m "git add した"' },
  { id: 'N04', expect: 'allow', cmd: 'git -C {clean} commit -q -o -m x -m "Co-Authored-By: a <a@example.invalid>" -- a.txt' },
  { id: 'N05', expect: 'allow', cmd: 'git add a.txt' },
  {
    id: 'N06', expect: 'allow',
    cmd: 'git commit -m "$(cat <<\'EOF\'\nfix: handle ) and it\'s "quoted" (#12)\n\nCo-Authored-By: a <a@example.invalid>\nEOF\n)"',
  },
  { id: 'N07', expect: 'allow', cmd: 'H=$(git rev-parse HEAD); echo "$H"' },
  { id: 'N08', expect: 'allow', cmd: 'git commit -m x && git show --stat HEAD | head -5' },
  { id: 'N09', expect: 'allow', cmd: 'echo "git commit -a"' },
  { id: 'N10', expect: 'allow', cmd: "cat > notes.txt <<'EOF'\ngit add .env && git commit -a -m x\nEOF" },
  { id: 'N11', expect: 'allow', cmd: 'grep -rn "git commit -a" docs/ | head' },
  { id: 'N12', expect: 'allow', cmd: 'git -c core.quotepath=false status' },
  { id: 'N13', expect: 'allow', cmd: 'GIT_PAGER=cat git log -1' },
  { id: 'N14', expect: 'allow', cmd: 'git lfs ls-files' },
  { id: 'N15', expect: 'allow', cmd: 'git commit -m x' },
  { id: 'N16', expect: 'allow', cmd: 'cd {clean} && git status' },
  { id: 'N17', expect: 'allow', cmd: 'git diff --cached --name-only' },
  { id: 'N18', expect: 'allow', cmd: 'git push origin main' },
  { id: 'N19', expect: 'allow', cmd: 'npm run lint -- --fix' },
  { id: 'N20', expect: 'allow', cmd: '"$PY" -B script.py' },
  { id: 'N21', expect: 'allow', cmd: 'git -C {clean} add -- a.txt' },
  { id: 'N22', expect: 'allow', cmd: "git log --format='%h %s' -3 | cat" },
  { id: 'N23', expect: 'allow', cmd: "find . -name '*.md' -exec grep -l git {} +" },
  { id: 'N24', expect: 'allow', cmd: 'git --version' },
  { id: 'N25', expect: 'allow', cmd: 'for f in a.txt; do git add "$f"; done' },
  { id: 'N26', expect: 'allow', cmd: 'git commit --amend --no-edit' },
  { id: 'N27', expect: 'allow', cmd: 'git -C "$R" status' },
  { id: 'N28', expect: 'allow', cmd: 'git commit -m "$MSG"' },
  { id: 'N29', expect: 'allow', cmd: 'git config --get remote.origin.url' },
  { id: 'N30', expect: 'allow', cmd: "bash -c 'echo hi'" },
  { id: 'N31', expect: 'allow', cmd: 'git commit --allow-empty -m x' },
  { id: 'N32', expect: 'allow', cmd: 'git -c core.quotepath=false commit -m x' },
  { id: 'N33', expect: 'allow', cmd: 'git -c user.name=t -c user.email=t@example.invalid commit -m x' },
  { id: 'N34', expect: 'allow', cmd: 'git -c color.ui=never status && git commit -m x' },
  { id: 'N35', expect: 'allow', cmd: 'git -c core.fsmonitor=/usr/bin/true status' },
  { id: 'N36', expect: 'allow', cmd: 'git -c Advice.detachedHead=false add a.txt' },

  // --- commit と同じコマンドでは、読むだけの git 以外を拒む -------------------------
  { id: 'A01', expect: 'deny', cmd: 'git update-index --add --cacheinfo 100644,e69de29bb2d1d6434b8b29ae775ad8c2e48c5391,.env && git commit -m x' },
  { id: 'A02', expect: 'deny', cmd: 'git read-tree HEAD && git commit -m x' },
  { id: 'A03', expect: 'deny', cmd: 'git apply --cached p.diff; git commit -m x' },
  { id: 'A04', expect: 'deny', cmd: 'git checkout HEAD -- a.txt && git commit -m x' },
  { id: 'A05', expect: 'deny', cmd: 'git restore --staged --source=HEAD a.txt && git commit -m x' },
  { id: 'A06', expect: 'deny', cmd: 'git reset HEAD -- a.txt && git commit -m x' },
  { id: 'A07', expect: 'deny', cmd: 'git stash apply --index && git commit -m x' },
  { id: 'A08', expect: 'deny', cmd: 'git commit -m x && git push' },
  { id: 'A09', expect: 'deny', cmd: 'git cherry-pick -n HEAD && git commit -m x' },
  { id: 'A10', expect: 'deny', cmd: 'git commit -m x && git commit --amend -m y' },

  // --- index を通らずに commit や ref を作る plumbing は拒む ------------------------
  { id: 'B01', expect: 'deny', cmd: 'git commit-tree -m x 4b825dc642cb6eb9a060e54bf8d69288fbee4904' },
  { id: 'B02', expect: 'deny', cmd: 'git update-ref refs/heads/x HEAD' },
  { id: 'B03', expect: 'deny', cmd: 'git mktree </dev/null' },

  // --- 文字列でシェルに渡した git は拒む / シェルに流す本文は読む ------------------------
  { id: 'C01', expect: 'deny', cmd: "bash -c 'git add a.txt && git commit -m x'" },
  { id: 'C02', expect: 'deny', cmd: 'sh -c "git commit -m x"' },
  { id: 'C03', expect: 'deny', cmd: 'eval "git commit -m x"' },
  { id: 'C04', expect: 'deny', cmd: "zsh -lc 'git status'" },
  { id: 'C05', expect: 'deny', cmd: "printf '%s\\n' 'git commit -m x' | bash" },
  { id: 'C06', expect: 'deny', cmd: "bash <<'EOF'\ngit commit -a -m x\nEOF" },
  { id: 'C07', expect: 'deny', cmd: "env -S 'git commit -m x'" },

  // --- 検査する対象のリポ（場所を変える形・環境変数・入力の cwd） -------------------------
  { id: 'D01', expect: 'deny', cmd: 'cd {dirty} && git commit -m x' },
  { id: 'D02', expect: 'deny', cmd: 'pushd {dirty} && git commit -m x' },
  { id: 'D03', expect: 'deny', cmd: '(cd {dirty}; git commit -m x)' },
  { id: 'D04', expect: 'deny', cmd: 'GIT_INDEX_FILE={root}/idx git commit -m x' },
  { id: 'D05', expect: 'deny', cmd: 'export GIT_DIR={dirty}/.git; git commit -m x' },
  { id: 'D06', expect: 'deny', cmd: 'env -C {dirty} git commit -m x' },
  { id: 'D07', expect: 'deny', cwd: 'dirty', project: 'clean', cmd: 'git commit -m x' },
  { id: 'D08', expect: 'deny', cmd: 'GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=alias.zz GIT_CONFIG_VALUE_0=commit git zz -m x' },

  // --- commit のときに stage する形・pathspec ------------------------------------------
  { id: 'E01', expect: 'deny', cmd: 'git -C {tracked} commit -o -m x -- conf/' },
  { id: 'E02', expect: 'deny', cmd: 'git commit -m x -- .env' },
  { id: 'E03', expect: 'deny', cmd: "git commit -i -m x '*.json'" },
  { id: 'E04', expect: 'deny', cmd: 'git commit --pathspec-from-file=list.txt -m x' },
  { id: 'E05', expect: 'deny', cmd: 'git commit -p -m x' },
  { id: 'E06', expect: 'deny', cmd: 'git commit --interactive' },
  { id: 'E07', expect: 'deny', cmd: 'git commit $ARGS -m x' },
  { id: 'E08', expect: 'deny', cmd: "printf '%s\\n' a.txt | xargs git commit -m x" },
  { id: 'E09', expect: 'deny', cmd: 'git commit --bogus-opt -m x' },
  { id: 'E10', expect: 'deny', cmd: 'git -C {tracked} commit -m x conf/dummy-token.json' },

  // --- alias ----------------------------------------------------------------------
  { id: 'F01', expect: 'deny', cmd: 'git -c alias.ci=commit ci -m x' },
  { id: 'F02', expect: 'deny', cmd: 'git --config-env=alias.ci=CI_CMD ci -m x' },
  { id: 'F03', expect: 'deny', cwd: 'alias', project: 'alias', cmd: 'git ci -m x' },
  { id: 'F04', expect: 'deny', cmd: 'git -c include.path={root}/inc ci -m x' },

  // --- 同じコマンドの add はすべて見る・stage は add と同じに見る ---------------------------
  { id: 'G01', expect: 'deny', cmd: 'git add a.txt && git add .env' },
  { id: 'G02', expect: 'deny', cmd: 'git stage .env' },

  // --- global option を挟んだ形 -----------------------------------------------------
  { id: 'H01', expect: 'deny', cmd: 'git --no-optional-locks commit -a -m x' },
  { id: 'H02', expect: 'deny', cmd: 'git --bogus-global value commit -a -m x' },
  { id: 'H03', expect: 'deny', cmd: 'git --git-dir {dirty}/.git commit -m x' },
  { id: 'H04', expect: 'deny', cmd: 'git --no-optional-locks add .env' },
  { id: 'H05', expect: 'deny', cmd: 'git --literal-pathspecs commit -a -m x' },

  // --- 引用符・変数・置換で作った語 -----------------------------------------------------
  { id: 'J01', expect: 'deny', cmd: 'git "commit" -a -m x' },
  { id: 'J02', expect: 'deny', cmd: "g''it commit -a -m x" },
  { id: 'J03', expect: 'deny', cmd: 'G=git; $G commit -a -m x' },
  { id: 'J04', expect: 'deny', cmd: 'git $SUB -a -m x' },
  { id: 'J05', expect: 'deny', cmd: '$(echo git) commit -a -m x' },
  { id: 'J06', expect: 'deny', cmd: 'git c""ommit -a -m x' },
  { id: 'J07', expect: 'deny', cmd: 'git -C "$R" commit -m x' },
  { id: 'J08', expect: 'deny', cmd: 'git -c "$K" commit -m x' },

  // --- egress / add -A の形を、git の呼び出しごとに見る ----------------------------------
  { id: 'EG01', expect: 'deny', cmd: 'git --no-optional-locks remote add x https://example.invalid/r.git' },
  { id: 'EG02', expect: 'deny', cmd: 'git "push" https://example.invalid/r.git main' },
  { id: 'EG03', expect: 'deny', cmd: 'git --no-optional-locks config remote.origin.url https://example.invalid/r.git' },
  { id: 'AA01', expect: 'deny', cmd: 'git --no-optional-locks add -A' },
  { id: 'AA02', expect: 'deny', cmd: 'git stage .' },
  { id: 'AA03', expect: 'deny', cwd: 'dirty', project: 'clean', cmd: 'git add {dirty}' },

  // --- commit や add と同じコマンドの -c / --config-env は allowlist の鍵だけ --------------
  { id: 'K01', expect: 'deny', cmd: 'git -c core.fsmonitor=/usr/bin/true status && git commit -m x' },
  { id: 'K02', expect: 'deny', cmd: 'git --config-env=core.fsmonitor=FSM status && git commit -m x' },
  { id: 'K03', expect: 'deny', cmd: 'git -c diff.external=/usr/bin/true diff && git commit -m x' },
  { id: 'K04', expect: 'deny', cmd: 'git -c core.fsmonitor=/usr/bin/true commit -m x' },
  { id: 'K05', expect: 'deny', cmd: 'git -c core.pager=cat add a.txt' },
  { id: 'K06', expect: 'deny', cmd: 'git -c "$K" status && git commit -m x' },

  // --- 読みきれない形 ----------------------------------------------------------------
  { id: 'P01', expect: 'deny', cmd: 'git commit -m "unterminated' },

  // --- 前からの拒み（回帰） -----------------------------------------------------------
  { id: 'R01', expect: 'deny', cmd: 'git add .env' },
  { id: 'R02', expect: 'deny', cmd: 'git add ".env"' },
  { id: 'R03', expect: 'deny', cmd: 'git commit -a -m x' },
  { id: 'R04', expect: 'deny', cmd: 'git commit -am x' },
  { id: 'R05', expect: 'deny', cmd: 'git add a.txt && git commit -m x' },
  { id: 'R06', expect: 'deny', cmd: 'git --git-dir={dirty}/.git commit -m x' },
  { id: 'R07', expect: 'deny', cwd: 'dirty', project: 'dirty', cmd: 'git commit -m x' },
  { id: 'R08', expect: 'deny', cmd: 'git -C {dirty} commit -m x' },
  { id: 'R09', expect: 'deny', cmd: 'git -C {root}/nonexistent commit -m x' },
  { id: 'R10', expect: 'deny', cmd: 'git add -A' },
  { id: 'R11', expect: 'deny', cmd: 'git add .' },
  { id: 'R12', expect: 'deny', cmd: 'git commit --no-verify -m x' },
  { id: 'R13', expect: 'deny', cmd: 'git commit -n -m x' },
  { id: 'R14', expect: 'deny', cmd: 'git -c core.hooksPath=/dev/null commit -m x' },
  { id: 'R15', expect: 'deny', cmd: 'git remote add x https://example.invalid/r.git' },
  { id: 'R16', expect: 'deny', cmd: 'git push https://example.invalid/r.git main' },
  { id: 'R17', expect: 'deny', cmd: 'git add --pathspec-from-file=list.txt' },
  { id: 'R18', expect: 'deny', cmd: '(cd sub && git add .env)' },
  { id: 'R19', expect: 'deny', cmd: 'git commit "-a" -m x' },
  { id: 'R20', expect: 'deny', cmd: 'git add "$PWD"' },
];

// git の global / system の設定を読まない環境。
function isolatedEnv(root) {
  const gcfg = path.join(root, 'gitconfig-empty');
  if (!fs.existsSync(gcfg)) fs.writeFileSync(gcfg, '');
  const env = {};
  for (const [k, v] of Object.entries(process.env)) if (!/^GIT_/.test(k) && k !== 'CLAUDE_PROJECT_DIR') env[k] = v;
  env.GIT_CONFIG_GLOBAL = gcfg;
  env.GIT_CONFIG_NOSYSTEM = '1';
  return env;
}

function setupRepos() {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'git-guards-test-')));
  const env = isolatedEnv(root);
  const git = (cwd, ...args) => execFileSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.invalid', ...args], {
    cwd, env, stdio: ['ignore', 'pipe', 'pipe'],
  });
  const mk = (name, files) => {
    const d = path.join(root, name);
    fs.mkdirSync(d, { recursive: true });
    git(d, 'init', '-q');
    for (const [f, body] of Object.entries(files)) {
      fs.mkdirSync(path.dirname(path.join(d, f)), { recursive: true });
      fs.writeFileSync(path.join(d, f), body);
    }
    return d;
  };
  const dirs = {};
  dirs.clean = mk('clean', { 'a.txt': 'a\n' });
  git(dirs.clean, 'add', '--', 'a.txt');
  dirs.dirty = mk('dirty', { 'a.txt': 'a\n', '.env': '' });
  git(dirs.dirty, 'add', '--', 'a.txt', '.env');
  dirs.tracked = mk('tracked', { 'a.txt': 'a\n', 'conf/dummy-token.json': '' });
  git(dirs.tracked, 'add', '--', 'a.txt', 'conf/dummy-token.json');
  git(dirs.tracked, 'commit', '-q', '-m', 'init');
  dirs.alias = mk('alias', { 'a.txt': 'a\n' });
  git(dirs.alias, 'add', '--', 'a.txt');
  git(dirs.alias, 'config', 'alias.ci', 'commit');
  return { root, env, dirs };
}

function cleanupRepos(repos) {
  fs.rmSync(repos.root, { recursive: true, force: true });
}

// 1 つの case を 3 本の hook に渡す。stopAtFirstDeny のときは、deny が出たらそこで止める。
function runCase(hooksDir, c, repos, stopAtFirstDeny = false) {
  const fill = (s) => s.replace(/\{(clean|dirty|tracked|alias|root)\}/g, (_m, k) => (k === 'root' ? repos.root : repos.dirs[k]));
  const command = fill(c.cmd);
  const cwd = repos.dirs[c.cwd || 'clean'];
  const project = repos.dirs[c.project || 'clean'];
  const input = JSON.stringify({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command }, cwd });
  const denied = [];
  const broken = [];
  for (const h of HOOKS) {
    const r = spawnSync(process.execPath, [path.join(hooksDir, h)], {
      input, cwd: project, env: { ...repos.env, CLAUDE_PROJECT_DIR: project }, encoding: 'utf8', timeout: 20000,
    });
    if (r.error || r.status !== 0) { broken.push(`${h}: exit ${r.status}${r.error ? ` ${r.error.code}` : ''}`); continue; }
    if (!r.stdout) continue;
    let out;
    try { out = JSON.parse(r.stdout); } catch { broken.push(`${h}: JSON でない出力`); continue; }
    if (out && out.hookSpecificOutput && out.hookSpecificOutput.permissionDecision === 'deny') {
      denied.push(h);
      if (stopAtFirstDeny) break;
    }
  }
  return { id: c.id, decision: denied.length ? 'deny' : 'allow', denied, broken };
}

function main() {
  const argv = process.argv.slice(2);
  const hi = argv.indexOf('--hooks-dir');
  const hooksDir = path.resolve(hi >= 0 ? argv[hi + 1] : path.join(__dirname, '..'));
  const asJson = argv.includes('--json');
  const repos = setupRepos();
  let failed = 0;
  const results = [];
  try {
    for (const c of CASES) {
      const r = runCase(hooksDir, c, repos);
      r.expect = c.expect;
      r.ok = r.decision === c.expect && r.broken.length === 0;
      if (!r.ok) failed++;
      results.push(r);
    }
  } finally {
    cleanupRepos(repos);
  }
  if (asJson) {
    process.stdout.write(JSON.stringify({ hooksDir, total: results.length, failed, results }, null, 1) + '\n');
  } else {
    for (const r of results) {
      if (!r.ok) console.log(`✗ ${r.id}: expect ${r.expect} got ${r.decision} ${r.denied.join(',')} ${r.broken.join('; ')}`);
    }
    console.log(`${results.length - failed}/${results.length} ok`);
  }
  process.exit(failed ? 1 : 0);
}

module.exports = { CASES, HOOKS, setupRepos, cleanupRepos, runCase, isolatedEnv };

if (require.main === module) main();
