'use strict';

// Issue #204: owned DUMMY repositories only. Hook stdin DATA, native commits,
// injected reader failures and single-site reverses are separate observations.
// Normal: node --test .claude/hooks/tests/staged-secret-deletions.test.cjs
// Reverse: node .claude/hooks/tests/staged-secret-deletions.test.cjs --reverse
// ISSUE204_HOOKS_DIR selects a complete saved source; no production hook is edited.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const hooks = path.resolve(process.env.ISSUE204_HOOKS_DIR || path.join(__dirname, '..'));
const guard = require(path.join(hooks, 'lib/git-guard-common.cjs'));
const readers = require(path.join(hooks, 'lib/git-precommit-readers.cjs'));
const reverse = process.argv.includes('--reverse');
const evidence = [];
const installations = ['/opt/homebrew/bin/git', '/usr/local/bin/git', '/usr/bin/git', '/bin/git'];
const gitExe = installations.find(executable => guard.resolveTrustedGitExecutable({ text: executable }));
assert.ok(gitExe, 'a trusted Git installation is required; unexercised cases do not pass');
const command = 'git commit -m DUMMY-untrack';
const dummy = 'DUMMY fixture contents only, no credentials.\n'.repeat(8);
const sha256 = value => createHash('sha256').update(value).digest('hex');

function fixture(t, tracked = { '.env': dummy, 'ordinary.txt': 'DUMMY ordinary\n' }) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'issue204-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const repo = path.join(root, 'repo');
  const home = path.join(root, 'home');
  const template = path.join(root, 'empty-template');
  for (const dir of [repo, home, template]) fs.mkdirSync(dir);
  const env = { PATH: [path.dirname(gitExe), '/usr/bin', '/bin'].join(path.delimiter), HOME: home,
    GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: os.devNull, GIT_CONFIG_SYSTEM: os.devNull,
    GIT_TERMINAL_PROMPT: '0', LC_ALL: 'C' };
  function git(...args) {
    const result = spawnSync(gitExe, args, { cwd: repo, env, encoding: 'utf8', timeout: 10000 });
    assert.ifError(result.error);
    assert.equal(result.signal, null);
    assert.equal(result.status, 0, JSON.stringify(args) + '\n' + result.stderr);
    evidence.push({ kind: 'native-git', cwd: repo, executable: gitExe, args, env,
      status: result.status, stdout: result.stdout, stderr: result.stderr });
    return result.stdout;
  }
  function write(name, content = dummy) {
    fs.mkdirSync(path.dirname(path.join(repo, name)), { recursive: true });
    fs.writeFileSync(path.join(repo, name), content);
  }
  git('init', '-q', '--template=' + template);
  // Use owned local identity settings; inherited identity variables deliberately
  // remain UNKNOWN in the egress guard and are not needed by this fixture.
  git('config', 'user.name', 'DUMMY fixture');
  git('config', 'user.email', 'fixture@example.invalid');
  const banner = git('--no-lazy-fetch', '--version');
  assert.ok(readers.supportsInspectionHardening(banner), 'actual inspection capability is required');
  for (const [name, content] of Object.entries(tracked)) write(name, content);
  git('add', '--', ...Object.keys(tracked));
  git('commit', '-q', '-m', 'DUMMY-seed');
  return { root, repo, env, git, write };
}

function run(f, hook = 'block-secret-git.cjs', proposed = command, options = {}) {
  const selected = options.hooks || hooks;
  const input = { tool_name: 'Bash', tool_input: { command: proposed }, cwd: f.repo };
  const env = { ...f.env, CLAUDE_PROJECT_DIR: f.repo };
  const args = [];
  let trace;
  if (options.probe || options.fault) {
    trace = path.join(f.root, 'reader-trace-' + evidence.length + '.jsonl');
    const preload = path.join(f.root, 'reader-probe-' + evidence.length + '.cjs');
    // The seam only changes one reader result; parsing, selected context, other
    // Git reads, the production denial wire and the second check still run.
    fs.writeFileSync(preload, `const fs = require('node:fs');
const r = require(${JSON.stringify(path.join(selected, 'lib/git-precommit-readers.cjs'))});
const original = r.readInspectionGit;
const fault = ${JSON.stringify(options.fault || null)};
let count = 0;
r.readInspectionGit = (args, options) => {
  if (!(args[0] === 'diff' && args.includes('--cached') && args.includes('--name-only'))) return original(args, options);
  count++;
  const row = { count, args, cwd: options.cwd, cdirs: options.cdirs, executable: options.executable };
  if (fault && count === fault.at) {
    row.fault = fault;
    fs.appendFileSync(${JSON.stringify(trace)}, JSON.stringify(row) + '\\n');
    if (fault.error) throw Object.assign(new Error('DUMMY reader failure'), { code: fault.error });
    return fault.output;
  }
  const output = original(args, options);
  fs.appendFileSync(${JSON.stringify(trace)}, JSON.stringify({ ...row, output }) + '\\n');
  return output;
};
`);
    args.push('--require', preload);
  }
  args.push(path.join(selected, hook));
  const result = spawnSync(process.execPath, args, {
    cwd: f.repo, env, encoding: 'utf8', input: JSON.stringify(input), timeout: 15000,
  });
  const probes = trace && fs.existsSync(trace)
    ? fs.readFileSync(trace, 'utf8').trim().split('\n').filter(Boolean).map(line => JSON.parse(line)) : [];
  evidence.push({ kind: options.fault ? 'injected-hook' : 'direct-hook', hook, selected,
    node: process.version, cwd: f.repo, env, input, status: result.status,
    signal: result.signal, error: result.error?.code, stdout: result.stdout, stderr: result.stderr, probes });
  // A crash, timeout, malformed wire or unrelated failure cannot count as ALLOW or UNKNOWN.
  assert.ifError(result.error);
  assert.equal(result.signal, null);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, '');
  if (result.stdout === '') return { verdict: 'ALLOW', reason: '', probes };
  const wire = JSON.parse(result.stdout).hookSpecificOutput;
  assert.equal(wire.hookEventName, 'PreToolUse');
  assert.equal(wire.permissionDecision, 'deny');
  assert.equal(typeof wire.permissionDecisionReason, 'string');
  const reason = wire.permissionDecisionReason;
  const verdict = reason.startsWith('[禁止] ') ? 'FORBIDDEN'
    : reason.startsWith('[判断不能] ') ? 'UNKNOWN' : 'BROKEN';
  assert.notEqual(verdict, 'BROKEN', reason);
  return { verdict, reason, probes };
}
function expect(f, expected, proposed = command, options = {}) {
  const result = run(f, 'block-secret-git.cjs', proposed, options);
  assert.equal(result.verdict, expected, result.reason);
  return result;
}
function expectStagedSecret(f, name, options = {}) {
  const result = expect(f, 'FORBIDDEN', command, options);
  assert.match(result.reason, /staged に secret-looking file/);
  assert.ok(result.reason.includes(name), result.reason);
  return result;
}

test.after(() => {
  if (!process.env.ISSUE204_EVIDENCE) return;
  const names = ['block-secret-git.cjs', 'block-git-add-all.cjs', 'block-secret-egress.cjs',
    'lib/git-guard-common.cjs', 'lib/git-precommit-readers.cjs', 'lib/executable-identity.cjs'];
  const source = Object.fromEntries(names.map(name => [name, sha256(fs.readFileSync(path.join(hooks, name)))]));
  fs.writeFileSync(process.env.ISSUE204_EVIDENCE, JSON.stringify({ node: process.version,
    platform: process.platform, gitExe, hooks, reverse, source, evidence }, null, 2) + '\n');
});

if (!reverse) {
  test('I204-D01: rm --cached permits both staged checks and all hooks; native commit omits the path', t => {
    const f = fixture(t);
    f.git('rm', '--cached', '--', '.env');
    assert.equal(f.git('diff', '--cached', '--name-status', '-z'), 'D\0.env\0');
    assert.equal(fs.readFileSync(path.join(f.repo, '.env'), 'utf8'), dummy);
    const result = expect(f, 'ALLOW', command, { probe: true });
    assert.equal(result.probes.length, 2, 'both actual staged reads are reached');
    for (const hook of ['block-git-add-all.cjs', 'block-secret-egress.cjs']) {
      const other = run(f, hook);
      assert.equal(other.verdict, 'ALLOW', hook + ': ' + other.reason);
    }
    f.git('commit', '-m', 'DUMMY-untrack');
    const tree = f.git('ls-tree', '-r', '--name-only', '-z', 'HEAD').split('\0');
    assert.ok(!tree.includes('.env'));
    assert.ok(tree.includes('ordinary.txt'));
    assert.ok(f.git('ls-tree', '-r', '--name-only', '-z', 'HEAD^').split('\0').includes('.env'),
      'untracking does not erase history');
    assert.ok(fs.existsSync(path.join(f.repo, '.env')), 'the local file remains');
  });

  test('I204-D02: ordinary deletion control remains allowed by all hooks', t => {
    const f = fixture(t, { 'ordinary.txt': dummy });
    f.git('rm', '--cached', '--', 'ordinary.txt');
    for (const hook of ['block-secret-git.cjs', 'block-git-add-all.cjs', 'block-secret-egress.cjs']) {
      const result = run(f, hook);
      assert.equal(result.verdict, 'ALLOW', result.reason);
    }
  });

  test('I204-D03: NUL-delimited secret deletion retains spaces, newline and Unicode', t => {
    const name = 'nested dir/日本語\nprivate.key';
    const f = fixture(t, { [name]: dummy, 'ordinary.txt': dummy });
    f.git('rm', '--cached', '--', name);
    expect(f, 'ALLOW');
  });

  test('I204-D04: secret deletion plus ordinary addition is allowed', t => {
    const f = fixture(t);
    f.git('rm', '--cached', '--', '.env');
    f.write('new public.txt');
    f.git('add', '--', 'new public.txt');
    expect(f, 'ALLOW');
  });

  for (const kind of ['addition', 'modification', 'rename', 'copy', 'type-change', 'delete-and-readd']) {
    test('I204-N: secret ' + kind + ' remains FORBIDDEN', t => {
      const f = fixture(t, kind === 'addition' || kind === 'rename' || kind === 'copy'
        ? { 'public.txt': dummy } : { '.env': dummy });
      if (kind === 'rename') {
        f.git('mv', '--', 'public.txt', '.env');
        assert.match(f.git('diff', '--cached', '--name-status', '-z'), /^R100\0public\.txt\0\.env\0$/);
      } else if (kind === 'copy') {
        f.git('config', 'diff.renames', 'copies');
        f.write('.env');
        f.write('public.txt', dummy + 'DUMMY changed source\n');
        f.git('add', '--', 'public.txt', '.env');
        assert.ok(f.git('diff', '--cached', '--name-status', '-z').includes('C100\0public.txt\0.env\0'));
      } else if (kind === 'type-change') {
        fs.unlinkSync(path.join(f.repo, '.env'));
        fs.symlinkSync('ordinary.txt', path.join(f.repo, '.env'));
        f.git('add', '--', '.env');
        assert.equal(f.git('diff', '--cached', '--name-status', '-z'), 'T\0.env\0');
      } else {
        if (kind === 'delete-and-readd') f.git('rm', '--cached', '--', '.env');
        f.write('.env', dummy + 'DUMMY changed\n');
        f.git('add', '--', '.env');
      }
      expectStagedSecret(f, '.env');
      const second = expectStagedSecret(f, '.env', { fault: { at: 1, output: '' } });
      assert.match(second.reason, /実行対象の commit/);
      assert.equal(second.probes.length, 2, 'the second read also checks the non-deletion');
    });
  }

  for (const kind of ['addition', 'modification']) {
    test('I204-M: deletion mixed with secret ' + kind + ' remains FORBIDDEN', t => {
      const f = fixture(t, kind === 'modification' ? { '.env': dummy, '.env.local': 'DUMMY old\n' } : undefined);
      f.git('rm', '--cached', '--', '.env');
      f.write('.env.local', 'DUMMY different contents\n');
      f.git('add', '--', '.env.local');
      const result = expectStagedSecret(f, '.env.local');
      assert.ok(!result.reason.includes('file が含まれています: .env,'), 'deletion is not an offender');
      assert.match(result.reason, /削除.*取り消さない/);
    });
  }

  test('I204-NUL: secret addition after a deletion cannot hide in a newline filename', t => {
    const f = fixture(t);
    f.git('rm', '--cached', '--', '.env');
    const name = 'nested dir/public\nprivate.key';
    f.write(name);
    f.git('add', '--', name);
    expectStagedSecret(f, name);
  });

  for (const option of ['', '-o ', '-i ']) {
    test('I204-P: deletion does not permit commit ' + option + '-- .env', t => {
      const f = fixture(t);
      f.git('rm', '--cached', '--', '.env');
      const result = expect(f, 'FORBIDDEN', 'git commit -m DUMMY ' + option + '-- .env');
      assert.match(result.reason, /(?:pathspec.*禁止|staged に secret-looking file)/);
    });
  }
  for (const option of ['', '-o ', '-i ']) {
    for (const directory of ['sub', '.']) {
      test('I204-PDIR: retained secret under directory pathspec ' + option + directory + ' is refused', t => {
        const f = fixture(t, { 'sub/.env': dummy, 'sub/public.txt': 'DUMMY public\n' });
        f.git('rm', '--cached', '--', 'sub/.env');
        f.write('sub/public.txt', 'DUMMY changed\n');
        const result = expect(f, 'FORBIDDEN', 'git commit -m DUMMY ' + option + '-- ' + directory);
        assert.match(result.reason, /staged に secret-looking file.*sub\/\.env/);
        const second = expect(f, 'FORBIDDEN', 'git commit -m DUMMY ' + option + '-- ' + directory,
          { fault: { at: 1, output: '' } });
        assert.match(second.reason, /実行対象の commit/);
        assert.equal(second.probes.length, 2);
      });
    }
  }
  for (const mode of ['-o --amend -m DUMMY', '--only --amend -m DUMMY', '--on --amend -m DUMMY',
    '-qo --amend -m DUMMY', '--only --allow-empty -m DUMMY', '--fixup=reword:HEAD --no-edit']) {
    test('I204-PONLY: alternate tree selection remains refused: ' + mode, t => {
      const f = fixture(t);
      f.git('rm', '--cached', '--', '.env');
      assert.match(expect(f, 'FORBIDDEN', 'git commit ' + mode).reason, /staged に secret-looking file/);
      const second = expect(f, 'FORBIDDEN', 'git commit ' + mode, { fault: { at: 1, output: '' } });
      assert.match(second.reason, /実行対象の commit/);
    });
  }
  test('I204-PDATA: only-like message DATA does not select an alternate tree', t => {
    const f = fixture(t);
    f.git('rm', '--cached', '--', '.env');
    for (const value of ['--only', '--fixup=reword:HEAD', '-o']) {
      expect(f, 'ALLOW', 'git commit -m ' + value);
    }
  });
  for (const [suffix, reason] of [['-- "*.txt"', /magic \/ glob/],
    ['--pathspec-from-file=paths.txt', /pathspec-from-file/], ['-a', /commit -a/]]) {
    test('I204-P: unsupported selection stays UNKNOWN: ' + suffix, t => {
      const f = fixture(t, { 'ordinary.txt': dummy });
      f.git('rm', '--cached', '--', 'ordinary.txt');
      assert.match(expect(f, 'UNKNOWN', 'git commit -m DUMMY ' + suffix).reason, reason);
    });
  }

  test('I204-U: absent repository still stops UNKNOWN', t => {
    const f = fixture(t);
    const result = expect(f, 'UNKNOWN', 'git -C missing commit -m DUMMY');
    assert.match(result.reason, /staged ファイルの検査に失敗/);
  });
  test('I204-U: deletion does not bypass a later uninspected reader', t => {
    const f = fixture(t);
    f.git('rm', '--cached', '--', '.env');
    f.git('config', 'core.fsmonitor', path.join(f.root, 'DUMMY-unexecuted-helper'));
    const result = expect(f, 'UNKNOWN', 'git status; git commit -m DUMMY', { probe: true });
    assert.equal(result.probes.length, 2, 'later reader checks follow both successful staged reads');
    assert.match(result.reason, /fsmonitor/);
  });
  test('I204-U: corrupt index still stops UNKNOWN', t => {
    const f = fixture(t);
    fs.writeFileSync(path.join(f.repo, '.git', 'index'), 'DUMMY invalid index');
    assert.match(expect(f, 'UNKNOWN').reason, /staged ファイルの検査に失敗/);
  });

  for (const at of [1, 2]) {
    for (const fault of [{ error: 'ETIMEDOUT' }, { error: 'EIO' }, { output: 'ordinary.txt' },
      { output: 'ordinary.txt\0\0' }, { output: null }]) {
      test('I204-F: reader ' + at + ' failure ' + JSON.stringify(fault) + ' stops explicitly UNKNOWN', t => {
        const f = fixture(t);
        f.git('rm', '--cached', '--', '.env');
        const result = expect(f, 'UNKNOWN', command, { fault: { at, ...fault } });
        assert.equal(result.probes.length, at, 'failure injected at the intended read');
        assert.match(result.reason, /staged ファイルの検査に失敗/);
      });
    }
  }
} else {
  for (const at of [1, 2]) {
    test('I204-R' + at + ': reverting only staged filter ' + at + ' restores the exact filename refusal', t => {
      const f = fixture(t);
      f.git('rm', '--cached', '--', '.env');
      expect(f, 'ALLOW');
      const copy = path.join(f.root, 'mutant-hooks');
      fs.mkdirSync(copy);
      fs.cpSync(path.join(hooks, 'lib'), path.join(copy, 'lib'), { recursive: true });
      const filename = path.join(hooks, 'block-secret-git.cjs');
      const source = fs.readFileSync(filename, 'utf8');
      const needle = "['diff', '--cached', '--name-only', ...(!ca.pathspecs.length && !ca.only ? ['--diff-filter=d'] : []), '-z']";
      const parts = source.split(needle);
      assert.equal(parts.length, 3, 'exactly two corrected staged reads');
      const old = "['diff', '--cached', '--name-only', '-z']";
      const changed = parts[0] + (at === 1 ? old : needle) + parts[1] + (at === 2 ? old : needle) + parts[2];
      assert.equal(changed.split(needle).length, 2, 'only one deletion filter is removed');
      fs.writeFileSync(path.join(copy, 'block-secret-git.cjs'), changed);
      const result = expectStagedSecret(f, '.env', { hooks: copy, probe: true });
      assert.equal(result.probes.length, at);
      assert.equal(result.probes.at(-1).output, '.env\0');
      assert.equal(result.probes.at(-1).args.includes('--diff-filter=d'), false);
      if (at === 2) assert.equal(result.probes[0].output, '');
      assert.match(result.reason, at === 1 ? /CLAUDE.md/ : /実行対象の commit/);
      evidence.push({ kind: 'reverse', at, originalSha256: sha256(source), mutantSha256: sha256(changed),
        regressionExpected: 'ALLOW', observed: result.verdict, reason: result.reason });
      const ordinary = fixture(t, { 'ordinary.txt': dummy });
      ordinary.git('rm', '--cached', '--', 'ordinary.txt');
      expect(ordinary, 'ALLOW', command, { hooks: copy });
      f.write('.env.local', 'DUMMY different\n');
      f.git('add', '--', '.env.local');
      expectStagedSecret(f, '.env.local', { hooks: copy });
      assert.equal(fs.readFileSync(filename, 'utf8'), source, 'selected source is never mutated');
    });
  }
}
