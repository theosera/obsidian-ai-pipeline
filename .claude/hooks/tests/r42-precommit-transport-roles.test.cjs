'use strict';

// Source/operation contracts and Hook-input DATA only. Proposed commands,
// callbacks, transport helpers and network operations are never executed.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');
const { spawnSync } = require('node:child_process');
const hooks = path.resolve(process.argv[2] || path.join(__dirname, '..'));
const readers = require(path.join(hooks, 'lib/git-precommit-readers.cjs'));
const guard = require(path.join(hooks, 'lib/git-guard-common.cjs'));
const baseline = { PATH: '/DUMMY/bin', HOME: '/DUMMY/home' };
const transports = ['GIT_SSH', 'GIT_SSH_COMMAND', 'GIT_SSH_VARIANT', 'GIT_ASKPASS'];

function selectedReader(command, environment = baseline) {
  const parsed = guard.inspect(command, { trackGitPreCommitEnvironment: true,
    initialGitPreCommitEnvironmentSources: readers.environmentSources(environment) });
  assert.deepEqual(parsed.problems, []);
  const g = parsed.gits.find(g => g.sub !== 'commit');
  assert.ok(g);
  const invocation = parsed.invocations.find(i => i.order === g.invocationOrder);
  const deps = { environment, executable: '/DUMMY/git', isTrusted: () => true,
    probe: () => new Map(), indexHook: () => false };
  return { g, invocation, deps };
}
function assess(command, environment) {
  const f = selectedReader(command, environment);
  return readers.assessReader(f.g, f.invocation, '/DUMMY/repo', f.deps);
}
function unknown(command, environment) {
  const decision = assess(command, environment);
  assert.equal(decision?.category, 'UNKNOWN');
  assert.match(decision.reason, /command-selected-transport/);
}

test('changed transport selections remain in actual context and receive their own reader gate', () => {
  for (const name of transports) {
    const command = `${name}=/DUMMY/selected git -P status; git commit -m x`;
    const f = selectedReader(command);
    const context = readers.readerContext(f.g, f.invocation, '/DUMMY/repo', f.deps);
    assert.ok(context);
    assert.equal(context.selected.get(name), '/DUMMY/selected');
    assert.equal(context.env[name], undefined); // inspection copy only
    unknown(command);
  }
});

test('prefix, env, exported and stored exported selections reach the same consumer', () => {
  for (const prefix of [
    'GIT_SSH_COMMAND=/DUMMY/selected ',
    'env GIT_SSH_COMMAND=/DUMMY/selected ',
    'export GIT_SSH_COMMAND=/DUMMY/selected; ',
    'GIT_SSH_COMMAND=/DUMMY/selected; export GIT_SSH_COMMAND; ',
    'transport=/DUMMY/selected; export GIT_SSH_COMMAND="$transport"; ',
  ]) unknown(`${prefix}git -P status; git commit -m x`);
  unknown('GIT_ASKPASS=/DUMMY/selected git -P cat-file -p HEAD:a.txt; git commit -m x');
});

test('unused locals, removed selections and earlier overrides retain normal controls', () => {
  assert.equal(assess('GIT_SSH_COMMAND=/DUMMY/unused; git -P status; git commit -m x'), null);
  assert.equal(assess('transport=/DUMMY/unused; git -P status; git commit -m x'), null);
  assert.equal(assess('export GIT_SSH_COMMAND=/DUMMY/unused; unset GIT_SSH_COMMAND; git -P status; git commit -m x'), null);
  assert.equal(assess('export GIT_SSH_COMMAND=/DUMMY/unused; env -u GIT_SSH_COMMAND git -P status; git commit -m x'), null);
});

test('inherited and explicit baseline-equal values do not acquire a new transport refusal', () => {
  for (const name of transports) {
    const inherited = { ...baseline, [name]: '/DUMMY/inherited' };
    assert.equal(assess('git -P status; git commit -m x', inherited), null);
    assert.equal(assess(`${name}=/DUMMY/inherited git -P status; git commit -m x`, inherited), null);
    unknown(`${name}=/DUMMY/different git -P status; git commit -m x`, inherited);
    assert.equal(assess(`unset ${name}; git -P status; git commit -m x`, inherited), null);
    assert.equal(assess(`env -u ${name} git -P status; git commit -m x`, inherited), null);
  }
  // These controls concern this new gate, not the safety of inherited helpers.
});

test('ordinary status, unused editor, genuine stdout query and config getter stay separate', () => {
  assert.equal(assess('git -P status; git commit -m x'), null);
  assert.equal(assess('GIT_EDITOR=/DUMMY/unused git -P status; git commit -m x'), null);
  assert.equal(assess('git -P status; git commit -m x', { ...baseline, GIT_EDITOR: 'DUMMY' }), null);
  assert.equal(assess('GIT_SSH_COMMAND=/DUMMY/unused git -P status -h; git commit -m x'), null);
  assert.equal(assess('GIT_SSH_COMMAND=/DUMMY/unused git -P --version; git commit -m x'), null);
  assert.equal(assess('GIT_SSH_COMMAND=/DUMMY/unused git -P config --get user.name; git commit -m x'), null);
});

test('own inspection forces no-lazy-fetch while actual selected and inherited zero remain data', () => {
  const inherited = { ...baseline, GIT_NO_LAZY_FETCH: '0' };
  const f = selectedReader('GIT_NO_LAZY_FETCH=0 git -P status; git commit -m x', inherited);
  const context = readers.readerContext(f.g, f.invocation, '/DUMMY/repo', f.deps);
  assert.equal(context.env.GIT_NO_LAZY_FETCH, '1');
  assert.equal(context.selected.get('GIT_NO_LAZY_FETCH'), '0');
  assert.equal(inherited.GIT_NO_LAZY_FETCH, '0');
  const selectedWord = f.invocation.gitPreCommitEnvironmentSources.find(v => v.name === 'GIT_NO_LAZY_FETCH').word;
  assert.equal(selectedWord.literalValue ?? selectedWord.text, '0');
  unknown('GIT_NO_LAZY_FETCH=0 GIT_SSH_COMMAND=/DUMMY/selected git -P status; git commit -m x', inherited);
  const calls = [];
  assert.ok(readers.probeConfig(context, (exe, args, options) => {
    calls.push({ args, env: options.env }); return { status: 1, stdout: '' };
  }));
  assert.equal(readers.indexHookSource(context, (exe, args, options) => {
    calls.push({ args, env: options.env }); return { status: 0, stdout: '/DUMMY/post-index-change\n' };
  }, () => { throw Object.assign(new Error('DUMMY absent'), { code: 'ENOENT' }); }), false);
  for (const call of calls) {
    assert.ok(call.args.includes('--no-lazy-fetch'));
    assert.equal(call.env.GIT_NO_LAZY_FETCH, '1');
  }
});

// VM spies replace the trusted backend; no backend/helper is run by these tests.
function inspectionSpy({ unsupported = false, banner = 'git version 2.54.0\n' } = {}) {
  const calls = [];
  const environment = { ...baseline, GIT_NO_LAZY_FETCH: '0' };
  const fakeFs = { ...fs, accessSync: () => {}, statSync: () => ({ isFile: () => true }), realpathSync: p => p };
  const child = { spawnSync: () => { throw new Error('unexpected native spawn'); }, execFileSync: (exe, args, options) => {
    calls.push({ exe, args: Array.from(args), env: { ...options.env } });
    if (args.includes('--version')) {
      if (unsupported) throw Object.assign(new Error('DUMMY unsupported --no-lazy-fetch'), { status: 129 });
      return banner;
    }
    return args.includes('config') ? '' : 'DUMMY inspection';
  } };
  const sandbox = { module: { exports: {} }, Buffer, process: { env: environment, cwd: () => '/DUMMY/repo', platform: process.platform },
    require: name => name === 'node:fs' ? fakeFs : name === 'node:child_process' ? child
      : name === './git-guard-common.cjs' ? { ...guard, trustedGitExecutable: () => true } : require(name) };
  vm.runInNewContext(fs.readFileSync(path.join(hooks, 'lib/git-precommit-readers.cjs'), 'utf8'), sandbox);
  return { readers: sandbox.module.exports, calls, environment };
}

test('own version capability, configured-hook probe and diff/ls-files all receive flag and environment', () => {
  const spy = inspectionSpy();
  assert.equal(spy.readers.readInspectionGit(['diff', '--cached', '--name-only', '-z'], { cwd: '/DUMMY/repo' }), 'DUMMY inspection');
  assert.equal(spy.readers.readInspectionGit(['ls-files', '-z'], { cwd: '/DUMMY/repo' }), 'DUMMY inspection');
  assert.deepEqual(spy.calls[0].args, ['--no-lazy-fetch', '--version']);
  assert.equal(spy.calls.filter(c => c.args.includes('--version')).length, 1);
  assert.ok(spy.calls.some(c => c.args.includes('config')));
  assert.ok(spy.calls.some(c => c.args.includes('diff')));
  assert.ok(spy.calls.some(c => c.args.includes('ls-files')));
  for (const call of spy.calls) {
    assert.ok(call.args.includes('--no-lazy-fetch'));
    assert.equal(call.env.GIT_NO_LAZY_FETCH, '1');
  }
  assert.equal(spy.environment.GIT_NO_LAZY_FETCH, '0');
});

test('unsupported capability stops before object/config reads; fsmonitor floor stays separate', () => {
  const unsupported = inspectionSpy({ unsupported: true });
  assert.throws(() => unsupported.readers.readInspectionGit(['diff', '--cached'], { cwd: '/DUMMY/repo' }), /unsupported/);
  assert.equal(unsupported.calls.length, 1);
  assert.deepEqual(unsupported.calls[0].args, ['--no-lazy-fetch', '--version']);
  const old = inspectionSpy({ banner: 'git version 2.35.1\n' });
  assert.throws(() => old.readers.readInspectionGit(['diff', '--cached'], { cwd: '/DUMMY/repo' }), /fsmonitor/);
  assert.equal(old.calls.length, 1);
  assert.equal(readers.supportsInspectionHardening('git version 2.39.5\n'), true); // fsmonitor predicate only
});

test('Hook DATA enforces selected transport only before a commit and preserves FORBIDDEN priority', t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'r42-reader-transport-'));
  try {
    const home = path.join(root, 'home'); const repo = path.join(root, 'repo');
    fs.mkdirSync(home); fs.mkdirSync(repo);
    const environment = { PATH: process.env.PATH, HOME: home, XDG_CONFIG_HOME: path.join(home, '.config'),
      GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_SYSTEM: '/dev/null',
      GIT_PAGER: 'cat', GIT_TERMINAL_PROMPT: '0', LC_ALL: 'C', CLAUDE_PROJECT_DIR: repo };
    const git = (...args) => {
      const r = spawnSync('git', args, { cwd: repo, env: environment, encoding: 'utf8', timeout: 20000 });
      assert.equal(r.error, undefined); assert.equal(r.status, 0, r.stderr);
    };
    git('init', '-q'); git('config', 'user.name', 'DUMMY'); git('config', 'user.email', 'dummy@example.invalid');
    fs.writeFileSync(path.join(repo, 'a.txt'), 'DUMMY\n'); git('add', '--', 'a.txt');
    git('-c', 'core.hooksPath=/dev/null', 'commit', '-q', '-m', 'DUMMY fixture');
    fs.writeFileSync(path.join(repo, 'a.txt'), 'DUMMY staged\n'); git('add', '--', 'a.txt');
    let actualHookCalls = 0;
    const run = (command, extra = {}) => {
      const r = spawnSync(process.execPath, [path.join(hooks, 'block-secret-git.cjs')], { cwd: repo,
        env: { ...environment, ...extra }, input: JSON.stringify({ tool_name: 'Bash', tool_input: { command }, cwd: repo }),
        encoding: 'utf8', timeout: 20000 });
      actualHookCalls++;
      assert.equal(r.error, undefined); assert.equal(r.status, 0, r.stderr);
      if (!r.stdout) return 'ALLOW';
      const result = JSON.parse(r.stdout).hookSpecificOutput;
      assert.equal(result.permissionDecision, 'deny');
      return result.permissionDecisionReason.startsWith('[禁止] ') ? 'FORBIDDEN'
        : result.permissionDecisionReason.startsWith('[判断不能] ') ? 'UNKNOWN' : 'BROKEN';
    };
    assert.equal(run('GIT_SSH_COMMAND=/DUMMY/selected git -P status; git commit -m x'), 'UNKNOWN');
    assert.equal(run('export GIT_SSH_COMMAND=/DUMMY/selected; git -P status; git commit -m x'), 'UNKNOWN');
    assert.equal(run('git -P status; git commit -m x'), 'ALLOW');
    assert.equal(run('GIT_SSH_COMMAND=/DUMMY/unused; git -P status; git commit -m x'), 'ALLOW');
    assert.equal(run('export GIT_SSH_COMMAND=/DUMMY/unused; env -u GIT_SSH_COMMAND git -P status; git commit -m x'), 'ALLOW');
    assert.equal(run('git -P status; git commit -m x', { GIT_EDITOR: 'DUMMY' }), 'ALLOW');
    assert.equal(run('git commit -m x; GIT_SSH_COMMAND=/DUMMY/unused git -P status'), 'ALLOW');
    assert.equal(run('GIT_SSH_COMMAND=/DUMMY/selected git -P status; git add .env; git commit -m x'), 'FORBIDDEN');
    assert.equal(run('git add .env; GIT_SSH_COMMAND=/DUMMY/selected git -P status; git commit -m x'), 'FORBIDDEN');
    t.diagnostic(`owned fixture: ${actualHookCalls} actual secret-git Hook calls; no proposed command executed`);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
