'use strict';

// obs#202: the secret-git guard bounds its own Git children per call and per
// decision. Children are owned sleepers and DUMMY repositories; no commit is
// proposed for real, no helper or network runs, and no hook file is changed.
// Normal:  node --test .claude/hooks/tests/git-inspection-timeouts.test.cjs
// Reverse: node .claude/hooks/tests/git-inspection-timeouts.test.cjs --reverse
//   drops timeout and killSignal where the guard starts a child, so every
//   bounded test must fail. --reverse-signal drops only killSignal, so the
//   tests whose child ignores SIGTERM must fail.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const Module = require('node:module');
const childProcess = require('node:child_process');
const hooks = path.join(__dirname, '..');
const commonFile = path.join(hooks, 'lib/git-guard-common.cjs');
const readerFile = path.join(hooks, 'lib/git-precommit-readers.cjs');
const guard = require(commonFile);
const readers = require(readerFile);
const reverse = process.argv.includes('--reverse') ? 'bounds'
  : process.argv.includes('--reverse-signal') ? 'signal' : null;
const installations = ['/opt/homebrew/bin/git', '/usr/local/bin/git', '/usr/bin/git', '/bin/git'];
const gitExe = installations.find(executable => guard.resolveTrustedGitExecutable({ text: executable }));
assert.ok(gitExe, 'a trusted Git installation is required; unexercised cases do not pass');

// A child that does not return within any bound; one that also ignores SIGTERM
// (exec keeps the ignored disposition and leaves no grandchild holding the
// pipe); one that is slow but finishes; and one that fails.
const STUCK = ['/bin/sleep', ['10']];
const TERM_IGNORING = ['/bin/sh', ['-c', 'trap "" TERM; exec /bin/sleep 10']];
const FAILING = ['/bin/sh', ['-c', 'exit 2']];
const slow = seconds => ['/bin/sleep', [String(seconds)]];
// Room for process start-up and the other, fast Git calls of one decision.
const SLACK_MS = 3000;
const STAGED = ['diff', '--cached', '--name-only', '-z'];

function withoutBounds(options) {
  if (!reverse) return options;
  const copy = { ...options };
  if (reverse === 'bounds') delete copy.timeout;
  delete copy.killSignal;
  return copy;
}
/** Start the planned child with the options the guard chose for its Git call. */
function runPlanned([program, args], options) {
  return childProcess.execFileSync(program, args,
    { ...withoutBounds(options), cwd: os.tmpdir(), stdio: ['ignore', 'pipe', 'ignore'] });
}
function timed(action) {
  const start = process.hrtime.bigint();
  let value;
  let error;
  try { value = action(); } catch (caught) { error = caught; }
  return { value, error, ms: Number(process.hrtime.bigint() - start) / 1e6 };
}

/** Recompile the readers with a substitute child_process; a plan names the slow stage. */
function mockedReaders(plans) {
  const calls = [];
  const compiled = new Module(readerFile, module);
  compiled.filename = readerFile;
  compiled.paths = Module._nodeModulePaths(path.dirname(readerFile));
  const originalRequire = compiled.require.bind(compiled);
  compiled.require = name => {
    if (name === './git-guard-common.cjs') return { ...guard, trustedGitExecutable: word => word.text === '/DUMMY/git' };
    if (name === 'node:child_process') return { ...childProcess, execFileSync(executable, args, options) {
      const stage = args.includes('--version') ? 'version' : args.includes('config') ? 'config' : 'read';
      calls.push({ stage, options });
      if (plans[stage]) runPlanned(plans[stage], options);
      if (stage === 'version') return 'git version 2.54.0\n';
      if (stage === 'config') throw Object.assign(new Error('DUMMY absent config'), { status: 1, stdout: '' });
      return '';
    } };
    return originalRequire(name);
  };
  compiled._compile(fs.readFileSync(readerFile, 'utf8'), readerFile);
  return { readers: compiled.exports, calls };
}
const inspection = extra => ({ executable: '/DUMMY/git', env: { HOME: '/DUMMY/home' }, cwd: os.tmpdir(), encoding: 'utf8', ...extra });

/** Recompile the shared library so that only the alias lookup starts the planned child. */
function mockedAlias(plan) {
  const calls = [];
  const compiled = new Module(commonFile, module);
  compiled.filename = commonFile;
  compiled.paths = Module._nodeModulePaths(path.dirname(commonFile));
  const originalRequire = compiled.require.bind(compiled);
  compiled.require = name => name !== 'node:child_process' ? originalRequire(name) : { ...childProcess,
    execFileSync(executable, args, options) {
      if (!args.some(arg => String(arg).startsWith('alias.'))) return childProcess.execFileSync(executable, args, options);
      calls.push({ args, options });
      if (plan) runPlanned(plan, options);
      throw Object.assign(new Error('DUMMY absent alias'), { status: 1 });
    } };
  compiled._compile(fs.readFileSync(commonFile, 'utf8'), commonFile);
  const aliasProblem = (g, options) => {
    const saved = process.env.PATH;
    process.env.PATH = [path.dirname(gitExe), '/usr/bin', '/bin'].join(path.delimiter);
    try { return compiled.exports.aliasProblem(g, os.tmpdir(), options); } finally { process.env.PATH = saved; }
  };
  return { aliasProblem, calls };
}
const dummyAlias = { sub: 'dummyalias', cdirs: [] };

test('a decision deadline gives each child the smaller of its cap and the time left', () => {
  let clock = 1000;
  const deadline = guard.createGitDeadline(8000, () => clock);
  assert.equal(deadline.remaining(4000), 4000);
  clock += 6000;
  assert.equal(deadline.remaining(4000), 2000);
  clock += 2000;
  assert.equal(deadline.remaining(4000), 0);
  clock += 5000;
  assert.equal(deadline.remaining(2000), 0);
});

test('without a deadline each inspection child still has a fixed cap and SIGKILL', () => {
  const { readers: mocked, calls } = mockedReaders({});
  assert.equal(mocked.readInspectionGit(STAGED, inspection()), '');
  assert.deepEqual(calls.map(call => [call.stage, call.options.timeout, call.options.killSignal]),
    [['version', 2000, 'SIGKILL'], ['config', 2000, 'SIGKILL'], ['read', 4000, 'SIGKILL']]);
  assert.equal('deadline' in calls[2].options, false);
});

test("the readers' fixed-cap probes end their children with SIGKILL", () => {
  const seen = [];
  const spawn = (executable, args, options) => { seen.push(options); return { status: 1, stdout: Buffer.alloc(0) }; };
  const context = { executable: '/DUMMY/git', globals: [], cwd: os.tmpdir(), env: {} };
  readers.probeConfig(context, spawn);
  if (process.platform !== 'win32') readers.indexHookSource(context, spawn);
  assert.ok(seen.length >= 1);
  for (const options of seen) {
    assert.equal(options.timeout, 2000);
    assert.equal(options.killSignal, 'SIGKILL');
  }
});

for (const stage of ['version', 'config', 'read']) {
  test(`a ${stage} child that does not return ends within the decision deadline`, () => {
    const { readers: mocked, calls } = mockedReaders({ [stage]: STUCK });
    const result = timed(() => mocked.readInspectionGit(STAGED, inspection({ deadline: guard.createGitDeadline(600) })));
    assert.equal(result.error?.code, 'ETIMEDOUT', String(result.error));
    assert.ok(result.ms < 600 + SLACK_MS, result.ms + ' ms');
    const call = calls.find(entry => entry.stage === stage);
    assert.ok(call.options.timeout > 0 && call.options.timeout <= 600, String(call.options.timeout));
  });
}

test('a read child that ignores SIGTERM still ends within the decision deadline', () => {
  const { readers: mocked } = mockedReaders({ read: TERM_IGNORING });
  const result = timed(() => mocked.readInspectionGit(STAGED, inspection({ deadline: guard.createGitDeadline(600) })));
  assert.equal(result.error?.code, 'ETIMEDOUT', String(result.error));
  assert.ok(result.ms < 600 + SLACK_MS, result.ms + ' ms');
});

test('slow calls in turn share one deadline, and an exhausted deadline starts no child', () => {
  const { readers: mocked, calls } = mockedReaders({ version: slow(0.4), config: slow(0.4), read: slow(0.4) });
  const deadline = guard.createGitDeadline(1000);
  const first = timed(() => mocked.readInspectionGit(STAGED, inspection({ deadline })));
  assert.equal(first.error?.code, 'ETIMEDOUT', String(first.error));
  assert.ok(first.ms < 1000 + SLACK_MS, first.ms + ' ms');
  const started = calls.length;
  const second = timed(() => mocked.readInspectionGit(STAGED, inspection({ deadline })));
  assert.equal(second.error?.code, 'ETIMEDOUT', String(second.error));
  assert.equal(calls.length, started, 'no child starts after the deadline');
});

test('a failing inspection child is still a failure, not a timeout', () => {
  const { readers: mocked } = mockedReaders({ read: FAILING });
  const result = timed(() => mocked.readInspectionGit(STAGED, inspection({ deadline: guard.createGitDeadline(8000) })));
  assert.equal(result.error?.status, 2, String(result.error));
  assert.notEqual(result.error?.code, 'ETIMEDOUT');
});

test('an alias lookup that does not return ends within the decision deadline', () => {
  const { aliasProblem, calls } = mockedAlias(STUCK);
  const result = timed(() => aliasProblem(dummyAlias, { deadline: guard.createGitDeadline(600) }));
  assert.ifError(result.error);
  assert.match(result.value, /時間内に終わらなかった/);
  assert.ok(result.ms < 600 + SLACK_MS, result.ms + ' ms');
  assert.ok(calls[0].options.timeout > 0 && calls[0].options.timeout <= 600, String(calls[0].options.timeout));
  assert.equal(calls[0].options.killSignal, 'SIGKILL');
});

test('an alias lookup child that ignores SIGTERM still ends within the decision deadline', () => {
  const { aliasProblem } = mockedAlias(TERM_IGNORING);
  const result = timed(() => aliasProblem(dummyAlias, { deadline: guard.createGitDeadline(600) }));
  assert.ifError(result.error);
  assert.match(result.value, /時間内に終わらなかった/);
  assert.ok(result.ms < 600 + SLACK_MS, result.ms + ' ms');
});

test('an exhausted deadline answers the alias lookup without starting a child', () => {
  const { aliasProblem, calls } = mockedAlias(STUCK);
  assert.match(aliasProblem(dummyAlias, { deadline: guard.createGitDeadline(0) }), /時間内に終わらなかった/);
  assert.equal(calls.length, 0);
});

test('an absent alias still passes and a failing lookup still stops, with a fixed cap', () => {
  const absent = mockedAlias(null);
  assert.equal(absent.aliasProblem(dummyAlias), null);
  assert.equal(absent.calls[0].options.timeout, 2000);
  assert.equal(absent.calls[0].options.killSignal, 'SIGKILL');
  const failing = mockedAlias(FAILING);
  assert.match(failing.aliasProblem(dummyAlias), /確かめられない/);
  assert.doesNotMatch(failing.aliasProblem(dummyAlias), /時間内/);
});

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'obs202-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const repo = path.join(root, 'repo');
  const home = path.join(root, 'home');
  const template = path.join(root, 'empty-template');
  for (const dir of [repo, home, template]) fs.mkdirSync(dir);
  const env = { PATH: [path.dirname(gitExe), '/usr/bin', '/bin'].join(path.delimiter), HOME: home,
    GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: os.devNull, GIT_CONFIG_SYSTEM: os.devNull,
    GIT_TERMINAL_PROMPT: '0', LC_ALL: 'C' };
  const git = (...args) => {
    const result = childProcess.spawnSync(gitExe, args, { cwd: repo, env, encoding: 'utf8', timeout: 10000 });
    assert.equal(result.status, 0, JSON.stringify(args) + '\n' + result.stderr);
    return result.stdout;
  };
  git('init', '-q', '--template=' + template);
  git('config', 'user.name', 'DUMMY fixture');
  git('config', 'user.email', 'fixture@example.invalid');
  assert.ok(readers.supportsInspectionHardening(git('--no-lazy-fetch', '--version')), 'actual inspection capability is required');
  fs.writeFileSync(path.join(repo, 'ordinary.txt'), 'DUMMY ordinary\n');
  git('add', '--', 'ordinary.txt');
  git('commit', '-q', '-m', 'DUMMY-seed');
  return { root, repo, env };
}

let preloads = 0;
/**
 * Run the real hook. The preload only puts a planned child in front of the
 * matching guard Git calls, with the options the guard passed; the Git call
 * itself still runs when that child returns.
 */
function runHook(f, command, plan = null) {
  const args = [];
  const trace = path.join(f.root, 'trace-' + preloads + '.jsonl');
  if (plan) {
    const preload = path.join(f.root, 'preload-' + preloads + '.cjs');
    fs.writeFileSync(preload, `'use strict';
const cp = require('node:child_process');
const fs = require('node:fs');
const original = cp.execFileSync;
const plan = ${JSON.stringify(plan)};
const reverse = ${JSON.stringify(reverse)};
const seen = {};
const stage = args => args.includes('--version') ? 'version'
  : args.some(arg => String(arg).startsWith('alias.')) ? 'alias'
  : args.includes('config') ? 'config' : args.includes('ls-files') ? 'ls-files'
  : args.includes('diff') ? 'diff' : 'other';
cp.execFileSync = (executable, args, options) => {
  const name = stage(args);
  seen[name] = (seen[name] || 0) + 1;
  fs.appendFileSync(${JSON.stringify(trace)}, JSON.stringify({ name, at: seen[name],
    timeout: options && options.timeout, killSignal: options && options.killSignal }) + '\\n');
  if (plan.stages.includes(name) && (!plan.at || plan.at === seen[name])) {
    const bounded = { ...options, cwd: ${JSON.stringify(os.tmpdir())}, stdio: ['ignore', 'pipe', 'ignore'] };
    if (reverse) { if (reverse === 'bounds') delete bounded.timeout; delete bounded.killSignal; }
    original(plan.child[0], plan.child[1], bounded);
  }
  return original(executable, args, options);
};
`);
    args.push('--require', preload);
  }
  preloads++;
  args.push(path.join(hooks, 'block-secret-git.cjs'));
  const start = process.hrtime.bigint();
  const result = childProcess.spawnSync(process.execPath, args, {
    cwd: f.repo, env: { ...f.env, CLAUDE_PROJECT_DIR: f.repo }, encoding: 'utf8', timeout: 30000,
    input: JSON.stringify({ tool_name: 'Bash', tool_input: { command }, cwd: f.repo }) });
  const ms = Number(process.hrtime.bigint() - start) / 1e6;
  // The hook itself must answer: not this test's spawn timeout, a signal or a crash.
  assert.ifError(result.error);
  assert.equal(result.signal, null);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, '');
  const calls = fs.existsSync(trace)
    ? fs.readFileSync(trace, 'utf8').trim().split('\n').filter(Boolean).map(line => JSON.parse(line)) : [];
  if (!result.stdout) return { verdict: 'ALLOW', reason: '', ms, calls };
  const wire = JSON.parse(result.stdout).hookSpecificOutput;
  assert.equal(wire.permissionDecision, 'deny');
  const reason = wire.permissionDecisionReason;
  const verdict = reason.startsWith('[禁止] ') ? 'FORBIDDEN' : reason.startsWith('[判断不能] ') ? 'UNKNOWN' : 'BROKEN';
  return { verdict, reason, ms, calls };
}

for (const [name, command, plan, child, cap, message] of [
  ['the first staged read does not return', 'git commit -m DUMMY', { stages: ['diff'], at: 1 }, STUCK, 4000,
    /staged ファイルの検査に失敗しました（時間内に終わりませんでした）/],
  ['the first staged read ignores SIGTERM', 'git commit -m DUMMY', { stages: ['diff'], at: 1 }, TERM_IGNORING, 4000,
    /staged ファイルの検査に失敗しました（時間内に終わりませんでした）/],
  ['the pathspec read does not return', 'git commit -m DUMMY -- ordinary.txt', { stages: ['ls-files'], at: 1 }, STUCK, 4000,
    /pathspec が当たるファイルの検査に失敗しました（時間内に終わりませんでした）/],
  ['the second staged read does not return', 'git commit -m DUMMY', { stages: ['diff'], at: 2 }, STUCK, 4000,
    /staged ファイルの検査に失敗しました（時間内に終わりませんでした）/],
  ['the alias lookup does not return', 'git gitk', { stages: ['alias'] }, STUCK, 2000,
    /alias かどうかを確かめられない（時間内に終わらなかった/],
]) {
  test(`the hook itself denies when ${name}`, t => {
    const result = runHook(fixture(t), command, { ...plan, child });
    assert.equal(result.verdict, 'UNKNOWN', result.reason);
    assert.match(result.reason, message);
    assert.ok(result.ms < cap + SLACK_MS, result.ms + ' ms');
    const hit = result.calls.find(call => call.name === plan.stages[0] && (!plan.at || call.at === plan.at));
    assert.ok(hit, JSON.stringify(result.calls));
    assert.equal(hit.killSignal, 'SIGKILL');
  });
}

test('slow Git calls in turn still end in a deny within the decision deadline', t => {
  const result = runHook(fixture(t), 'git commit -m DUMMY -- ordinary.txt',
    { stages: ['version', 'config', 'diff', 'ls-files'], child: slow(1.9) });
  assert.equal(result.verdict, 'UNKNOWN', result.reason);
  assert.match(result.reason, /時間内に終わりませんでした/);
  assert.ok(result.ms < 8000 + SLACK_MS, result.ms + ' ms');
});

test('a normal Git still allows the same commands', t => {
  const f = fixture(t);
  for (const command of ['git commit -m DUMMY', 'git commit -m DUMMY -- ordinary.txt', 'git gitk']) {
    const result = runHook(f, command);
    assert.equal(result.verdict, 'ALLOW', command + ': ' + result.reason);
  }
});

test('a failing Git read still denies with the failure message', t => {
  const result = runHook(fixture(t), 'git commit -m DUMMY', { stages: ['diff'], at: 1, child: FAILING });
  assert.equal(result.verdict, 'UNKNOWN', result.reason);
  assert.match(result.reason, /staged ファイルの検査に失敗しました \(対象: /);
  assert.doesNotMatch(result.reason, /時間内/);
});
