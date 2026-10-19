'use strict';

// Proposed commits are Hook stdin DATA only. Native Git only creates owned
// DUMMY indexes and reads staged names; no commit, helper or network runs.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const Module = require('node:module');
const { spawnSync } = require('node:child_process');
const hooks = path.resolve(process.argv[2] || path.join(__dirname, '..'));
const guard = require(path.join(hooks, 'lib/git-guard-common.cjs'));
const readerFile = path.join(hooks, 'lib/git-precommit-readers.cjs');
const readers = require(readerFile);

function inspectionCapability(executable, cwd, environment, runner = spawnSync) {
  const env = readers.safeInspectionEnvironment(environment);
  if (!env) return { available: false, status: null, banner: '', errorCode: 'UNPROVED_ENVIRONMENT' };
  const result = runner(executable, ['--no-lazy-fetch', '--version'], {
    cwd, env: { ...env, GIT_OPTIONAL_LOCKS: '0' }, encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'], timeout: 20000,
  });
  const banner = typeof result.stdout === 'string' ? result.stdout.trim() : '';
  return { available: !result.error && result.status === 0 && readers.supportsInspectionHardening(banner),
    status: result.status, banner, errorCode: result.error?.code || null };
}

test('native index expectations require the option query, not a successful plain version banner', () => {
  for (const [result, available] of [
    [{ status: 0, stdout: 'git version 2.54.0\n' }, true],
    [{ status: 129, stdout: '', stderr: 'unknown option: --no-lazy-fetch' }, false],
    [{ status: 0, stdout: 'git version 2.35.1\n' }, false],
    [{ status: 0, stdout: 'DUMMY unsupported banner\n' }, false],
    [{ status: null, stdout: '', error: { code: 'ENOENT' } }, false],
  ]) {
    const calls = [];
    const capability = inspectionCapability('/DUMMY/git', '/DUMMY/repo', {}, (exe, args, options) => {
      calls.push({ exe, args, options }); return result;
    });
    assert.equal(capability.available, available);
    assert.equal(calls.length, 1);
    assert.deepEqual(calls[0].args, ['--no-lazy-fetch', '--version']);
    assert.equal(calls[0].options.env.GIT_NO_LAZY_FETCH, '1');
    assert.equal(calls[0].options.env.GIT_OPTIONAL_LOCKS, '0');
  }
  assert.equal(readers.supportsInspectionHardening('git version 2.43.0'), true,
    'Git 2.43 meets this separate floor but may still reject the option');
});

function mockedInspection(baseline) {
  const calls = [];
  const compiled = new Module(readerFile, module);
  compiled.filename = readerFile;
  compiled.paths = Module._nodeModulePaths(path.dirname(readerFile));
  const originalRequire = compiled.require.bind(compiled);
  compiled.require = name => {
    if (name === './git-guard-common.cjs') return { ...guard,
      trustedGitExecutable: word => /^\/DUMMY\/git[AB]$/.test(word.text) };
    if (name === 'node:child_process') return { execFileSync(executable, args, options) {
      calls.push({ executable, args, options });
      if (args.includes('--version')) return 'git version 2.54.0\n';
      if (args.includes('config')) throw Object.assign(new Error('DUMMY absent config'), { status: 1, stdout: '' });
      return '';
    } };
    return originalRequire(name);
  };
  const processFixture = baseline ? 'const process = { ...require("node:process"), env: ' + JSON.stringify(baseline) + ' };\n' : '';
  compiled._compile(processFixture + fs.readFileSync(readerFile, 'utf8'), readerFile);
  return { readers: compiled.exports, calls };
}

test('inspection rejects a missing or unproved explicit context before any program runs', () => {
  const { readers, calls } = mockedInspection();
  const args = ['diff', '--cached', '--name-only', '-z'];
  assert.throws(() => readers.readInspectionGit(args), /trusted inspection Git unavailable/);
  assert.throws(() => readers.readInspectionGit(args, { executable: '/DUMMY/gitA', cwd: '/DUMMY/repo' }), /environment/);
  for (const cwd of [undefined, 'relative', '/DUMMY/\0repo']) {
    assert.throws(() => readers.readInspectionGit(args, { executable: '/DUMMY/gitA', env: {}, cwd }), /cwd/);
  }
  assert.equal(calls.length, 0);
});

test('version and hook-config qualification are cached by program, environment and cwd', () => {
  const { readers, calls } = mockedInspection();
  const read = context => readers.readInspectionGit(['diff', '--cached', '--name-only', '-z'], context);
  const first = { executable: '/DUMMY/gitA', env: { HOME: '/DUMMY/home', GIT_INDEX_FILE: '/DUMMY/indexA' }, cwd: '/DUMMY/repoA' };
  read(first);
  read({ ...first, env: { GIT_INDEX_FILE: '/DUMMY/indexA', HOME: '/DUMMY/home' } });
  read({ ...first, executable: '/DUMMY/gitB' });
  read({ ...first, env: { ...first.env, GIT_INDEX_FILE: '/DUMMY/indexB' } });
  read({ ...first, cwd: '/DUMMY/repoB' });
  assert.equal(calls.filter(call => call.args.includes('--version')).length, 4);
  assert.equal(calls.filter(call => call.args.includes('config')).length, 4);
  assert.equal(calls.filter(call => call.args.includes('diff')).length, 5);
  for (const call of calls) {
    assert.equal(call.options.env.GIT_NO_LAZY_FETCH, '1');
    assert.equal(call.options.env.GIT_OPTIONAL_LOCKS, '0');
    assert.ok(call.args.includes('--no-lazy-fetch'));
    assert.ok(path.isAbsolute(call.options.cwd));
  }
});

test('env-i removes inherited targets in the snapshot behind the existing root-source refusal', () => {
  const installations = process.platform === 'win32'
    ? ['C:\\Program Files\\Git\\cmd\\git.exe', 'C:\\Program Files\\Git\\bin\\git.exe']
    : ['/usr/bin/git', '/bin/git', '/usr/local/bin/git', '/opt/homebrew/bin/git'];
  const absoluteGit = installations.find(executable => guard.resolveTrustedGitExecutable({ text: executable }));
  assert.ok(absoluteGit);
  const baseline = { HOME: '/DUMMY/home', PATH: '/DUMMY/bin',
    GIT_INDEX_FILE: '/DUMMY/inherited-index', GIT_DIR: '/DUMMY/inherited-repo' };
  const { readers, calls } = mockedInspection(baseline);
  const parsed = guard.inspect('env -i HOME=/DUMMY/home GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null ' +
    absoluteGit + ' commit -m x', { trackGitPreCommitEnvironment: true,
    initialGitPreCommitEnvironmentSources: readers.environmentSources(baseline) });
  assert.ok(parsed.problems.some(problem => /HOME \/ XDG_CONFIG_HOME/.test(problem)), 'existing early refusal is retained');
  const invocation = parsed.invocations.find(invocation => invocation.name === 'git');
  assert.ok(invocation);
  const names = invocation.gitPreCommitEnvironmentSources.map(source => source.name);
  assert.equal(names.includes('GIT_INDEX_FILE'), false);
  assert.equal(names.includes('GIT_DIR'), false);
  // The early refusal intentionally has no accepted commit g. This DTO checks
  // only the selected snapshot's reconstruction, not native env-i acceptance.
  const context = readers.commitInspectionContext({ cdirs: [] }, invocation, '/DUMMY/repo');
  assert.ok(context);
  assert.equal(Object.hasOwn(context.env, 'GIT_INDEX_FILE'), false);
  assert.equal(Object.hasOwn(context.env, 'GIT_DIR'), false);
  assert.equal(context.env.HOME, '/DUMMY/home');
  assert.equal(calls.length, 0);
});

function indexSnapshot(prefix, options = {}) {
  const installations = process.platform === 'win32'
    ? ['C:\\Program Files\\Git\\cmd\\git.exe', 'C:\\Program Files\\Git\\bin\\git.exe']
    : ['/usr/bin/git', '/bin/git', '/usr/local/bin/git', '/opt/homebrew/bin/git'];
  const executable = installations.find(candidate => guard.resolveTrustedGitExecutable({ text: candidate }));
  assert.ok(executable);
  const baseline = { HOME: '/DUMMY/home', PATH: path.dirname(executable),
    GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_SYSTEM: '/dev/null', GIT_CONFIG_NOSYSTEM: '1',
    GIT_AUTHOR_NAME: 'DUMMY author', GIT_AUTHOR_EMAIL: 'author@example.invalid', GIT_AUTHOR_DATE: 'DUMMY date',
    GIT_COMMITTER_NAME: 'DUMMY committer', GIT_COMMITTER_EMAIL: 'committer@example.invalid', GIT_COMMITTER_DATE: 'DUMMY date',
    ...options.baseline };
  const { readers, calls } = mockedInspection(baseline);
  const sources = readers.environmentSources(baseline).filter(source =>
    options.wide || guard.gitIndexInspectionEnvironmentName(source.name));
  const parsed = guard.inspect(prefix + executable + ' commit -m ordinary', {
    trackGitPreCommitEnvironment: true, trackGitIndexInspectionEnvironment: !options.wide,
    initialGitPreCommitEnvironmentSources: sources,
  });
  const invocation = parsed.invocations.findLast(invocation => invocation.name === 'git');
  assert.ok(invocation);
  const g = parsed.gits.findLast(g => g.sub === 'commit') || { cdirs: [] };
  const context = readers.commitInspectionContext(g, invocation, '/DUMMY/repo');
  assert.equal(calls.length, 0);
  return { parsed, invocation, context, sources: new Map(invocation.gitPreCommitEnvironmentSources.map(source => [source.name, source.word])) };
}

test('index projection omits all six author/committer values while wide reader tracking retains them', () => {
  const index = indexSnapshot('GIT_AUTHOR_NAME="$VALUE" ');
  assert.deepEqual(index.parsed.problems, []);
  assert.ok(index.context);
  for (const kind of ['AUTHOR', 'COMMITTER']) for (const suffix of ['NAME', 'EMAIL', 'DATE']) {
    const name = 'GIT_' + kind + '_' + suffix;
    assert.equal(guard.gitPreCommitEnvironmentName(name), true);
    assert.equal(guard.gitIndexInspectionEnvironmentName(name), false);
    assert.equal(index.sources.has(name), false);
    assert.equal(Object.hasOwn(index.context.env, name), false);
    assert.equal(indexSnapshot('', { wide: true }).sources.has(name), true);
  }
  for (const name of ['GIT_INDEX_FILE', 'GIT_DIR', 'GIT_CONFIG_GLOBAL', 'PATH', 'HOME']) {
    assert.equal(guard.gitIndexInspectionEnvironmentName(name), true);
  }
});

test('unused and static identity-only namerefs preserve index sources without relaxing the wide pass', () => {
  for (const prefix of ['declare -n ref=ordinary; ',
    'declare -n ref=GIT_AUTHOR_NAME; ref="$(cat .env)"; ',
    'declare -n ref=GIT_AUTHOR_NAME; ref="$(cat .env)"; GIT_AUTHOR_NAME=ordinary ']) {
    const index = indexSnapshot(prefix);
    assert.deepEqual(index.parsed.problems, []);
    assert.equal(index.invocation.gitPreCommitEnvironmentUnknown, false);
    assert.ok(index.sources.get('PATH'));
    assert.ok(index.context);
    assert.equal(Object.hasOwn(index.context.env, 'GIT_AUTHOR_NAME'), false);
  }
  const wide = indexSnapshot('declare -n ref=ordinary; ', { wide: true });
  assert.equal(wide.sources.has('GIT_AUTHOR_NAME'), true);
  assert.equal(wide.sources.get('PATH'), null, 'existing wide uncertainty remains');
  assert.equal(wide.context, null);
});

test('a static critical nameref name or target stays unknown even when the source was absent', () => {
  for (const name of ['GIT_INDEX_FILE', 'GIT_DIR', 'GIT_CONFIG_GLOBAL', 'PATH', 'HOME']) {
    for (const declaration of ['declare -n ref=' + name, 'declare -n ' + name + '=ordinary']) {
      const selected = indexSnapshot(declaration + '; ');
      assert.equal(selected.sources.has(name), true, declaration);
      assert.equal(selected.sources.get(name), null, declaration);
      assert.equal(selected.context, null, declaration);
    }
  }
  for (const declaration of ['declare -n -- ref=GIT_INDEX_FILE',
    'declare -n ref=GIT_INDEX_FILE; declare -n link=ref; link=/DUMMY/index',
    'declare -n ref=ordinary; declare -n ordinary=GIT_DIR; ref=/DUMMY/repo']) {
    assert.equal(indexSnapshot(declaration + '; ').context, null, declaration);
  }
});

test('dynamic, unassigned and unsupported nameref uncertainty is sticky across partial replacements', () => {
  for (const declaration of ['declare -n ref="$TARGET"', 'declare -n ref',
    "declare -n ref='GIT_INDEX_FILE[0]'", 'declare -n "$NAME=ordinary"', 'declare -n ref=ordinary other']) {
    for (const replacement of ['',
      'export PATH=/usr/bin HOME=/DUMMY/home GIT_INDEX_FILE=/DUMMY/index; ',
      'unset ref; ', "printf '%s' 'env -i'; ", 'env -u GIT_INDEX_FILE ']) {
      const selected = indexSnapshot(declaration + '; ' + replacement);
      assert.equal(selected.invocation.gitPreCommitEnvironmentUnknown, true, declaration + '; ' + replacement);
      assert.equal(selected.context, null, declaration + '; ' + replacement);
    }
  }
});

test('only actual env-i clears sticky index-source uncertainty and retains the existing root refusal', () => {
  const selected = indexSnapshot('declare -n ref="$TARGET"; env -i HOME=/DUMMY/home GIT_CONFIG_GLOBAL=/dev/null ');
  assert.equal(selected.invocation.gitPreCommitEnvironmentUnknown, false);
  assert.ok(selected.parsed.problems.some(problem => /HOME \/ XDG_CONFIG_HOME/.test(problem)));
  assert.equal(selected.sources.has('GIT_INDEX_FILE'), false);
  assert.equal(selected.sources.has('GIT_DIR'), false);
  assert.equal(selected.context.env.HOME, '/DUMMY/home');
});

test('index-irrelevant nameref declarations still taint prior scalar value proofs', () => {
  const selected = indexSnapshot('chosen=/DUMMY/index; declare -n ref=ordinary; GIT_INDEX_FILE="$chosen" ');
  assert.equal(selected.invocation.gitPreCommitEnvironmentUnknown, false);
  assert.equal(selected.context, null, 'tainted saved value must not prove the index selection');
});

let owned;
let actualHookCalls = 0;
const inspectionCapabilities = new Map();
function inspectionReady(t, f, executables) {
  for (const executable of new Set(executables)) {
    if (!inspectionCapabilities.has(executable)) {
      inspectionCapabilities.set(executable, inspectionCapability(executable, f.repos.secret, f.base));
    }
    const capability = inspectionCapabilities.get(executable);
    t.diagnostic(`owned fixture inspection ${JSON.stringify(executable)}: ${JSON.stringify(capability)}`);
    if (!capability.available) {
      t.skip('native inspection unavailable: --no-lazy-fetch capability or fsmonitor floor');
      return false;
    }
  }
  return true;
}
function fixtures() {
  if (owned) return owned;
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'r46-inspection-context-'));
  const home = path.join(root, 'home');
  const fakeBin = path.join(root, 'fake-bin');
  fs.mkdirSync(home); fs.mkdirSync(fakeBin);
  const installations = process.platform === 'win32'
    ? ['C:\\Program Files\\Git\\cmd\\git.exe', 'C:\\Program Files\\Git\\bin\\git.exe']
    : ['/opt/homebrew/bin/git', '/usr/local/bin/git', '/usr/bin/git', '/bin/git'];
  const setupGit = installations.find(executable => guard.resolveTrustedGitExecutable({ text: executable }));
  assert.ok(setupGit, 'owned fixture requires a known Git installation');
  const absoluteGit = fs.existsSync('/usr/bin/git') ? '/usr/bin/git' : setupGit;
  const realGit = fs.realpathSync(setupGit);
  const base = { PATH: [path.dirname(realGit), '/usr/bin', '/bin'].join(path.delimiter), HOME: home,
    GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_SYSTEM: '/dev/null',
    GIT_OPTIONAL_LOCKS: '0', GIT_TERMINAL_PROMPT: '0', GIT_PAGER: 'cat', LC_ALL: 'C' };
  const git = (cwd, args, extra = {}) => {
    const result = spawnSync(setupGit, ['-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null', ...args],
      { cwd, env: { ...base, ...extra }, encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    return result.stdout;
  };
  const repos = {};
  for (const [name, filename] of [['secret', '.env'], ['ordinary', 'a.txt']]) {
    const repo = path.join(root, name); fs.mkdirSync(repo); repos[name] = repo;
    git(root, ['init', '-q', repo]);
    fs.writeFileSync(path.join(repo, filename), 'DUMMY fixture contents only\n');
    git(repo, ['add', '--', filename]);
  }
  const alternateIndex = path.join(root, 'empty-index');
  git(repos.secret, ['read-tree', '--empty'], { GIT_INDEX_FILE: alternateIndex });
  const marker = path.join(root, 'fake-git-invocations');
  const fakeGit = path.join(fakeBin, process.platform === 'win32' ? 'git.exe' : 'git');
  fs.writeFileSync(fakeGit, '#!' + process.execPath + '\n' +
    "require('node:fs').appendFileSync(" + JSON.stringify(marker) + ", 'DUMMY inspection\\n');\n" +
    "if (process.argv.includes('--version')) process.stdout.write('git version 2.54.0\\n');\n" +
    "process.exit(process.argv.includes('config') ? 1 : 0);\n", { mode: 0o700 });
  owned = { root, home, fakeBin, fakeGit, marker, setupGit, absoluteGit, base, repos, alternateIndex, git };
  return owned;
}
function run(command, repoName = 'secret', extra = {}) {
  const f = fixtures();
  const cwd = f.repos[repoName];
  actualHookCalls++;
  const result = spawnSync(process.execPath, [path.join(hooks, 'block-secret-git.cjs')], {
    cwd, env: { ...f.base, ...extra, CLAUDE_PROJECT_DIR: cwd }, encoding: 'utf8',
    input: JSON.stringify({ tool_name: 'Bash', tool_input: { command }, cwd }),
  });
  return observeHookResult(result);
}
function observeHookResult(result) {
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, '');
  if (!result.stdout) return { verdict: 'ALLOW', reason: '' };
  const output = JSON.parse(result.stdout).hookSpecificOutput;
  assert.equal(output.permissionDecision, 'deny');
  const reason = output.permissionDecisionReason;
  return { verdict: typeof reason !== 'string' ? 'BROKEN'
    : reason.startsWith('[禁止] ') ? 'FORBIDDEN'
    : reason.startsWith('[判断不能] ') ? 'UNKNOWN' : 'BROKEN', reason };
}
function expect(command, expected, repoName, extra) {
  const result = run(command, repoName, extra);
  assert.equal(result.verdict, expected, command + '\n' + result.reason);
  if (expected === 'FORBIDDEN') assert.match(result.reason, /staged.*\.env/);
  return result;
}
test.after(() => {
  const fakeCalls = owned && fs.existsSync(owned.marker)
    ? fs.readFileSync(owned.marker, 'utf8').trim().split('\n').length : 0;
  if (owned) fs.rmSync(owned.root, { recursive: true, force: true });
  console.log('r46 owned Hook DATA calls: ' + actualHookCalls + '; fake Git invocations: ' + fakeCalls + '; proposed commits: 0');
});

test('malformed deny wire cannot satisfy an UNKNOWN inspection expectation', () => {
  const observe = reason => observeHookResult({ status: 0, stderr: '', stdout: JSON.stringify({
    hookSpecificOutput: { permissionDecision: 'deny', permissionDecisionReason: reason },
  }) });
  for (const reason of ['DUMMY unexpected prefix', '', '[判断不能]DUMMY', '[禁止]DUMMY', null, 42, {}, undefined]) {
    assert.deepEqual(observe(reason), { verdict: 'BROKEN', reason });
  }
  for (const [reason, verdict] of [['[禁止] DUMMY staged .env', 'FORBIDDEN'], ['[判断不能] DUMMY context', 'UNKNOWN']]) {
    assert.deepEqual(observe(reason), { verdict, reason });
  }
  assert.deepEqual(observeHookResult({ status: 0, stderr: '', stdout: '' }), { verdict: 'ALLOW', reason: '' });
});

test('known installations resolve independently while an unknown first PATH candidate is never trusted', () => {
  const f = fixtures();
  const shadow = { PATH: f.fakeBin + path.delimiter + f.base.PATH };
  assert.equal(guard.resolveTrustedGitExecutable({ text: 'git' }, shadow, f.repos.secret), null);
  assert.equal(guard.resolveTrustedGitExecutable({ text: f.fakeGit }, shadow, f.repos.secret), null);
  assert.equal(guard.resolveTrustedGitExecutable({ text: f.absoluteGit }, shadow, f.repos.secret), fs.realpathSync(f.absoluteGit));
  assert.equal(guard.resolveTrustedGitExecutable({ text: 'git' }, f.base, f.repos.secret), fs.realpathSync(f.setupGit));
  assert.equal(fs.existsSync(f.marker), false);
});

test('own SG reads the absolute Git index despite shadow PATH and refuses unknown programs without starting them', t => {
  const f = fixtures();
  if (!inspectionReady(t, f, [f.absoluteGit, f.setupGit])) return;
  const shadow = { PATH: f.fakeBin + path.delimiter + f.base.PATH };
  expect(f.absoluteGit + ' commit -m x', 'FORBIDDEN', 'secret', shadow);
  expect(f.absoluteGit + ' commit -m x', 'ALLOW', 'ordinary', shadow);
  expect('git commit -m x', 'UNKNOWN', 'secret', shadow);
  expect(f.fakeGit + ' commit -m x', 'UNKNOWN', 'secret', shadow);
  expect('command -p git commit -m x', 'UNKNOWN');
  expect('git commit -m x', 'FORBIDDEN');
  expect('git commit -m x', 'ALLOW', 'ordinary');
  assert.equal(fs.existsSync(f.marker), false, 'inspection must not launch the owned fake Git');
});

test('own SG preserves actual index and repository removals, env-i and unchanged inherited targets', t => {
  const f = fixtures();
  if (!inspectionReady(t, f, [f.absoluteGit])) return;
  const commit = f.absoluteGit + ' commit -m x';
  const alternate = { GIT_INDEX_FILE: f.alternateIndex };
  expect('env -u GIT_INDEX_FILE ' + commit, 'FORBIDDEN', 'secret', alternate);
  expect('unset GIT_INDEX_FILE; ' + commit, 'FORBIDDEN', 'secret', alternate);
  expect('builtin unset GIT_INDEX_FILE; ' + commit, 'FORBIDDEN', 'secret', alternate);
  expect('env -u GIT_INDEX_FILE ' + commit, 'FORBIDDEN');
  expect(commit, 'ALLOW', 'secret', alternate);
  const otherRepo = { GIT_DIR: path.join(f.repos.ordinary, '.git') };
  expect('env -u GIT_DIR ' + commit, 'FORBIDDEN', 'secret', otherRepo);
  expect('unset GIT_DIR; ' + commit, 'FORBIDDEN', 'secret', otherRepo);
  expect('builtin unset GIT_DIR; ' + commit, 'FORBIDDEN', 'secret', otherRepo);
  expect(commit, 'ALLOW', 'secret', otherRepo);
  const reset = 'env -i HOME=' + f.home + ' GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null ';
  for (const repo of ['secret', 'ordinary']) {
    const refusal = expect(reset + commit, 'UNKNOWN', repo, alternate);
    assert.match(refusal.reason, /^\[判断不能\].*HOME \/ XDG_CONFIG_HOME/);
  }
  expect(commit, 'ALLOW', 'ordinary');
  assert.equal(fs.existsSync(f.marker), false);
});

test('own SG restores the five original normal inputs without changing the staged-secret refusals', t => {
  const f = fixtures();
  if (!inspectionReady(t, f, [f.setupGit])) return;
  const normalInputs = [
    'GIT_AUTHOR_NAME="$(cat .env)" git commit --author=ordinary -m ordinary',
    'GIT_AUTHOR_NAME="$(cat .env)" git commit --author=ordinary --date=ordinary -m ordinary',
    'export GIT_AUTHOR_NAME=ordinary; declare -n ref=GIT_AUTHOR_NAME; ref="$(cat .env)"; GIT_AUTHOR_NAME=ordinary git commit -m ordinary',
    'declare -n ref=ordinary; git commit -m ordinary',
    'GIT_AUTHOR_NAME="$(cat .env)" git commit --author="Ordinary <ordinary@example.invalid>" -m ordinary',
  ];
  for (const command of normalInputs) expect(command, 'ALLOW', 'ordinary');
  expect(normalInputs[0], 'FORBIDDEN');
  expect('declare -n ref=GIT_INDEX_FILE; ' + f.absoluteGit + ' commit -m ordinary', 'UNKNOWN');
  expect('declare -n ref="$TARGET"; GIT_INDEX_FILE=/DUMMY/index ' + f.absoluteGit + ' commit -m ordinary', 'UNKNOWN');
  assert.equal(fs.existsSync(f.marker), false);
});
