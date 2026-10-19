'use strict';

// Proposed commands are Hook stdin DATA. Native Git only creates owned DUMMY
// indexes and performs hardened reads. No proposed commit or loader is run.
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
const baseline = { HOME: '/DUMMY/home', PATH: '/DUMMY/bin', GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_SYSTEM: '/dev/null' };
const q = value => "'" + value.replaceAll("'", "'\\''") + "'";

function mocked(platform = 'linux', environment = baseline) {
  const calls = [], resolutions = [];
  const moduleCopy = new Module(readerFile, module);
  moduleCopy.filename = readerFile;
  moduleCopy.paths = Module._nodeModulePaths(path.dirname(readerFile));
  const original = moduleCopy.require.bind(moduleCopy);
  moduleCopy.require = name => name === './git-guard-common.cjs' ? { ...guard,
    trustedGitExecutable: () => true,
    resolveTrustedGitExecutable: (word, env, cwd) => {
      resolutions.push({ word, env, cwd });
      return '/DUMMY/git';
    },
  } : name === 'node:child_process' ? { execFileSync(executable, args, options) {
    calls.push({ executable, args, options });
    if (args.includes('--version')) return 'git version 2.54.0\n';
    if (args.includes('config')) throw Object.assign(new Error('DUMMY absent config'), { status: 1, stdout: '' });
    return '';
  } } : original(name);
  moduleCopy._compile('const process = { ...require("node:process"), platform: ' + JSON.stringify(platform) +
    ', env: ' + JSON.stringify(environment) + ' };\n' + fs.readFileSync(readerFile, 'utf8'), readerFile);
  return { readers: moduleCopy.exports, calls, resolutions };
}
function selected(command, platform = 'linux', environment = baseline) {
  const mock = mocked(platform, environment);
  const parsed = guard.inspect(command, { trackGitPreCommitEnvironment: true, trackGitIndexInspectionEnvironment: true,
    initialGitPreCommitEnvironmentSources: mock.readers.environmentSources(environment) });
  const invocation = parsed.invocations.findLast(value => value.name === 'git');
  const g = parsed.gits.findLast(value => value.sub === 'commit') || { cdirs: [] };
  const context = invocation && mock.readers.commitInspectionContext(g, invocation, '/DUMMY/base');
  return { ...mock, parsed, invocation, g, context };
}

test('the finite loader inventory participates in both selected and index environment snapshots', () => {
  assert.equal(guard.INSPECTION_LOADER_ENVIRONMENT_NAMES.length, 15);
  for (const name of guard.INSPECTION_LOADER_ENVIRONMENT_NAMES) {
    assert.equal(guard.inspectionLoaderEnvironmentName(name), true);
    assert.equal(guard.gitPreCommitEnvironmentName(name), true);
    assert.equal(guard.gitIndexInspectionEnvironmentName(name), true);
    const value = selected(name + '=/DUMMY/source git commit -m DUMMY');
    const word = value.invocation.gitPreCommitEnvironmentSources.find(source => source.name === name).word;
    assert.equal(word.dynamic, false);
    assert.equal(typeof word.literalValue === 'string' ? word.literalValue : word.text, '/DUMMY/source');
  }
  assert.equal(guard.inspectionLoaderEnvironmentName('ORDINARY'), false);
});

test('active loader sources stop before any Git query, while proven inactive families disappear', () => {
  for (const platform of ['linux', 'darwin', 'win32']) {
    const mock = mocked(platform);
    for (const name of guard.INSPECTION_LOADER_ENVIRONMENT_NAMES) {
      const active = platform === 'linux' ? name.startsWith('LD_')
        : platform === 'darwin' ? name.startsWith('DYLD_') || name === 'LD_LIBRARY_PATH' : true;
      const env = { ...baseline, [name]: '/DUMMY/source' };
      assert.equal(mock.readers.safeInspectionEnvironment(env) === null, active, platform + ':' + name);
      if (active) assert.throws(() => mock.readers.readInspectionGit(['diff', '--cached'], {
        executable: '/DUMMY/git', env, cwd: '/DUMMY/base',
      }), /environment/);
      else assert.equal(Object.hasOwn(mock.readers.safeInspectionEnvironment(env), name), false);
    }
    assert.equal(mock.calls.length, 0);
  }
});

test('whole empty lists stay empty without restoring fallback defaults; unqualified raw empty paths stop', () => {
  for (const platform of ['linux', 'darwin']) {
    const { readers } = mocked(platform);
    for (const name of guard.INSPECTION_LOADER_ENVIRONMENT_NAMES) {
      const active = platform === 'linux' ? name.startsWith('LD_') : name.startsWith('DYLD_') || name === 'LD_LIBRARY_PATH';
      const unqualified = active && ['LD_ORIGIN_PATH', 'DYLD_SHARED_CACHE_DIR'].includes(name);
      const result = readers.safeInspectionEnvironment({ ...baseline, [name]: '' });
      assert.equal(result === null, unqualified, platform + ':' + name);
      if (result) assert.equal(Object.hasOwn(result, name), active);
      if (result && active) assert.equal(result[name], '');
    }
    assert.equal(readers.safeInspectionEnvironment({ LD_LIBRARY_PATH: ':' }), null);
  }
});

test('prefix, export and inherited loader selection refuse; actual removal and unused locals do not invent a source', () => {
  for (const name of ['LD_PRELOAD', 'LD_LIBRARY_PATH', 'LD_AUDIT']) {
    for (const prefix of [name + '=/DUMMY/source ', 'export ' + name + '=/DUMMY/source; ',
      'env ' + name + '=/DUMMY/source ', 'export ' + name + '="$DUMMY"; ',
      'declare -n ref=' + name + '; ref=/DUMMY/source; ']) {
      const value = selected(prefix + 'git commit -m DUMMY');
      assert.equal(value.context, null, prefix);
      assert.equal(value.calls.length, 0);
    }
    const inherited = { ...baseline, [name]: '/DUMMY/source' };
    assert.equal(selected('git commit -m DUMMY', 'linux', inherited).context, null);
    for (const prefix of ['env -u ' + name + ' ', 'unset ' + name + '; ', 'env -i ']) {
      const value = selected(prefix + 'git commit -m DUMMY', 'linux', inherited);
      assert.ok(value.context, prefix);
      assert.equal(Object.hasOwn(value.context.env, name), false);
    }
    assert.ok(selected(name + '=/DUMMY/source; git commit -m DUMMY').context, 'unexported local is unused');
    assert.ok(selected(name + "='' git commit -m DUMMY").context);
  }
  assert.ok(selected('LD_PRELOAD=/DUMMY/source git commit -m DUMMY', 'darwin').context, 'pinned Darwin consumer does not use LD_PRELOAD');
  assert.equal(selected('LD_LIBRARY_PATH=/DUMMY/source git commit -m DUMMY', 'darwin').context, null);
});

test('raw directory arguments are applied once to every read and distinguish cache entries', () => {
  const { readers, calls } = mocked();
  const cwd = '/DUMMY/base';
  const read = cdirs => readers.readInspectionGit(['diff', '--cached', '--name-only', '-z'], {
    executable: '/DUMMY/git', env: baseline, cwd, cdirs,
  });
  const first = ['jump/..', '', '/DUMMY/absolute', '..'];
  read(first); read([...first]); read(['jump', '..']);
  assert.equal(calls.filter(call => call.args.includes('--version')).length, 2);
  assert.equal(calls.filter(call => call.args.includes('config')).length, 2);
  assert.equal(calls.filter(call => call.args.includes('diff')).length, 3);
  for (const call of calls) {
    const expected = call.args[1] === 'jump/..' ? first : ['jump', '..'];
    assert.deepEqual(call.args.slice(0, expected.length * 2), expected.flatMap(value => ['-C', value]));
    assert.equal(call.args.filter(arg => arg === '-C').length, expected.length);
    assert.equal(call.options.cwd, cwd);
    assert.equal(Object.hasOwn(call.options, 'cdirs'), false, 'metadata is not a child-process option');
  }
  for (const invalid of [null, 'jump/..', ['/DUMMY/\0bad']]) assert.throws(() => read(invalid), /directory arguments/);
});

test('program resolution stays before -C and reader config/hook probes keep the same raw argv', () => {
  const value = selected('git -C jump -C .. commit -m DUMMY');
  assert.ok(value.context);
  assert.equal(value.resolutions[0].cwd, '/DUMMY/base');
  assert.equal(value.context.cwd, '/DUMMY/base');
  assert.deepEqual(value.context.cdirs, ['jump', '..']);
  value.readers.readInspectionGit(['diff', '--cached'], value.context);
  const parsed = guard.inspect('git -C jump -C .. status', { trackGitPreCommitEnvironment: true,
    initialGitPreCommitEnvironmentSources: value.readers.environmentSources(baseline) });
  const invocation = parsed.invocations.find(i => i.name === 'git');
  const context = value.readers.readerContext(parsed.gits[0], invocation, '/DUMMY/base', {
    environment: baseline, executable: '/DUMMY/git', isTrusted: () => true, realpath: () => '/DUMMY/git',
  });
  assert.ok(context);
  assert.equal(context.inspectionBanner, 'git version 2.54.0');
  const probes = [];
  const spawn = (exe, args, options) => {
    probes.push({ exe, args, options });
    return args.includes('config') ? { status: 1, stdout: '' } : { status: 0, stdout: '/DUMMY/hook\n' };
  };
  assert.ok(value.readers.probeConfig(context, spawn) instanceof Map);
  assert.equal(value.readers.indexHookSource(context, spawn, () => { throw Object.assign(new Error('absent'), { code: 'ENOENT' }); }), false);
  for (const probe of probes) {
    assert.deepEqual(probe.args.slice(0, 4), ['-C', 'jump', '-C', '..']);
    assert.equal(probe.args.filter(arg => arg === '-C').length, 2);
    assert.equal(probe.options.cwd, '/DUMMY/base');
  }
});

let owned, hookCalls = 0;
function fixtures(t) {
  if (owned) return owned;
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'r47-inspection-sources-'));
  const home = path.join(root, 'home'); fs.mkdirSync(home);
  const candidates = process.platform === 'win32'
    ? ['C:\\Program Files\\Git\\cmd\\git.exe', 'C:\\Program Files\\Git\\bin\\git.exe']
    : ['/opt/homebrew/bin/git', '/usr/local/bin/git', '/usr/bin/git', '/bin/git'];
  const git = candidates.find(file => guard.resolveTrustedGitExecutable({ text: file }));
  const env = { PATH: git ? path.dirname(git) + path.delimiter + '/usr/bin:/bin' : '', HOME: home,
    XDG_CONFIG_HOME: path.join(home, '.config'), GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_CONFIG_SYSTEM: '/dev/null', GIT_OPTIONAL_LOCKS: '0', GIT_TERMINAL_PROMPT: '0', GIT_PAGER: 'cat', LC_ALL: 'C' };
  const version = git && spawnSync(git, ['--no-lazy-fetch', '--version'], { cwd: root, env, encoding: 'utf8' });
  if (!version || version.status !== 0 || !mocked().readers.supportsInspectionHardening(version.stdout)) {
    fs.rmSync(root, { recursive: true, force: true });
    t.skip('known backend did not qualify hardened inspection; no native witness or allow claim');
    return null;
  }
  const native = (cwd, args) => {
    const result = spawnSync(git, ['--no-pager', '--no-lazy-fetch', '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null', ...args], { cwd, env, encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr); return result.stdout;
  };
  const base = path.join(root, 'base'), secret = path.join(root, 'target'), ordinary = path.join(root, 'ordinary');
  for (const [repo, filename] of [[base, 'a.txt'], [secret, '.env'], [ordinary, 'b.txt']]) {
    fs.mkdirSync(repo); native(root, ['init', '-q', repo]); fs.writeFileSync(path.join(repo, filename), 'DUMMY contents only\n'); native(repo, ['add', '--', filename]);
  }
  const child = path.join(secret, 'child'); fs.mkdirSync(child);
  const marker = path.join(root, 'unsafe-loader-probe-attempts');
  owned = { root, home, git, env, native, base, secret, ordinary, child, marker, version: version.stdout.trim() };
  return owned;
}
function run(f, command, inherited = {}) {
  hookCalls++;
  // Inherited loader DTOs enter JS after Node starts with a clean environment.
  // A sentinel prevents any regression from actually passing them to a loader.
  const launcher = 'const cp=require("node:child_process"),fs=require("node:fs");const original=cp.execFileSync;' +
    'cp.execFileSync=(exe,args,options)=>{if(Object.entries(options?.env||{}).some(([n,v])=>/^(LD_|DYLD_)/.test(n)&&v!=="")){' +
    'fs.appendFileSync(' + JSON.stringify(f.marker) + ',"blocked unsafe loader replay\\n");throw Error("DUMMY blocked loader replay");}return original(exe,args,options);};' +
    'Object.assign(process.env,' + JSON.stringify(inherited) + ');require(' + JSON.stringify(path.join(hooks, 'block-secret-git.cjs')) + ');';
  const result = spawnSync(process.execPath, ['-e', launcher], { cwd: f.base, env: { ...f.env, CLAUDE_PROJECT_DIR: f.base }, encoding: 'utf8',
    input: JSON.stringify({ tool_name: 'Bash', tool_input: { command }, cwd: f.base }) });
  return observeHookResult(result).verdict;
}
function observeHookResult(result) {
  assert.equal(result.status, 0, result.stderr); assert.equal(result.stderr, '');
  if (!result.stdout) return { verdict: 'ALLOW', reason: '' };
  const output = JSON.parse(result.stdout).hookSpecificOutput;
  assert.equal(output.permissionDecision, 'deny');
  const reason = output.permissionDecisionReason;
  return { verdict: typeof reason !== 'string' ? 'BROKEN'
    : reason.startsWith('[禁止] ') ? 'FORBIDDEN'
    : reason.startsWith('[判断不能] ') ? 'UNKNOWN' : 'BROKEN', reason };
}

test('malformed deny wire cannot satisfy an UNKNOWN loader inspection expectation', () => {
  const observe = reason => observeHookResult({ status: 0, stderr: '', stdout: JSON.stringify({
    hookSpecificOutput: { permissionDecision: 'deny', permissionDecisionReason: reason },
  }) });
  for (const reason of ['DUMMY unexpected prefix', '', '[判断不能]DUMMY', '[禁止]DUMMY', null, 42, {}, undefined]) {
    assert.deepEqual(observe(reason), { verdict: 'BROKEN', reason });
  }
  for (const [reason, verdict] of [['[禁止] DUMMY .env', 'FORBIDDEN'], ['[判断不能] DUMMY loader', 'UNKNOWN']]) {
    assert.deepEqual(observe(reason), { verdict, reason });
  }
  assert.deepEqual(observeHookResult({ status: 0, stderr: '', stdout: '' }), { verdict: 'ALLOW', reason: '' });
});

test('owned Hook DATA inspects the physical target for symlink/parent, repeated, absolute and empty -C', t => {
  const f = fixtures(t); if (!f) return;
  try { fs.symlinkSync(f.child, path.join(f.base, 'jump'), 'dir'); }
  catch (error) { t.skip('symlink fixture unavailable: ' + error.code); return; }
  assert.equal(f.native(f.base, ['-C', 'jump/..', 'diff', '--no-ext-diff', '--no-textconv', '--cached', '--name-only', '-z']), '.env\0');
  for (const args of ['-C jump/..', '-C jump -C ..', '-C ' + q(f.base + '/jump/..'), "-C '' -C jump/..", '-C jump -C ' + q(f.secret)]) {
    assert.equal(run(f, f.git + ' ' + args + ' commit -m DUMMY'), 'FORBIDDEN', args);
  }
  for (const args of ['', '-C .', '-C ' + q(f.ordinary), "-C ''"]) {
    assert.equal(run(f, f.git + ' ' + args + ' commit -m DUMMY'), 'ALLOW', args);
  }
  assert.equal(run(f, f.git + ' -C does-not-exist commit -m DUMMY'), 'UNKNOWN');
  assert.equal(f.native(f.base, ['diff', '--no-ext-diff', '--no-textconv', '--cached', '--name-only', '-z']), 'a.txt\0');
});

test('owned Hook DATA refuses active prefix/export/prior-reader loaders before any unsafe replay', t => {
  const f = fixtures(t); if (!f) return;
  const active = process.platform === 'darwin' ? 'DYLD_INSERT_LIBRARIES' : 'LD_PRELOAD';
  const commit = f.git + ' commit -m DUMMY';
  for (const command of [active + '=/DUMMY/source ' + commit, 'export ' + active + '=/DUMMY/source; ' + commit,
    active + '=/DUMMY/source ' + f.git + ' -P status; ' + commit,
    active + '=/DUMMY/source ' + f.git + ' --version; ' + commit]) {
    assert.equal(run(f, command), 'UNKNOWN', command);
  }
  assert.equal(run(f, active + "='' " + commit), process.platform === 'win32' ? 'UNKNOWN' : 'ALLOW');
  assert.equal(run(f, active + '=/DUMMY/source; ' + commit), 'ALLOW', 'unused local');
  assert.equal(run(f, commit + '; ' + active + '=/DUMMY/source ' + f.git + ' status'), 'ALLOW', 'after-commit source is outside the prior-reader gate');
  assert.equal(run(f, active + '=/DUMMY/source ' + f.git + ' add .env; ' + commit), 'FORBIDDEN', 'independent forbidden filename remains');
  assert.equal(fs.existsSync(f.marker), false);
});

test('owned Hook DATA safely models inherited/removal/empty/inactive selection without native loader activation', t => {
  const f = fixtures(t); if (!f) return;
  const active = process.platform === 'darwin' ? 'DYLD_INSERT_LIBRARIES' : 'LD_PRELOAD';
  const commit = f.git + ' commit -m DUMMY';
  assert.equal(run(f, commit, { [active]: '/DUMMY/source' }), 'UNKNOWN');
  for (const prefix of ['env -u ' + active + ' ', 'unset ' + active + '; ']) {
    assert.equal(run(f, prefix + commit, { [active]: '/DUMMY/source' }), 'ALLOW', prefix);
  }
  assert.equal(run(f, commit, { [active]: '' }), process.platform === 'win32' ? 'UNKNOWN' : 'ALLOW');
  if (process.platform === 'darwin') assert.equal(run(f, commit, { LD_PRELOAD: '/DUMMY/source' }), 'ALLOW');
  if (process.platform === 'linux') assert.equal(run(f, commit, { DYLD_INSERT_LIBRARIES: '/DUMMY/source' }), 'ALLOW');
  assert.equal(fs.existsSync(f.marker), false);
});

test.after(() => {
  if (owned) {
    assert.equal(fs.existsSync(owned.marker), false, 'no active loader reached an own native Git');
    fs.rmSync(owned.root, { recursive: true, force: true });
  }
  console.log('r47 owned Hook DATA calls: ' + hookCalls + '; proposed commits/loaders/network/L3: 0');
});
