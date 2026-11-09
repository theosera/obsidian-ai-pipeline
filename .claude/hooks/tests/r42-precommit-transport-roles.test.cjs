'use strict';

// Source/operation contracts and Hook-input DATA only. Proposed commands,
// callbacks, transport helpers and network operations are never executed.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const Module = require('node:module');
const vm = require('node:vm');
const { spawnSync } = require('node:child_process');
const hooks = path.resolve(process.argv[2] || path.join(__dirname, '..'));
const readers = require(path.join(hooks, 'lib/git-precommit-readers.cjs'));
const guard = require(path.join(hooks, 'lib/git-guard-common.cjs'));
const baseline = { PATH: '/DUMMY/bin', HOME: '/DUMMY/home' };
const transports = ['GIT_SSH', 'GIT_SSH_COMMAND', 'GIT_SSH_VARIANT', 'GIT_ASKPASS', 'SSH_ASKPASS'];

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

test('native fixture gate requires the actual no-lazy-fetch capability as well as the fsmonitor floor', () => {
  for (const [result, available] of [
    [{ status: 0, stdout: 'git version 2.54.0\n' }, true],
    [{ status: 0, stdout: 'git version 2.53.0\n' }, true],
    [{ status: 129, stdout: '', stderr: 'unknown option: --no-lazy-fetch' }, false],
    [{ status: 0, stdout: 'git version 2.35.1\n' }, false],
    [{ status: 0, stdout: 'DUMMY unsupported banner\n' }, false],
    [{ status: null, stdout: '', error: { code: 'ENOENT' } }, false],
  ]) {
    const calls = [];
    const capability = inspectionCapability('/DUMMY/git', '/DUMMY/repo', baseline, (exe, args, options) => {
      calls.push({ exe, args, options }); return result;
    });
    assert.equal(capability.available, available);
    assert.equal(calls.length, 1);
    assert.deepEqual(calls[0].args, ['--no-lazy-fetch', '--version']);
    assert.equal(calls[0].options.env.GIT_NO_LAZY_FETCH, '1');
    assert.equal(calls[0].options.env.GIT_OPTIONAL_LOCKS, '0');
  }
  assert.equal(readers.supportsInspectionHardening('git version 2.43.0'), true,
    'the version floor alone does not prove that --no-lazy-fetch is implemented');
});

function selectedReader(command, environment = baseline, implementations = { guard, readers }) {
  const parsed = implementations.guard.inspect(command, { trackGitPreCommitEnvironment: true,
    initialGitPreCommitEnvironmentSources: implementations.readers.environmentSources(environment) });
  assert.deepEqual(parsed.problems, []);
  const g = parsed.gits.find(g => g.sub !== 'commit');
  assert.ok(g);
  const invocation = parsed.invocations.find(i => i.order === g.invocationOrder);
  const deps = { environment, executable: '/DUMMY/git', isTrusted: () => true,
    probe: () => new Map(), indexHook: () => false, emptySSHConsumerQualified: true }; // pinned Git2.54 consumer DTO
  return { g, invocation, deps };
}

// Compile one in-memory source change at a time; no Hook or native helper runs.
function singleEdgeOff(edge) {
  const commonFile = path.join(hooks, 'lib/git-guard-common.cjs');
  const readerFile = path.join(hooks, 'lib/git-precommit-readers.cjs');
  let commonSource = fs.readFileSync(commonFile, 'utf8');
  let readerSource = fs.readFileSync(readerFile, 'utf8');
  const edits = {
    projection: ["['HOME', 'XDG_CONFIG_HOME', 'PAGER', 'PATH', 'SSH_ASKPASS']", "['HOME', 'XDG_CONFIG_HOME', 'PAGER', 'PATH']"],
    transport: ["['GIT_SSH', 'GIT_SSH_COMMAND', 'GIT_SSH_VARIANT', 'GIT_ASKPASS', 'SSH_ASKPASS']", "['GIT_SSH', 'GIT_SSH_COMMAND', 'GIT_SSH_VARIANT', 'GIT_ASKPASS']"],
    inspection: [" || name === 'SSH_ASKPASS'", ''],
    configProbe: [String.raw`const CONFIG_PATTERN = '^(core\\.(fsmonitor|pager|hookspath|askpass|sshcommand|gitproxy)`, String.raw`const CONFIG_PATTERN = '^(core\\.(fsmonitor|pager|hookspath|sshcommand|gitproxy)`],
    configGate: ["    if (!environment.has('GIT_ASKPASS') && config.get('core.askpass')) return 'configured-askpass';", ''],
    configParser: [String.raw`const CONFIG_KEY = /^(?:core\.(?:fsmonitor|pager|hookspath|askpass|sshcommand|gitproxy)`, String.raw`const CONFIG_KEY = /^(?:core\.(?:fsmonitor|pager|hookspath|sshcommand|gitproxy)`],
    inherited: ["    if (ssh?.kind === 'env' && inheritedProgram(ssh.name) || inheritedProgram('GIT_ASKPASS') || inheritedProgram('SSH_ASKPASS') && !sshAskpassShadowed(environment, config, ssh, emptySSHConsumerQualified)) return 'inherited-transport-program';", ''],
    sshConfigProbe: [String.raw`const CONFIG_PATTERN = '^(core\\.(fsmonitor|pager|hookspath|askpass|sshcommand|gitproxy)`, String.raw`const CONFIG_PATTERN = '^(core\\.(fsmonitor|pager|hookspath|askpass|gitproxy)`],
    sshConfigGate: ["    if (ssh?.kind === 'config' && ssh.value) return 'configured-ssh-command';", ''],
    credentialProbe: [String.raw`const CONFIG_PATTERN = '^(core\\.(fsmonitor|pager|hookspath|askpass|sshcommand|gitproxy)|credential(\\..*)?\\.helper`, String.raw`const CONFIG_PATTERN = '^(core\\.(fsmonitor|pager|hookspath|askpass|sshcommand|gitproxy)`],
    credentialGate: ["    if (credentialHelperSource(config)) return 'credential-helper';", ''],
    proxyProbe: [String.raw`const CONFIG_PATTERN = '^(core\\.(fsmonitor|pager|hookspath|askpass|sshcommand|gitproxy)`, String.raw`const CONFIG_PATTERN = '^(core\\.(fsmonitor|pager|hookspath|askpass|sshcommand)`],
    proxyGate: ["    if (gitProxySource(environment, config)) return 'git-proxy';", ''],
    combinedShadow: [" && !sshAskpassShadowed(environment, config, ssh, emptySSHConsumerQualified)", ''],
  };
  const edit = edits[edge];
  assert.ok(edit);
  const source = edge === 'projection' ? commonSource : readerSource;
  assert.equal(source.split(edit[0]).length, 2, `one ${edge} edge`);
  if (edge === 'projection') commonSource = source.replace(...edit);
  else readerSource = source.replace(...edit);
  const compile = (filename, source, overrides = {}) => {
    const compiled = new Module(filename, module);
    compiled.filename = filename;
    compiled.paths = Module._nodeModulePaths(path.dirname(filename));
    const originalRequire = compiled.require.bind(compiled);
    compiled.require = name => Object.hasOwn(overrides, name) ? overrides[name] : originalRequire(name);
    compiled._compile(source, filename);
    return compiled.exports;
  };
  const selectedGuard = edge === 'projection' ? compile(commonFile, commonSource) : guard;
  return { guard: selectedGuard, readers: compile(readerFile, readerSource, { './git-guard-common.cjs': selectedGuard }) };
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

function configuredAssessment(value, command = 'git -P status; git commit -m x', environment = baseline,
  implementations = { guard, readers }) {
  return configAssessment(value === undefined ? [] : [['core.askpass', value]], command, environment, implementations);
}

function configAssessment(records, command = 'git -P status; git commit -m x', environment = baseline,
  implementations = { guard, readers }) {
  const f = selectedReader(command, environment, implementations);
  f.deps.probe = context => implementations.readers.probeConfig(context, (_executable, args) => {
    const selected = records.filter(([key]) => new RegExp(args.at(-1)).test(key));
    return { status: selected.length ? 0 : 1, stdout: selected.map(([key, value]) => `local\0${key}\n${value}\0`).join('') };
  });
  return implementations.readers.assessReader(f.g, f.invocation, '/DUMMY/repo', f.deps);
}

test('ordered Git proxy sources retain first-match disables and unknown-host candidates', () => {
  const command = 'git -P diff --no-ext-diff --no-textconv HEAD; git commit -m x';
  const records = values => values.map(value => ['core.gitproxy', value]);
  for (const values of [['/DUMMY/proxy'], ['/DUMMY/proxy for example.invalid'],
    ['/DUMMY/proxy', 'none'], ['none for example.invalid', '/DUMMY/proxy for other.invalid']]) {
    assert.match(configAssessment(records(values), command).reason, /git-proxy/);
  }
  for (const values of [[], [''], ['none'], ['none', '/DUMMY/proxy'],
    ['none for example.invalid', '/DUMMY/proxy for example.invalid'],
    ['none for example.invalid', '/DUMMY/proxy for sub.example.invalid']]) {
    assert.equal(configAssessment(records(values), command), null);
  }
  for (const edge of ['proxyProbe', 'proxyGate']) {
    assert.equal(configAssessment(records(['/DUMMY/proxy']), command, baseline, singleEdgeOff(edge)), null);
    assert.equal(configAssessment(records(['none']), command, baseline, singleEdgeOff(edge)), null);
  }
  const parsed = readers.parseConfigOutput('global\0core.gitproxy\nnone for example.invalid\0local\0core.gitproxy\n/DUMMY/proxy\0');
  assert.deepEqual(parsed.gitProxyValues, ['none for example.invalid', '/DUMMY/proxy']);
  const role = readers.operationRole(selectedReader(command).g);
  assert.equal(readers.selectedHelper(role, selectedReader(command).g, new Map(), new Map([['core.gitproxy', 'none']])), 'git-proxy'); // ordering absent
  assert.equal(configAssessment(records(['/DUMMY/proxy']), command, { ...baseline, GIT_PROXY_COMMAND: '' }), null);
  for (const value of ['none', '/DUMMY/proxy']) assert.match(configAssessment(records(['none']), command, { ...baseline, GIT_PROXY_COMMAND: value }).reason, /git-proxy/);
  const context = selectedReader(command, { ...baseline, GIT_PROXY_COMMAND: '/DUMMY/proxy' });
  const dto = readers.readerContext(context.g, context.invocation, '/DUMMY/repo', context.deps);
  assert.equal(dto.selected.get('GIT_PROXY_COMMAND'), '/DUMMY/proxy');
  assert.equal(dto.env.GIT_PROXY_COMMAND, undefined);
  assert.equal(dto.env.GIT_NO_LAZY_FETCH, '1');
  for (const query of ['git -P diff -h; git commit -m x', 'git -P config --get core.gitProxy; git commit -m x']) {
    assert.equal(configAssessment(records(['/DUMMY/proxy']), query), null);
  }
  const usage = guard.inspect('git -c core.gitProxy=/DUMMY/proxy commit -h', { trackGitPreCommitEnvironment: true,
    initialGitPreCommitEnvironmentSources: readers.environmentSources(baseline) });
  const g = usage.gits[0];
  assert.equal(readers.targetGlobals(g, usage.invocations.find(i => i.order === g.invocationOrder), true), null);
});

test('SSH askpass is suppressed only by empty effective Git and native SSH consumers together', () => {
  const command = 'git -P status; git commit -m x';
  const inherited = { ...baseline, SSH_ASKPASS: '/DUMMY/helper' };
  const both = { ...inherited, GIT_ASKPASS: '', GIT_SSH_COMMAND: '' };
  const expected = process.platform === 'win32' ? 'UNKNOWN' : undefined;
  assert.equal(assess(command, both)?.category, expected);
  assert.equal(configAssessment([['core.askpass', ''], ['core.sshcommand', '']], command, inherited)?.category, expected);
  assert.equal(assess(command, { ...inherited, GIT_ASKPASS: '', GIT_SSH: '' })?.category, expected);
  for (const environment of [inherited, { ...inherited, GIT_ASKPASS: '' }, { ...inherited, GIT_SSH_COMMAND: '' },
    { ...both, GIT_ASKPASS: '/DUMMY/git-helper' }, { ...both, GIT_SSH_COMMAND: '/DUMMY/ssh-helper' }]) {
    assert.equal(assess(command, environment)?.category, 'UNKNOWN');
  }
  const unqualified = selectedReader(command, both);
  unqualified.deps.emptySSHConsumerQualified = false;
  assert.equal(readers.assessReader(unqualified.g, unqualified.invocation, '/DUMMY/repo', unqualified.deps)?.category, 'UNKNOWN');
  const off = singleEdgeOff('combinedShadow'), f = selectedReader(command, both, off);
  assert.equal(off.readers.assessReader(f.g, f.invocation, '/DUMMY/repo', f.deps)?.category, 'UNKNOWN');
  assert.match(assess('SSH_ASKPASS=/DUMMY/changed ' + command, both).reason, /command-selected-transport/);
  assert.match(configAssessment([['credential.helper', '/DUMMY/helper']], command, both).reason, /credential-helper/);
});

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
  for (const edge of ['projection', 'transport']) {
    const off = singleEdgeOff(edge);
    const command = 'SSH_ASKPASS=/DUMMY/selected git -P status; git commit -m x';
    const f = selectedReader(command, baseline, off);
    assert.equal(off.readers.assessReader(f.g, f.invocation, '/DUMMY/repo', f.deps), null, `${edge} alone is necessary`);
    for (const control of ['git -P status; git commit -m x',
      'SSH_ASKPASS=/DUMMY/selected git -P status -h; git commit -m x']) {
      const c = selectedReader(control, baseline, off);
      assert.equal(off.readers.assessReader(c.g, c.invocation, '/DUMMY/repo', c.deps), null);
    }
  }
  const configured = configuredAssessment('/DUMMY/program');
  assert.equal(configured?.category, 'UNKNOWN');
  assert.match(configured.reason, /configured-askpass/);
  for (const edge of ['configProbe', 'configGate']) {
    assert.equal(configuredAssessment('/DUMMY/program', undefined, baseline, singleEdgeOff(edge)), null, `${edge} alone is necessary`);
  }
  // Parser-only removal keeps fail-closed UNKNOWN, so this is not necessity evidence.
  const parserOff = configuredAssessment('/DUMMY/program', undefined, baseline, singleEdgeOff('configParser'));
  assert.equal(parserOff?.category, 'UNKNOWN');
  assert.doesNotMatch(parserOff.reason, /configured-askpass/);
  for (const value of ['', undefined]) assert.equal(configuredAssessment(value), null);
  assert.equal(configuredAssessment('/DUMMY/program', undefined, { ...baseline, GIT_ASKPASS: '' }), null);
  assert.match(configuredAssessment('/DUMMY/program', undefined, { ...baseline, GIT_ASKPASS: '/DUMMY/inherited' }).reason, /inherited-transport-program/);
  for (const command of ['git -P status -h; git commit -m x',
    'git -P --version; git commit -m x', 'git -P config --get user.name; git commit -m x']) {
    assert.equal(configuredAssessment('/DUMMY/program', command), null);
  }
  for (const key of ['core.askPass', 'core.sshCommand', 'credential.helper']) for (const value of ['', '/DUMMY/program']) {
    const parsed = guard.inspect(`git -c ${key}=${value} commit -h`, { trackGitPreCommitEnvironment: true,
      initialGitPreCommitEnvironmentSources: readers.environmentSources(baseline) });
    const g = parsed.gits[0], invocation = parsed.invocations.find(i => i.order === g.invocationOrder);
    assert.deepEqual(readers.targetGlobals(g, invocation, true), key === 'credential.helper' ? [] : null);
  }
  for (const [key, reason, edges] of [
    ['core.sshcommand', 'configured-ssh-command', ['sshConfigProbe', 'sshConfigGate']],
    ['credential.helper', 'credential-helper', ['credentialProbe', 'credentialGate']],
  ]) {
    assert.match(configAssessment([[key, '/DUMMY/program']]).reason, new RegExp(reason));
    for (const edge of edges) assert.equal(configAssessment([[key, '/DUMMY/program']], undefined, baseline, singleEdgeOff(edge)), null);
    assert.equal(configAssessment([[key, '']]), null);
    assert.equal(configAssessment([[key, '/DUMMY/program']], 'git -P status -h; git commit -m x'), null);
  }
  assert.equal(configAssessment([['core.sshcommand', '/DUMMY/config']], undefined, { ...baseline, GIT_SSH_COMMAND: '', GIT_SSH: '/DUMMY/lower' }), null);
  assert.equal(configAssessment([['core.sshcommand', '']], undefined, { ...baseline, GIT_SSH: '/DUMMY/lower' }), null);
  const inherited = { ...baseline, GIT_SSH_COMMAND: '/DUMMY/inherited' };
  const off = singleEdgeOff('inherited'), selected = selectedReader('git -P status; git commit -m x', inherited, off);
  assert.equal(off.readers.assessReader(selected.g, selected.invocation, '/DUMMY/repo', selected.deps), null);
  assert.equal(configAssessment([], undefined, inherited)?.category, 'UNKNOWN');
  const A = 'credential.https://example.invalid/Case.helper', B = 'credential.https://example.invalid/case.helper';
  for (const records of [
    [['credential.helper', '/DUMMY/program'], ['credential.helper', '']],
    [[A, '/DUMMY/program'], ['credential.helper', '']],
    [[A, '/DUMMY/program'], [A, '']],
  ]) assert.equal(configAssessment(records), null);
  for (const records of [
    [['credential.helper', ''], ['credential.helper', '/DUMMY/program']],
    [['credential.helper', '/DUMMY/program'], [A, '']],
    [[A, '/DUMMY/program'], [B, '']],
    [[A, '/DUMMY/program'], ['credential.helper', ''], [B, '/DUMMY/later']],
  ]) assert.match(configAssessment(records).reason, /credential-helper/);
  const parsed = readers.parseConfigOutput(`global\0${A}\n/DUMMY/program\0local\0${B}\n\0`);
  assert.deepEqual(parsed.credentialHelperRecords.map(r => [r.scope, r.rawKey, r.subsection]),
    [['global', A, 'https://example.invalid/Case'], ['local', B, 'https://example.invalid/case']]);
  const f = selectedReader('git -P status; git commit -m x');
  f.deps.probe = () => new Map([['credential.helper', '']]);
  assert.match(readers.assessReader(f.g, f.invocation, '/DUMMY/repo', f.deps).reason, /credential-helper/);
});

test('prefix, env, exported and stored exported selections reach the same consumer', () => {
  for (const name of transports) {
    for (const prefix of [
      `${name}=/DUMMY/selected `,
      `env ${name}=/DUMMY/selected `,
      `export ${name}=/DUMMY/selected; `,
      `${name}=/DUMMY/selected; export ${name}; `,
      `transport=/DUMMY/selected; export ${name}="$transport"; `,
    ]) unknown(`${prefix}git -P status; git commit -m x`);
    unknown(`${name}=/DUMMY/selected git -P cat-file -p HEAD:a.txt; git commit -m x`);
  }
});

test('unused locals, removed selections and earlier overrides retain normal controls', () => {
  for (const name of transports) {
    assert.equal(assess(`${name}=/DUMMY/unused; git -P status; git commit -m x`), null);
    assert.equal(assess(`export ${name}=/DUMMY/unused; unset ${name}; git -P status; git commit -m x`), null);
    assert.equal(assess(`export ${name}=/DUMMY/unused; env -u ${name} git -P status; git commit -m x`), null);
  }
  assert.equal(assess('transport=/DUMMY/unused; git -P status; git commit -m x'), null);
});

test('inherited programs remain selected while empty and nonprogram variant controls stay separate', () => {
  for (const name of transports) {
    const inherited = { ...baseline, [name]: '/DUMMY/inherited' };
    for (const command of ['git -P status; git commit -m x', `${name}=/DUMMY/inherited git -P status; git commit -m x`]) {
      if (name === 'GIT_SSH_VARIANT') assert.equal(assess(command, inherited), null);
      else assert.match(assess(command, inherited).reason, /inherited-transport-program/);
    }
    assert.equal(assess('git -P status; git commit -m x', { ...baseline, [name]: '' }), null);
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
  for (const name of transports) {
    assert.equal(assess(`${name}=/DUMMY/unused git -P status -h; git commit -m x`), null);
    assert.equal(assess(`${name}=/DUMMY/unused git -P --version; git commit -m x`), null);
    assert.equal(assess(`${name}=/DUMMY/unused git -P config --get user.name; git commit -m x`), null);
  }
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
  const selected = { ...baseline, SSH_ASKPASS: '/DUMMY/inherited', GIT_NO_LAZY_FETCH: '0' };
  const safe = readers.safeInspectionEnvironment(selected);
  assert.equal(safe.SSH_ASKPASS, undefined);
  assert.equal(safe.GIT_NO_LAZY_FETCH, '1');
  assert.equal(selected.SSH_ASKPASS, '/DUMMY/inherited');
  assert.equal(selected.GIT_NO_LAZY_FETCH, '0');
  const off = singleEdgeOff('inspection');
  const unsafe = off.readers.safeInspectionEnvironment(selected);
  assert.equal(unsafe.SSH_ASKPASS, '/DUMMY/inherited');
  assert.equal(unsafe.GIT_NO_LAZY_FETCH, '1');
  const actual = selectedReader('SSH_ASKPASS=/DUMMY/selected git -P status; git commit -m x', selected, off);
  assert.equal(off.readers.readerContext(actual.g, actual.invocation, '/DUMMY/repo', actual.deps).selected.get('SSH_ASKPASS'), '/DUMMY/selected');
  assert.equal(off.readers.assessReader(actual.g, actual.invocation, '/DUMMY/repo', actual.deps)?.category, 'UNKNOWN');
});

// VM spies replace the trusted backend; no backend/helper is run by these tests.
function inspectionSpy({ unsupported = false, banner = 'git version 2.54.0\n' } = {}) {
  const calls = [];
  const environment = { ...baseline, GIT_NO_LAZY_FETCH: '0', SSH_ASKPASS: '/DUMMY/inherited' };
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
  return { readers: sandbox.module.exports, calls, environment,
    inspection: { cwd: '/DUMMY/repo', executable: '/DUMMY/git', env: environment } };
}

test('own version capability, configured-hook probe and diff/ls-files all receive flag and environment', () => {
  const spy = inspectionSpy();
  assert.equal(spy.readers.readInspectionGit(['diff', '--cached', '--name-only', '-z'], spy.inspection), 'DUMMY inspection');
  assert.equal(spy.readers.readInspectionGit(['ls-files', '-z'], spy.inspection), 'DUMMY inspection');
  assert.deepEqual(spy.calls[0].args, ['--no-lazy-fetch', '--version']);
  assert.equal(spy.calls.filter(c => c.args.includes('--version')).length, 1);
  assert.ok(spy.calls.some(c => c.args.includes('config')));
  assert.ok(spy.calls.some(c => c.args.includes('diff')));
  assert.ok(spy.calls.some(c => c.args.includes('ls-files')));
  for (const call of spy.calls) {
    assert.ok(call.args.includes('--no-lazy-fetch'));
    assert.equal(call.env.GIT_NO_LAZY_FETCH, '1');
    assert.equal(call.env.SSH_ASKPASS, undefined);
  }
  assert.equal(spy.environment.GIT_NO_LAZY_FETCH, '0');
  assert.equal(spy.environment.SSH_ASKPASS, '/DUMMY/inherited');
});

test('unsupported capability stops before object/config reads; fsmonitor floor stays separate', () => {
  const unsupported = inspectionSpy({ unsupported: true });
  assert.throws(() => unsupported.readers.readInspectionGit(['diff', '--cached'], unsupported.inspection), /unsupported/);
  assert.equal(unsupported.calls.length, 1);
  assert.deepEqual(unsupported.calls[0].args, ['--no-lazy-fetch', '--version']);
  const old = inspectionSpy({ banner: 'git version 2.35.1\n' });
  assert.throws(() => old.readers.readInspectionGit(['diff', '--cached'], old.inspection), /fsmonitor/);
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
    const executable = guard.resolveTrustedGitExecutable({ text: 'git' }, environment, repo);
    if (!executable) { t.skip('native inspection requires a known selected Git installation'); return; }
    const capability = inspectionCapability(executable, repo, environment);
    t.diagnostic(`owned fixture inspection capability: ${JSON.stringify(capability)}`);
    if (!capability.available) { t.skip('native inspection unavailable: --no-lazy-fetch capability or fsmonitor floor'); return; }
    const qualifiedGit254 = capability.banner === 'git version 2.54.0';
    t.diagnostic(`owned fixture exact consumer ${qualifiedGit254}`);
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
    for (const name of transports) {
      assert.equal(run(`${name}=/DUMMY/selected git -P status; git commit -m x`), 'UNKNOWN');
      assert.equal(run(`export ${name}=/DUMMY/selected; git -P status; git commit -m x`), 'UNKNOWN');
      assert.equal(run(`transport=/DUMMY/selected; export ${name}="$transport"; git -P status; git commit -m x`), 'UNKNOWN');
      assert.equal(run(`${name}=/DUMMY/unused; git -P status; git commit -m x`), 'ALLOW');
      assert.equal(run(`export ${name}=/DUMMY/unused; unset ${name}; git -P status; git commit -m x`), 'ALLOW');
      assert.equal(run(`export ${name}=/DUMMY/unused; env -u ${name} git -P status; git commit -m x`), 'ALLOW');
      const inherited = { [name]: '/DUMMY/inherited' };
      const inheritedDecision = name === 'GIT_SSH_VARIANT' ? 'ALLOW' : 'UNKNOWN';
      assert.equal(run('git -P status; git commit -m x', inherited), inheritedDecision);
      assert.equal(run(`${name}=/DUMMY/inherited git -P status; git commit -m x`, inherited), inheritedDecision);
      assert.equal(run('git -P status; git commit -m x', { [name]: '' }), 'ALLOW');
      assert.equal(run(`${name}= git -P status; git commit -m x`, { [name]: '' }), 'ALLOW');
      assert.equal(run(`${name}=/DUMMY/different git -P status; git commit -m x`, inherited), 'UNKNOWN');
      assert.equal(run(`${name}=/DUMMY/unused git -P status -h; git commit -m x`), 'ALLOW');
      assert.equal(run(`git commit -m x; ${name}=/DUMMY/unused git -P status`), 'ALLOW');
      assert.equal(run(`${name}=/DUMMY/selected git -P status; git add .env; git commit -m x`), 'FORBIDDEN');
      assert.equal(run(`git add .env; ${name}=/DUMMY/selected git -P status; git commit -m x`), 'FORBIDDEN');
    }
    assert.equal(run('git -P status; git commit -m x'), 'ALLOW');
    assert.equal(run('git -P status; git commit -m x', { GIT_EDITOR: 'DUMMY' }), 'ALLOW');
    assert.equal(run('SSH_ASKPASS=/tmp/stage git -P diff HEAD; git commit -m x'), 'UNKNOWN');
    assert.equal(run('git diff; git commit', { GIT_SSH_COMMAND: '/DUMMY/helper' }), 'UNKNOWN');
    assert.equal(run('git -P status; git commit -m x', { GIT_SSH_COMMAND: '', GIT_SSH: '/DUMMY/lower' }), 'ALLOW');
    assert.equal(run('git -P status; git commit -m x', { GIT_SSH_COMMAND: '/DUMMY/higher', GIT_SSH: '/DUMMY/lower' }), 'UNKNOWN');
    const configPath = path.join(repo, '.git', 'config'), baseConfig = fs.readFileSync(configPath, 'utf8');
    const configuredReader = 'git -P cat-file -p HEAD:a.txt; git commit -m x';
    try {
      fs.writeFileSync(configPath, baseConfig + '\n[core]\n\taskPass = /DUMMY/program\n');
      assert.equal(run(configuredReader), 'UNKNOWN');
      assert.equal(run('git -P status; git commit -m x'), 'UNKNOWN');
      assert.equal(run(configuredReader, { GIT_ASKPASS: '' }), 'ALLOW');
      assert.equal(run(configuredReader, { GIT_ASKPASS: '/DUMMY/inherited' }), 'UNKNOWN');
      assert.equal(run(configuredReader, { SSH_ASKPASS: '/DUMMY/lower-priority' }), 'UNKNOWN');
      assert.equal(run('unset GIT_ASKPASS; ' + configuredReader, { GIT_ASKPASS: '/DUMMY/inherited' }), 'UNKNOWN');
      assert.equal(run('env -u GIT_ASKPASS ' + configuredReader, { GIT_ASKPASS: '/DUMMY/inherited' }), 'UNKNOWN');
      assert.equal(run('git -P cat-file -h; git commit -m x'), 'ALLOW');
      assert.equal(run('git -P config --get user.name; git commit -m x'), 'ALLOW');
      assert.equal(run('git commit -m x; git -P cat-file -p HEAD:a.txt'), 'ALLOW');
      assert.equal(run('git -c core.askPass=/DUMMY/program commit -h; git commit -m x'), 'UNKNOWN');
      assert.equal(run(configuredReader + '; git add .env'), 'FORBIDDEN');
      assert.equal(run('git add .env; ' + configuredReader), 'FORBIDDEN');
      fs.writeFileSync(configPath, baseConfig + '\n[core]\n\taskPass =\n');
      assert.equal(run(configuredReader), 'ALLOW');
      assert.equal(run(configuredReader, { SSH_ASKPASS: '/DUMMY/lower-priority' }), 'UNKNOWN');
      assert.equal(run(configuredReader, { GIT_ASKPASS: '', SSH_ASKPASS: '/DUMMY/native-ssh' }), 'UNKNOWN');
      fs.writeFileSync(configPath, baseConfig + '\n[core]\n\tsshCommand = /DUMMY/config\n');
      assert.equal(run(configuredReader), 'UNKNOWN');
      assert.equal(run(configuredReader, { GIT_SSH_COMMAND: '' }), 'ALLOW');
      assert.equal(run(configuredReader, { GIT_SSH_COMMAND: '/DUMMY/inherited' }), 'UNKNOWN');
      assert.equal(run('git -P cat-file -h; git commit -m x'), 'ALLOW');
      assert.equal(run('git -P config --get user.name; git commit -m x'), 'ALLOW');
      assert.equal(run('git commit -m x; git -P cat-file -p HEAD:a.txt'), 'ALLOW');
      assert.equal(run('git -c core.sshCommand=/DUMMY/program commit -h; git commit -m x'), 'UNKNOWN');
      assert.equal(run(configuredReader + '; git add .env'), 'FORBIDDEN');
      fs.writeFileSync(configPath, baseConfig + '\n[core]\n\tsshCommand =\n');
      assert.equal(run(configuredReader), 'ALLOW');
      assert.equal(run(configuredReader, { GIT_SSH: '/DUMMY/lower' }), 'ALLOW');
      const credentialCases = [
        ['[credential]\n helper = /DUMMY/program\n', 'UNKNOWN'],
        ['[credential]\n helper = /DUMMY/program\n helper =\n', 'ALLOW'],
        ['[credential]\n helper =\n helper = /DUMMY/program\n', 'UNKNOWN'],
        ['[credential "https://example.invalid/Case"]\n helper = /DUMMY/program\n[credential "https://example.invalid/case"]\n helper =\n', 'UNKNOWN'],
        ['[credential "https://example.invalid/Case"]\n helper = /DUMMY/program\n helper =\n', 'ALLOW'],
        ['[credential "https://example.invalid/Case"]\n helper = /DUMMY/program\n[credential]\n helper =\n', 'ALLOW'],
        ['[credential]\n helper = /DUMMY/program\n[credential "https://example.invalid/Case"]\n helper =\n', 'UNKNOWN'],
      ];
      for (const [text, expected] of credentialCases) {
        fs.writeFileSync(configPath, baseConfig + '\n' + text);
        assert.equal(run(configuredReader), expected);
      }
      fs.writeFileSync(configPath, baseConfig + '\n[credential]\n helper = /DUMMY/program\n');
      assert.equal(run('git -P cat-file -h; git commit -m x'), 'ALLOW');
      assert.equal(run('git -P config --get user.name; git commit -m x'), 'ALLOW');
      assert.equal(run('git commit -m x; git -P cat-file -p HEAD:a.txt'), 'ALLOW');
      assert.equal(run('git -c credential.helper=/DUMMY/program commit -h; git commit -m x'), qualifiedGit254 ? 'ALLOW' : 'UNKNOWN');
      assert.equal(run(configuredReader + '; git add .env'), 'FORBIDDEN');
    } finally { fs.writeFileSync(configPath, baseConfig); }
    try {
      const exact = 'git -P diff --no-ext-diff --no-textconv HEAD; git commit -m x';
      for (const [values, expected] of [
        [['/DUMMY/proxy'], 'UNKNOWN'], [['/DUMMY/proxy for example.invalid'], 'UNKNOWN'],
        [['none'], 'ALLOW'], [[''], 'ALLOW'], [['none', '/DUMMY/proxy'], 'ALLOW'],
        [['none for example.invalid', '/DUMMY/proxy for example.invalid'], 'ALLOW'],
        [['none for example.invalid', '/DUMMY/proxy for other.invalid'], 'UNKNOWN'],
        [['/DUMMY/proxy', 'none'], 'UNKNOWN'],
      ]) {
        fs.writeFileSync(configPath, baseConfig + '\n[core]\n' + values.map(value => ' gitProxy = ' + value + '\n').join(''));
        assert.equal(run(exact), expected);
      }
      fs.writeFileSync(configPath, baseConfig + '\n[core]\n gitProxy = /DUMMY/proxy\n');
      assert.equal(run(exact, { GIT_PROXY_COMMAND: '' }), 'ALLOW');
      assert.equal(run(exact, { GIT_PROXY_COMMAND: 'none' }), 'UNKNOWN');
      assert.equal(run('git -P diff -h; git commit -m x'), 'ALLOW');
      assert.equal(run('git commit -m x; git -P diff --no-ext-diff --no-textconv HEAD'), 'ALLOW');
      assert.equal(run(exact + '; git add .env'), 'FORBIDDEN');
      fs.writeFileSync(configPath, baseConfig);
      const both = { SSH_ASKPASS: '/DUMMY/helper', GIT_ASKPASS: '', GIT_SSH_COMMAND: '' };
      assert.equal(run('git -P status; git commit -m x', both), process.platform !== 'win32' && qualifiedGit254 ? 'ALLOW' : 'UNKNOWN');
      assert.equal(run('git -P status; git commit -m x', { SSH_ASKPASS: '/DUMMY/helper', GIT_ASKPASS: '' }), 'UNKNOWN');
      assert.equal(run('git -P status; git commit -m x', { SSH_ASKPASS: '/DUMMY/helper', GIT_SSH_COMMAND: '' }), 'UNKNOWN');
      assert.equal(run('SSH_ASKPASS=/DUMMY/changed git -P status; git commit -m x', both), 'UNKNOWN');
      assert.equal(run('git -P status; git commit -m x; git add .env', both), 'FORBIDDEN');
    } finally { fs.writeFileSync(configPath, baseConfig); }
    assert.equal(run(configuredReader), 'ALLOW');
    t.diagnostic(`owned fixture: ${actualHookCalls} actual secret-git Hook calls; no proposed command executed`);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
