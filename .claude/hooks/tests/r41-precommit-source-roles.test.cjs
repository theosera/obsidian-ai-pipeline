'use strict';
// Pure operation/source contracts; callback/verifier bodies are never executed.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const hooks = path.resolve(process.argv[2] || path.join(__dirname, '..'));
const readers = require(path.join(hooks, 'lib/git-precommit-readers.cjs'));
const word = text => ({ text, literalValue: text, dynamic: false, dynamicMaySplit: false });
const environment = { PATH: '/DUMMY/bin', HOME: '/DUMMY/home' };
function fixture(sub, args = [], globals = ['-P']) {
  const g = { sub, args: args.map(a => typeof a === 'string' ? word(a) : a), configs: [], configEnvs: [], pagerDisabled: globals.includes('-P') };
  const invocation = { nameWord: word('git'), args: [...globals.map(word), word(sub), ...g.args],
    gitPreCommitEnvironmentSources: readers.environmentSources(environment), gitPreCommitEnvironmentUnknown: false };
  return { g, invocation };
}
function assess(sub, args, entries = [], hook = false) {
  const f = fixture(sub, args);
  return readers.assessReader(f.g, f.invocation, '/DUMMY/repo', { environment, executable: '/DUMMY/git', isTrusted: () => true,
    probe: () => new Map(entries), indexHook: () => hook });
}
test('index reader callback presence/unknown stops; absence and real stdout query remain', () => {
  assert.equal(assess('status', ['--short']), null);
  assert.match(assess('status', ['--short'], [], true).reason, /post-index-change/);
  assert.match(assess('status', ['--short'], [], null).reason, /post-index-change/);
  assert.equal(assess('config', ['--get', 'user.name'], [], true), null);
  const f = fixture('status', ['-h']); f.g.terminal = true; f.g.helpKind = 'stdout';
  assert.equal(readers.assessReader(f.g, f.invocation, '/DUMMY/repo', { environment, executable: '/DUMMY/git', isTrusted: () => true,
    probe: () => new Map(), indexHook: () => { throw new Error('inactive callback inspected'); } }), null);
});
test('configured post-index events preserve multiple event values and enabled selection', () => {
  const conf = readers.parseConfigOutput('local\0hook.dummy.event\npost-index-change\0local\0hook.dummy.event\npre-commit\0');
  assert.equal(readers.configuredPostIndex(conf), true);
  const disabled = readers.parseConfigOutput('local\0hook.dummy.event\npost-index-change\0local\0hook.dummy.enabled\nfalse\0');
  assert.equal(readers.configuredPostIndex(disabled), false);
  const collision = readers.parseConfigOutput('local\0hook.Foo.event\npost-index-change\0local\0hook.foo.enabled\nfalse\0');
  assert.equal(readers.configuredPostIndex(collision), true);
  assert.equal(assess('status', [], [['hook.dummy.event', 'pre-commit']], false), null);
  assert.match(assess('status', [], [['hook.dummy.event', 'post-index-change']]).reason, /configured post-index/);
});
test('hook lookup resolves selected path and checks execute permission without reading a body', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'r41-hook-role-'));
  try {
    const hook = path.join(root, 'post-index-change'); fs.writeFileSync(hook, 'DUMMY DATA\n', { mode: 0o600 });
    const context = { executable: '/DUMMY/git', globals: ['-C', '/DUMMY/target'], cwd: '/DUMMY/repo', env: {} };
    let argv;
    const spawn = (exe, args) => { argv = args; return { status: 0, stdout: hook + '\n' }; };
    assert.equal(readers.indexHookSource(context, spawn), false);
    fs.chmodSync(hook, 0o700); assert.equal(readers.indexHookSource(context, spawn), true);
    assert.deepEqual(argv, ['-C', '/DUMMY/target', '--no-pager', '--no-lazy-fetch', 'rev-parse', '--path-format=absolute', '--git-path', 'hooks/post-index-change']);
    assert.equal(readers.indexHookSource(context, () => ({ status: 0, stdout: '/DUMMY/path\nextra\n' })), null);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
test('hook inspection overrides traditional hooks and optional signature mode is separate', () => {
  assert.ok(readers.inspectionArgs(['diff', '--cached']).includes('core.hooksPath=/dev/null'));
  assert.match(assess('log', ['-1', '--format=%G?']).reason, /signature-format/);
  assert.equal(assess('log', ['-1', '--format=%h']), null);
  assert.equal(assess('log', ['--grep', '--format=%G?', '-1']), null);
  assert.equal(assess('log', ['--', '--format=%G?']), null);
  assert.match(assess('log', ['--show-signature']).reason, /signature-verifier/);
  assert.equal(assess('log', ['--no-show-signature'], [['log.showsignature', 'true']]), null);
  assert.match(assess('log', ['--no-show-signature', '--format=%G?']).reason, /signature-format/);
});
test('pretty escapes, aliases and default selectors preserve active versus unused sources', () => {
  assert.equal(assess('log', ['--format=%%G?']), null);
  assert.match(assess('log', ['--format=%%%G?']).reason, /signature-format/);
  assert.match(assess('show', ['--format=%+G?']).reason, /signature-format/);
  assert.match(assess('log', [], [['format.pretty', 'format:%G?']]).reason, /signature-format/);
  assert.equal(assess('log', ['--format=%h'], [['format.pretty', 'format:%G?']]), null);
  assert.match(assess('log', ['--pretty=dummy'], [['pretty.dummy', 'format:%G?']]).reason, /signature-format/);
  assert.equal(assess('status', [], [['format.pretty', 'format:%G?']], false), null);
});
test('selected inline source keys are replayed while config-env unknown sources stop', () => {
  const f = fixture('log', [], ['-c', 'format.pretty=%G?', '-P']);
  assert.deepEqual(readers.targetGlobals(f.g, f.invocation), ['-c', 'format.pretty=%G?']);
  const e = fixture('log', [], ['--config-env=format.pretty=DUMMY', '-P']);
  assert.equal(readers.targetGlobals(e.g, e.invocation), null);
});

test('irrelevant inherited helpers are removed only from inspection, with actual values preserved', () => {
  const names = ['GIT_EDITOR', 'GIT_SEQUENCE_EDITOR', 'GIT_SSH', 'GIT_SSH_COMMAND', 'GIT_SSH_VARIANT', 'GIT_ASKPASS', 'GIT_MERGE_AUTOEDIT'];
  const original = { ...environment, ...Object.fromEntries(names.map(name => [name, 'DUMMY'])) };
  const inspected = readers.safeInspectionEnvironment(original);
  assert.ok(inspected); for (const name of names) { assert.equal(inspected[name], undefined); assert.equal(original[name], 'DUMMY'); }
  assert.equal(readers.safeInspectionEnvironment({ ...original, GIT_UNKNOWN_DUMMY: 'x' }), null);
  assert.equal(readers.safeInspectionEnvironment({ ...original, GIT_TRACE: '/DUMMY/sink' }), null);
  const f = fixture('status'); f.invocation.gitPreCommitEnvironmentSources = readers.environmentSources(original);
  const context = readers.readerContext(f.g, f.invocation, '/DUMMY/repo', { environment: original, executable: '/DUMMY/git', isTrusted: () => true });
  assert.ok(context); assert.equal(context.env.GIT_EDITOR, undefined);
  assert.equal(f.invocation.gitPreCommitEnvironmentSources.find(x => x.name === 'GIT_EDITOR').word.literalValue, 'DUMMY');
});
test('only selected dynamic format is unknown; consumed DATA and later literal override remain ordinary', () => {
  const unknown = { text: '--format=\0', dynamic: true, dynamicMaySplit: false };
  assert.equal(assess('log', ['--grep', unknown, '-1']), null);
  assert.match(assess('log', [unknown, '-1']).reason, /signature-format/);
  assert.equal(assess('log', [unknown, '--format=%h', '-1']), null);
  assert.match(assess('log', ['--format=%h', unknown, '-1']).reason, /signature-format/);
  assert.equal(assess('log', [{ ...unknown, literalValue: '--format=%h' }, '-1']), null);
  assert.equal(assess('log', ['--', unknown]), null);
});
