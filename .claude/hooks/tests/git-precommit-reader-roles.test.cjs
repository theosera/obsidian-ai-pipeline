'use strict';

// Pure source/operation contracts: no Git child, fixture, network, or native command.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const hooks = path.resolve(process.argv[2] || path.join(__dirname, '..'));
const readers = require(path.join(hooks, 'lib/git-precommit-readers.cjs'));

const w = text => ({ text, literalValue: text, dynamic: false, dynamicMaySplit: false });
const dynamic = () => ({ text: '$DUMMY', dynamic: true, dynamicMaySplit: false });
const baseline = { PATH: '/DUMMY/trusted/bin', HOME: '/DUMMY/owned/home', DUMMY_UNRELATED: 'keep' };
function fixture(sub, args = [], globals = [], env = {}) {
  const g = { sub, args: args.map(a => typeof a === 'string' ? w(a) : a), configs: [], configEnvs: [],
    pagerDisabled: globals.includes('--no-pager'), pagerForced: globals.includes('--paginate') };
  const invocation = { nameWord: w('git'), args: [...globals.map(w), w(sub), ...g.args],
    gitPreCommitEnvironmentSources: readers.environmentSources({ ...baseline, ...env }), gitPreCommitEnvironmentUnknown: false };
  return { g, invocation };
}
function assess(f, entries = [], extra = {}) {
  return readers.assessReader(f.g, f.invocation, '/DUMMY/owned/repo', {
    environment: baseline, executable: '/DUMMY/trusted/git', isTrusted: () => true,
    probe: () => new Map(entries), indexHook: () => false, ...extra,
  });
}
const category = result => result?.category || 'ALLOW';

test('clean status/getter remain allowed; default-paged diff is explicitly unknown', () => {
  assert.equal(assess(fixture('status')), null);
  assert.equal(assess(fixture('config', ['--get', 'user.name'])), null);
  assert.equal(category(assess(fixture('diff'))), 'UNKNOWN');
  assert.match(assess(fixture('diff')).reason, /default-pager/);
});
test('real no-pager, per-command disable, and exact no-pager strings differ from unknown default', () => {
  assert.equal(assess(fixture('diff', [], ['--no-pager'])), null);
  assert.equal(assess(fixture('diff'), [['pager.diff', 'false']]), null);
  assert.equal(assess(fixture('diff', [], [], { GIT_PAGER: '' })), null);
  assert.equal(assess(fixture('diff', [], [], { GIT_PAGER: 'cat' })), null);
  assert.equal(category(assess(fixture('diff'), [['core.pager', '/DUMMY/helper']])), 'UNKNOWN');
});
test('pager command setting can activate a normally unpaged getter', () => {
  assert.equal(category(assess(fixture('config', ['--get', 'user.name']), [['pager.config', '/DUMMY/helper']])), 'UNKNOWN');
  assert.equal(assess(fixture('config', ['--get', 'user.name'], ['--no-pager']), [['pager.config', '/DUMMY/helper']]), null);
});
test('fsmonitor is not excluded from object/attribute readers by their subcommand label', () => {
  const cfg = [['core.fsmonitor', '/DUMMY/helper']];
  assert.equal(category(assess(fixture('status'), cfg)), 'UNKNOWN');
  assert.equal(category(assess(fixture('rev-parse', ['HEAD']), cfg)), 'UNKNOWN');
  assert.equal(assess(fixture('config', ['--get', 'user.name'], ['--no-pager']), cfg), null);
  for (const disabled of ['false', 'no', 'off', '0', '']) assert.equal(assess(fixture('status'), [['core.fsmonitor', disabled]]), null);
  for (const sub of ['log', 'show', 'diff-tree', 'check-attr', 'check-ignore', 'grep', 'blame', 'rev-list']) {
    assert.match(assess(fixture(sub, [], ['--no-pager']), cfg).reason, /fsmonitor/);
    assert.equal(assess(fixture(sub, [], ['--no-pager']), [['core.fsmonitor', 'false']]), null);
  }
});
test('driver command and textconv are different active roles', () => {
  const cfg = [['diff.dummy.command', '/DUMMY/external'], ['diff.dummy.textconv', '/DUMMY/textconv']];
  assert.equal(category(assess(fixture('diff', [], ['--no-pager']), cfg)), 'UNKNOWN');
  assert.equal(assess(fixture('status'), cfg), null);
  assert.equal(assess(fixture('diff', ['--no-ext-diff', '--no-textconv'], ['--no-pager']), cfg), null);
});
test('blame defaults and grep selected textconv are not missed by the index table', () => {
  const cfg = [['diff.dummy.textconv', '/DUMMY/textconv']];
  assert.equal(category(assess(fixture('blame', ['a.txt'], ['--no-pager']), cfg)), 'UNKNOWN');
  assert.equal(assess(fixture('blame', ['--no-textconv', 'a.txt'], ['--no-pager']), cfg), null);
  assert.equal(category(assess(fixture('grep', ['--textconv', '-e', 'ordinary'], ['--no-pager']), cfg)), 'UNKNOWN');
  assert.equal(assess(fixture('grep', ['-e', '--textconv'], ['--no-pager']), cfg), null);
  assert.equal(assess(fixture('grep', ['-ne', '--textconv'], ['--no-pager']), cfg), null);
  assert.equal(category(assess(fixture('grep', ['--textc', 'ordinary'], ['--no-pager']), cfg)), 'UNKNOWN');
  assert.equal(assess(fixture('grep', ['--textconv', '--no-textconv', '-e', 'ordinary'], ['--no-pager']), cfg), null);
  assert.equal(category(assess(fixture('grep', ['--textconv', 'ordinary', '--no-textconv'], ['--no-pager']), cfg)), 'UNKNOWN');
  assert.equal(readers.operationRole(fixture('grep', ['ordinary', '--textconv']).g).textconv, false);
  assert.equal(category(assess(fixture('grep', ['ordinary', '--textconv'], ['--no-pager']), cfg)), 'UNKNOWN');
  assert.equal(assess(fixture('grep', ['ordinary', '--', '--textconv'], ['--no-pager']), cfg), null);
  assert.equal(assess(fixture('cat-file', ['--path', '--textconv', '-p', 'HEAD:a'], ['--no-pager']), cfg), null);
});
test('last diff toggle wins; option-looking required values and post-- operands are DATA', () => {
  const cfg = [['diff.external', '/DUMMY/helper']];
  assert.equal(assess(fixture('diff', ['--ext-diff', '--no-ext-diff'], ['--no-pager']), cfg), null);
  assert.equal(category(assess(fixture('diff', ['--no-ext-diff', '--ext-diff'], ['--no-pager']), cfg)), 'UNKNOWN');
  assert.equal(category(assess(fixture('diff', ['-G', '--no-ext-diff'], ['--no-pager']), cfg)), 'UNKNOWN');
  assert.equal(assess(fixture('diff', ['--no-ext-diff', '--', '--ext-diff'], ['--no-pager']), cfg), null);
});
test('unknown scalar may be an option; a consumed scalar cannot change option selection', () => {
  assert.equal(category(assess(fixture('diff', [dynamic()], ['--no-pager']))), 'UNKNOWN');
  assert.equal(assess(fixture('diff', ['--no-ext-diff', '-G', dynamic()], ['--no-pager'])), null);
});
test('output-file and uninspected reader modes are not declared pure from the subcommand name', () => {
  assert.equal(category(assess(fixture('diff', ['--output=/DUMMY/file'], ['--no-pager']))), 'UNKNOWN');
  assert.equal(category(assess(fixture('cat-file', ['--filters', 'HEAD:a'], ['--no-pager']))), 'UNKNOWN');
  assert.equal(category(assess(fixture('cat-file', ['--unsupported', 'HEAD:a'], ['--no-pager']))), 'UNKNOWN');
  assert.equal(category(assess(fixture('cat-file', ['--textc', 'HEAD:a'], ['--no-pager']))), 'UNKNOWN');
  assert.equal(category(assess(fixture('help', ['diff']))), 'UNKNOWN');
  assert.equal(category(assess(fixture('remote', ['show', 'origin']))), 'UNKNOWN');
});
test('stdout query is helper-inactive only after source/trace qualification', () => {
  const f = fixture('diff', ['-h']); f.g.terminal = true; f.g.helpKind = 'stdout';
  assert.equal(assess(f), null);
  assert.equal(category(assess(f, [['trace2.eventtarget', '/DUMMY/sink']])), 'UNKNOWN');
  assert.equal(category(assess(f, [['pager.diff', '/DUMMY/pager']])), 'UNKNOWN');
  assert.equal(assess(f, [['pager.diff', 'cat']]), null);
  f.g.helpKind = 'manual';
  assert.equal(category(assess(f)), 'UNKNOWN');
  f.g.helpKind = 'stdout'; f.g.pagerForced = true;
  assert.equal(category(assess(f)), 'UNKNOWN');
});
test('global forced pager skips per-command pager selection', () => {
  const cfg = [['pager.diff', 'cat'], ['core.pager', '/DUMMY/actual-helper']];
  assert.equal(assess(fixture('diff'), cfg), null);
  assert.equal(category(assess(fixture('diff', [], ['--paginate']), cfg)), 'UNKNOWN');
  assert.equal(assess(fixture('diff', [], ['--paginate'], { GIT_PAGER: 'cat' }), cfg), null);
});
test('version does not select conditional or per-command pager unless globally forced', () => {
  const cfg = readers.parseConfigOutput('global\0includeif.onbranch:main.path\n/DUMMY/source\0global\0pager.version\n/DUMMY/helper\0');
  const off = { GIT_TRACE2: '0', GIT_TRACE2_EVENT: '0', GIT_TRACE2_PERF: '0' };
  assert.equal(assess(fixture('version', [], [], off), [], { probe: () => cfg }), null);
  assert.match(assess(fixture('version', [], ['--paginate'], off), [], { probe: () => cfg }).reason, /early-pager-source/);
  assert.match(assess(fixture('version'), [], { probe: () => cfg }).reason, /early-trace-source/);
});
test('single consumed grep scalars and fixed-prefix operands cannot become mode flags', () => {
  const scalar = { text: '\0', raw: '"$PAT"', dynamic: true, dynamicMaySplit: false };
  const attached = { ...scalar, text: '-eprefix\0' };
  const operand = { ...scalar, text: 'prefix\0' };
  assert.equal(assess(fixture('grep', ['-e', scalar, '--', 'a.txt'], ['--no-pager'])), null);
  assert.equal(assess(fixture('grep', [attached, '--', 'a.txt'], ['--no-pager'])), null);
  assert.equal(readers.operationRole(fixture('grep', [operand, '--textconv']).g).textconv, false);
  assert.equal(category(assess(fixture('grep', [operand, '--textconv'], ['--no-pager']))), 'UNKNOWN');
  assert.equal(assess(fixture('grep', [operand, '--', '--textconv'], ['--no-pager']), [['diff.dummy.textconv', '/DUMMY/helper']]), null);
  assert.equal(category(assess(fixture('grep', [scalar], ['--no-pager']))), 'UNKNOWN');
  assert.equal(category(assess(fixture('grep', ['-e', { ...scalar, dynamicMaySplit: true }], ['--no-pager']))), 'UNKNOWN');
});
test('possibly empty attached values join both option arities instead of hiding a later source', () => {
  const scalar = { text: '\0', dynamic: true, dynamicMaySplit: false };
  const logPattern = { ...scalar, text: '-G\0' };
  const logFormat = { ...scalar, text: '--format=\0' };
  assert.equal(assess(fixture('log', [logPattern, '-1'], ['--no-pager'])), null);
  // Unknown format DATA may select signature verification, unlike an unknown grep pattern.
  assert.equal(category(assess(fixture('log', [logFormat, '-1'], ['--no-pager']))), 'UNKNOWN');
  const cfg = [['diff.dummy.textconv', '/DUMMY/helper']];
  assert.equal(category(assess(fixture('log', [logPattern, '--no-textconv'], ['--no-pager']), cfg)), 'UNKNOWN');
  assert.equal(category(assess(fixture('grep', ['--textconv', { ...scalar, text: '-e\0' }, '--no-textconv'], ['--no-pager']), cfg)), 'UNKNOWN');
});
test('known grep inactive abbreviation and exact later usage use the common role proof', () => {
  assert.equal(assess(fixture('grep', ['-O/DUMMY/helper', '--no-open-files', 'ordinary'], ['--no-pager'])), null);
  const usage = fixture('grep', ['-O/DUMMY/helper', '--help'], ['--no-pager']);
  assert.equal(assess(usage), null);
  assert.equal(category(assess(usage, [['trace2.eventtarget', '/DUMMY/sink']])), 'UNKNOWN');
});
test('grep usage keeps preceding file callbacks distinct from consumed option-looking DATA', () => {
  for (const args of [['-nf', '/DUMMY/not-opened', '--help'], ['-fn', '--help'], ['-f/DUMMY/not-opened', '--help']]) {
    assert.equal(category(assess(fixture('grep', args, ['--no-pager']))), 'UNKNOWN');
  }
  for (const args of [['-e', '-f', '--help'], ['-ne', '-f', '--help'], ['-e-f', '--help']]) {
    assert.equal(assess(fixture('grep', args, ['--no-pager'])), null);
  }
  assert.equal(category(assess(fixture('grep', ['--context', '-f', '--help'], ['--no-pager']))), 'UNKNOWN');
  assert.equal(category(assess(fixture('grep', ['-e', '-f', '--help'], ['--no-pager']), [['trace2.eventtarget', '/DUMMY/sink']])), 'UNKNOWN');
});
test('grep quiet suppresses only the default pager after actual option-role selection', () => {
  for (const args of [['--quiet', 'needle'], ['-q', 'needle'], ['-nqe', 'needle', '--', 'a.txt']]) {
    assert.equal(assess(fixture('grep', args)), null);
  }
  for (const args of [['--quiet', '--no-quiet', 'needle'], ['-e', '--quiet', 'needle'], ['--', 'needle', '--quiet']]) {
    assert.match(assess(fixture('grep', args)).reason, /default-pager/);
  }
  assert.match(assess(fixture('grep', ['--quiet', 'needle']), [['pager.grep', '/DUMMY/helper']]).reason, /pager/);
  assert.match(assess(fixture('grep', ['--quiet', 'needle'], ['--paginate'])).reason, /default-pager/);
  assert.match(assess(fixture('grep', ['--quiet', 'needle']), [['core.fsmonitor', '/DUMMY/helper']]).reason, /fsmonitor/);
  assert.match(assess(fixture('grep', ['--quiet', 'needle']), [['trace2.eventtarget', '/DUMMY/sink']]).reason, /trace2/);
});
test('invalid numeric context and implicit dash paths are mode-unknown, not default-pager evidence', () => {
  for (const args of [['--context', '--open-files-in-pager', 'needle'], ['-Cbogus', 'needle'], ['-nAbogus', 'needle'],
    ['--before-context', 'bogus', 'needle'], ['--after-context=bogus', 'needle'], ['needle', '-O/DUMMY/helper']]) {
    assert.equal(readers.operationRole(fixture('grep', args).g).unknown, true);
    assert.match(assess(fixture('grep', args, ['--no-pager'])).reason, /mode \/ option/);
  }
  for (const args of [['--context', '1', 'needle'], ['-C+1', 'needle'], ['-e', '--context', '--', 'a.txt'],
    ['needle', '--', '-O/DUMMY/path'], ['-e', 'needle', '--', '--quiet']]) {
    assert.equal(assess(fixture('grep', args, ['--no-pager'])), null);
  }
});
test('grep NODASH expression tokens do not turn a later -e into an implicit dash path', () => {
  const args = ['(', '-e', 'needle', ')', '--', 'a.txt'];
  assert.equal(readers.operationRole(fixture('grep', args).g).unknown, false);
  assert.match(assess(fixture('grep', args)).reason, /default-pager/);
  assert.equal(assess(fixture('grep', args, ['--no-pager'])), null);
});
test('only exact fixed-consumer commit -h can omit dormant non-source inline keys', () => {
  const f = fixture('commit', ['-h'], ['-c', 'foo.bar=unused']); f.g.terminal = true; f.g.helpKind = 'stdout';
  assert.equal(assess(f, [], { commitUsageConsumerQualified: true }), null);
  assert.equal(category(assess(f)), 'UNKNOWN');
  f.g.args.push(w('--quiet')); f.invocation.args.push(w('--quiet'));
  assert.equal(category(assess(f, [], { commitUsageConsumerQualified: true })), 'UNKNOWN');
  for (const setting of ['include.path=/DUMMY/not-opened', 'includeIf.onbranch:main.path=/DUMMY/not-opened',
    'remote.origin.url=/DUMMY/source-selector', 'core.worktree=/DUMMY/not-selected', 'extensions.worktreeConfig=true']) {
    const bad = fixture('commit', ['-h'], ['-c', setting]); bad.g.terminal = true; bad.g.helpKind = 'stdout';
    assert.equal(category(assess(bad, [], { commitUsageConsumerQualified: true, probe: () => { throw new Error('must not probe'); } })), 'UNKNOWN');
  }
  const pager = fixture('commit', ['-h'], ['-c', 'pager.commit=/DUMMY/first', '-c', 'pager.commit=cat']);
  pager.g.terminal = true; pager.g.helpKind = 'stdout';
  assert.deepEqual(readers.targetGlobals(pager.g, pager.invocation, true), ['-c', 'pager.commit=/DUMMY/first', '-c', 'pager.commit=cat']);
  const referenced = fixture('commit', ['-h'], ['--config-env=pager.commit=CFG']); referenced.g.terminal = true; referenced.g.helpKind = 'stdout';
  assert.equal(category(assess(referenced, [], { commitUsageConsumerQualified: true })), 'UNKNOWN');
});
test('probe reconstructs exact selected values and removals without inheriting missing HOME', () => {
  const f = fixture('status');
  f.invocation.gitPreCommitEnvironmentSources = [{ name: 'PATH', word: w(baseline.PATH) }, { name: 'GIT_INDEX_FILE', word: w('/DUMMY/index') }];
  const ctx = readers.readerContext(f.g, f.invocation, '/DUMMY/repo', { environment: baseline, executable: '/DUMMY/git', isTrusted: () => true });
  assert.equal(Object.hasOwn(ctx.env, 'HOME'), false);
  assert.equal(ctx.env.GIT_INDEX_FILE, '/DUMMY/index');
  assert.equal(ctx.env.DUMMY_UNRELATED, 'keep');
});
test('unknown snapshot, duplicate names, changed PATH and EXEC_PATH stop before a probe', () => {
  const mutations = [f => { f.invocation.gitPreCommitEnvironmentUnknown = true; },
    f => { f.invocation.gitPreCommitEnvironmentSources.push({ name: 'PATH', word: w(baseline.PATH) }); },
    f => { f.invocation.gitPreCommitEnvironmentSources.find(s => s.name === 'PATH').word = w('/DUMMY/other'); },
    f => { f.invocation.gitPreCommitEnvironmentSources.push({ name: 'GIT_EXEC_PATH', word: w('/DUMMY/helper-dir') }); },
    f => { f.invocation.gitPreCommitEnvironmentSources.find(s => s.name === 'HOME').word = dynamic(); }];
  for (const mutate of mutations) {
    const f = fixture('status'); mutate(f);
    assert.equal(category(assess(f, [], { probe: () => { throw new Error('must not probe'); } })), 'UNKNOWN');
  }
});
test('unknown Git environment and diagnostic sinks stop before spawning, with no values exported', () => {
  for (const env of [{ GIT_TRACE: '/DUMMY/private-sink' }, { GIT_TRACE2_EVENT: 'af_unix:/DUMMY/socket' },
    { GIT_UNKNOWN_NEW_FEATURE: 'DUMMY' }, { HOME: '/DUMMY/other-private-home' },
    { GIT_CONFIG_GLOBAL: '/DUMMY/private-config' }, { GIT_CONFIG_PARAMETERS: "'include.path'='/DUMMY/config'" }]) {
    const result = assess(fixture('status', [], [], env), [], { probe: () => { throw new Error('must not probe'); } });
    assert.equal(category(result), 'UNKNOWN'); assert.equal(JSON.stringify(result).includes('private'), false);
  }
  assert.equal(readers.safeInspectionEnvironment({ GIT_TRACE: '/DUMMY/sink' }), null);
  assert.equal(readers.safeInspectionEnvironment({ GIT_UNKNOWN_NEW_FEATURE: 'DUMMY' }), null);
});
test('internal Git disables all Trace2 config fallbacks, including the first version query', () => {
  const safe = readers.safeInspectionEnvironment({ HOME: '/DUMMY/home', GIT_TRACE: '0', GIT_CONFIG_NOSYSTEM: '1' });
  assert.equal(Object.hasOwn(safe, 'GIT_TRACE'), false);
  assert.deepEqual([safe.GIT_TRACE2, safe.GIT_TRACE2_EVENT, safe.GIT_TRACE2_PERF], ['0', '0', '0']);
  assert.equal(category(assess(fixture('status'), [['trace2.eventtarget', '/DUMMY/file'] ])), 'UNKNOWN');
  assert.equal(assess(fixture('status'), [['trace2.eventtarget', 'false']]), null);
  assert.equal(assess(fixture('status', [], [], { GIT_TRACE2_EVENT: '0' }), [['trace2.eventtarget', '/DUMMY/file']]), null);
  assert.equal(assess(fixture('status', [], [], { GIT_TRACE2_EVENT: 'FALSE' }), [['trace2.eventtarget', '/DUMMY/file']]), null);
  const local = readers.parseConfigOutput('local\0trace2.eventtarget\n/DUMMY/unused-local-sink\0');
  assert.equal(assess(fixture('status'), [], { probe: () => local }), null);
  const early = readers.parseConfigOutput('global\0trace2.eventtarget\n/DUMMY/active-global-sink\0local\0trace2.eventtarget\n0\0');
  assert.equal(category(assess(fixture('status'), [], { probe: () => early })), 'UNKNOWN');
});
test('conditional includes keep early trace and pager uncertainties separate', () => {
  const cfg = readers.parseConfigOutput('global\0includeif.onbranch:main.path\n/DUMMY/conditional\0');
  assert.match(assess(fixture('status', [], ['--no-pager']), [], { probe: () => cfg }).reason, /early-trace-source/);
  const off = { GIT_TRACE2: '0', GIT_TRACE2_EVENT: 'FALSE', GIT_TRACE2_PERF: '0' };
  assert.equal(assess(fixture('status', [], ['--no-pager'], off), [], { probe: () => cfg }), null);
  assert.match(assess(fixture('status', [], [], off), [], { probe: () => cfg }).reason, /early-pager-source/);
  assert.equal(assess(fixture('status', [], [], { ...off, GIT_PAGER: 'cat' }), [], { probe: () => cfg }), null);
  assert.equal(category(assess(fixture('status', [], ['--no-pager'], { ...off, GIT_TRACE2_EVENT: '' }), [], { probe: () => cfg })), 'UNKNOWN');
});
test('numbered config only admits selected ordinary keys; zero leaves unused KEY/VALUE as DATA', () => {
  assert.equal(assess(fixture('status', [], [], { GIT_CONFIG_COUNT: '0', GIT_CONFIG_KEY_0: 'include.path', GIT_CONFIG_VALUE_0: '/DUMMY/not-read' })), null);
  assert.equal(assess(fixture('status', [], [], { GIT_CONFIG_COUNT: '1', GIT_CONFIG_KEY_0: 'user.name', GIT_CONFIG_VALUE_0: 'DUMMY' })), null);
  assert.equal(category(assess(fixture('status', [], [], { GIT_CONFIG_COUNT: '1', GIT_CONFIG_KEY_0: 'include.path', GIT_CONFIG_VALUE_0: '/DUMMY/not-read' }))), 'UNKNOWN');
});
test('absolute Git must match the pinned executable; trusted name alone is insufficient', () => {
  const f = fixture('status'); f.invocation.nameWord = w('/DUMMY/other/git');
  assert.equal(category(assess(f, [], { realpath: p => p })), 'UNKNOWN');
});
test('command -p default search is not confused with the hook PATH lookup', () => {
  const f = fixture('status'); f.invocation.commandDefaultSearch = true;
  assert.equal(category(assess(f, [], { probe: () => { throw new Error('must not probe'); } })), 'UNKNOWN');
  f.invocation.commandDefaultSearch = false;
  assert.equal(assess(f), null);
  f.invocation.commandDefaultSearch = true; f.invocation.nameWord = w('/DUMMY/trusted/git');
  assert.equal(assess(f, [], { realpath: p => p }), null);
});
test('target globals preserve repeated -C/value roles; display settings cannot select helpers', () => {
  const f = fixture('status', [], ['-C', '/DUMMY/repo', '-C', '', '--git-dir=/DUMMY/git-dir', '-c', 'user.name=DUMMY', '--no-pager']);
  assert.deepEqual(readers.targetGlobals(f.g, f.invocation), ['-C', '/DUMMY/repo', '-C', '', '--git-dir=/DUMMY/git-dir']);
  const unsafe = fixture('status', [], ['-c', 'core.fsmonitor=/DUMMY/helper']);
  assert.equal(readers.targetGlobals(unsafe.g, unsafe.invocation), null);
});
test('bounded probe uses no pager, exact context, helper-only regex and no fsmonitor override', () => {
  const ctx = { executable: '/DUMMY/git', globals: ['-C', '/DUMMY/repo'], cwd: '/DUMMY', env: { DUMMY: 'only' } };
  let captured;
  assert.deepEqual(readers.probeConfig(ctx, (...args) => { captured = args; return { status: 0, stdout: Buffer.from('local\0core.fsmonitor\nfalse\0') }; }), new Map([['core.fsmonitor', 'false']]));
  assert.equal(captured[0], '/DUMMY/git');
  assert.deepEqual(captured[1].slice(0, 8), ['-C', '/DUMMY/repo', '--no-pager', '--no-lazy-fetch', 'config', '--show-scope', '--null', '--get-regexp']);
  assert.equal(captured[1].includes('core.fsmonitor=false'), false);
  assert.equal(captured[2].maxBuffer, 65536); assert.equal(captured[2].timeout, 2000);
  assert.deepEqual(captured[2].env, ctx.env);
});
test('absent status1 differs from timeout/error/partial data and malformed framing', () => {
  const ctx = { executable: '/DUMMY/git', globals: [], cwd: '/DUMMY', env: {} };
  assert.deepEqual(readers.probeConfig(ctx, () => ({ status: 1, stdout: Buffer.alloc(0) })), new Map());
  for (const response of [{ status: 2 }, { status: 1, stdout: Buffer.from('partial') }, { status: null, signal: 'SIGTERM' }, { status: 0, error: new Error('timeout') }]) {
    assert.equal(readers.probeConfig(ctx, () => response), null);
  }
  for (const output of ['local\0core.fsmonitor\nfalse', 'local\0core.fsmonitor\0', 'local\0credential.username\nDUMMY\0',
    'local\0core.fsmonitor\nfalse\0\0', 'unproved\0core.fsmonitor\nfalse\0']) assert.equal(readers.parseConfigOutput(output), null);
  // credential.helper is now an observed source; retaining it must reach UNKNOWN.
  const credential = readers.parseConfigOutput('local\0credential.helper\nDUMMY\0');
  assert.equal(credential.get('credential.helper'), 'DUMMY');
  assert.equal(category(assess(fixture('status'), [], { probe: () => credential })), 'UNKNOWN');
  assert.equal(readers.parseConfigOutput(Buffer.from([0xff, 0])), null);
});
test('private helper values do not enter reasons; repeated keys keep last effective selection', () => {
  const cfg = readers.parseConfigOutput('local\0core.fsmonitor\n/DUMMY/PRIVATE_HELPER\0local\0core.fsmonitor\nfalse\0');
  assert.equal(assess(fixture('status'), [...cfg]), null);
  const result = assess(fixture('status'), [['core.fsmonitor', '/DUMMY/PRIVATE_HELPER']]);
  assert.equal(result.reason.includes('PRIVATE_HELPER'), false);
});
test('inspection hardening is separate from the config observation', () => {
  assert.deepEqual(readers.inspectionArgs(['diff', '--cached', '--name-only', '-z']),
    ['--no-pager', '--no-lazy-fetch', '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null', 'diff', '--no-ext-diff', '--no-textconv', '--cached', '--name-only', '-z']);
  assert.deepEqual(readers.inspectionArgs(['ls-files', '-z', '--', 'a.txt']),
    ['--no-pager', '--no-lazy-fetch', '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null', 'ls-files', '-z', '--', 'a.txt']);
});
test('inspection does not use the boolean fsmonitor override on older or unknown Git', () => {
  for (const banner of ['git version 2.35.1\n', 'unknown', 'git version $DUMMY']) assert.equal(readers.supportsInspectionHardening(banner), false);
  for (const banner of ['git version 2.36.0\n', 'git version 2.54.0\n', 'git version 2.39.5 (Apple Git-154)\n']) assert.equal(readers.supportsInspectionHardening(banner), true);
});
