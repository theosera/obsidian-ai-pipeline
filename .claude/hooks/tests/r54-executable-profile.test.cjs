'use strict';
// Profile contracts are tested with synthetic rows and an injected filesystem.
// No Hook, selected executable, fixture setup, shell or network command runs.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const vm = require('node:vm');
const hooks = path.resolve(process.argv[2] || path.join(__dirname, '..'));
const profile = require(path.join(hooks, 'tests/executable-profile-qualification.cjs'));
const { CASES } = require(path.join(hooks, 'tests/git-guards.test.cjs'));
const ledgerFile = path.join(hooks, 'tests/fixtures/r54-selected-executable-profile.json');
const ledgerBytes = fs.readFileSync(ledgerFile);
const ledger = JSON.parse(ledgerBytes);
const sha = value => crypto.createHash('sha256').update(value).digest('hex');
const caseHash = value => sha(JSON.stringify(value));
const ORIGINAL_DIGEST = '450e94994846d221d3056b1580822b513d6f87c5f086f14b7b95389c85a46b75';
const LEDGER_DIGEST = '097bb5f68a126dba325e498c54356f1e00643d3ac5555948767bf4c0901b7e17';
const SG = 'block-secret-git.cjs', AG = 'block-git-add-all.cjs', EG = 'block-secret-egress.cjs';
const HOOKS = [SG, AG, EG];
// Literal excluded IDs from the reviewed proposal d807f549..., not a filter of
// current guard results. None may acquire a profile declaration.
const EXCLUDED_OVERREFUSALS = [
  'N16', 'EGR2N08', 'EGR2N09', 'R2P11', 'R2P12', 'R2P13', 'R2P14', 'R2P15',
  'R3P49', 'R3P55', 'R4P15', 'R4PX23', 'R14P17', 'R14P28', 'R14P64', 'R14P66',
  'R15EF17', 'R15EF23', 'R15EF25', 'R15EG052', 'R15AU03', 'R15AU04', 'R15AU05',
  'R15AU06', 'R15AU07', 'R15AU08', 'R15AU14', 'R15AU15', 'R19AGA04', 'R19AGA05',
  'R19AGA06', 'R19AGA07', 'R19AGA08', 'R19AGA09', 'R19AGA10', 'R19AGA12',
  'R22-parent-bash-function-startup-unexported', 'R22-parent-bash-function-startup-restored',
  'R22GF02', 'R22GF03', 'R22GF05', 'R22GF06', 'R38AG-STATIC-FILE',
  'R38AG-STATIC-NESTED-C', 'R38AG-STATIC-ABS-FILE', 'R38AG-ACTUAL-HELP',
  'R38AG-PRINTED-DATA', 'R38AG-EXPLICIT-END-OPTIONS', 'R38AG-LITERAL-PWD-FILE-DATA-V2',
  'R38AG-SCALAR-STATIC-ALTERNATIVE-V2',
];
const one = path.resolve('/DUMMY/profile/one'), two = path.resolve('/DUMMY/profile/two');
const file = (directory, name = 'curl') => directory + path.sep + name;
const environment = { PATH: [one, two].join(path.delimiter) };
const missingCase = () => ({ id: 'SYNTHETIC', cmd: 'curl -q https://ordinary.invalid', expect: 'allow', allowBy: EG });
const failure = code => Object.assign(Error(code), { code });
function fakeFilesystem(entries = {}) {
  const calls = [];
  const realpathSync = () => { throw Error('use native realpath'); };
  realpathSync.native = name => {
    calls.push(['realpath', name]);
    const entry = entries[name];
    if (!entry) throw failure('ENOENT');
    if (entry.realpathError) throw failure(entry.realpathError);
    return entry.physical || name;
  };
  return { calls, realpathSync,
    statSync(name) {
      calls.push(['stat', name]);
      const entry = entries[name];
      if (!entry) throw failure('ENOENT');
      if (entry.statError) throw failure(entry.statError);
      return { isFile: () => entry.file !== false };
    },
    accessSync(name) {
      calls.push(['access', name]);
      const entry = entries[name];
      if (!entry) throw failure('ENOENT');
      if (entry.accessError) throw failure(entry.accessError);
      if (entry.executable === false) throw failure('EACCES');
    },
  };
}
function declaration(c, stage = {}, disposition = 'DEPENDENT_SELECTED_SOURCE_ONLY') {
  return { id: c.id, originalCaseSHA256: caseHash(c), rootPriorityDisposition: disposition,
    stages: [{ kind: 'NO_SELECTED_EXECUTABLE_NO_NAMED_INSTALL', word: 'curl',
      stageKind: 'callee', stageIndex: 0, searchBinding: 'UNCHANGED_INHERITED_PATH',
      searchSnapshot: { pathPresent: true, pathChanged: false, defaultSearch: false }, ...stage }] };
}
function syntheticLedger(cases, entries = []) {
  return { schema: 'R54_SELECTED_EXECUTABLE_TEST_PROFILE_V1', baselineCount: cases.length,
    baselineDefinitionsSHA256: caseHash(cases), entries };
}
function wire(own = {}, broken = []) {
  const values = { [SG]: 'ALLOW', [AG]: 'ALLOW', [EG]: 'ALLOW', ...own };
  const denied = HOOKS.filter(hook => values[hook] !== 'ALLOW');
  return { decision: denied.length ? 'deny' : 'allow', denied, broken,
    ownSG: values[SG], ownAG: values[AG], ownEG: values[EG],
    reasonPrefixes: Object.fromEntries(denied.map(hook => [hook, values[hook] === 'FORBIDDEN' ? '[禁止] ' : '[判断不能] '])) };
}

function syntheticMain(fault = null, asText = false) {
  const source = fs.readFileSync(path.join(hooks, 'tests/git-guards.test.cjs'), 'utf8');
  const start = source.indexOf('function main() {'), end = source.indexOf('\n}\n', start);
  assert.ok(start >= 0 && end > start);
  assert.equal(source.indexOf('function main() {', start + 1), -1);
  const cases = [missingCase(), { id: 'UNCHANGED', cmd: 'printf ordinary', expect: 'allow' }];
  const selectedLedger = syntheticLedger(cases, [declaration(cases[0])]);
  const reason = fault === 'operational' ? '[判断不能] DUMMY componentを読み込めません' : '[判断不能] DUMMY missing selected executable';
  const calls = [], output = [], lines = [];
  const filesystemEntries = {}, filesystem = fakeFilesystem(filesystemEntries);
  let cleanups = 0;
  const processDTO = { argv: ['node', 'DUMMY', '--hooks-dir', '/DUMMY/hooks', ...(!asText ? ['--json'] : []), '--executable-profile'],
    stdout: { write(value) { output.push(value); } }, exitCode: null,
    exit(code) { throw Error('unexpected synthetic process.exit ' + code); } };
  const tools = { ...profile, createProfile(c, l) { return profile.createProfile(c, l, filesystem); } };
  const sandbox = { process: processDTO, __dirname: '/DUMMY/hooks/tests', path, CASES: cases, HOOKS,
    console: { log(value) { if (!asText) throw Error('JSON mode must not log'); lines.push(value); }, error() { throw Error('unexpected error output'); } },
    require(name) {
      if (name === './executable-profile-qualification.cjs') return tools;
      if (name === './fixtures/r54-selected-executable-profile.json') return selectedLedger;
      throw Error('unexpected synthetic main dependency ' + name);
    },
    setupRepos() { return { env: { ...environment }, dirs: { clean: '/DUMMY/repo' }, fixtureEnvironmentSets: {} }; },
    cleanupRepos() { cleanups++; },
    runCase(directory, c, repos, stopAtFirstDeny, captureReasonTexts) {
      calls.push({ directory, id: c.id, stopAtFirstDeny, captureReasonTexts });
      assert.equal(stopAtFirstDeny, false); assert.equal(captureReasonTexts, true);
      if (c.id === 'UNCHANGED') return { id: c.id, ...wire(), reasonTexts: {} };
      if (fault === 'prerequisite-drift') filesystemEntries[file(one)] = {};
      const row = { id: c.id, ...wire({ [EG]: 'UNKNOWN' }), reasonTexts: { [EG]: reason } };
      if (fault === 'malformed') { row.reasonPrefixes[EG] = null; row.broken.push('unrecognized deny reason prefix'); }
      return row;
    } };
  vm.runInNewContext(source.slice(start, end + 3) + '\nmain();', sandbox, { filename: 'pure-profile-main-extract.cjs' });
  assert.equal(cleanups, 1); assert.equal(calls.length, 2);
  return { result: !asText ? JSON.parse(output.join('')) : null, lines,
    exitCode: processDTO.exitCode, reason, calls, filesystemCalls: filesystem.calls };
}

test('original 8696 definitions and all 646 declarations remain exact and exclude 50 overrefusals', () => {
  assert.equal(CASES.length, 8696);
  assert.equal(caseHash(CASES), ORIGINAL_DIGEST);
  assert.equal(sha(ledgerBytes), LEDGER_DIGEST);
  assert.equal(ledger.baselineDefinitionsSHA256, ORIGINAL_DIGEST);
  assert.equal(ledger.entries.length, 646);
  const originals = new Map(CASES.map(c => [c.id, c]));
  const declared = new Set();
  for (const entry of ledger.entries) {
    assert.ok(originals.has(entry.id), entry.id);
    assert.equal(declared.has(entry.id), false, entry.id);
    assert.equal(entry.originalCaseSHA256, caseHash(originals.get(entry.id)), entry.id);
    declared.add(entry.id);
  }
  assert.equal(EXCLUDED_OVERREFUSALS.length, 50);
  assert.equal(new Set(EXCLUDED_OVERREFUSALS).size, 50);
  for (const id of EXCLUDED_OVERREFUSALS) {
    assert.ok(originals.has(id), id);
    assert.equal(declared.has(id), false, id);
  }
  assert.doesNotThrow(() => profile.createProfile(CASES, ledger, fakeFilesystem()));
  const special = ledger.entries.filter(d => d.rootPriorityDisposition === 'EG_DEPENDENT_KEEP_SG_FORBIDDEN');
  assert.deepEqual(special.map(d => d.id), ['R13P035']);
  assert.equal(caseHash(CASES), ORIGINAL_DIGEST, 'construction must not edit the original oracle');
});

test('profile factory rejects baseline drift and duplicate or changed declarations', () => {
  const c = missingCase(), good = syntheticLedger([c], [declaration(c)]);
  assert.throws(() => profile.createProfile([c], { ...good, baselineDefinitionsSHA256: '0'.repeat(64) }, fakeFilesystem()));
  assert.throws(() => profile.createProfile([c], { ...good, entries: [declaration(c), declaration(c)] }, fakeFilesystem()));
  assert.throws(() => profile.createProfile([c], { ...good, entries: [{ ...declaration(c), originalCaseSHA256: '0'.repeat(64) }] }, fakeFilesystem()));
});

test('factory retains the original hash even if an undeclared input object is changed after construction', () => {
  const c = missingCase(), cases = [c];
  const selected = profile.createProfile(cases, syntheticLedger(cases), fakeFilesystem());
  assert.equal(selected.definitionsUnchanged(), true);
  c.cmd = 'printf changed after construction';
  assert.equal(selected.definitionsUnchanged(), false);
  assert.throws(() => selected.qualify(c, environment), /drift|original|bound/i);
});

test('factory caches declarations so later ledger mutation cannot change their prerequisite or priority', () => {
  const c = missingCase(), d = declaration(c), selected = profile.createProfile([c], syntheticLedger([c], [d]), fakeFilesystem());
  d.stages[0].kind = 'INVALID_AFTER_CONSTRUCTION';
  d.rootPriorityDisposition = 'INVALID_AFTER_CONSTRUCTION';
  const q = selected.qualify(c, environment);
  assert.equal(q.applies, true);
  assert.equal(selected.effectiveCase(c, q, environment).expectedOwnSG, 'ALLOW');
});

test('missing qualification independently walks every explicit PATH entry', () => {
  const observed = fakeFilesystem();
  const q = profile.independentlyAbsent('curl', environment, observed);
  assert.equal(q.applies, true);
  assert.deepEqual(observed.calls, [['stat', file(one)], ['stat', file(two)]]);
  const nonexecutable = fakeFilesystem({ [file(one)]: { executable: false } });
  assert.equal(profile.independentlyAbsent('curl', environment, nonexecutable).applies, true);
  assert.deepEqual(nonexecutable.calls.at(-1), ['stat', file(two)]);
});

test('present first candidate and filesystem uncertainty keep the original assertions', () => {
  const c = missingCase();
  for (const entry of [{}, { statError: 'EIO' }, { accessError: 'EIO' }]) {
    const observed = fakeFilesystem({ [file(one)]: entry });
    const q = profile.qualification(c, declaration(c), environment, observed);
    assert.equal(q.applies, false);
    assert.equal(q.originalSemanticAssertionsRetained, true);
    assert.equal(profile.effectiveCase(c, q, environment), c);
    assert.equal(observed.calls.some(([, name]) => name === file(two)), false, 'no later candidate may replace the first present or uncertain entry');
  }
});

test('unqualified PATH entries cannot be counted as independently missing', () => {
  for (const env of [{}, { PATH: '' }, { PATH: 'relative' }, { PATH: '\0' }]) {
    assert.equal(profile.independentlyAbsent('curl', env, fakeFilesystem()).applies, false);
  }
});

test('qualification is bound to the exact original case and actual PATH presence/value', () => {
  const c = missingCase(), q = profile.qualification(c, declaration(c), environment, fakeFilesystem());
  assert.equal(profile.effectiveCase(c, q, { ...environment }).expectedOwnEG, 'UNKNOWN');
  assert.throws(() => profile.effectiveCase({ ...c, id: 'OTHER' }, q, environment));
  assert.throws(() => profile.effectiveCase({ ...c, cmd: 'printf changed' }, q, environment));
  assert.throws(() => profile.effectiveCase(c, q, { PATH: two }));
  assert.throws(() => profile.effectiveCase(c, q, {}));
  assert.throws(() => profile.effectiveCase(c, q));
});

test('missing override refuses changed, absent, default or unbound search snapshots', () => {
  const c = missingCase();
  for (const patch of [{ pathChanged: true }, { pathPresent: false }, { defaultSearch: true }]) {
    const d = declaration(c); Object.assign(d.stages[0].searchSnapshot, patch);
    assert.throws(() => profile.qualification(c, d, environment, fakeFilesystem()));
  }
  const d = declaration(c); delete d.stages[0].searchBinding;
  assert.throws(() => profile.qualification(c, d, environment, fakeFilesystem()));
});

test('explicit absolute absence is independent of PATH, and a present file never becomes missing', () => {
  const c = missingCase(), absolute = file(one), d = declaration(c, { kind: 'SELECTED_EXPLICIT_PATH_UNAVAILABLE', word: absolute });
  delete d.stages[0].searchBinding; delete d.stages[0].searchSnapshot;
  assert.equal(profile.qualification(c, d, {}, fakeFilesystem()).applies, true);
  assert.equal(profile.qualification(c, d, {}, fakeFilesystem({ [absolute]: {} })).applies, false);
});

test('an original ALLOW override cannot mask SG or AG denial or malformed wire', () => {
  const c = missingCase(), before = JSON.stringify(c);
  const q = profile.qualification(c, declaration(c), environment, fakeFilesystem());
  const expected = profile.effectiveCase(c, q, environment);
  assert.equal(JSON.stringify(c), before);
  assert.equal(expected.expectedOwnSG, 'ALLOW'); assert.equal(expected.expectedOwnAG, 'ALLOW');
  assert.equal(profile.matchesCase(wire({ [EG]: 'UNKNOWN' }), expected, HOOKS), true);
  for (const hook of [SG, AG]) for (const verdict of ['UNKNOWN', 'FORBIDDEN']) {
    assert.equal(profile.matchesCase(wire({ [EG]: 'UNKNOWN', [hook]: verdict }), expected, HOOKS), false);
  }
  assert.equal(profile.matchesCase(wire({ [EG]: 'UNKNOWN', [SG]: 'UNKNOWN', [AG]: 'UNKNOWN' }), expected, HOOKS), false);
  assert.equal(profile.matchesCase(wire({ [EG]: 'UNKNOWN' }, ['bad deny reason']), expected, HOOKS), false);
});

test('R13P035 independent SG FORBIDDEN is a required obligation after only EG changes', () => {
  const original = CASES.find(c => c.id === 'R13P035'), before = JSON.stringify(original);
  const selected = profile.createProfile(CASES, ledger, fakeFilesystem());
  const q = selected.qualify(original, environment), expected = selected.effectiveCase(original, q, environment);
  assert.equal(expected.expectedOwnEG, 'UNKNOWN'); assert.equal(expected.expectedOwnSG, 'FORBIDDEN');
  assert.equal(expected.expectReasonPrefixes[SG], '[禁止] ');
  assert.equal(profile.matchesCase(wire({ [EG]: 'UNKNOWN', [SG]: 'FORBIDDEN' }), expected, HOOKS), true);
  assert.equal(profile.matchesCase(wire({ [EG]: 'UNKNOWN', [SG]: 'UNKNOWN' }), expected, HOOKS), false);
  assert.equal(profile.matchesCase(wire({ [EG]: 'UNKNOWN' }), expected, HOOKS), false);
  assert.equal(JSON.stringify(original), before);
});

test('a guard returning only UNKNOWN cannot pass a qualified ordinary program assertion', () => {
  const c = missingCase(), d = declaration(c), observed = fakeFilesystem({ [file(one)]: {} });
  const q = profile.qualification(c, d, environment, observed), expected = profile.effectiveCase(c, q, environment);
  assert.equal(q.applies, false); assert.equal(expected.expect, 'allow');
  assert.equal(profile.matchesCase(wire(), expected, HOOKS), true);
  assert.equal(profile.matchesCase(wire({ [EG]: 'UNKNOWN' }), expected, HOOKS), false);
  assert.equal(profile.matchesCase(wire({ [EG]: 'UNKNOWN', [SG]: 'UNKNOWN', [AG]: 'UNKNOWN' }), expected, HOOKS), false);
});

test('one qualified absolute ping installation refines only its declared secret destination to FORBIDDEN', () => {
  const original = CASES.find(c => c.id === 'R39PING-ABSOLUTE-CLIENT');
  const originalBytes = JSON.stringify(original);
  const declared = ledger.entries.find(d => d.id === original.id);
  assert.equal(original.expectedOwnEG, 'UNKNOWN');
  assert.equal(declared.rootPriorityDisposition, 'CONFIRMED_LITERAL_SECRET_DESTINATION');
  for (const entry of [null, { executable: false }, { statError: 'EIO' }, { realpathError: 'EIO' }]) {
    const observed = fakeFilesystem(entry ? { '/sbin/ping': entry } : {});
    const q = profile.qualification(original, declared, environment, observed);
    assert.equal(q.applies, false);
    assert.equal(profile.effectiveCase(original, q, environment), original);
  }
  const observed = fakeFilesystem({ '/sbin/ping': { physical: '/DUMMY/native/ping' } });
  const q = profile.qualification(original, declared, environment, observed);
  const expected = profile.effectiveCase(original, q, environment);
  assert.equal(q.applies, true); assert.equal(expected.expectedOwnEG, 'FORBIDDEN');
  assert.equal(expected.expectReasonPrefixes[EG], '[禁止] ');
  assert.equal(profile.matchesCase(wire({ [EG]: 'FORBIDDEN' }), expected, HOOKS), true);
  assert.equal(profile.matchesCase(wire({ [EG]: 'UNKNOWN' }), expected, HOOKS), false);
  const unbound = JSON.parse(JSON.stringify(declared));
  unbound.rootPriorityDisposition = 'DEPENDENT_SELECTED_SOURCE_ONLY';
  assert.throws(() => profile.qualification(original, unbound, environment, observed));
  assert.equal(JSON.stringify(original), originalBytes);
  assert.equal(caseHash(CASES), ORIGINAL_DIGEST);
});

test('query absence changes no original semantic assertion when its external program is present', () => {
  const originals = new Map(CASES.map(c => [c.id, c]));
  const queries = ledger.entries.filter(d => d.stages.some(s => s.stageKind === 'selected-wrapper-query-or-source'));
  assert.equal(queries.length, 69);
  for (const d of queries) {
    const original = originals.get(d.id), word = d.stages[0].word;
    const present = profile.qualification(original, d, environment, fakeFilesystem({ [file(one, word)]: {} }));
    assert.equal(present.applies, false, d.id);
    assert.equal(profile.effectiveCase(original, present, environment), original, d.id);
    const absent = profile.qualification(original, d, environment, fakeFilesystem());
    assert.equal(absent.applies, true, d.id);
    const expected = profile.effectiveCase(original, absent, environment);
    assert.equal(expected.expectedOwnEG, 'UNKNOWN', d.id);
    if (original.expect === 'allow') {
      assert.equal(expected.expectedOwnSG, original.expectedOwnSG || 'ALLOW', d.id);
      assert.equal(expected.expectedOwnAG, original.expectedOwnAG || 'ALLOW', d.id);
    }
  }
});

test('qualification takes declared prerequisites and filesystem evidence, never a guard verdict', () => {
  const c = missingCase(), env = { ...environment };
  Object.defineProperty(env, 'actualGuardVerdict', { get() { throw Error('guard verdict must not be read'); } });
  const d = declaration(c);
  Object.defineProperty(d, 'actualGuardVerdict', { get() { throw Error('guard verdict must not be read'); } });
  assert.equal(profile.qualification(c, d, env, fakeFilesystem()).applies, true);
  assert.equal(profile.qualification(c, d, env, fakeFilesystem({ [file(one)]: {} })).applies, false);
  assert.equal(caseHash(CASES), ORIGINAL_DIGEST, 'pure observations leave production input/oracle definitions exact');
});

test('pure main integration preserves original FAIL and raw reason alongside passing profile assertions', () => {
  const { result, exitCode, reason } = syntheticMain();
  assert.equal(result.total, 2); assert.equal(result.originalFailed, 1); assert.equal(result.failed, 0);
  assert.equal(result.profileAdjusted, 1); assert.equal(result.operationalReasonFailures, 0);
  assert.equal(result.originalDefinitionsUnchanged, true); assert.equal(exitCode, 0);
  assert.equal(result.results[0].originalOK, false); assert.equal(result.results[0].profileOK, true);
  assert.equal(result.results[0].profileQualificationStable, true);
  assert.equal(result.results[0].expect, 'allow'); assert.equal(result.results[0].profileExpected.expect, 'deny');
  assert.equal(result.results[0].reasonTexts[EG], reason);
  assert.equal(result.results[1].originalOK, true); assert.equal(result.results[1].profileQualification.applies, false);
});

test('pure main integration rejects operational UNKNOWN and malformed wire instead of accepting their profile shape', () => {
  for (const fault of ['operational', 'malformed']) {
    const { result, exitCode } = syntheticMain(fault);
    assert.equal(result.originalFailed, 1); assert.equal(result.failed, 1); assert.equal(exitCode, 1);
    assert.equal(result.results[0].profileOK, false);
    assert.equal(result.operationalReasonFailures, fault === 'operational' ? 1 : 0);
  }
  assert.equal(caseHash(CASES), ORIGINAL_DIGEST);
});

test('pure main refuses absent-to-present prerequisite drift even when UNKNOWN matches the precheck expectation', () => {
  const { result, exitCode, filesystemCalls } = syntheticMain('prerequisite-drift');
  const changed = result.results[0];
  assert.equal(result.originalFailed, 1); assert.equal(result.failed, 1); assert.equal(exitCode, 1);
  assert.equal(result.profileAdjusted, 1); assert.equal(result.operationalReasonFailures, 0);
  assert.equal(changed.profileQualification.applies, true);
  assert.equal(changed.profileExpected.expectedOwnEG, 'UNKNOWN');
  assert.equal(changed.ownEG, 'UNKNOWN'); assert.deepEqual(changed.broken, []);
  assert.equal(profile.matchesCase(changed, changed.profileExpected, HOOKS), true, 'the bound precheck alone would have matched');
  assert.equal(changed.originalOK, false); assert.equal(changed.profileQualificationStable, false);
  assert.equal(changed.profileOK, false);
  assert.equal(filesystemCalls.filter(([operation, name]) => operation === 'stat' && name === file(one)).length, 2);
  assert.equal(result.results[1].profileQualificationStable, true);
  assert.equal(result.originalDefinitionsUnchanged, true); assert.equal(caseHash(CASES), ORIGINAL_DIGEST);
});

test('text runner emits independent prerequisite and actual wire reasons without losing original failures', () => {
  for (const fault of [null, 'operational']) {
    const { lines, exitCode, reason } = syntheticMain(fault, true);
    const prefix = 'Executable profile evidence: ';
    const rows = lines.filter(line => line.startsWith(prefix)).map(line => JSON.parse(line.slice(prefix.length)));
    assert.equal(rows.length, 1);
    const row = rows[0];
    assert.equal(row.id, 'SYNTHETIC'); assert.equal(row.originalOK, false);
    assert.equal(row.ownEG, 'UNKNOWN'); assert.equal(row.ownSG, 'ALLOW'); assert.equal(row.ownAG, 'ALLOW');
    assert.equal(row.reasonTexts[EG], reason); assert.equal(row.reasonPrefixes[EG], '[判断不能] ');
    assert.equal(row.qualification.applies, true); assert.equal(row.qualificationStable, true);
    assert.equal(row.qualification.reasons[0].reason, 'no-executable-in-explicit-actual-path');
    assert.equal(row.operationalReasonFailure, fault === 'operational');
    assert.equal(row.profileOK, fault !== 'operational');
    assert.equal(exitCode, fault === 'operational' ? 1 : 0);
    assert.equal(lines.some(line => line.startsWith('Original oracle: 1/2 pass;')), true);
  }
});
