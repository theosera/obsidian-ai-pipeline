'use strict';
// The --slogin-state runner contract with an injected filesystem and synthetic
// Hook rows. No Hook, selected executable, fixture setup, shell or network runs.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const hooks = path.resolve(process.argv[2] || path.join(__dirname, '..'));
const profile = require(path.join(hooks, 'tests/executable-profile-qualification.cjs'));
const { CASES } = require(path.join(hooks, 'tests/git-guards.test.cjs'));
const sloginEntries = JSON.parse(fs.readFileSync(path.join(hooks, 'tests/fixtures/r39-slogin-executable-profile.json')));
const source = fs.readFileSync(path.join(hooks, 'tests/git-guards.test.cjs'), 'utf8');
const SG = 'block-secret-git.cjs', AG = 'block-git-add-all.cjs', EG = 'block-secret-egress.cjs';
const HOOKS = [SG, AG, EG];
const declaredIDs = new Set(sloginEntries.map(entry => entry.id));
const declared = CASES.filter(c => declaredIDs.has(c.id));
const ordinary = CASES.find(c => !declaredIDs.has(c.id));
const SLOGIN = '/usr/bin/slogin';

/** Only the compatibility executable is observed; every other path is absent. */
function filesystem(mode) {
  const observe = file => {
    if (file !== SLOGIN || mode === 'absent') throw Object.assign(Error('DUMMY absent'), { code: 'ENOENT' });
    if (mode === 'unknown') throw Object.assign(Error('DUMMY observation'), { code: 'EIO' });
  };
  return {
    statSync(file) { observe(file); return { isFile: () => true }; },
    accessSync(file) { observe(file); },
    realpathSync: { native(file) { observe(file); return '/usr/bin/ssh'; } },
  };
}

/** A Hook row as the real guards return it for the observed filesystem. */
function wire(c, unknown) {
  const deny = unknown || c.expect === 'deny';
  const prefix = unknown ? '[判断不能] ' : (c.expectReasonPrefixes || {})[EG];
  return { id: c.id, decision: deny ? 'deny' : 'allow', denied: deny ? [EG] : [], broken: [],
    reasonPrefixes: deny ? { [EG]: prefix } : {}, reasonTexts: deny ? { [EG]: prefix + 'DUMMY' } : {} };
}

function syntheticMain(argv, mode) {
  const start = source.indexOf('function main() {'), end = source.indexOf('\n}\n', start);
  assert.ok(start >= 0 && end > start);
  const cases = [...declared, ordinary], observed = filesystem(mode), output = [], calls = [];
  const ledger = { schema: 'R54_SELECTED_EXECUTABLE_TEST_PROFILE_V1', baselineCount: cases.length,
    baselineDefinitionsSHA256: profile.hashCase(cases), entries: [] };
  let setup = 0, cleanup = 0;
  const processDTO = { argv: ['node', '/DUMMY/runner', '--json', ...argv],
    stdout: { write(v) { output.push(v); } }, exitCode: null, exit() { throw Error('unexpected exit'); } };
  const sandbox = { process: processDTO, __dirname: '/DUMMY/tests', path, CASES: cases, HOOKS,
    console: { log() { throw Error('unexpected text output'); }, error() { throw Error('unexpected console error'); } },
    require(name) {
      if (name === './executable-profile-qualification.cjs') return { ...profile,
        createProfile(inputs, declarations) { return profile.createProfile(inputs, declarations, observed); },
        independentlyAbsent(word, environment) { return profile.independentlyAbsent(word, environment, observed); } };
      if (name === './fixtures/r54-selected-executable-profile.json') return ledger;
      if (name === './fixtures/r39-slogin-executable-profile.json') return sloginEntries;
      throw Error('unexpected pure dependency ' + name);
    },
    setupRepos() { setup++; return { env: { PATH: '/DUMMY/bin:/usr/bin' }, dirs: { clean: '/DUMMY/project' }, fixtureEnvironmentSets: {} }; },
    cleanupRepos() { cleanup++; },
    runCase(directory, c, repos, stopAtFirstDeny, captureReasons) {
      calls.push(c.id); assert.equal(stopAtFirstDeny, false); assert.equal(captureReasons, true);
      return wire(c, mode !== 'present');
    } };
  vm.runInNewContext(source.slice(start, end + 3) + '\nmain();', sandbox, { filename: 'r39-slogin-state-main-extract.cjs' });
  assert.equal(setup, 1); assert.equal(cleanup, 1);
  return { result: JSON.parse(output.join('')), calls, exitCode: processDTO.exitCode };
}

test('the declarations bind twenty original cases with six FORBIDDEN and fourteen ALLOW expectations', () => {
  assert.equal(sloginEntries.length, 20);
  assert.equal(declared.length, 20);
  assert.ok(ordinary);
  assert.deepEqual(declared.map(c => c.expectedOwnEG).sort(), [...Array(6).fill('FORBIDDEN'), ...Array(14).fill('ALLOW')].sort());
});

test('a prepared present state keeps every original expectation and runs only the declared cases', () => {
  const { result, calls, exitCode } = syntheticMain(['--executable-profile', '--slogin-state=present'], 'present');
  assert.deepEqual(calls, declared.map(c => c.id));
  assert.equal(result.total, 20); assert.equal(result.failed, 0); assert.equal(exitCode, 0);
  assert.equal(result.sloginState, 'present'); assert.equal(result.sloginStateFailed, 0);
  assert.equal(result.profileAdjusted, 0); assert.equal(result.originalFailed, 0);
  for (const r of result.results) {
    assert.equal(r.sloginStateOK, true, r.id);
    assert.ok(r.sloginState.observed.every(reason => ['explicit-present', 'first-executable-present'].includes(reason)), r.id);
  }
});

test('a prepared absent state requires the declared UNKNOWN for every case', () => {
  const { result, calls, exitCode } = syntheticMain(['--executable-profile', '--slogin-state=absent'], 'absent');
  assert.equal(calls.length, 20); assert.ok(!calls.includes(ordinary.id));
  assert.equal(result.failed, 0); assert.equal(exitCode, 0);
  assert.equal(result.sloginStateFailed, 0); assert.equal(result.profileAdjusted, 20);
  for (const r of result.results) {
    assert.equal(r.ownEG, 'UNKNOWN', r.id);
    assert.ok(r.sloginState.observed.every(reason => ['explicit-absent', 'no-executable-in-explicit-actual-path'].includes(reason)), r.id);
  }
});

test('a requested state that the filesystem does not show fails every case', () => {
  for (const [state, mode] of [['present', 'absent'], ['absent', 'present'], ['present', 'unknown'], ['absent', 'unknown']]) {
    const { result, exitCode } = syntheticMain(['--executable-profile', '--slogin-state=' + state], mode);
    assert.equal(result.sloginStateFailed, 20, state + '/' + mode);
    assert.equal(result.failed, 20, state + '/' + mode);
    assert.equal(exitCode, 1, state + '/' + mode);
  }
});

test('the state option is exact and does not combine with other selections', () => {
  for (const [argv, message] of [
    [['--executable-profile', '--slogin-state'], /exactly one of present or absent/],
    [['--executable-profile', '--slogin-state=maybe'], /exactly one of present or absent/],
    [['--executable-profile', '--slogin-state=present', '--slogin-state=absent'], /exactly one of present or absent/],
    [['--slogin-state=present'], /requires --executable-profile/],
    [['--executable-profile', '--r57-policy-contract', '--slogin-state=present'], /omit --r57-policy-contract/],
  ]) assert.throws(() => syntheticMain(argv, 'present'), message, argv.join(' '));
});
