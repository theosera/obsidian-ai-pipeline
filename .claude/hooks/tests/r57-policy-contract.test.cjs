'use strict';
// Pure fixed declarations and synthetic runner wire only. No Hook/setup/native execution.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), vm = require('node:vm');
const hooks = path.resolve(process.argv[2] || path.join(__dirname, '..'));
const cp = require('node:child_process');
let childAttempts = 0;
for (const name of ['execFileSync', 'spawnSync', 'execFile', 'spawn', 'execSync', 'exec', 'fork']) cp[name] = () => { childAttempts++; throw Error('pure policy test must not start a child'); };
const { CASES } = require(path.join(hooks, 'tests/git-guards.test.cjs'));
const profile = require(path.join(hooks, 'tests/executable-profile-qualification.cjs'));
const { createPolicyContract } = require(path.join(hooks, 'tests/r57-policy-contract.cjs'));
const ledger = require(path.join(hooks, 'tests/fixtures/r57-policy-contract.json'));
const backendBytes = fs.readFileSync(path.join(hooks, 'tests/fixtures/r54-selected-executable-profile.json'));
const hash = x => crypto.createHash('sha256').update(typeof x === 'string' || Buffer.isBuffer(x) ? x : JSON.stringify(x)).digest('hex');
const json = x => JSON.stringify(x), clone = x => JSON.parse(json(x));
const ORIGINAL = '450e94994846d221d3056b1580822b513d6f87c5f086f14b7b95389c85a46b75';
const EG = 'block-secret-egress.cjs', SG = 'block-secret-git.cjs', AG = 'block-git-add-all.cjs', HOOKS = [SG, AG, EG];
const selected = () => createPolicyContract(CASES, ledger, backendBytes);
const declared = ledger.entries.map(d => CASES.find(c => c.id === d.id));
const ordinary = CASES.find(c => c.id === 'R29SW24');
const wire = (eg = 'UNKNOWN', sg = 'ALLOW', ag = 'ALLOW') => {
  const owns = { [EG]: eg, [SG]: sg, [AG]: ag }, denied = HOOKS.filter(h => owns[h] !== 'ALLOW');
  return { decision: denied.length ? 'deny' : 'allow', ownEG: eg, ownSG: sg, ownAG: ag, denied, broken: [],
    reasonPrefixes: Object.fromEntries(denied.map(h => [h, owns[h] === 'FORBIDDEN' ? '[禁止] ' : '[判断不能] '])),
    reasonTexts: Object.fromEntries(denied.map(h => [h, '[判断不能] DUMMY opaque policy root'])) };
};

test('original8696 and R54bytes654 remain exact; eleven fixed declarations are unique and disjoint', () => {
  assert.equal(CASES.length, 8696); assert.equal(hash(CASES), ORIGINAL);
  assert.equal(hash(backendBytes), 'f7760a0bc01b10caf7b302ac3e0686c1cd762d219041568f054f8816c2f95d90');
  const backend = JSON.parse(backendBytes), ids = new Set(backend.entries.map(d => d.id));
  assert.equal(backend.entries.length, 654); assert.equal(ledger.entries.length, 11);
  assert.equal(new Set(ledger.entries.map(d => d.id)).size, 11);
  for (const d of ledger.entries) {
    const c = CASES[d.originalIndex]; assert.equal(c.id, d.id); assert.equal(c.expect, 'allow');
    assert.deepEqual(c, d.originalDefinition); assert.equal(hash(c), d.originalDefinitionJSONSHA256); assert.equal(ids.has(c.id), false);
  }
});

test('expectation derivation changes only four EG policy fields, preserving original input and ALLOW history', () => {
  const policy = selected();
  for (const c of declared) {
    const before = json(c), q = policy.qualify(c), expected = policy.effectiveCase(c, c, q);
    assert.equal(q.applies, true); assert.equal(q.source, 'fixed-policy-declaration-only');
    assert.equal(expected.expect, 'deny'); assert.equal(expected.expectedOwnEG, 'UNKNOWN');
    assert.equal(expected.denyBy, EG); assert.equal(expected.expectReasonPrefixes[EG], '[判断不能] ');
    const restored = { ...expected }; for (const k of ['expect', 'expectedOwnEG', 'denyBy', 'expectReasonPrefixes']) delete restored[k];
    const original = { ...c }; for (const k of ['expect', 'expectedOwnEG', 'denyBy', 'expectReasonPrefixes']) delete original[k];
    assert.deepEqual(restored, original); assert.equal(json(c), before); assert.equal(c.expect, 'allow');
  }
  assert.equal(hash(CASES), ORIGINAL);
});

test('original SG/AG ALLOW obligations remain even when aggregate deny and EG UNKNOWN match', () => {
  const policy = selected(), c = declared[0], expected = policy.effectiveCase(c, c, policy.qualify(c));
  assert.equal(profile.matchesCase(wire(), expected, HOOKS), true); assert.equal(policy.nonEgressAssertionsMatch(wire(), c), true);
  for (const altered of [wire('UNKNOWN', 'UNKNOWN'), wire('UNKNOWN', 'ALLOW', 'FORBIDDEN')]) {
    assert.equal(profile.matchesCase(altered, expected, HOOKS), true, 'four derived fields alone would miss this');
    assert.equal(policy.nonEgressAssertionsMatch(altered, c), false);
  }
});

test('nondeclared terminal/query/DATA cases retain R54 expectation and receive no policy declaration', () => {
  const policy = selected();
  for (const id of ['R29SW24', 'R29SW25', 'R29SW30', 'R29SW31']) {
    const c = CASES.find(c => c.id === id), q = policy.qualify(c);
    assert.equal(q.applies, false); assert.equal(policy.effectiveCase(c, c, q), c);
  }
});

test('declaration drift, extra IDs, old expectation edits and changed R54 bytes are rejected', () => {
  for (const change of [l => l.entries.pop(), l => l.entries.push(clone(l.entries[0])),
    l => { l.entries[0].originalDefinition.expect = 'deny'; }, l => { l.entries[0].setFields.expectedOwnEG = 'ALLOW'; },
    l => { l.reviewReference.bodySHA256 = '0'.repeat(64); }]) {
    const altered = clone(ledger); change(altered); assert.throws(() => createPolicyContract(CASES, altered, backendBytes));
  }
  assert.throws(() => createPolicyContract(CASES, ledger, Buffer.concat([backendBytes, Buffer.from(' ')])));
  const c = clone(declared[0]); c.cmd += ' ordinary'; assert.throws(() => selected().qualify(c));
  const policy = selected(), original = declared[0];
  assert.throws(() => policy.effectiveCase(original, { ...original, expect: 'deny' }, policy.qualify(original)));
});

function syntheticMain({ asText = false, fault = null, noExecutableProfile = false } = {}) {
  const source = fs.readFileSync(path.join(hooks, 'tests/git-guards.test.cjs'), 'utf8');
  const start = source.indexOf('function main() {'), end = source.indexOf('\n}\n', start);
  assert.ok(start >= 0 && end > start);
  const cases = [...declared, ordinary], policy = selected(), output = [], lines = [];
  let setup = 0, cleanup = 0, calls = 0;
  const processDTO = { argv: ['node', '/DUMMY/runner', ...(!asText ? ['--json'] : []),
    ...(!noExecutableProfile ? ['--executable-profile'] : []), '--r57-policy-contract'],
    stdout: { write(v) { output.push(v); } }, exitCode: null, exit() { throw Error('unexpected exit'); } };
  const tools = { ...profile, createProfile() { return { qualify(c) { return { caseID: c.id, applies: false, source: 'original-oracle-no-profile-declaration' }; }, effectiveCase(c) { return c; }, definitionsUnchanged() { return true; } }; } };
  const sandbox = { process: processDTO, __dirname: '/DUMMY/tests', path, CASES: cases, HOOKS,
    fs: { readFileSync(p) { assert.equal(p, '/DUMMY/tests/fixtures/r54-selected-executable-profile.json'); return backendBytes; } },
    console: { log(v) { lines.push(v); }, error() { throw Error('unexpected console error'); } },
    require(name) {
      if (name === './executable-profile-qualification.cjs') return tools;
      if (name === './fixtures/r54-selected-executable-profile.json') return JSON.parse(backendBytes);
      if (name === './fixtures/r57-policy-contract.json') return ledger;
      if (name === './r57-policy-contract.cjs') return { createPolicyContract() { return policy; } };
      throw Error('unexpected pure dependency ' + name);
    },
    setupRepos() { setup++; return { env: { PATH: '/DUMMY' }, dirs: { clean: '/DUMMY/project' }, fixtureEnvironmentSets: {} }; },
    cleanupRepos() { cleanup++; },
    runCase(directory, c, repos, stopAtFirstDeny, captureReasons) {
      calls++; assert.equal(stopAtFirstDeny, false); assert.equal(captureReasons, true);
      const r = { id: c.id, ...wire(c.id === ordinary.id ? 'ALLOW' : 'UNKNOWN') };
      if (c.id === declared[0].id) {
        if (fault === 'operational') r.reasonTexts[EG] = '[判断不能] DUMMY componentを読み込めません';
        if (fault === 'broken') r.broken.push('DUMMY invalid wire');
        if (fault === 'SG') { r.ownSG = 'UNKNOWN'; r.denied.push(SG); r.reasonPrefixes[SG] = '[判断不能] '; }
        if (fault === 'wrong-prefix') r.reasonPrefixes[EG] = '[禁止] ';
      }
      return r;
    } };
  try { vm.runInNewContext(source.slice(start, end + 3) + '\nmain();', sandbox, { filename: 'r57-pure-main-extract.cjs' }); }
  catch (error) { if (!noExecutableProfile) throw error; return { error, setup, cleanup, calls }; }
  assert.equal(setup, 1); assert.equal(cleanup, 1); assert.equal(calls, 12);
  return { result: asText ? null : JSON.parse(output.join('')), lines, exitCode: processDTO.exitCode };
}

test('explicit policy flag requires executable profile before any fixture or runCase', () => {
  const r = syntheticMain({ noExecutableProfile: true }); assert.match(r.error.message, /requires --executable-profile/);
  assert.equal(r.setup, 0); assert.equal(r.calls, 0);
});

test('pure main preserves original11 FAIL and profile-before-policy11 FAIL separately from adopted contract', () => {
  const { result, exitCode } = syntheticMain();
  assert.equal(result.total, 12); assert.equal(result.originalFailed, 11); assert.equal(result.profileBeforePolicyFailed, 11);
  assert.equal(result.profileAdjusted, 0); assert.equal(result.policyContractAdjusted, 11); assert.equal(result.policyContractDeclared, 11);
  assert.equal(result.failed, 0); assert.equal(exitCode, 0);
  for (const r of result.results.slice(0, 11)) {
    assert.equal(r.expect, 'allow'); assert.equal(r.originalOK, false); assert.equal(r.profileBeforePolicyOK, false);
    assert.equal(r.profileOK, true); assert.equal(r.policyContractOK, true); assert.equal(r.policyExpected.expect, 'deny');
  }
  assert.equal(result.results[11].policyContractQualification.applies, false);
});

test('pure main rejects operational denial, BROKEN, SG obligation loss and incorrect reason prefix', () => {
  for (const fault of ['operational', 'broken', 'SG', 'wrong-prefix']) {
    const { result, exitCode } = syntheticMain({ fault }); assert.equal(result.failed, 1, fault); assert.equal(exitCode, 1);
    assert.equal(result.results[0].profileBeforePolicyOK, false); assert.equal(result.results[0].policyContractOK, false);
    assert.equal(result.operationalReasonFailures, fault === 'operational' ? 1 : 0);
  }
});

test('text mode emits all eleven fixed policy evidence rows and leaves nondeclared case quiet', () => {
  const { lines } = syntheticMain({ asText: true }), prefix = 'R57 policy contract evidence: ';
  const rows = lines.filter(l => l.startsWith(prefix)).map(l => JSON.parse(l.slice(prefix.length)));
  assert.equal(rows.length, 11); assert.deepEqual(rows.map(r => r.id), ledger.entries.map(d => d.id));
  for (const r of rows) {
    assert.equal(r.originalExpect, 'allow'); assert.equal(r.originalOK, false); assert.equal(r.profileBeforePolicyOK, false);
    assert.equal(r.policyContractOK, true); assert.equal(r.ownEG, 'UNKNOWN'); assert.equal(r.ownSG, 'ALLOW'); assert.equal(r.ownAG, 'ALLOW');
    assert.equal(r.reasonPrefixes[EG], '[判断不能] '); assert.equal(r.qualification.source, 'fixed-policy-declaration-only');
  }
  assert.equal(lines.some(l => l.includes('R57 policy contract: declared 11; adjusted: 11')), true);
});

test('pure preparation leaves definitions exact and starts no native child', () => {
  assert.equal(hash(CASES), ORIGINAL); assert.equal(childAttempts, 0);
});
