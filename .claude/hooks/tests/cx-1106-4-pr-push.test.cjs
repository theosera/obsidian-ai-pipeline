'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const fixture = require('./cx-1106-4-fixture.cjs');

test('CX-1106-4 requested lanes retain their finite synthetic contract', t => {
  const hooks = path.resolve(process.argv[2] || path.join(__dirname, '..'));
  const result = fixture.run(hooks, { baseline: process.argv.includes('--baseline'), legacyOnly: true });
  assert.equal(result.cases, 41, 'retain the approved finite corpus');
  assert.equal(result.broken, 0, 'complete Hook wire contract');
  assert.equal(result.unexpectedAttempts, 0, 'only finite modeled getters');
  assert.equal(result.nativeExecutions, 0, 'no native child execution');
  assert.equal(result.settingsAccesses, 0, 'no settings access');
  assert.equal(result.sourcesUnchanged, true, 'source identity remains fixed');
  assert.deepEqual(result.failed, [], 'finite contract assertion IDs');
  const exact = result.results.filter(row => row.expectedCategory);
  assert.equal(exact.length, 3, 'retain the added exact-category assertions');
  assert.equal(exact.every(row => row.expectedCategory === 'UNKNOWN' && row.category === 'UNKNOWN'), true,
    'added denials require the exact category');
  t.diagnostic(JSON.stringify({ cases: result.cases, passed: result.cases - result.failed.length,
    failed: result.failed.length, broken: result.broken, nativeExecutions: result.nativeExecutions,
    settingsAccesses: result.settingsAccesses, modeledGetters: result.modeledGetters,
    sourcePinsStable: result.sourcesUnchanged, exactUnknownCases: exact.length }));
});

test('CX-1107-4 additive synthetic source contract', t => {
  const hooks = path.resolve(process.argv[2] || path.join(__dirname, '..'));
  const result = fixture.run(hooks);
  assert.equal(result.retainedCases, 41);
  assert.equal(result.cases, 48);
  assert.equal(result.broken + result.nativeExecutions + result.unexpectedAttempts + result.settingsAccesses, 0);
  assert.equal(result.sourcesUnchanged, true);
  assert.deepEqual(result.failed, [], 'additive contract assertion IDs');
  t.diagnostic(JSON.stringify({ retainedCases: result.retainedCases, addedCases: result.cases - result.retainedCases,
    passed: result.cases, broken: result.broken, sourcePinsStable: result.sourcesUnchanged }));
});

test('CX-1107-4 owned native getters retain the requested contract', t => {
  const hooks = path.resolve(process.argv[2] || path.join(__dirname, '..'));
  const result = fixture.runNative(hooks);
  assert.equal(result.cases, 6);
  assert.equal(result.broken + result.unexpectedAttempts, 0);
  assert.equal(result.sourcesUnchanged, true);
  assert.deepEqual(result.failed, [], 'native contract assertion IDs');
  assert.equal(result.results.every(row => row.getters > 0), true);
  t.diagnostic(JSON.stringify({ cases: result.cases, passed: result.passed, broken: result.broken,
    nativeGetters: result.nativeGetters, unexpectedAttempts: result.unexpectedAttempts,
    sourcePinsStable: result.sourcesUnchanged }));
});

test('CX-1107-4 extended synthetic source contract', t => {
  const hooks = path.resolve(process.argv[2] || path.join(__dirname, '..'));
  const result = fixture.run(hooks, { extended: true });
  assert.equal(result.retainedCases, 41); assert.equal(result.previousCases, 48);
  assert.equal(result.cases, 69);
  assert.equal(result.broken + result.nativeExecutions + result.unexpectedAttempts + result.settingsAccesses, 0);
  assert.equal(result.sourcesUnchanged, true);
  assert.deepEqual(result.failed, [], 'extended contract assertion IDs');
  t.diagnostic(JSON.stringify({ previousCases: result.previousCases, addedCases: result.cases - result.previousCases,
    passed: result.cases, broken: result.broken, sourcePinsStable: result.sourcesUnchanged }));
});

test('CX-1107-4 extended owned native source contract', t => {
  const hooks = path.resolve(process.argv[2] || path.join(__dirname, '..'));
  const programs = ['/usr/bin/git'];
  if (fs.existsSync('/usr/local/bin/git')) programs.push('/usr/local/bin/git');
  for (const git of programs) {
    const result = fixture.runNative(hooks, { extended: true, git });
    assert.equal(result.previousCases, 6); assert.equal(result.cases, 16);
    assert.equal(result.broken + result.unexpectedAttempts, 0);
    assert.equal(result.sourcesUnchanged, true);
    assert.deepEqual(result.failed, [], 'extended native contract assertion IDs');
    assert.equal(result.versions.length, 1);
    t.diagnostic(JSON.stringify({ git, versions: result.versions, previousCases: result.previousCases,
      addedCases: result.cases - result.previousCases, passed: result.passed,
      nativeGetters: result.nativeGetters, unexpectedAttempts: result.unexpectedAttempts,
      sourcePinsStable: result.sourcesUnchanged }));
  }
});
