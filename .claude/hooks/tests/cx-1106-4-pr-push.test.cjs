'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fixture = require('./cx-1106-4-fixture.cjs');

test('CX-1106-4 requested lanes retain their finite synthetic contract', t => {
  const hooks = path.resolve(process.argv[2] || path.join(__dirname, '..'));
  const result = fixture.run(hooks, { baseline: process.argv.includes('--baseline') });
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
