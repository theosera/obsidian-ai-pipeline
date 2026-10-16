'use strict';
/** Loading the public bank must work; a stale or modified ledger must fail before any Hook runs. */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const runner = path.join(__dirname, 'git-guards.test.cjs');
function load(file) {
  return spawnSync(process.execPath, ['-e', `const {CASES}=require(${JSON.stringify(file)});console.log(JSON.stringify({count:CASES.length,unique:new Set(CASES.map(c=>c.id)).size}));`], { encoding: 'utf8', timeout: 10000 });
}
test('public guard runner loads its exact ledger and unique input bank without executing Hooks', () => {
  const result = load(runner);
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  const summary = JSON.parse(result.stdout);
  assert.equal(summary.count, 8454 + require('./r39-review-cases.json').length + require('./r40-precommit-cases.json').length);
  assert.equal(summary.unique, summary.count);
});

test('R40 preserves all original input data and separately exports the original 8586 oracles', () => {
  const { CASES, R40_ORIGINAL_8586_CASES: original } = require(runner);
  const hash = value => require('node:crypto').createHash('sha256').update(JSON.stringify(value)).digest('hex');
  assert.equal(original.length, 8586);
  assert.equal(hash(original), 'ca889710ee94567674bc411cb3f7d87c8206eb304e1c5eef699188113b95247a');
  const oracleKeys = new Set(['expect', 'expectedOwnSG', 'denyBy', 'expectReasonPrefixes']);
  const data = c => Object.fromEntries(Object.entries(c).filter(([key]) => !oracleKeys.has(key)));
  assert.deepEqual(CASES.slice(0, 8586).map(data), original.map(data));
  assert.equal(CASES.slice(0, 8586).filter((c, i) => JSON.stringify(c) !== JSON.stringify(original[i])).length, 45);
});

test('modified R40 oracle ledger fails before any Hook or fixture execution', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pr191-r40-oracle-binding-'));
  try {
    for (const name of ['git-guards.test.cjs', 'r38-guard-oracle-adjustments.json', 'r39-review-cases.json',
      'r40-precommit-cases.json', 'r40-precommit-oracle-adjustments.json']) {
      fs.copyFileSync(path.join(__dirname, name), path.join(root, name));
    }
    assert.equal(load(path.join(root, 'git-guards.test.cjs')).status, 0);
    const file = path.join(root, 'r40-precommit-oracle-adjustments.json');
    const ledger = JSON.parse(fs.readFileSync(file, 'utf8'));
    ledger.adjustments[0].setFields.expect = 'allow';
    fs.chmodSync(file, 0o600);
    fs.writeFileSync(file, JSON.stringify(ledger));
    const result = load(path.join(root, 'git-guards.test.cjs'));
    assert.ifError(result.error);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /R40_PRECOMMIT_LEDGER_BINDING/);
    assert.equal(result.stdout, '');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('modified R40 input bank fails before any Hook or fixture execution', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pr191-r40-bank-binding-'));
  try {
    for (const name of ['git-guards.test.cjs', 'r38-guard-oracle-adjustments.json', 'r39-review-cases.json',
      'r40-precommit-cases.json', 'r40-precommit-oracle-adjustments.json']) {
      if (fs.existsSync(path.join(__dirname, name))) fs.copyFileSync(path.join(__dirname, name), path.join(root, name));
    }
    const pristine = load(path.join(root, 'git-guards.test.cjs'));
    assert.equal(pristine.status, 0, pristine.stderr);
    const file = path.join(root, 'r40-precommit-cases.json');
    const bank = JSON.parse(fs.readFileSync(file, 'utf8'));
    bank[0].cmd = 'printf DUMMY';
    fs.chmodSync(file, 0o600);
    fs.writeFileSync(file, JSON.stringify(bank));
    const result = load(path.join(root, 'git-guards.test.cjs'));
    assert.ifError(result.error);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /R40_PRECOMMIT_BANK_BINDING/);
    assert.equal(result.stdout, '');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
test('modified guard ledger fails its binding before any Hook or fixture execution', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pr191-ledger-binding-'));
  try {
    for (const name of ['git-guards.test.cjs', 'r38-guard-oracle-adjustments.json', 'r39-review-cases.json']) {
      if (fs.existsSync(path.join(__dirname, name))) fs.copyFileSync(path.join(__dirname, name), path.join(root, name));
    }
    const file = path.join(root, 'r38-guard-oracle-adjustments.json');
    const ledger = JSON.parse(fs.readFileSync(file, 'utf8'));
    ledger.testOnlyTamper = 'DUMMY';
    // copyFile preserves a read-only frozen source mode; only this owned copy is writable.
    fs.chmodSync(file, 0o600);
    fs.writeFileSync(file, JSON.stringify(ledger));
    const result = load(path.join(root, 'git-guards.test.cjs'));
    assert.ifError(result.error);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /R38_LEDGER_EXACT_JSON_BINDING/);
    assert.equal(result.stdout, '');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('fixture base excludes ambient terminal DATA while explicit cases retain their own environments', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pr191-ambient-fixture-'));
  try {
    const script = `const r=require(${JSON.stringify(runner)});const e=r.isolatedEnv(${JSON.stringify(root)});console.log(JSON.stringify({present:['TERM','DISPLAY','PRINTER'].filter(k=>Object.hasOwn(e,k)),explicitCases:r.CASES.filter(c=>c.env&&['TERM','DISPLAY','PRINTER'].some(k=>Object.hasOwn(c.env,k))).length}));`;
    const result = spawnSync(process.execPath, ['-e', script], {
      encoding: 'utf8', timeout: 10000,
      env: { ...process.env, TERM: 'DUMMY', DISPLAY: 'DUMMY', PRINTER: 'DUMMY' },
    });
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stderr);
    const summary = JSON.parse(result.stdout);
    assert.deepEqual(summary.present, []);
    assert.ok(summary.explicitCases > 0);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
