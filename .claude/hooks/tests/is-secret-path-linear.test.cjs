'use strict';
// Synthetic data only. Never print generated inputs or read user configuration.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { spawnSync } = require('node:child_process');

const modulePath = process.env.IS_SECRET_PATH_MODULE || path.join(__dirname, '../lib/git-guard-common.cjs');
const source = fs.readFileSync(modulePath, 'utf8');
const { isSecretPath } = require(modulePath);
const start = source.indexOf('const SECRET_PATH_RE = [');
const helper = source.indexOf('const secretTemplateAllowed = ', start);
const end = source.indexOf('\n/**', helper);
assert.ok(start >= 0 && helper > start && end > helper, 'canonical policy declarations are available');
const oracle = vm.runInNewContext(source.slice(start, end) + `
({
  rules: SECRET_PATH_RE.map(re => re.source),
  test: p => !!p && SECRET_PATH_RE.some(re => re.test(secretTemplateAllowed(p) ? p.slice(0, -'.env.example'.length) : p))
})`, Object.create(null));

function random(seed) {
  return () => {
    seed ^= seed << 13;
    seed ^= seed >>> 17;
    seed ^= seed << 5;
    return seed >>> 0;
  };
}
const fragments = [...oracle.rules, source.slice(helper, end)];
const atoms = [...new Set(fragments.flatMap(rule => rule.match(/[A-Za-z_][A-Za-z_-]*/g) || []))];
const choose = (next, values) => values[next() % values.length];
function outcome(fn, value) {
  try { return ['return', fn(value)]; }
  catch (error) { return ['throw', error.name]; }
}
function sameOutcome(a, b) { return a[0] === b[0] && a[1] === b[1]; }

test('generated strings retain the canonical policy', t => {
  const next = random(0x57a1c);
  const punctuation = ['', '.', '/', '-', '_', '*', '?', ' ', '\t', '\n', '\r', '\u2028', '\u2029', '\0', '\\'];
  const units = [0, 9, 10, 13, 32, 47, 127, 255, 0x130, 0x17f, 0x212a, 0xd800, 0xdc00, 0xffff];
  let mismatches = 0, comparisons = 0, matches = 0;
  const compare = value => {
    const expected = outcome(oracle.test, value);
    comparisons++;
    if (expected[0] === 'return' && expected[1] === true) matches++;
    if (!sameOutcome(expected, outcome(isSecretPath, value))) mismatches++;
  };
  for (const first of atoms) for (const second of atoms) {
    for (const prefix of ['', '.', 'SYNTHETIC/']) for (const separator of ['', '/', '.', '-']) {
      const value = prefix + first + separator + second;
      compare(value);
      compare(value.toUpperCase());
    }
  }
  for (let i = 0; i < 30000; i++) {
    let value = '';
    const parts = next() % 9;
    for (let j = 0; j < parts; j++) {
      const atom = choose(next, atoms);
      value += choose(next, punctuation) + (next() & 1 ? atom : atom.toUpperCase());
      if (next() % 4 === 0) value += String.fromCharCode(choose(next, units));
    }
    compare(value);
  }
  assert.equal(mismatches, 0, 'generated policy mismatch count');
  assert.ok(matches > 0 && matches < comparisons, 'both policy outcomes were compared');
  t.diagnostic('synthetic comparisons: ' + comparisons);
});

test('non-string callers retain coercion and exception behavior', () => {
  const factories = [
    () => undefined, () => null, () => false, () => true, () => 0, () => -1,
    () => NaN, () => 1n, () => Symbol('SYNTHETIC'), () => ({}), () => [],
    () => new String(''), () => new String(atoms[0]),
    () => ({ toString() { throw new TypeError('SYNTHETIC'); } }),
  ];
  let mismatches = 0;
  for (const make of factories) {
    if (!sameOutcome(outcome(oracle.test, make()), outcome(isSecretPath, make()))) mismatches++;
  }
  for (const atom of atoms) {
    const make = () => {
      let calls = 0;
      return { get calls() { return calls; }, toString() { return (++calls & 1 ? '.' : '/') + atom; } };
    };
    const before = make(), after = make();
    if (!sameOutcome(outcome(oracle.test, before), outcome(isSecretPath, after)) || before.calls !== after.calls) mismatches++;
  }
  assert.equal(mismatches, 0, 'coercion policy mismatch count');
});

test('generated input completes within an isolated resource budget', () => {
  const program = `
    const { isSecretPath } = require(process.argv[1]);
    let state = 0x49e31;
    const chunks = [];
    for (let i = 0; i < 128; i++) {
      const units = new Uint16Array(4096);
      for (let j = 0; j < units.length; j++) {
        state ^= state << 13; state ^= state >>> 17; state ^= state << 5;
        units[j] = 0x400 + (state >>> 0) % 1024;
      }
      chunks.push(String.fromCharCode(...units));
    }
    if (typeof isSecretPath(chunks.join('')) !== 'boolean') process.exitCode = 1;
  `;
  const result = spawnSync(process.execPath, ['-e', program, modulePath], {
    env: Object.create(null), timeout: 5000, maxBuffer: 1024, encoding: 'utf8',
  });
  assert.equal(result.error?.code, undefined, 'resource budget completion');
  assert.equal(result.signal, null, 'worker completed normally');
  assert.equal(result.status, 0, 'worker exit status');
  assert.equal(result.stdout, '', 'worker emits no generated data');
  assert.equal(result.stderr, '', 'worker emits no generated data');
});
