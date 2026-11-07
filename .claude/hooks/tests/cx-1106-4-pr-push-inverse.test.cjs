'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const fixture = require('./cx-1106-4-fixture.cjs');
const EG = fixture.FILES[0], READERS = fixture.FILES[2];

test('CX-1106-4 single-guard removals independently turn the focused contract red', t => {
  const hooks = path.resolve(process.argv[2] || path.join(__dirname, '..'));
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'cx-1106-4-inverse-'));
  const sources = Object.fromEntries(fixture.FILES.map(file => [file, fs.readFileSync(path.join(hooks, file), 'utf8')]));
  const headGuard = "    if (operation === 'pr create' && !selected('head').some(word => {\n      const head = literalSourceWord(word); return head && head.text !== '';\n    })) return 'UNKNOWN'; // Explicit nonempty head skips the documented implicit push/fork path.\n";
  const mutations = [
    [EG, '!leadingCdContext || !g.cdLikeBefore', '!g.cdLikeBefore', ['D11']],
    [EG, '      insp.invocations.length !== 2 || invocation !== insp.invocations[1] ||\n', '', ['D12']],
    [EG, "if (args.length !== 2 || args[0] !== 'origin') return null;", "if (args[0] !== 'origin') return null;", ['D03']],
    [EG, "if (args.length !== 2 || args[0] !== 'origin') return null;", 'if (args.length !== 2) return null;', ['D10']],
    [EG, "!branch.startsWith('claude/')", 'false', ['D02']],
    [READERS, 'if (!hasSources && !requirements.requiredPushURL) return null;', 'if (!hasSources) return null;', ['D01']],
    [READERS, "if (requirements.requiredPushURL && (g.sub !== 'push' || !urls.length ||", "if (false && (g.sub !== 'push' || !urls.length ||", ['D01']],
    [READERS, "if (g.sub !== 'push' || config.some(record => record.key.toLowerCase() === 'remote.origin.mirror') ||\n          !operationConfig || operationConfig.status !== 1 || operationConfig.text !== '') {", 'if (false) {', ['D27', 'D28', 'D29']],
    [READERS, "if (!source || source.text !== 'refs/heads/' + branch + '\\n') {", 'if (false) {', ['D26', 'D30']],
    [EG, headGuard, '', ['D18']],
    [READERS, '      if (scopedPushConfig) {', '      if (false) {', ['D31', 'D32', 'D33']],
  ];
  let hookCases = 0, red = 0;
  try {
    const reference = fixture.run(hooks, { legacyOnly: true });
    assert.equal(reference.cases, 41);
    assert.equal(reference.broken, 0); assert.deepEqual(reference.failed, []);
    assert.equal(reference.sourcesUnchanged, true);
    assert.equal(reference.nativeExecutions + reference.unexpectedAttempts + reference.settingsAccesses, 0);
    hookCases += reference.cases;
    for (const [index, [file, before, after, witnesses]] of mutations.entries()) {
      const trial = path.join(root, String(index));
      for (const [relative, source] of Object.entries(sources)) {
        const selected = relative === file;
        if (selected) assert.equal(source.split(before).length - 1, 1, 'exact mutation source anchor');
        const target = path.join(trial, relative);
        fs.mkdirSync(path.dirname(target), { recursive: true });
        fs.writeFileSync(target, selected ? source.replace(before, after) : source);
      }
      const result = fixture.run(trial, { legacyOnly: true });
      hookCases += result.cases;
      assert.equal(result.broken, 0, 'red evidence requires complete Hook output');
      assert.equal(result.nativeExecutions + result.unexpectedAttempts + result.settingsAccesses, 0);
      assert.equal(result.sourcesUnchanged, true);
      assert.ok(result.failed.length > 0, 'each removed guard must make assertions red');
      for (const witness of witnesses) {
        const row = result.results.find(entry => entry.id === witness);
        assert.equal(row.expected, 'DENY'); assert.equal(row.actual, 'ALLOW', 'mutation ' + (index + 1) + ' witness ' + witness);
        if (row.expectedCategory) {
          const before = reference.results.find(entry => entry.id === witness);
          assert.equal(before.category, 'UNKNOWN', 'new reference requires exact category');
          assert.equal(row.category, 'ALLOW', 'new mutation requires complete allowance');
        }
      }
      if (index === mutations.length - 1) assert.deepEqual(result.failed, witnesses, 'new removal changes only its added witnesses');
      red++;
    }
    assert.equal(red, mutations.length);
    assert.equal(mutations.length, 11);
    assert.equal(hookCases, 492);
    for (const [file, source] of Object.entries(sources)) {
      assert.equal(fs.readFileSync(path.join(hooks, file), 'utf8') === source, true, 'original source pins remain fixed');
    }
    t.diagnostic(JSON.stringify({ mutations: mutations.length, red, hookCases,
      referenceCases: reference.cases, nativeExecutions: 0, unexpectedAttempts: 0,
      settingsAccesses: 0, sourcePinsStable: true }));
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('CX-1107-4 additive guard removal turns its synthetic witnesses red', t => {
  const hooks = path.resolve(process.argv[2] || path.join(__dirname, '..'));
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'cx-1107-4-inverse-'));
  const sources = Object.fromEntries(fixture.FILES.map(file => [file, fs.readFileSync(path.join(hooks, file), 'utf8')]));
  try {
    const before = '      if (!hookAbsent) {';
    assert.equal(sources[READERS].split(before).length - 1, 1, 'exact additive mutation anchor');
    for (const [relative, source] of Object.entries(sources)) {
      const target = path.join(root, relative);
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, relative === READERS ? source.replace(before, '      if (false) {') : source);
    }
    const reference = fixture.run(hooks), trial = fixture.run(root);
    assert.deepEqual(reference.failed, []);
    assert.equal(reference.cases, 48); assert.equal(trial.cases, 48);
    for (const result of [reference, trial]) {
      assert.equal(result.broken + result.nativeExecutions + result.unexpectedAttempts + result.settingsAccesses, 0);
      assert.equal(result.sourcesUnchanged, true);
    }
    const witnesses = ['H01', 'H02', 'H06', 'H07'];
    assert.deepEqual(trial.failed, witnesses, 'only additive source witnesses change');
    for (const id of witnesses) {
      assert.equal(reference.results.find(row => row.id === id).category, 'UNKNOWN');
      assert.equal(trial.results.find(row => row.id === id).category, 'ALLOW');
    }
    t.diagnostic(JSON.stringify({ addedConditions: 1, mutations: 1, red: 1, witnesses: witnesses.length,
      hookCases: reference.cases + trial.cases, retainedCasesUnchanged: reference.retainedCases }));
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('CX-1107-4 extended guard removals independently turn their witnesses red', t => {
  const hooks = path.resolve(process.argv[2] || path.join(__dirname, '..'));
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'cx-1107-4-extended-inverse-'));
  const sources = Object.fromEntries(fixture.FILES.map(file => [file, fs.readFileSync(path.join(hooks, file), 'utf8')]));
  const mutations = [
    ['if (!hookConfig || hookConfig.status !== 1 || hookConfig.text !== \'\') {', 'if (false) {',
      ['J05', 'J06', 'J07', 'J08', 'J09', 'J10', 'J11', 'J17']],
    ['if (!hookAbsent) {', "if (!hookAbsent && name !== 'reference-transaction') {", ['J01', 'J02', 'J18']],
    ['if (!directoryAbsent) {', 'if (false) {', ['J13', 'J15', 'J16']],
  ];
  let red = 0, hookCases = 0;
  try {
    const reference = fixture.run(hooks, { extended: true });
    assert.equal(reference.cases, 69); assert.deepEqual(reference.failed, []);
    hookCases += reference.cases;
    for (const [index, [before, after, witnesses]] of mutations.entries()) {
      assert.equal(sources[READERS].split(before).length - 1, 1, 'exact extended mutation anchor');
      const trial = path.join(root, String(index));
      for (const [relative, source] of Object.entries(sources)) {
        const target = path.join(trial, relative);
        fs.mkdirSync(path.dirname(target), { recursive: true });
        fs.writeFileSync(target, relative === READERS ? source.replace(before, after) : source);
      }
      const result = fixture.run(trial, { extended: true });
      hookCases += result.cases;
      assert.equal(result.broken + result.nativeExecutions + result.unexpectedAttempts + result.settingsAccesses, 0);
      assert.equal(result.sourcesUnchanged, true);
      assert.deepEqual(result.failed, witnesses, 'only the selected extended witnesses change');
      for (const id of witnesses) {
        assert.equal(reference.results.find(row => row.id === id).category, 'UNKNOWN');
        assert.equal(result.results.find(row => row.id === id).category, 'ALLOW');
      }
      assert.deepEqual(result.results.slice(0, reference.previousCases), reference.results.slice(0, reference.previousCases));
      red++;
    }
    assert.equal(red, 3); assert.equal(hookCases, 276);
    t.diagnostic(JSON.stringify({ addedConditions: mutations.length, red, hookCases,
      previousCasesUnchanged: reference.previousCases, sourcePinsStable: reference.sourcesUnchanged }));
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('CX-1107-4 selected source identity has an independent inverse witness', t => {
  const hooks = path.resolve(process.argv[2] || path.join(__dirname, '..'));
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'cx-1107-4-identity-inverse-'));
  const sources = Object.fromEntries(fixture.FILES.map(file => [file, fs.readFileSync(path.join(hooks, file), 'utf8')]));
  try {
    const before = 'hookPath = selectedHook.text.slice(0, -1);';
    assert.equal(sources[READERS].split(before).length - 1, 1);
    for (const [relative, source] of Object.entries(sources)) {
      const target = path.join(root, relative);
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, relative === READERS ? source.replace(before,
        'hookPath = path.resolve(selectedHook.text.slice(0, -1));') : source);
    }
    const reference = fixture.run(hooks, { extended: true }), trial = fixture.run(root, { extended: true });
    assert.deepEqual(reference.failed, []); assert.deepEqual(trial.failed, ['J21']);
    for (const result of [reference, trial]) {
      assert.equal(result.broken + result.nativeExecutions + result.unexpectedAttempts + result.settingsAccesses, 0);
      assert.equal(result.sourcesUnchanged, true);
    }
    assert.deepEqual(trial.results.slice(0, reference.previousCases), reference.results.slice(0, reference.previousCases));
    assert.equal(trial.results.find(row => row.id === 'J21').sourceIdentityDifferences, 1);
    t.diagnostic(JSON.stringify({ mutations: 1, red: 1, hookCases: reference.cases + trial.cases,
      previousCasesUnchanged: reference.previousCases, sourcePinsStable: true }));
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
