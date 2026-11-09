'use strict';
/** Fault-inject static Hook wire DATA into the public runner; no proposed command executes. */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const hooks = path.resolve(process.argv[2] || path.join(__dirname, '..'));
const runnerFile = path.join(hooks, 'tests/git-guards.test.cjs');
const runner = require(runnerFile);
const bankHash = () => crypto.createHash('sha256').update(JSON.stringify(runner.CASES)).digest('hex');
const sourceBefore = fs.readFileSync(runnerFile);
const bankBefore = bankHash();
const deniedWire = reason => ({ hookSpecificOutput: { permissionDecision: 'deny', ...(reason === undefined ? {} : { permissionDecisionReason: reason }) } });
const wires = {
  missing: deniedWire(undefined), empty: deniedWire(''), unknown: deniedWire('DUMMY unclassified'),
  nonstring: deniedWire(7), nearPrefix: deniedWire('[禁止]DUMMY'),
  forbidden: deniedWire('[禁止] DUMMY'), unknownKnown: deniedWire('[判断不能] DUMMY'),
};

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pr191-r51-runner-wire-'));
  for (const directory of ['hooks', 'tests', 'home', 'tmp', 'repo']) fs.mkdirSync(path.join(root, directory));
  const env = { PATH: path.dirname(process.execPath), HOME: path.join(root, 'home'), TMPDIR: path.join(root, 'tmp'),
    GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_SYSTEM: '/dev/null', LC_ALL: 'C' };
  const repos = { root, env, dirs: { clean: path.join(root, 'repo') } };
  for (const name of runner.HOOKS) {
    fs.writeFileSync(path.join(root, 'hooks', name), `
      'use strict';
      require('node:fs').readFileSync(0, 'utf8'); // Consume Hook DATA, never evaluate it.
      if (require('node:path').basename(__filename) !== process.env.R51_SELECTED_HOOK) process.exit(0);
      if (process.env.R51_WIRE_MODE === 'exit') process.exit(7);
      if (process.env.R51_WIRE_MODE === 'json') { process.stdout.write('DUMMY not JSON'); process.exit(0); }
      if (process.env.R51_WIRE_MODE !== 'allow') process.stdout.write(JSON.stringify(${JSON.stringify(wires)}[process.env.R51_WIRE_MODE]));
    `);
  }
  // Keep the entire source bank and ledger binding. After those bind, the private harness
  // selects one original case and substitutes owned non-Git setup, then calls the real main.
  const entry = 'if (require.main === module) main();';
  const source = sourceBefore.toString('utf8');
  assert.equal(source.split(entry).length, 2);
  const setup = `
    if (require.main === module) {
      const selected = CASES.find(c => c.id === process.env.R51_CASE_ID);
      if (!selected || !['N01', 'N10', 'N14'].includes(selected.id)) throw new Error('R51_BOUNDED_CASE');
      CASES.splice(0, CASES.length, selected);
      setupRepos = () => ({ root: ${JSON.stringify(root)}, env: { ...process.env }, dirs: { clean: ${JSON.stringify(repos.dirs.clean)} } });
      cleanupRepos = () => {};
      main();
    }
  `;
  const entryFile = path.join(root, 'tests/git-guards.test.cjs');
  fs.writeFileSync(entryFile, source.replace(entry, setup));
  for (const name of ['r38-guard-oracle-adjustments.json', 'r39-review-cases.json', 'r40-precommit-cases.json',
    'r40-precommit-oracle-adjustments.json', 'r41-signature-source-oracle-adjustments.json']) {
    fs.copyFileSync(path.join(path.dirname(runnerFile), name), path.join(root, 'tests', name));
  }
  return {
    root, repos, hooksDir: path.join(root, 'hooks'),
    direct(mode, hook, stop = false) {
      return runner.runCase(path.join(root, 'hooks'), { id: 'R51-DUMMY', cmd: 'printf DUMMY',
        env: { R51_WIRE_MODE: mode, R51_SELECTED_HOOK: hook } }, repos, stop);
    },
    cli(mode, hook, json = true, id = 'N10') {
      return spawnSync(process.execPath, [entryFile, '--hooks-dir', path.join(root, 'hooks'), ...(json ? ['--json'] : [])], {
        env: { ...env, R51_WIRE_MODE: mode, R51_SELECTED_HOOK: hook, R51_CASE_ID: id }, cwd: repos.dirs.clean,
        encoding: 'utf8', timeout: 20000,
      });
    },
    close() { fs.rmSync(root, { recursive: true, force: true }); },
  };
}

// R51_TESTS_BEGIN
test('every Hook missing, empty, unknown or nonstring deny reason is broken, including early stop', () => {
  const f = fixture();
  try {
    for (const hook of runner.HOOKS) for (const mode of ['missing', 'empty', 'unknown', 'nonstring', 'nearPrefix']) {
      const row = f.direct(mode, hook);
      assert.equal(row.decision, 'deny');
      assert.equal(row.reasonPrefixes[hook], null);
      assert.equal(row.broken.length, 1, `${hook}/${mode}: ${JSON.stringify(row)}`);
      assert.match(row.broken[0], /unrecognized deny reason prefix/);
    }
    assert.equal(f.direct('unknown', runner.HOOKS[0], true).broken.length, 1);
  } finally { f.close(); }
});

test('bounded public JSON entrypoint rejects malformed deny wire for a generic original deny case', () => {
  const f = fixture();
  try {
    for (const mode of ['missing', 'empty', 'unknown', 'nonstring', 'nearPrefix']) {
      const result = f.cli(mode, runner.HOOKS[2]);
      assert.ifError(result.error);
      assert.equal(result.status, 1, result.stdout);
      assert.equal(result.stderr, '');
      const out = JSON.parse(result.stdout);
      assert.equal(out.total, 1);
      assert.equal(out.failed, 1);
      assert.equal(out.results[0].id, 'N10');
      assert.equal(out.results[0].ok, false);
      assert.equal(out.results[0].ownEG, 'UNCLASSIFIED');
      assert.equal(out.results[0].broken.length, 1);
    }
  } finally { f.close(); }
});

test('bounded public text entrypoint reports invalid deny as failed and exits nonzero', () => {
  const f = fixture();
  try {
    const result = f.cli('unknown', runner.HOOKS[0], false);
    assert.ifError(result.error);
    assert.equal(result.status, 1);
    assert.equal(result.stderr, '');
    assert.match(result.stdout, /unrecognized deny reason prefix/);
    assert.match(result.stdout, /0\/1 ok\n$/);
  } finally { f.close(); }
});

test('known deny prefixes retain each own Hook classification and generic deny acceptance', () => {
  const f = fixture();
  try {
    for (const [mode, own] of [['forbidden', 'FORBIDDEN'], ['unknownKnown', 'UNKNOWN']]) {
      for (const [hook, suffix] of runner.HOOKS.map((hook, index) => [hook, ['SG', 'AG', 'EG'][index]])) {
        const result = f.cli(mode, hook);
        assert.ifError(result.error);
        assert.equal(result.status, 0, result.stderr);
        const out = JSON.parse(result.stdout);
        assert.equal(out.failed, 0);
        assert.equal(out.results[0]['own' + suffix], own);
        assert.deepEqual(out.results[0].broken, []);
      }
    }
  } finally { f.close(); }
});

test('empty ALLOW wire and existing execution/JSON failures retain their classifications', () => {
  const f = fixture();
  try {
    const result = f.cli('allow', runner.HOOKS[0], true, 'N01');
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stderr);
    const out = JSON.parse(result.stdout);
    assert.equal(out.failed, 0);
    assert.deepEqual(out.results[0].broken, []);
    assert.deepEqual([out.results[0].ownSG, out.results[0].ownAG, out.results[0].ownEG], ['ALLOW', 'ALLOW', 'ALLOW']);
    for (const mode of ['exit', 'json']) assert.equal(f.direct(mode, runner.HOOKS[0]).broken.length, 1);
  } finally { f.close(); }
});

test('an original strict UNKNOWN-prefix case still rejects a different known deny classification', () => {
  const f = fixture();
  try {
    for (const [mode, status] of [['unknownKnown', 0], ['forbidden', 1]]) {
      const result = f.cli(mode, runner.HOOKS[2], true, 'N14');
      assert.ifError(result.error);
      assert.equal(result.status, status, result.stdout);
      const row = JSON.parse(result.stdout).results[0];
      assert.equal(row.id, 'N14');
      assert.deepEqual(row.broken, []);
      assert.equal(row.ok, status === 0);
    }
  } finally { f.close(); }
});

test('fault injection leaves the accepted 8696 bank, ledger inputs and runner source unchanged', () => {
  assert.equal(runner.CASES.length, 8696);
  assert.equal(bankBefore, '450e94994846d221d3056b1580822b513d6f87c5f086f14b7b95389c85a46b75');
  assert.equal(bankHash(), bankBefore);
  assert.deepEqual(fs.readFileSync(runnerFile), sourceBefore);
});
