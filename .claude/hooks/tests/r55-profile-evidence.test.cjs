'use strict';
// Execute only the runner's main function with synthetic cases, wire rows and
// filesystem observations. No fixture setup, Hook or selected program runs.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const crypto = require('node:crypto');
const hooks = path.resolve(process.argv[2] || path.join(__dirname, '..'));
const profile = require(path.join(hooks, 'tests/executable-profile-qualification.cjs'));
const source = fs.readFileSync(path.join(hooks, 'tests/git-guards.test.cjs'), 'utf8');
const SG = 'block-secret-git.cjs', AG = 'block-git-add-all.cjs', EG = 'block-secret-egress.cjs';
const HOOKS = [SG, AG, EG];
const PREFIX = 'Executable profile evidence: ';
const hash = value => crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');

function runText({ declared = true, presence = 'present', failed = false } = {}) {
  const c = { id: 'R55-SYNTHETIC', cmd: 'curl -q https://ordinary.invalid', expect: 'allow', allowBy: EG };
  const cases = [c], originalHash = hash(cases);
  const ledger = { schema: 'R54_SELECTED_EXECUTABLE_TEST_PROFILE_V1',
    baselineCount: 1, baselineDefinitionsSHA256: originalHash,
    entries: declared ? [{ id: c.id, originalCaseSHA256: hash(c),
      rootPriorityDisposition: 'DEPENDENT_SELECTED_SOURCE_ONLY',
      stages: [{ kind: 'NO_SELECTED_EXECUTABLE_NO_NAMED_INSTALL', word: 'curl',
        stageKind: 'callee', stageIndex: 0, searchBinding: 'UNCHANGED_INHERITED_PATH',
        searchSnapshot: { pathPresent: true, pathChanged: false, defaultSearch: false } }] }] : [] };
  const filesystemCalls = [], lines = [], calls = [];
  const filesystem = {
    statSync(file) {
      filesystemCalls.push(['stat', file]);
      if (presence !== 'present') throw Object.assign(Error('DUMMY filesystem observation'), { code: presence === 'missing' ? 'ENOENT' : 'EIO' });
      return { isFile: () => true };
    },
    accessSync(file) { filesystemCalls.push(['access', file]); },
  };
  let cleanups = 0;
  const processDTO = { argv: ['node', 'DUMMY', '--hooks-dir', '/DUMMY/hooks', '--executable-profile'],
    exitCode: null, stdout: { write() { throw Error('unexpected JSON output'); } },
    exit() { throw Error('unexpected synthetic process.exit'); } };
  const mainStart = source.indexOf('function main() {'), mainEnd = source.indexOf('\n}\n', mainStart);
  assert.ok(mainStart >= 0 && mainEnd > mainStart);
  assert.equal(source.indexOf('function main() {', mainStart + 1), -1);
  const sandbox = {
    process: processDTO, __dirname: '/DUMMY/hooks/tests', path, CASES: cases, HOOKS,
    console: { log(value) { lines.push(value); }, error() { throw Error('unexpected error output'); } },
    require(name) {
      if (name === './executable-profile-qualification.cjs') return { ...profile,
        createProfile(inputs, declarations) { return profile.createProfile(inputs, declarations, filesystem); } };
      if (name === './fixtures/r54-selected-executable-profile.json') return ledger;
      throw Error('unexpected synthetic dependency: ' + name);
    },
    setupRepos() { return { env: { PATH: '/DUMMY/profile/bin' }, dirs: { clean: '/DUMMY/project' }, fixtureEnvironmentSets: {} }; },
    cleanupRepos() { cleanups++; },
    runCase(directory, input, repos, stopAtFirstDeny, captureReasonTexts) {
      calls.push(input.id);
      assert.equal(directory, path.resolve('/DUMMY/hooks'));
      assert.equal(stopAtFirstDeny, false);
      assert.equal(captureReasonTexts, true);
      const denied = declared && presence === 'missing' || failed;
      const prefix = failed ? '[禁止] ' : '[判断不能] ';
      return { id: input.id, decision: denied ? 'deny' : 'allow', denied: denied ? [EG] : [], broken: [],
        reasonPrefixes: denied ? { [EG]: prefix } : {},
        reasonTexts: denied ? { [EG]: prefix + 'DUMMY controlled wire reason' } : {} };
    },
  };
  vm.runInNewContext(source.slice(mainStart, mainEnd + 3) + '\nmain();', sandbox, { filename: 'r55-pure-profile-main.cjs' });
  assert.deepEqual(calls, [c.id]);
  assert.equal(cleanups, 1);
  assert.equal(hash(cases), originalHash, 'emission must not change original cases or assertions');
  return { rows: lines.filter(line => line.startsWith(PREFIX)).map(line => JSON.parse(line.slice(PREFIX.length))),
    lines, exitCode: processDTO.exitCode, filesystemCalls };
}

for (const presence of ['present', 'missing', 'io_unknown']) {
  test('text evidence retains declared ' + presence + ' case independently of applicability', () => {
    const { rows, lines, exitCode, filesystemCalls } = runText({ presence });
    assert.equal(rows.length, 1);
    const row = rows[0], applies = presence === 'missing';
    assert.equal(row.id, 'R55-SYNTHETIC');
    assert.equal(row.qualification.source, 'declaration-and-independent-filesystem-only');
    assert.equal(row.qualification.applies, applies);
    assert.equal(row.qualification.originalSemanticAssertionsRetained, !applies);
    assert.equal(row.originalOK, !applies);
    assert.equal(row.profileOK, true);
    assert.equal(row.qualificationStable, true);
    assert.equal(row.operationalReasonFailure, false);
    assert.equal(row.ownEG, applies ? 'UNKNOWN' : 'ALLOW');
    assert.equal(row.ownSG, 'ALLOW');
    assert.equal(row.ownAG, 'ALLOW');
    assert.equal(filesystemCalls.filter(([operation]) => operation === 'stat').length, 2);
    assert.equal(row.qualification.reasons.length, applies ? 1 : 0, 'I/O unknown must not become absence');
    if (applies) assert.equal(row.qualification.reasons[0].reason, 'no-executable-in-explicit-actual-path');
    assert.equal(lines.includes('1/1 ok'), true);
    assert.equal(lines.includes('Original oracle: ' + (applies ? '0' : '1') + '/1 pass; explicit profile prerequisites active: ' + (applies ? '1' : '0') + '; operational denial failures: 0'), true);
    assert.equal(exitCode, 0);
  });
}

test('ordinary nondeclared passing cases do not add profile evidence noise', () => {
  const { rows, lines, exitCode, filesystemCalls } = runText({ declared: false });
  assert.deepEqual(rows, []);
  assert.deepEqual(filesystemCalls, []);
  assert.equal(lines.includes('1/1 ok'), true);
  assert.equal(exitCode, 0);
});

test('nondeclared failures retain their diagnostic row and original failure', () => {
  const { rows, lines, exitCode } = runText({ declared: false, failed: true });
  assert.equal(rows.length, 1);
  assert.equal(rows[0].qualification.source, 'original-oracle-no-profile-declaration');
  assert.equal(rows[0].qualification.applies, false);
  assert.equal(rows[0].originalOK, false);
  assert.equal(rows[0].profileOK, false);
  assert.equal(rows[0].ownEG, 'FORBIDDEN');
  assert.equal(lines.includes('0/1 ok'), true);
  assert.equal(exitCode, 1);
});
