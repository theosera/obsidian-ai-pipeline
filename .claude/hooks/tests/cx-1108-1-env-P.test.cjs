'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const Module = require('node:module');
const fixture = require('./cx-1108-1-env-P-fixture.cjs');
const hooks = path.resolve(process.argv[2] || path.join(__dirname, '..'));
const common = path.join(hooks, 'lib/git-guard-common.cjs');
const guard = require(common);
const source = fs.readFileSync(common, 'utf8');
const inspect = command => guard.inspect(command, { trackExecutableSearch: true,
  initialExecutableSearchPathPresent: true, trackOutboundEnvironment: true });
const selected = command => inspect(command).invocations.at(-1);

test('CX-1108-1 recognized env options have explicit, exhaustive dispositions', () => {
  const match = source.match(/const optionEffects = (\{[\s\S]*?\n    \});/);
  assert.ok(match);
  const effects = require('node:vm').runInNewContext('(' + match[1] + ')');
  assert.deepEqual(Object.keys(effects).sort(), ['ignore-environment', 'null', 'unset', 'chdir', 'split-string',
    'argv0', 'debug', 'default-signal', 'ignore-signal', 'block-signal', 'list-signal-handling', 'help', 'version', 'path'].sort());
  const allowed = ['clear', 'unset', 'chdir', 'split-string', 'argv0', 'irrelevant', 'terminal', 'unknown'];
  for (const effect of Object.values(effects)) assert.ok(allowed.includes(effect));
  assert.equal(effects.path, 'unknown');
  // A newly recognized entry with no accounted-for effect must fail closed.
  const marker = 'const optionEffects = {';
  assert.equal(source.split(marker).length - 1, 1);
  const altered = source.replace(marker, marker + "\n      'dummy-unaccounted': 'unaccounted',");
  const alteredModule = new Module(common);
  alteredModule.filename = common; alteredModule.paths = Module._nodeModulePaths(path.dirname(common));
  alteredModule._compile(altered, common);
  const value = alteredModule.exports.inspect('env --dummy-unaccounted curl -q https://example.invalid/').invocations[0];
  assert.equal(value.envUnknown, true, 'an unaccounted-for option must be UNKNOWN');
});

test('CX-1108-1 modeled, irrelevant and terminal options retain their semantics', () => {
  for (const prefix of ['env -i', 'env -', 'env --ignore-environment', 'env -u PATH', 'env --unset=PATH'])
    assert.equal(selected(prefix + ' /usr/bin/curl -q https://example.invalid/').executableSearch.pathPresent, false);
  for (const prefix of ['env -C /DUMMY/cwd', 'env --chdir=/DUMMY/cwd'])
    assert.equal(selected(prefix + ' curl -q https://example.invalid/').cdLikeHere, true);
  for (const prefix of ['env -a DUMMY', 'env --argv0=DUMMY'])
    assert.equal(selected(prefix + ' curl -q https://example.invalid/').argv0Word.text, 'DUMMY');
  for (const prefix of ["env -S 'curl -q https://example.invalid/'", "env --split-string='curl -q https://example.invalid/'"])
    assert.equal(selected(prefix + ' git status').splitString, true);
  for (const option of ['-0', '-v', '--null', '--debug', '--default-signal', '--ignore-signal', '--block-signal', '--list-signal-handling']) {
    const value = selected('env ' + option + ' curl -q https://example.invalid/');
    assert.equal(value.envUnknown, false); assert.equal(value.executableSearch.pathChanged, false);
  }
  for (const option of ['--help', '--version']) assert.equal(selected('env ' + option).nonExec, true);
  assert.equal(selected('env -P').envUnknown, true, 'missing value remains parser UNKNOWN');
  assert.equal(selected('env --path=/DUMMY/search curl -q https://example.invalid/').envUnknown, true,
    'BSD short option must not introduce a supported GNU long option');
});

test('CX-1108-1 direct Hook DATA and one-entry inverse retain exact controls', () => {
  const root = fixture.createFixture(), trial = fs.mkdtempSync(path.join(os.tmpdir(), 'cx-1108-1-source-'));
  const pinsBefore = Object.fromEntries(fixture.RUNTIME.map(file => [file, fixture.pin(path.join(hooks, file))]));
  const run = hooksDir => {
    const child = spawnSync(process.execPath, [path.join(__dirname, 'cx-1108-1-env-P-fixture.cjs'), hooksDir, root], {
      env: { PATH: '/usr/bin:/bin', LC_ALL: 'C', TMPDIR: root }, encoding: 'utf8', timeout: 120000,
      maxBuffer: 4 * 1024 * 1024,
    });
    assert.equal(child.error, undefined); assert.equal(child.signal, null); assert.equal(child.stderr, '');
    const result = JSON.parse(child.stdout);
    assert.equal(result.fatal, undefined, result.fatal);
    return { status: child.status, result };
  };
  try {
    const reference = run(hooks);
    assert.equal(reference.status, 0, JSON.stringify(reference.result.failures));
    assert.deepEqual(reference.result.failures, []);
    assert.equal(reference.result.rows.length, 20); assert.equal(reference.result.hookCalls, 60);
    const before = "version: 'terminal', path: 'unknown'";
    const after = "version: 'terminal', path: 'irrelevant'";
    assert.equal(source.split(before).length - 1, 1, 'the only new -P disposition must be uniquely removable');
    const altered = source.replace(before, after);
    for (const file of fixture.RUNTIME) {
      const target = path.join(trial, file); fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, file === 'lib/git-guard-common.cjs' ? altered : fs.readFileSync(path.join(hooks, file)));
    }
    const inverse = run(trial);
    assert.equal(inverse.status, 1, 'removing only the -P disposition must fail the same focused assertions');
    const changed = ['split-curl', 'attached-curl', 'split-git', 'dynamic-quoted-split', 'dynamic-quoted-attached'];
    assert.deepEqual(inverse.result.failures.slice().sort(), [
      ...changed.flatMap(id => [id + ':parser-unknown', id + ':egress-unknown']),
      'option-table:selection-unknown', 'scope:outer-unknown', 'scope:child-environment-unknown',
    ].sort(), 'inverse failures must identify the intended lost UNKNOWN proof only');
    for (const row of reference.result.rows) {
      const other = inverse.result.rows.find(value => value.id === row.id);
      assert.equal(row.command, other.command); assert.equal(row.input, other.input);
      for (const hook of fixture.HOOKS) {
        assert.notEqual(row.outputs[hook].verdict, 'BROKEN');
        assert.notEqual(other.outputs[hook].verdict, 'BROKEN');
        if (!changed.includes(row.id)) assert.deepEqual(other.outputs[hook], row.outputs[hook], 'every unrelated control must remain identical');
      }
      if (changed.includes(row.id)) assert.equal(other.outputs[fixture.EG].verdict, 'ALLOW', 'inverse must lose the selection protection');
    }
    for (const file of fixture.RUNTIME.filter(file => file !== 'lib/git-guard-common.cjs'))
      assert.deepEqual(inverse.result.sourcePins[file], reference.result.sourcePins[file]);
    assert.equal(inverse.result.sourcePins['lib/git-guard-common.cjs'].sha256, fixture.digest(altered));
    assert.deepEqual(Object.fromEntries(fixture.RUNTIME.map(file => [file, fixture.pin(path.join(hooks, file))])), pinsBefore);
    console.log(JSON.stringify({ evidence: 'CX-1108-1', reference: reference.result, inverse: inverse.result,
      summary: { uniqueInputs: 20, referenceHookCalls: 60, inverseHookCalls: 60, inverseFailedAssertions: 13,
        broken: 0, unexpectedChildAttempts: 0, proposedCommandsExecuted: 0 } }));
  } finally { fs.rmSync(root, { recursive: true, force: true }); fs.rmSync(trial, { recursive: true, force: true }); }
});
