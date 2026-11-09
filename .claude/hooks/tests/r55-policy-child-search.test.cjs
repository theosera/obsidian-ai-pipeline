'use strict';
// Parser/filesystem-model tests. No sudo/doas, client, shell source or payload executes.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const hooks = path.resolve(process.argv[2] || path.join(__dirname, '..'));
const guard = require(path.join(hooks, 'lib/git-guard-common.cjs'));
const modulePath = path.join(hooks, 'lib/executable-identity.cjs');
const inspect = command => guard.inspect(command, { trackExecutableSearch: true,
  initialExecutableSearchPathPresent: true, trackOutboundEnvironment: true });
const selected = command => inspect(command).invocations.at(-1);
const fakeFs = {
  constants: { X_OK: 1 },
  statSync(file) { check(file); return { isFile: () => true }; },
  accessSync(file) { check(file); },
  realpathSync: { native(file) { check(file); return file; } },
};
const installed = new Set(['sudo', 'doas', 'curl', 'env', 'bash', 'printf'].map(name => '/usr/bin/' + name));
function check(file) {
  if (!installed.has(file)) throw Object.assign(new Error('owned missing candidate'), { code: 'ENOENT' });
}
const moduleObject = { exports: {} };
vm.runInNewContext(fs.readFileSync(modulePath, 'utf8'), { module: moduleObject,
  exports: moduleObject.exports, process: { platform: 'linux' }, require(name) {
    if (name === 'node:fs') return fakeFs;
    if (name === 'node:path') return path.posix;
    throw Error('Unexpected dependency: ' + name);
  } }, { filename: modulePath });
const identity = invocation => moduleObject.exports.invocationExecutableIdentity(invocation,
  { environment: { PATH: '/usr/bin' }, cwd: '/owned', builtinNames: ['printf'] });

for (const launcher of ['sudo', 'doas']) {
  test(launcher + ' keeps launcher lookup separate from its policy-selected bare child', () => {
    const value = selected(launcher + ' curl -q --version');
    assert.equal(value.wrapperProgramWords[0].executableSearch.pathChanged, false);
    assert.equal(value.executableSearch.pathChanged, true);
    assert.equal(identity(value).kind, 'unknown-search');
    for (const prefix of [launcher + ' -- ', '/usr/bin/' + launcher + ' ']) {
      const alternative = selected(prefix + 'curl -q --version');
      assert.equal(alternative.executableSearch.pathChanged, true);
      assert.equal(identity(alternative).kind, 'unknown-search');
    }
  });

  test(launcher + ' propagates lookup uncertainty to the next wrapper before the final absolute child', () => {
    const value = selected(launcher + ' env /usr/bin/curl -q --version');
    assert.deepEqual(value.wrapperProgramWords.map(entry => entry.name), [launcher, 'env']);
    assert.deepEqual(value.wrapperProgramWords.map(entry => entry.executableSearch.pathChanged), [false, true]);
    assert.equal(identity(value).kind, 'unknown-search');
    const absolute = selected(launcher + ' /usr/bin/env /usr/bin/curl -q --version');
    assert.equal(identity(absolute).kind, 'trusted-external');
  });

  test(launcher + ' preserves absolute child identity without certifying policy or permissions', () => {
    const value = selected(launcher + ' /usr/bin/curl -q --version');
    assert.equal(value.executableSearch.pathChanged, true);
    assert.equal(identity(value).kind, 'trusted-external');
    const options = launcher === 'sudo' ? '--prompt curl ' : '-u root ';
    assert.equal(identity(selected(launcher + ' ' + options + '/usr/bin/curl -q --version')).kind, 'trusted-external');
  });

  test(launcher + ' carries unknown lookup into source inside an absolute child shell', () => {
    const outer = selected(launcher + ' /usr/bin/bash -c "curl -q --version"');
    assert.equal(identity(outer).kind, 'trusted-external');
    assert.equal(outer.executableSearch.pathChanged, true);
    const inner = command => guard.inspect(command, { trackExecutableSearch: true,
      initialExecutableSearchPathPresent: true,
      initialExecutableSearchChanged: outer.executableSearch.pathChanged }).invocations.at(-1);
    assert.equal(identity(inner('curl -q --version')).kind, 'unknown-search');
    assert.equal(identity(inner('/usr/bin/curl -q --version')).kind, 'trusted-external');
    assert.equal(identity(inner('printf ordinary')).kind, 'builtin');
  });

  test(launcher + ' does not contaminate a following independent statement', () => {
    const values = inspect(launcher + ' curl -q --version; curl -q --version').invocations;
    assert.equal(values.length, 2);
    assert.equal(values[0].executableSearch.pathChanged, true);
    assert.equal(values[1].executableSearch.pathChanged, false);
    assert.equal(identity(values[1]).kind, 'trusted-external');
  });

  test(launcher + ' environment clearing and removal cannot restore inherited child lookup', () => {
    for (const middle of ['-i', '-u PATH']) {
      const bare = selected(launcher + ' /usr/bin/env ' + middle + ' curl -q --version');
      assert.equal(bare.executableSearch.pathPresent, false);
      assert.equal(identity(bare).kind, 'unknown-search');
      assert.equal(identity(selected(launcher + ' /usr/bin/env ' + middle + ' /usr/bin/curl -q --version')).kind, 'trusted-external');
    }
  });
}

test('sudo preserve-env forms are not proof of a preserved policy-selected PATH', () => {
  for (const option of ['-E', '--preserve-env', '--preserve-env=PATH']) {
    const value = selected('sudo ' + option + ' curl -q --version');
    assert.equal(value.executableSearch.pathChanged, true);
    assert.equal(identity(value).kind, 'unknown-search');
  }
});

test('genuine no-child queries do not introduce a child search boundary', () => {
  for (const command of ['sudo -V', 'sudo --help', 'doas -L', 'doas -C /DUMMY/config curl']) {
    const value = selected(command);
    assert.equal(value.nonExec, true, command);
    assert.equal(value.executableSearch.pathChanged, false, command);
    assert.equal(value.wrapperProgramWords[0].executableSearch.pathChanged, false, command);
  }
});

test('printed DATA and a selected local function do not activate a wrapper policy boundary', () => {
  const value = selected("printf '%s' 'sudo curl -q --version'");
  assert.equal(value.executableSearch.pathChanged, false);
  assert.equal(identity(value).kind, 'builtin');
  const fn = inspect('sudo(){ printf ordinary; }; sudo curl -q --version').invocations.find(value => value.functionCallName === 'sudo');
  assert.equal(fn.functionCallName, 'sudo');
  assert.deepEqual(fn.wrapperNames, []);
  assert.equal(fn.executableSearch.pathChanged, false);
});
