'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const guard = require('../lib/git-guard-common.cjs');
const word = text => ({ text, raw: JSON.stringify(text), quoted: true, dynamic: false, dynamicMaySplit: false });
const inherited = { GIT_DIR: '/DUMMY/base/.git', HOME: '/DUMMY/home', PATH: '/usr/bin:/bin', GIT_PAGER: 'cat' };
function inspect(command, values = inherited) {
  return guard.inspect(command, { trackGitPreCommitEnvironment: true,
    initialGitPreCommitEnvironmentSources: Object.entries(values).map(([name, text]) => ({ name, word: word(text) })) });
}
const gitCalls = result => result.invocations.filter(invocation => invocation.name === 'git');
const selected = invocation => new Map(invocation.gitPreCommitEnvironmentSources.map(source => [source.name, source.word]));
const value = (invocation, name) => selected(invocation).get(name)?.text;

test('pre-commit snapshots require opt-in and do not turn inherited HOME into a shell mutation', () => {
  const ordinary = gitCalls(guard.inspect('git status'))[0];
  assert.deepEqual(ordinary.gitPreCommitEnvironmentSources, []);
  assert.equal(ordinary.gitPreCommitEnvironmentUnknown, false);
  const enabled = gitCalls(inspect('git status'))[0];
  assert.equal(value(enabled, 'HOME'), '/DUMMY/home');
  assert.equal(enabled.gitEnvNames.includes('HOME'), false);
});

test('prefix target applies to the selected Git only, then the inherited target resumes', () => {
  const calls = gitCalls(inspect('GIT_DIR=/DUMMY/other git status; git commit -m x'));
  assert.deepEqual(calls.map(call => value(call, 'GIT_DIR')), ['/DUMMY/other', '/DUMMY/base/.git']);
});

test('unexported target local is absent, whereas an exported target is selected', () => {
  assert.equal(selected(gitCalls(inspect('GIT_WORK_TREE=/DUMMY/local; git status'))[0]).has('GIT_WORK_TREE'), false);
  assert.equal(value(gitCalls(inspect('export GIT_WORK_TREE=/DUMMY/exported; git status'))[0], 'GIT_WORK_TREE'), '/DUMMY/exported');
});

test('assignment preserves an inherited export attribute and a known empty pager', () => {
  const call = gitCalls(inspect('GIT_PAGER=; git diff'))[0];
  assert.equal(selected(call).has('GIT_PAGER'), true);
  assert.equal(value(call, 'GIT_PAGER'), '');
});

test('actual env -u removes a selected name only from that child', () => {
  const calls = gitCalls(inspect('env -u GIT_DIR git status; git commit -m x'));
  assert.equal(selected(calls[0]).has('GIT_DIR'), false);
  assert.equal(value(calls[1], 'GIT_DIR'), '/DUMMY/base/.git');
});

test('actual env -i leaves no inherited Git, root, pager or PATH snapshot', () => {
  const call = gitCalls(inspect('env -i git --version'))[0];
  assert.deepEqual(call.gitPreCommitEnvironmentSources, []);
});

test('shell unset is absence rather than an inherited-value fallback', () => {
  const call = gitCalls(inspect('unset GIT_DIR; unset HOME; git status'))[0];
  assert.equal(selected(call).has('GIT_DIR'), false);
  assert.equal(selected(call).has('HOME'), false);
});

test('conditional target export remains opaque instead of choosing either branch', () => {
  const call = gitCalls(inspect('if test x; then export GIT_DIR=/DUMMY/conditional; fi; git status'))[0];
  assert.equal(selected(call).has('GIT_DIR'), true);
  assert.equal(selected(call).get('GIT_DIR'), null);
});

test('subshell and function-prefix selections do not replace the outer target', () => {
  const subshell = gitCalls(inspect('(export GIT_DIR=/DUMMY/sub; git status); git status'));
  assert.deepEqual(subshell.map(call => value(call, 'GIT_DIR')), ['/DUMMY/sub', '/DUMMY/base/.git']);
  const calls = gitCalls(inspect('f() { GIT_DIR=/DUMMY/function git status; }; f; git status'));
  assert.deepEqual(calls.map(call => value(call, 'GIT_DIR')), ['/DUMMY/function', '/DUMMY/base/.git']);
});

test('an unsupported mediated Git source is not promoted into a certified child snapshot', () => {
  const result = inspect("sh -c 'env -u GIT_DIR git status'");
  assert.equal(gitCalls(result).length, 0);
  assert.ok(result.problems.some(problem => problem.includes('source') && problem.includes('git')));
  const shell = result.invocations.find(invocation => invocation.name === 'sh');
  assert.equal(value(shell, 'GIT_DIR'), '/DUMMY/base/.git');
});

test('Git config count and key/value slots keep their actual ordered selections', () => {
  const values = { ...inherited, GIT_CONFIG_COUNT: '1', GIT_CONFIG_KEY_0: 'core.fsmonitor', GIT_CONFIG_VALUE_0: '/DUMMY/monitor' };
  const calls = gitCalls(inspect('GIT_CONFIG_COUNT=0 git status; env -u GIT_CONFIG_COUNT git status; git status', values));
  assert.equal(value(calls[0], 'GIT_CONFIG_COUNT'), '0');
  assert.equal(value(calls[0], 'GIT_CONFIG_VALUE_0'), '/DUMMY/monitor');
  assert.equal(selected(calls[1]).has('GIT_CONFIG_COUNT'), false);
  assert.equal(value(calls[2], 'GIT_CONFIG_COUNT'), '1');
});

test('the opt-in family does not capture unrelated environment values', () => {
  const call = gitCalls(inspect('git status', { ...inherited, UNRELATED_DUMMY: 'ordinary' }))[0];
  assert.equal(selected(call).has('UNRELATED_DUMMY'), false);
  assert.equal(guard.gitPreCommitEnvironmentName('GIT_CONFIG_VALUE_0'), true);
  assert.equal(guard.gitPreCommitEnvironmentName('PAGER'), true);
  assert.equal(guard.gitPreCommitEnvironmentName('invalid=name'), false);
});


test('an unresolved exported name keeps environment uncertainty explicit', () => {
  const call = gitCalls(inspect('export "$CHOICE"; git status'))[0];
  assert.equal(call.gitPreCommitEnvironmentUnknown, true);
});

test('actual command -p search survives unwrapping without treating consumed or printed DATA as selection', () => {
  assert.equal(gitCalls(inspect('command -p git status'))[0].commandDefaultSearch, true);
  assert.equal(gitCalls(inspect('command -pp git status'))[0].commandDefaultSearch, true);
  assert.equal(gitCalls(inspect('command git status'))[0].commandDefaultSearch, false);
  assert.equal(gitCalls(inspect('command -- git status'))[0].commandDefaultSearch, false);
  assert.equal(gitCalls(inspect('git -c user.name=-p status'))[0].commandDefaultSearch, false);
  assert.equal(inspect("printf '%s' 'command -p git status'").invocations[0].commandDefaultSearch, false);
  assert.equal(gitCalls(inspect('command -pv git')).length, 0);
});
