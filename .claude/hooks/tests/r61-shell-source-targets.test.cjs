'use strict';
// All shell text below is DATA for inspect. No shell, Git, network or Hook child runs here.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const cp = require('node:child_process');
let childAttempts = 0;
for (const name of ['execFileSync', 'spawnSync', 'execFile', 'spawn', 'execSync', 'exec', 'fork']) {
  cp[name] = () => { childAttempts++; throw Error('R61 L1 must not launch a child'); };
}
const hooks = path.resolve(process.argv[2] || path.join(__dirname, '..'));
const { inspect, gitTransportClientRole, gitTransportSourceRole } = require(path.join(hooks, 'lib/git-guard-common.cjs'));
const options = { trackOutboundEnvironment: true, trackExecutableSearch: true,
  trackGitPreCommitEnvironment: true, trackGitIndexInspectionEnvironment: true };
const analyse = source => inspect(source, options);
const handler = 'command_not_found_handle(){ printf DUMMY; }; ';
const cnf = source => analyse(source).invocations.filter(i => i.commandNotFoundSourceUnknown);
const unknown = source => assert.ok(analyse(source).problems.some(p => p.includes('wait -p')), source);
const ordinary = source => assert.deepEqual(analyse(source).problems, [], source);

for (const [label, suffix] of [
  ['literal failed lookup', 'definitely_missing_xyz'],
  ['command bypasses function lookup but retains failed external lookup', 'command definitely_missing_xyz'],
  ['command default search is still unproved', 'command -p definitely_missing_xyz'],
  ['dynamic command identity', '"$DUMMY_COMMAND"'],
  ['unproved outer launcher', 'nohup definitely_missing_xyz'],
  ['disabled builtin is no longer certified', 'enable -n printf; printf ordinary'],
]) test('R61 implicit callback: ' + label, () => {
  const a = analyse(handler + suffix);
  assert.ok(a.problems.some(p => p.includes('command_not_found_handle')));
  assert.ok(a.invocations.some(i => i.commandNotFoundRole));
  assert.equal(a.invocations.some(i => i.functionCallName === 'command_not_found_handle'), false);
});

for (const [label, suffix] of [
  ['successful literal builtin', 'printf ordinary'],
  ['successful command builtin', 'command printf ordinary'],
  ['builtin lookup does not fall back to command-not-found', 'builtin definitely_missing_xyz'],
  ['exec failure does not fall back to command-not-found', 'exec definitely_missing_xyz'],
  ['slash name has no command-not-found lookup', './definitely_missing_xyz'],
  ['absolute outer launcher is a separate child boundary', '/usr/bin/nohup definitely_missing_xyz'],
  ['real query', 'command -v definitely_missing_xyz'],
  ['printed callback name is DATA', "printf '%s' command_not_found_handle"],
  ['actual function removal', 'unset -f command_not_found_handle; definitely_missing_xyz'],
]) test('R61 inactive callback: ' + label, () => {
  assert.deepEqual(cnf(handler + suffix), []);
  ordinary(handler + suffix);
});

test('R61 slash inactivity proof requires a preserved executable word boundary', () => {
  assert.equal(cnf(handler + 'prefix$DUMMY/bin').length, 1);
  assert.equal(cnf(handler + '"$DUMMY/bin"').length, 0);
});
test('R61 dormant callback preserves the real shopt builtin query', () => {
  ordinary(handler + 'shopt -q nullglob');
  ordinary(handler + 'command shopt -q nullglob');
});
test('R61 actual unquoted [[ syntax cannot select the callback, but lookalikes can', () => {
  ordinary(handler + '[[ ordinary = ordinary ]]');
  for (const suffix of ["'[[' ordinary = ordinary ']]'", '\\[\\[ ordinary = ordinary \\]\\]', 'command [[ ordinary = ordinary ]]']) {
    assert.equal(cnf(handler + suffix).length, 1, suffix);
  }
});
test('R61 unused imported callback does not reject a successful builtin', () => {
  const a = inspect('printf ordinary', { ...options, initialFunctionSourceNames: ['command_not_found_handle'] });
  assert.deepEqual(a.problems, []);
});
test('R61 imported callback active lookup remains unresolved source', () => {
  const a = inspect('definitely_missing_xyz', { ...options, initialFunctionSourceNames: ['command_not_found_handle'] });
  assert.ok(a.problems.some(p => p.includes('command_not_found_handle')));
});
test('R61 unset-v does not remove the function; readonly/conditional removal is not proof', () => {
  for (const prefix of ['unset -v command_not_found_handle; ',
    'readonly -f command_not_found_handle; unset -f command_not_found_handle; ',
    'declare -fr command_not_found_handle; unset -f command_not_found_handle; ',
    'if :; then unset -f command_not_found_handle; fi; ']) {
    assert.equal(cnf(handler + prefix + 'definitely_missing_xyz').length, 1, prefix);
  }
});
test('R61 explicit function call retains actual body inspection and no implicit-role claim', () => {
  const a = analyse(handler + 'command_not_found_handle');
  assert.deepEqual(a.problems, []);
  assert.equal(a.invocations.find(i => i.functionCallName).functionCallName, 'command_not_found_handle');
  assert.ok(a.invocations.some(i => i.name === 'printf'));
  assert.deepEqual(a.invocations.filter(i => i.commandNotFoundRole), []);
});

for (const command of [
  "wait -p 'a[$(printf DUMMY)]' 123",
  "wait -np 'a[$(printf DUMMY)]' 123",
  "wait -fp'a[$(printf DUMMY)]' 123",
  "wait -p 'a[$(printf DUMMY)]' -p 'b[$(printf DUMMY)]' 123",
  'wait -p "$UNKNOWN_TARGET" 123',
  'wait --unknown -p status 123',
  'wait -p',
]) test('R61 wait target evaluation UNKNOWN: ' + command, () => unknown(command));

for (const command of [
  'wait', 'wait 123', 'wait -- 123', 'wait -n 123', 'wait -f 123',
  'wait --help', 'wait -p status 123', 'wait -np status 123', 'wait -pstatus 123',
  "wait -p 'a[0]' 123", "wait -p 'a[1+2]' 123",
  "wait -p 'a[$(printf DUMMY)]' -p status 123",
  "wait -- -p 'a[$(printf DUMMY)]'", // after -- is PID DATA, not a variable target
  "printf '%s' \"wait -p a[DATA]\"",
]) test('R61 normal wait/printed DATA: ' + command, () => ordinary(command));

test('R61 directly saved PID kind preserves original ordinary wait controls without literal promotion', () => {
  for (const source of ['sleep 0 & p=$!; wait "$p"', 'sleep 0 & p=$!; wait -p status "$p"',
    'sleep 0 & p="$!"; wait -p status "${p}"', 'wait "$!"']) ordinary(source);
  const a = analyse('sleep 0 & p=$!; wait -p status "$p"').invocations.at(-1);
  assert.equal(a.args.at(-1).dynamic, true);
  assert.equal(a.args.at(-1).literalValue, undefined);
});
test('R61 PID kind does not survive readonly, nameref, conditional assignment or delayed writer', () => {
  for (const source of ['readonly p=ordinary; p=$!; wait "$p"',
    'declare -n p=other; p=$!; wait "$p"', 'if :; then p=$!; fi; wait "$p"',
    'trap \'read p\' EXIT; p=$!; wait "$p"', 'p=$!; printf ordinary; wait "$p"',
    'p=$!; wait -p "$p" 123', 'p=$!; wait $p']) unknown(source);
});
test('R61 later same-command assignment invalidates saved PID kind before option parsing', () => {
  for (const prefix of ['p=$! p=-p;', 'p=$! p[0]=-p;', 'p=$! p+=-p;', 'p=$! p=(-p);']) {
    const source = prefix + " wait \"$p\" 'a[$(printf DUMMY)]' 123";
    const a = analyse(source);
    assert.ok(a.problems.some(p => p.includes('wait -p')), source);
    const role = a.invocations.findLast(i => i.name === 'wait').waitAssignmentRole;
    if (prefix === 'p=$! p=-p;') assert.equal(role.targetWord.text, 'a[$(printf DUMMY)]');
    else assert.equal(role.unknown, true, 'unproved array/append/compound scalar remains UNKNOWN');
  }
  ordinary('p=$! q=ordinary; wait "$p"');
});
test('R61 static wait target does not invalidate an unrelated exported scalar source', () => {
  const a = analyse('export GIT_SSH_COMMAND=ordinary; wait -p status 999999999; git push origin main');
  assert.equal(a.invocations.at(-1).gitTransportSources[0].word.text, 'ordinary');
});
test('R61 readonly function listing is DATA, not an attribute write', () => {
  for (const prefix of ['readonly -f; ', 'readonly -fp command_not_found_handle; ', 'declare -frp command_not_found_handle; ']) {
    ordinary(handler + prefix + 'unset -f command_not_found_handle; definitely_missing_xyz');
  }
});

test('R61 wait actual help differs from a consumed help-looking target', () => {
  assert.equal(analyse('wait --help').invocations[0].waitAssignmentRole.terminal, true);
  const a = analyse('wait -p --help 123');
  assert.equal(a.invocations[0].waitAssignmentRole.terminal, false);
  assert.ok(a.problems.some(p => p.includes('wait -p')));
});
test('R61 wait effective last target and option argument arity are retained', () => {
  const a = analyse('wait -fp first -npsecond -- 123').invocations[0];
  assert.equal(a.waitAssignmentRole.targetWord.text, 'second');
  assert.equal(a.waitAssignmentRole.unknown, false);
});
test('R61 initial unset invalidates exported Git helper proof before any successful reap', () => {
  const a = analyse('GIT_SSH_COMMAND=ordinary; export GIT_SSH_COMMAND; wait -p GIT_SSH_COMMAND 999999999; git push origin main');
  const g = a.invocations.findLast(i => i.name === 'git');
  assert.deepEqual(g.gitTransportSources, [{ name: 'GIT_SSH_COMMAND', word: null }]);
});
test('R61 wait target invalidates PATH and prompt-variable proofs', () => {
  const a = analyse('PATH=/usr/bin; wait -p PATH 123; printf ordinary');
  assert.equal(a.invocations.at(-1).pathChangedBefore, true);
  const b = analyse("PS4='+ '; wait -p PS4 123; set -x; :");
  assert.ok(b.problems.some(p => p.includes('PS4')));
});
test('R61 delayed wait target invalidates registered prompt and scalar proof', () => {
  const a = analyse("PS4='+ '; trap 'wait -p PS4 123' EXIT; set -x; :");
  assert.ok(a.problems.some(p => p.includes('PS4')));
});
test('R61 pre-existing read/printf/getopts target checks remain active', () => {
  for (const source of ["read 'a[$(printf DUMMY)]'", "printf -v 'a[$(printf DUMMY)]' '%s' DUMMY", "getopts a 'a[$(printf DUMMY)]' DUMMY"]) {
    assert.ok(analyse(source).problems.some(p => p.includes('添字')), source);
  }
  for (const source of ['read a', "printf -v a '%s' DUMMY", 'getopts a result DUMMY']) ordinary(source);
});

for (const source of ['git clone DUMMY', 'git fetch origin', 'git fetch-pack origin main',
  'git pull origin main', 'git push origin main', 'git ls-remote origin']) {
  test('R61 extracted transport client role without explicit settings: ' + source, () => {
    const g = analyse(source).gits[0];
    assert.ok(gitTransportClientRole(g));
    assert.equal(gitTransportSourceRole(g), null);
  });
}
for (const source of ['git push --help', 'git ls-remote --get-url origin', 'git fetch-pack --diag-url origin',
  'git fetch-pack --stateless-rpc origin', 'git status']) {
  test('R61 transport inactive actual query: ' + source, () => {
    const g = analyse(source).gits[0];
    assert.equal(gitTransportClientRole(g), null);
    assert.equal(gitTransportSourceRole(g), null);
  });
}
test('R61 source wrapper retains explicit-source selection and consumer metadata', () => {
  const g = analyse("git -c core.sshCommand='printf DUMMY' push origin main").gits[0];
  const source = gitTransportSourceRole(g), client = gitTransportClientRole(g);
  assert.equal(source.repositoryWord.text, client.repositoryWord.text);
  assert.equal(source.argvUnknown, client.argvUnknown);
  assert.equal(source.settings[0].key, 'core.sshcommand');
});
test('R61 consumed wait value arity cannot be erased by a later static target', () => {
  for (const source of ['wait -p $X -p status', 'wait -p * -p status', 'wait -p {first,second} -p status']) unknown(source);
  ordinary('wait -p "$X" -p status'); // exactly one consumed word; later target is effective
  ordinary('wait -p earlier -p status');
});
test('R61 function body traversal is not proof that callback removal executed', () => {
  for (const body of ['return; unset -f command_not_found_handle;', 'unset -f command_not_found_handle;']) {
    const source = handler + 'f(){ ' + body + ' }; f; definitely_missing_xyz';
    const a = analyse(source);
    assert.ok(a.problems.some(problem => problem.includes('command_not_found_handle')), source);
    assert.ok(a.invocations.some(invocation => invocation.commandNotFoundRole), source);
  }
  ordinary(handler + 'unset -f command_not_found_handle; definitely_missing_xyz');
});
test('R61 analysis attempted no child processes', () => assert.equal(childAttempts, 0));
