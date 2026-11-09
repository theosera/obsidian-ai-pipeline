'use strict';
/** Pure roles only: command strings are Hook DATA, never native ping invocations. */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const hooks = path.resolve(process.argv[2] || path.join(__dirname, '..'));
const guard = require(path.join(hooks, 'lib/git-guard-common.cjs'));
const source = fs.readFileSync(path.join(hooks, 'block-secret-egress.cjs'), 'utf8');
/** Extract one uniquely named production function for evaluation in the test sandbox. */
function productionFunction(name) {
  const prefix = 'function ' + name + '(';
  const start = source.indexOf(prefix), end = source.indexOf('\n}\n', start);
  assert.ok(start >= 0 && end > start);
  assert.equal(source.indexOf(prefix, start + prefix.length), -1);
  return source.slice(start, end + 3);
}
const sandbox = {};
vm.createContext(sandbox);
vm.runInContext(['knownWord', 'literalSourceWord', 'directDnsRole'].map(productionFunction).join('\n') + '\nthis.role=directDnsRole;', sandbox, { timeout: 1000 });
/** Parse command text as data and return the selected ping invocation and its production resolver role. */
function inspect(command) {
  const data = guard.inspect(command, { trackOutboundEnvironment: true });
  assert.deepEqual(data.problems, []);
  const invocation = data.invocations.find(x => ['ping', 'ping6'].includes(x.name) && !x.definitionName && !x.functionCallName);
  assert.ok(invocation);
  return { invocation, role: sandbox.role(invocation) };
}
test('R39 ping selected hostname preserves its original producer word', () => {
  const { invocation, role } = inspect(`ping -c 1 -- "$(sed -n p .e''nv).invalid"`);
  assert.equal(role.unknownArgv, false);
  assert.equal(role.selectedWords.length, 1);
  assert.equal(role.selectedWords[0], invocation.args[3]);
  assert.ok(role.selectedWords[0].raw.includes('sed -n p'));
});
test('R39 ping count attached and bundled forms keep the destination role', () => {
  for (const command of ['ping -c1 ordinary.invalid', 'ping -nqc1 ordinary.invalid', 'ping6 -c 1 ::1']) {
    const { role } = inspect(command);
    assert.equal(role.unknownArgv, false);
    assert.equal(role.selectedWords.length, 1);
  }
});
test('R39 ping numeric-output option retains the forward resolver destination', () => {
  const { invocation, role } = inspect('ping -n -c 1 ordinary.invalid');
  assert.equal(role.selectedWords[0], invocation.args[3]);
});
test('R39 ping unknown leading byte needs an explicit operand boundary', () => {
  assert.equal(inspect('ping "$HOST"').role.unknownArgv, true);
  assert.equal(inspect('ping -- "$HOST"').role.unknownArgv, false);
  assert.equal(inspect('ping "x$HOST"').role.unknownArgv, false);
});
test('R39 ping unresolved consumed source and numeric DATA remain unknown', () => {
  for (const command of ['ping -c "$COUNT" ordinary.invalid', 'ping -S "$SOURCE" ordinary.invalid', 'ping -p "$PATTERN" ordinary.invalid']) {
    assert.equal(inspect(command).role.unknownArgv, true);
  }
});
test('R39 ping cross-backend option differences are not treated as help', () => {
  assert.equal(inspect('ping -h 1 ordinary.invalid').role.terminal, false);
  assert.equal(inspect('ping -h 1 ordinary.invalid').role.unknownArgv, true);
  assert.equal(inspect('ping6 -t -W ordinary.invalid').role.unknownArgv, true);
  assert.equal(inspect('ping6 -a a').role.unknownArgv, true);
});
test('R39 ping terminal first query differs from a consumed value', () => {
  assert.equal(inspect('ping -V').role.terminal, true);
  assert.equal(inspect('ping -c -V ordinary.invalid').role.terminal, false);
  assert.equal(inspect('ping -c -V ordinary.invalid').role.unknownArgv, true);
});
test('R39 ping permutation, extra operands and argv bounds stay unresolved', () => {
  for (const command of ['ping ordinary.invalid -c 1', 'ping ordinary.invalid other.invalid', 'ping ' + Array(65).fill('ordinary.invalid').join(' ')]) {
    assert.equal(inspect(command).role.unknownArgv, true);
  }
});
