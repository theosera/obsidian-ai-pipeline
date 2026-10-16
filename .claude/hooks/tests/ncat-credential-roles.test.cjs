'use strict';
/** Pure production roles: command strings are DATA; no Ncat/TLS/network execution. */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const hooks = path.resolve(process.argv[2] || path.join(__dirname, '..'));
const guard = require(path.join(hooks, 'lib/git-guard-common.cjs'));
const source = fs.readFileSync(path.join(hooks, 'block-secret-egress.cjs'), 'utf8');
function productionFunction(name) {
  const prefix = 'function ' + name + '(';
  const start = source.indexOf(prefix), end = source.indexOf('\n}\n', start);
  assert.ok(start >= 0 && end > start);
  assert.equal(source.indexOf(prefix, start + prefix.length), -1);
  return source.slice(start, end + 3);
}
const sandbox = {};
vm.createContext(sandbox);
vm.runInContext(['knownWord', 'literalSourceWord', 'socketAuthenticationLiteralWord',
  'socketAuthenticationValue', 'socketAuthenticationRole', 'ncatCredentialSourceVerdict']
  .map(productionFunction).join('\n') +
  '\nthis.role=socketAuthenticationRole;this.verdict=ncatCredentialSourceVerdict;',
sandbox, { timeout: 1000 });
function inspect(command) {
  const data = guard.inspect(command, { trackOutboundEnvironment: true });
  assert.deepEqual(data.problems, []);
  const invocation = data.invocations.find(x => x.name === 'ncat' && !x.definitionName && !x.functionCallName);
  assert.ok(invocation);
  return { invocation, role: sandbox.role(invocation, true), verdict: sandbox.verdict(invocation) };
}
test('R39 Ncat selected last cert/key retain actual producer words', () => {
  const { invocation, role, verdict } = inspect('ncat --ssl-cert first.txt --ssl-cert a.txt --ssl-key b.txt ordinary.invalid 443');
  assert.equal(role.selected.get('ssl-cert'), invocation.args[3]);
  assert.equal(role.selected.get('ssl-key'), invocation.args[5]);
  assert.equal(verdict, 'UNKNOWN');
});
test('R39 Ncat either credential activates TLS and receive/zero/UDP do not clear its pair', () => {
  for (const mode of ['', '--recv-only ', '-z ', '-u ', '-m -1 ']) {
    assert.equal(inspect(`ncat ${mode}--ssl-cert a.txt --ssl-key b.txt ordinary.invalid 443`).verdict, 'UNKNOWN');
  }
});
test('R39 Ncat true getopt query exits before authentication files', () => {
  for (const command of ['ncat --help --ssl-cert a.txt --ssl-key b.txt',
    'ncat --ssl-cert a.txt --ssl-key b.txt --help',
    'ncat --ssl-cert a.txt --ssl-key b.txt --version']) {
    assert.equal(inspect(command).verdict, false);
  }
});
test('R39 Ncat consumed query and unresolved argv do not certify inactive credentials', () => {
  for (const command of ['ncat --ssl-cert --help --ssl-key b.txt ordinary.invalid 443',
    'ncat --opaque value --ssl-cert a.txt --ssl-key b.txt --help',
    'ncat --inactive --ssl-cert a.txt --ssl-key b.txt ordinary.invalid 443',
    'ncat --ssl-cert "$CERT" --ssl-key b.txt ordinary.invalid 443']) {
    assert.equal(inspect(command).verdict, 'UNKNOWN');
  }
});
test('R39 Ncat ordinary TLS and proven missing pair are inactive for this credential edge', () => {
  for (const command of ['ncat --ssl ordinary.invalid 443', 'ncat ordinary.invalid 443',
    'ncat --ssl-cert a.txt ordinary.invalid 443', 'ncat --ssl-key b.txt ordinary.invalid 443']) {
    assert.equal(inspect(command).verdict, false);
  }
});
test('R39 Ncat empty cert and empty key follow consumer order', () => {
  assert.equal(inspect('ncat --ssl-cert a.txt --ssl-cert= --ssl-key b.txt ordinary.invalid 443').verdict, false);
  assert.equal(inspect('ncat --ssl-cert /dev/null --ssl-key b.txt ordinary.invalid 443').verdict, false);
  assert.equal(inspect('ncat --ssl-cert a.txt --ssl-key= ordinary.invalid 443').verdict, 'UNKNOWN');
});
test('R39 Ncat listener authentication is active except known before-consumer rejection', () => {
  assert.equal(inspect('ncat -l --ssl-cert a.txt --ssl-key b.txt 443').verdict, 'UNKNOWN');
  assert.equal(inspect('ncat -l --ssl-cert a.txt --ssl-key b.txt --ssl-alpn h2 443').verdict, false);
  assert.equal(inspect('ncat -l -z --ssl-cert a.txt --ssl-key b.txt 443').verdict, false);
});
test('R39 Ncat bounded selection distinguishes proven incompatible local transports', () => {
  assert.equal(inspect('ncat -U --ssl-cert a.txt --ssl-key b.txt ordinary.sock').verdict, false);
  assert.equal(inspect('ncat --vsock --ssl-cert a.txt --ssl-key b.txt 2 443').verdict, false);
});
