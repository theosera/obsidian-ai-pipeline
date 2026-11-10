'use strict';
// Concrete synthetic values and their numbered correspondence live only in
// the companion map. Proposed commands are DATA; only Hook processes run.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');
const { spawnSync } = require('node:child_process');
const hooks = path.resolve(process.argv[2] || path.join(__dirname, '..'));
const map = JSON.parse(fs.readFileSync(path.join(__dirname, 'cx-1106-3-map.txt'), 'utf8'));
const guard = require(path.join(hooks, 'lib/git-guard-common.cjs'));
const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), map.fixture.prefix)));
const q = value => "'" + value.replace(/'/g, "'\\''") + "'";
const owned = value => root + path.sep + value;
let hookCalls = 0;
let baselineHookCalls = 0;
const baselineHooks = process.env.CX_1106_3_BASELINE_HOOKS;
for (const name of map.fixture.dirs.concat(map.fixture.homes)) fs.mkdirSync(owned(name), { recursive: true });
for (const [name, body] of Object.entries(map.fixture.files)) fs.writeFileSync(owned(name), body);
for (const [name, target] of Object.entries(map.fixture.links)) fs.symlinkSync(target, owned(name));
fs.mkdirSync(owned(map.fixture.blockedDir));
fs.chmodSync(owned(map.fixture.blockedDir), 0);
fs.symlinkSync(map.fixture.loop, owned(map.fixture.loop));
const marker = owned(map.fixture.wireMarker), preload = owned(map.fixture.preload);
fs.writeFileSync(preload, `const fs=require('node:fs'),cp=require('node:child_process');
for(const name of ['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork'])cp[name]=()=>{
 fs.appendFileSync(${JSON.stringify(marker)},name+'\\n');throw Error('native execution forbidden');};`);
const environment = { PATH: map.commands.path.join(path.delimiter), HOME: owned(map.fixture.homes[0]),
  LC_ALL: 'C', TMPDIR: root, CLAUDE_PROJECT_DIR: root, GIT_CONFIG_NOSYSTEM: '1',
  GIT_CONFIG_GLOBAL: os.devNull, GIT_CONFIG_SYSTEM: os.devNull, GIT_TERMINAL_PROMPT: '0' };
const files = ['block-secret-egress.cjs', 'lib/git-guard-common.cjs', 'lib/git-precommit-readers.cjs', 'lib/executable-identity.cjs'];
const originals = new Map(files.map(file => [file, fs.readFileSync(path.join(hooks, file))]));
const inverse = owned('inverse');
for (const [file, bytes] of originals) {
  const target = path.join(inverse, file);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  let output = bytes;
  if (file === 'lib/git-guard-common.cjs') {
    const source = bytes.toString('utf8');
    const anchor = '  const selected = normalizeSecretOperand(value, context);';
    assert.equal(source.split(anchor).length - 1, 1, 'single added guard anchor');
    output = source.replace(anchor, '  return false;\n' + anchor);
  }
  fs.writeFileSync(target, output);
}
const inverseGuard = require(path.join(inverse, 'lib/git-guard-common.cjs'));
test.after(() => {
  fs.chmodSync(owned(map.fixture.blockedDir), 0o700);
  fs.rmSync(root, { recursive: true, force: true });
});
function fill(value, group) { return value.replaceAll('{group}', group).replaceAll('{policy}', map.policies[group]); }
function data(row, group) {
  const cwd = owned(fill(row.cwd, group));
  const operand = row.absolute ? owned(fill(row.operand, group)) : fill(row.operand, group);
  return { cwd, operand, canonical: owned(fill(row.canonical, group)) };
}
function command(role, value, cwd, cd) {
  const source = map.commands[role].replace('{operand}', q(value));
  return cd ? map.commands.cd.replace('{cwd}', q(cwd)).replace('{command}', source) : source;
}
function observe(source, cwd, selectedHooks = hooks) {
  const result = spawnSync(process.execPath, ['--require', preload, path.join(selectedHooks, files[0])], {
    input: JSON.stringify({ tool_name: 'Bash', cwd, tool_input: { command: source } }),
    cwd: root, env: environment, encoding: 'utf8', timeout: 10000, maxBuffer: 65536,
  });
  hookCalls++;
  if (selectedHooks === baselineHooks) baselineHookCalls++;
  assert.equal(result.error, undefined, 'Hook completes');
  assert.equal(result.signal, null, 'Hook completes without signal');
  assert.equal(result.status, 0, 'Hook exit status');
  assert.equal(result.stderr, '', 'Hook stderr');
  assert.equal(fs.existsSync(marker), false, 'no native program attempted');
  if (result.stdout === '') return 'ALLOW';
  const wire = JSON.parse(result.stdout)?.hookSpecificOutput;
  assert.equal(wire?.permissionDecision, 'deny', 'exact decision wire');
  assert.equal(typeof wire.permissionDecisionReason, 'string', 'reason wire');
  if (wire.permissionDecisionReason.startsWith('[禁止] ')) return 'FORBIDDEN';
  assert.ok(wire.permissionDecisionReason.startsWith('[判断不能] '), 'known reason category');
  return 'UNKNOWN';
}
for (const row of map.cases) {
  test('CX-1106-3 ' + row.id + ' denial', () => {
    const item = data(row, map.fixture.groups[0]);
    const context = { cwd: item.cwd };
    const selected = path.isAbsolute(item.operand) ? item.operand : item.cwd + path.sep + item.operand;
    if (row.id !== map.cases.at(-1).id) {
      assert.equal(fs.realpathSync.native(selected), fs.realpathSync.native(item.canonical), 'same synthetic file');
    } else {
      assert.equal(fs.existsSync(selected), false, 'new synthetic entry is absent');
      assert.equal(fs.existsSync(item.canonical), false, 'canonical synthetic entry is absent');
      assert.equal(fs.realpathSync.native(path.dirname(selected)), fs.realpathSync.native(path.dirname(item.canonical)), 'same existing parent');
    }
    assert.equal(guard.secretPathVerdict(item.canonical, context), 'FORBIDDEN', 'canonical reference');
    assert.equal(guard.secretPathVerdict(item.operand, context), 'FORBIDDEN', 'equivalent selection');
    for (const cd of [false, true]) {
      const verdict = observe(command('write', item.operand, item.cwd, cd), cd ? root : item.cwd);
      assert.equal(verdict, cd ? 'UNKNOWN' : 'FORBIDDEN', 'path and execution context remain distinct');
    }
    assert.equal(observe(command('outbound', item.operand, item.cwd, false), item.cwd), 'UNKNOWN', 'existing evidence policy');
  });
  test('CX-1106-3 ' + row.id + ' inverse', () => {
    const item = data(row, map.fixture.groups[0]);
    assert.equal(guard.isSecretPath(item.operand), false, 'legacy operand inventory');
    assert.equal(inverseGuard.secretPathVerdict(item.operand, { cwd: item.cwd }), false, 'only new guard removed');
    for (const cd of [false, true]) {
      const source = command('write', item.operand, item.cwd, cd), cwd = cd ? root : item.cwd;
      assert.equal(observe(source, cwd, inverse), 'ALLOW', 'same denial assertion becomes red');
      if (baselineHooks) assert.equal(observe(source, cwd, baselineHooks), 'ALLOW', 'base entrypoint');
    }
  });
  test('CX-1106-3 ' + row.id + ' ordinary', () => {
    const item = data(row, map.fixture.groups[1]);
    assert.equal(guard.secretPathVerdict(item.canonical, { cwd: item.cwd }), false);
    assert.equal(guard.secretPathVerdict(item.operand, { cwd: item.cwd }), false);
    for (const cd of [false, true]) {
      const source = command('write', item.operand, item.cwd, cd), cwd = cd ? root : item.cwd;
      assert.equal(observe(source, cwd), 'ALLOW', 'ordinary operation remains allowed');
      if (baselineHooks) assert.equal(observe(source, cwd, baselineHooks), 'ALLOW', 'unchanged ordinary base');
    }
    assert.equal(observe(command('read', item.operand, item.cwd, false), item.cwd), 'ALLOW');
  });
}
for (const row of map.unknown) test('CX-1106-3 ' + row.id + ' unresolved', () => {
  const cwd = owned(row.cwd);
  assert.equal(guard.secretPathVerdict(row.operand, { cwd }), 'UNKNOWN');
  const source = command('write', row.operand, cwd, false);
  assert.equal(observe(source, cwd), 'UNKNOWN', 'unproved is never a confirmed prohibition');
  assert.equal(observe(source, cwd, inverse), 'ALLOW', 'new uncertainty guard is active');
  if (baselineHooks) assert.equal(observe(source, cwd, baselineHooks), 'ALLOW', 'base uncertainty input');
});
test('CX-1106-3 09 observation', () => {
  const source = originals.get(files[1]).toString('utf8');
  let calls = 0;
  const fakeFs = Object.create(fs);
  fakeFs.lstatSync = (name, options) => {
    const stat = fs.lstatSync(name, options);
    if (++calls === 2) return new Proxy(stat, { get(target, key) { return key === 'ino' ? target.ino + 1n : Reflect.get(target, key); } });
    return stat;
  };
  const sandbox = { module: { exports: {} }, exports: {}, process, Buffer,
    require: name => name === 'node:fs' ? fakeFs : require(name) };
  vm.runInNewContext(source, sandbox, { timeout: 2000 });
  const item = data(map.cases[1], map.fixture.groups[1]);
  assert.equal(sandbox.module.exports.secretPathVerdict(item.operand, { cwd: item.cwd }), 'UNKNOWN');
  assert.equal(guard.secretPathVerdict(item.operand, { cwd: item.cwd }), false);
});
test('CX-1106-3 10 wire', () => {
  const item = data(map.cases[1], map.fixture.groups[1]);
  const invalid = { cwd: null };
  assert.equal(guard.secretPathVerdict(item.operand, invalid), 'UNKNOWN');
  assert.equal(guard.secretPathVerdict(item.canonical, invalid), 'UNKNOWN');
  assert.equal(fs.existsSync(marker), false);
  for (const [file, bytes] of originals) assert.deepEqual(fs.readFileSync(path.join(hooks, file)), bytes, 'source unchanged');
});
test('CX-1106-3 11 consumer', () => {
  const row = map.checks[2], cwd = owned(row.cwd);
  assert.equal(guard.secretPathVerdict(row.operand, { cwd }), 'FORBIDDEN');
  assert.equal(guard.secretPathVerdict(row.operand, { cwd, gitPathspec: true }), false);
  for (const cd of [false, true]) {
    const source = command('write', row.operand, cwd, cd), inputCwd = cd ? root : cwd;
    assert.equal(observe(source, inputCwd), 'ALLOW');
    if (baselineHooks) assert.equal(observe(source, inputCwd, baselineHooks), 'ALLOW');
  }
  assert.equal(observe(command('outbound', row.operand, cwd, false), cwd), 'UNKNOWN');
});
test('CX-1106-3 12 normalization', () => {
  const row = map.checks[3], cwd = owned(row.cwd);
  fs.mkdirSync(owned(row.directory));
  assert.equal(guard.secretPathVerdict(row.operand, { cwd }), 'UNKNOWN');
  assert.equal(observe(command('write', row.operand, cwd, false), cwd), 'UNKNOWN');
  assert.equal(inverseGuard.secretPathVerdict(row.operand, { cwd }), false);
});
test('CX-1106-3 13 consumer', () => {
  const row = map.checks[4], cwd = owned(row.cwd);
  assert.equal(fs.realpathSync.native(cwd + path.sep + row.operand), owned(row.canonical));
  assert.equal(guard.secretPathVerdict(row.operand, { cwd }), 'FORBIDDEN');
  assert.equal(guard.secretPathVerdict(row.operand, { cwd, gitPathspec: true }), false);
  assert.equal(observe(command('write', row.operand, cwd, false), cwd), 'ALLOW');
  assert.equal(observe(command('outbound', row.operand, cwd, false), cwd), 'UNKNOWN');
});
test('CX-1106-3 14 compatibility', () => {
  const protectedItem = data(map.cases[1], map.fixture.groups[0]);
  const ordinaryItem = data(map.cases[1], map.fixture.groups[1]);
  const values = [protectedItem.canonical, ordinaryItem.canonical, protectedItem.operand, ordinaryItem.operand];
  const direct = values.map(value => guard.isSecretPath(value));
  assert.deepEqual(values.map(guard.isSecretPath), direct, 'legacy map callback');
  assert.deepEqual(values.filter(guard.isSecretPath), values.filter(value => guard.isSecretPath(value)), 'legacy filter callback');
  assert.equal(values.some(guard.isSecretPath), direct.some(Boolean), 'legacy some callback');
  assert.equal(values.every(guard.isSecretPath), direct.every(Boolean), 'legacy every callback');
  assert.ok(direct.every(value => typeof value === 'boolean'), 'legacy return shape');
  assert.equal(guard.isSecretPath.length, 1, 'legacy declared arity');
  const gits = values.map(value => guard.inspect(command('message', value, root, false)).gits[0]);
  assert.ok(gits.every(Boolean));
  assert.deepEqual(gits.map(guard.gitObjectInputDecision), gits.map(value => guard.gitObjectInputDecision(value)), 'legacy Git callback');
  assert.equal(guard.gitObjectInputDecision.length, 1, 'legacy Git arity');
  for (const value of values) assert.equal(guard.isSecretOperandPath(value), guard.isSecretPath(value), 'new adapter omission');
  for (const value of gits) assert.deepEqual(guard.gitObjectInputDecisionWithContext(value), guard.gitObjectInputDecision(value), 'new Git adapter omission');
  let unknown = 0;
  assert.equal(guard.isSecretOperandPath(ordinaryItem.operand, { cwd: null, onUnknown: () => unknown++ }), false);
  assert.equal(unknown, 1, 'new adapter retains uncertainty separately');
  if (baselineHooks) {
    const base = require(path.join(baselineHooks, files[1]));
    for (const name of ['isSecretPath', 'gitObjectInputDecision']) assert.equal(guard[name].toString(), base[name].toString(), 'legacy public source retained');
  }
});
test('CX-1106-3 counts', t => {
  assert.equal(hookCalls, baselineHooks ? 77 : 52, 'every planned Hook input ran');
  assert.equal(baselineHookCalls, baselineHooks ? 25 : 0, 'base comparison count');
  t.diagnostic(JSON.stringify({ numberedKinds: map.cases.length, denial: 5, inverse: 5, ordinary: 5,
    unresolved: 3, observation: 1, wire: 1, consumer: 2, normalization: 1, compatibility: 1,
    hookCalls, baselineHookCalls, nativeAttempts: 0, proposedCommandsExecuted: 0 }));
});
