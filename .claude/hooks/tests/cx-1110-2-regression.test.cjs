'use strict';
// Synthetic fixtures are generated at runtime. Commands are Hook input DATA.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const hooks = path.resolve(__dirname, '..');
const guard = require(path.join(hooks, 'lib/git-guard-common.cjs'));
const map = require('./cx-1106-3-map.txt')(guard,
  fs.readFileSync(path.join(hooks, 'lib/git-guard-common.cjs'), 'utf8'));
const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'cx11102-')));
const owned = value => path.join(root, value);
const quote = value => "'" + value.replace(/'/g, "'\\''") + "'";
for (const name of map.fixture.dirs.concat(map.fixture.homes)) fs.mkdirSync(owned(name), { recursive: true });
for (const [name, body] of Object.entries(map.fixture.files)) fs.writeFileSync(owned(name), body);
for (const [name, target] of Object.entries(map.fixture.links)) fs.symlinkSync(target, owned(name));
const item = group => map.project(map.cases[1], group, root).canonical;
const protectedFile = item(map.fixture.groups[0]);
const ordinaryFile = item(map.fixture.groups[1]);
const protectedDir = path.dirname(protectedFile);
const ordinaryDir = path.dirname(ordinaryFile);
const leaf = path.basename(ordinaryFile);
const source = (role, value) => map.commands[role].replace('{operand}', quote(value));
const change = (cwd, command) => map.commands.cd.replace('{cwd}', quote(cwd)).replace('{command}', command);
const shell = command => ['bash', '--noprofile', '--norc', '-c', quote(command)].join(' ');
const outbound = map.commands.outbound.split(' | ')[1];
const marker = owned('native-marker');
const preload = owned('preload.cjs');
fs.writeFileSync(preload, `const fs=require('node:fs'),cp=require('node:child_process');
for(const name of ['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork'])cp[name]=()=>{
fs.appendFileSync(${JSON.stringify(marker)},name+'\\n');throw Error('native execution forbidden');};`);
const environment = {
  PATH: map.commands.path.join(path.delimiter), HOME: owned(map.fixture.homes[0]),
  LC_ALL: 'C', TMPDIR: root, CLAUDE_PROJECT_DIR: root, GIT_CONFIG_NOSYSTEM: '1',
  GIT_CONFIG_GLOBAL: os.devNull, GIT_CONFIG_SYSTEM: os.devNull, GIT_TERMINAL_PROMPT: '0',
};
let hookCalls = 0;
function observe(command, cwd, selectedHooks = hooks) {
  const result = spawnSync(process.execPath, ['--require', preload, path.join(selectedHooks, 'block-secret-egress.cjs')], {
    input: JSON.stringify({ tool_name: 'Bash', cwd, tool_input: { command } }),
    cwd: root, env: environment, encoding: 'utf8', timeout: 10000, maxBuffer: 65536,
  });
  hookCalls++;
  assert.equal(result.error, undefined, 'Hook completes');
  assert.equal(result.signal, null, 'Hook signal');
  assert.equal(result.status, 0, 'Hook status');
  assert.equal(result.stderr, '', 'Hook stderr');
  assert.equal(fs.existsSync(marker), false, 'no native program attempted');
  if (result.stdout === '') return 'ALLOW';
  const wire = JSON.parse(result.stdout)?.hookSpecificOutput;
  assert.equal(wire?.permissionDecision, 'deny', 'decision wire');
  const reason = wire.permissionDecisionReason;
  if (reason.startsWith('[禁止] ')) return 'FORBIDDEN';
  assert.ok(reason.startsWith('[判断不能] '), 'reason category');
  return 'UNKNOWN';
}
test.after(() => fs.rmSync(root, { recursive: true, force: true }));

test('CX-1110-2 01', () => {
  const value = path.join(ordinaryDir, 'absent-a', 'absent-b', leaf);
  assert.equal(guard.secretPathVerdict(value, { cwd: ordinaryDir }), false);
  assert.equal(observe(source('write', value), ordinaryDir), 'ALLOW');
  const relative = ['absent-a', 'absent-b', leaf].join(path.sep);
  assert.equal(guard.secretPathVerdict(relative, { cwd: protectedDir }), 'FORBIDDEN');
  assert.equal(observe(source('write', relative), protectedDir), 'FORBIDDEN');
});
test('CX-1110-2 02', () => {
  const alias = owned('alias-a');
  fs.symlinkSync(ordinaryDir, alias);
  const value = path.join(alias, 'absent-a', leaf);
  assert.equal(guard.secretPathVerdict(value, { cwd: ordinaryDir }), 'UNKNOWN');
  assert.equal(observe(source('write', value), ordinaryDir), 'UNKNOWN');
});
test('CX-1110-2 03', () => {
  const parent = String.fromCharCode(46).repeat(2);
  const value = ordinaryDir + path.sep + ['absent-a', parent, leaf].join(path.sep);
  assert.equal(guard.secretPathVerdict(value, { cwd: ordinaryDir }), 'UNKNOWN');
});
test('CX-1110-2 04', () => {
  const command = change(ordinaryDir, shell(source('write', leaf)));
  assert.equal(observe(command, protectedDir), 'UNKNOWN');
  if (process.env.CX_1110_2_PR_HOOKS) assert.equal(observe(command, protectedDir, process.env.CX_1110_2_PR_HOOKS), 'FORBIDDEN');
});
test('CX-1110-2 05', () => {
  const command = change(protectedDir, shell(source('write', leaf)));
  assert.equal(observe(command, ordinaryDir), 'UNKNOWN');
  if (process.env.CX_1110_2_PR_HOOKS) assert.equal(observe(command, ordinaryDir, process.env.CX_1110_2_PR_HOOKS), 'UNKNOWN');
});
test('CX-1110-2 06', () => {
  const command = change(protectedDir, shell(shell(source('write', leaf))));
  assert.equal(observe(command, ordinaryDir), 'UNKNOWN');
});
test('CX-1110-2 07', () => {
  const command = change(protectedDir, shell(source('write', ordinaryFile)));
  assert.equal(observe(command, ordinaryDir), 'UNKNOWN');
});
test('CX-1110-2 08', () => {
  const mark = String.fromCharCode(45);
  const command = [map.commands.read.replace('{operand}', ['--', mark].join(' ')), '<' + os.devNull + ';', outbound].join(' ');
  assert.equal(observe(command, protectedDir), 'ALLOW');
});
test('CX-1110-2 09', () => {
  const mark = String.fromCharCode(45);
  const command = ['grep', '-f', mark, '<' + os.devNull + ';', outbound].join(' ');
  assert.equal(observe(command, protectedDir), 'ALLOW');
});
test('CX-1110-2 10', () => {
  const mark = String.fromCharCode(45);
  const command = [map.commands.read.replace('{operand}', ''), '<', quote(mark), ';', outbound].join(' ');
  assert.equal(observe(command, protectedDir), 'UNKNOWN');
});
test('CX-1110-2 11', () => {
  const terminal = String.fromCharCode(45, 104);
  for (const value of [protectedFile, path.join(ordinaryDir, 'absent-a', leaf)]) {
    assert.equal(observe(source('message', value) + ' ' + terminal, ordinaryDir), 'ALLOW');
  }
});
test('CX-1110-2 counts', t => {
  assert.equal(hookCalls, process.env.CX_1110_2_PR_HOOKS ? 14 : 12);
  assert.equal(fs.existsSync(marker), false);
  t.diagnostic(JSON.stringify({ hookCalls, nativeAttempts: 0, proposedCommandsExecuted: 0 }));
});
