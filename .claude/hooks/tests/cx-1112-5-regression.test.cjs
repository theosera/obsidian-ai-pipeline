'use strict';
// Owned fixtures and existing policy generate the inputs at runtime.
// Proposed commands remain Hook JSON DATA; only Node Hook processes run.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const hooks = path.resolve(process.env.CX_1112_5_HOOKS || path.join(__dirname, '..'));
const guard = require(path.join(hooks, 'lib/git-guard-common.cjs'));
const map = require('./cx-1106-3-map.txt')(guard,
  fs.readFileSync(path.join(hooks, 'lib/git-guard-common.cjs'), 'utf8'));
const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'cx11125-')));
const owned = name => path.join(root, name);
const quote = value => "'" + value.replace(/'/g, "'\\''") + "'";
let serial = 0, hookCalls = 0, directChecks = 0;
const next = () => 'generated-' + serial++;
for (const name of map.fixture.dirs.concat(map.fixture.homes)) fs.mkdirSync(owned(name), { recursive: true });
for (const [name, body] of Object.entries(map.fixture.files)) fs.writeFileSync(owned(name), body);
for (const [name, target] of Object.entries(map.fixture.links)) fs.symlinkSync(target, owned(name));
const marker = owned(next()), preload = owned(next() + '.cjs');
fs.writeFileSync(preload, `const fs=require('node:fs'),cp=require('node:child_process');
for(const name of ['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork'])cp[name]=()=>{
fs.appendFileSync(${JSON.stringify(marker)},name+'\\n');throw Error('native execution forbidden');};`);
const environment = {
  PATH: map.commands.path.join(path.delimiter), HOME: owned(map.fixture.homes[0]),
  TMPDIR: root, LC_ALL: 'C', CLAUDE_PROJECT_DIR: root, GIT_CONFIG_NOSYSTEM: '1',
  GIT_CONFIG_GLOBAL: os.devNull, GIT_CONFIG_SYSTEM: os.devNull, GIT_TERMINAL_PROMPT: '0',
};
const item = index => map.project(map.cases[1], map.fixture.groups[index], root);
const operand = depth => Array.from({ length: depth + 1 }, next).join(path.sep);
const command = value => map.commands.write.replace('{operand}', quote(value));
function direct(value, cwd, expected) {
  assert.equal(guard.secretPathVerdict(value, { cwd }), expected, 'shared decision');
  directChecks++;
}
function observe(source, cwd, expected) {
  const result = spawnSync(process.execPath, ['--require', preload, path.join(hooks, 'block-secret-egress.cjs')], {
    cwd: root, env: environment, encoding: 'utf8', timeout: 10000, maxBuffer: 65536,
    input: JSON.stringify({ tool_name: 'Bash', cwd, tool_input: { command: source } }),
  });
  hookCalls++;
  assert.equal(result.error, undefined, 'Hook completes');
  assert.equal(result.signal, null, 'Hook signal');
  assert.equal(result.status, 0, 'Hook status');
  assert.equal(result.stderr, '', 'Hook stderr');
  assert.equal(fs.existsSync(marker), false, 'no native program attempted');
  let actual = 'ALLOW';
  if (result.stdout !== '') {
    const wire = JSON.parse(result.stdout)?.hookSpecificOutput;
    assert.equal(wire?.permissionDecision, 'deny', 'decision wire');
    const reason = wire.permissionDecisionReason;
    assert.equal(typeof reason, 'string', 'reason wire');
    if (reason.startsWith('[禁止] ')) actual = 'FORBIDDEN';
    else {
      assert.ok(reason.startsWith('[判断不能] '), 'reason category');
      actual = 'UNKNOWN';
    }
  }
  assert.equal(actual, expected, 'Hook decision');
}
test.after(() => fs.rmSync(root, { recursive: true, force: true }));

test('CX-1112-5 01 shared decisions', () => {
  for (let depth = 1; depth <= 3; depth++) for (let group = 0; group < map.fixture.groups.length; group++) {
    const selected = item(group), value = operand(depth);
    const expected = group === 0 ? 'FORBIDDEN' : false;
    direct(value, selected.cwd, expected);
    direct(path.join(selected.cwd, value), selected.cwd, expected);
  }
});
test('CX-1112-5 02 Hook contexts', () => {
  for (let depth = 1; depth <= 3; depth++) for (let group = 0; group < map.fixture.groups.length; group++) {
    const selected = item(group), source = command(operand(depth));
    const expected = group === 0 ? 'FORBIDDEN' : 'ALLOW';
    observe(source, selected.cwd, expected);
    observe(map.commands.cd.replace('{cwd}', quote(selected.cwd)).replace('{command}', source), root,
      group === 0 ? 'UNKNOWN' : expected);
  }
});
test('CX-1112-5 03 unresolved proof', () => {
  const selected = item(1), alias = owned(next());
  fs.symlinkSync(selected.cwd, alias);
  const value = path.join(alias, operand(2));
  direct(value, selected.cwd, 'UNKNOWN');
  observe(command(value), selected.cwd, 'UNKNOWN');
  const parent = path.relative(path.join(root, next()), root);
  direct(operand(1) + path.sep + parent + path.sep + next(), selected.cwd, 'UNKNOWN');
  direct(operand(1), null, 'UNKNOWN');
});
test('CX-1112-5 04 normalization proof', () => {
  const check = map.checks[3], cwd = owned(check.directory), value = operand(2);
  fs.mkdirSync(cwd);
  direct(value, cwd, 'UNKNOWN');
  observe(command(value), cwd, 'UNKNOWN');
});
test('CX-1112-5 05 independent absolute selection', () => {
  for (let group = 0; group < map.fixture.groups.length; group++) {
    const selected = item(group), cwd = item(1 - group).cwd;
    const value = path.join(selected.cwd, operand(2));
    direct(value, cwd, group === 0 ? 'FORBIDDEN' : false);
    observe(command(value), cwd, group === 0 ? 'FORBIDDEN' : 'ALLOW');
  }
});
test('CX-1112-5 counts', t => {
  assert.equal(directChecks, 18);
  assert.equal(hookCalls, 16);
  assert.equal(fs.existsSync(marker), false);
  t.diagnostic(JSON.stringify({ directChecks, hookCalls, nativeAttempts: 0, proposedCommandsExecuted: 0 }));
});
