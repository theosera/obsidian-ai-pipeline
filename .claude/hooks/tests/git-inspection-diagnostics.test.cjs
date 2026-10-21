'use strict';

// Internal Git observations only, in an owned DUMMY root. No proposed Bash,
// Claude entry, user settings, real secrets, or external transport is exercised.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const hooks = path.resolve(process.argv[2] || path.join(__dirname, '..'));
const os = require('node:os');
const { spawnSync } = require('node:child_process');

test('internal alias config observation suppresses inherited and global diagnostic destinations', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pr191-alias-diagnostics-'));
  try {
    const config = path.join(root, 'dummy.gitconfig');
    const trace = path.join(root, 'dummy-trace');
    const trace2 = path.join(root, 'dummy-trace2');
    fs.writeFileSync(config, '[alias]\n\tr40dummy = printf DUMMY\n[trace2]\n\teventTarget = ' + JSON.stringify(trace2) + '\n');
    const env = { PATH: process.env.PATH, HOME: root, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: config,
      GIT_TRACE: trace };
    // Benign positive activation control: the same config getter really creates
    // the two owned destinations when observation hardening is absent.
    const direct = spawnSync('git', ['config', '--get', 'alias.r40dummy'], { cwd: root, env, encoding: 'utf8', timeout: 10000 });
    assert.ifError(direct.error);
    assert.equal(direct.status, 0);
    assert.ok(fs.statSync(trace).size > 0);
    assert.ok(fs.statSync(trace2).size > 0);
    fs.unlinkSync(trace); fs.unlinkSync(trace2);
    const common = path.join(hooks, 'lib/git-guard-common.cjs');
    const script = `const guard=require(${JSON.stringify(common)});const known=guard.aliasProblem({sub:'r40dummy',cdirs:[]},process.cwd());const absent=guard.aliasProblem({sub:'r40absent',cdirs:[]},process.cwd());console.log(JSON.stringify({knownRejected:typeof known==='string',absentAllowed:absent===null}));`;
    const checked = spawnSync(process.execPath, ['-e', script], { cwd: root, env, encoding: 'utf8', timeout: 10000 });
    assert.ifError(checked.error);
    assert.equal(checked.status, 0, checked.stderr);
    assert.deepEqual(JSON.parse(checked.stdout), { knownRejected: true, absentAllowed: true });
    assert.equal(fs.existsSync(trace), false);
    assert.equal(fs.existsSync(trace2), false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
