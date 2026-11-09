'use strict';
// All shell-looking strings below are Hook JSON DATA; no proposed command executes.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const flag = process.argv.indexOf('--hooks-dir');
if (flag >= 0 && !process.argv[flag + 1]) throw Error('--hooks-dir needs a path');
const hooks = path.resolve(flag >= 0 ? process.argv[flag + 1] : path.join(__dirname, '..'));

test('R60 bounds shared inspection work and discards incomplete partial proofs', t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'r60-work-budget-'));
  try {
    const home = path.join(root, 'home'); fs.mkdirSync(home);
    const nativeMarker = path.join(root, 'native-attempt');
    const preload = path.join(root, 'no-native.cjs');
    fs.writeFileSync(preload, "const cp = require('node:child_process'); for (const n of ['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork']) cp[n] = () => { require('node:fs').appendFileSync(" + JSON.stringify(nativeMarker) + ", n); throw Error('R60 native forbidden'); };");
    const env = { PATH: '/usr/bin:/bin', HOME: home, TMPDIR: root, LC_ALL: 'C', CLAUDE_PROJECT_DIR: root,
      GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: os.devNull, GIT_CONFIG_SYSTEM: os.devNull };
    const inspector = "const g=require(process.argv[1]);const s=JSON.parse(require('node:fs').readFileSync(0,'utf8'));const r=g.inspect(s);console.log(JSON.stringify({problems:r.problems,names:r.invocations.map(i=>i.name),gits:r.gits.length,aliases:r.commands===r.invocations}));";
    const run = (command, hook = false) => {
      const args = ['--require', preload].concat(hook ? [path.join(hooks, 'block-secret-egress.cjs')] : ['-e', inspector, path.join(hooks, 'lib/git-guard-common.cjs')]);
      const start = Date.now();
      const r = spawnSync(process.execPath, args, { cwd: root, env, input: JSON.stringify(hook ? { tool_input: { command } } : command), encoding: 'utf8', timeout: 5000 });
      t.diagnostic(JSON.stringify({ hook, inputBytes: Buffer.byteLength(command), elapsedMs: Date.now() - start, status: r.status, signal: r.signal, error: r.error?.code || null }));
      assert.ifError(r.error); assert.equal(r.status, 0); assert.equal(r.signal, null); assert.equal(r.stderr, '');
      assert.equal(fs.existsSync(nativeMarker), false);
      return hook ? r.stdout : JSON.parse(r.stdout);
    };
    const incomplete = r => {
      assert.ok(r.problems.some(p => p.includes('work budget')));
      assert.deepEqual(r.names, []); assert.equal(r.gits, 0); assert.equal(r.aliases, true);
    };
    // Same compact function is selected many times; source depth and input volume stay small.
    const repeated = 'f(){ ' + ':;'.repeat(5500) + ' }; if false; then ' + 'f;'.repeat(10800) + 'fi; printf R60_DATA_MARKER';
    assert.equal(Buffer.byteLength(repeated), 32650);
    incomplete(run(repeated));
    const wire = JSON.parse(run(repeated, true)).hookSpecificOutput;
    assert.equal(wire.hookEventName, 'PreToolUse'); assert.equal(wire.permissionDecision, 'deny');
    assert.ok(wire.permissionDecisionReason.startsWith('[判断不能] '));
    assert.ok(wire.permissionDecisionReason.includes('work budget'));
    incomplete(run('f(){ :; }; g(){ ' + 'f;'.repeat(500) + ' }; ' + 'g;'.repeat(20)));
    // Child heredocs are parsed on every function call and must not obtain fresh source budgets.
    const source = 'printf R60_DATA_MARKER #' + 'a'.repeat(18000);
    incomplete(run("f(){ bash <<'END_R60'\n" + source + '\nEND_R60\n}; ' + 'f;'.repeat(20)));
    // Mediated source calls inspect recursively; those calls must share the outer budget too.
    incomplete(run('f(){ trap ' + JSON.stringify(source) + ' EXIT; }; ' + 'f;'.repeat(20)));
    // One module instance must release its exhausted budget before the next independent inspection.
    const sequentialCode = "const g=require(process.argv[1]);const inputs=JSON.parse(require('node:fs').readFileSync(0,'utf8'));console.log(JSON.stringify(inputs.map(s=>{const r=g.inspect(s);return {problems:r.problems,names:r.invocations.map(i=>i.name),gits:r.gits.length,aliases:r.commands===r.invocations};})));";
    const sequential = spawnSync(process.execPath, ['--require', preload, '-e', sequentialCode, path.join(hooks, 'lib/git-guard-common.cjs')], {
      cwd: root, env, input: JSON.stringify([repeated, 'printf R60_DATA_MARKER']), encoding: 'utf8', timeout: 5000 });
    assert.ifError(sequential.error); assert.equal(sequential.status, 0); assert.equal(sequential.signal, null); assert.equal(sequential.stderr, '');
    const sequence = JSON.parse(sequential.stdout); incomplete(sequence[0]);
    assert.deepEqual(sequence[1].problems, []); assert.deepEqual(sequence[1].names, ['printf']);
    assert.equal(fs.existsSync(nativeMarker), false);
    // A finite command-visit boundary and independent ordinary inspections retain their types.
    const exact = run(':;'.repeat(4096));
    assert.deepEqual(exact.problems, []); assert.equal(exact.names.length, 4096);
    incomplete(run(':;'.repeat(4097)));
    for (const command of ['printf R60_DATA_MARKER', 'f(){ printf R60_DATA_MARKER; }; f',
      "printf '%s' 'git status; f; ordinary DATA'", 'f(){ :; :; }; f; f']) {
      const ordinary = run(command); assert.deepEqual(ordinary.problems, []); assert.ok(ordinary.names.includes('printf') || ordinary.names.includes(':'));
      assert.equal(run(command, true), '');
    }
    t.diagnostic('Actual Hook JSON DATA only; no shell payload, native client, Git, network, settings, or Claude dispatch. Finite work bound is not a universal deadline guarantee.');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('R60 Hook lifetime shares later source work and cannot return an ignored partial result', t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'r60-hook-work-budget-'));
  try {
    const home = path.join(root, 'home'); fs.mkdirSync(home);
    const nativeMarker = path.join(root, 'native-attempt');
    const preload = path.join(root, 'no-native.cjs');
    fs.writeFileSync(preload, "const cp = require('node:child_process'); for (const n of ['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork']) cp[n] = () => { require('node:fs').appendFileSync(" + JSON.stringify(nativeMarker) + ", n); throw Error('R60 native forbidden'); };");
    const env = { PATH: '/usr/bin:/bin', HOME: home, TMPDIR: root, LC_ALL: 'C', CLAUDE_PROJECT_DIR: root,
      GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: os.devNull, GIT_CONFIG_SYSTEM: os.devNull };
    const run = (command, body) => {
      const script = "const g=require(process.argv[1]);const {cmd}=g.readInput('R60 test');" + body;
      const args = body ? ['-e', script, path.join(hooks, 'lib/git-guard-common.cjs')]
        : [path.join(hooks, 'block-secret-egress.cjs')];
      const start = Date.now();
      const result = spawnSync(process.execPath, ['--require', preload, ...args], {
        cwd: root, env, input: JSON.stringify({ tool_input: { command } }), encoding: 'utf8', timeout: 5000,
      });
      t.diagnostic(JSON.stringify({ inputBytes: Buffer.byteLength(command), elapsedMs: Date.now() - start,
        status: result.status, signal: result.signal, error: result.error?.code || null, source: body ? 'owned consumer' : 'actual EG' }));
      assert.ifError(result.error); assert.equal(result.status, 0); assert.equal(result.signal, null); assert.equal(result.stderr, '');
      assert.equal(fs.existsSync(nativeMarker), false);
      return result.stdout;
    };
    const unknown = stdout => {
      const wire = JSON.parse(stdout).hookSpecificOutput;
      assert.equal(wire.hookEventName, 'PreToolUse'); assert.equal(wire.permissionDecision, 'deny');
      assert.ok(wire.permissionDecisionReason.startsWith('[判断不能] '));
      assert.ok(wire.permissionDecisionReason.includes('work budget'));
      assert.equal(stdout.includes('UNREACHABLE'), false);
    };
    // Retained exact owned input: the initial inspection has 3,201 invocations,
    // but egress later inspects the same selected child source 1,600 times.
    const repeatedChild = "f(){ bash -c '" + ':;'.repeat(700) + "printf R60_DATA_MARKER'; }; " + 'f;'.repeat(1600);
    assert.equal(Buffer.byteLength(repeatedChild), 4642);
    assert.equal(require('node:crypto').createHash('sha256').update(repeatedChild).digest('hex'),
      '9bf1463d264a08dea9b7e3afab006533c36f1233da189b15a2186561a951d13b');
    unknown(run(repeatedChild));
    // A second root inspection, an ignored result and even a local catch must
    // not allow Hook code to continue after the cumulative budget is exhausted.
    const visits = ':;'.repeat(2200);
    unknown(run(visits, "g.inspect(cmd);try{g.inspect(cmd);}catch{}process.stdout.write('UNREACHABLE');"));
    // Re-reading this process's input sees EOF, but must not reset its lifetime.
    unknown(run(visits, "g.inspect(cmd);g.readInput('R60 second read');g.inspect(cmd);process.stdout.write('UNREACHABLE');"));
    // Direct parser consumers outside inspect's catch share the same source
    // budget; exactly eight chunks fit, the ninth must emit a complete deny.
    const source = 'printf R60_DATA_MARKER #' + 'a'.repeat(32768 - 'printf R60_DATA_MARKER #'.length);
    assert.equal(run(source, "for(let k=0;k<8;k++)g.parseShell(cmd);process.stdout.write('SOURCE_BOUNDARY_CONTINUED');"),
      'SOURCE_BOUNDARY_CONTINUED');
    unknown(run(source, "for(let k=0;k<9;k++)g.parseShell(cmd);process.stdout.write('UNREACHABLE');"));
    for (const command of ['printf R60_DATA_MARKER', 'f(){ printf R60_DATA_MARKER; }; f',
      "f(){ bash -c 'printf R60_DATA_MARKER'; }; f; f"]) {
      assert.equal(run(command), '');
    }
    t.diagnostic('Hook JSON DATA only; persistent process budget is separate from standalone inspection reset. No proposed command or native child executes.');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
