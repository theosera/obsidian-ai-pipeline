'use strict';

// All command strings are synthetic Hook stdin DATA. They are never executed.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const HOOKS = ['block-secret-git.cjs', 'block-git-add-all.cjs', 'block-secret-egress.cjs'];
const EG = HOOKS[2];
const RUNTIME = [...HOOKS, 'lib/git-guard-common.cjs', 'lib/executable-identity.cjs', 'lib/git-precommit-readers.cjs'];
const digest = data => crypto.createHash('sha256').update(data).digest('hex');
const pin = file => { const bytes = fs.readFileSync(file); return { bytes: bytes.length, sha256: digest(bytes) }; };
const q = value => "'" + value.replace(/'/g, "'\\''") + "'";

function createFixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'cx-1108-1-env-P-'));
  for (const dir of ['home', 'repo', 'search']) fs.mkdirSync(path.join(root, dir));
  for (const name of ['curl', 'git']) fs.writeFileSync(path.join(root, 'search', name),
    'DUMMY inert fixture; must never execute\n', { mode: 0o700 });
  const env = environment(root);
  const setup = spawnSync('/usr/bin/git', ['-c', 'core.hooksPath=/dev/null', 'init', '-q', path.join(root, 'repo')],
    { env, encoding: 'utf8' });
  if (setup.error || setup.status !== 0 || setup.stderr) throw Error('owned repository setup failed');
  // Only read-only Git metadata probes are allowed inside a Hook process.
  // No shell, env, curl, selected fixture, or submitted git status may start.
  fs.writeFileSync(path.join(root, 'sentinel.cjs'), `
const fs = require('node:fs'), cp = require('node:child_process');
const allowed = ${JSON.stringify(fs.realpathSync.native('/usr/bin/git'))};
const log = ${JSON.stringify(path.join(root, 'native-probes.jsonl'))};
const unexpected = ${JSON.stringify(path.join(root, 'unexpected-child'))};
for (const name of ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork']) {
  const original = cp[name];
  cp[name] = function(executable, args, ...rest) {
    let known = false;
    try { known = require('node:path').isAbsolute(executable) && fs.realpathSync.native(executable) === allowed; } catch {}
    const readOnly = Array.isArray(args) && (args.includes('config') || args.includes('rev-parse') || args.includes('--version'));
    if (!known || !readOnly) { fs.appendFileSync(unexpected, 'DUMMY unexpected child attempt\\n'); throw Error('DUMMY unexpected child'); }
    fs.appendFileSync(log, JSON.stringify({ executable, args }) + '\\n');
    return original.call(this, executable, args, ...rest);
  };
}
`);
  return root;
}

function environment(root) {
  return { PATH: '/usr/bin:/bin', HOME: path.join(root, 'home'), TMPDIR: root, LC_ALL: 'C',
    GIT_CONFIG_GLOBAL: os.devNull, GIT_CONFIG_SYSTEM: os.devNull, GIT_CONFIG_NOSYSTEM: '1',
    GIT_OPTIONAL_LOCKS: '0', GIT_TERMINAL_PROMPT: '0', CLAUDE_PROJECT_DIR: path.join(root, 'repo') };
}

function cases(root) {
  const dir = q(path.join(root, 'search')), curl = 'curl -q https://example.invalid/';
  return [
    { id: 'split-curl', command: `env -P ${dir} ${curl}`, kind: 'new-selection', parserUnknown: true },
    { id: 'attached-curl', command: `env -P${dir} ${curl}`, kind: 'new-selection', parserUnknown: true },
    { id: 'split-git', command: `env -P ${dir} git status`, kind: 'new-selection', parserUnknown: true },
    { id: 'plain-curl', command: curl, kind: 'allow' },
    { id: 'plain-git', command: 'git status', kind: 'allow' },
    { id: 'missing-value', command: 'env -P; git status', kind: 'existing-option', parserUnknown: true },
    { id: 'dynamic-split', command: `env -P $DUMMY_PATH ${curl}`, kind: 'existing-option', parserUnknown: true },
    { id: 'dynamic-attached', command: `env -P$DUMMY_PATH ${curl}`, kind: 'existing-option', parserUnknown: true },
    { id: 'dynamic-quoted-split', command: `env -P "$DUMMY_PATH" ${curl}`, kind: 'new-dynamic', parserUnknown: true },
    { id: 'dynamic-quoted-attached', command: `env -P"$DUMMY_PATH" ${curl}`, kind: 'new-dynamic', parserUnknown: true },
    { id: 'env-PATH-curl', command: `env PATH=${dir} ${curl}`, kind: 'existing-search' },
    { id: 'prefix-PATH-curl', command: `PATH=${dir} ${curl}`, kind: 'existing-search' },
    { id: 'explicit-curl', command: `${q(path.join(root, 'search', 'curl'))} -q https://example.invalid/`, kind: 'existing-search' },
    { id: 'env-PATH-git', command: `env PATH=${dir} git status`, kind: 'existing-search' },
    { id: 'prefix-PATH-git', command: `PATH=${dir} git status`, kind: 'existing-search' },
    { id: 'explicit-git', command: `${q(path.join(root, 'search', 'git'))} status`, kind: 'existing-search' },
    { id: 'harmless-flags', command: `env -0v ${curl}`, kind: 'allow' },
    { id: 'harmless-long', command: `env --debug --list-signal-handling ${curl}`, kind: 'allow' },
    { id: 'terminal-help', command: 'env --help', kind: 'allow' },
    { id: 'terminal-version', command: 'env --version', kind: 'allow' },
  ];
}

function classify(result) {
  if (result.error || result.status !== 0 || result.signal || result.stderr) return { verdict: 'BROKEN', reason: null };
  if (result.stdout === '') return { verdict: 'ALLOW', reason: '' };
  let wire;
  try { wire = JSON.parse(result.stdout).hookSpecificOutput; } catch { return { verdict: 'BROKEN', reason: null }; }
  const reason = wire?.permissionDecisionReason;
  return { reason, verdict: wire?.permissionDecision !== 'deny' || typeof reason !== 'string' ? 'BROKEN'
    : reason.startsWith('[判断不能] ') ? 'UNKNOWN' : reason.startsWith('[禁止] ') ? 'FORBIDDEN' : 'BROKEN' };
}

function evaluate(hooks, root) {
  const guard = require(path.join(hooks, 'lib/git-guard-common.cjs'));
  const identity = require(path.join(hooks, 'lib/executable-identity.cjs'));
  const env = environment(root), cwd = env.CLAUDE_PROJECT_DIR;
  const hookEnv = { ...env, NODE_OPTIONS: '--require=' + path.join(root, 'sentinel.cjs') };
  const options = { trackExecutableSearch: true, initialExecutableSearchPathPresent: true,
    trackOutboundEnvironment: true };
  const rows = [];
  for (const entry of cases(root)) {
    const parsed = guard.inspect(entry.command, options), invocation = parsed.invocations[0];
    const outputs = {};
    const input = JSON.stringify({ tool_name: 'Bash', tool_input: { command: entry.command }, cwd });
    for (const hook of HOOKS) {
      const result = spawnSync(process.execPath, [path.join(hooks, hook)], { cwd, env: hookEnv,
        input, encoding: 'utf8', timeout: 20000, maxBuffer: 1024 * 1024 });
      outputs[hook] = { ...classify(result), status: result.status, signal: result.signal,
        error: result.error?.code || null, stderr: result.stderr, stdout: result.stdout };
    }
    rows.push({ ...entry, input, parserUnknownObserved: invocation?.envUnknown === true,
      parserProblems: parsed.problems, outputs });
  }
  const inherited = '/DUMMY/inherited';
  const scopeCommand = `env -P ${q(path.join(root, 'search'))} sh -c 'curl -q https://example.invalid/'; curl -q https://example.invalid/`;
  const scoped = guard.inspect(scopeCommand, { ...options, initialOutboundEnvironmentSources: [
    { name: 'PATH', word: { text: inherited, raw: q(inherited), dynamic: false, dynamicMaySplit: false } },
  ] });
  const outer = scoped.invocations[0], following = scoped.invocations.at(-1);
  const child = guard.inspect(outer.shellScripts[0].text, { ...options,
    initialOutboundEnvironmentSources: outer.outboundEnvironmentSources,
    initialOutboundEnvironmentUnknown: outer.outboundEnvironmentUnknown,
    initialExecutableSearchChanged: outer.executableSearch.pathChanged }).invocations[0];
  const source = fs.readFileSync(path.join(hooks, 'lib/git-guard-common.cjs'), 'utf8');
  const effectsMatch = source.match(/const optionEffects = (\{[\s\S]*?\n    \});/);
  if (!effectsMatch) throw Error('explicit env option table missing');
  const effects = require('node:vm').runInNewContext('(' + effectsMatch[1] + ')');
  const version = spawnSync('/usr/bin/git', ['--version'], { cwd, env, encoding: 'utf8' });
  if (version.error || version.status !== 0) throw Error('Git version observation failed');
  const selected = Object.fromEntries(['env', 'curl', 'git', 'sh'].map(name => [name,
    identity.resolveExecutableIdentity({ text: name, dynamic: false },
      { name, searchMode: 'path', searchPath: env.PATH, cwd })]));
  return { rows, effects, scope: { command: scopeCommand, inherited,
    outerUnknown: outer.envUnknown, outerPATH: outer.outboundEnvironmentSources.find(x => x.name === 'PATH')?.word?.text,
    childPATH: child.outboundEnvironmentSources.find(x => x.name === 'PATH')?.word?.text,
    childEnvironmentUnknown: child.outboundEnvironmentUnknown, childSearch: child.executableSearch,
    followingUnknown: following.envUnknown, followingSearch: following.executableSearch },
    root, cwd, project: cwd, environment: env, hookEnvironment: hookEnv, selected,
    backend: 'BSD -P is conservatively UNKNOWN; host env is not invoked',
    node: process.version, platform: process.platform, git: version.stdout.trim(),
    sourcePins: Object.fromEntries(RUNTIME.map(file => [file, pin(path.join(hooks, file))])),
    fixturePins: Object.fromEntries(['search/curl', 'search/git', 'sentinel.cjs'].map(file => [file, pin(path.join(root, file))])),
    unexpectedChildAttempts: fs.existsSync(path.join(root, 'unexpected-child')) ? 1 : 0,
    hookCalls: rows.length * HOOKS.length, proposedCommandsExecuted: 0 };
}

function failures(result) {
  const failed = [];
  for (const row of result.rows) {
    if (row.parserUnknown && !row.parserUnknownObserved) failed.push(row.id + ':parser-unknown');
    for (const [hook, output] of Object.entries(row.outputs)) {
      if (output.verdict === 'BROKEN') failed.push(row.id + ':' + hook + ':broken');
      if (row.kind === 'allow' && output.verdict !== 'ALLOW') failed.push(row.id + ':' + hook + ':allow-control');
    }
    if (row.kind !== 'allow') {
      if (row.outputs[EG].verdict !== 'UNKNOWN') failed.push(row.id + ':egress-unknown');
      else if (!/実行名・PATH lookup|env の option/.test(row.outputs[EG].reason)) failed.push(row.id + ':egress-reason');
    }
  }
  if (result.effects.path !== 'unknown') failed.push('option-table:selection-unknown');
  if (!result.scope.outerUnknown) failed.push('scope:outer-unknown');
  if (!result.scope.childEnvironmentUnknown) failed.push('scope:child-environment-unknown');
  if (result.scope.outerPATH !== result.scope.inherited || result.scope.childPATH !== result.scope.inherited)
    failed.push('scope:child-PATH-preserved');
  if (result.scope.followingUnknown || result.scope.followingSearch.pathChanged) failed.push('scope:following-unchanged');
  if (result.unexpectedChildAttempts) failed.push('native:unexpected-child');
  return failed;
}

module.exports = { HOOKS, EG, RUNTIME, digest, pin, createFixture, environment, cases, evaluate, failures };
if (require.main === module) {
  try {
    const result = evaluate(path.resolve(process.argv[2]), path.resolve(process.argv[3]));
    result.failures = failures(result);
    process.stdout.write(JSON.stringify(result) + '\n');
    process.exitCode = result.failures.length ? 1 : 0;
  } catch (error) { process.stdout.write(JSON.stringify({ fatal: error.stack }) + '\n'); process.exitCode = 2; }
}
