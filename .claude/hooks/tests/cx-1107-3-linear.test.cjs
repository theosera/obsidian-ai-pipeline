'use strict';
// Synthetic Hook JSON DATA only. Generated words and volume limits are never printed.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');
const { spawnSync } = require('node:child_process');
const hooks = path.resolve(process.env.CX1107_HOOKS || path.join(__dirname, '..'));
const source = fs.readFileSync(path.join(hooks, 'block-secret-egress.cjs'), 'utf8');
const common = fs.readFileSync(path.join(hooks, 'lib/git-guard-common.cjs'), 'utf8');
const settings = JSON.parse(fs.readFileSync(path.join(__dirname, '../../settings.json'), 'utf8'));
const deadline = settings.hooks.PreToolUse.flatMap(entry => entry.hooks)
  .find(entry => entry.command.endsWith('/block-secret-egress.cjs"')).timeout * 1000;
const volumeExpression = common.match(/^const MAX_HOOK_COMMAND_BYTES = ([^;]+);$/m)?.[1];
assert.ok(volumeExpression && /^[\d *]+$/.test(volumeExpression), 'production volume declaration');
const volume = vm.runInNewContext(volumeExpression, Object.create(null));
function section(text, first, last) {
  const start = text.indexOf(first), end = text.indexOf(last, start);
  assert.ok(start >= 0 && end > start, 'unique production section');
  assert.equal(text.indexOf(first, start + first.length), -1, 'unique production declaration');
  return text.slice(start, end);
}
function load(text) {
  const code = section(text, 'const RAW_UPLOAD_RE = ', "// (B')") +
    section(text, 'const SECRET_FILE_RE = ', 'const NET_VERB_RE = ') +
    section(text, 'function knownWord(word)', "/** Bash's first help/version") +
    section(text, 'function gitDiffModes(g)', '/** Select an archive format');
  return vm.runInNewContext(code + '\n;({rawUploadShape, rawSecretFileMatches, gitDiffModes,' +
    'secret: SECRET_FILE_RE, upload: RAW_UPLOAD_RE, rules: SECRET_FILE_LINEAR_RULES})',
  { gitRe: () => /(?!) / });
}
const api = load(source);
const previousShortOptions = /^-(?:[puwsRabc]|[UMCB][0-9]*|[0-9]+)+$/;
function specializationContract(text) {
  const policy = load(text);
  for (const rule of policy.rules) assert.equal(policy.secret.source.split(rule).length, 2, 'one specialized policy branch');
}
function random(seed) {
  return () => { seed ^= seed << 13; seed ^= seed >>> 17; seed ^= seed << 5; return seed >>> 0; };
}
const next = random(0x731c9);
const choose = values => values[next() % values.length];
function compare(predicate, oracle, values) {
  let mismatches = 0, matches = 0, comparisons = 0;
  for (const value of values) {
    const expected = oracle(value);
    comparisons++;
    if (expected) matches++;
    if (predicate(value) !== expected) mismatches++;
  }
  assert.equal(mismatches, 0, 'policy mismatch count');
  assert.ok(matches > 0 && matches < comparisons, 'both policy outcomes compared');
}
test('CX-1107-3 raw filename policy parity', () => {
  const atoms = [...new Set(api.secret.source.match(/[A-Za-z_][A-Za-z_-]*/g))];
  const separators = ['', '.', '/', ' ', '\t', '\n', '\r', '\u2028', '\u2029', '\0', "'", '"', '=', '\\'];
  const values = [];
  for (const first of atoms) for (const second of atoms) for (const separator of separators) {
    const value = first + separator + second;
    values.push(value, value.toUpperCase(), value + '.json', value + '.JSONx');
  }
  for (let i = 0; i < 12000; i++) {
    let value = '';
    for (let j = next() % 9; j > 0; j--) value += choose(atoms) + choose(separators);
    values.push(value);
  }
  compare(api.rawSecretFileMatches, value => api.secret.test(value), values);
});
test('CX-1107-3 specialized policy spelling cannot silently restore the old path', () => {
  specializationContract(source);
  for (const rule of api.rules) {
    const changed = source.replace(rule, rule.replace(/[A-Za-z]+/, 'SYNTHETIC'));
    assert.notEqual(changed, source, 'policy mutation exists');
    assert.throws(() => specializationContract(changed), 'policy drift must fail the contract');
  }
});
test('CX-1107-3 raw upload policy parity', () => {
  const programs = ['curl', 'CURL', 'xcurl', 'curlx', '_curl', 'curl_', '/curl', '\u212acurl'];
  const options = ['--data-binary', '--upload-file', '-T', '-F', '-d', '--data', '--datax', '-Tx', '--DATA', ''];
  const separators = ['', ' ', '\t', '\n', '\r', '\r\n', '\n\t', '\v', '\f', '\u2028', '\u2029', '\u00a0'];
  const values = [];
  for (const program of programs) for (const option of options) for (const separator of separators) {
    for (const tail of ['', '@', 'x@', '-@', '\n@']) values.push(program + separator + option + tail);
  }
  for (let i = 0; i < 12000; i++) {
    let value = '';
    for (let j = next() % 9; j > 0; j--) value += choose([...programs, ...options, '@']) + choose(separators);
    values.push(value);
  }
  compare(api.rawUploadShape, value => api.upload.test(value), values);
});
test('CX-1107-3 raw predicates preserve non-string coercion and exceptions', () => {
  const factories = [() => undefined, () => null, () => false, () => 0, () => 1n,
    () => Symbol('SYNTHETIC'), () => ({}), () => [], () => new String(''),
    () => ({ toString() { throw new TypeError('SYNTHETIC'); } })];
  const observe = (fn, value) => {
    try { return ['return', fn(value)]; } catch (error) { return ['throw', error.name]; }
  };
  let mismatches = 0;
  for (const [predicate, oracle] of [[api.rawSecretFileMatches, api.secret], [api.rawUploadShape, api.upload]]) {
    for (const make of factories) {
      if (JSON.stringify(observe(predicate, make())) !== JSON.stringify(observe(value => oracle.test(value), make()))) mismatches++;
    }
  }
  assert.equal(mismatches, 0, 'coercion mismatch count');
});
test('CX-1107-3 Git option language parity', () => {
  const values = ['', '-', '--', '-h', '-n', '-S', '-U', '-p', '-1', '-x'];
  const alphabet = 'puwsRabcUMCB0129xz\n\r\u2028\u2029';
  for (const first of alphabet) for (const second of alphabet) for (const third of alphabet) {
    const value = '-' + first + second + third;
    // These earlier value/terminal branches are outside the changed predicate.
    if (!/^-[nOSGU]$|^-[nOSG].+/.test(value)) values.push(value);
  }
  let mismatches = 0;
  for (const text of values.filter(value => !['', '-', '--', '-h', '-n', '-S', '-U'].includes(value))) {
    const word = { text, dynamicMaySplit: false };
    const actual = api.gitDiffModes({ sub: 'diff-files', args: [word] });
    if (actual.external !== !previousShortOptions.test(text) || actual.textconv !== !previousShortOptions.test(text)) mismatches++;
  }
  assert.equal(mismatches, 0, 'option policy mismatch count');
});

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'cx11073-'));
const home = path.join(root, 'home'); fs.mkdirSync(home);
const environment = { PATH: '/usr/local/bin:/usr/bin:/bin', HOME: home, TMPDIR: root, LC_ALL: 'C',
  CLAUDE_PROJECT_DIR: root, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: os.devNull, GIT_CONFIG_SYSTEM: os.devNull };
test.after(() => fs.rmSync(root, { recursive: true, force: true }));
const preload = path.join(root, 'observe.cjs');
fs.writeFileSync(preload, `const fs=require('node:fs'),cp=require('node:child_process');
let blocked=0;
const patterns=${JSON.stringify([api.secret.source, api.upload.source, previousShortOptions.source])};
const original=RegExp.prototype.test;
if(process.env.CX1107_RESOURCE==='1')RegExp.prototype.test=function(value){
 if(patterns.includes(this.source)){blocked++;throw Error('CX1107 restored nonlinear path');}
 return original.call(this,value);
};
for(const key of ['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork'])cp[key]=()=>{throw Error('CX1107 native child forbidden');};
process.on('exit',()=>fs.writeSync(3,JSON.stringify({cpu:process.cpuUsage(),blocked})));
`);
function run(command, selected = hooks, resource = false) {
  const start = performance.now();
  const result = spawnSync(process.execPath, ['--require', preload, path.join(selected, 'block-secret-egress.cjs')], {
    cwd: root, env: { ...environment, ...(resource ? { CX1107_RESOURCE: '1' } : {}) },
    input: JSON.stringify({ tool_name: 'Bash', cwd: root, tool_input: { command } }), encoding: 'utf8',
    stdio: ['pipe', 'pipe', 'pipe', 'pipe'], timeout: deadline * 3, maxBuffer: volume,
  });
  const elapsed = performance.now() - start;
  assert.equal(result.error, undefined, 'Hook completes');
  assert.equal(result.signal, null, 'Hook signal');
  assert.equal(result.status, 0, 'Hook status');
  assert.equal(result.stderr, '', 'Hook stderr');
  if (result.stdout) assert.equal(JSON.parse(result.stdout).hookSpecificOutput.permissionDecision, 'deny', 'Hook wire');
  const usage = JSON.parse(result.output[3]);
  return { stdout: result.stdout, elapsed, cpu: (usage.cpu.user + usage.cpu.system) / 1000, blocked: usage.blocked };
}
function previous(text) {
  return text
    .replace("if (typeof value !== 'string') return SECRET_FILE_RE.test(value);", 'return SECRET_FILE_RE.test(value);')
    .replace('{ test: rawUploadShape }', 'RAW_UPLOAD_RE')
    .replace('/^-[puwsRabcUMCB0-9]+$/', previousShortOptions.toString());
}
test('CX-1107-3 production decisions retain the previous predicates', () => {
  const control = path.join(root, 'control'); fs.mkdirSync(control);
  fs.symlinkSync(path.join(hooks, 'lib'), path.join(control, 'lib'), 'dir');
  fs.writeFileSync(path.join(control, 'block-secret-egress.cjs'), previous(source));
  const commands = ['printf ordinary', 'curl --data @DUMMY', 'curl\n--data @DUMMY',
    'curl\n\t--data @DUMMY', 'curl --datax @DUMMY', 'curl --data\n@DUMMY',
    'printf token.json # curl', 'printf token/ordinary.json # curl', 'printf TOKEN.JSONx # curl',
    'printf .env.example # curl', 'printf secrets/DUMMY # curl', 'git diff -1x',
    'git diff -U1', 'git diff -p1', 'git diff -1\n'];
  let mismatches = 0;
  for (const command of commands) if (run(command).stdout !== run(command, control).stdout) mismatches++;
  assert.equal(mismatches, 0, 'production decision mismatch count');
});
function fill(prefix, atom, suffix) {
  return prefix + atom.repeat(Math.floor((volume - Buffer.byteLength(prefix + suffix)) / Buffer.byteLength(atom))) + suffix;
}
const workloads = [
  ['raw filename', () => fill("printf '%s' '", 'token', "' # curl")],
  ['raw upload', () => fill("printf '%s' '", 'curl --data ', "'")],
  ['Git option', () => fill('git diff -', '1', 'x')],
];
for (const [kind, generate] of workloads) test('CX-1107-3 resource ' + kind, t => {
  const result = run(generate(), hooks, true);
  assert.equal(result.blocked, 0, 'no restored nonlinear predicate was reached');
  assert.ok(result.cpu < deadline, 'isolated Hook CPU stays within the configured deadline');
  // CPU accounting and the deterministic path sentinel remain stable on a busy runner.
  // Wall time is evidence for this run, not a scheduling-sensitive regression assertion.
  t.diagnostic(JSON.stringify({ seconds: result.elapsed / 1000, ratio: result.elapsed / deadline,
    cpuSeconds: result.cpu / 1000, cpuRatio: result.cpu / deadline }));
});
