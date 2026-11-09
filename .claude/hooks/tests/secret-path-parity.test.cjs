'use strict';
/**
 * Compare the production wrapper's extracted grep filter with the canonical
 * filename predicate. Filenames are stdin DATA. Git runs only in disposable
 * DUMMY fixtures; extracted reader/restore fragments are tested separately.
 * The full production wrapper and Vault operations are never run. SECRET_PATH_PARITY_SCRIPT_SOURCE selects a saved older source for
 * baseline comparison without copying its regex into this test.
 *
 * node --test .claude/hooks/tests/secret-path-parity.test.cjs
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { spawnSync } = require('node:child_process');
const hooks = path.resolve(process.argv[2] || path.join(__dirname, '..'));
const { isSecretPath } = require(path.join(hooks, 'lib/git-guard-common.cjs'));

// Resolve the installed Git before fixture PATH stubs are introduced. Retain
// usable tool paths while isolating Git configuration from the user's account.
const toolPath = process.env.PATH || '/usr/bin:/bin';
const gitExecutable = toolPath.split(path.delimiter).map(dir => path.resolve(dir, 'git')).find(candidate => {
  try { fs.accessSync(candidate, fs.constants.X_OK); return fs.statSync(candidate).isFile(); }
  catch { return false; }
});
assert.ok(gitExecutable, 'Git is available on the test process PATH');
const fixtureEnv = { PATH: toolPath, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: os.devNull };
const shellQuote = value => "'" + value.replaceAll("'", "'\\''") + "'";

// The production predicates explicitly use C. Other caller locales exercise
// that isolation only when installed; minimal Linux images may omit UTF-8
// locale data, and Bash's startup warning is not a filename-parity mismatch.
const callerLocaleCandidates = ['C', 'C.UTF-8', 'en_US.UTF-8'];
const localeListing = spawnSync('locale', ['-a'], { encoding: 'utf8', env: { ...fixtureEnv, LC_ALL: 'C' } });
const localeKey = locale => locale.toLowerCase().replace(/[-_.]/g, '');
const localeListingAvailable = !localeListing.error && localeListing.status === 0;
const installedLocaleNames = new Map(localeListingAvailable ? localeListing.stdout.split(/\r?\n/).filter(Boolean).map(locale => [localeKey(locale), locale]) : []);
// Use the installed spelling (for example C.utf8 on Linux), not an assumed alias.
const callerLocales = callerLocaleCandidates.map(locale => locale === 'C' ? 'C' : installedLocaleNames.get(localeKey(locale))).filter(Boolean);
const unavailableCallerLocales = callerLocaleCandidates.filter(locale => locale !== 'C' && !installedLocaleNames.has(localeKey(locale)));


const scriptPath = process.env.SECRET_PATH_PARITY_SCRIPT_SOURCE ||
  path.resolve(hooks, '../skills/vault-ops/scripts/safe-vault-push-perm.sh');
const source = fs.readFileSync(scriptPath, 'utf8');
function assignment(name, optional = false) {
  const matches = [...source.matchAll(new RegExp(`^  ${name}=(.*)$`, 'gm'))];
  if (optional && !matches.length) return '';
  assert.equal(matches.length, 1, `single production ${name} assignment`);
  if (name === 'SECRET_SPACE_UTF8_ERE') assert.match(matches[0][1], /^\$'(?:\\x[0-9a-f]{2}|\|)*'$/i);
  else assert.match(matches[0][1], /^(?:'[^']*'|"\$\{SECRET_SPACE_UTF8_ERE\}")+$/);
  return matches[0][0].trim();
}
const assignments = [assignment('SECRET_SPACE_UTF8_ERE', true), assignment('SECRET_ERE'), assignment('ALLOW_ERE')].join('\n');
const filterMatch = source.match(/^    if printf '%s\\n' "\$\{(?:staged_path|secret_scan_path)\}" \| (.+) >\/dev\/null; then$/m) ||
  source.match(/^  offenders="\$\(git diff --cached --name-only \| (.+) \|\| true\)"$/m);
assert.ok(filterMatch, 'extract only the production filename grep filter');
const filter = filterMatch[1];
const scanPathHelper = source.match(/^secret_template_scan_path\(\) \{[\s\S]*?^\}/m)?.[0] || '';
if (source.includes('secret_scan_path')) assert.ok(scanPathHelper, 'production final-template helper is extracted');
assert.match(filter, /^(?:LC_ALL=C )?grep -ivE "\$\{ALLOW_ERE\}" \| (?:LC_ALL=C )?grep -iE "\$\{SECRET_ERE\}"$/,
  'the extracted filter contains only the two production grep predicates');

function readerSource() {
  const match = source.match(/^collect_staged_secret_paths\(\) \{[\s\S]*?^\}/m);
  assert.ok(match, 'production NUL reader exists');
  return [scanPathHelper, match[0]].filter(Boolean).join('\n');
}
function fixture(t, names = []) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secret-path-parity-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  fs.mkdirSync(path.join(dir, 'tmp'));
  const git = (...args) => {
    const result = spawnSync(gitExecutable, args, { cwd: dir, encoding: 'utf8', env: fixtureEnv });
    assert.equal(result.status, 0, result.stderr);
    return result.stdout;
  };
  git('init', '-q');
  for (const filename of names) {
    fs.mkdirSync(path.dirname(path.join(dir, filename)), { recursive: true });
    fs.writeFileSync(path.join(dir, filename), 'DUMMY_ONLY\n');
  }
  if (names.length) git('add', '--', ...names);
  return { dir, git };
}
function runReader(dir, options = {}) {
  const restore = options.restore ? source.match(/^    for f in "\$\{SECRET_OFFENDERS\[@\]\}"; do\n      git restore --staged -- "\$\{f\}" \|\| true\n    done/m) : null;
  if (options.restore) assert.ok(restore, 'extract actual production exact-name restore loop');
  const commands = `${readerSource()}\nif collect_staged_secret_paths; then\n` +
    `if [ "\${#SECRET_OFFENDERS[@]}" -gt 0 ]; then\n${restore ? restore[0] : ''}\nprintf '%s\\0' "\${SECRET_OFFENDERS[@]}"\nfi\n` +
    `else\n[ "\${#SECRET_OFFENDERS[@]}" -eq 0 ] || exit 9\nexit 7\nfi`;
  return spawnSync('/bin/bash', ['--noprofile', '--norc', '-c', `set -euo pipefail\n${commands}`], {
    cwd: dir, encoding: 'utf8', env: { ...fixtureEnv, PATH: options.bin ? `${options.bin}${path.delimiter}${toolPath}` : toolPath,
      TMPDIR: path.join(dir, 'tmp'), LC_ALL: 'C', ...options.env },
  });
}
function nulFields(text) { return text ? text.split('\0').slice(0, -1) : []; }

function shellSecret(filename, locale = 'C', literalLFProbe = false) {
  assert.ok((literalLFProbe || !filename.includes('\n')) && !filename.includes('\0'), 'filename DATA or explicit LF predicate probe');
  const selection = scanPathHelper ? 'secret_template_scan_path "$1"' : 'secret_scan_path="$1"';
  const result = spawnSync('/bin/bash', ['--noprofile', '--norc', '-c',
    `${assignments}\n${scanPathHelper}\n${selection}\nprintf '%s\\n' "\${secret_scan_path}" | ${filter} || true`, 'filename-data', filename], {
    encoding: 'utf8', env: { ...fixtureEnv, LC_ALL: locale },
  });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, '');
  return result.stdout.length > 0;
}

function parity(cases, locale) {
  const mismatches = [];
  for (const [filename, expected] of cases) {
    assert.equal(isSecretPath(filename), expected, `canonical policy for ${JSON.stringify(filename)}`);
    const actual = shellSecret(filename, locale);
    if (actual !== expected) mismatches.push({ filename, expected, actual });
  }
  assert.deepEqual(mismatches, [], `production filter parity (${locale || 'C'}): ${scriptPath}`);
}

test('ASCII boundary controls use the actual production shell filter', () => {
  const suffixes = [
    ['', true], ['.local', true], ['?backup', true], ['*backup', true],
    [' backup', true], ['\tbackup', true], ['\vbackup', true], ['\fbackup', true], ['\rbackup', true],
    ['backup', false], ['_backup', false], ['9backup', false], ['-backup', false],
    ['!backup', false], ['#backup', false], ['/backup', false], [':backup', false],
  ];
  const cases = ['.env', 'notes/.ENV'].flatMap(prefix => suffixes.map(([suffix, expected]) => [prefix + suffix, expected]));
  cases.push(['prefix.env?backup', false], ['notes/prefix.env.local', false]);
  parity(cases);
});

test('ASCII names cover all twelve secret families and public adjacent names', () => {
  const families = [
    '.env.production', 'x_tokens.json', 'data/tokens.json', 'pkce_state.json',
    'credentials-development.json', 'service-account-test.json', 'public-token-cache.json',
    'pipeline_config.json', 'dummy.key', 'dummy.pem', 'id_rsa', 'id_ed25519',
    'secrets.json', 'secrets.yaml', 'secrets.yml', 'secrets', 'secrets/public.txt',
  ];
  const cases = families.flatMap(filename => [filename, filename.toUpperCase(), `notes/${filename}`].map(name => [name, true]));
  for (const filename of families) for (const end of ['\r', '\u2028', '\u2029']) {
    cases.push([filename + end, ['.env.production', 'secrets/public.txt'].includes(filename)]);
  }
  cases.push(...[
    'public.txt', 'env.local', 'x_tokens.txt', 'data/tokens.txt', 'pkce_state.txt',
    'credentials.json.backup', 'service-account.txt', 'pipeline_config.json.bak',
    'dummy.key.txt', 'id_rsa.pub', 'id_ed25519.pub', 'secrets.txt', 'secrets-public/file.txt',
    'prefix-secrets/file.txt',
  ].map(filename => [filename, false]));
  parity(cases);
});

test('template exception is exact across case and subdirectories', () => {
  parity([
    ['.env.example', false], ['notes/.env.example', false], ['NOTES/.ENV.EXAMPLE', false],
    ['prefix.env.example', false], ['.env.example.backup', true], ['notes/.env.example?backup', true],
    ['.env.example/child', true], ['.env.examples', true], ['.env.example_backup', true],
    ['.env.example\r', true], ['.env.example\u2028', true], ['notes/.ENV.EXAMPLE\u2029', true],
    ['.env.example\r\r', true],
  ]);
});

test('production C locale preserves ECMAScript whitespace and ASCII case across caller locales', t => {
  assert.match(filter, /^LC_ALL=C grep -ivE .* \| LC_ALL=C grep -iE /);
  for (const locale of unavailableCallerLocales) {
    t.diagnostic(`Skipped caller locale ${locale}: ${localeListingAvailable ? 'not installed (locale -a)' : 'locale enumeration unavailable'}; production C predicates remain tested`);
  }
  const cases = [['.ENV?backup', true], ['notes/SECRETS', true], ['.env\tbackup', true],
    ['.envébackup', false], ['sécrets/file.txt', false], ['credentials-é.json', true]];
  for (const locale of callerLocales) parity(cases, locale);
  // Full ECMAScript whitespace set; LF is only a literal predicate-byte probe.
  // Actual LF filenames are rejected by the reader before classification.
  // Literal alternatives must match whole UTF-8 sequences, not individual bytes.
  const whitespace = [0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0xa0, 0x1680,
    ...Array.from({ length: 11 }, (_, i) => 0x2000 + i), 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff];
  for (const codePoint of whitespace) {
    const suffix = String.fromCodePoint(codePoint);
    const filename = `.env${suffix}backup`;
    assert.equal(isSecretPath(filename), true);
    for (const locale of callerLocales) assert.equal(shellSecret(filename, locale, codePoint === 0x0a), true);
  }
  for (const codePoint of [0x85, 0x180e, 0x200b, 0x2060, 0x1f600, 0xe9, 0xc0]) {
    const filename = `.env${String.fromCodePoint(codePoint)}backup`;
    assert.equal(isSecretPath(filename), false);
    for (const locale of callerLocales) assert.equal(shellSecret(filename, locale), false);
  }
});

test('actual Git NUL reader classifies raw Unicode and quoted-control filename DATA', t => {
  const whitespace = [0x09, 0x0b, 0x0c, 0x0d, 0x20, 0xa0, 0x1680,
    ...Array.from({ length: 11 }, (_, i) => 0x2000 + i), 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff];
  const names = ['.env?backup', '.env*backup', 'notes/SECRETS', 'notes/.env.example', '.env!public', 'public.txt',
    'x_tokens.json\r', '.env.example\r', '.env.example\u2028', 'notes/.ENV.EXAMPLE\u2029',
    ...whitespace.map(cp => `.env${String.fromCodePoint(cp)}DUMMY`)];
  const { dir, git } = fixture(t, names);
  const before = git('diff', '--cached', '--name-only', '-z');
  assert.ok(git('diff', '--cached', '--name-only').includes('\\302\\240'), 'default Git reader really quotes NBSP');
  const result = runReader(dir);
  assert.equal(result.status, 0, result.stderr);
  // Filesystem normalization can fold U+2002/U+2003 into U+2000/U+2001.
  // Compare the actual Git names, not the requested creation spellings.
  assert.deepEqual(nulFields(result.stdout).sort(), nulFields(before).filter(isSecretPath).sort());
  assert.equal(git('diff', '--cached', '--name-only', '-z'), before, 'reader does not alter index');
  assert.ok(!fs.readdirSync(path.join(dir, 'tmp')).some(name => name.startsWith('vault-ops-staged.')), 'owned capture cleaned');
  for (const publicNames of [[], ['public.txt', 'notes/.env.example', '.env!public']]) {
    const publicFixture = fixture(t, publicNames);
    const publicResult = runReader(publicFixture.dir);
    assert.equal(publicResult.status, 0, publicResult.stderr);
    assert.equal(publicResult.stdout, '', 'complete empty/public input is an ordinary no-offender control');
  }
});

test('nonzero Git, truncated NUL and read-length failures publish no offenders', t => {
  const { dir, git } = fixture(t, ['.env?DUMMY', 'public.txt']);
  const before = git('diff', '--cached', '--name-only', '-z');
  const bin = path.join(dir, 'bin'); fs.mkdirSync(bin);
  const fakeGit = path.join(bin, 'git');
  for (const body of [
    "printf '.env?DUMMY\\0'; exit 3", "printf '.env?DUMMY\\0partial'", "printf '.env?DUMMY\\0\\0'",
  ]) {
    fs.writeFileSync(fakeGit, `#!/bin/sh\n${body}\n`, { mode: 0o755 });
    const result = runReader(dir, { bin, restore: true });
    assert.equal(result.status, 7, result.stderr);
    assert.equal(result.stdout, '');
    assert.ok(!fs.readdirSync(path.join(dir, 'tmp')).some(name => name.startsWith('vault-ops-staged.')));
  }
  fs.writeFileSync(fakeGit, `#!/bin/sh\nexec ${shellQuote(gitExecutable)} "$@"\n`, { mode: 0o755 });
  fs.writeFileSync(path.join(bin, 'wc'), '#!/bin/sh\ncat >/dev/null\nprintf 999999\n', { mode: 0o755 });
  const unread = runReader(dir, { bin, restore: true });
  assert.equal(unread.status, 7, unread.stderr);
  assert.equal(unread.stdout, '');
  assert.equal(git('diff', '--cached', '--name-only', '-z'), before, 'failure never unstages');
  assert.ok(!fs.readdirSync(path.join(dir, 'tmp')).some(name => name.startsWith('vault-ops-staged.')));
  fs.writeFileSync(path.join(bin, 'wc'), '#!/bin/sh\nexit 2\n', { mode: 0o755 });
  assert.equal(runReader(dir, { bin, restore: true }).status, 7, 'size-read failure stops');
  fs.writeFileSync(path.join(bin, 'wc'), '#!/bin/sh\nfor capture in "$TMPDIR"/vault-ops-staged.*; do rm -f -- "$capture"; done\nprintf 0\n', { mode: 0o755 });
  assert.equal(runReader(dir, { bin, restore: true }).status, 7, 'failed input open stops even when reported size is zero');
  assert.equal(git('diff', '--cached', '--name-only', '-z'), before);
  fs.unlinkSync(path.join(bin, 'wc'));
  fs.writeFileSync(path.join(bin, 'grep'), '#!/bin/sh\nexit 2\n', { mode: 0o755 });
  assert.equal(runReader(dir, { bin, restore: true }).status, 7, 'predicate runtime failure stops');
});

test('LF filename boundary fails closed before any unstage, including public names', t => {
  for (const filename of ['.env\nDUMMY', 'public\nsecrets']) {
    const { dir, git } = fixture(t, ['.env?DUMMY', filename]);
    const before = git('diff', '--cached', '--name-only', '-z');
    assert.equal(isSecretPath(filename), filename.startsWith('.env'));
    const result = runReader(dir, { restore: true });
    assert.equal(result.status, 7, result.stderr);
    assert.equal(result.stdout, '');
    assert.equal(git('diff', '--cached', '--name-only', '-z'), before);
    assert.ok(!fs.readdirSync(path.join(dir, 'tmp')).some(name => name.startsWith('vault-ops-staged.')));
  }
});

test('extracted production restore loop preserves exact array filenames and -- boundary', t => {
  const names = ['.env?backup', '.env*backup', '.env\tDUMMY', '.env\uFEFFDUMMY', '-DUMMY.key', '.env.example', 'public.txt'];
  const { dir } = fixture(t, names);
  const bin = path.join(dir, 'bin'); fs.mkdirSync(bin);
  const log = path.join(dir, 'restore-argv');
  fs.writeFileSync(path.join(bin, 'git'), `#!/bin/sh\nif [ "$1" = restore ]; then printf "%s\\0" "$@" >> "$PARITY_LOG"; else exec ${shellQuote(gitExecutable)} "$@"; fi\n`, { mode: 0o755 });
  const result = runReader(dir, { bin, restore: true, env: { PARITY_LOG: log } });
  assert.equal(result.status, 0, result.stderr);
  const fields = nulFields(fs.readFileSync(log, 'utf8'));
  const actual = [];
  for (let i = 0; i < fields.length; i += 4) {
    assert.deepEqual(fields.slice(i, i + 3), ['restore', '--staged', '--']);
    actual.push(fields[i + 3]);
  }
  assert.deepEqual(actual.sort(), names.filter(isSecretPath).sort());
});

// Fault injection targets one producer/predicate at a time. The extracted
// reader and restore loop remain production code; no Vault or network is used.
const grepExecutable = toolPath.split(path.delimiter).map(dir => path.resolve(dir, 'grep')).find(candidate => {
  try { fs.accessSync(candidate, fs.constants.X_OK); return fs.statSync(candidate).isFile(); }
  catch { return false; }
});
assert.ok(grepExecutable, 'grep is available before fixture PATH stubs');
const digest = bytes => require('node:crypto').createHash('sha256').update(bytes).digest('hex');
function gateFixtureState(dir, names) {
  const state = {};
  function visit(relative) {
    const filename = path.join(dir, relative), stat = fs.lstatSync(filename);
    assert.ok(!stat.isSymbolicLink(), 'DUMMY fixture has no symlink');
    if (stat.isDirectory()) for (const child of fs.readdirSync(filename).sort()) visit(path.join(relative, child));
    else state[relative] = digest(fs.readFileSync(filename));
  }
  visit('.git');
  for (const name of names) visit(name);
  return state;
}
function gateFaultFixture(t, names) {
  const f = fixture(t, names), bin = path.join(f.dir, 'bin'), log = path.join(f.dir, 'restore-attempts');
  fs.mkdirSync(bin);
  fs.writeFileSync(path.join(bin, 'git'), `#!/bin/sh\nif [ "$1" = restore ]; then printf '%s\\0' "$@" >> "$PARITY_LOG"; else exec ${shellQuote(gitExecutable)} "$@"; fi\n`, { mode: 0o755 });
  return { ...f, bin, log, before: gateFixtureState(f.dir, names), names };
}
function assertGateFaultClosed(f, result) {
  assert.equal(result.error, undefined);
  assert.equal(result.status, 7, result.stderr);
  assert.equal(result.stdout, '', 'no partial offender array is published');
  assert.equal(fs.existsSync(f.log), false, 'no restore attempt after a reader/predicate failure');
  assert.deepEqual(gateFixtureState(f.dir, f.names), f.before, 'HEAD, refs, index, objects and DUMMY files stay unchanged');
  assert.deepEqual(fs.readdirSync(path.join(f.dir, 'tmp')), [], 'owned filename capture is removed');
}
function predicateFault(f, stage, emitsInput = false, onlyName = '') {
  const flag = stage === 'first' ? '-ivE' : '-iE';
  fs.writeFileSync(path.join(f.bin, 'grep'), `#!/bin/sh\nif [ "$1" = ${shellQuote(flag)} ]; then\n  filename=$(cat)\n  if [ -z ${shellQuote(onlyName)} ] || [ "$filename" = ${shellQuote(onlyName)} ]; then\n    ${emitsInput ? 'printf "%s\\n" "$filename"' : ':'}\n    exit 2\n  fi\n  printf '%s\\n' "$filename" | ${shellQuote(grepExecutable)} "$@"\nelse\n  exec ${shellQuote(grepExecutable)} "$@"\nfi\n`, { mode: 0o755 });
}
function runProducerFault(f) {
  const restore = source.match(/^    for f in "\$\{SECRET_OFFENDERS\[@\]\}"; do\n      git restore --staged -- "\$\{f\}" \|\| true\n    done/m);
  assert.ok(restore, 'production restore loop is available');
  // Only the pipeline's Bash printf producer fails. Diagnostic/output code
  // uses builtin printf so the adapter cannot manufacture a missing offender.
  const commands = `set -euo pipefail\nprintf() { return 2; }\n${readerSource()}\n` +
    `if collect_staged_secret_paths; then\nif [ "\${#SECRET_OFFENDERS[@]}" -gt 0 ]; then\n${restore[0]}\nbuiltin printf '%s\\0' "\${SECRET_OFFENDERS[@]}"\nfi\n` +
    `else\n[ "\${#SECRET_OFFENDERS[@]}" -eq 0 ] || exit 9\nexit 7\nfi`;
  return spawnSync('/bin/bash', ['--noprofile', '--norc', '-c', commands], {
    cwd: f.dir, encoding: 'utf8', env: { ...fixtureEnv, PATH: `${f.bin}${path.delimiter}${toolPath}`,
      TMPDIR: path.join(f.dir, 'tmp'), LC_ALL: 'C', PARITY_LOG: f.log },
  });
}

test('first predicate error cannot hide behind a later ordinary nonmatch', t => {
  for (const emitsInput of [false, true]) {
    const f = gateFaultFixture(t, ['.env?DUMMY']);
    predicateFault(f, 'first', emitsInput);
    assertGateFaultClosed(f, runReader(f.dir, { bin: f.bin, restore: true, env: { PARITY_LOG: f.log } }));
  }
});

test('later predicate failure publishes no earlier matched secret or partial unstage', t => {
  for (const stage of ['first', 'second']) {
    const f = gateFaultFixture(t, ['.env?DUMMY', 'z-fail.public.txt']);
    predicateFault(f, stage, false, 'z-fail.public.txt');
    assertGateFaultClosed(f, runReader(f.dir, { bin: f.bin, restore: true, env: { PARITY_LOG: f.log } }));
  }
});

test('printf producer and final predicate errors stop with unchanged fixture state', t => {
  for (const names of [['.env?DUMMY'], ['public.txt']]) {
    const f = gateFaultFixture(t, names);
    assertGateFaultClosed(f, runProducerFault(f));
  }
  for (const emitsInput of [false, true]) {
    const f = gateFaultFixture(t, ['.env?DUMMY']);
    predicateFault(f, 'second', emitsInput);
    assertGateFaultClosed(f, runReader(f.dir, { bin: f.bin, restore: true, env: { PARITY_LOG: f.log } }));
  }
});

test('normal nonmatch and exact template remain ordinary; secret match alone reaches restore', t => {
  for (const names of [['public.txt'], ['notes/.ENV.EXAMPLE'], ['.env?DUMMY']]) {
    const f = gateFaultFixture(t, names);
    const result = runReader(f.dir, { bin: f.bin, restore: true, env: { PARITY_LOG: f.log } });
    assert.equal(result.status, 0, result.stderr);
    const expected = names.filter(isSecretPath);
    assert.deepEqual(nulFields(result.stdout), expected);
    assert.equal(fs.existsSync(f.log), expected.length > 0);
    if (expected.length) assert.deepEqual(nulFields(fs.readFileSync(f.log, 'utf8')), ['restore', '--staged', '--', ...expected]);
    assert.deepEqual(gateFixtureState(f.dir, f.names), f.before, 'restore stub records argv; no actual unstage or other fixture write');
    assert.deepEqual(fs.readdirSync(path.join(f.dir, 'tmp')), []);
  }
});


test('R36 final template exemption retains protected ancestor components', () => {
  const cases = [
    ['secrets/.env.example', true], ['notes/secrets/.env.example', true],
    ['SECRETS/.ENV.EXAMPLE', true], ['.env.local/.env.example', true],
    ['notes/.env?backup/.ENV.EXAMPLE', true], ['notes/.env*backup/.env.example', true],
    ['.env.example/.env.example', true], ['notes/.env backup/.env.example', true],
    ['.env.example', false], ['notes/.env.example', false], ['NOTES/.ENV.EXAMPLE', false],
    ['secrets-public/.env.example', false], ['.envx/.env.example', false],
  ];
  for (const locale of callerLocales) parity(cases, locale);
});

test('R36 extracted reader and restore retain original ancestor-template filenames', t => {
  const names = ['secrets/.env.example', 'notes/SECRETS/.ENV.EXAMPLE', '.env.local/.env.example',
    '.env.example', 'notes/.env.example', 'secrets-public/.env.example'];
  const expected = ['secrets/.env.example', 'notes/SECRETS/.ENV.EXAMPLE', '.env.local/.env.example'];
  const { dir, git } = fixture(t, names);
  const before = gateFixtureState(dir, names);
  const result = runReader(dir);
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(nulFields(result.stdout).sort(), expected.sort());
  assert.deepEqual(gateFixtureState(dir, names), before, 'reader preserves Git objects/index/refs and files');
  const bin = path.join(dir, 'bin'); fs.mkdirSync(bin);
  const log = path.join(dir, 'restore-argv');
  fs.writeFileSync(path.join(bin, 'git'), `#!/bin/sh\nif [ "$1" = restore ]; then printf "%s\\0" "$@" >> "$PARITY_LOG"; else exec ${shellQuote(gitExecutable)} "$@"; fi\n`, { mode: 0o755 });
  const restored = runReader(dir, { bin, restore: true, env: { PARITY_LOG: log } });
  assert.equal(restored.status, 0, restored.stderr);
  const fields = nulFields(fs.readFileSync(log, 'utf8')), actual = [];
  for (let i = 0; i < fields.length; i += 4) {
    assert.deepEqual(fields.slice(i, i + 3), ['restore', '--staged', '--']);
    actual.push(fields[i + 3]);
  }
  assert.deepEqual(actual.sort(), expected, 'restore receives original names, never transformed scan paths');
  assert.equal(git('diff', '--cached', '--name-only', '-z').includes('secrets/.env.example'), true);
});

test('R36 LF reader boundary publishes no prior ancestor-template offender or restore', t => {
  for (const filename of ['zzpublic\n/notes/.env.example', 'zzsecrets/\n.env.example']) {
    const f = gateFaultFixture(t, ['secrets/.env.example', filename]);
    assertGateFaultClosed(f, runReader(f.dir, { bin: f.bin, restore: true, env: { PARITY_LOG: f.log } }));
  }
});
