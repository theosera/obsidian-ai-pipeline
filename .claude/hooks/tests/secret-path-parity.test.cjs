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
const { isSecretPath } = require('../lib/git-guard-common.cjs');

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


const scriptPath = process.env.SECRET_PATH_PARITY_SCRIPT_SOURCE ||
  path.resolve(__dirname, '../../skills/vault-ops/scripts/safe-vault-push-perm.sh');
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
const filterMatch = source.match(/^    if printf '%s\\n' "\$\{staged_path\}" \| (.+) >\/dev\/null; then$/m) ||
  source.match(/^  offenders="\$\(git diff --cached --name-only \| (.+) \|\| true\)"$/m);
assert.ok(filterMatch, 'extract only the production filename grep filter');
const filter = filterMatch[1];
assert.match(filter, /^(?:LC_ALL=C )?grep -ivE "\$\{ALLOW_ERE\}" \| (?:LC_ALL=C )?grep -iE "\$\{SECRET_ERE\}"$/,
  'the extracted filter contains only the two production grep predicates');

function readerSource() {
  const match = source.match(/^collect_staged_secret_paths\(\) \{[\s\S]*?^\}/m);
  assert.ok(match, 'production NUL reader exists');
  return match[0];
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
      TMPDIR: path.join(dir, 'tmp'), LC_ALL: 'en_US.UTF-8', ...options.env },
  });
}
function nulFields(text) { return text ? text.split('\0').slice(0, -1) : []; }

function shellSecret(filename, locale = 'C.UTF-8', literalLFProbe = false) {
  assert.ok((literalLFProbe || !filename.includes('\n')) && !filename.includes('\0'), 'filename DATA or explicit LF predicate probe');
  const result = spawnSync('/bin/bash', ['--noprofile', '--norc', '-c', `${assignments}\n${filter} || true`], {
    input: `${filename}\n`, encoding: 'utf8', env: { ...fixtureEnv, LC_ALL: locale },
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
  assert.deepEqual(mismatches, [], `production filter parity (${locale || 'C.UTF-8'}): ${scriptPath}`);
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

test('production C locale preserves ECMAScript whitespace and ASCII case across caller locales', () => {
  assert.match(filter, /^LC_ALL=C grep -ivE .* \| LC_ALL=C grep -iE /);
  const cases = [['.ENV?backup', true], ['notes/SECRETS', true], ['.env\tbackup', true],
    ['.envébackup', false], ['sécrets/file.txt', false], ['credentials-é.json', true]];
  for (const locale of ['C', 'C.UTF-8', 'en_US.UTF-8']) parity(cases, locale);
  // Full ECMAScript whitespace set; LF is only a literal predicate-byte probe.
  // Actual LF filenames are rejected by the reader before classification.
  // Literal alternatives must match whole UTF-8 sequences, not individual bytes.
  const whitespace = [0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0xa0, 0x1680,
    ...Array.from({ length: 11 }, (_, i) => 0x2000 + i), 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff];
  for (const codePoint of whitespace) {
    const suffix = String.fromCodePoint(codePoint);
    const filename = `.env${suffix}backup`;
    assert.equal(isSecretPath(filename), true);
    for (const locale of ['C', 'C.UTF-8', 'en_US.UTF-8']) assert.equal(shellSecret(filename, locale, codePoint === 0x0a), true);
  }
  for (const codePoint of [0x85, 0x180e, 0x200b, 0x2060, 0x1f600, 0xe9, 0xc0]) {
    const filename = `.env${String.fromCodePoint(codePoint)}backup`;
    assert.equal(isSecretPath(filename), false);
    for (const locale of ['C', 'C.UTF-8', 'en_US.UTF-8']) assert.equal(shellSecret(filename, locale), false);
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
