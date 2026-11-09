'use strict';
// Filesystem/parser-independent tests only. No executable or proposed command runs.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');
const hooks = path.resolve(process.argv[2] || path.join(__dirname, '..'));
const modulePath = path.join(hooks, 'lib/executable-identity.cjs');
const { resolveExecutableIdentity: resolve } = require(modulePath);
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'r54-executable-identity-'));
test.after(() => fs.rmSync(root, { recursive: true, force: true }));
const word = text => ({ text, dynamic: false, dynamicMaySplit: false });
const options = (searchPath, cwd = root) => ({ name: 'cat', searchMode: 'path', searchPath, cwd });
const inert = (file, mode = 0o700) => { fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, 'DUMMY inert file; never executed\n'); fs.chmodSync(file, mode); };
const cat = ['/bin/cat', '/usr/bin/cat'].find(file => {
  try { fs.accessSync(file, fs.constants.X_OK); return fs.statSync(file).isFile(); } catch { return false; }
});

function mocked(entries, platform = 'linux', faults = new Map()) {
  const calls = [];
  const error = code => Object.assign(new Error(code), { code });
  const read = file => {
    calls.push(file);
    if (faults.has(file)) throw error(faults.get(file));
    if (!entries.has(file)) throw error('ENOENT');
    return entries.get(file);
  };
  const fakeFs = {
    constants: { X_OK: 1 },
    statSync(file) { const entry = read(file); return { isFile: () => entry.file !== false, isDirectory: () => entry.directory === true }; },
    accessSync(file) { if (read(file).executable === false) throw error('EACCES'); },
    realpathSync: { native(file) { return read(file).real || file; } },
  };
  const module = { exports: {} };
  vm.runInNewContext(fs.readFileSync(modulePath, 'utf8'), {
    module, exports: module.exports, process: { platform, env: { PATH: '/UNAPPROVED_FALLBACK' } },
    require(name) { if (name === 'node:fs') return fakeFs; if (name === 'node:path') return path.posix; throw Error('Unexpected dependency: ' + name); },
  }, { filename: modulePath });
  return { resolve: module.exports.resolveExecutableIdentity,
    invocation: module.exports.invocationExecutableIdentity, calls };
}

test('bare lookup requires an explicit actual PATH mode, with no process fallback', () => {
  const m = mocked(new Map([['/usr/bin/cat', {}]]));
  for (const opts of [{ name: 'cat' }, { name: 'cat', searchMode: 'unknown', searchPath: '/usr/bin' },
    { name: 'cat', searchMode: 'default', searchPath: '/usr/bin' }, { name: 'cat', searchMode: 'path' }]) {
    assert.equal(m.resolve(word('cat'), opts).kind, 'unknown-search');
  }
  assert.equal(m.calls.length, 0);
  assert.equal(m.resolve(word('cat'), options('/usr/bin')).kind, 'trusted-external');
});

test('literal executable, registered basename and relative explicit path boundaries remain strict', () => {
  const m = mocked(new Map());
  for (const flag of ['dynamic', 'dynamicMaySplit', 'ansiCUnknown', 'braceExpanded', 'globExpanded', 'tildeExpanded']) {
    assert.equal(m.resolve({ ...word('cat'), [flag]: true }, options('/usr/bin')).kind, 'unknown-search', flag);
  }
  for (const text of ['cat\0DUMMY', './cat', '../cat', '/usr/bin/other']) {
    assert.equal(m.resolve(word(text), options('/usr/bin')).kind, 'unknown-search', text);
  }
  assert.equal(m.resolve(word('cat'), { ...options('/usr/bin'), name: '../cat' }).kind, 'unknown-search');
});

test('absolute trusted installations work without PATH and Homebrew anchors are independent', () => {
  const m = mocked(new Map([['/usr/bin/cat', {}], ['/opt/homebrew/bin/gh', { real: '/opt/homebrew/Cellar/gh/DUMMY/bin/gh' }]]));
  assert.equal(m.resolve(word('/usr/bin/cat'), { name: 'cat', searchMode: 'unknown' }).kind, 'trusted-external');
  const gh = m.resolve(word('gh'), { name: 'gh', searchMode: 'path', searchPath: '/opt/homebrew/bin' });
  assert.equal(gh.kind, 'trusted-external');
  assert.equal(gh.resolvedPath, '/opt/homebrew/Cellar/gh/DUMMY/bin/gh');
});

test('an untrusted executable first match is never skipped for a later trusted one', () => {
  const m = mocked(new Map([['/usr/bin/cat', {}], ['/owned/cat', {}]]));
  const r = m.resolve(word('cat'), options('/owned:/usr/bin'));
  assert.equal(r.kind, 'untrusted-first-match');
  assert.equal(r.resolvedPath, '/owned/cat');
  assert.equal(m.resolve(word('/owned/cat'), { name: 'cat' }).kind, 'untrusted-first-match');
});

test('fixed sbin installations still require actual selection and do not trust a PATH prefix', () => {
  const m = mocked(new Map([['/sbin/ping', {}], ['/usr/sbin/ping6', {}], ['/owned/ping', {}]]));
  const query = (text, name, searchPath) => m.resolve(word(text), { name, searchMode: 'path', searchPath });
  assert.equal(query('ping', 'ping', '/usr/bin:/sbin').kind, 'trusted-external');
  assert.equal(query('/usr/sbin/ping6', 'ping6', undefined).kind, 'trusted-external');
  assert.equal(query('ping', 'ping', '/usr/bin').kind, 'not-found');
  assert.equal(query('ping', 'ping', '/owned:/sbin').kind, 'untrusted-first-match');
});

test('nonexecutable files and directories do not shadow the selected trusted executable', () => {
  const m = mocked(new Map([['/usr/bin/cat', {}], ['/data/cat', { executable: false }], ['/dir/cat', { file: false, directory: true }]]));
  assert.equal(m.resolve(word('cat'), options('/data:/dir:/usr/bin')).kind, 'trusted-external');
});

test('candidate metadata errors stop instead of silently selecting a later installation', () => {
  const m = mocked(new Map([['/usr/bin/cat', {}]]), 'linux', new Map([['/opaque/cat', 'EACCES']]));
  const r = m.resolve(word('cat'), options('/opaque:/usr/bin'));
  assert.equal(r.kind, 'unknown-search');
  assert.equal(r.reason, 'candidate-metadata-unavailable');
});

test('missing executable is distinct from unknown search and untrusted selection', () => {
  const m = mocked(new Map());
  const r = m.resolve(word('cat'), options('/missing'));
  assert.equal(r.kind, 'not-found');
  assert.equal(r.resolvedPath, null);
  assert.equal(m.resolve(word('/missing/cat'), { name: 'cat' }).kind, 'not-found');
});

test('Windows search stays closed without touching a guessed POSIX filesystem', () => {
  const m = mocked(new Map([['/usr/bin/cat', {}]]), 'win32');
  assert.equal(m.resolve(word('cat'), options('/usr/bin')).kind, 'unknown-search');
  assert.equal(m.resolve(word('/usr/bin/cat'), { name: 'cat' }).kind, 'unknown-search');
  assert.equal(m.calls.length, 0);
});

test('owned inert shadow and trusted symlink are resolved by filesystem identity only', { skip: process.platform === 'win32' || !cat }, () => {
  const dir = path.join(root, 'shadow'), file = path.join(dir, 'cat');
  inert(file);
  assert.equal(resolve(word('cat'), options(dir + path.delimiter + path.dirname(cat))).kind, 'untrusted-first-match');
  fs.unlinkSync(file); fs.symlinkSync(cat, file);
  const r = resolve(word('cat'), options(dir));
  assert.equal(r.kind, 'trusted-external');
  assert.equal(r.resolvedPath, fs.realpathSync.native(cat));
  assert.equal(resolve(word(file), { name: 'cat' }).kind, 'trusted-external');
});

test('raw relative PATH preserves symlink before dot-dot without lexical collapse', { skip: process.platform === 'win32' || !cat }, () => {
  const base = path.join(root, 'base'), target = path.join(root, 'target'), child = path.join(target, 'child');
  fs.mkdirSync(base); fs.mkdirSync(child, { recursive: true }); fs.symlinkSync(child, path.join(base, 'jump'), 'dir');
  inert(path.join(target, 'cat'));
  const r = resolve(word('cat'), options('jump/..' + path.delimiter + path.dirname(cat), base));
  assert.equal(r.kind, 'untrusted-first-match');
  assert.equal(r.resolvedPath, fs.realpathSync.native(path.join(target, 'cat')));
});

test('empty PATH components require a validated physical cwd while absolute-only search does not', { skip: process.platform === 'win32' || !cat }, () => {
  const dir = path.join(root, 'empty-component'); fs.mkdirSync(dir); inert(path.join(dir, 'cat'));
  assert.equal(resolve(word('cat'), options('', dir)).kind, 'untrusted-first-match');
  assert.equal(resolve(word('cat'), options(path.delimiter + path.dirname(cat), dir)).kind, 'untrusted-first-match');
  assert.equal(resolve(word('cat'), { ...options(''), cwd: undefined }).kind, 'unknown-search');
  assert.equal(resolve(word('cat'), options('.', path.join(root, 'missing-cwd'))).kind, 'unknown-search');
  assert.equal(resolve(word('cat'), { ...options(path.dirname(cat)), cwd: undefined }).kind, 'trusted-external');
});

const inheritedSearch = () => ({ pathPresent: true, pathChanged: false, defaultSearch: false });
const wrapper = (name, extras = {}) => ({ name, word: { ...word(name), quoted: false },
  executableSearch: inheritedSearch(), ...extras });
const invocation = (name, wrappers = [], extras = {}) => ({ name, nameWord: word(name),
  wrapperNames: wrappers.map(entry => entry.name), wrapperProgramWords: wrappers,
  executableSearch: inheritedSearch(), ...extras });
const caller = (PATH = '/usr/bin') => ({ environment: { PATH }, cwd: '/owned', builtinNames: ['printf', ':'] });

test('wrapper and callee snapshots do not borrow an absent, cleared or default PATH', () => {
  const m = mocked(new Map([['/usr/bin/env', {}], ['/usr/bin/curl', {}]]));
  assert.equal(m.invocation(invocation('curl'), caller()).kind, 'trusted-external');
  assert.equal(m.invocation(invocation('curl'), { environment: {}, cwd: '/owned' }).kind, 'unknown-search');
  for (const snapshot of [undefined, { pathPresent: false, pathChanged: false, defaultSearch: false },
    { pathPresent: true, pathChanged: true, defaultSearch: false },
    { pathPresent: true, pathChanged: false, defaultSearch: true }]) {
    assert.equal(m.invocation(invocation('curl', [], { executableSearch: snapshot }), caller()).kind, 'unknown-search');
  }
  const cleared = { pathPresent: false, pathChanged: false, defaultSearch: false };
  assert.equal(m.invocation(invocation('curl', [wrapper('env')], { executableSearch: cleared }), caller()).kind, 'unknown-search');
  const absolute = invocation('curl', [wrapper('env')], { nameWord: word('/usr/bin/curl'), executableSearch: cleared });
  assert.equal(m.invocation(absolute, caller()).kind, 'trusted-external');
});

test('an outer shadow wrapper stops before a cleared child or trusted absolute callee', () => {
  const m = mocked(new Map([['/usr/bin/env', {}], ['/usr/bin/curl', {}], ['/shadow/env', {}]]));
  const child = invocation('curl', [wrapper('env')], { nameWord: word('/usr/bin/curl'),
    executableSearch: { pathPresent: false, pathChanged: false, defaultSearch: false } });
  const r = m.invocation(child, caller('/shadow:/usr/bin'));
  assert.equal(r.kind, 'untrusted-first-match');
  assert.equal(r.resolvedPath, '/shadow/env');
});

test('direct builtin proof survives a same-name shadow but env and exec force external lookup', () => {
  const m = mocked(new Map([['/usr/bin/env', {}], ['/usr/bin/printf', {}], ['/shadow/printf', {}]]));
  const options = caller('/shadow:/usr/bin');
  assert.equal(m.invocation(invocation('printf'), options).kind, 'builtin');
  assert.equal(m.invocation(invocation('printf', [wrapper('builtin')]), options).kind, 'builtin');
  assert.equal(m.invocation(invocation('printf', [wrapper('command')]), options).kind, 'builtin');
  for (const name of ['env', 'exec']) {
    assert.equal(m.invocation(invocation('printf', [wrapper(name)]), options).kind, 'untrusted-first-match', name);
    assert.equal(m.invocation(invocation('printf', [wrapper(name)]), caller()).kind, 'trusted-external', name);
  }
  assert.equal(m.invocation(invocation('printf'), { ...options, builtinNames: [] }).kind, 'untrusted-first-match');
});

test('external wrappers and childless queries cannot impersonate shell command/builtin/exec', () => {
  const entries = new Map([['/usr/bin/env', {}], ['/usr/bin/curl', {}], ['/usr/bin/command', {}],
    ['/usr/bin/builtin', {}], ['/usr/bin/exec', {}]]);
  const m = mocked(entries);
  for (const name of ['command', 'builtin', 'exec']) {
    const r = m.invocation(invocation('curl', [wrapper('env'), wrapper(name)]), caller());
    assert.equal(r.kind, 'unknown-search', name);
    assert.equal(r.reason, 'shell-primitive-after-external-boundary');
    assert.equal(m.invocation(invocation(name, [wrapper('env')]), caller()).kind, 'unknown-search', name + ' callee');
  }
  assert.equal(m.invocation(invocation('curl', [wrapper('exec'), wrapper('command')]), caller()).kind, 'unknown-search');
  assert.equal(m.invocation(invocation('command', [], { nonExec: true }), caller()).kind, 'unknown-search');
  assert.equal(m.invocation({ name: null, nameWord: null }, caller()).kind, 'unknown-search');
});

test('command-p search is not the hook PATH while explicit callee identity stays independent', () => {
  const m = mocked(new Map([['/usr/bin/curl', {}]]));
  const defaultSearch = { pathPresent: true, pathChanged: false, defaultSearch: true };
  assert.equal(m.invocation(invocation('curl', [wrapper('command')], { executableSearch: defaultSearch }), caller()).kind, 'unknown-search');
  assert.equal(m.invocation(invocation('curl', [wrapper('command')], {
    nameWord: word('/usr/bin/curl'), executableSearch: defaultSearch }), caller()).kind, 'trusted-external');
  assert.equal(m.invocation(invocation('printf', [wrapper('command')], { executableSearch: defaultSearch }), caller()).kind, 'builtin');
});

test('only unquoted bare time before an external boundary is a reserved wrapper', () => {
  const m = mocked(new Map([['/usr/bin/env', {}], ['/usr/bin/printf', {}]]));
  assert.equal(m.invocation(invocation('printf', [wrapper('time')]), caller()).kind, 'builtin');
  assert.equal(m.invocation(invocation('printf', [wrapper('time', { word: { ...word('time'), quoted: true } })]), caller()).kind, 'not-found');
  assert.equal(m.invocation(invocation('printf', [wrapper('time', { word: word('/usr/bin/time') })]), caller()).kind, 'not-found');
  assert.equal(m.invocation(invocation('printf', [wrapper('env'), wrapper('time')]), caller()).kind, 'not-found');
  const trustedTime = mocked(new Map([['/usr/bin/time', {}], ['/usr/bin/printf', {}], ['/shadow/printf', {}]]));
  assert.equal(trustedTime.invocation(invocation('printf', [wrapper('time', {
    word: { ...word('time'), quoted: true } })]), caller('/shadow:/usr/bin')).kind, 'untrusted-first-match');
  const shadowTime = mocked(new Map([['/usr/bin/time', {}], ['/usr/bin/printf', {}], ['/shadow/time', {}]]));
  assert.equal(shadowTime.invocation(invocation('printf', [wrapper('time'), wrapper('time')]), caller('/shadow:/usr/bin')).kind, 'builtin');
  for (const prefix of ['command', 'builtin']) {
    const selected = invocation('printf', [wrapper(prefix), wrapper('time')]);
    assert.equal(shadowTime.invocation(selected, caller('/shadow:/usr/bin')).kind, 'untrusted-first-match', prefix);
    assert.equal(shadowTime.invocation(selected, caller()).kind, 'trusted-external', prefix);
  }
});

test('all wrapper identities precede the callee and incomplete selection metadata is closed', () => {
  const m = mocked(new Map([['/usr/bin/env', {}], ['/usr/bin/timeout', {}], ['/usr/bin/curl', {}]]));
  assert.equal(m.invocation(invocation('curl', [wrapper('env'), wrapper('timeout')]), caller()).kind, 'trusted-external');
  assert.equal(m.invocation(invocation('curl', [wrapper('env'), wrapper('timeout', {
    executableSearch: { pathPresent: false, pathChanged: false, defaultSearch: false } })]), caller()).kind, 'unknown-search');
  assert.equal(m.invocation(invocation('curl', [wrapper('env')], { wrapperNames: ['env', 'timeout'] }), caller()).kind, 'unknown-search');
  assert.equal(m.invocation(invocation('printf', [], { wrapped: true }), caller()).kind, 'unknown-search');
  assert.equal(m.invocation(invocation('curl', [], { nameWord: word('other') }), caller()).kind, 'unknown-search');
  assert.equal(m.invocation(invocation('printf', [], { functionCallName: 'printf' }), caller()).kind, 'unknown-search');
});
