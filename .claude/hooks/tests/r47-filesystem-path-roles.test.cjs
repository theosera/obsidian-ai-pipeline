'use strict';
// Commands below are Hook stdin DATA. Native Git only creates owned DUMMY
// repositories and reads their root; no proposed add/commit or network runs.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const hooks = path.resolve(process.argv[2] || path.join(__dirname, '..'));
const guard = require(path.join(hooks, 'lib/git-guard-common.cjs'));
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pr191-r47-path-'));
const base = path.join(root, 'base');
const target = path.join(root, 'target');
const home = path.join(root, 'home');
const env = { HOME: home, PATH: '/usr/bin:/bin', GIT_CONFIG_GLOBAL: '/dev/null',
  GIT_CONFIG_SYSTEM: '/dev/null', GIT_CONFIG_NOSYSTEM: '1', CLAUDE_PROJECT_DIR: base };
const git = ['/usr/bin/git', '/bin/git', '/opt/homebrew/bin/git', '/usr/local/bin/git']
  .find(executable => guard.resolveTrustedGitExecutable({ text: executable }));
for (const dir of [base, target, home, path.join(target, 'child'),
  path.join(target, 'ordinary-dir', 'child')]) fs.mkdirSync(dir, { recursive: true });
fs.symlinkSync(path.join(target, 'child'), path.join(base, 'jump'), 'dir');
fs.symlinkSync(path.join(target, 'ordinary-dir', 'child'), path.join(target, 'link'), 'dir');
fs.symlinkSync(target, path.join(target, 'root-link'), 'dir');
fs.symlinkSync(target, path.join(root, 'outside-root-link'), 'dir');
fs.writeFileSync(path.join(base, 'not-a-directory'), 'DUMMY');
test.after(() => fs.rmSync(root, { recursive: true, force: true }));
const quote = value => "'" + value.replace(/'/g, "'\\''") + "'";
function invoke(hook, command, cwd = base) {
  const r = spawnSync(process.execPath, [path.join(hooks, hook)], { env, cwd,
    input: JSON.stringify({ tool_name: 'Bash', tool_input: { command }, cwd }),
    encoding: 'utf8', timeout: 10000 });
  assert.equal(r.error, undefined); assert.equal(r.signal, null); assert.equal(r.status, 0);
  const output = r.stdout.trim() ? JSON.parse(r.stdout) : {};
  return output.hookSpecificOutput?.permissionDecisionReason || 'ALLOW';
}

test('filesystem cwd preserves symlink before .. and ordered empty/absolute -C', () => {
  const physical = fs.realpathSync.native(target);
  assert.equal(guard.gitFilesystemDir(base, ['jump/..']), physical);
  assert.equal(guard.gitFilesystemDir(base, ['jump', '..', '']), physical);
  assert.equal(guard.gitFilesystemDir(base, ['', path.join(base, 'jump'), '..']), physical);
  assert.equal(guard.gitFilesystemDir(base, ['missing']), null);
  assert.equal(guard.gitFilesystemDir(base, ['not-a-directory']), null);
  assert.equal(guard.filesystemPath(target, 'link/..'), fs.realpathSync.native(path.join(target, 'ordinary-dir')));
});

test('PATH keeps symlink/.. for its first selected executable without running it', { skip: !git }, () => {
  const fake = path.join(target, process.platform === 'win32' ? 'git.exe' : 'git');
  fs.writeFileSync(fake, 'DUMMY executable content, never run'); fs.chmodSync(fake, 0o700);
  const lookup = { PATH: ['jump/..', path.dirname(git)].join(path.delimiter) };
  assert.equal(guard.resolveTrustedGitExecutable({ text: 'git' }, lookup, base), null);
  fs.unlinkSync(fake);
  fs.symlinkSync(git, fake);
  assert.equal(guard.resolveTrustedGitExecutable({ text: 'git' }, lookup, base), fs.realpathSync.native(git));
  assert.equal(guard.resolveTrustedGitExecutable({ text: path.join(base, 'jump') + '/../git' }, {}, base), fs.realpathSync.native(git));
  fs.unlinkSync(fake);
});

test('Git root comparison uses the physical -C target, with ordinary file controls', { skip: !git }, () => {
  for (const dir of [base, target]) {
    const r = spawnSync(git, ['init', '-q', dir], { cwd: base, env, encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
  }
  fs.writeFileSync(path.join(target, 'ordinary.txt'), 'DUMMY');
  const command = quote(git) + ' -C jump/.. add ' + quote(target);
  for (const hook of ['block-git-add-all.cjs', 'block-secret-egress.cjs']) {
    assert.match(invoke(hook, command), /^\[禁止\]/, hook);
    assert.equal(invoke(hook, quote(git) + ' -C jump/.. add ordinary.txt'), 'ALLOW', hook);
    // Git's pathspec consumer normalizes link/.. lexically; -C uses chdir.
    assert.match(invoke(hook, quote(git) + ' add link/..', target), /^\[禁止\]/, hook);
    assert.equal(invoke(hook, quote(git) + ' add root-link', target), 'ALLOW', hook);
    assert.equal(invoke(hook, quote(git) + ' add ' + quote(path.join(target, 'root-link')), target), 'ALLOW', hook);
    assert.match(invoke(hook, quote(git) + ' -C jump/.. add ' + quote(path.join(root, 'outside-root-link'))), /^\[判断不能\]/, hook);
    assert.match(invoke(hook, quote(git) + ' -C missing add ordinary.txt'), /^\[判断不能\]/, hook);
    assert.equal(invoke(hook, quote(git) + ' -C missing add -h'), 'ALLOW', hook);
  }
});
