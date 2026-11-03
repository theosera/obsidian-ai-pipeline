'use strict';

// Only the Hook entrypoint is executed. Every shell/client command below is
// stdin DATA; the named gh installation is a finite filesystem identity model.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const hooks = path.resolve(process.argv[2] || path.join(__dirname, '..'));
const baseline = process.argv.includes('--baseline');
const EG = 'block-secret-egress.cjs';
const q = value => "'" + value.replace(/'/g, "'\\''") + "'";
const digest = value => crypto.createHash('sha256').update(value).digest('hex');

function observe(result) {
  if (result.error || result.status !== 0 || result.signal || result.stderr !== '') return 'BROKEN';
  if (result.stdout === '') return 'ALLOW';
  let wire;
  try { wire = JSON.parse(result.stdout)?.hookSpecificOutput; } catch { return 'BROKEN'; }
  if (wire?.permissionDecision !== 'deny' || typeof wire.permissionDecisionReason !== 'string') return 'BROKEN';
  return wire.permissionDecisionReason.startsWith('[禁止] ') ? 'FORBIDDEN' :
    wire.permissionDecisionReason.startsWith('[判断不能] ') ? 'UNKNOWN' : 'BROKEN';
}

test('CX-1103-1 leading literal absolute cd uses only its qualified destination', async t => {
  if (process.platform === 'win32') { t.skip('POSIX filesystem identity model does not qualify Windows'); return; }
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'cx-1103-1-literal-cd-'));
  const T = path.join(root, 'T'), U = path.join(root, 'U'), home = path.join(root, 'home');
  const UShadow = path.join(root, 'U-shadow'), TAlias = path.join(root, 'T-symlink');
  const spaced = path.join(T, 'a b'), noSearch = path.join(root, 'no-search');
  const ordinaryFile = path.join(root, 'ordinary-file'), missing = path.join(root, 'missing');
  const UGit = path.join(root, 'U-git-config'), marker = path.join(root, 'unexpected-native-child');
  let hookCalls = 0;
  try {
    for (const dir of [T, U, UShadow, home, spaced, noSearch, UGit, path.join(UGit, '.git')]) fs.mkdirSync(dir);
    fs.symlinkSync(T, TAlias, 'dir');
    fs.writeFileSync(ordinaryFile, 'DUMMY ordinary file\n');
    fs.chmodSync(noSearch, 0o600);
    fs.writeFileSync(path.join(UGit, '.git/config'), '[core]\n\tsshCommand = /DUMMY/transport\n');
    for (const directory of [T, UShadow]) fs.writeFileSync(path.join(directory, 'gh'),
      '#!/DUMMY/never-execute\nDUMMY inert shadow\n', { mode: 0o700 });
    const preload = path.join(root, 'identity-model-and-no-native.cjs');
    fs.writeFileSync(preload, `
'use strict';
const fs=require('node:fs'),cp=require('node:child_process'),path=require('node:path');
const installed=new Set(['/usr/bin/gh']);
const anchors=new Set(['/usr/bin','/bin','/usr/sbin','/sbin','/usr/local/bin','/opt/homebrew/bin']);
const selected=file=>typeof file==='string' && path.basename(file)==='gh' && anchors.has(path.dirname(file));
const missing=()=>{throw Object.assign(Error('CX-1103-1 modeled absent named gh installation'),{code:'ENOENT'});};
const stat=fs.statSync,access=fs.accessSync,real=fs.realpathSync,native=fs.realpathSync.native;
fs.statSync=function(file,...args){if(selected(file))return installed.has(file)?{isFile:()=>true,isDirectory:()=>false}:missing();return stat.call(this,file,...args);};
fs.accessSync=function(file,...args){if(selected(file))return installed.has(file)?undefined:missing();return access.call(this,file,...args);};
fs.realpathSync=function(file,...args){if(selected(file))return installed.has(file)?file:missing();return real.call(this,file,...args);};
fs.realpathSync.native=function(file,...args){if(selected(file))return installed.has(file)?file:missing();return native.call(this,file,...args);};
for(const name of ['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork'])cp[name]=()=>{fs.appendFileSync(${JSON.stringify(marker)},name+'\\n');throw Error('CX-1103-1 selected/native child execution forbidden');};
`);
    const environment = { PATH: '/usr/bin:/bin', HOME: home, TMPDIR: root, LC_ALL: 'C',
      CLAUDE_PROJECT_DIR: T, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: os.devNull,
      GIT_CONFIG_SYSTEM: os.devNull, GIT_TERMINAL_PROMPT: '0' };
    const sourceFiles = [EG, 'lib/git-guard-common.cjs', 'lib/git-precommit-readers.cjs', 'lib/executable-identity.cjs'];
    const sourcePins = () => Object.fromEntries(sourceFiles.map(file => [file, digest(fs.readFileSync(path.join(hooks, file)))]));
    const sourceBefore = sourcePins();
    const gh = 'gh repo view o/r --json visibility';
    const cd = dir => 'cd ' + q(dir);
    const prefix = dir => cd(dir) + ' && ';
    const guard = require(path.join(hooks, 'lib/git-guard-common.cjs'));
    assert.equal(guard.inspect(prefix(U) + gh).invocations.find(entry => entry.name === 'gh').cdLikeBefore, true,
      'egress qualification must not redefine the shared cdLikeBefore contract');
    assert.equal(guard.inspect(gh).invocations.find(entry => entry.name === 'gh').cdLikeBefore, false);
    const cases = [
      { id: 'control-no-cd', command: gh, expected: 'ALLOW' },
      { id: 'allow-1-same-cwd', command: prefix(T) + gh, positive: true },
      { id: 'allow-2-different-cwd', command: prefix(U) + gh, positive: true },
      { id: 'allow-3-downstream-pipeline', command: prefix(T) + gh + ' 2>&1 | head -2', positive: true },
      { id: 'allow-4-quoted-space', command: 'cd "' + spaced + '" && ' + gh, positive: true },
      { id: 'allow-5-semicolon-after-grep', command: prefix(U) + 'grep -c x f; ' + gh, positive: true },
      ...['command', 'exec', 'env'].flatMap(wrapper => [
        { id: 'control-wrapper-' + wrapper, command: wrapper + ' ' + gh, expected: 'ALLOW' },
        { id: 'allow-extra-wrapper-same-' + wrapper, command: prefix(T) + wrapper + ' ' + gh, positive: true },
        { id: 'allow-extra-wrapper-different-' + wrapper, command: prefix(U) + wrapper + ' ' + gh, positive: true },
      ]),
      { id: 'control-issue-explicit-repository', command: 'gh issue list --repo o/r --json number', expected: 'ALLOW' },
      { id: 'allow-extra-symlink-same-realpath', command: prefix(TAlias) + 'gh issue list --repo o/r --json number', positive: true },
      { id: 'control-relative-PATH-input-shadow', command: gh, extraEnv: { PATH: '.:/usr/bin:/bin' }, expected: 'UNKNOWN' },
      { id: 'allow-extra-relative-PATH-destination', command: prefix(U) + gh, extraEnv: { PATH: '.:/usr/bin:/bin' }, positive: true },
      { id: 'deny-1-variable', command: 'cd "$D" && ' + gh },
      { id: 'deny-2-command-substitution', command: 'cd "$(pwd)" && ' + gh },
      { id: 'deny-2-backtick', command: 'cd `pwd` && ' + gh },
      { id: 'deny-3-tilde', command: 'cd ~/x && ' + gh },
      { id: 'deny-4-oldpwd', command: 'cd - && ' + gh },
      { id: 'deny-5-relative', command: 'cd sub && ' + gh },
      { id: 'deny-5-cdpath-prefix', command: 'CDPATH=/DUMMY cd sub && ' + gh },
      { id: 'deny-6-pushd', command: 'pushd ' + q(U) + ' && ' + gh },
      { id: 'deny-6-popd', command: 'popd && ' + gh },
      { id: 'deny-7-two-prior-cd', command: prefix(U) + prefix(T) + gh },
      { id: 'deny-7-later-cd', command: prefix(U) + gh + '; ' + cd(T) },
      { id: 'deny-7-later-builtin-cd', command: prefix(U) + gh + '; builtin ' + cd(T) },
      { id: 'deny-7-function-cd', command: prefix(U) + 'f() { ' + cd(T) + '; }; f; ' + gh },
      { id: 'deny-7-unused-function-cd', command: prefix(U) + 'f() { ' + cd(T) + '; }; ' + gh },
      { id: 'deny-7-later-shell-cd', command: prefix(U) + gh + '; bash -c ' + q(cd(T)) },
      { id: 'deny-7-later-stdin-shell-cd', command: prefix(U) + gh + '; bash <<< ' + q(cd(T)) },
      { id: 'deny-7-later-eval-cd', command: prefix(U) + gh + '; eval ' + q(cd(T)) },
      { id: 'deny-8-subshell', command: '(' + prefix(U) + gh + ')' },
      { id: 'control-8-isolated-subshell-cd', command: '(' + cd(U) + ') && ' + gh, expected: 'ALLOW' },
      { id: 'deny-8-group', command: '{ ' + cd(U) + '; } && ' + gh },
      { id: 'deny-8-pipeline', command: cd(U) + ' | ' + gh },
      { id: 'deny-8-background', command: cd(U) + ' & ' + gh },
      { id: 'deny-8-or-condition', command: cd(U) + ' || ' + gh },
      { id: 'deny-8-cd-redirection', command: cd(U) + ' > ordinary-output && ' + gh },
      { id: 'deny-8-following-group-source', command: prefix(U) + '{ ' + gh + '; }' },
      { id: 'deny-8-following-subshell-source', command: prefix(U) + '(' + gh + ')' },
      { id: 'deny-8-leading-context-command', command: 'printf ordinary; ' + prefix(U) + gh },
      { id: 'deny-9-function-shadow', command: 'cd() { :; }; ' + prefix(U) + gh },
      { id: 'deny-9-alias-shadow', command: 'alias cd=:; ' + prefix(U) + gh },
      { id: 'deny-9-later-alias-shadow', command: prefix(U) + gh + '; alias cd=:' },
      { id: 'deny-9-modern-inherited-cd', command: prefix(U) + gh, extraEnv: { 'BASH_FUNC_cd%%': '() { :; }' } },
      { id: 'deny-9-legacy-inherited-cd', command: prefix(U) + gh, extraEnv: { cd: '() { :; }' } },
      { id: 'deny-10-builtin-prefix', command: 'builtin ' + prefix(U) + gh },
      { id: 'deny-10-command-prefix', command: 'command ' + prefix(U) + gh },
      { id: 'deny-10-assignment-prefix', command: 'X=1 ' + prefix(U) + gh },
      { id: 'deny-10-physical-option', command: 'cd -P ' + q(U) + ' && ' + gh },
      { id: 'deny-10-double-dash', command: 'cd -- ' + q(U) + ' && ' + gh },
      { id: 'deny-10-later-wrapper-cwd', command: prefix(U) + 'env -C ' + q(T) + ' ' + gh },
      { id: 'deny-11-dot-segment', command: prefix(U + '/.') + gh },
      { id: 'deny-11-dotdot-segment', command: prefix(U + '/../U') + gh },
      { id: 'deny-12-missing', command: prefix(missing) + gh },
      { id: 'deny-12-file', command: prefix(ordinaryFile) + gh },
      { id: 'deny-12-no-search', command: prefix(noSearch) + gh },
      { id: 'deny-13-git-push', command: prefix(U) + 'git push' },
      { id: 'deny-13-git-fetch', command: prefix(U) + 'git fetch' },
      { id: 'deny-13-git-transport-config', command: prefix(UGit) + 'git fetch' },
      { id: 'deny-14-relative-PATH-shadow', command: prefix(UShadow) + gh, extraEnv: { PATH: '.:/usr/bin:/bin' } },
      // The request's "same verdict as before" shell condition retains this
      // baseline ALLOW; the negative-section heading is not a replacement oracle.
      { id: 'control-15-child-shell', command: prefix(U) + 'bash -c ' + q(gh), expected: 'ALLOW' },
      { id: 'deny-15-child-shell-own-cd', command: prefix(U) + 'bash -c ' + q(prefix(T) + gh) },
      { id: 'deny-16-gh-internal-git', command: prefix(U) + 'gh pr create --repo o/r --head topic --title ordinary --body ordinary' },
    ];
    for (const entry of cases) await t.test(entry.id, () => {
      const input = JSON.stringify({ tool_name: 'Bash', tool_input: { command: entry.command }, cwd: T });
      const result = spawnSync(process.execPath, ['--require', preload, path.join(hooks, EG)], {
        cwd: T, env: { ...environment, ...entry.extraEnv }, input, encoding: 'utf8', timeout: 20000,
      });
      hookCalls++;
      const verdict = observe(result);
      t.diagnostic(JSON.stringify({ id: entry.id, command: entry.command, baseline,
        verdict, status: result.status, signal: result.signal, errorCode: result.error?.code || null,
        stdout: result.stdout, stderr: result.stderr }));
      assert.notEqual(verdict, 'BROKEN', 'Hook output must retain its complete verdict contract');
      assert.equal(fs.existsSync(marker), false, 'no proposed/native command may execute or be attempted');
      if (entry.positive) assert.equal(verdict, baseline ? 'UNKNOWN' : 'ALLOW');
      else if (entry.expected) assert.equal(verdict, entry.expected);
      else assert.equal(verdict, 'UNKNOWN');
    });
    assert.deepEqual(sourcePins(), sourceBefore, 'runtime source must stay fixed during the focused cut');
    t.diagnostic(JSON.stringify({ hookCalls, sourcePins: sourceBefore, baseline,
      nativeAttempts: 0, proposedCommandsExecuted: 0,
      fixtureScope: 'owned synthetic directories and finite named gh identity model; native gh behavior unqualified' }));
  } finally {
    if (fs.existsSync(noSearch)) fs.chmodSync(noSearch, 0o700);
    fs.rmSync(root, { recursive: true, force: true });
  }
});
