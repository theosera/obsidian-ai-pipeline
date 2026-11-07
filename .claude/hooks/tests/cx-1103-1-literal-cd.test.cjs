'use strict';

// Only the Hook entrypoint is executed. Every shell/client command below is
// stdin DATA; named gh/curl installations are a finite filesystem identity model.
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
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'cx-1103-1-literal-cd-')));
  const T = path.join(root, 'T'), U = path.join(root, 'U'), home = path.join(root, 'home');
  const UShadow = path.join(root, 'U-shadow'), TAlias = path.join(root, 'T-symlink');
  const UAlias = path.join(root, 'U-symlink'), loop = path.join(root, 'loop');
  const protectedDir = path.join(root, 'secrets'), protectedWordParent = path.join(root, 'word-only');
  const protectedWordOnly = path.join(protectedWordParent, 'secrets'), protectedRealOnly = path.join(root, 'ordinary-link');
  const sameWordParent = path.join(root, 'same-word-only'), sameProtectedWord = path.join(sameWordParent, 'secrets');
  const spaced = path.join(T, 'a b'), noSearch = path.join(root, 'no-search');
  const ordinaryFile = path.join(root, 'ordinary-file'), missing = path.join(root, 'missing');
  const UGit = path.join(root, 'U-git-config'), marker = path.join(root, 'unexpected-native-child');
  let hookCalls = 0;
  try {
    for (const dir of [T, U, UShadow, home, spaced, noSearch, UGit, path.join(UGit, '.git'), protectedDir, protectedWordParent, sameWordParent]) fs.mkdirSync(dir);
    fs.symlinkSync(T, TAlias, 'dir');
    fs.symlinkSync(U, UAlias, 'dir');
    fs.symlinkSync('loop', loop, 'dir');
    fs.symlinkSync(U, protectedWordOnly, 'dir');
    fs.symlinkSync(protectedDir, protectedRealOnly, 'dir');
    fs.symlinkSync(T, sameProtectedWord, 'dir');
    fs.writeFileSync(ordinaryFile, 'DUMMY ordinary file\n');
    fs.chmodSync(noSearch, 0o600);
    fs.writeFileSync(path.join(UGit, '.git/config'), '[core]\n\tsshCommand = /DUMMY/transport\n');
    for (const directory of [T, UShadow]) fs.writeFileSync(path.join(directory, 'gh'),
      '#!/DUMMY/never-execute\nDUMMY inert shadow\n', { mode: 0o700 });
    const preload = path.join(root, 'identity-model-and-no-native.cjs');
    fs.writeFileSync(preload, `
'use strict';
const fs=require('node:fs'),cp=require('node:child_process'),path=require('node:path');
const installed=new Set(['/usr/bin/gh','/usr/bin/curl']);
const anchors=new Set(['/usr/bin','/bin','/usr/sbin','/sbin','/usr/local/bin','/opt/homebrew/bin']);
const selected=file=>typeof file==='string' && ['gh','curl'].includes(path.basename(file)) && anchors.has(path.dirname(file));
const missing=()=>{throw Object.assign(Error('CX-1103-1 modeled absent named gh/curl installation'),{code:'ENOENT'});};
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
    assert.equal(guard.isSecretPath(protectedDir), true, 'direct synthetic target selects both protected-path guards');
    assert.equal(guard.isSecretPath(protectedWordOnly), true, 'word-only synthetic link selects the lexical guard');
    assert.equal(guard.isSecretPath(fs.realpathSync.native(protectedWordOnly)), false, 'word-only physical target stays ordinary');
    assert.equal(guard.isSecretPath(protectedRealOnly), false, 'real-only synthetic link word stays ordinary');
    assert.equal(guard.isSecretPath(fs.realpathSync.native(protectedRealOnly)), true, 'real-only physical target selects the physical guard');
    assert.equal(guard.isSecretPath(sameProtectedWord), true, 'same-directory word witness selects only the lexical guard');
    assert.equal(fs.realpathSync.native(sameProtectedWord), fs.realpathSync.native(T));
    assert.equal(guard.isSecretPath(fs.realpathSync.native(sameProtectedWord)), false);
    const differentCwdIds = new Set([
      'allow-2-different-cwd', 'allow-4-quoted-space', 'allow-5-semicolon-after-grep',
      'allow-extra-wrapper-different-command', 'allow-extra-wrapper-different-exec',
      'allow-extra-wrapper-different-env', 'allow-extra-relative-PATH-destination',
      'control-root-binding-absolute-xdg-relative-home', 'control-root-binding-posix-appdata',
      'control-root-binding-unset-xdg-data',
    ]);
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
      { id: 'deny-cwd-protection-direct', command: prefix(protectedDir) + gh, cwdProtectionCase: true },
      { id: 'deny-cwd-protection-word-only', command: prefix(protectedWordOnly) + gh, cwdProtectionCase: true },
      { id: 'deny-cwd-protection-real-only', command: prefix(protectedRealOnly) + gh, cwdProtectionCase: true },
      { id: 'deny-cwd-protection-non-gh', command: prefix(U) + 'curl -q https://example.com', cwdProtectionCase: true },
      { id: 'control-cwd-protection-curl-no-cd', command: 'curl -q https://example.com', expected: 'ALLOW', cwdProtectionCase: true },
      { id: 'deny-root-binding-relative-home', command: prefix(U) + gh, extraEnv: { HOME: '.' }, contextControlCase: true },
      { id: 'deny-root-binding-relative-xdg', command: prefix(U) + gh, extraEnv: { XDG_CONFIG_HOME: '.' }, contextControlCase: true },
      { id: 'deny-root-binding-xdg-data', command: prefix(U) + gh, extraEnv: { XDG_DATA_HOME: '.' }, contextControlCase: true },
      { id: 'deny-root-binding-no-selected-root', command: prefix(U) + gh, extraEnv: { HOME: '', XDG_CONFIG_HOME: '' }, contextControlCase: true },
      { id: 'deny-root-binding-empty-xdg-relative-home', command: prefix(U) + gh, extraEnv: { HOME: '.', XDG_CONFIG_HOME: '' }, contextControlCase: true },
      ...[
        ['relative-home', { HOME: '.' }],
        ['relative-xdg', { XDG_CONFIG_HOME: '.' }],
        ['xdg-data', { XDG_DATA_HOME: '.' }],
        ['no-selected-root', { HOME: '', XDG_CONFIG_HOME: '' }],
      ].flatMap(([name, extraEnv]) => [
        { id: 'control-root-binding-' + name + '-same-realpath', command: prefix(TAlias) + gh, extraEnv, expected: 'ALLOW', contextControlCase: true },
        { id: 'control-root-binding-' + name + '-no-cd', command: gh, extraEnv, expected: 'ALLOW', contextControlCase: true },
      ]),
      ...[['relative', '.'], ['empty', ''], ['absolute', home]].flatMap(([name, value]) => [
        { id: 'control-root-binding-gh-config-' + name + '-different-cwd', command: prefix(U) + gh, extraEnv: { GH_CONFIG_DIR: value }, expected: 'UNKNOWN', contextControlCase: true },
        { id: 'control-root-binding-gh-config-' + name + '-no-cd', command: gh, extraEnv: { GH_CONFIG_DIR: value }, expected: 'UNKNOWN', contextControlCase: true },
      ]),
      { id: 'control-root-binding-absolute-xdg-relative-home', command: prefix(U) + gh, extraEnv: { XDG_CONFIG_HOME: home, HOME: '.' }, expected: 'ALLOW', contextControlCase: true },
      { id: 'control-root-binding-posix-appdata', command: prefix(U) + gh, extraEnv: { AppData: '.' }, expected: 'ALLOW', contextControlCase: true },
      { id: 'control-root-binding-unset-xdg-data', command: prefix(U) + 'env -u XDG_DATA_HOME ' + gh, extraEnv: { XDG_DATA_HOME: '.' }, expected: 'ALLOW', contextControlCase: true },
      { id: 'allow-same-dir-spaced-input', command: 'cd "' + spaced + '" && ' + gh, cwd: spaced, expected: 'ALLOW', sameDirScopeCase: true },
      { id: 'deny-same-dir-relative-self', command: "cd '.' && " + gh, sameDirScopeCase: true },
      { id: 'deny-same-dir-relative-sibling', command: "cd '../U' && " + gh, sameDirScopeCase: true },
      { id: 'deny-same-dir-relative-missing', command: "cd 'missing' && " + gh, sameDirScopeCase: true },
      { id: 'deny-same-dir-absolute-loop', command: prefix(loop) + gh, sameDirScopeCase: true },
      { id: 'deny-same-dir-relative-loop', command: "cd '../loop' && " + gh, sameDirScopeCase: true },
      { id: 'deny-same-dir-different-symlink', command: prefix(UAlias) + gh, sameDirScopeCase: true },
      { id: 'deny-same-dir-two-same-cd', command: prefix(T) + prefix(T) + gh, sameDirScopeCase: true },
      { id: 'deny-same-dir-two-mixed-cd', command: prefix(T) + prefix(U) + gh, sameDirScopeCase: true },
      { id: 'deny-same-dir-dot-component', command: prefix(T + '/.') + gh, sameDirScopeCase: true },
      { id: 'deny-same-dir-gh-config', command: prefix(T) + gh, extraEnv: { GH_CONFIG_DIR: '.' }, sameDirScopeCase: true },
      { id: 'deny-same-dir-path-shadow', command: prefix(T) + gh, extraEnv: { PATH: '.:/usr/bin:/bin' }, sameDirScopeCase: true },
      { id: 'forbid-same-dir-issue-body-file', command: prefix(T) + 'gh issue create --repo o/r --title ordinary --body-file ordinary.txt', expected: 'FORBIDDEN', sameDirScopeCase: true },
      { id: 'deny-same-dir-non-gh', command: prefix(T) + 'curl -q https://example.com', sameDirScopeCase: true },
      { id: 'deny-same-dir-relative-gh-pager', command: prefix(T) + gh, extraEnv: { GH_PAGER: './relative-helper' }, sameDirScopeCase: true },
      { id: 'control-same-dir-child-shell', command: prefix(T) + 'bash -c ' + q(gh), expected: 'ALLOW', sameDirScopeCase: true },
      { id: 'control-same-dir-two-cd-child-shell', command: prefix(T) + prefix(T) + 'bash -c ' + q(gh), expected: 'ALLOW', sameDirScopeCase: true },
      { id: 'control-same-dir-physical-cd-child-shell', command: 'cd -P ' + q(T) + ' && bash -c ' + q(gh), expected: 'ALLOW', sameDirScopeCase: true },
      { id: 'deny-same-dir-control-witness', command: cd(T) + ' | ' + gh, sameDirGuardTarget: T, sameDirGuardWitnessCase: true },
      { id: 'deny-same-dir-alias-witness', command: prefix(T) + gh + '; alias cd=:', sameDirGuardTarget: T, sameDirGuardWitnessCase: true },
      { id: 'deny-same-dir-syntax-witness', command: 'builtin ' + prefix(T) + gh, sameDirGuardTarget: T, sameDirGuardWitnessCase: true },
      { id: 'deny-same-dir-word-witness', command: prefix(sameProtectedWord) + gh, sameDirGuardTarget: sameProtectedWord, sameDirGuardWitnessCase: true },
      { id: 'deny-same-dir-realpath-witness', command: prefix(protectedRealOnly) + gh, cwd: protectedDir, sameDirGuardTarget: protectedRealOnly, sameDirGuardWitnessCase: true },
    ];
    // The owner narrowed only cwd lending. Keep historical case definitions and
    // explicitly pin the ten previously allowed different-cwd inputs to UNKNOWN.
    for (const entry of cases) if (differentCwdIds.has(entry.id)) {
      entry.differentCwdCase = true;
      entry.expected = 'UNKNOWN';
    }
    assert.equal(cases.filter(entry => !entry.cwdProtectionCase && !entry.contextControlCase && !entry.sameDirScopeCase && !entry.sameDirGuardWitnessCase).length, 69, 'retain all original focused inputs');
    assert.equal(cases.filter(entry => entry.positive).length, 13, 'retain all historical positive case identities');
    assert.equal(cases.filter(entry => entry.positive && !entry.differentCwdCase).length, 6, 'retain all six original same-directory ALLOW assertions');
    assert.equal(cases.filter(entry => entry.positive && entry.differentCwdCase).length, 7, 'explicitly narrow seven historical positives to UNKNOWN');
    assert.equal(cases.filter(entry => entry.differentCwdCase).length, 10, 'only the ten named previous expectations are narrowed');
    assert.equal(cases.filter(entry => entry.cwdProtectionCase).length, 5, 'only the requested cwd-protection inputs are added');
    assert.equal(cases.filter(entry => !entry.contextControlCase && !entry.sameDirScopeCase && !entry.sameDirGuardWitnessCase).length, 74, 'retain all previous focused definitions');
    assert.equal(cases.filter(entry => entry.contextControlCase).length, 22, 'only the requested inherited-context controls are added');
    assert.equal(cases.filter(entry => !entry.sameDirScopeCase && !entry.sameDirGuardWitnessCase).length, 96, 'retain every prior focused case');
    assert.equal(cases.filter(entry => entry.sameDirScopeCase).length, 18, 'remove only the two named unpublished shell controls');
    assert.equal(cases.filter(entry => !entry.sameDirGuardWitnessCase).length, 114, 'retain all fifth-snapshot inputs except the two named controls');
    assert.equal(cases.filter(entry => entry.sameDirGuardWitnessCase).length, 5, 'add only the five same-directory guard witnesses');
    assert.equal(cases.length, 119, 'every focused group must run');
    for (const entry of cases) await t.test(entry.id, () => {
      const inputCwd = entry.cwd || T;
      if (entry.sameDirGuardWitnessCase) assert.equal(fs.realpathSync.native(entry.sameDirGuardTarget), fs.realpathSync.native(inputCwd),
        'every new guard witness must target the same physical directory as its payload cwd');
      const input = JSON.stringify({ tool_name: 'Bash', tool_input: { command: entry.command }, cwd: inputCwd });
      const result = spawnSync(process.execPath, ['--require', preload, path.join(hooks, EG)], {
        cwd: inputCwd, env: { ...environment, ...entry.extraEnv }, input, encoding: 'utf8', timeout: 20000,
      });
      hookCalls++;
      const verdict = observe(result);
      t.diagnostic(JSON.stringify({ id: entry.id, command: entry.command, baseline,
        ...(entry.cwdProtectionCase ? { cwdProtectionCase: true } : {}),
        ...(entry.contextControlCase ? { contextControlCase: true } : {}),
        ...(entry.sameDirScopeCase ? { sameDirScopeCase: true } : {}),
        ...(entry.sameDirGuardWitnessCase ? { sameDirGuardWitnessCase: true } : {}),
        ...(entry.sameDirGuardWitnessCase ? { sameDirGuardSameRealpath: true } : {}),
        ...(entry.differentCwdCase ? { differentCwdCase: true } : {}),
        verdict, status: result.status, signal: result.signal, errorCode: result.error?.code || null,
        stdout: result.stdout, stderr: result.stderr }));
      assert.notEqual(verdict, 'BROKEN', 'Hook output must retain its complete verdict contract');
      assert.equal(fs.existsSync(marker), false, 'no proposed/native command may execute or be attempted');
      if (entry.expected) assert.equal(verdict, entry.expected);
      else if (entry.positive) assert.equal(verdict, baseline ? 'UNKNOWN' : 'ALLOW');
      else assert.equal(verdict, 'UNKNOWN');
    });
    assert.deepEqual(sourcePins(), sourceBefore, 'runtime source must stay fixed during the focused cut');
    t.diagnostic(JSON.stringify({ hookCalls, sourcePins: sourceBefore, baseline,
      retainedOriginalCases: 69, retainedOriginalPositiveCases: 13, cwdProtectionCases: 5,
      retainedPreviousCases: 74, contextControlCases: 22,
      previousScopeCases: 96, sameDirScopeCases: 18, fifthSnapshotCases: 114, sameDirGuardWitnessCases: 5, changedDifferentCwdCases: 10,
      retainedSameDirPositiveCases: 6, narrowedDifferentCwdPositiveCases: 7,
      ownedFixtureRoot: root,
      nativeAttempts: 0, proposedCommandsExecuted: 0,
      fixtureScope: 'owned synthetic directories and finite named gh/curl identity model; native backend behavior unqualified' }));
  } finally {
    if (fs.existsSync(noSearch)) fs.chmodSync(noSearch, 0o700);
    fs.rmSync(root, { recursive: true, force: true });
  }
});
