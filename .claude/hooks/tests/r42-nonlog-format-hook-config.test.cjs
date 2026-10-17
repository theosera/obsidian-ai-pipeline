'use strict';
// Pure roles and owned Hook DATA; proposed Git commands and native callbacks never run.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const { spawnSync } = require('node:child_process');
const hooks = path.resolve(process.argv[2] || path.join(__dirname, '..'));
const readers = require(path.join(hooks, 'lib/git-precommit-readers.cjs'));
const guard = require(path.join(hooks, 'lib/git-guard-common.cjs'));
const environment = { PATH: '/DUMMY/bin', HOME: '/DUMMY/home' };
function assess(command, entries = [], indexHook = () => false) {
  const parsed = guard.inspect(command + '; git commit -m x', { trackGitPreCommitEnvironment: true,
    initialGitPreCommitEnvironmentSources: readers.environmentSources(environment) });
  assert.deepEqual(parsed.problems, []);
  const g = parsed.gits[0], invocation = parsed.invocations.find(i => i.order === g.invocationOrder);
  return readers.assessReader(g, invocation, '/DUMMY/repo', { environment, executable: '/DUMMY/git',
    isTrusted: () => true, probe: () => entries instanceof Map ? entries : new Map(entries), indexHook });
}
const unknown = command => {
  const decision = assess(command);
  assert.equal(decision?.category, 'UNKNOWN');
  assert.match(decision.reason, /non-log-signature-format/);
};
test('exact shortlog and ref-filter review inputs select verifier uncertainty', () => {
  unknown("git -P shortlog '--format=%G?' HEAD");
  unknown("git -P for-each-ref '--format=%(signature:grade)' refs/heads");
  unknown("git -P branch --list '--format=%(signature:signer)'");
  unknown("git -P for-each-ref '--format=%(*signature:grade)' refs/tags");
});
test('shortlog description and additive group formats have separate active roles', () => {
  unknown("git -P shortlog '--group=format:%G?' -s HEAD");
  unknown("git -P shortlog '--group=%G?' HEAD");
  unknown("git -P shortlog '--group=format:%G?' --group=author HEAD");
  unknown("git -P shortlog --summary '--format=%G?' --no-summary HEAD");
  unknown("git -P shortlog --committer '--format=%G?' HEAD");
  unknown("git -P shortlog -c '--format=%G?' HEAD");
  assert.equal(assess("git -P shortlog '--format=%G?' --summary HEAD"), null);
  assert.equal(assess("git -P shortlog '--group=format:%G?' --no-group HEAD"), null);
  assert.equal(assess("git -P shortlog '--group=trailer:%G?' HEAD"), null);
});
test('known normal formats, genuine help and ordinary defaults stay available', () => {
  for (const cmd of ['git -P shortlog HEAD', 'git -P shortlog --format=%s HEAD',
    "git -P for-each-ref '--format=%(refname)' refs/heads", "git -P branch --list '--format=%(refname)'",
    "git -P shortlog '--format=%G?' -h", "git -P for-each-ref '--format=%(signature:grade)' -h"]) {
    assert.equal(assess(cmd), null, cmd);
  }
});
test('last format wins; consumed data and terminators cannot become selectors', () => {
  assert.equal(assess("git -P shortlog '--format=%G?' --format=%s HEAD"), null);
  unknown("git -P shortlog --format=%s '--format=%G?' HEAD");
  assert.equal(assess("git -P for-each-ref '--format=%(signature:grade)' '--format=%(refname)' refs/heads"), null);
  assert.equal(assess("git -P shortlog --grep '--format=%G?' HEAD"), null);
  assert.equal(assess("git -P shortlog HEAD -- '--format=%G?'"), null);
  assert.equal(assess("git -P for-each-ref -- '--format=%(signature:grade)'"), null);
});
test('ref-filter escaped percent and raw contents signature are not verification atoms', () => {
  assert.equal(assess("git -P for-each-ref '--format=%%(signature:grade)' refs/heads"), null);
  assert.equal(assess("git -P for-each-ref '--format=%(contents:signature)' refs/heads"), null);
  unknown("git -P for-each-ref '--format=%%%(signature:grade)' refs/heads");
  assert.equal(assess("git -P shortlog '--format=%%G?' HEAD"), null);
  unknown("git -P shortlog '--format=%%%G?' HEAD");
});
test('selected sort verification and unproved dynamic/abbreviated selectors stop', () => {
  unknown('git -P for-each-ref --sort=signature:grade refs/heads');
  unknown('git -P branch --list --sort=-signature:grade');
  assert.equal(assess('git -P for-each-ref --sort=refname refs/heads'), null);
  assert.equal(assess('git -P for-each-ref --sort=signature:grade --no-sort refs/heads'), null);
  assert.equal(assess('git -P shortlog --format="$FORMAT" HEAD')?.category, 'UNKNOWN');
  assert.equal(assess('git -P shortlog --form=%s HEAD')?.category, 'UNKNOWN');
});
test('branch config sorting is multi-valued and CLI sort is additive until explicit reset', () => {
  const config = readers.parseConfigOutput('local\0branch.sort\nsignature:grade\0local\0branch.sort\nrefname\0');
  assert.deepEqual(config.branchSort, ['signature:grade', 'refname']);
  assert.match(assess('git -P branch --list', config).reason, /non-log-signature-format/);
  assert.match(assess('git -P branch --list --sort=refname', config).reason, /non-log-signature-format/);
  assert.equal(assess('git -P branch --list --no-sort --sort=refname', config), null);
  assert.equal(assess('git -P branch --show-current', config), null);
  unknown('git -P branch --list --sort=version:signature:grade');
  unknown("git -P for-each-ref '--sort=-v:*signature:grade' refs/tags");
  assert.equal(assess('git -P shortlog HEAD', [['format.pretty', '%G?']]), null);
});
test('Git2.54 friendly-name disable does not disable another configured hook event', () => {
  const entries = [['hook.dummy.event', 'post-index-change'], ['hook.post-index-change.enabled', 'false']];
  assert.equal(readers.configuredPostIndex(new Map(entries)), true);
  assert.match(assess('git -P status', entries).reason, /configured post-index/);
  assert.equal(readers.configuredPostIndex(new Map([...entries, ['hook.dummy.enabled', 'false']])), false);
});
test('friendly-name disable leaves the independent traditional hook presence gate intact', () => {
  const entries = [['hook.dummy.event', 'post-index-change'], ['hook.dummy.enabled', 'false'],
    ['hook.post-index-change.enabled', 'false']];
  assert.equal(assess('git -P status', entries), null);
  assert.match(assess('git -P status', entries, () => true).reason, /post-index-change/);
  assert.match(assess('git -P status', entries, () => null).reason, /post-index-change/);
});

test('owned Hook DATA wires exact review inputs, normal formats and independent hook gates', t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'r42-nonlog-source-'));
  try {
    const home = path.join(root, 'home'), repo = path.join(root, 'repo'), marker = path.join(root, 'HOOK_EXECUTED');
    fs.mkdirSync(home); fs.mkdirSync(repo);
    const env = { PATH: process.env.PATH, HOME: home, XDG_CONFIG_HOME: path.join(home, '.config'),
      GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_SYSTEM: '/dev/null',
      GIT_NO_LAZY_FETCH: '1', GIT_PAGER: 'cat', LC_ALL: 'C', CLAUDE_PROJECT_DIR: repo };
    const git = (...args) => {
      const r = spawnSync('git', ['--no-pager', '--no-lazy-fetch', '-c', 'core.hooksPath=/dev/null',
        '-c', 'commit.gpgSign=false', ...args], { cwd: repo, env, encoding: 'utf8', timeout: 20000 });
      assert.equal(r.error, undefined); assert.equal(r.status, 0, r.stderr);
    };
    git('init', '-q'); git('config', 'user.name', 'DUMMY'); git('config', 'user.email', 'dummy@example.invalid');
    fs.writeFileSync(path.join(repo, 'a.txt'), 'DUMMY\n'); git('add', '--', 'a.txt'); git('commit', '-q', '-m', 'DUMMY fixture');
    fs.writeFileSync(path.join(repo, 'a.txt'), 'DUMMY staged\n'); git('add', '--', 'a.txt');
    let actualHookCalls = 0, actualEgressCalls = 0;
    const run = (command, hook = 'block-secret-git.cjs') => {
      const r = spawnSync(process.execPath, [path.join(hooks, hook)], { cwd: repo, env,
        input: JSON.stringify({ tool_name: 'Bash', tool_input: { command }, cwd: repo }), encoding: 'utf8', timeout: 20000 });
      if (hook === 'block-secret-git.cjs') actualHookCalls++;
      else actualEgressCalls++;
      assert.equal(r.error, undefined); assert.equal(r.status, 0, r.stderr);
      if (!r.stdout) return 'ALLOW';
      const result = JSON.parse(r.stdout).hookSpecificOutput;
      assert.equal(result.permissionDecision, 'deny');
      return result.permissionDecisionReason.startsWith('[禁止] ') ? 'FORBIDDEN'
        : result.permissionDecisionReason.startsWith('[判断不能] ') ? 'UNKNOWN' : 'BROKEN';
    };
    assert.equal(run("git -P shortlog '--format=%G?' HEAD; git commit -m x"), 'UNKNOWN');
    assert.equal(run("git -P for-each-ref '--format=%(signature:grade)' refs/heads; git commit -m x"), 'UNKNOWN');
    assert.equal(run('git -P shortlog --format=%s HEAD; git commit -m x'), 'ALLOW');
    assert.equal(run("git -P for-each-ref '--format=%(refname)' refs/heads; git commit -m x"), 'ALLOW');
    assert.equal(run("git -P reflog show '--format=%G?' HEAD; git commit -m x"), 'UNKNOWN');
    // reflog is outside the caller's supported pre-commit reader set, even for a normal format.
    assert.equal(run('git -P reflog show --format=%h HEAD; git commit -m x'), 'UNKNOWN');
    assert.equal(run('git -c branch.sort=signature:grade -P branch --list; git commit -m x'), 'UNKNOWN');
    // Explicit non-display inline keys retain the existing earlier UNKNOWN boundary.
    assert.equal(run('git -c branch.sort=signature:grade -P branch --list --no-sort --sort=refname; git commit -m x'), 'UNKNOWN');
    assert.equal(run('git -c branch.sort=signature:grade -c gpg.program=/DUMMY/unused -P branch --list --no-sort --sort=refname; git commit -m x'), 'UNKNOWN');
    assert.equal(run('git -c gpg.program=/DUMMY/unused -c branch.sort=signature:grade -P branch --list --no-sort --sort=refname; git commit -m x'), 'UNKNOWN');
    assert.equal(run('git --config-env=branch.sort=DUMMY_UNRESOLVED -P branch --list --no-sort --sort=refname; git commit -m x'), 'UNKNOWN');
    assert.equal(run('git -c branch.sort=refname commit -m x'), 'UNKNOWN');
    assert.equal(run('git -c branch.sort=refname add a.txt; git commit -m x'), 'UNKNOWN');
    git('config', '--add', 'branch.sort', 'signature:grade');
    git('config', '--add', 'branch.sort', 'refname');
    assert.equal(run('git -P branch --list; git commit -m x'), 'UNKNOWN');
    assert.equal(run('git -P branch --list --sort=refname; git commit -m x'), 'UNKNOWN');
    assert.equal(run('git -P branch --list --no-sort --sort=refname; git commit -m x'), 'ALLOW');
    assert.equal(run('git -P branch --list --no-sort --sort=refname; git commit -m x', 'block-secret-egress.cjs'), 'ALLOW');
    assert.equal(run('git -P branch --show-current; git commit -m x'), 'ALLOW');
    git('config', '--unset-all', 'branch.sort');
    assert.equal(run('git -c hook.dummy.event=post-index-change -c hook.post-index-change.enabled=false -P status; git commit -m x'), 'UNKNOWN');
    assert.equal(run("git -P shortlog '--format=%G?' HEAD; git add .env; git commit -m x"), 'FORBIDDEN');
    // Only now install a traditional marker. Own inspection overrides hooksPath;
    // the selected reader checks presence without invoking or reading its body.
    fs.writeFileSync(path.join(repo, '.git/hooks/post-index-change'),
      '#!/bin/sh\nprintf DUMMY > ' + JSON.stringify(marker) + '\n', { mode: 0o700 });
    assert.equal(run('git -c hook.post-index-change.enabled=false -P status; git commit -m x'), 'UNKNOWN');
    assert.equal(fs.existsSync(marker), false);
    t.diagnostic(`owned fixture: ${actualHookCalls} actual secret-git Hook calls; no native verifier or callback`);
    t.diagnostic(`owned fixture: ${actualEgressCalls} actual egress Hook call for the same repository-configured sort reset DATA`);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
