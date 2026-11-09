'use strict';

// Commands are Hook stdin DATA. The selected gh installation is a filesystem
// model; native children and network clients are forbidden in the Hook process.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const hooks = path.resolve(process.env.CX1107_HOOKS || path.join(__dirname, '..'));
const baseline = process.env.CX1107_BASELINE === '1';
const inverse = process.env.CX1107_INVERSE === '1';
const EG = 'block-secret-egress.cjs';
const gh = command => 'GH_HOST=github.com gh ' + command;

const type1 = [
  ['pr-list', gh('pr list --repo o/r')],
  ['pr-view', gh('pr view 1 --repo o/r')],
  ['pr-diff', gh('pr diff 1 --repo o/r')],
  ['pr-checks', gh('pr checks 1 --repo o/r')],
  ['pr-status', gh('pr status --repo o/r')],
  ['issue-list', gh('issue list --repo o/r')],
  ['issue-view', gh('issue view 1 --repo o/r')],
  ['issue-status', gh('issue status --repo o/r')],
  ['run-list', gh('run list --repo o/r')],
  ['run-view', gh('run view 1 --repo o/r')],
  ['run-watch', gh('run watch 1 --repo o/r')],
  ['repo-list', gh('repo list o')],
  ['repo-view', gh('repo view o/r')],
  ['api-default-get', 'gh api --hostname github.com repos/o/r'],
  ['api-explicit-get', 'gh api --hostname github.com --method GET /repos/o/r'],
  ['pr-list-options', gh('pr list -R o/r --app ordinary --assignee ordinary --author ordinary --base main --head topic --jq . --json number --label ordinary --limit 2 --search ordinary --state open --template ordinary --draft')],
  ['pr-view-options', gh('pr view 1 -Ro/r --jq . --json number --template ordinary --comments')],
  ['pr-diff-options', gh('pr diff 1 --repo=o/r --color never --exclude ordinary --name-only --patch')],
  ['pr-checks-options', gh('pr checks 1 -Ro/r --interval 2 --jq . --json name --template ordinary --fail-fast --required --watch')],
  ['pr-status-options', gh('pr status -R o/r --jq . --json number --template ordinary --conflict-status')],
  ['issue-list-options', gh('issue list -R o/r --app ordinary --assignee ordinary --author ordinary --jq . --json number --label ordinary --limit 2 --mention ordinary --milestone ordinary --search ordinary --state open --template ordinary --type ordinary')],
  ['issue-view-options', gh('issue view 1 -R o/r --jq . --json number --template ordinary --comments')],
  ['issue-status-options', gh('issue status -R o/r --jq . --json number --template ordinary')],
  ['run-list-options', gh('run list -R o/r --branch main --commit ordinary --created ordinary --event push --jq . --json name --limit 2 --status completed --template ordinary --user ordinary --workflow ordinary --all')],
  ['run-view-options', gh('run view 1 -R o/r --attempt 1 --job 2 --jq . --json name --template ordinary --exit-status --log --log-failed --verbose')],
  ['run-watch-options', gh('run watch 1 -R o/r --interval 2 --compact --exit-status')],
  ['repo-list-options', gh('repo list o --jq . --json name --language ordinary --limit 2 --template ordinary --topic ordinary --visibility public --archived --fork --no-archived --source')],
  ['repo-view-options', gh('repo view github.com/o/r --branch main --jq . --json name --template ordinary')],
  ['api-output-options', 'gh api --hostname=github.com -XGET --jq . --template ordinary --include --silent repos/o/r'],
  ['pr-list-alias', gh('-R o/r pr ls')],
  ['issue-list-alias', gh('issue ls -R o/r')],
  ['run-list-alias', gh('run ls -R o/r')],
  ['repo-list-alias', gh('repo ls o')],
  ['quoted-command', "GH_HOST=github.com g''h pr view 1 --repo 'o/r'"],
  ['public-fallback-token', gh('pr list -R o/r'), { GH_TOKEN: undefined, GITHUB_TOKEN: 'DUMMY_SYNTHETIC_AUTH' }],
];

const type2 = [
  ['pr-write', gh('pr close 1 -R o/r')],
  ['issue-write', gh('issue close 1 -R o/r')],
  ['run-write', gh('run cancel 1 -R o/r')],
  ['repo-write', gh('repo edit o/r --description ordinary')],
  ['auth-output', gh('auth status --show-token')],
  ['execution-entry', gh('extension install o/r')],
  ['api-post', 'gh api --hostname github.com --method POST repos/o/r'],
  ['api-delete', 'gh api --hostname github.com -X DELETE repos/o/r'],
  ['api-field', 'gh api --hostname github.com --field ordinary=value repos/o/r'],
  ['api-raw-field', 'gh api --hostname github.com --raw-field ordinary=value repos/o/r'],
  ['api-get-field', 'gh api --hostname github.com -X GET --field ordinary=value repos/o/r'],
  ['api-input', 'gh api --hostname github.com --input ordinary.json repos/o/r'],
  ['api-header', 'gh api --hostname github.com --header Host:outside.invalid repos/o/r'],
  ['api-host', 'gh api --hostname outside.invalid repos/o/r'],
  ['api-url', 'gh api --hostname github.com https://outside.invalid/repos/o/r'],
  ['repo-host', gh('pr list -R outside.invalid/o/r')],
  ['positional-host', gh('pr view https://outside.invalid/o/r/pull/1 -R o/r')],
  ['unknown-operation', gh('pr ordinary -R o/r')],
  ['unknown-option', gh('pr list -R o/r --ordinary')],
  ['browser', gh('pr view 1 -R o/r --web')],
  ['helper', 'GH_PAGER=DUMMY GH_HOST=github.com gh pr list -R o/r'],
  ['config-root', 'GH_CONFIG_DIR=DUMMY GH_HOST=github.com gh pr list -R o/r'],
  ['source', 'GH_TOKEN="$(cat .e\'\'nv)" GH_HOST=github.com gh pr list -R o/r'],
  ['multiple-commands', 'export GH_TOKEN; GH_HOST=github.com gh pr list -R o/r'],
  ['wrapper', 'GH_HOST=github.com command gh pr list -R o/r'],
  ['redirection', 'GH_HOST=github.com gh pr list -R o/r > ordinary-output'],
  ['missing-repository', gh('pr list')],
  ['unqualified-host', 'gh pr list -R o/r'],
  ['api-missing-host', 'gh api repos/o/r'],
  ['api-pagination', 'gh api --hostname github.com --paginate repos/o/r'],
  ['selector-kind', gh('pr view topic -R o/r')],
];

function observe(result) {
  if (result.error || result.status !== 0 || result.signal || result.stderr !== '') return 'BROKEN';
  if (result.stdout === '') return 'ALLOW';
  try {
    const wire = JSON.parse(result.stdout)?.hookSpecificOutput;
    return wire?.permissionDecision === 'deny' && typeof wire.permissionDecisionReason === 'string' ? 'DENY' : 'BROKEN';
  } catch { return 'BROKEN'; }
}

test('CX-1107-1 qualified read authentication allowlist', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'cx1107-read-'));
  const home = path.join(root, 'home'), cwd = path.join(root, 'cwd'), marker = path.join(root, 'native-attempt');
  fs.mkdirSync(home); fs.mkdirSync(cwd);
  const preload = path.join(root, 'model.cjs');
  fs.writeFileSync(preload, `
'use strict';
const fs=require('node:fs'),cp=require('node:child_process'),path=require('node:path');
const selected=f=>typeof f==='string'&&path.basename(f)==='gh'&&['/usr/bin','/bin','/usr/local/bin','/opt/homebrew/bin'].includes(path.dirname(f));
const missing=()=>{throw Object.assign(Error('modeled absent installation'),{code:'ENOENT'});};
const stat=fs.statSync,access=fs.accessSync,real=fs.realpathSync,native=fs.realpathSync.native;
fs.statSync=function(f,...a){if(selected(f))return f==='/usr/bin/gh'?{isFile:()=>true,isDirectory:()=>false}:missing();return stat.call(this,f,...a);};
fs.accessSync=function(f,...a){if(selected(f))return f==='/usr/bin/gh'?undefined:missing();return access.call(this,f,...a);};
fs.realpathSync=function(f,...a){if(selected(f))return f==='/usr/bin/gh'?f:missing();return real.call(this,f,...a);};
fs.realpathSync.native=function(f,...a){if(selected(f))return f==='/usr/bin/gh'?f:missing();return native.call(this,f,...a);};
const stop=()=>{fs.appendFileSync(${JSON.stringify(marker)},'attempt\\n');throw Error('native child/network forbidden');};
for(const name of ['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork'])cp[name]=stop;
for(const name of ['node:http','node:https']){const m=require(name);m.request=stop;m.get=stop;}
const net=require('node:net');net.connect=stop;net.createConnection=stop;global.fetch=stop;
`);
  const environment = { PATH: '/usr/bin:/bin', HOME: home, TMPDIR: root, LC_ALL: 'C', CLAUDE_PROJECT_DIR: cwd,
    GH_TOKEN: 'DUMMY_SYNTHETIC_AUTH', GH_ENTERPRISE_TOKEN: 'DUMMY_SYNTHETIC_AUTH', GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: os.devNull, GIT_CONFIG_SYSTEM: os.devNull, GIT_TERMINAL_PROMPT: '0' };
  const run = (directory, fixture) => {
    const env = { ...environment, ...fixture[2] };
    for (const key of Object.keys(env)) if (env[key] === undefined) delete env[key];
    return observe(spawnSync(process.execPath, ['--require', preload, path.join(directory, EG)], {
      cwd, env, input: JSON.stringify({ tool_name: 'Bash', tool_input: { command: fixture[1] }, cwd }),
      encoding: 'utf8', timeout: 15000, maxBuffer: 1024 * 1024,
    }));
  };
  try {
    for (const fixture of type1) await t.test('type1-' + fixture[0], () => assert.equal(run(hooks, fixture), baseline ? 'DENY' : 'ALLOW'));
    for (const fixture of type2) await t.test('type2-' + fixture[0], () => assert.equal(run(hooks, fixture), 'DENY'));
    if (inverse && !baseline) {
      const source = fs.readFileSync(path.join(hooks, EG), 'utf8');
      const disabled = source.replace('const entry = GH_READ_AUTH_ALLOWLIST.get(role.operation);', 'const entry = undefined;');
      assert.notEqual(disabled, source);
      const mutant = path.join(root, 'without-read-permission');
      fs.mkdirSync(mutant); fs.cpSync(path.join(hooks, 'lib'), path.join(mutant, 'lib'), { recursive: true });
      fs.writeFileSync(path.join(mutant, EG), disabled);
      for (const fixture of type1) await t.test('inverse-' + fixture[0], () => {
        const verdict = run(mutant, fixture);
        assert.equal(verdict, 'DENY');
        assert.throws(() => assert.equal(verdict, 'ALLOW'), assert.AssertionError);
      });
      const checks = [
        ['operation-membership', "  ['pr list',", "  ['pr close', ['repo', '', 'number']],\n  ['pr list',", 'pr-write'],
        ['value-option-membership', '!values.has(value.option)', 'false', 'api-get-field'],
        ['flag-membership', '[...role.flags.keys()].some(name => !flags.has(name))', 'false', 'api-pagination'],
        ['get-method', "methods.some(method => method !== 'GET')", 'false', 'api-post'],
        ['repository-selection', "['pr', 'issue', 'run'].includes(role.operation.split(' ')[0]) && repositories.length !== 1", 'false', 'missing-repository'],
        ['numeric-selector', "operands.length === 1 && /^[1-9][0-9]*$/.test(operands[0].text)", 'operands.length === 1', 'selector-kind'],
      ];
      const sourceStart = source.indexOf('  // Qualify a single root command');
      const sourceEnd = source.indexOf('  const [valueNames, flagNames, operandKind] = entry;', sourceStart);
      assert.ok(sourceStart > 0 && sourceEnd > sourceStart);
      checks.push(['source-qualification', source.slice(sourceStart, sourceEnd), '', 'multiple-commands']);
      for (const [name, before, after, id] of checks) await t.test('inverse-guard-' + name, () => {
        assert.equal(source.split(before).length, 2, 'mutation anchor is unique');
        const directory = path.join(root, name);
        fs.mkdirSync(directory); fs.cpSync(path.join(hooks, 'lib'), path.join(directory, 'lib'), { recursive: true });
        fs.writeFileSync(path.join(directory, EG), source.replace(before, after));
        const fixture = type2.find(entry => entry[0] === id);
        assert.ok(fixture);
        const verdict = run(directory, fixture);
        assert.equal(verdict, 'ALLOW', 'removing this guard must contradict the type2 denial');
        assert.throws(() => assert.equal(verdict, 'DENY'), assert.AssertionError);
      });
    }
    assert.equal(fs.existsSync(marker), false, 'the Hook must not execute a native child or network client');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
