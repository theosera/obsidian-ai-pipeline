'use strict';
// Commands are Hook JSON DATA only. Fixed native Git calls configure/read an
// owned fixture; there is no push/fetch/helper/shell/network witness execution.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {spawnSync} = require('node:child_process');
const hooks = path.resolve(process.argv[2] || path.join(__dirname, '..'));
const guard = require(path.join(hooks, 'lib/git-guard-common.cjs'));
const readers = require(path.join(hooks, 'lib/git-precommit-readers.cjs'));
const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'r61-effective-transport-')));
const git = guard.resolveTrustedGitExecutable({text:'git'});
assert(git, 'owned getter fixture requires trusted installed Git');
for (const name of ['repo','home','xdg','tmp']) fs.mkdirSync(path.join(root,name));
const cwd = path.join(root,'repo'), global = path.join(root,'global'), system = path.join(root,'system');
fs.writeFileSync(global,''); fs.writeFileSync(system,'');
const env = {PATH:process.env.PATH, HOME:path.join(root,'home'),XDG_CONFIG_HOME:path.join(root,'xdg'),TMPDIR:path.join(root,'tmp'),LANG:'C',LC_ALL:'C',GIT_CONFIG_GLOBAL:global,GIT_CONFIG_SYSTEM:system,GIT_CONFIG_NOSYSTEM:'1',GIT_TERMINAL_PROMPT:'0'};
const native = (args, directory=cwd, environment=env) => {
  assert(['init','config','--version'].includes(args[0]));
  const r=spawnSync(git,args,{cwd:directory,env:environment,encoding:'utf8',shell:false,timeout:5000,maxBuffer:65536});
  assert.equal(r.status,0); assert.equal(r.error,undefined); return r.stdout;
};
native(['init','-q','--initial-branch=main']);
native(['config','remote.origin.url','ssh://git@receiver.invalid/DUMMY.git']);
const config=path.join(cwd,'.git/config'), clean=fs.readFileSync(config);
const helper=path.join(root,'DUMMY-NONEXECUTABLE-HELPER');fs.writeFileSync(helper,'DUMMY_NO_SHEBANG\n',{mode:0o400});
assert.equal(fs.statSync(helper).mode&0o111,0);
const reset=()=>{fs.writeFileSync(config,clean);fs.writeFileSync(global,'');};
const set=(key,value,extra=[])=>native(['config',...extra,key,value]);
function hook(command, expected, extraEnv={}, directory=cwd) {
  const r=spawnSync(process.execPath,[path.join(hooks,'block-secret-egress.cjs')],{
    cwd:directory,env:{...env,...extraEnv,CLAUDE_PROJECT_DIR:directory},encoding:'utf8',shell:false,timeout:12000,maxBuffer:65536,
    input:JSON.stringify({hook_event_name:'PreToolUse',tool_name:'Bash',tool_input:{command},cwd:directory}),
  });
  assert.equal(r.error,undefined);assert.equal(r.status,0,r.stderr);
  const output=r.stdout?JSON.parse(r.stdout):null;
  const denied=output?.hookSpecificOutput?.permissionDecision==='deny';
  assert.equal(denied,expected==='UNKNOWN',command+' => '+(output?.hookSpecificOutput?.permissionDecisionReason||'ALLOW'));
  if(denied) assert.match(output.hookSpecificOutput.permissionDecisionReason,/^\[判断不能\] /);
}
test.after(()=>fs.rmSync(root,{recursive:true,force:true}));
test('exact push DATA selects repository SSH helper; controls stay ALLOW',()=>{
  reset();set('core.sshCommand',helper);hook('git push origin main','UNKNOWN');
  hook('git config --get core.sshCommand','ALLOW');hook('git status --short','ALLOW');hook("printf '%s' 'git push origin main'",'ALLOW');
  reset();hook('git push origin main','ALLOW');
});
test('global and included config are effective, explicit harmless settings preserve target',()=>{
  reset();native(['config','--file',global,'core.sshCommand',helper]);hook('git push origin main','UNKNOWN');
  reset();const include=path.join(root,'included');fs.writeFileSync(include,'[core]\n sshCommand = '+helper+'\n');set('include.path',include);hook('git push origin main','UNKNOWN');
  reset();set('core.sshCommand',helper);hook('git -c color.ui=never push origin main','UNKNOWN');
});
test('inactive protocol and branch/default destination selection retain ordinary work',()=>{
  reset();set('core.sshCommand',helper);set('remote.origin.url','https://receiver.invalid/DUMMY.git');hook('git push origin main','ALLOW');
  set('remote.secure.url','ssh://git@receiver.invalid/DUMMY.git');set('remote.pushDefault','secure');hook('git push','UNKNOWN');
  set('branch.main.pushRemote','origin');hook('git push','ALLOW');
});
test('push uses all pushURLs, fetch first URL; foreign helper precedes URL protocol',()=>{
  reset();set('core.sshCommand',helper);set('remote.origin.url','https://receiver.invalid/DUMMY.git');
  set('remote.origin.pushurl','https://receiver.invalid/one.git');set('remote.origin.pushurl','ssh://git@receiver.invalid/two.git',['--add']);hook('git push origin main','UNKNOWN');
  hook('git fetch origin','ALLOW');set('remote.origin.vcs','');hook('git fetch origin','UNKNOWN');
});
test('URL insteadOf/pushInsteadOf are selected before helper roles',()=>{
  reset();set('core.sshCommand',helper);set('remote.origin.url','https://receiver.invalid/DUMMY.git');
  set('url.ssh://git@receiver.invalid/.insteadOf','https://receiver.invalid/');hook('git push origin main','UNKNOWN');
  reset();set('core.sshCommand',helper);set('remote.origin.url','https://receiver.invalid/DUMMY.git');
  set('url.ssh://git@receiver.invalid/.pushInsteadOf','https://receiver.invalid/');hook('git push origin main','UNKNOWN');hook('git fetch origin','ALLOW');
});
test('first matching git proxy and empty env override preserve disable controls',()=>{
  reset();set('remote.origin.url','git://receiver.invalid/DUMMY.git');set('core.gitProxy','none for receiver.invalid');set('core.gitProxy',helper,['--add']);hook('git push origin main','ALLOW');
  reset();set('remote.origin.url','git://receiver.invalid/DUMMY.git');set('core.gitProxy',helper);hook('git push origin main','UNKNOWN');hook('git push origin main','ALLOW',{GIT_PROXY_COMMAND:''});
});
test('ordered export/unset and child source metadata do not rewrite primary outbound proofs',()=>{
  reset();set('core.sshCommand',helper);
  hook("bash -c 'git push origin main'",'UNKNOWN');hook('env -u GIT_SSH_COMMAND git push origin main','UNKNOWN',{GIT_SSH_COMMAND:'DUMMY'});
  reset();hook("bash -c 'git push origin main'",'UNKNOWN'); // prior parser source refusal, not a new transport denial
});
test('alternate cwd and GIT_DIR target the consumer repository',()=>{
  reset();set('core.sshCommand',helper);const other=path.join(root,'other');fs.mkdirSync(other);native(['init','-q','--initial-branch=main'],other);
  hook('git -C '+cwd+' push origin main','UNKNOWN',{},other);
  hook('git push origin main','UNKNOWN',{GIT_DIR:path.join(cwd,'.git')},other);
});
test('bounded inspector caches exact contexts and rejects exhausted query budget',()=>{
  const invocation=guard.inspect('git push origin main',{trackGitPreCommitEnvironment:true,initialGitPreCommitEnvironmentSources:readers.environmentSources(env)}).invocations[0];
  const g=guard.inspect('git push origin main').gits[0];let calls=0;
  const inspector=readers.createTransportInspector({environment:env,spawn(_file,args){calls++;if(args.at(-1)==='--version')return {status:0,stdout:Buffer.from('git version 2.54.0\n')};return {status:1,stdout:Buffer.alloc(0)};},now:()=>0});
  assert.equal(inspector(g,invocation,cwd),null);assert.equal(inspector(g,invocation,cwd),null);assert.equal(calls,2);
  for(let i=0;i<10;i++)inspector(g,invocation,cwd+'/'+i);
  assert(inspector.stats().queries<=12);
});

test('clone excludes caller-local helper but selects global helper and unknown template',()=>{
  reset();set('core.sshCommand',helper);hook('git clone ssh://git@receiver.invalid/DUMMY.git','ALLOW');
  native(['config','--file',global,'core.sshCommand',helper]);hook('git clone ssh://git@receiver.invalid/DUMMY.git','UNKNOWN');
  hook('git clone https://receiver.invalid/DUMMY.git','ALLOW');
  reset();hook('git clone https://receiver.invalid/DUMMY.git','UNKNOWN',{GIT_TEMPLATE_DIR:path.join(root,'template')});
});

test('worktree and conditional includes preserve the actual repository target',()=>{
  reset();set('extensions.worktreeConfig','true');const worktree=path.join(cwd,'.git/config.worktree');fs.writeFileSync(worktree,'[core]\n sshCommand = '+helper+'\n');hook('git push origin main','UNKNOWN');fs.unlinkSync(worktree);
  reset();const included=path.join(root,'conditioned');fs.writeFileSync(included,'[core]\n sshCommand = '+helper+'\n');set('includeIf.gitdir:'+path.join(cwd,'.git')+'.path',included);hook('git push origin main','UNKNOWN');
});
test('fetch all checks each configured route and custom URL helpers remain unknown',()=>{
  reset();set('core.sshCommand',helper);set('remote.origin.url','https://receiver.invalid/DUMMY.git');set('remote.other.url','ssh://git@receiver.invalid/DUMMY.git');hook('git fetch --all','UNKNOWN');set('remote.other.skipFetchAll','true');hook('git fetch --all','ALLOW');
  set('remote.other.url','https://receiver.invalid/other.git');hook('git fetch --all','ALLOW');
  reset();set('remote.origin.url','DUMMY::ordinary');hook('git fetch origin','UNKNOWN');
});
test('config-env proof and repeated same-context transport queries remain bounded',()=>{
  reset();hook('C=never git --config-env=color.ui=C push origin main','ALLOW');
  set('core.sshCommand',helper);set('remote.origin.url','https://receiver.invalid/DUMMY.git');
  hook(Array(8).fill('git push origin main').join('; '),'ALLOW');
});

test('effective credential and askpass sources are limited to authentication routes',()=>{
  reset();set('credential.helper','DUMMY-NONEXECUTED');set('remote.origin.url','https://receiver.invalid/DUMMY.git');hook('git fetch origin','UNKNOWN');
  set('credential.helper','',['--add']);hook('git fetch origin','ALLOW');
  set('core.askpass',helper);hook('git fetch origin','UNKNOWN');set('remote.origin.url',cwd);hook('git fetch origin','ALLOW');
  reset();set('credential.https://other.invalid.helper','DUMMY-NONEXECUTED');set('remote.origin.url','https://receiver.invalid/DUMMY.git');hook('git fetch origin','UNKNOWN'); // URL matching not qualified
});
test('remote pack program has a local executable role, not an SSH local program role',()=>{
  reset();set('remote.origin.receivepack',helper);set('remote.origin.url',cwd);hook('git push origin main','UNKNOWN');
  set('remote.origin.receivepack','git-receive-pack');hook('git push origin main','ALLOW');
  set('remote.origin.receivepack',helper);set('remote.origin.url','ssh://git@receiver.invalid/DUMMY.git');hook('git push origin main','ALLOW');
});

test('an explicitly selected copy controls reader dependency loading',()=>{
  const selected=path.join(root,'selected-source-copy');fs.cpSync(hooks,selected,{recursive:true});
  fs.writeFileSync(path.join(selected,'lib/git-precommit-readers.cjs'),"throw new Error('R61_SELECTED_COPY_SENTINEL');\n");
  const r=spawnSync(process.execPath,[__filename,selected],{env,encoding:'utf8',shell:false,timeout:5000,maxBuffer:65536});
  assert.notEqual(r.status,0);assert.match(r.stderr,/R61_SELECTED_COPY_SENTINEL/);
});

test('raw git authority preserves IPv6 and rejects unqualified normalization',()=>{
  reset();set('remote.origin.url','git://[2001:db8::1]/DUMMY.git');set('core.gitProxy','none');hook('git push origin main','ALLOW');
  assert.deepEqual(readers.transportRoute('git://[2001:db8::1]:0099/DUMMY.git'),{kind:'git',host:'[2001:db8::1]:0099'});
  assert.equal(readers.transportRoute('git://user@receiver.invalid/DUMMY.git'),null);
  set('remote.origin.url','GIT://receiver.invalid/DUMMY.git');hook('git push origin main','UNKNOWN');
});
