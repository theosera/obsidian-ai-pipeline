'use strict';
// L1/mock-only qualification of the getter copy. These strings are DATA; no
// native Git operation, shell witness, helper or network action is executed.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const hooks=path.resolve(process.argv[2]||path.join(__dirname,'..'));
const guard=require(path.join(hooks,'lib/git-guard-common.cjs'));
const readers=require(path.join(hooks,'lib/git-precommit-readers.cjs'));
const root=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'r61-transport-projection-')));
const env={PATH:process.env.PATH,HOME:root,XDG_CONFIG_HOME:root,GIT_CONFIG_NOSYSTEM:'1',GIT_TERMINAL_PROMPT:'0'};
test.after(()=>fs.rmSync(root,{recursive:true,force:true}));
const parsed=command=>guard.inspect(command,{trackExecutableSearch:true,trackGitPreCommitEnvironment:true,initialGitPreCommitEnvironmentSources:readers.environmentSources(env)});
const pair=command=>{const p=parsed(command),g=p.gits.find(g=>g.sub==='push');assert(g);const invocation=p.invocations.find(i=>i.name==='git');assert(invocation);return {p,g,invocation};};
const context=command=>{const {g,invocation}=pair(command);return readers.transportInspectionContext(g,invocation,root,{environment:env});};
const client=command=>guard.gitTransportClientRole(parsed(command).gits[0]);
const encode=records=>records.map(([key,value])=>'local\0'+key+'\n'+value+'\0').join('');

test('shared push parser preserves optional, negated, abbreviated and consumed option roles',()=>{
 for(const command of ['git push --force-with-lease=main:HEAD origin HEAD:main','git push --no-verbose origin HEAD:main','git push --no-verb origin HEAD:main','git push --push-opt "--no-veri" origin','OPT=--no-verbose; git push origin "$OPT"']){
  const role=client(command);assert.equal(role.argvUnknown,false,command);assert.equal(role.repositoryWord.text,'origin');
 }
 const p=guard.gitPushRepository(parsed('git push --push-opt "--no-veri" origin').gits[0].args);
 assert.equal(p.payloadWords[0].text,'--no-veri');assert.equal(p.repository.text,'origin');
 assert.match(fs.readFileSync(path.join(hooks,'block-secret-egress.cjs'),'utf8'),/const pushRepository = guard\.gitPushRepository;/);
});
test('fixed refspec prefixes are DATA; generated first bytes and unknown arity remain unknown',()=>{
 for(const command of ['REF=ordinary; git push origin "HEAD:refs/heads/$REF"','git push origin "HEAD:refs/heads/$(printf ordinary)"','SUFFIX=ordinary; git push origin "main$SUFFIX"'])assert.equal(client(command).argvUnknown,false,command);
 assert.equal(client('git push origin "$(cat DUMMY):refs/heads/ordinary"').argvUnknown,true);
 assert.equal(client('git push origin -- "$(cat DUMMY):refs/heads/ordinary"').argvUnknown,false);
 assert.equal(client('git push --unknown-selector DUMMY origin main').argvUnknown,true);
 assert.equal(client('git push -o $DYNAMIC origin main').argvUnknown,true);
});
test('pull actual stdout usage is distinct from a consumed help value',()=>{
 assert.equal(client('git pull --no-edit --help'),null);
 assert.notEqual(client('git pull --upload-pack --help origin'),null);
 assert.notEqual(client('git pull --unknown --help'),null);
});
test('finite key classification retains every selector and unknown key',()=>{
 for(const key of ['color.ui','http.extraHeader','http.https://DUMMY.invalid/repo.userAgent','push.pushOption'])assert.equal(readers.transportInspectionDataKey(key),'omit');
 assert.equal(readers.transportInspectionDataKey('remote.DUMMY.push'),'remote-name');
 for(const key of ['include.path','includeIf.gitdir:DUMMY.path','core.sshCommand','core.gitProxy','credential.helper','core.askpass','remote.DUMMY.url','remote.DUMMY.pushurl','remote.DUMMY.vcs','remote.DUMMY.receivepack','branch.main.remote','url.ssh://DUMMY/.insteadOf','unrecognized.key','trace2.eventTarget'])assert.equal(readers.transportInspectionDataKey(key),null,key);
});
test('inline projection omits DATA only and preserves exact selector order and original words',()=>{
 const {g,invocation}=pair('git -c http.extraHeader="$(cat DUMMY)" -c color.ui=never -c core.sshCommand=DUMMY-A -c core.sshCommand=DUMMY-B push origin main');
 const before=JSON.stringify({g,invocation});const c=readers.transportInspectionContext(g,invocation,root,{environment:env});assert(c);
 assert.deepEqual(c.globals,['-c','core.sshCommand=DUMMY-A','-c','core.sshCommand=DUMMY-B']);
 assert.equal(JSON.stringify({g,invocation}),before);assert.equal(c.inspectionProjection.length,2);
});
test('numbered projection compacts retained selectors in order and ignores count-zero orphan values',()=>{
 const c=context('GIT_CONFIG_COUNT=3 GIT_CONFIG_KEY_0=http.extraHeader GIT_CONFIG_VALUE_0="$(cat DUMMY)" GIT_CONFIG_KEY_1=core.sshCommand GIT_CONFIG_VALUE_1=DUMMY-A GIT_CONFIG_KEY_2=core.sshCommand GIT_CONFIG_VALUE_2=DUMMY-B git push origin main');assert(c);
 assert.equal(c.env.GIT_CONFIG_COUNT,'2');assert.equal(c.env.GIT_CONFIG_KEY_0,'core.sshCommand');assert.equal(c.env.GIT_CONFIG_VALUE_0,'DUMMY-A');assert.equal(c.env.GIT_CONFIG_VALUE_1,'DUMMY-B');assert.equal(c.env.GIT_CONFIG_KEY_2,undefined);
 const zero=context('GIT_CONFIG_COUNT=0 GIT_CONFIG_KEY_0=core.sshCommand GIT_CONFIG_VALUE_0="$(cat DUMMY)" git push origin main');assert(zero);assert.equal(zero.env.GIT_CONFIG_COUNT,'0');assert.equal(zero.env.GIT_CONFIG_KEY_0,undefined);
 assert.equal(context('GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.sshCommand GIT_CONFIG_VALUE_0="$(cat DUMMY)" git push origin main'),null);
 assert.equal(context('GIT_CONFIG_COUNT=$COUNT git push origin main'),null);
});
test('UA elision does not erase a retained helper config-env dependency',()=>{
 const c=context('GIT_HTTP_USER_AGENT=DUMMY-helper git --config-env=core.sshCommand=GIT_HTTP_USER_AGENT push origin main');assert(c);
 assert.equal(c.env.GIT_HTTP_USER_AGENT,undefined);assert.equal(c.selected.get('GIT_HTTP_USER_AGENT'),'DUMMY-helper');assert.deepEqual(c.globals,['-c','core.sshCommand=DUMMY-helper']);
 assert.equal(context('GIT_HTTP_USER_AGENT="$(cat DUMMY)" git --config-env=core.sshCommand=GIT_HTTP_USER_AGENT push origin main'),null);
 assert(context('GIT_HTTP_USER_AGENT="$(cat DUMMY)" git --config-env=color.ui=GIT_HTTP_USER_AGENT push origin main'));
});
test('projected refspec values preserve remote name presence, not payload proofs',()=>{
 const c=context('git --config-env=remote.DUMMY.push=REFS push');assert(c);
 assert.deepEqual(c.globals,['-c','remote.DUMMY.push=refs/heads/DUMMY:refs/heads/DUMMY']);
 assert.deepEqual(c.inspectionProjection,[{source:'config-env',key:'remote.DUMMY.push',action:'preserve-remote-name-only'}]);
 const n=context('GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=remote.DUMMY.push GIT_CONFIG_VALUE_0="$(cat DUMMY)" git push');assert(n);assert.equal(n.env.GIT_CONFIG_KEY_0,'remote.DUMMY.push');assert.equal(n.env.GIT_CONFIG_COUNT,'1');
 assert.equal(n.selected.get('GIT_CONFIG_VALUE_0'),undefined);
});
test('opaque selector, include, root and loader uncertainty are never projected away',()=>{
 for(const command of ['git -c core.sshCommand="$(cat DUMMY)" push origin main','git -c include.path="$(cat DUMMY)" push origin main','git -c unknown.key="$(cat DUMMY)" push origin main','HOME="$(cat DUMMY)" git push origin main',(process.platform==='darwin'?'DYLD_INSERT_LIBRARIES':'LD_PRELOAD')+'=DUMMY git push origin main','GIT_TRACE=DUMMY git push origin main']){
  const p=parsed(command),g=p.gits.find(g=>g.sub==='push');
  if(!g){assert(p.problems.length>0,command+' must retain a prior parser refusal');continue;}
  const invocation=p.invocations.find(i=>i.name==='git');assert(invocation);
  assert.equal(readers.transportInspectionContext(g,invocation,root,{environment:env}),null,command);
 }
});
test('mock getter sees exact selectors/remote names and cache equivalence only after projection',()=>{
 const calls=[];const spawn=(_exe,args,options)=>{calls.push({args:[...args],env:{...options.env}});if(args.at(-1)==='--version')return {status:0,stdout:Buffer.from('git version 2.54.0\n')};return {status:1,stdout:Buffer.alloc(0)};};
 const inspect=readers.createTransportInspector({environment:env,spawn,now:()=>0});
 for(const value of ['DUMMY-A','DUMMY-B']){const {g,invocation}=pair('git -c http.userAgent='+value+' push origin main');assert.equal(inspect(g,invocation,root),null);}
 assert.equal(calls.length,2);assert.equal(calls.some(c=>c.args.some(a=>a.includes('http.userAgent'))),false);
 const retained=pair('git -c remote.DUMMY.push=main -c core.sshCommand=DUMMY-helper push origin main');
 const ctx=readers.transportInspectionContext(retained.g,retained.invocation,root,{environment:env});assert(ctx);assert(ctx.globals.includes('remote.DUMMY.push=refs/heads/DUMMY:refs/heads/DUMMY'));assert(ctx.globals.includes('core.sshCommand=DUMMY-helper'));
 const fresh=pair('git -c color.ui=never --git-dir='+root+'/different push origin main');assert.equal(inspect(fresh.g,fresh.invocation,root),null);assert.equal(calls.length,4);
});
test('configured helper remains UNKNOWN beside projected numbered DATA',()=>{
 const {g,invocation}=pair('GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=color.ui GIT_CONFIG_VALUE_0="$(cat DUMMY)" git push origin main');
 const inspect=readers.createTransportInspector({environment:env,now:()=>0,spawn(_exe,args){
  if(args.at(-1)==='--version')return {status:0,stdout:Buffer.from('git version 2.54.0\n')};
  if(args.includes('config'))return {status:0,stdout:Buffer.from(encode([['core.sshcommand','DUMMY-helper'],['remote.origin.url','ssh://DUMMY.invalid/repo']]))};
  assert(args.includes('get-url'));return {status:0,stdout:Buffer.from('ssh://DUMMY.invalid/repo\n')};
 }});
 assert.equal(inspect(g,invocation,root)?.category,'UNKNOWN');
});
