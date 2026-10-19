'use strict';
// Production helper extraction only. No hook top-level or native client executes.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const hooks=process.argv[2]||path.join(__dirname,'..');
const source=fs.readFileSync(path.join(hooks,'block-secret-egress.cjs'),'utf8');
function extract(start,end){const a=source.indexOf(start);assert(a>=0,start);const b=source.indexOf(end,a);assert(b>a,end);return source.slice(a,b)}
const extracted=[extract('function knownInvocationContext(','\n/** Preserve a helper'),extract('function netcatAliasName(','\nfunction netcatAliasRole('),extract('function untrustedClientExecution(','\n/** A wrapper query')].join('\n');
const context={...require('./executable-role-fixture.cjs')};
vm.runInNewContext(extracted+'\nthis.fn=untrustedClientExecution;',context);
const unknown=name=>({name,nameWord:{text:'./DUMMY'},unknownContextBefore:true});
const rows=[
 ['null-default',unknown(null),[],false],
 ['undefined-name-default',unknown(undefined),[],false],
 ['empty-identity',unknown(''),[''],false],
 ['numeric-index-zero',unknown(0),[0],false],
 ['numeric-index-two',unknown(2),[2],false],
 ['null-array-callback-index',unknown(null),[0],false],
 ['null-undefined-argument',unknown(null),[undefined],false],
 ['explicit-client',unknown('dig'),['dig'],true],
 ['different-client',unknown('dig'),['host'],false],
 ['canonical-client',unknown('curl'),[null],true],
 ['alias-client',unknown('nc.openbsd'),[null],true],
 ['ordinary-nonclient',unknown('printf'),[null],false],
 ['array-is-not-identity',unknown(null),[['dig']],false],
 ['explicit-client-known-context',{name:'dig',nameWord:{text:'dig'}},['dig'],false],
 ['explicit-client-unknown-path',{name:'dig',nameWord:{text:'dig'},pathChangedBefore:true},['dig'],true],
 ['explicit-client-trusted-absolute',{name:'dig',nameWord:{text:'/usr/bin/dig'},pathChangedBefore:true},['dig'],false]
];
for(const [id,invocation,args,expected]of rows)assert.equal(context.fn(invocation,...args),expected,id);
// JavaScript Array#some supplies a numeric second argument. An explicit lambda
// instead uses the helper's default; neither admits a null parser name.
assert.equal([unknown(null)].some(context.fn),false,'direct Array#some callback');
assert.equal([unknown(null)].some(invocation=>context.fn(invocation)),false,'explicit Array#some lambda');
process.stdout.write(JSON.stringify({tests:rows.length+2,pass:rows.length+2,fail:0,sourceHelperExtracted:true,HookCalls:0,nativeClientCalls:0})+'\n');
