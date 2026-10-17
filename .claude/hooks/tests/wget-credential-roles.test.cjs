'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const hooks=path.resolve(process.argv[2]||path.join(__dirname,'..'));
const guard=require(path.join(hooks,'lib/git-guard-common.cjs'));
const source=fs.readFileSync(path.join(hooks,'block-secret-egress.cjs'),'utf8');
function slice(start,end){const a=source.indexOf(start),z=source.indexOf(end,a);assert.ok(a>=0&&z>a);assert.equal(source.indexOf(start,a+start.length),-1);return source.slice(a,z);}
// Extract production functions only; the Hook entrypoint is never executed here.
const code=slice('function knownWord(word)',"/** Bash's first help/version")+
 slice('function quotedAttachedOptionValue(word, text, shortValues, longValues = [])','function arrayReaderCallback(invocation)')+
 slice('// Wget 1.25.0 --help:','/** Extract copy operands');
const api=vm.runInNewContext(code+'\n;({role:wgetSelectedCredentialRole,verdict:wgetSelectedCredentialVerdict,payload:wgetPayloadRole})',{guard,URL},{timeout:1000});
const W="env -i /usr/bin/w''get --no-config --no-netrc";
function inspect(cmd){const data=guard.inspect(cmd,{trackOutboundEnvironment:true});assert.deepEqual(data.problems,[]);const inv=data.invocations.find(x=>x.name==='wget');assert.ok(inv);return {role:api.role(inv),payload:api.payload(inv)};}
function r(t){return inspect(W+' '+t).role;}
test('selected cert and key are separate file-role fallbacks with unknown backend',()=>{
 for(const option of ['--certificate','--private-key']){const x=r(option+" .e''nv https://target.invalid");assert.equal(x.active,true);assert.equal(x.backendSourceProven,false);assert.equal(x.verdict,'UNKNOWN');assert.equal(x.selected.length,1);}
});
test('last empty names retain byte semantics without clearing an independent selector',()=>{
 assert.equal(r("--certificate .e''nv --certificate '' https://target.invalid").active,false);
 assert.equal(r("--private-key .e''nv --private-key '' https://target.invalid").active,false);
 assert.equal(r("--certificate '' --private-key ordinary.txt https://target.invalid").active,true);
 assert.equal(r("--private-key '' --certificate ordinary.txt https://target.invalid").active,true);
});
test('format only is DATA and final proven invalid format is pre-retrieval',()=>{
 assert.equal(r('--certificate-type PEM --private-key-type DER https://target.invalid').active,false);
 assert.equal(r("--certificate .e''nv --certificate-type ENG https://target.invalid").invalidFinalTypeBeforeRetrieval,true);
 for(const type of ['PEM','der','ASN1'])assert.equal(r('--certificate ordinary.txt --certificate-type '+type+' https://target.invalid').active,true);
});
test('redirect reachability is separate from linked retrieval',()=>{
 assert.equal(r('--certificate ordinary.txt http://target.invalid').active,true);
 assert.equal(r('--certificate ordinary.txt --max-redirect 0 http://target.invalid').active,true);
 assert.equal(r('--certificate ordinary.txt --no-hsts --max-redirect 0 http://target.invalid').active,false);
 assert.equal(r('--certificate ordinary.txt --no-hsts --max-redirect 0 http://target.invalid').hsts,false);
 for(const option of ['-r','-m','-p','--recursive','--mirror','--page-requisites']){const x=r('--certificate ordinary.txt --max-redirect 0 '+option+' http://target.invalid');assert.equal(x.linkedRetrieval,true);assert.equal(x.active,true);}
});
test('query, no retrieval and explicit empty input remain inactive',()=>{
 for(const tail of ['--help','--version','','-i /dev/null'])assert.equal(r('--certificate ordinary.txt '+tail).active,false);
});
test('credential operands preserve parser roles and option-looking DATA',()=>{
 assert.equal(r("--user-agent=--certificate=.e''nv https://target.invalid").active,false);
 assert.equal(r('-- --certificate=ordinary.txt').active,false);
 const x=r('--certificate=first.txt --certificate final.txt https://target.invalid');assert.equal(x.values.get('certificate').text,'final.txt');
});
test('CA and peer pins are distinct verification source roles',()=>{
 for(const option of ['--ca-certificate','--ca-directory','--pinnedpubkey','--crl-file'])assert.equal(r(option+" .e''nv https://target.invalid").active,false);
});
test('FTPS is TLS while direct unproxied FTP is inactive',()=>{
 assert.equal(r('--private-key ordinary.txt ftps://target.invalid/DUMMY').active,true);
 assert.equal(r('--no-proxy --private-key ordinary.txt ftp://target.invalid/DUMMY').active,false);
});

test('unproven one-word option identity cannot prove invalid format is a CLI option',()=>{
 for(const name of ['certificate-type','private-key-type']){const x=inspect(W+' --certificate ordinary.txt "$OPT" --'+name+' ENG https://target.invalid');assert.equal(x.payload.unknown,false);assert.equal(x.payload.unknownOptionArity,true);assert.equal(x.role.active,true);assert.equal(x.role.verdict,'UNKNOWN');}
 assert.equal(r('--certificate ordinary.txt --certificate-type ENG https://target.invalid').active,false);
});

test('all inactive-source exemptions require the same proved argv boundary',()=>{
 for(const tail of ['--certificate ordinary.txt "$OPT" --help https://target.invalid', "--certificate ordinary.txt \"$OPT\" --certificate '' https://target.invalid", '--certificate ordinary.txt "$OPT" --post-data ordinary --method HEAD https://target.invalid']){const x=inspect(W+' '+tail);assert.equal(x.role.argvKnown,false);assert.equal(x.role.active,true);assert.equal(x.role.verdict,'UNKNOWN');}
 for(const tail of ['--certificate ordinary.txt --help https://target.invalid', "--certificate ordinary.txt --certificate '' https://target.invalid", '--certificate ordinary.txt --post-data ordinary --method HEAD https://target.invalid']){const x=inspect(W+' '+tail);assert.equal(x.role.argvKnown,true);assert.equal(x.role.active,false);}
});
