'use strict';

// Each mutation runs only a copied Hook against the existing synthetic focused
// corpus. The supplied shell/client commands remain stdin DATA throughout.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const hooks = path.resolve(process.argv[2] || path.join(__dirname, '..'));
const EG = 'block-secret-egress.cjs';
const FOCUSED = 'tests/cx-1103-1-literal-cd.test.cjs';
const digest = value => crypto.createHash('sha256').update(value).digest('hex');

const countGuard = `  if (Math.max(directoryCommands(parsed),
      insp.invocations.filter(invocation => ['cd', 'pushd', 'popd'].includes(invocation.name)).length) !== 1) return null;`;
const syntaxGuard = String.raw`function leadingCdSyntax(first = null) {
  return /^\s*cd(?=\s)/.test(cmd) &&
    (first === null || first.words.length === 2 && first.words[0].raw === 'cd');
}`;
const dotGuard = `  if (target.text.split('/').some(part => part === '.' || part === '..')) return null;`;
const directoryGuard = `  let cwd, inputCwd;
  try {
    cwd = fs.realpathSync.native(target.text);
    if (!fs.statSync(cwd).isDirectory()) return null;
    fs.accessSync(target.text, fs.constants.X_OK);
    // Retain the mode-bit check even when the Hook is run by a privileged test
    // actor: a directory with no search bits is not qualified by that actor.
    for (let directory = cwd;; directory = path.dirname(directory)) {
      if (!(fs.statSync(directory).mode & 0o111)) return null;
      if (directory === path.dirname(directory)) break;
    }
    inputCwd = fs.realpathSync.native(baseDir);
  } catch { return null; }`;
const controlGuard = String.raw`  if (parsed.errors.length || parsed.unsupportedSources.length || parsed.async || parsed.evaluationUnknown ||
      first.scope !== parsed.scope || first.effects.length !== 1 ||
      first.effects.some(effect => effect.pipeline || effect.conditional || effect.unsafeSetup) ||
      first.redirs.length || first.heredocBodies.length || first.definitionName ||
      !/^\s*$/.test(cmd.slice(0, first.words[0].start)) ||
      !/^[ \t\r\n]*&&/.test(cmd.slice(target.start + target.raw.length))) return null;`;

const mutations = [
  {
    id: 'without-cwd-lending', before: 'const leadingCdContext = leadingLiteralCdContext();',
    after: 'const leadingCdContext = null;',
    expected: ['allow-1-same-cwd', 'allow-3-downstream-pipeline',
      'allow-extra-wrapper-same-command', 'allow-extra-wrapper-same-exec',
      'allow-extra-wrapper-same-env', 'allow-extra-symlink-same-realpath'],
    from: 'ALLOW', to: 'UNKNOWN',
    contextControlTransitions: Object.fromEntries([
      'control-root-binding-relative-home-same-realpath',
      'control-root-binding-relative-xdg-same-realpath',
      'control-root-binding-xdg-data-same-realpath',
      'control-root-binding-no-selected-root-same-realpath',
    ].map(id => [id, { from: 'ALLOW', to: 'UNKNOWN' }])),
    sameDirScopeTransitions: {
      'allow-same-dir-spaced-input': { from: 'ALLOW', to: 'UNKNOWN' },
      'forbid-same-dir-issue-body-file': { from: 'FORBIDDEN', to: 'UNKNOWN', unknownReason: 'network-context' },
    },
  },
  {
    id: 'without-whole-input-directory-count', before: countGuard, after: '',
    expected: ['deny-same-dir-two-same-cd', 'deny-same-dir-two-mixed-cd'],
    from: 'UNKNOWN', to: 'ALLOW',
  },
  {
    id: 'without-dot-components', before: dotGuard, after: '',
    expected: ['deny-same-dir-dot-component'], from: 'UNKNOWN', to: 'ALLOW',
  },
  {
    id: 'without-directory-qualification', before: directoryGuard,
    after: '  const cwd = target.text, inputCwd = fs.realpathSync.native(baseDir);',
    expected: [], from: 'UNKNOWN', to: 'ALLOW',
    extraTransitions: { 'allow-extra-symlink-same-realpath': { from: 'ALLOW', to: 'UNKNOWN' } },
    contextControlTransitions: Object.fromEntries([
      'control-root-binding-relative-home-same-realpath',
      'control-root-binding-relative-xdg-same-realpath',
      'control-root-binding-xdg-data-same-realpath',
      'control-root-binding-no-selected-root-same-realpath',
    ].map(id => [id, { from: 'ALLOW', to: 'UNKNOWN' }])),
  },
  {
    id: 'without-control-and-effect-qualification', before: controlGuard, after: '',
    expected: ['deny-same-dir-control-witness'], from: 'UNKNOWN', to: 'ALLOW',
  },
  {
    id: 'without-alias-veto',
    before: " || insp.invocations.some(invocation => invocation.name === 'alias')", after: '',
    expected: ['deny-same-dir-alias-witness'], from: 'UNKNOWN', to: 'ALLOW',
  },
  {
    id: 'without-leading-cd-syntax', before: syntaxGuard,
    after: 'function leadingCdSyntax() { return true; }',
    expected: ['deny-same-dir-syntax-witness'], from: 'UNKNOWN', to: 'ALLOW',
  },
  {
    id: 'without-gh-only-cwd-lending',
    before: "    if (invocation.name === 'gh' && invocation.scope === rootScope && !invocation.cdLikeHere &&",
    after: '    if (invocation.scope === rootScope && !invocation.cdLikeHere &&',
    expected: ['deny-same-dir-non-gh'], from: 'UNKNOWN', to: 'ALLOW',
  },
  {
    id: 'without-protected-cd-word', before: '  if (guard.isSecretPath(target.text)) return null;', after: '',
    expected: ['deny-same-dir-word-witness'], from: 'UNKNOWN', to: 'ALLOW',
  },
  {
    id: 'without-protected-cd-realpath', before: '  if (guard.isSecretPath(cwd)) return null;', after: '',
    expected: ['deny-same-dir-realpath-witness'], from: 'UNKNOWN', to: 'ALLOW',
  },
  {
    id: 'without-same-directory-equality', before: '  if (cwd !== inputCwd) return null;\n', after: '',
    expected: ['allow-2-different-cwd', 'allow-4-quoted-space', 'allow-5-semicolon-after-grep',
      'allow-extra-wrapper-different-command', 'allow-extra-wrapper-different-exec',
      'allow-extra-wrapper-different-env', 'allow-extra-relative-PATH-destination',
      'control-root-binding-absolute-xdg-relative-home', 'control-root-binding-posix-appdata',
      'control-root-binding-unset-xdg-data', 'deny-same-dir-different-symlink',
      'deny-root-binding-relative-home', 'deny-root-binding-relative-xdg',
      'deny-root-binding-xdg-data', 'deny-root-binding-no-selected-root',
      'deny-root-binding-empty-xdg-relative-home', 'deny-16-gh-internal-git'],
    from: 'UNKNOWN', to: 'ALLOW',
  },
];

test('CX-1103-1 same-directory guards independently break their named focused assertions', async t => {
  if (process.platform === 'win32') { t.skip('focused corpus has no qualified Windows identity model'); return; }
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'cx-1103-1-cd-inverse-'));
  const files = [EG, 'lib/git-guard-common.cjs', 'lib/git-precommit-readers.cjs', 'lib/executable-identity.cjs', FOCUSED];
  const originals = new Map(files.map(file => [file, fs.readFileSync(path.join(hooks, file))]));
  const pins = () => Object.fromEntries(files.map(file => [file, digest(fs.readFileSync(path.join(hooks, file)))]));
  const sourcePins = pins();
  const source = originals.get(EG).toString('utf8');
  let totalHookCalls = 0;
  let originalSubsetHookCalls = 0, cwdProtectionHookCalls = 0, contextControlHookCalls = 0, sameDirScopeHookCalls = 0, sameDirGuardWitnessHookCalls = 0;
  try {
    const run = (id, alteredSource, expectedStatus) => {
      const trial = path.join(root, id);
      for (const [file, bytes] of originals) {
        const target = path.join(trial, file);
        fs.mkdirSync(path.dirname(target), { recursive: true });
        fs.writeFileSync(target, file === EG ? alteredSource : bytes);
      }
      const result = spawnSync(process.execPath, ['--test-reporter=spec', path.join(trial, FOCUSED), trial], {
        env: { PATH: '/usr/bin:/bin', LC_ALL: 'C', TMPDIR: root },
        encoding: 'utf8', timeout: 120000, maxBuffer: 4 * 1024 * 1024,
      });
      assert.equal(result.error, undefined, id + ': focused child must complete');
      assert.equal(result.signal, null, id + ': focused child must not terminate by signal');
      assert.equal(result.stderr, '', id + ': focused child stderr');
      assert.equal(result.status, expectedStatus, id + ': focused assertion status\n' + result.stdout);
      const rows = new Map();
      let summary = null;
      for (const line of result.stdout.split('\n')) {
        const start = line.indexOf('{"');
        if (start < 0) continue;
        let row;
        try { row = JSON.parse(line.slice(start)); } catch { continue; }
        if (typeof row.id === 'string') {
          assert.equal(rows.has(row.id), false, id + ': duplicate focused case');
          assert.notEqual(row.verdict, 'BROKEN', id + ': broken wire is not mutation evidence');
          assert.equal(row.status, 0, id + ': Hook must complete normally');
          assert.equal(row.stderr, '', id + ': Hook stderr');
          rows.set(row.id, row);
        }
        if (row.hookCalls) summary = row;
      }
      const originalRows = new Map([...rows].filter(([, row]) => row.cwdProtectionCase !== true && row.contextControlCase !== true && row.sameDirScopeCase !== true && row.sameDirGuardWitnessCase !== true));
      const cwdProtectionRows = new Map([...rows].filter(([, row]) => row.cwdProtectionCase === true));
      const contextControlRows = new Map([...rows].filter(([, row]) => row.contextControlCase === true));
      const sameDirScopeRows = new Map([...rows].filter(([, row]) => row.sameDirScopeCase === true));
      const sameDirGuardWitnessRows = new Map([...rows].filter(([, row]) => row.sameDirGuardWitnessCase === true));
      assert.equal(originalRows.size, 69, id + ': every unchanged original focused input must run');
      assert.equal([...originalRows.keys()].filter(key => key.startsWith('allow-')).length, 13,
        id + ': retain all historical positive case identities');
      assert.equal([...originalRows.values()].filter(row => row.id.startsWith('allow-') && row.differentCwdCase !== true).length, 6,
        id + ': retain the six same-directory original positives');
      assert.equal([...originalRows.values()].filter(row => row.id.startsWith('allow-') && row.differentCwdCase === true).length, 7,
        id + ': explicitly narrow the seven different-cwd historical positives');
      assert.equal(cwdProtectionRows.size, 5, id + ': exactly the requested cwd-protection inputs must run');
      assert.equal(originalRows.size + cwdProtectionRows.size, 74, id + ': every previous focused input must run');
      assert.equal(contextControlRows.size, 22, id + ': exactly the requested inherited-context controls must run');
      assert.equal(originalRows.size + cwdProtectionRows.size + contextControlRows.size, 96, id + ': every previous focused input must run');
      assert.equal(sameDirScopeRows.size, 18, id + ': remove only the two named unpublished controls');
      assert.equal(originalRows.size + cwdProtectionRows.size + contextControlRows.size + sameDirScopeRows.size, 114,
        id + ': retain every other fifth-snapshot input');
      assert.equal(sameDirGuardWitnessRows.size, 5, id + ': exactly five same-directory guard witnesses must run');
      assert.equal(rows.size, 119, id + ': every focused input must run');
      for (const row of contextControlRows.values()) assert.notEqual(row.cwdProtectionCase, true,
        id + ': inherited-context controls must stay separate from cwd-protection inputs');
      for (const row of sameDirScopeRows.values()) {
        assert.notEqual(row.cwdProtectionCase, true, id + ': same-directory inputs form a separate group');
        assert.notEqual(row.contextControlCase, true, id + ': same-directory inputs form a separate group');
      }
      for (const row of sameDirGuardWitnessRows.values()) {
        assert.notEqual(row.cwdProtectionCase, true, id + ': guard witnesses form a separate group');
        assert.notEqual(row.contextControlCase, true, id + ': guard witnesses form a separate group');
        assert.notEqual(row.sameDirScopeCase, true, id + ': guard witnesses form a separate group');
        assert.equal(row.sameDirGuardSameRealpath, true, id + ': every guard witness must assert its same-directory target');
      }
      assert.ok(summary, id + ': focused source/native summary is required');
      assert.equal(typeof summary.ownedFixtureRoot, 'string', id + ': normalization must bind this run\'s owned fixture root');
      assert.ok(path.isAbsolute(summary.ownedFixtureRoot));
      assert.equal(summary.nativeAttempts, 0, id + ': no selected/native program may execute or be attempted');
      assert.equal(summary.proposedCommandsExecuted, 0);
      assert.equal(summary.hookCalls, rows.size);
      assert.equal(summary.retainedOriginalCases, 69, id + ': focused summary must retain the original corpus');
      assert.equal(summary.retainedOriginalPositiveCases, 13, id + ': focused summary must retain historical positive identities');
      assert.equal(summary.cwdProtectionCases, 5, id + ': focused summary must bind the five added inputs');
      assert.equal(summary.retainedPreviousCases, 74, id + ': focused summary must retain all prior definitions and expectations');
      assert.equal(summary.contextControlCases, 22, id + ': focused summary must bind the inherited-context controls');
      assert.equal(summary.previousScopeCases, 96, id + ': focused summary must retain all prior definitions');
      assert.equal(summary.sameDirScopeCases, 18, id + ': focused summary must bind retained same-directory inputs');
      assert.equal(summary.fifthSnapshotCases, 114, id + ': focused summary must bind every retained fifth-snapshot input');
      assert.equal(summary.sameDirGuardWitnessCases, 5, id + ': focused summary must bind all five guard witnesses');
      assert.equal(summary.changedDifferentCwdCases, 10, id + ': only ten named historical expectations are narrowed');
      assert.equal(summary.retainedSameDirPositiveCases, 6);
      assert.equal(summary.narrowedDifferentCwdPositiveCases, 7);
      assert.equal(summary.sourcePins[EG], digest(alteredSource), id + ': observed Hook must bind the mutation');
      totalHookCalls += summary.hookCalls;
      originalSubsetHookCalls += originalRows.size;
      cwdProtectionHookCalls += cwdProtectionRows.size;
      contextControlHookCalls += contextControlRows.size;
      sameDirScopeHookCalls += sameDirScopeRows.size;
      sameDirGuardWitnessHookCalls += sameDirGuardWitnessRows.size;
      return { rows, originalRows, cwdProtectionRows, contextControlRows, sameDirScopeRows, sameDirGuardWitnessRows, summary };
    };
    const reference = run('unchanged-reference', source, 0);
    for (const mutation of mutations) await t.test(mutation.id, () => {
      assert.equal(source.split(mutation.before).length - 1, 1, mutation.id + ': exact guard anchor must be unique');
      const alteredSource = source.replace(mutation.before, mutation.after);
      assert.notEqual(alteredSource, source);
      const observed = run(mutation.id, alteredSource, 1);
      const changed = [];
      for (const [id, row] of observed.rows) {
        const original = reference.rows.get(id);
        assert.ok(original, mutation.id + ': unchanged corpus id');
        assert.equal(row.cwdProtectionCase, original.cwdProtectionCase,
          mutation.id + ': original/additional corpus membership must stay fixed');
        assert.equal(row.contextControlCase, original.contextControlCase,
          mutation.id + ': inherited-context corpus membership must stay fixed');
        assert.equal(row.sameDirScopeCase, original.sameDirScopeCase,
          mutation.id + ': same-directory corpus membership must stay fixed');
        assert.equal(row.sameDirGuardWitnessCase, original.sameDirGuardWitnessCase,
          mutation.id + ': same-directory guard-witness membership must stay fixed');
        assert.equal(row.sameDirGuardSameRealpath, original.sameDirGuardSameRealpath,
          mutation.id + ': same-directory target qualification must stay fixed');
        assert.equal(row.differentCwdCase, original.differentCwdCase,
          mutation.id + ': narrowed historical case membership must stay fixed');
        assert.equal(row.command.split(observed.summary.ownedFixtureRoot).join('<owned-fixture>'),
          original.command.split(reference.summary.ownedFixtureRoot).join('<owned-fixture>'),
          mutation.id + ': command shape must remain identical after normalizing only the owned fixture root');
        if (row.verdict !== original.verdict) changed.push(id);
      }
      const transitions = new Map(mutation.expected.map(id => [id, { from: mutation.from, to: mutation.to }]));
      for (const [id, transition] of Object.entries(mutation.extraTransitions || {})) transitions.set(id, transition);
      for (const [id, transition] of Object.entries(mutation.cwdProtectionTransitions || {})) transitions.set(id, transition);
      for (const [id, transition] of Object.entries(mutation.contextControlTransitions || {})) transitions.set(id, transition);
      for (const [id, transition] of Object.entries(mutation.sameDirScopeTransitions || {})) transitions.set(id, transition);
      assert.ok(transitions.size > 0, mutation.id + ': each single-guard removal must have direct inverse evidence');
      assert.deepEqual(changed.sort(), [...transitions.keys()].sort(),
        mutation.id + ': only the named cases may explain the single-guard assertion failure');
      const changedOriginalCases = changed.filter(id => reference.originalRows.has(id));
      const changedCwdProtectionCases = changed.filter(id => reference.cwdProtectionRows.has(id));
      const changedContextControlCases = changed.filter(id => reference.contextControlRows.has(id));
      const changedSameDirScopeCases = changed.filter(id => reference.sameDirScopeRows.has(id));
      const changedSameDirGuardWitnessCases = changed.filter(id => reference.sameDirGuardWitnessRows.has(id));
      assert.deepEqual(changedOriginalCases, [...transitions.keys()].filter(id => reference.originalRows.has(id)).sort(),
        mutation.id + ': historical inputs must use their explicitly narrowed same-directory expectations');
      assert.deepEqual(changedCwdProtectionCases, [...transitions.keys()].filter(id => reference.cwdProtectionRows.has(id)).sort(),
        mutation.id + ': additional transitions must stay separate from the original expectations');
      assert.deepEqual(changedContextControlCases, [...transitions.keys()].filter(id => reference.contextControlRows.has(id)).sort(),
        mutation.id + ': inherited-context transitions must stay separate from the other input groups');
      assert.deepEqual(changedSameDirScopeCases, [...transitions.keys()].filter(id => reference.sameDirScopeRows.has(id)).sort(),
        mutation.id + ': same-directory transitions must stay separate from historical inputs');
      assert.deepEqual(changedSameDirGuardWitnessCases, [...transitions.keys()].filter(id => reference.sameDirGuardWitnessRows.has(id)).sort(),
        mutation.id + ': each new same-directory witness must retain its named guard dependency');
      for (const [id, transition] of transitions) {
        assert.equal(reference.rows.get(id).verdict, transition.from, id + ': qualified reference');
        const row = observed.rows.get(id);
        assert.equal(row.verdict, transition.to, id + ': mutation must change the semantic verdict');
        if (transition.to === 'UNKNOWN') assert.match(row.stdout,
          transition.unknownReason === 'network-context' ? /network client の config・argv・実行 source または context が不足/ : /実行名・PATH lookup/,
          id + ': the lost cwd proof must stop at the identified existing context guard');
        else assert.equal(row.stdout, '', id + ': red must be ALLOW, not a different unknown or broken result');
      }
      t.diagnostic(JSON.stringify({ mutation: mutation.id, sourceSHA256: digest(alteredSource),
        referenceSHA256: sourcePins[EG], changedCases: changed, from: mutation.from, to: mutation.to,
        extraTransitions: mutation.extraTransitions || {},
        cwdProtectionTransitions: mutation.cwdProtectionTransitions || {}, changedOriginalCases, changedCwdProtectionCases,
        contextControlTransitions: mutation.contextControlTransitions || {}, changedContextControlCases,
        sameDirScopeTransitions: mutation.sameDirScopeTransitions || {}, changedSameDirScopeCases,
        changedSameDirGuardWitnessCases, characterization: 'active-inverse', focusedStatus: 1,
        hookCalls: observed.summary.hookCalls, nativeAttempts: 0, broken: 0 }));
    });
    assert.equal(mutations.length, 11, 'remove only the two obsolete helper mutations');
    assert.equal(originalSubsetHookCalls, 828, 'reference and all eleven mutations must execute the historical 69 input identities');
    assert.equal(cwdProtectionHookCalls, 60, 'reference and all eleven mutations must execute the five cwd-protection inputs');
    assert.equal(contextControlHookCalls, 264, 'reference and all eleven mutations must execute the 22 inherited-context controls');
    assert.equal(originalSubsetHookCalls + cwdProtectionHookCalls + contextControlHookCalls, 1152, 'all runs must execute the prior 96 input identities');
    assert.equal(sameDirScopeHookCalls, 216, 'all runs must execute the 18 retained same-directory inputs');
    assert.equal(originalSubsetHookCalls + cwdProtectionHookCalls + contextControlHookCalls + sameDirScopeHookCalls, 1368,
      'all runs must execute the retained 114 fifth-snapshot input identities');
    assert.equal(sameDirGuardWitnessHookCalls, 60, 'all runs must execute all five new same-directory guard witnesses');
    assert.equal(totalHookCalls, 1428, 'reference and all eleven mutations must execute all 119 inputs');
    assert.deepEqual(pins(), sourcePins, 'candidate source must stay fixed across inverse qualification');
    t.diagnostic(JSON.stringify({ guards: mutations.length, activeGuards: 11, independentlyMaskedGuards: 0,
      sourcePins, totalHookCalls, originalSubsetHookCalls, cwdProtectionHookCalls, contextControlHookCalls, sameDirScopeHookCalls, sameDirGuardWitnessHookCalls,
      previousCorpusHookCalls: originalSubsetHookCalls + cwdProtectionHookCalls + contextControlHookCalls,
      nativeAttempts: 0, broken: 0,
      fifthSnapshotHookCalls: originalSubsetHookCalls + cwdProtectionHookCalls + contextControlHookCalls + sameDirScopeHookCalls,
      scope: '114 retained inputs and five same-directory guard witnesses; exact one-guard mutations only' }));
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
