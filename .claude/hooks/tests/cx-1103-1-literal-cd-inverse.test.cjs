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
    expected: ['allow-1-same-cwd', 'allow-2-different-cwd', 'allow-3-downstream-pipeline',
      'allow-4-quoted-space', 'allow-5-semicolon-after-grep',
      'allow-extra-wrapper-same-command', 'allow-extra-wrapper-different-command',
      'allow-extra-wrapper-same-exec', 'allow-extra-wrapper-different-exec',
      'allow-extra-wrapper-same-env', 'allow-extra-wrapper-different-env',
      'allow-extra-symlink-same-realpath', 'allow-extra-relative-PATH-destination'],
    from: 'ALLOW', to: 'UNKNOWN',
  },
  {
    id: 'without-whole-input-directory-count', before: countGuard, after: '',
    expected: ['deny-7-two-prior-cd', 'deny-7-later-cd', 'deny-7-later-builtin-cd'],
    from: 'UNKNOWN', to: 'ALLOW',
  },
  {
    id: 'without-dot-components', before: dotGuard, after: '',
    expected: ['deny-11-dot-segment', 'deny-11-dotdot-segment'], from: 'UNKNOWN', to: 'ALLOW',
  },
  {
    id: 'without-directory-qualification', before: directoryGuard,
    after: '  const cwd = target.text, inputCwd = fs.realpathSync.native(baseDir);',
    expected: ['deny-12-missing', 'deny-12-file', 'deny-12-no-search'], from: 'UNKNOWN', to: 'ALLOW',
    extraTransitions: { 'allow-extra-symlink-same-realpath': { from: 'ALLOW', to: 'UNKNOWN' } },
  },
  {
    id: 'without-control-and-effect-qualification', before: controlGuard, after: '',
    expected: ['deny-8-pipeline', 'deny-8-background', 'deny-8-or-condition', 'deny-8-cd-redirection'],
    from: 'UNKNOWN', to: 'ALLOW',
  },
  {
    id: 'without-alias-veto',
    before: " || insp.invocations.some(invocation => invocation.name === 'alias')", after: '',
    expected: ['deny-9-later-alias-shadow'], from: 'UNKNOWN', to: 'ALLOW',
  },
  {
    id: 'without-gh-cwd-boundary',
    before: '      cdCwd && ghCdContextUnknown(invocation) ||\n', after: '',
    expected: ['deny-16-gh-internal-git'], from: 'UNKNOWN', to: 'ALLOW',
  },
  {
    id: 'without-leading-cd-syntax', before: syntaxGuard,
    after: 'function leadingCdSyntax() { return true; }',
    expected: ['deny-10-builtin-prefix', 'deny-10-command-prefix', 'deny-10-assignment-prefix',
      'deny-10-physical-option', 'deny-10-double-dash'], from: 'UNKNOWN', to: 'ALLOW',
  },
];

test('CX-1103-1 each removed guard independently breaks its focused assertions', async t => {
  if (process.platform === 'win32') { t.skip('focused corpus has no qualified Windows identity model'); return; }
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'cx-1103-1-cd-inverse-'));
  const files = [EG, 'lib/git-guard-common.cjs', 'lib/git-precommit-readers.cjs', 'lib/executable-identity.cjs', FOCUSED];
  const originals = new Map(files.map(file => [file, fs.readFileSync(path.join(hooks, file))]));
  const pins = () => Object.fromEntries(files.map(file => [file, digest(fs.readFileSync(path.join(hooks, file)))]));
  const sourcePins = pins();
  const source = originals.get(EG).toString('utf8');
  let totalHookCalls = 0;
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
      assert.equal(rows.size, 69, id + ': every unchanged focused input must run');
      assert.ok(summary, id + ': focused source/native summary is required');
      assert.equal(summary.nativeAttempts, 0, id + ': no selected/native program may execute or be attempted');
      assert.equal(summary.proposedCommandsExecuted, 0);
      assert.equal(summary.hookCalls, rows.size);
      assert.equal(summary.sourcePins[EG], digest(alteredSource), id + ': observed Hook must bind the mutation');
      totalHookCalls += summary.hookCalls;
      return { rows, summary };
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
        // Commands contain each owned fixture's fresh root path; compare the
        // fixed case id and verdict rather than unrelated randomized pathname bytes.
        if (row.verdict !== original.verdict) changed.push(id);
      }
      const transitions = new Map(mutation.expected.map(id => [id, { from: mutation.from, to: mutation.to }]));
      for (const [id, transition] of Object.entries(mutation.extraTransitions || {})) transitions.set(id, transition);
      assert.deepEqual(changed.sort(), [...transitions.keys()].sort(),
        mutation.id + ': only this removed guard may explain red focused assertions');
      for (const [id, transition] of transitions) {
        assert.equal(reference.rows.get(id).verdict, transition.from, id + ': qualified reference');
        const row = observed.rows.get(id);
        assert.equal(row.verdict, transition.to, id + ': mutation must change the semantic verdict');
        if (transition.to === 'UNKNOWN') assert.match(row.stdout, /実行名・PATH lookup/,
          id + ': the lost cwd proof must stop at the executable/context guard');
        else assert.equal(row.stdout, '', id + ': red must be ALLOW, not a different unknown or broken result');
      }
      t.diagnostic(JSON.stringify({ mutation: mutation.id, sourceSHA256: digest(alteredSource),
        referenceSHA256: sourcePins[EG], changedCases: changed, from: mutation.from, to: mutation.to,
        extraTransitions: mutation.extraTransitions || {},
        hookCalls: observed.summary.hookCalls, nativeAttempts: 0, broken: 0 }));
      if (mutation.id === 'without-control-and-effect-qualification') {
        assert.equal(mutations.indexOf(mutation), 4, 'retain the original five mutations in their original order');
        assert.equal(totalHookCalls, 414, 'the original five mutations must retain all 414 Hook inputs');
      }
    });
    assert.equal(mutations.length, 8, 'retain five original mutations and exactly three added guards');
    assert.equal(totalHookCalls, 621, 'reference and all eight mutations must execute the unchanged 69 inputs');
    assert.deepEqual(pins(), sourcePins, 'candidate source must stay fixed across inverse qualification');
    t.diagnostic(JSON.stringify({ guards: mutations.length, sourcePins, totalHookCalls,
      retainedOriginalGuards: 5, retainedOriginalHookCalls: 414, additionalGuards: 3,
      nativeAttempts: 0, broken: 0, scope: 'unchanged synthetic focused inputs; exact one-guard mutations only' }));
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
