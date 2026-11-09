'use strict';
// Independent test prerequisites only. Never consult a guard verdict,
// import production selection code, or execute a candidate program.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const hashCase = value => crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
const pathBinding = environment => {
  if (!environment || typeof environment !== 'object') throw Error('Actual case environment is required');
  return hashCase(Object.hasOwn(environment, 'PATH') ? ['present', environment.PATH] : ['absent']);
};

function executablePresence(file, filesystem = fs) {
  try {
    if (!filesystem.statSync(file).isFile()) return 'not-executable';
  } catch (error) {
    return ['ENOENT', 'ENOTDIR'].includes(error.code) ? 'absent' : 'unknown';
  }
  try { filesystem.accessSync(file, fs.constants.X_OK); return 'present'; }
  catch (error) {
    return ['ENOENT', 'ENOTDIR', 'EACCES', 'EPERM'].includes(error.code) ? 'not-executable' : 'unknown';
  }
}

function independentlyAbsent(word, environment, filesystem = fs) {
  if (typeof word !== 'string' || !word || word.includes('\0')) return { applies: false, reason: 'unqualified-word' };
  if (path.isAbsolute(word)) {
    const presence = executablePresence(word, filesystem);
    return { applies: ['absent', 'not-executable'].includes(presence), reason: 'explicit-' + presence };
  }
  if (word.includes('/') || typeof environment?.PATH !== 'string' || environment.PATH.includes('\0'))
    return { applies: false, reason: 'unqualified-search' };
  for (const directory of environment.PATH.split(path.delimiter)) {
    // No implicit cwd/default-PATH proof is manufactured by this test helper.
    if (!path.isAbsolute(directory)) return { applies: false, reason: 'unqualified-path-entry' };
    const presence = executablePresence(directory + path.sep + word, filesystem);
    if (presence === 'present') return { applies: false, reason: 'first-executable-present' };
    if (presence === 'unknown') return { applies: false, reason: 'filesystem-unknown' };
  }
  return { applies: true, reason: 'no-executable-in-explicit-actual-path' };
}

const unsupported = new Set([
  'DEFAULT_SEARCH_UNQUALIFIED', 'EXTERNAL_SHELL_PRIMITIVE',
  'CHILD_PATH_CLEARED_LOOKUP_UNQUALIFIED', 'UNSUPPORTED_EXEC_LOOKUP',
]);
const absent = new Set([
  'NO_SELECTED_EXECUTABLE_NO_NAMED_INSTALL', 'SELECTED_EXPLICIT_PATH_UNAVAILABLE',
  'INSTALLED_BUT_OUTSIDE_SELECTED_PATH',
]);
const knownInstallations = new Set(['/usr/bin', '/bin', '/usr/sbin', '/sbin', '/usr/local/bin', '/opt/homebrew/bin']);
const refined = 'KNOWN_ABSOLUTE_INSTALLATION_SECRET_DESTINATION';

function independentlyKnownAbsoluteInstallation(word, filesystem = fs) {
  if (typeof word !== 'string' || !path.isAbsolute(word) || !knownInstallations.has(path.dirname(word)) ||
      !/^[A-Za-z0-9][A-Za-z0-9_.+-]*$/.test(path.basename(word)) || executablePresence(word, filesystem) !== 'present')
    return { applies: false, reason: 'absolute-installation-not-qualified' };
  try {
    const physical = filesystem.realpathSync.native(word);
    return typeof physical === 'string' && path.isAbsolute(physical)
      ? { applies: true, reason: 'independent-known-absolute-installation', physical }
      : { applies: false, reason: 'absolute-installation-identity-unknown' };
  } catch { return { applies: false, reason: 'absolute-installation-identity-unknown' }; }
}

function qualification(originalCase, declaration, environment, filesystem = fs) {
  if (!declaration || declaration.id !== originalCase.id || declaration.originalCaseSHA256 !== hashCase(originalCase))
    throw Error('Profile declaration is not bound to the original case');
  if (!['DEPENDENT_SELECTED_SOURCE_ONLY', 'EG_DEPENDENT_KEEP_SG_FORBIDDEN', 'CONFIRMED_LITERAL_SECRET_DESTINATION'].includes(declaration.rootPriorityDisposition))
    throw Error('Profile declaration lacks an explicit priority disposition');
  const refinement = declaration.rootPriorityDisposition === 'CONFIRMED_LITERAL_SECRET_DESTINATION';
  if (declaration.stages.some(stage => stage.kind === refined) !== refinement ||
      refinement && (declaration.stages.length !== 1 || declaration.stages[0].kind !== refined))
    throw Error('Refined secret-destination assertion must have one independent installation prerequisite');
  const reasons = [];
  for (const stage of declaration.stages) {
    if (unsupported.has(stage.kind)) reasons.push({ kind: stage.kind, reason: 'declared-unqualified-selection-stage' });
    else if (absent.has(stage.kind)) {
      if (!path.isAbsolute(stage.word) && (stage.searchBinding !== 'UNCHANGED_INHERITED_PATH' ||
          stage.searchSnapshot?.pathPresent !== true || stage.searchSnapshot?.pathChanged !== false ||
          stage.searchSnapshot?.defaultSearch !== false))
        throw Error('Absence prerequisite is not bound to an unchanged inherited search stage');
      const result = independentlyAbsent(stage.word, environment, filesystem);
      if (result.applies) reasons.push({ kind: stage.kind, word: stage.word, reason: result.reason });
    } else if (stage.kind === refined) {
      const result = independentlyKnownAbsoluteInstallation(stage.word, filesystem);
      if (result.applies) reasons.push({ kind: stage.kind, word: stage.word, reason: result.reason, physical: result.physical });
    } else throw Error('Unknown profile prerequisite kind');
  }
  return { caseID: originalCase.id, originalCaseSHA256: hashCase(originalCase),
    actualPATHBinding: pathBinding(environment), applies: reasons.length > 0, reasons,
    preserveOwnSGForbidden: declaration.rootPriorityDisposition === 'EG_DEPENDENT_KEEP_SG_FORBIDDEN',
    expectedOwnEG: refinement ? 'FORBIDDEN' : 'UNKNOWN',
    originalSemanticAssertionsRetained: reasons.length === 0,
    source: 'declaration-and-independent-filesystem-only' };
}

function effectiveCase(originalCase, qualified, environment) {
  if (qualified.caseID !== originalCase.id || qualified.originalCaseSHA256 !== hashCase(originalCase) ||
      qualified.actualPATHBinding !== pathBinding(environment))
    throw Error('Qualification does not bind this exact original case and actual environment');
  if (!qualified.applies) return originalCase;
  const ownEG = qualified.expectedOwnEG || 'UNKNOWN';
  if (!['UNKNOWN', 'FORBIDDEN'].includes(ownEG)) throw Error('Unsupported explicit profile classification');
  const result = { ...originalCase, expect: 'deny', expectedOwnEG: ownEG,
    expectReasonPrefixes: { ...originalCase.expectReasonPrefixes,
      'block-secret-egress.cjs': ownEG === 'FORBIDDEN' ? '[禁止] ' : '[判断不能] ' } };
  if (originalCase.expect === 'allow') {
    result.expectedOwnSG = originalCase.expectedOwnSG || 'ALLOW';
    result.expectedOwnAG = originalCase.expectedOwnAG || 'ALLOW';
  }
  if (qualified.preserveOwnSGForbidden) {
    if (originalCase.expectedOwnSG && originalCase.expectedOwnSG !== 'FORBIDDEN')
      throw Error('Independent SG obligation conflicts with original declaration');
    result.expectedOwnSG = 'FORBIDDEN';
    result.expectReasonPrefixes['block-secret-git.cjs'] = '[禁止] ';
  }
  // Existing SG/AG obligations and their prefixes are never weakened.
  if (!result.denyBy) result.denyBy = 'block-secret-egress.cjs';
  if (result.allowBy === 'block-secret-egress.cjs') delete result.allowBy;
  return result;
}

function matchesCase(result, expected, hooks) {
  return result.decision === expected.expect && result.broken.length === 0 &&
    (!expected.expectedOwnEG || result.ownEG === expected.expectedOwnEG) &&
    (!expected.expectedOwnSG || result.ownSG === expected.expectedOwnSG) &&
    (!expected.expectedOwnAG || result.ownAG === expected.expectedOwnAG) &&
    (!expected.denyBy || result.denied.includes(expected.denyBy)) &&
    (!expected.allowBy || hooks.includes(expected.allowBy) && !result.denied.includes(expected.allowBy)) &&
    Object.entries(expected.expectReasonPrefixes || {}).every(([hook, prefix]) => result.reasonPrefixes[hook] === prefix);
}

function infrastructureReason(reasonTexts) {
  return Object.values(reasonTexts || {}).some(reason => typeof reason === 'string' &&
    ['途中で例外', '読み込めません', 'MODULE_NOT_FOUND', 'Cannot find module'].some(marker => reason.includes(marker)));
}

function createProfile(cases, ledger, filesystem = fs) {
  if (ledger.schema !== 'R54_SELECTED_EXECUTABLE_TEST_PROFILE_V1' || ledger.baselineCount !== cases.length ||
      ledger.baselineDefinitionsSHA256 !== hashCase(cases) || !Array.isArray(ledger.entries))
    throw Error('Selected-executable profile baseline is not exact');
  const byID = new Map(cases.map(c => [c.id, c]));
  const baselineHashes = new Map(cases.map(c => [c.id, hashCase(c)]));
  const baselineDefinitionsHash = hashCase(cases);
  if (byID.size !== cases.length) throw Error('Duplicate original case ID');
  const declarations = new Map();
  for (const declaration of ledger.entries) {
    const c = byID.get(declaration.id);
    if (!c || declarations.has(c.id) || hashCase(c) !== declaration.originalCaseSHA256 ||
        !Array.isArray(declaration.stages) || !declaration.stages.length)
      throw Error('Selected-executable declaration is not bound to an original unique case');
    for (const stage of declaration.stages) if (!unsupported.has(stage.kind) && !absent.has(stage.kind) && stage.kind !== refined)
      throw Error('Unsupported selected-executable prerequisite kind');
    declarations.set(c.id, JSON.parse(JSON.stringify(declaration)));
  }
  return {
    qualify(c, environment) {
      if (!byID.has(c.id) || hashCase(c) !== baselineHashes.get(c.id)) throw Error('Original case drift');
      const declaration = declarations.get(c.id);
      return declaration ? qualification(c, declaration, environment, filesystem) : {
        caseID: c.id, originalCaseSHA256: hashCase(c), actualPATHBinding: pathBinding(environment),
        applies: false, reasons: [], originalSemanticAssertionsRetained: true,
        source: 'original-oracle-no-profile-declaration',
      };
    },
    effectiveCase,
    definitionsUnchanged: () => hashCase(cases) === baselineDefinitionsHash,
  };
}

module.exports = { hashCase, executablePresence, independentlyAbsent, qualification, effectiveCase,
  independentlyKnownAbsoluteInstallation, createProfile, matchesCase, infrastructureReason };
