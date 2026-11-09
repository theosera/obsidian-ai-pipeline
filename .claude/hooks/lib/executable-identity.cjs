'use strict';

// Filesystem identity only: callers own shell/builtin selection, actual PATH,
// cwd provenance, wrapper order, and whether a result supports an argv role.
const fs = require('node:fs');
const path = require('node:path');
const INSTALLATION_DIRECTORIES = Object.freeze([
  '/usr/bin', '/bin', '/usr/sbin', '/sbin', '/usr/local/bin', '/opt/homebrew/bin',
]);
const missing = error => error?.code === 'ENOENT' || error?.code === 'ENOTDIR';
const result = (kind, reason, resolvedPath = null) => ({ kind, resolvedPath, reason });

/** Resolve a literal registered executable without executing it or inferring PATH. */
function resolveExecutableIdentity(word, options = {}) {
  if (!options || typeof options !== 'object') return result('unknown-search', 'missing-search-options');
  const { name, searchPath, searchMode, cwd } = options;
  if (process.platform === 'win32') return result('unknown-search', 'windows-search-profile-unqualified');
  if (typeof name !== 'string' || !(name === '[' || /^[A-Za-z0-9][A-Za-z0-9_.+-]*$/.test(name))) {
    return result('unknown-search', 'invalid-registered-name');
  }
  if (!word || typeof word.text !== 'string' || !word.text || word.text.includes('\0') ||
      word.dynamic || word.dynamicMaySplit || word.ansiCUnknown || word.braceExpanded ||
      word.globExpanded || word.tildeExpanded || path.basename(word.text) !== name) {
    return result('unknown-search', 'executable-word-not-literal');
  }
  const absolute = path.isAbsolute(word.text);
  if (!absolute && word.text !== name) return result('unknown-search', 'relative-executable-path-unqualified');
  if (!absolute && (searchMode !== 'path' || typeof searchPath !== 'string' || searchPath.includes('\0'))) {
    return result('unknown-search', 'actual-search-path-not-established');
  }

  // Each trust anchor is an independently named installation, never a PATH
  // prefix. A symlink is trusted only by equality with its current native target.
  const trusted = new Set();
  let trustReadUnknown = false;
  for (const directory of INSTALLATION_DIRECTORIES) {
    const installation = directory + '/' + name;
    try {
      if (!fs.statSync(installation).isFile()) continue;
      fs.accessSync(installation, fs.constants.X_OK);
      trusted.add(fs.realpathSync.native(installation));
    } catch (error) {
      if (!missing(error) && error?.code !== 'EACCES' && error?.code !== 'EPERM') trustReadUnknown = true;
    }
  }

  const selected = candidate => {
    try {
      if (!fs.statSync(candidate).isFile()) return null;
    } catch (error) {
      return missing(error) ? null : result('unknown-search', 'candidate-metadata-unavailable');
    }
    try {
      fs.accessSync(candidate, fs.constants.X_OK);
    } catch (error) {
      if (missing(error) || error?.code === 'EACCES' || error?.code === 'EPERM') return null;
      return result('unknown-search', 'candidate-executability-unavailable');
    }
    try {
      const physical = fs.realpathSync.native(candidate);
      if (trusted.has(physical)) return result('trusted-external', 'selected-trusted-installation', physical);
      return trustReadUnknown ? result('unknown-search', 'installation-identity-unavailable', physical)
        : result('untrusted-first-match', 'selected-executable-outside-trusted-installations', physical);
    } catch {
      return result('unknown-search', 'candidate-identity-unavailable');
    }
  };
  if (absolute) return selected(word.text) || result('not-found', 'explicit-executable-not-found');

  let physicalCwd;
  const cwdForRelativeEntry = () => {
    if (physicalCwd !== undefined) return physicalCwd;
    physicalCwd = null;
    if (typeof cwd !== 'string' || !path.isAbsolute(cwd) || cwd.includes('\0')) return null;
    try {
      const physical = fs.realpathSync.native(cwd);
      if (fs.statSync(physical).isDirectory()) physicalCwd = physical;
    } catch {}
    return physicalCwd;
  };
  for (const directory of searchPath.split(path.delimiter)) {
    let base = directory;
    if (!path.isAbsolute(directory)) {
      const physical = cwdForRelativeEntry();
      if (physical === null) return result('unknown-search', 'relative-path-entry-cwd-unavailable');
      base = directory ? physical + path.sep + directory : physical;
    }
    // Do not normalize symlink/.. before the filesystem resolves the candidate.
    const identity = selected(base + path.sep + name);
    if (identity) return identity;
  }
  return result('not-found', 'no-executable-in-actual-search-path');
}

/** Check each selected wrapper and callee without borrowing a shell builtin across exec. */
function invocationExecutableIdentity(invocation, options = {}) {
  if (!invocation || !options || typeof options !== 'object' || invocation.nonExec ||
      invocation.functionCallName || invocation.definitionName || invocation.dynamicName || invocation.incomplete) {
    return result('unknown-search', 'invocation-selection-requires-caller-policy');
  }
  const { environment, cwd, builtinNames = [] } = options;
  let builtins;
  try { builtins = new Set(builtinNames); } catch { return result('unknown-search', 'invalid-caller-builtin-inventory'); }
  const wrappers = invocation.wrapperProgramWords || [];
  if (!Array.isArray(wrappers) || invocation.wrapped === true && wrappers.length === 0 || invocation.wrapperNames &&
      (!Array.isArray(invocation.wrapperNames) || invocation.wrapperNames.length !== wrappers.length ||
       invocation.wrapperNames.some((name, index) => name !== wrappers[index]?.name))) {
    return result('unknown-search', 'wrapper-selection-metadata-incomplete');
  }
  const literal = (word, name) => typeof name === 'string' && name.length > 0 && word &&
    typeof word.text === 'string' && !word.text.includes('\0') && path.basename(word.text) === name &&
    !word.dynamic && !word.dynamicMaySplit && !word.ansiCUnknown && !word.braceExpanded &&
    !word.globExpanded && !word.tildeExpanded;
  const external = (word, name, snapshot) => resolveExecutableIdentity(word, {
    name, cwd,
    searchMode: snapshot?.pathPresent === true && snapshot.pathChanged === false &&
      snapshot.defaultSearch === false ? 'path' : 'unknown',
    searchPath: environment && typeof environment.PATH === 'string' ? environment.PATH : undefined,
  });
  const shellPrimitives = new Set(['command', 'builtin', 'exec']);
  let externalBoundary = false;
  let reservedTimePosition = true;
  for (const entry of wrappers) {
    if (!literal(entry?.word, entry?.name)) return result('unknown-search', 'wrapper-word-not-literal');
    const bare = entry.word.text === entry.name;
    if (!externalBoundary && bare && shellPrimitives.has(entry.name)) {
      reservedTimePosition = false;
      if (entry.name === 'exec') externalBoundary = true;
      continue;
    }
    if (reservedTimePosition && !externalBoundary && bare && entry.name === 'time' && entry.word.quoted === false) continue;
    // An external launcher selecting these words cannot execute a shell builtin.
    if (externalBoundary && shellPrimitives.has(entry.name)) {
      return result('unknown-search', 'shell-primitive-after-external-boundary');
    }
    const identity = external(entry.word, entry.name, entry.executableSearch);
    if (identity.kind !== 'trusted-external') return identity;
    externalBoundary = true;
    reservedTimePosition = false;
  }
  if (!literal(invocation.nameWord, invocation.name)) return result('unknown-search', 'callee-word-not-literal');
  if (externalBoundary && shellPrimitives.has(invocation.name)) {
    return result('unknown-search', 'shell-primitive-after-external-boundary');
  }
  if (!externalBoundary && invocation.nameWord.text === invocation.name && builtins.has(invocation.name)) {
    return result('builtin', 'selected-caller-supported-shell-builtin');
  }
  return external(invocation.nameWord, invocation.name, invocation.executableSearch);
}

module.exports = { resolveExecutableIdentity, invocationExecutableIdentity };
