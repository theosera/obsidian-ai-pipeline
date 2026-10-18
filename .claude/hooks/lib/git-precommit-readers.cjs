'use strict';

// This gate concerns readers before a commit, not callbacks of the commit itself.
// Configuration values remain internal: callers receive a fixed reason, never a
// helper command, private configuration value, or configuration dump.
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync, execFileSync } = require('node:child_process');
const guard = require('./git-guard-common.cjs');

const CONFIG_PATTERN = '^(core\\.(fsmonitor|pager|hookspath|askpass|sshcommand|gitproxy)|credential(\\..*)?\\.helper|pager\\..*|diff\\.(external|.*\\.(command|textconv))|trace2\\.(normal|event|perf)target|hook\\..*\\.(event|enabled)|log\\.showsignature|format\\.pretty|pretty\\..*|branch\\.sort|includeif\\..*\\.path)$';
const CONFIG_KEY = /^(?:core\.(?:fsmonitor|pager|hookspath|askpass|sshcommand|gitproxy)|credential(?:\..*)?\.helper|pager\..+|diff\.(?:external|.+\.(?:command|textconv))|trace2\.(?:normal|event|perf)target|hook\..+\.(?:event|enabled)|log\.showsignature|format\.pretty|pretty\..+|branch\.sort|includeif\..+\.path)$/i;
const SIGNATURE_READERS = new Set(['log', 'show', 'whatchanged', 'rev-list']);
const R41_CONFIG_KEY = /^(?:core\.hookspath|hook\..+\.(?:event|enabled)|log\.showsignature|format\.pretty|pretty\..+|branch\.sort)$/i;
const DEFAULT_PAGED = new Set(['diff', 'log', 'show', 'branch', 'shortlog', 'blame', 'grep', 'whatchanged', 'reflog']);
// Revision/object readers can consult attributes, paths or an index as well.
// A read-only subcommand label is not evidence that fsmonitor cannot be reached.
const INDEX_READERS = new Set(['status', 'diff', 'diff-files', 'diff-index', 'diff-tree', 'ls-files',
  'log', 'show', 'whatchanged', 'rev-list', 'blame', 'grep', 'check-attr', 'check-ignore', 'describe', 'cat-file',
  'ls-tree', 'merge-base', 'for-each-ref', 'show-ref', 'name-rev', 'count-objects', 'var', 'cherry', 'rev-parse']);
const OBJECT_READERS = new Set(['rev-parse', 'ls-tree', 'cat-file', 'describe', 'merge-base', 'rev-list',
  'for-each-ref', 'show-ref', 'name-rev', 'count-objects', 'var', 'check-ignore', 'check-attr', 'cherry']);
const DIFF_READERS = new Set(['diff', 'diff-index', 'diff-files', 'diff-tree', 'log', 'show', 'whatchanged', 'rev-list', 'blame']);
const FALSE = /^(?:false|no|off|0)$/i;
const TRUE = /^(?:true|yes|on|1)$/i;
const unknown = reason => ({ category: 'UNKNOWN', reason });
const ROOT_ENV = new Set(['HOME', 'XDG_CONFIG_HOME', 'GIT_CONFIG', 'GIT_CONFIG_GLOBAL', 'GIT_CONFIG_SYSTEM']);
const SAFE_GIT_ENV = /^GIT_(?:DIR|WORK_TREE|COMMON_DIR|INDEX_FILE|OBJECT_DIRECTORY|ALTERNATE_OBJECT_DIRECTORIES|NAMESPACE|CEILING_DIRECTORIES|DISCOVERY_ACROSS_FILESYSTEM|CONFIG(?:_GLOBAL|_SYSTEM|_NOSYSTEM|_COUNT|_PARAMETERS|_KEY_\d+|_VALUE_\d+)?|AUTHOR_(?:NAME|EMAIL|DATE)|COMMITTER_(?:NAME|EMAIL|DATE)|PAGER|EXTERNAL_DIFF|DIFF_OPTS|OPTIONAL_LOCKS|TERMINAL_PROMPT|ATTR_(?:NOSYSTEM|SOURCE)|NO_REPLACE_OBJECTS|NO_LAZY_FETCH|REPLACE_REF_BASE|SHALLOW_FILE|(?:LITERAL|GLOB|NOGLOB|ICASE)_PATHSPECS)$/;

const INSPECTION_IRRELEVANT_GIT_ENV = /^GIT_(?:EDITOR|SEQUENCE_EDITOR|SSH|SSH_COMMAND|SSH_VARIANT|ASKPASS|PROXY_COMMAND|MERGE_AUTOEDIT)$/;

/** Do not let an inspection itself write a trace file or contact a trace socket. */
function safeInspectionEnvironment(environment) {
  const result = { ...environment };
  for (const [name, value] of Object.entries(environment)) {
    if (/^GIT_TRACE/.test(name)) {
      if (value !== '' && value !== '0' && !(/^GIT_TRACE2(?:_EVENT|_PERF)?$/.test(name) && /^false$/i.test(value))) return null;
      delete result[name];
    } else if (INSPECTION_IRRELEVANT_GIT_ENV.test(name) || name === 'SSH_ASKPASS') {
      delete result[name]; // inspection-only: selected actual-command values remain untouched
    } else if (/^GIT_/.test(name) && !SAFE_GIT_ENV.test(name)) return null;
  }
  // Unsetting is insufficient: Trace2 can otherwise fall back to system config.
  result.GIT_TRACE2 = '0'; result.GIT_TRACE2_EVENT = '0'; result.GIT_TRACE2_PERF = '0';
  // This is the inspection copy, never proof about the actual reader's source.
  result.GIT_NO_LAZY_FETCH = '1';
  return result;
}

/** A parser-proven single value; an unknown scalar can still become an option. */
function literal(word) {
  if (!word || word.ansiCUnknown || word.dynamicMaySplit === true || word.globExpanded || word.braceExpanded || word.tildeExpanded) return null;
  if (typeof word.literalValue === 'string') return word.literalValue;
  return word.dynamic === false && typeof word.text === 'string' ? word.text : null;
}
function singleDataWord(word) {
  return !!word && word.dynamicMaySplit === false && !word.ansiCUnknown && !word.globExpanded && !word.braceExpanded && !word.tildeExpanded;
}

/** Unknown attached values have two arities if their expansion can be empty. */
function attachedDataRole(g, depth) {
  for (let i = 0; i < g.args.length; i++) {
    const word = g.args[i];
    if (literal(word) !== null || !singleDataWord(word) || !word.text.includes('\0')) continue;
    const text = word.text;
    const short = (g.sub === 'grep' ? /^-[viaIriwEGFPnhHlLzocpWq0-9]*[efABCmO]/ : /^-[GSOI]/).exec(text);
    const long = (g.sub === 'grep'
      ? /^(--(?:open-files-in-pager|color|context|before-context|after-context|threads|max-depth|max-count|parent-basename))=/
      : /^(--(?:format|pretty))=/).exec(text);
    if (!short && !long) continue;
    if (long && SIGNATURE_READERS.has(g.sub)) continue; // selected format value is handled in option order below
    if (depth >= 4) return { unknown: true };
    const option = short ? short[0] : long[0];
    const value = text.slice(option.length);
    const replace = t => ({ ...g, args: g.args.map((w, index) => index === i ? {
      ...w, text: t, literalValue: t, dynamic: false, dynamicMaySplit: false,
    } : w) });
    const nonempty = operationRole(replace(option + 'DUMMY'), depth + 1);
    if (long || value.replaceAll('\0', '')) return nonempty;
    const empty = operationRole(replace(option), depth + 1);
    const merged = {};
    for (const key of Object.keys(nonempty)) {
      if (key === 'prettyFormat') merged[key] = nonempty[key] === empty[key] ? nonempty[key] : null;
      else if (key === 'signature') merged[key] = nonempty[key] === empty[key] ? nonempty[key] : nonempty[key] === true || empty[key] === true ? true : null;
      else merged[key] = key === 'query' ? nonempty[key] && empty[key] : nonempty[key] || empty[key];
    }
    return merged;
  }
  return null;
}

/** Seed values only in the late inspection; do not mark inherited HOME as a mutation. */
function environmentSources(env) {
  return Object.entries(env).filter(([name]) => guard.gitPreCommitEnvironmentName(name)).map(([name, value]) => ({
    name, word: { text: value, literalValue: value, dynamic: false, dynamicMaySplit: false },
  }));
}

const ownHookConfigByCwd = new Map();
const inspectionVersions = new Map();
/** A known installation must be the first candidate in the hook's actual search. */
function trustedGit() {
  return guard.resolveTrustedGitExecutable({ text: 'git' });
}

/** A missing tracked name is an actual removal, never an inherited fallback. */
function invocationEnvironment(invocation, baseline = process.env) {
  if (invocation.gitPreCommitEnvironmentUnknown || !Array.isArray(invocation.gitPreCommitEnvironmentSources)) return null;
  const selected = new Map();
  const env = Object.fromEntries(Object.entries(baseline).filter(([name]) => !guard.gitPreCommitEnvironmentName(name)));
  for (const source of invocation.gitPreCommitEnvironmentSources) {
    if (!guard.gitPreCommitEnvironmentName(source.name) || selected.has(source.name)) return null;
    const value = literal(source.word);
    if (value === null || value.includes('\0')) return null;
    selected.set(source.name, value);
    env[source.name] = value;
  }
  return { env, selected };
}

/** Bind staged and pathspec reads to the parsed commit's program, environment and cwd. */
function commitInspectionContext(g, invocation, baseDir) {
  if (!invocation || invocation.unknownContextBefore || invocation.pathChangedBefore ||
      g.unknownContextBefore || g.cdLikeBefore) return null;
  const selected = invocationEnvironment(invocation);
  const callee = literal(invocation.nameWord);
  if (!selected || !callee || callee === 'git' && invocation.commandDefaultSearch === true) return null;
  const cwd = guard.resolveDir(baseDir, g.cdirs || []);
  const executable = guard.resolveTrustedGitExecutable({ text: callee }, selected.env, cwd);
  const env = safeInspectionEnvironment(selected.env);
  return executable && env ? { executable, env, cwd } : null;
}

function inspectionContextKey(executable, env, cwd) {
  return JSON.stringify([executable, cwd, Object.entries(env).sort(([a], [b]) => a.localeCompare(b))]);
}
function cachedInspectionBanner(executable, environment, cwd) {
  const env = safeInspectionEnvironment(environment);
  if (!env) return '';
  env.GIT_OPTIONAL_LOCKS = '0';
  return inspectionVersions.get(inspectionContextKey(executable, env, cwd)) || '';
}

/** These overrides harden the hook's own inspection, not the proposed command. */
function inspectionArgs(args) {
  return ['--no-pager', '--no-lazy-fetch', '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null', ...args.slice(0, 1),
    ...(args[0] === 'diff' ? ['--no-ext-diff', '--no-textconv'] : []), ...args.slice(1)];
}
function readInspectionGit(args, options) {
  const executable = options?.executable;
  if (!executable || !guard.trustedGitExecutable({ text: executable })) throw new Error('trusted inspection Git unavailable');
  const env = options?.env && safeInspectionEnvironment(options.env);
  if (env) env.GIT_OPTIONAL_LOCKS = '0';
  if (!env) throw new Error('unproved inspection Git environment');
  const ownCwd = options?.cwd;
  if (typeof ownCwd !== 'string' || !path.isAbsolute(ownCwd) || ownCwd.includes('\0')) throw new Error('unproved inspection Git cwd');
  const contextKey = inspectionContextKey(executable, env, ownCwd);
  if (!inspectionVersions.has(contextKey)) {
    // The real option query qualifies this trusted backend's CLI capability;
    // the separate version floor below concerns fsmonitor boolean semantics.
    const banner = execFileSync(executable, ['--no-lazy-fetch', '--version'], {
      cwd: ownCwd, env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 2000, maxBuffer: 1024,
    });
    if (!supportsInspectionHardening(banner)) throw new Error('Git fsmonitor boolean hardening needs Git >= 2.36');
    inspectionVersions.set(contextKey, banner.trim());
  }
  // Configured hook events are separate from traditional core.hooksPath hooks.
  let configured;
  if (!ownHookConfigByCwd.has(contextKey)) {
  try {
    configured = execFileSync(executable, ['--no-pager', '--no-lazy-fetch', 'config', '--show-scope', '--null', '--get-regexp', '^hook\\..*\\.(event|enabled)$'], {
      cwd: options?.cwd, env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 2000, maxBuffer: 65536,
    });
  } catch (error) {
    if (error.status !== 1 || error.stdout?.length) throw new Error('inspection hook source unavailable');
    configured = '';
  }
  const ownConfig = configured ? parseConfigOutput(configured) : new Map();
  if (!ownConfig || configuredPostIndex(ownConfig)) throw new Error('inspection post-index-change source uninspected');
  ownHookConfigByCwd.set(contextKey, true);
  }
  return execFileSync(executable, inspectionArgs(args), { ...options, env });
}
/** Older Git can interpret core.fsmonitor=false as a hook pathname. */
function supportsInspectionHardening(banner) {
  const match = /^git version (\d+)\.(\d+)(?:\.\d+)?(?:[ .\n]|$)/.exec(banner);
  return !!match && (Number(match[1]) > 2 || Number(match[1]) === 2 && Number(match[2]) >= 36);
}

/** Literal context values with trailing nonnumeric DATA fail before paging. */
function invalidGrepContextValue(word) {
  const value = literal(word);
  return value !== null && value !== '' && !/^[\t-\r ]*[+-]?\d+$/.test(value);
}

/** A usage exit does not undo a pattern-file callback parsed before it. */
function grepUsagePrefixFileFree(g) {
  const required = ['context', 'before-context', 'after-context', 'threads', 'max-depth', 'max-count', 'parent-basename'];
  for (let k = 0; k < g.args.length; k++) {
    const text = literal(g.args[k]);
    if (text === null) return false;
    if (['--help', '--help-all'].includes(text)) return true;
    if (text === '--' || !text.startsWith('-') && !['(', ')'].includes(text)) return false;
    if (text.startsWith('--')) {
      const eq = text.indexOf('=');
      const name = text.slice(2, eq < 0 ? undefined : eq);
      if (name === 'file') return false;
      // grepPagerEffect already proves the unique long-option selection.
      // Required-value abbreviations consume a word; optional -O/color do not.
      if (required.some(full => full.startsWith(name))) {
        const value = eq < 0 ? g.args[++k] : { text: text.slice(eq + 1), dynamic: false };
        if (!singleDataWord(value) && eq < 0) return false;
        if (['context', 'before-context', 'after-context'].some(full => full.startsWith(name)) && invalidGrepContextValue(value)) return false;
      }
      continue;
    }
    if (!/^-[^-]/.test(text) || /^-\d+$/.test(text)) continue;
    for (let j = 1; j < text.length; j++) {
      if (text[j] === 'f') return false;
      if ('eABCm'.includes(text[j])) {
        const value = j + 1 === text.length ? g.args[++k] : { text: text.slice(j + 1), dynamic: false };
        if (!singleDataWord(value) && j + 1 === text.length) return false;
        if ('ABC'.includes(text[j]) && invalidGrepContextValue(value)) return false;
        break;
      }
      if (text[j] === 'O') break; // optional attached program, never the next word
    }
  }
  return false;
}

/** Classify option roles without reading configuration or running the command. */
function operationRole(g, attachmentDepth = 0) {
  const role = { index: INDEX_READERS.has(g.sub), external: g.sub === 'diff',
    textconv: ['diff', 'log', 'show', 'blame'].includes(g.sub), defaultPaged: DEFAULT_PAGED.has(g.sub),
    pagerDisabled: g.pagerDisabled === true, pagerForced: g.pagerForced === true, query: false, unknown: false,
    signature: null, prettyFormat: undefined };
  if (g.terminal && g.helpKind === 'stdout') return { ...role, index: false, external: false, textconv: false, query: !role.pagerForced };
  if (g.terminal || g.incomplete || g.dynamicOpt) return { ...role, unknown: true };
  if (g.sub === 'version') return { ...role, query: !role.pagerForced };
  if (g.sub === 'help') return { ...role, unknown: true }; // manual viewer source is not inspected
  const grepEffect = g.sub === 'grep' ? guard.grepPagerEffect(g) : null;
  if (grepEffect?.terminal && grepUsagePrefixFileFree(g)) {
    return { ...role, index: false, external: false, textconv: false, query: !role.pagerForced };
  }
  if (DIFF_READERS.has(g.sub) || g.sub === 'grep') {
    const attached = attachedDataRole(g, attachmentDepth);
    if (attached) return { ...role, ...attached };
  }
  if (grepEffect && (grepEffect.unknown || grepEffect.opensFiles)) role.unknown = true;
  if (!(DIFF_READERS.has(g.sub) || INDEX_READERS.has(g.sub) || OBJECT_READERS.has(g.sub) ||
      ['config', 'branch', 'remote', 'shortlog', 'grep', 'reflog'].includes(g.sub))) return { ...role, unknown: true };
  if (g.sub === 'branch' && g.args.some(w => literal(w) === '--show-current')) role.defaultPaged = false;
  if (g.sub === 'remote' && g.args.some(w => literal(w) === 'show') && !g.args.some(w => literal(w) === '-n')) return { ...role, unknown: true };
  if (!DIFF_READERS.has(g.sub)) {
    // Existing SG readOnlyMode has already checked config/branch/remote arity.
    if (!['config', 'branch', 'remote', 'grep'].includes(g.sub) && g.args.some(w => literal(w) === null)) role.unknown = true;
    if (g.sub === 'grep' || g.sub === 'cat-file') {
      let end = false, explicitPaths = false;
      const values = new Set(g.sub === 'grep' ? ['-e', '-f', '-A', '-B', '-C', '-m', '--context', '--before-context',
        '--after-context', '--threads', '--max-depth', '--max-count', '--parent-basename'] : ['--path']);
      const grepFlags = new Set(['cached', 'index', 'no-index', 'untracked', 'exclude-standard', 'recurse-submodules',
        'invert-match', 'ignore-case', 'word-regexp', 'text', 'textconv', 'recursive', 'extended-regexp', 'basic-regexp',
        'fixed-strings', 'perl-regexp', 'line-number', 'column', 'full-name', 'files-with-matches', 'name-only',
        'files-without-match', 'null', 'only-matching', 'count', 'break', 'heading', 'show-function', 'function-context',
        'and', 'or', 'not', 'quiet', 'all-match', 'ext-grep', 'debug', 'color', 'open-files-in-pager']);
      for (let k = 0; k < g.args.length; k++) {
        const t = literal(g.args[k]);
        if (end) {
          if (g.sub === 'grep' && t === '--') explicitPaths = true;
          else if (g.sub === 'grep' && !explicitPaths && t !== null && t.startsWith('-')) role.unknown = true;
          continue;
        }
        if (t === null) {
          // A fixed non-dash prefix proves a nonempty grep pattern operand;
          // its value cannot resume option parsing after STOP_AT_NON_OPTION.
          if (g.sub === 'grep' && singleDataWord(g.args[k]) && g.args[k].text.includes('\0') &&
              g.args[k].text[0] !== '\0' && g.args[k].text[0] !== '-') { end = true; continue; }
          role.unknown = true; continue;
        }
        if (g.sub === 'grep' && ['(', ')'].includes(t)) continue; // PARSE_OPT_NODASH expression tokens
        if (t === '--') { end = true; explicitPaths = true; continue; }
        if (g.sub === 'grep' && (!t.startsWith('-') || t === '-')) { end = true; continue; }
        const eq = t.indexOf('='); const name = eq < 0 ? t : t.slice(0, eq);
        if (values.has(name)) {
          const value = eq < 0 ? g.args[++k] : { text: t.slice(eq + 1), dynamic: false };
          if (eq < 0 && !singleDataWord(value)) role.unknown = true;
          if (g.sub === 'grep' && ['-A', '-B', '-C', '--context', '--before-context', '--after-context'].includes(name) && invalidGrepContextValue(value)) role.unknown = true;
          continue;
        }
        if (g.sub === 'grep' && /^-[^-]/.test(t) && !/^-\d+$/.test(t)) {
          for (let j = 1; j < t.length; j++) {
            if (t[j] === 'q') role.defaultPaged = false;
            if ('efABCm'.includes(t[j])) {
              const value = j + 1 === t.length ? g.args[++k] : { text: t.slice(j + 1), dynamic: false };
              if (j + 1 === t.length && !singleDataWord(value)) role.unknown = true;
              if ('ABC'.includes(t[j]) && invalidGrepContextValue(value)) role.unknown = true;
              break;
            }
            if (t[j] === 'O') break;
          }
        }
        if (g.sub === 'grep' && t.startsWith('--') && !grepFlags.has(name.slice(2)) &&
            !(name.startsWith('--no-') && grepFlags.has(name.slice(5))) &&
            !(grepEffect && !grepEffect.unknown && name.startsWith('--no-') && '--no-open-files-in-pager'.startsWith(name))) role.unknown = true;
        if (t === '--textconv') role.textconv = true;
        if (t === '--no-textconv') role.textconv = false;
        if (g.sub === 'grep' && t === '--quiet') role.defaultPaged = false;
        if (g.sub === 'grep' && t === '--no-quiet') role.defaultPaged = true;
        if (['--filters', '--batch-command'].includes(name)) role.unknown = true;
        if (g.sub === 'cat-file' && t.startsWith('-') && t !== '-' && ![
          '-t', '-s', '-e', '-p', '-z', '-Z', '--textconv', '--no-textconv', '--filters', '--batch', '--batch-check',
          '--batch-all-objects', '--buffer', '--unordered', '--use-mailmap', '--no-use-mailmap', '--follow-symlinks',
          '--allow-unknown-type', '--batch-command',
        ].includes(name)) role.unknown = true;
        if (g.sub === 'cat-file' && eq >= 0 && !['--batch', '--batch-check'].includes(name)) role.unknown = true;
      }
    }
    return role;
  }
  const values = new Set(['--output', '--diff-filter', '--find-object', '--order-file', '--skip-to', '--rotate-to',
    '--src-prefix', '--dst-prefix', '--line-prefix', '--output-indicator-new', '--output-indicator-old', '--output-indicator-context',
    '--word-diff-regex', '--anchored', '--diff-algorithm', '--inter-hunk-context', '--format', '--pretty', '--max-count',
    '--author', '--committer', '--grep', '--since', '--until', '--date', '--decorate-refs', '--decorate-refs-exclude']);
  const optionalAttached = new Set(['--format', '--pretty']);
  const flags = new Set(['--ext-diff', '--no-ext-diff', '--textconv', '--no-textconv', '--cached', '--staged', '--no-index',
    '--stat', '--numstat', '--shortstat', '--name-only', '--name-status', '--raw', '--patch', '--no-patch', '--quiet',
    '--exit-code', '--binary', '--full-index', '--check', '--relative', '--no-relative', '--color', '--no-color', '--word-diff',
    '--abbrev', '--no-renames', '--renames', '--minimal', '--patience', '--histogram', '--indent-heuristic', '--no-indent-heuristic',
    '--show-signature', '--no-show-signature', '--oneline', '--all', '--no-decorate', '--decorate', '--reverse', '--first-parent', '--no-walk', '--follow']);
  let end = false;
  for (let k = 0; k < g.args.length; k++) {
    const w = g.args[k];
    if (end) { if (!w || w.dynamicMaySplit !== false && w.dynamic) role.unknown = true; continue; }
    const t = literal(w);
    if (t === null) {
      if (SIGNATURE_READERS.has(g.sub) && singleDataWord(w) && /^--(?:format|pretty)=/.test(w.text || '')) role.prettyFormat = null;
      else role.unknown = true;
      continue;
    }
    if (t === '--') { end = true; continue; }
    if (!t.startsWith('-') || t === '-') continue;
    const eq = t.indexOf('='); const name = eq < 0 ? t : t.slice(0, eq);
    if (name === '--output') { role.unknown = true; } // an output-file effect is not a pure reader
    if (values.has(name)) {
      if (SIGNATURE_READERS.has(g.sub) && ['--format', '--pretty'].includes(name)) {
        role.prettyFormat = eq < 0 ? 'medium' : t.slice(eq + 1);
      }
      if (eq < 0 && !optionalAttached.has(name)) {
        if (!g.args[k + 1] || g.args[k + 1].dynamicMaySplit === true) role.unknown = true;
        k++;
      }
      continue;
    }
    if (['-G', '-S', '-O', '-I', '-n'].includes(t)) {
      if (!g.args[k + 1] || g.args[k + 1].dynamicMaySplit === true) role.unknown = true;
      k++; continue;
    }
    if (/^-(?:[GSOI].+|n\d+|\d+|[pquwbsz]+|[UMCBR]\d*)$/.test(t)) continue;
    if (!flags.has(name) || eq >= 0 && !['--stat', '--color', '--word-diff', '--abbrev', '--relative', '--decorate'].includes(name)) {
      role.unknown = true; continue;
    }
    if (name === '--show-signature') role.signature = true;
    if (name === '--no-show-signature') role.signature = false;
    if (name === '--oneline') role.prettyFormat = 'oneline';
    if (name === '--ext-diff') role.external = true;
    if (name === '--no-ext-diff') role.external = false;
    if (name === '--textconv') role.textconv = true;
    if (name === '--no-textconv') role.textconv = false;
  }
  return role;
}

/** Replay only proven target globals; display/identity -c keys cannot select helpers. */
function targetGlobals(g, invocation, fixedCommitUsageConsumer = false) {
  const globals = invocation.args.slice(0, invocation.args.length - g.args.length - 1);
  const result = [];
  const targets = new Set(['-C', '--git-dir', '--work-tree', '--namespace']);
  const harmless = new Set(['--bare', '--no-replace-objects', '--literal-pathspecs', '--glob-pathspecs', '--noglob-pathspecs', '--icase-pathspecs']);
  const exactCommitUsage = fixedCommitUsageConsumer && g.sub === 'commit' && g.terminal && g.helpKind === 'stdout' &&
    g.args.length === 1 && literal(g.args[0]) === '-h';
  const inline = value => {
    if (value === null || value.includes('\0')) return null;
    if (R41_CONFIG_KEY.test(value.split('=', 1)[0])) return ['-c', value];
    if (!guard.preCommitConfigKey({ configs: [value], configEnvs: [] })) return [];
    if (!exactCommitUsage) return null;
    const key = value.split('=', 1)[0].toLowerCase();
    if (!/^[a-z][a-z0-9-]*(?:\.[^\s=\0]+)+$/.test(key)) return null;
    if (/^(?:include(?:if)?\.|remote\..*\.url$|safe\.|extensions\.)/.test(key)) return null;
    if (['core.askpass', 'core.sshcommand', 'core.gitproxy'].includes(key)) return null;
    if (/^credential(?:\..*)?\.helper$/.test(key)) return [];
    if (CONFIG_KEY.test(key)) return ['-c', value]; // preserve the helper selection and its order
    if (/^core\./.test(key)) return null;
    // Only this exact commit usage on the fixed consumer exits before its
    // config/index callbacks. Setup/source selectors above remain unsupported.
    return [];
  };
  for (let i = 0; i < globals.length; i++) {
    const t = literal(globals[i]);
    if (t === null) return null;
    if (['--no-pager', '-P', '--paginate', '-p'].includes(t)) continue;
    const eq = t.indexOf('='); const name = eq < 0 ? t : t.slice(0, eq);
    if (targets.has(name)) {
      if (eq >= 0) { if (t.includes('\0')) return null; result.push(t); }
      else { const v = literal(globals[++i]); if (v === null || v.includes('\0')) return null; result.push(t, v); }
    } else if (name === '-c' || name === '--config-env') {
      const v = eq >= 0 ? t.slice(eq + 1) : literal(globals[++i]);
      if (name === '--config-env') {
        // Non-Git referenced variables are not in this environment snapshot.
        if (v === null || R41_CONFIG_KEY.test(v.split('=', 1)[0]) || guard.preCommitConfigKey({ configs: [], configEnvs: [v] })) return null;
      } else {
        const selected = inline(v); if (!selected) return null; result.push(...selected);
      }
      // Referenced unknown helper variables are never recovered from a parent env.
    } else if (t.startsWith('-c') && t.length > 2) {
      const selected = inline(t.slice(2)); if (!selected) return null; result.push(...selected);
    } else if (harmless.has(t)) result.push(t);
    else return null;
  }
  return result;
}

/** Reconstruct the selected child environment without probing an untrusted PATH. */
function readerContext(g, invocation, baseDir, deps = {}) {
  const baseline = deps.environment || process.env;
  if (invocation.gitPreCommitEnvironmentUnknown || !Array.isArray(invocation.gitPreCommitEnvironmentSources) ||
      invocation.unknownContextBefore || invocation.pathChangedBefore || g.unknownContextBefore || g.cdLikeBefore) return null;
  const reconstructed = invocationEnvironment(invocation, baseline);
  if (!reconstructed) return null;
  const { selected, env } = reconstructed;
  for (const name of ROOT_ENV) if (selected.has(name) && selected.get(name) !== baseline[name] && selected.get(name) !== '/dev/null') return null;
  if (selected.has('GIT_CONFIG')) return null; // config's source.file override is not the reader's normal config selection
  if (selected.get('GIT_CONFIG_PARAMETERS')) return null; // opaque serialization can select include/source roots
  if (selected.has('GIT_CONFIG_COUNT')) {
    const count = selected.get('GIT_CONFIG_COUNT');
    if (!/^(?:0|[1-9]\d*)$/.test(count) || Number(count) > 64) return null;
    for (let i = 0; i < Number(count); i++) {
      const key = selected.get('GIT_CONFIG_KEY_' + i);
      if (!key || !selected.has('GIT_CONFIG_VALUE_' + i) || guard.preCommitConfigKey({ configs: [key], configEnvs: [] })) return null;
    }
  }
  // Neither the probe nor the hook's binary lookup uses a command-supplied PATH.
  const callee = literal(invocation.nameWord);
  if (!callee || !(deps.isTrusted || guard.trustedGitExecutable)({ text: callee })) return null;
  // command -p uses the shell's default search, not this hook's pinned PATH.
  // No platform/default-search equivalence is inferred from a bare Git name.
  if (callee === 'git' && invocation.commandDefaultSearch === true) return null;
  if (callee === 'git' && (!selected.has('PATH') || selected.get('PATH') !== baseline.PATH)) return null;
  if (selected.has('GIT_EXEC_PATH')) return null;
  const executable = deps.executable || trustedGit();
  if (!executable) return null;
  if (callee !== 'git') {
    try { if ((deps.realpath || fs.realpathSync)(callee) !== (deps.realpath || fs.realpathSync)(executable)) return null; }
    catch { return null; }
  }
  const safeEnv = safeInspectionEnvironment(env);
  if (!safeEnv) return null;
  const inspectionBanner = cachedInspectionBanner(executable, safeEnv, guard.resolveDir(baseDir, g.cdirs || []));
  const globals = targetGlobals(g, invocation, deps.commitUsageConsumerQualified === true || inspectionBanner === 'git version 2.54.0');
  if (!globals) return null;
  return { executable, globals, cwd: baseDir, env: safeEnv, selected, inspectionBanner };
}

/** --show-scope --null emits scope NUL key LF value NUL; values stay internal. */
function parseConfigOutput(output) {
  const bytes = Buffer.isBuffer(output) ? output : Buffer.from(output || '', 'utf8');
  if (bytes.length > 65536) return null;
  const text = bytes.toString('utf8');
  if (!Buffer.from(text, 'utf8').equals(bytes) || text && !text.endsWith('\0')) return null;
  const entries = new Map();
  const postIndexNames = new Set();
  const postIndexEnabled = new Map(), branchSort = [];
  const fields = text ? text.slice(0, -1).split('\0') : [];
  if (fields.length % 2) return null;
  const trace2 = new Map();
  const credentialHelperRecords = [], gitProxyValues = [];
  let earlyConditional = false, pagerConditional = false;
  for (let i = 0; i < fields.length; i += 2) {
    const scope = fields[i], record = fields[i + 1];
    if (!['system', 'global', 'local', 'worktree', 'command'].includes(scope)) return null;
    const lf = record.indexOf('\n');
    if (lf < 1) return null;
    const rawKey = record.slice(0, lf), key = rawKey.toLowerCase();
    if (!CONFIG_KEY.test(key)) return null;
    const value = record.slice(lf + 1);
    entries.set(key, value);
    const credential = /^credential(?:\.(.*))?\.helper$/i.exec(rawKey);
    if (credential) credentialHelperRecords.push({ scope, rawKey, value, subsection: credential[1] ?? null });
    if (key === 'branch.sort') branchSort.push(value);
    if (key === 'core.gitproxy') gitProxyValues.push(value);
    const hookEvent = /^hook\.(.+)\.event$/i.exec(record.slice(0, lf));
    const hookEnabled = /^hook\.(.+)\.enabled$/i.exec(record.slice(0, lf));
    if (hookEvent && value === 'post-index-change') postIndexNames.add(hookEvent[1]);
    if (hookEnabled) postIndexEnabled.set(hookEnabled[1], value); // last effective helper value; values may contain LF
    if (/^includeif\./.test(key)) {
      pagerConditional = true;
      if (['system', 'global'].includes(scope)) earlyConditional = true;
    }
    // Trace2 starts before repository setup and consumes system/global only.
    if (/^trace2\./.test(key) && ['system', 'global'].includes(scope)) trace2.set(key, value);
  }
  Object.defineProperty(entries, 'postIndexNames', { value: postIndexNames });
  Object.defineProperty(entries, 'postIndexEnabled', { value: postIndexEnabled });
  Object.defineProperty(entries, 'branchSort', { value: branchSort });
  Object.defineProperty(entries, 'trace2EarlySources', { value: trace2 });
  Object.defineProperty(entries, 'earlyConditionalSource', { value: earlyConditional });
  Object.defineProperty(entries, 'pagerConditionalSource', { value: pagerConditional });
  Object.defineProperty(entries, 'credentialHelperRecords', { value: credentialHelperRecords });
  Object.defineProperty(entries, 'gitProxyValues', { value: gitProxyValues });
  return entries;
}

function probeConfig(context, spawn = spawnSync) {
  const r = spawn(context.executable, [...context.globals, '--no-pager', '--no-lazy-fetch', 'config', '--show-scope', '--null', '--get-regexp', CONFIG_PATTERN], {
    cwd: context.cwd, env: context.env, stdio: ['ignore', 'pipe', 'ignore'], timeout: 2000, maxBuffer: 65536,
  });
  if (r.error || r.signal || ![0, 1].includes(r.status)) return null;
  if (r.status === 1) return !r.stdout || r.stdout.length === 0 ? new Map() : null;
  return parseConfigOutput(r.stdout);
}


/** Select configured events without losing earlier values of a multi-valued key. */
function configuredPostIndex(config) {
  const names = config.postIndexNames || new Set([...config].filter(([key, value]) => /^hook\..+\.event$/.test(key) && value === 'post-index-change').map(([key]) => key.slice(5, -6)));
  return [...names].some(name => !FALSE.test((config.postIndexEnabled ? config.postIndexEnabled.get(name) : config.get('hook.' + name + '.enabled')) || 'true'));
}
/** Resolve Git's selected traditional path; never read or execute the hook body. */
function indexHookSource(context, spawn = spawnSync, access = fs.accessSync) {
  if (process.platform === 'win32') return null; // executable suffix selection is not certified here
  const r = spawn(context.executable, [...context.globals, '--no-pager', '--no-lazy-fetch', 'rev-parse', '--path-format=absolute', '--git-path', 'hooks/post-index-change'], {
    cwd: context.cwd, env: context.env, stdio: ['ignore', 'pipe', 'ignore'], timeout: 2000, maxBuffer: 4096,
  });
  if (r.error || r.signal || r.status !== 0) return null;
  const text = Buffer.isBuffer(r.stdout) ? r.stdout.toString('utf8') : r.stdout;
  if (typeof text !== 'string' || !text.endsWith('\n') || /[\r\n\0]/.test(text.slice(0, -1)) || !path.isAbsolute(text.slice(0, -1))) return null;
  try { access(text.slice(0, -1), fs.constants.X_OK); return true; }
  catch (error) { return ['ENOENT', 'ENOTDIR', 'EACCES'].includes(error.code) ? false : null; }
}
function signatureFormatActive(format, config) {
  const builtins = new Set(['oneline', 'short', 'medium', 'full', 'fuller', 'reference', 'email', 'mboxrd', 'raw']);
  for (let depth = 0; depth < 8; depth++) {
    if (typeof format !== 'string') return true;
    if (builtins.has(format) || format === '') return false;
    if (format.startsWith('format:') || format.startsWith('tformat:') || format.includes('%')) {
      for (let i = 0; i < format.length; i++) {
        if (format[i] !== '%') continue;
        if (format[i + 1] === '%') { i++; continue; }
        let j = i + 1; if ('+- '.includes(format[j] || '\0')) j++;
        if (format[j] === 'G') return true;
      }
      return false;
    }
    return true; // named aliases are an uninspected selected source (case/abbreviation included)
  }
  return true;
}

/** Ref-filter's %% escape is distinct from pretty formats and raw signature DATA. */
function refSignatureFormatActive(format) {
  if (typeof format !== 'string') return true;
  for (let i = 0; i < format.length; i++) {
    if (format[i] !== '%') continue;
    if (format[i + 1] === '%') { i++; continue; }
    if (format[i + 1] !== '(') continue;
    const end = format.indexOf(')', i + 2);
    if (end < 0) return true;
    const atom = format.slice(i + 2, end);
    if (/^\*?signature(?::|$)/.test(atom)) return true;
    i = end;
  }
  return false;
}

/** Bound the additional pretty/ref-filter consumers without treating operands as options. */
function nonLogSignatureSource(g, config) {
  const pretty = g.sub === 'shortlog';
  if (!pretty && !['for-each-ref', 'branch'].includes(g.sub)) return null;
  let format, summary = false, showCurrent = false;
  const groups = [], sorts = g.sub === 'branch'
    ? [...(config.branchSort || (config.has('branch.sort') ? [config.get('branch.sort')] : []))] : [];
  const data = new Set(pretty
    ? ['--author', '--grep', '--since', '--until', '--date', '--max-count', '-w']
    : ['--count', '--points-at', '--exclude']);
  const optional = new Set(['--contains', '--no-contains', '--merged', '--no-merged']);
  const selectors = pretty ? ['--format', '--pretty', '--group', '--summary'] : ['--format', '--sort'];
  for (let i = 0; i < g.args.length; i++) {
    const text = literal(g.args[i]);
    if (text === null) return 'unproved-non-log-format';
    if (text === '--') break;
    if (text === '-h') return null; // these consumers exit during parse-options, before formatting
    const eq = text.indexOf('='), name = eq < 0 ? text : text.slice(0, eq);
    const value = () => eq < 0 ? literal(g.args[++i]) : text.slice(eq + 1);
    if (name === '--format' || pretty && name === '--pretty') {
      format = pretty && eq < 0 ? 'medium' : value();
    } else if (g.sub === 'branch' && name === '--show-current') showCurrent = true;
    else if (g.sub === 'branch' && name === '--no-show-current') showCurrent = false;
    else if (pretty && name === '--group') {
      const group = value();
      if (group === null) return 'unproved-non-log-format';
      if (group.startsWith('format:')) groups.push(group.slice(7));
      else if (!group.startsWith('trailer:') && group.includes('%')) groups.push(group);
    } else if (pretty && name === '--no-group') groups.length = 0;
    else if (pretty && name === '--summary') summary = true;
    else if (pretty && name === '--no-summary') summary = false;
    else if (pretty && /^-[nsec]+$/.test(text)) { if (text.includes('s')) summary = true; }
    else if (!pretty && name === '--sort') sorts.push(value());
    else if (!pretty && name === '--no-sort') sorts.length = 0;
    else if (data.has(name)) { if (eq < 0 && name !== '-w') i++; }
    else if (optional.has(name)) {
      if (eq < 0 && g.args[i + 1] && !literal(g.args[i + 1])?.startsWith('-')) i++;
    } else if (name.startsWith('--') && selectors.some(full => full !== name && full.startsWith(name))) {
      return 'unproved-non-log-format'; // unproved abbreviation/arity
    }
  }
  if (showCurrent) return null; // branch exits before ref sorting/formatting
  if (pretty) {
    if ((!summary && format !== undefined && signatureFormatActive(format, config)) ||
        groups.some(value => signatureFormatActive(value, config))) return 'non-log-signature-format';
  } else if (format !== undefined && refSignatureFormatActive(format) ||
      sorts.some(value => value === null || /^-?(?:(?:version|v):)?\*?signature(?::|$)/.test(value))) return 'non-log-signature-format';
  return null;
}

/** Preserve Git's source presence priority; an empty higher command still shadows lower sources. */
function selectedSSHProgram(environment, config) {
  if (environment.has('GIT_SSH_COMMAND')) return { kind: 'env', name: 'GIT_SSH_COMMAND', value: environment.get('GIT_SSH_COMMAND') };
  if (config.has('core.sshcommand')) return { kind: 'config', value: config.get('core.sshcommand') };
  return environment.has('GIT_SSH') ? { kind: 'env', name: 'GIT_SSH', value: environment.get('GIT_SSH') } : null;
}

/** Both consumer paths must stop before the lower SSH_ASKPASS is reachable.
 * Pinned POSIX Git exec preparation rejects an empty selected SSH program; it
 * does not substitute native ssh. Windows execution is not qualified here. */
function sshAskpassShadowed(environment, config, ssh, qualified) {
  const gitAskpass = environment.has('GIT_ASKPASS') ? environment.get('GIT_ASKPASS')
    : config.has('core.askpass') ? config.get('core.askpass') : null;
  return qualified && process.platform !== 'win32' && gitAskpass === '' && ssh?.value === '';
}

/** Remote hosts are unproved for lazy fetch. Keep every potentially first
 * matching command; only a prior disabling match can remove its domain. */
function gitProxySource(environment, config) {
  if (environment.has('GIT_PROXY_COMMAND')) return environment.get('GIT_PROXY_COMMAND') !== '';
  if (!Array.isArray(config.gitProxyValues)) return config.has('core.gitproxy');
  const disabledDomains = [];
  for (const value of config.gitProxyValues) {
    const index = value.indexOf(' for ');
    const command = index < 0 ? value : value.slice(0, index);
    const domain = index < 0 ? null : value.slice(index + 5);
    if (domain !== null && disabledDomains.some(previous => domain === previous || domain.endsWith('.' + previous))) continue;
    if (command !== '' && command !== 'none') return true;
    if (domain === null) return false; // first unconditional disabling value wins
    disabledDomains.push(domain);
  }
  return false;
}

/** URL matching is unproved here; only the same original subsection can reset its candidates. */
function credentialHelperSource(config) {
  if (!Array.isArray(config.credentialHelperRecords)) {
    return [...config.keys()].some(key => /^credential(?:\..*)?\.helper$/i.test(key));
  }
  let selected = [];
  for (const record of config.credentialHelperRecords) {
    if (record.value !== '') selected.push(record);
    else if (record.subsection === null) selected = [];
    else selected = selected.filter(previous => previous.subsection !== record.subsection);
  }
  return selected.length !== 0;
}

/** Select active helper roles, not raw helper command strings. */
function selectedHelper(role, g, environment, config, baseline = process.env, emptySSHConsumerQualified = false) {
  const traceNames = ['GIT_TRACE2', 'GIT_TRACE2_EVENT', 'GIT_TRACE2_PERF'];
  const explicitlyOff = value => typeof value === 'string' && (value === '0' || /^false$/i.test(value));
  if (config.earlyConditionalSource && !traceNames.every(name => environment.has(name) && explicitlyOff(environment.get(name)))) return 'early-trace-source';
  const trace2 = config.trace2EarlySources || new Map([...config].filter(([key]) => /^trace2\./.test(key)));
  for (const [key, value] of trace2) {
    const name = { 'trace2.normaltarget': 'GIT_TRACE2', 'trace2.eventtarget': 'GIT_TRACE2_EVENT', 'trace2.perftarget': 'GIT_TRACE2_PERF' }[key];
    const selected = name && environment.has(name) && environment.get(name) !== '' ? environment.get(name) : value;
    if (selected !== '' && selected !== '0' && !/^false$/i.test(selected)) return 'trace2';
  }
  // Object/index readers can lazily fetch missing promisor objects, including
  // through another repository. Their bounded probe does not prove transport
  // inactivity. Inheritance or baseline equality is not proof that a program is inactive.
  if (!role.query && (role.index || DIFF_READERS.has(g.sub) || ['branch', 'shortlog', 'reflog'].includes(g.sub))) {
    for (const name of ['GIT_SSH', 'GIT_SSH_COMMAND', 'GIT_SSH_VARIANT', 'GIT_ASKPASS', 'SSH_ASKPASS']) {
      if (environment.has(name) && environment.get(name) !== baseline[name]) return 'command-selected-transport';
    }
    const ssh = selectedSSHProgram(environment, config);
    const inheritedProgram = name => environment.get(name) && environment.get(name) === baseline[name];
    if (ssh?.kind === 'config' && ssh.value) return 'configured-ssh-command';
    if (ssh?.kind === 'env' && inheritedProgram(ssh.name) || inheritedProgram('GIT_ASKPASS') || inheritedProgram('SSH_ASKPASS') && !sshAskpassShadowed(environment, config, ssh, emptySSHConsumerQualified)) return 'inherited-transport-program';
    if (!environment.has('GIT_ASKPASS') && config.get('core.askpass')) return 'configured-askpass';
    if (credentialHelperSource(config)) return 'credential-helper';
    if (gitProxySource(environment, config)) return 'git-proxy';
  }
  const nonLog = !role.query && nonLogSignatureSource(g, config);
  if (nonLog) return nonLog;
  if (SIGNATURE_READERS.has(g.sub) && !role.query) {
    if (role.signature === true || role.signature === null && TRUE.test(config.get('log.showsignature') || 'false')) return 'signature-verifier';
    const format = role.prettyFormat === undefined ? config.get('format.pretty') : role.prettyFormat;
    if (format !== undefined && signatureFormatActive(format, config)) return 'signature-format';
  }
  const monitor = config.get('core.fsmonitor');
  if (role.index && monitor !== undefined && !FALSE.test(monitor) && monitor !== '') return 'fsmonitor';
  if (role.external && (environment.has('GIT_EXTERNAL_DIFF') || config.has('diff.external') ||
      [...config.keys()].some(k => /^diff\..+\.command$/.test(k)))) return 'external-diff';
  if (role.textconv && [...config.keys()].some(k => /^diff\..+\.textconv$/.test(k))) return 'textconv';
  if (g.sub === 'version' && !role.pagerForced) return null; // no RUN_SETUP / per-command pager selection
  if (role.pagerDisabled) return null;
  if (config.pagerConditionalSource && !(environment.has('GIT_PAGER') && ['', 'cat'].includes(environment.get('GIT_PAGER')))) return 'early-pager-source';
  // A global -p sets use_pager before check_pager_config: that branch does not
  // consume pager.<cmd>, even if its value is a normally harmless literal cat.
  const perCommand = role.pagerForced ? undefined : config.get('pager.' + g.sub);
  const active = role.pagerForced || (perCommand !== undefined ? !FALSE.test(perCommand) : !role.query && role.defaultPaged);
  if (!active) return null;
  const pager = environment.has('GIT_PAGER') ? environment.get('GIT_PAGER')
    : perCommand !== undefined && !TRUE.test(perCommand) && !FALSE.test(perCommand) ? perCommand
      : config.has('core.pager') ? config.get('core.pager') : environment.has('PAGER') ? environment.get('PAGER') : null;
  // Git treats these exact pager strings as no paging; no program lookup occurs.
  return pager === '' || pager === 'cat' ? null : pager === null ? 'default-pager' : 'pager';
}

function assessReader(g, invocation, baseDir, deps = {}) {
  const role = operationRole(g);
  if (role.unknown) return unknown('commit 前の Git 読取の mode / option role を確定できません。');
  // Other reader labels are not a source-independent purity proof. Observe the
  // bounded configuration even when their ordinary pager mode is disabled.
  const context = readerContext(g, invocation, baseDir, deps);
  if (!context) return unknown('commit 前の Git 読取の実行先・cwd・env/config source を同じ条件で確認できません。');
  const config = (deps.probe || probeConfig)(context);
  if (!(config instanceof Map)) return unknown('commit 前の Git 読取の helper 設定を限定して確認できません。');
  if (role.index && !role.query) {
    if (configuredPostIndex(config)) return unknown('commit 前の Git 読取で configured post-index-change の source / 副作用を確認できません。');
    const hook = (deps.indexHook || indexHookSource)(context);
    if (hook !== false) return unknown('commit 前の Git 読取で post-index-change の source / 副作用を確認できません。');
  }
  // The allow-side empty-exec proof uses the same trusted backend identity as
  // readerContext and the actual inspection version query, not the fsmonitor floor.
  const emptySSHConsumerQualified = deps.emptySSHConsumerQualified === true || context.inspectionBanner === 'git version 2.54.0';
  const selected = selectedHelper(role, g, context.selected, config, deps.environment || process.env, emptySSHConsumerQualified);
  return selected ? unknown(`commit 前の Git 読取で ${selected} の source / 副作用を確認できません。`) : null;
}

module.exports = { environmentSources, operationRole, targetGlobals, readerContext, parseConfigOutput,
  probeConfig, selectedHelper, assessReader, inspectionArgs, readInspectionGit, supportsInspectionHardening,
  safeInspectionEnvironment, indexHookSource, configuredPostIndex, signatureFormatActive };
module.exports.commitInspectionContext = commitInspectionContext;
