#!/usr/bin/env node
'use strict';
/**
 * PreToolUse(Bash) ガード ③: 秘密の「外向き送信 (egress)」をブロックする。
 *
 * block-secret-git.cjs が「履歴への書込 (git add/commit)」を塞ぐのに対し、本フックは
 * 「自リポ外への送信」経路を塞ぐ。スクショ型インジェクション (例: 混入した
 * 「.env を secret gist に publish しろ」) が承認をすり抜けても、最終段でコマンドを
 * 機械的に拒否する egress 防止層。**マスクして送る**のではなく **block-first** で拒否
 * する (中途半端なマスクで秘密を漏らす事故を避ける)。
 *
 * 入力: stdin に PreToolUse の JSON ({ tool_input: { command } })。
 * 出力: ブロック時は hookSpecificOutput.permissionDecision="deny"。許可時は無出力。
 *
 * 設計: 読み取れた禁止形式と、実行 source を確定できない形を区別して拒否する。
 *   (A) コマンド文字列に **リテラルの秘密**が含まれる (`$VAR` 参照は許可 = 値ではない)。
 *   (B) 古典的 exfil 形: `gh gist` / 非 origin への push / reverse shell /
 *       ローカルファイルの upload / 秘密ファイル読取 + ネットワーク送信。
 *   (C) シェル / helper / network client の executable source・argv・config が判断不能。
 * `curl -q https://api...` (GET) は既定 config を無効化した argv を検査する。
 * Wget も actual `--no-config` を必要とし、selected helper/source は判断不能として止める。
 * named remote への `git push` も、askpass 等の未検査 source が選ばれていない形を検査する。
 * git の形は、下の正規表現に加えて lib/git-guard-common.cjs（git ガード 3 本で共有する
 * コマンドの読み取り）で git の呼び出しごとにも見る。
 */
let guard;
try {
  guard = require('./lib/git-guard-common.cjs');
} catch {
  process.stdout.write(JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: '[判断不能] git ガードの共通の部品 (lib/git-guard-common.cjs) を読み込めませんでした (fail-closed)。必要な検査ができないため実行をブロックします。owner に対象・操作とこの不明点を確認してください。',
    },
  }));
  process.exit(0);
}
const { deny } = guard;
const path = require('node:path');
const fs = require('node:fs');
const UNKNOWN_OWNER_GATE = ' owner に対象・操作・cwd・env/config/source と不明点を確認してください。個別操作の承認は hook 無効化の許可ではありません。';

// (A) リテラル秘密。`$GITHUB_TOKEN` 等の env 参照は値ではないので **当たらない**
// (値クラスに `$` を含めない / 代入値が `$` 始まりなら除外)。ops-logging の mask()
// 規則と整合。新形式を足したらここと Python 版・mask() を同時に更新する。
const SECRET_LITERALS = [
  /gh[pousr]_[A-Za-z0-9]{20,}/,                 // GitHub token
  /github_pat_[A-Za-z0-9_]{20,}/,               // GitHub fine-grained PAT
  /\bsk-[A-Za-z0-9_-]{20,}/,                     // OpenAI / Anthropic style (incl. sk-proj-)
  /\bAIza[0-9A-Za-z_-]{35}/,                     // Google API key (Gmail / YouTube)
  /\bAKIA[0-9A-Z]{16}\b/,                        // AWS access key id
  /\bxox[baprs]-[A-Za-z0-9-]{10,}/,             // Slack
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,         // PEM private key
  /:\/\/[^/\s:@]+:[^/\s@]{3,}@/,                 // URL 埋め込み user:pass@
  /Authorization:\s*Bearer\s+[A-Za-z0-9._-]{10,}/i,
  // KEY=<literal value> 形 (値が `$` 始まり = env 参照なら除外)。
  /(CLIENT_SECRET|REFRESH_TOKEN|API_KEY|ACCESS_TOKEN|PRIVATE_KEY|PASSWORD|GMAIL_CLIENT_SECRET)\s*[=:]\s*['"]?(?!\$)[A-Za-z0-9._\-/+]{8,}/i,
];

// `git` と subcommand の間には global option (`-c k=v` / `-C <dir>` / `--git-dir=…`) を
// 何個でも挟めるので、それを跨いで subcommand に当てる。block-git-add-all.cjs の
// GIT_OPTS と同一定義 (片方だけ古くなると穴が戻るため、変えるときは両方同時に)。
const GIT_OPTS = '(?:\\s+(?:-[cC]\\s*\\S+|--(?:git-dir|work-tree|exec-path|namespace)=\\S+|--no-pager|--bare|--paginate))*';
const gitRe = (tail) => new RegExp(`\\bgit${GIT_OPTS}\\s+${tail}`);

// (B) 古典的 exfil 形。
// SCP's textual copy backstop is checked after argv inspection; only a proven single
// receive/local operation is exempted. SFTP and every other raw backstop stay independent.
const SCP_TEXT_COPY_SHAPE = /\bscp\b[^\n]*\s[^\s]+:[^\s]/;
const EXFIL_SHAPES = [
  /\bgh\s+gist\b/,                                       // gh gist create/...
  /\b(nc|ncat)\b[^\n]*\s-e\b/,                           // reverse shell
  gitRe('remote\\s+add\\b'),                             // 外部 remote 追加
  gitRe('remote\\s+set-url\\b'),                         // 既存 remote (origin) の向き先すげ替え
  // 同上 (git config 経由)。⚠️ URL キーの **後に値が続く形 = 書き込み** だけを対象にする。
  // `git config remote.origin.url` / `git config --get remote.origin.url` は読み取りなので通す。
  gitRe('config\\b[^\\n]*\\bremote\\.[^\\s]+\\.url\\s+[^\\s;&|]'),
  // 明示 URL への push (named remote でない)。URL は `push` の直後とは限らない
  // (`git push --force <url>` / `git push '<url>'`) ので引数列のどこでも当てる。
  // named remote への push には URL 形のトークンが無いため誤検知しない。
  gitRe('push\\b[^;&|]*\\s[\'"]?(https?://|git@|ssh://|git://)'),
  /\bcurl\b[^\n]*\s(--data-binary|--upload-file|-T|-F|-d|--data)\b[^\n]*@/,  // ローカルファイル upload
  /\bsftp\b[^\n]*\s[^\s]+:[^\s]/,
  /\brsync\b[^\n]*\s[^\s]+:[^\s]/,
];

// (B') 秘密ファイル読取 + ネットワーク送信の組合せ (例: `cat .env | curl ...`)。
// 対象は block-secret-git.cjs の SECRET_RE / vault-ops の SECRET_ERE と揃える
// (CLAUDE.md「secret-pattern 4 系統を 1 PR で同時更新」)。
const SECRET_FILE_RE = /(\.env(\.|\b)|x_tokens\.json|pkce_state\.json|pipeline_config\.json|credentials[^/\s]*\.json|service-account[^/\s]*\.json|[^/\s]*token[^/\s]*\.json|\.pem\b|\.key\b|id_(rsa|ed25519)\b|secrets\.(json|ya?ml)\b|(^|[\s'"/=])secrets\/)/i;
const NET_VERB_RE = /\b(curl|wget|nc|ncat|scp|sftp|rsync|telnet)\b|\bgh\s+gist\b/i;
/** Remove exact template basename evidence while retaining every other secret family's markers. */
function withoutTemplateTokens(evidence, depth = 0) {
  if (!/\.env\.example/i.test(evidence) || depth > 16) return evidence;
  const parsed = guard.parseShell(evidence);
  const ranges = [];
  const sourceWords = parsed.cmds.flatMap((command) => command.words.concat(command.redirs.map((redir) => redir.word)))
    .filter((word) => evidence.slice(word.start, word.start + word.raw.length) === word.raw);
  const codeSources = new Map();
  const inspected = guard.inspect(evidence);
  for (const invocation of inspected.invocations) for (const script of invocation.trapScripts
    .concat(invocation.aliasScripts || [], invocation.expansionScripts || [], sshCommandSources(invocation))) {
    if (!script.dynamic) codeSources.set(`${script.start}:${script.raw}`, script.text);
  }
  for (const word of sourceWords) {
    const config = /^credential(?:\..+)?\.helper=(.*)$/is.exec(word.text);
    if (config) codeSources.set(`${word.start}:${word.raw}`, config[1].startsWith('!') ? config[1].slice(1) :
      config[1].startsWith('/') ? config[1] : `__credential_helper__${config[1]}`);
  }
  for (const g of inspected.gits) if (g.sub === 'config') {
    const operation = configOperation(g.args);
    if (!operation.read && !operation.rename && !operation.deletion && operation.operands.length > 1 && /^credential(?:\..+)?\.helper$/i.test(operation.operands[0])) {
      const word = operation.operandWords[1];
      codeSources.set(`${word.start}:${word.raw}`, word.text.startsWith('!') ? word.text.slice(1) :
        word.text.startsWith('/') ? word.text : `__credential_helper__${word.text}`);
    }
  }
  const markers = (source, offset) => {
    for (const match of source.matchAll(/(^|[^A-Za-z0-9_.-])(\.env\.example)(?=$|[^A-Za-z0-9_.-])/gi)) {
      const start = offset + match.index + match[1].length;
      ranges.push({ start, end: start + match[2].length });
    }
  };
  for (const command of parsed.cmds) {
    for (const word of command.words.concat(command.redirs.map((redir) => redir.word))) {
      const filename = word.text.startsWith('@') ? word.text.slice(1) : word.text;
      const assignment = /^[A-Za-z_][A-Za-z0-9_]*\+?=(.*)$/.exec(filename);
      const templateFilename = /(^|\/)\.env\.example$/i.test(assignment ? assignment[1] : filename);
      const index = command.words.indexOf(word);
      const previous = index > 0 ? command.words[index - 1].text : '';
      const headerData = command.words.slice(0, index).some((entry) => /(^|\/)curl$/.test(entry.text)) &&
        ['-H', '--header', '--proxy-header'].includes(previous);
      const codeSource = codeSources.get(`${word.start}:${word.raw}`);
      const cleanSource = codeSource === undefined ? null : withoutTemplateTokens(codeSource, depth + 1);
      const templateDataSource = cleanSource !== null && cleanSource !== codeSource && !SECRET_FILE_RE.test(cleanSource);
      if ((word.dynamic && !templateDataSource) || (!templateFilename && !headerData && !templateDataSource)) continue;
      const start = word.start;
      const end = start + word.raw.length;
      // Nested sources can use relative offsets. Remove only a matching whole word in this source.
      if (evidence.slice(start, end) !== word.raw ||
          (start > 0 && !/[\s;&|<>()]/.test(evidence[start - 1])) ||
          (end < evidence.length && !/[\s;&|<>()]/.test(evidence[end]))) continue;
      if (headerData || templateDataSource) { markers(word.raw, start); continue; }
      // Keep path prefixes: a template filename must not hide a secrets/ or key-name marker.
      const literal = word.raw.toLowerCase().indexOf('.env.example', word.raw.lastIndexOf('/') + 1);
      if (literal >= 0) ranges.push({ start: start + literal, end: start + literal + '.env.example'.length });
    }
    // Quoted input to a file reader is literal data. Remove only template markers in that body.
    if (!command.words[0] || !/(^|\/)(?:cat|head|tail|base64|xxd)$/.test(command.words[0].text)) continue;
    for (const heredoc of command.heredocBodies) {
      if (!heredoc.quoted || !heredoc.body) continue;
      let start = evidence.indexOf(heredoc.body);
      while (start >= 0 && sourceWords.some((word) => word.start < start + heredoc.body.length &&
          word.start + word.raw.length > start)) start = evidence.indexOf(heredoc.body, start + 1);
      if (start >= 0) markers(heredoc.body, start);
    }
  }
  ranges.sort((a, b) => b.start - a.start || b.end - a.end);
  let result = evidence;
  let nextStart = evidence.length;
  for (const range of ranges) {
    if (range.end > nextStart) continue; // duplicate/overlapping entries must not erase adjacent evidence
    result = result.slice(0, range.start) + result.slice(range.end);
    nextStart = range.start;
  }
  return result;
}

const { cmd, baseDir } = guard.readInput('egress ガード');
if (!cmd) process.exit(0);

if (SECRET_LITERALS.some((re) => re.test(cmd))) {
  deny(
    'コマンド文字列が secret literal inventory の形 (token / key / client secret 等) に当たります。\n' +
    '文字列だけでは実行内容を確認できないためブロックしました (egress guard)。対応する env 変数参照 ($VAR) を検討できますが、' +
    '送信操作や hook 回避の許可ではありません。必要な操作は owner に対象・内容を確認してください。',
  );
}

if (EXFIL_SHAPES.some((re) => re.test(cmd))) {
  deny(
    '文字列に外向き送信に似た形 (gist / URL への push / reverse shell / ファイル upload 等) が含まれています。\n' +
    '実際の操作・引数をこの照合だけでは確認できないためブロックしました (egress guard)。' +
    '必要な操作は owner に対象・操作・cwd・env/config/source と不明点を確認してください。',
  );
}

// Check the required network shape before the raw filename inventory; long unrelated words
// must not spend the hook deadline in a filename-only backstop which cannot deny this input.
if (NET_VERB_RE.test(cmd) && SECRET_FILE_RE.test(withoutTemplateTokens(cmd))) {
  deny(
    '秘密ファイル名の形 (.env / *token*.json / *.key 等) とネットワーク名が同じ文字列に含まれています。\n' +
    '読取から送信への関係をこの照合だけでは確認できないためブロックしました (egress guard)。owner に対象・操作・cwd・source を確認してください。',
  );
}

// git の形を、git の呼び出しごとにも見る（global option や引用符を挟んだ形も同じに読む）。
// Modern and legacy Bash function environment formats are positive source selectors.
// Inspect only selector names here; never log or execute their environment bodies.
const inheritedFunctionNames = [...new Set(Object.entries(process.env).flatMap(([name, value]) => {
  const modern = /^BASH_FUNC_(.+)%%$/.exec(name);
  return modern ? [modern[1]] : /^[A-Za-z_][A-Za-z0-9_]*$/.test(name) && /^\(\)\s*\{/.test(value) ? [name] : [];
}))];
const insp = guard.inspect(cmd, {
  initialHelperEnvNames: ['VISUAL', 'EDITOR', 'RSYNC_RSH', 'BASH_ENV', 'ENV', 'SHELLOPTS', 'POSIXLY_CORRECT', 'GIT_EXTERNAL_DIFF', 'GIT_ASKPASS', 'SSH_ASKPASS', 'WGET_ASKPASS']
    .filter(name => process.env[name] !== undefined),
  initialGitIdentityEnvNames: ['GIT_AUTHOR_NAME', 'GIT_AUTHOR_EMAIL', 'GIT_AUTHOR_DATE', 'GIT_COMMITTER_NAME', 'GIT_COMMITTER_EMAIL', 'GIT_COMMITTER_DATE', 'EMAIL'].filter(name => process.env[name] !== undefined),
  initialGitHttpEnvNames: ['GIT_HTTP_USER_AGENT'].filter(name => process.env[name] !== undefined),
  initialGitHttpSources: ['GIT_HTTP_USER_AGENT'].filter(name => process.env[name] === '').map(name =>
    ({ name, word: { text: '', raw: "''", quoted: true, dynamic: false, dynamicMaySplit: false } })),
  initialGitConfigEnvNames: Object.keys(process.env).filter(name => /^(?:GIT_CONFIG_(?:COUNT|PARAMETERS|GLOBAL|SYSTEM|(?:KEY|VALUE)_\d+)|GIT_CONFIG)$/.test(name)),
  initialGitConfigSources: ['GIT_CONFIG_GLOBAL', 'GIT_CONFIG_SYSTEM', 'GIT_CONFIG'].filter(name => process.env[name] !== undefined).map(name =>
    ({ name, word: { text: '__inherited_default_git_config_root__', dynamic: false, dynamicMaySplit: false, implicitGitConfigRoot: true } }))
    .concat(['GIT_CONFIG_COUNT', 'GIT_CONFIG_PARAMETERS', ...Object.keys(process.env).filter(name => /^GIT_CONFIG_KEY_\d+$/.test(name))].filter(name => process.env[name] === '' || name === 'GIT_CONFIG_COUNT' && /^\d+$/.test(process.env[name] || '') || /^GIT_CONFIG_KEY_\d+$/.test(name) && /^[A-Za-z][A-Za-z0-9.-]*$/.test(process.env[name] || '')).map(name =>
      ({ name, word: { text: process.env[name], dynamic: false, dynamicMaySplit: false } }))),
  initialPagerEnvNames: ['GIT_PAGER', 'PAGER'].filter(name => process.env[name] !== undefined),
  initialShellStartupEnvNames: ['BASH_ENV', 'ENV'].filter(name => process.env[name] !== undefined),
  initialShellStartupSources: ['BASH_ENV', 'ENV'].filter(name => process.env[name] === '').map(name =>
    ({ name, word: { text: '', raw: "''", quoted: true, dynamic: false, dynamicMaySplit: false } })),
  initialGhEnvNames: ['GH_REPO', 'GH_HOST', 'GH_EDITOR', 'GH_BROWSER', 'GH_PAGER', 'GH_CONFIG_DIR', 'BROWSER', 'HOME', 'XDG_CONFIG_HOME', 'AppData']
    .filter(name => process.env[name] !== undefined),
  // Retain only the existing non-executing empty/cat pager controls; other inherited bodies stay unknown.
  initialGhSources: ['GH_PAGER'].filter(name => ['', 'cat'].includes(process.env[name])).map(name =>
    ({ name, word: { text: process.env[name], raw: "'" + process.env[name] + "'", quoted: true, dynamic: false, dynamicMaySplit: false } }))
    .concat(['HOME', 'XDG_CONFIG_HOME', 'AppData'].filter(name => process.env[name] !== undefined).map(name =>
      ({ name, word: { text: process.env[name] === '' ? '' : '__inherited_default_config_root__', raw: "'__inherited_default_config_root__'",
        quoted: true, dynamic: false, dynamicMaySplit: false, defaultGhConfigRoot: true } }))),
  initialPagerSources: ['PAGER', 'GIT_PAGER'].filter(name => ['', 'cat'].includes(process.env[name])).map(name =>
    ({ name, word: { text: process.env[name], raw: "'" + process.env[name] + "'", quoted: true, dynamic: false, dynamicMaySplit: false } })),
  initialPromptEnvPresent: process.env.PS4 !== undefined,
  initialTraceMode: process.env.SHELLOPTS === undefined ? false : null,
  initialFunctionSourceNames: inheritedFunctionNames,
  initialExportedFunctionNames: inheritedFunctionNames,
});
if (insp.problems.length) deny(guard.problemMessage(insp.problems, 'egress ガード') + UNKNOWN_OWNER_GATE);
const URL_ARG_RE = /^(https?:\/\/|ssh:\/\/|git:\/\/|git@)/;
// Git は最初の `:` より前に `/` が無い宛先を scp 形と読む。`./a:b` はローカル。
const SCP_ARG_RE = /^[^/:]+:/;
const REMOTE_URL_KEY_RE = /^remote\..+\.(?:url|pushurl)$/i;
/** Require a static word before treating an existing refusal as a confirmed prohibited form. */
function knownWord(word) {
  return Boolean(word && !word.dynamic && !word.ansiCUnknown && !word.text.includes('\0'));
}

/** Executable text needs both known bytes and one proven argv boundary before reparsing it. */
function literalSourceWord(word) {
  if (!word || word.dynamicMaySplit || word.ansiCUnknown || word.globExpanded || word.braceExpanded || word.tildeExpanded) return null;
  if (knownWord(word)) return word;
  return typeof word.literalValue === 'string' && word.dynamicMaySplit === false && !word.literalValue.includes('\0')
    ? { ...word, text: word.literalValue, dynamic: false } : null;
}

/** Bash's first help/version option exits before startup source or stdin is evaluated. */
function terminalBashQuery(invocation) {
  return invocation.name === 'bash' && knownInvocationContext(invocation) && knownWord(invocation.args[0]) &&
    ['--help', '--version'].includes(invocation.args[0].text);
}

/** A single literal here-string or quoted heredoc on proven fd 0 has a supported source proof. */
function shellStdinSource(invocation) {
  if (invocation.pipelineParticipant || invocation.heredocBodies.length + invocation.redirs.length !== 1) return null;
  const source = invocation.redirs[0] || invocation.heredocBodies[0];
  // Parser provenance must establish default/0 FD. It never infers a missing FD from
  // dropped argv, an allocated {fd}, or a body whose competing redirection order is unknown.
  if (!source.fdKnown || source.fd !== null && source.fd !== '0') return null;
  if (invocation.heredocBodies.length) return source.quoted
    ? { text: source.body, initialPositionals: invocation.shellPositionals } : null;
  if (source.op !== '<<<' || !literalSourceWord(source.word)) return null;
  return { ...literalSourceWord(source.word), initialPositionals: invocation.shellPositionals };
}

/** Downgrade evidence when executable identity or preceding context is not established by this parser. */
function knownInvocationContext(invocation) {
  const executable = invocation.nameWord?.text || '';
  return !invocation.dynamicName && !invocation.launcherUnknown && !invocation.incomplete &&
    !invocation.pathChangedBefore && !invocation.unknownContextBefore && !invocation.cdLikeBefore &&
    !invocation.envUnknown && !invocation.unsafeGroupSetup &&
    (!executable.includes('/') || ['/usr/bin/' + invocation.name, '/bin/' + invocation.name].includes(executable));
}

/** Preserve a helper's refusal while making uncertain command context explicit. */
function contextualVerdict(invocation, verdict) {
  return verdict === 'FORBIDDEN' && !knownInvocationContext(invocation) ? 'UNKNOWN' : verdict;
}

/** Stop at the same first matching invocation as the previous boolean some() checks. */
function firstVerdict(invocations, inspect) {
  for (const invocation of invocations) {
    const verdict = inspect(invocation);
    if (verdict) return verdict;
  }
  return false;
}
/** Return whether a repository argument uses a network URL or Git's scp syntax. */
function destinationArg(value) {
  return URL_ARG_RE.test(value) || (!/^file:\/\//i.test(value) && SCP_ARG_RE.test(value));
}

/** Copy clients use their own host:path syntax, never Git's local file:// exception. */
function remoteCopyAddressRole(name, value) {
  if (typeof value !== 'string' || !value || /[\0\r\n]/.test(value)) return 'UNKNOWN';
  const uri = /^([A-Za-z][A-Za-z0-9+.-]*):\/\//.exec(value);
  const scheme = uri?.[1].toLowerCase();
  if (scheme === (name === 'scp' ? 'scp' : 'rsync')) {
    try {
      const url = new URL(value);
      if (!url.hostname || url.password || url.port && (Number(url.port) < 1 || Number(url.port) > 65535) ||
          /[\s%]/.test(value) || name === 'rsync' && !url.pathname.split('/')[1]) return 'UNKNOWN';
      return 'REMOTE';
    } catch { return 'UNKNOWN'; }
  }
  // file: is a host specification in these parsers. Other URI-like formats have
  // no supported native format proof here and cannot establish a local operation.
  if (scheme && scheme !== 'file') return 'UNKNOWN';
  let colon = -1;
  if (name === 'scp') {
    if (value[0] === ':') return 'LOCAL';
    let bracket = value[0] === '[';
    for (let k = 0; k < value.length; k++) {
      if (value[k] === '@' && value[k + 1] === '[') bracket = true;
      if (value[k] === ']' && value[k + 1] === ':' && bracket) { colon = k + 1; break; }
      if (value[k] === ':' && !bracket) { colon = k; break; }
      if (value[k] === '/') break;
    }
  } else {
    const first = value.search(/[:/]/);
    if (first >= 0 && value[first] === ':') colon = first;
  }
  if (colon < 0) return 'LOCAL';
  const host = value.slice(0, colon).split('@').at(-1);
  return /^(?:[A-Za-z0-9_.][A-Za-z0-9_.-]*|\[[0-9A-Fa-f:.]+\])$/.test(host) ? 'REMOTE' : 'UNKNOWN';
}

/**
 * Locate the push repository without mistaking a refspec (`HEAD:main`) for scp.
 * Skip option values and honor --repo, including attached values and abbreviations.
 */
function pushRepository(words) {
  let positional;
  let explicit;
  let afterDD = false;
  let indeterminate = false;
  const payloadWords = [];
  const valueOpts = ['repo', 'receive-pack', 'exec', 'recurse-submodules', 'push-option'];
  for (let k = 0; k < words.length; k++) {
    const w = words[k];
    const t = w.text;
    if (!positional && w.dynamic && w.dynamicMaySplit !== false) indeterminate = true;
    if (!afterDD && t === '--') { afterDD = true; continue; }
    if (!afterDD && t.startsWith('--')) {
      const eq = t.indexOf('=');
      const name = t.slice(2, eq < 0 ? undefined : eq);
      const matches = valueOpts.filter((option) => option.startsWith(name));
      if (matches.length === 1) {
        const value = eq < 0 ? words[++k] : { ...w, text: t.slice(eq + 1) };
        if (!value) indeterminate = true;
        if (!positional && eq < 0 && value && value.dynamic && value.dynamicMaySplit !== false) indeterminate = true;
        if (matches[0] === 'repo') explicit = value;
        if (matches[0] === 'push-option') payloadWords.push(value);
      } else if (!positional && w.dynamic) indeterminate = true;
      continue;
    }
    if (!afterDD && t.startsWith('-')) {
      // -o と、前に値を取らない short option を束ねた形 (`-vo value`)。
      if (/^-[vqdnfu46]*o/.test(t)) {
        if (/^-[vqdnfu46]*o$/.test(t)) {
          const value = words[++k];
          payloadWords.push(value);
          if (!value) indeterminate = true;
          if (!positional && value && value.dynamic && value.dynamicMaySplit !== false) indeterminate = true;
        } else payloadWords.push({ ...w, text: t.slice(t.indexOf('o') + 1) });
      } else if (!positional && w.dynamic) indeterminate = true;
      continue;
    }
    if (!afterDD && !positional && w.dynamic) indeterminate = true;
    if (!positional) positional = w;
  }
  // --repo は位置引数の repository が無い時だけ使われる。
  return { repository: positional || explicit, indeterminate, payloadWords };
}

/** Preserve the existing destination/transport uncertainty for every push payload decision. */
function unknownPushDestination(g, push = pushRepository(g.args)) {
  const repo = push.repository;
  return push.indeterminate || Boolean(repo?.dynamic) ||
    g.configEnvs.some(config => destinationConfig(config.split('=')[0])) ||
    g.configs.some(config => transportConfig(config.split('=')[0]) || /^include(?:if\..+)?\.path$/i.test(config.split('=')[0])) ||
    g.gitEnvNames.some(name => /^GIT_CONFIG(?:_|$)/.test(name) || /^GIT_(?:SSH(?:_COMMAND)?|PROXY_COMMAND)$/.test(name));
}

/** Read config actions and operands without treating option values or getter patterns as writes. */
function configOperation(words) {
  const valueOpts = ['file', 'blob', 'type', 'default', 'value', 'url', 'comment'];
  const operands = [];
  const operandWords = [];
  let read = false;
  let afterDD = false;
  let actionSeen = false;
  let rename = false;
  let deletion = null;
  let unknownOption = false;
  let edit = false;
  let terminal = false;
  for (let k = 0; k < words.length; k++) {
    const word = words[k];
    const t = word.text;
    // An unresolved option can consume a later getter flag instead of selecting that read action.
    if (!afterDD && t.startsWith('-')) {
      const eq = t.indexOf('=');
      const shortValue = /^-[z]*[fbt]/.exec(t);
      const optionName = t.startsWith('--') && eq >= 0 ? t.slice(0, eq) : shortValue ? shortValue[0] : t;
      if (optionName.includes('\0') || word.ansiCUnknown || word.globExpanded || word.braceExpanded ||
          (word.dynamic && word.dynamicMaySplit !== false)) unknownOption = true;
    }
    if (!afterDD && t === '--') { afterDD = true; continue; }
    if (!afterDD && ['-h', '--help'].includes(t) && !word.dynamic && !word.ansiCUnknown) {
      terminal = true;
      continue;
    }
    if (!afterDD && t.startsWith('--')) {
      const eq = t.indexOf('=');
      const name = t.slice(2, eq < 0 ? undefined : eq);
      if (valueOpts.some((option) => option.startsWith(name))) {
        if (eq < 0) k++;
        continue;
      }
      if (name.startsWith('ren') && 'rename-section'.startsWith(name)) rename = true;
      if (name.startsWith('uns') && ['unset', 'unset-all'].some((option) => option.startsWith(name))) deletion = 'key';
      if (name.startsWith('rem') && 'remove-section'.startsWith(name)) deletion = 'section';
      if (name.startsWith('ed') && 'edit'.startsWith(name)) edit = true;
      if (/^(?:--get(?:-all|-regexp|-urlmatch|-color|-colorbool)?|--list)$/.test(t)) read = true;
      continue;
    }
    if (!afterDD && t.startsWith('-')) {
      if (/^-[z]*[fbt]$/.test(t)) k++;
      if (t === '-l') read = true;
      if (/^-[zl]*e/.test(t)) edit = true;
      continue;
    }
    if (!afterDD && !actionSeen && ['get', 'list', 'unset', 'remove-section', 'set', 'rename-section', 'edit'].includes(t)) {
      actionSeen = true;
      rename = t === 'rename-section';
      deletion = t === 'unset' ? 'key' : t === 'remove-section' ? 'section' : null;
      read = ['get', 'list'].includes(t);
      edit = t === 'edit';
      continue;
    }
    operands.push(t);
    operandWords.push(words[k]);
    // config は key 以降を value / value-pattern として扱う（--get という値もある）。
    afterDD = true;
  }
  return { read, rename, deletion, operands, operandWords, unknownOption, edit, terminal: terminal && !unknownOption };
}

/** Classify destination writes while keeping getters and consumed option values outside the refusal. */
function writesDestinationConfig(words) {
  const { read, rename, deletion, operands, operandWords, unknownOption } = configOperation(words);
  if (unknownOption) return 'UNKNOWN';
  // Removing a selected destination exposes fallback URLs/configuration just like replacing it.
  if (deletion) {
    if (!(operands.length > 0 && (operandWords[0].dynamic ||
        (deletion === 'key' ? destinationConfig(operands[0]) || editorConfig(operands[0])
          : destinationSection(operands[0]) || /^(?:core|sequence)$/i.test(operands[0]))))) return false;
    if (deletion === 'section' || !knownWord(operandWords[0])) return 'UNKNOWN';
  } else {
    const key = operandWords[0];
    if (!read && !rename && key &&
        (operands.length > 1 || key.dynamicMaySplit !== false || key.globExpanded || key.braceExpanded) &&
        (!knownWord(key) || key.globExpanded || key.braceExpanded || key.tildeExpanded)) return 'UNKNOWN';
    if (!read && operands.length > 1 && (editorConfig(operands[0]) ||
        (rename && /^(?:core|sequence)$/i.test(operands[0])))) return 'UNKNOWN';
    if (!(!read && operands.length > 1 && (rename ?
        operandWords[1].dynamic || destinationSection(operands[1]) : destinationConfig(operands[0])))) return false;
    if (rename || !knownWord(operandWords[0])) return 'UNKNOWN';
  }
  // An include or transport key selects executable/config source whose effect is not inspected here.
  return editorConfig(operands[0]) || transportConfig(operands[0]) || /^include(?:if\..+)?\.path$/i.test(operands[0]) ? 'UNKNOWN' : 'FORBIDDEN';
}

/** Editor configuration chooses executable source, including a fallback exposed by deletion. */
function editorConfig(key) { return /^(?:core|sequence)\.editor$/i.test(key); }

/** Read actual editor-relevant options, keeping required option values and refs after -- as DATA. */
function gitEditorOptions(g, required, shortValues, flags) {
  let afterDD = false;
  let unknown = Boolean(g.incomplete);
  const selected = new Set();
  for (let k = 0; k < g.args.length; k++) {
    const word = g.args[k];
    const text = word.text;
    if (word.dynamic || word.ansiCUnknown || word.globExpanded || word.braceExpanded) unknown = true;
    if (!afterDD && text === '--') { afterDD = true; continue; }
    if (afterDD || !text.startsWith('-')) continue;
    if (text.startsWith('--')) {
      const eq = text.indexOf('=');
      const name = text.slice(2, eq < 0 ? undefined : eq);
      if (required.includes(name)) { if (eq < 0) k++; continue; }
      if (!flags.includes(name) || eq >= 0) { unknown = true; continue; }
      selected.add(name);
    } else {
      for (let p = 1; p < text.length; p++) {
        if (shortValues.includes(text[p])) { if (p === text.length - 1) k++; break; }
        selected.add(text[p]);
      }
    }
  }
  return { selected, unknown };
}

/** Stop operations which can invoke an uninspected message or sequence editor. */
function gitEditorCanRun(g) {
  if (g.terminal) return false;
  if (g.sub === 'commit') return guard.parseCommitArgs(g.args).editorMayRun !== false;
  if (g.sub === 'merge' || g.sub === 'pull') return guard.parseMergeMessageArgs(g.args).editorMayRun !== false;
  if (g.sub === 'config') {
    const operation = configOperation(g.args);
    return operation.edit && !operation.terminal;
  }
  if (g.sub === 'rebase') {
    const parsed = gitEditorOptions(g, ['onto', 'strategy', 'strategy-option', 'exec', 'rebase-merges', 'update-refs', 'empty'], 'sxX',
      ['interactive', 'edit-todo', 'continue', 'abort', 'quit', 'skip', 'show-current-patch', 'help', 'no-edit', 'no-interactive',
        'root', 'force-rebase', 'no-ff', 'fork-point', 'no-fork-point', 'keep-base', 'reapply-cherry-picks', 'no-reapply-cherry-picks',
        'autosquash', 'no-autosquash', 'autostash', 'no-autostash', 'keep-empty', 'no-keep-empty', 'rebase-merges', 'no-rebase-merges',
        'apply', 'merge', 'quiet', 'verbose', 'stat', 'no-stat', 'committer-date-is-author-date', 'ignore-date', 'reset-author-date']);
    return parsed.unknown || ['interactive', 'edit-todo', 'continue', 'skip', 'i', 'e'].some(flag => parsed.selected.has(flag));
  }
  if (g.sub === 'cherry-pick' || g.sub === 'revert') {
    const parsed = gitEditorOptions(g, ['mainline', 'strategy', 'strategy-option', 'cleanup'], 'mX',
      ['edit', 'no-edit', 'continue', 'abort', 'quit', 'skip', 'no-commit', 'signoff', 'allow-empty', 'allow-empty-message',
        'keep-redundant-commits', 'ff', 'rerere-autoupdate', 'no-rerere-autoupdate', 'help']);
    if (parsed.unknown) return true;
    if (['abort', 'quit', 'help', 'no-commit', 'n'].some(flag => parsed.selected.has(flag))) return false;
    if (parsed.selected.has('edit') || parsed.selected.has('e') || parsed.selected.has('continue') || parsed.selected.has('skip')) return true;
    return g.sub === 'revert' && !parsed.selected.has('no-edit');
  }
  if (g.sub === 'am') {
    if (g.operationRole && ['query', 'cleanup'].includes(g.operationRole.mode) && !g.operationRole.unknown) return false;
    const parsed = gitEditorOptions(g, ['patch-format', 'directory', 'exclude', 'include', 'whitespace', 'reject'], 'pC',
      ['interactive', 'continue', 'resolved', 'abort', 'quit', 'skip', 'help', 'signoff', '3way', 'quiet', 'keep', 'keep-non-patch',
        'message-id', 'no-message-id', 'scissors', 'no-scissors', 'utf8', 'no-utf8', 'committer-date-is-author-date', 'ignore-date']);
    return parsed.unknown || ['interactive', 'continue', 'resolved', 'skip', 'i', 'e'].some(flag => parsed.selected.has(flag));
  }
  if (g.sub === 'branch') {
    const parsed = gitEditorOptions(g, ['format', 'sort', 'contains', 'no-contains', 'merged', 'no-merged', 'track'], '',
      ['edit-description', 'list', 'show-current', 'help', 'all', 'remotes', 'verbose', 'delete', 'force', 'move', 'copy']);
    return parsed.unknown || parsed.selected.has('edit-description');
  }
  if (g.sub === 'add' || g.sub === 'stage') {
    const parsed = guard.parseAddArgs(g.args);
    if (parsed.terminal) return false;
    const flags = gitEditorOptions(g, ['chmod', 'pathspec-from-file', 'unified', 'inter-hunk-context'], 'U',
      ['edit', 'interactive', 'patch', 'all', 'update', 'force', 'verbose', 'dry-run', 'intent-to-add', 'refresh', 'renormalize',
        'ignore-errors', 'ignore-missing', 'no-warn-embedded-repo', 'sparse', 'pathspec-file-nul']);
    return ['edit', 'interactive', 'patch', 'e', 'i', 'p'].some(flag => flags.selected.has(flag));
  }
  return false;
}

/** Bash socket paths are an unsupported native network channel, even without a network executable. */
function nativeSocketRedirection(invocation) {
  return invocation.redirs.some(redir => {
    if (['<<<', '<<', '<<-'].includes(redir.op)) return false;
    const word = redir.word;
    if (!word) return true;
    const text = typeof word.literalValue === 'string' && word.dynamicMaySplit === false ? word.literalValue : word.text;
    if (/^\/dev\/(?:tcp|udp)\//.test(text)) return true;
    if (!word.dynamic && !word.ansiCUnknown) return false;
    const prefix = text.split('\0')[0];
    return !prefix || ['/dev/tcp/', '/dev/udp/'].some(pathname => pathname.startsWith(prefix) || prefix.startsWith(pathname));
  });
}

/** mapfile/readarray callbacks are executable source, never ordinary delimiter/count option DATA. */
function quotedAttachedOptionValue(word, text, shortValues, longValues = []) {
  if (!word.dynamic || word.dynamicMaySplit !== false || word.ansiCUnknown || word.globExpanded || word.braceExpanded) return false;
  if (text.startsWith('--')) {
    const eq = text.indexOf('=');
    return eq >= 0 && longValues.includes(text.slice(2, eq));
  }
  if (!text.startsWith('-')) return false;
  for (let p = 1; p < text.length; p++) {
    if (text[p] === '\0') return false;
    if (shortValues.includes(text[p])) return true;
  }
  return false;
}

function arrayReaderCallback(invocation) {
  if (!['mapfile', 'readarray'].includes(invocation.name)) return false;
  let unknown = Boolean(invocation.incomplete);
  for (let k = 0; k < invocation.args.length; k++) {
    const word = invocation.args[k];
    const text = typeof word.literalValue === 'string' && word.dynamicMaySplit === false ? word.literalValue : word.text;
    if (word.dynamic && typeof word.literalValue !== 'string' && !quotedAttachedOptionValue(word, text, 'dnOsuCc') ||
        word.ansiCUnknown || word.globExpanded || word.braceExpanded) unknown = true;
    if (text === '--') return unknown;
    if (text === '--help') return unknown;
    if (!text.startsWith('-')) break;
    for (let p = 1; p < text.length; p++) {
      if (text[p] === 'C') return true;
      if ('dnOsuc'.includes(text[p])) {
        const value = p + 1 < text.length ? { ...word, text: text.slice(p + 1) } : invocation.args[++k];
        if (value?.dynamic && value.dynamicMaySplit !== false || value?.globExpanded || value?.braceExpanded) unknown = true;
        break;
      }
    }
  }
  return unknown;
}

// rsync uses popt: these value options can also appear after copy operands.
// Destination and selected-helper inspection must consume exactly the same values.
const RSYNC_VALUE_LONG = new Set(['rsh', 'rsync-path', 'filter', 'include', 'exclude', 'include-from', 'exclude-from', 'files-from',
    'compare-dest', 'copy-dest', 'link-dest', 'password-file', 'address', 'port', 'timeout', 'contimeout', 'bwlimit',
    'chown', 'chmod', 'usermap', 'groupmap', 'out-format', 'log-file', 'backup-dir', 'suffix', 'temp-dir', 'remote-option',
    'block-size', 'max-size', 'min-size', 'max-delete', 'modify-window', 'sockopts', 'skip-compress', 'compress-level']);
const RSYNC_FLAG_LONG = new Set(['archive', 'recursive', 'links', 'copy-links', 'copy-unsafe-links', 'safe-links', 'copy-dirlinks',
    'keep-dirlinks', 'perms', 'executability', 'acls', 'xattrs', 'owner', 'group', 'devices', 'specials', 'hard-links',
    'times', 'omit-dir-times', 'super', 'fake-super', 'sparse', 'dry-run', 'whole-file', 'no-whole-file', 'one-file-system',
    'existing', 'ignore-existing', 'remove-source-files', 'delete', 'delete-before', 'delete-during', 'delete-delay',
    'delete-after', 'delete-excluded', 'ignore-errors', 'force', 'partial', 'delay-updates', 'checksum', 'update',
    'inplace', 'append', 'append-verify', 'relative', 'no-implied-dirs', 'dirs', 'quiet', 'verbose', 'progress', 'stats',
    'numeric-ids', 'human-readable', 'itemize-changes', 'cvs-exclude', 'ignore-times', 'size-only', 'ipv4', 'ipv6', 'list-only']);
const RSYNC_VALUE_SHORT = 'efBMT';
const RSYNC_FLAG_SHORT = 'avrlpgoDHtOUJSLkKNnWxuzqsIbcdRACEXyih46';

/** A selected rsync remote shell is opaque local executable source; a proven local copy does not select it. */
function rsyncRemoteHelper(invocation) {
  if (invocation.name !== 'rsync') return false;
  const values = RSYNC_VALUE_LONG;
  const flags = RSYNC_FLAG_LONG;
  let selected = (invocation.helperEnvNames || []).includes('RSYNC_RSH');
  let unknown = Boolean(invocation.incomplete);
  let remote = false;
  let afterDD = false;
  for (let k = 0; k < invocation.args.length; k++) {
    const word = invocation.args[k];
    const text = typeof word.literalValue === 'string' && word.dynamicMaySplit === false ? word.literalValue : word.text;
    if (word.dynamic && typeof word.literalValue !== 'string' && !quotedAttachedOptionValue(word, text, RSYNC_VALUE_SHORT, [...values]) ||
        word.ansiCUnknown || word.globExpanded || word.braceExpanded) unknown = true;
    if (!afterDD && text === '--') { afterDD = true; continue; }
    if (!afterDD && ['--help', '--version'].includes(text)) return selected && unknown;
    if (!afterDD && text.startsWith('--')) {
      const eq = text.indexOf('=');
      const name = text.slice(2, eq < 0 ? undefined : eq);
      if (name === 'rsh') selected = true;
      if (values.has(name)) {
        const value = eq < 0 ? invocation.args[++k] : { ...word, text: text.slice(eq + 1) };
        if (value?.dynamic && value.dynamicMaySplit !== false || value?.globExpanded || value?.braceExpanded) unknown = true;
      } else if (!flags.has(name)) unknown = true;
      continue;
    }
    if (!afterDD && text.startsWith('-')) {
      for (let p = 1; p < text.length; p++) {
        if (RSYNC_VALUE_SHORT.includes(text[p])) {
          if (text[p] === 'e') selected = true;
          const value = p + 1 < text.length ? { ...word, text: text.slice(p + 1) } : invocation.args[++k];
          if (value?.dynamic && value.dynamicMaySplit !== false || value?.globExpanded || value?.braceExpanded) unknown = true;
          break;
        }
        if (!RSYNC_FLAG_SHORT.includes(text[p])) unknown = true;
      }
      continue;
    }
    const role = remoteCopyAddressRole('rsync', text);
    if (role === 'UNKNOWN') unknown = true;
    if (role === 'REMOTE') remote = true;
  }
  return selected && (remote || unknown);
}

/** Reconstruct credential-helper shell commands only for consumers or persistent helper writes. */
function credentialHelperSources(g) {
  const helperKey = (key) => /^credential(?:\..+)?\.helper$/i.test(key);
  const action = g.args.find((word) => !word.text.startsWith('-'));
  const consumes = ['push', 'fetch', 'pull', 'clone', 'ls-remote'].includes(g.sub) ||
    (g.sub === 'credential' && action && ['fill', 'approve', 'reject'].includes(action.text)) ||
    (g.sub === 'remote' && action && ['show', 'update'].includes(action.text)) ||
    (g.sub === 'submodule' && action && ['add', 'update'].includes(action.text));
  const values = [];
  if (consumes) {
    if (g.configEnvs.some((config) => helperKey(config.split('=')[0]))) {
      deny('credential helper の source が --config-env の値から作られ、egress ガードで検査できません (fail-closed)。' + UNKNOWN_OWNER_GATE);
    }
    for (const config of g.configs) {
      const eq = config.indexOf('=');
      const key = eq < 0 ? config : config.slice(0, eq);
      if (!helperKey(key)) continue;
      const value = eq < 0 ? '' : config.slice(eq + 1);
      if (!value && /^credential\.helper$/i.test(key)) values.length = 0;
      else if (value) values.push(value);
    }
  }
  if (g.sub === 'config') {
    const operation = configOperation(g.args);
    if (!operation.read && !operation.rename && !operation.deletion && operation.operands.length > 1 && helperKey(operation.operands[0])) {
      values.push(operation.operands[1]);
    }
  }
  return values.filter(Boolean).map((helper) => {
    if (helper.includes('\0')) deny('credential helper の source が変数・置換を含み、egress ガードで検査できません (fail-closed)。' + UNKNOWN_OWNER_GATE);
    // A neutral parser prefix represents Git's trusted named-helper dispatch while preserving shell suffix code.
    return { text: helper.startsWith('!') ? helper.slice(1) : helper.startsWith('/') ? helper : `__credential_helper__${helper}`,
      mediated: true,
      gitContext: consumes ? g : null };
  });
}

/** Askpass can run for remote reads as well as pushes; only proven local queries do not select it. */
function gitAskpassSource(g, invocation) {
  const envSelected = (invocation?.helperEnvNames || []).some(name => ['GIT_ASKPASS', 'SSH_ASKPASS'].includes(name)) ||
    g.gitEnvNames.some(name => name === 'GIT_ASKPASS');
  const configSelected = [...g.configs, ...g.configEnvs].some(config => /^core\.askpass(?:=|$)/i.test(config));
  if (!envSelected && !configSelected) return false;
  if (g.terminal && g.helpKind === 'stdout' && knownInvocationContext(invocation)) return false;
  const localQueries = new Set(['status', 'log', 'diff', 'show', 'rev-parse', 'ls-files', 'ls-tree', 'cat-file',
    'describe', 'shortlog', 'blame', 'grep', 'merge-base', 'rev-list', 'for-each-ref', 'show-ref', 'name-rev',
    'count-objects', 'var', 'version', 'check-ignore', 'check-attr', 'cherry', 'whatchanged',
    'diff-tree', 'diff-index', 'diff-files']);
  const local = localQueries.has(g.sub) || g.sub === 'config' && configOperation(g.args).read;
  return !local || !knownInvocationContext(invocation) || g.dynamicOpt || g.incomplete;
}

/** Establish disabling/query flags by option roles, never by a consumed value or pathspec. */
function gitDiffModes(g) {
  let external = g.sub === 'diff';
  let textconv = ['diff', 'show', 'log'].includes(g.sub);
  let unknown = !!(g.incomplete || g.dynamicOpt);
  const values = new Set(['output', 'diff-filter', 'find-object', 'order-file', 'skip-to', 'rotate-to',
    'src-prefix', 'dst-prefix', 'line-prefix', 'output-indicator-new', 'output-indicator-old', 'output-indicator-context',
    'word-diff-regex', 'anchored', 'diff-algorithm', 'inter-hunk-context', 'ignore-submodules', 'submodule',
    'format', 'pretty', 'max-count', 'author', 'committer', 'grep', 'since', 'until', 'date', 'decorate-refs', 'decorate-refs-exclude']);
  const flags = new Set(['ext-diff', 'no-ext-diff', 'textconv', 'no-textconv', 'cached', 'staged', 'no-index',
    'stat', 'numstat', 'shortstat', 'name-only', 'name-status', 'raw', 'patch', 'no-patch', 'quiet', 'exit-code',
    'binary', 'full-index', 'check', 'relative', 'no-relative', 'color', 'no-color', 'word-diff', 'abbrev',
    'no-renames', 'renames', 'minimal', 'patience', 'histogram', 'indent-heuristic', 'no-indent-heuristic']);
  const attachedOnly = new Set(['format', 'pretty', 'ignore-submodules', 'submodule']);
  const dataBoundary = word => Boolean(word && word.dynamicMaySplit === false && !word.ansiCUnknown &&
    !word.globExpanded && !word.braceExpanded && !word.tildeExpanded);
  for (let k = 0; k < g.args.length; k++) {
    const word = g.args[k];
    const text = word.text;
    if (text === '--') break;
    if (text === '-h' && !unknown) return { terminal: true, external: false, textconv: false };
    if (text.startsWith('--')) {
      const eq = text.indexOf('=');
      const name = text.slice(2, eq < 0 ? undefined : eq);
      if (values.has(name)) {
        // Formatting values are optional and attached. A following --ext-diff is
        // an actual selector; quoted scalar values inside --format= remain DATA.
        const value = eq < 0 ? attachedOnly.has(name) ? word : g.args[++k] : word;
        if (!dataBoundary(value) || !dataBoundary(word)) unknown = true;
      } else if (!flags.has(name) || !knownWord(word)) unknown = true;
      else if (eq < 0) {
        if (name === 'ext-diff') external = true;
        if (name === 'no-ext-diff') external = false;
        if (name === 'textconv') textconv = true;
        if (name === 'no-textconv') textconv = false;
      }
    } else if (text.startsWith('-') && text !== '-') {
      if (/^-[nOSGU]$/.test(text)) { if (!knownWord(word) || !dataBoundary(g.args[++k])) unknown = true; }
      else if (/^-[nOSG].+/.test(text)) { if (!dataBoundary(word)) unknown = true; }
      else if (!knownWord(word) || !/^-(?:[puwsRabc]|[UMCB][0-9]*|[0-9]+)+$/.test(text)) unknown = true;
    } else if (!knownWord(word)) unknown = true;
  }
  return { terminal: g.terminal && g.helpKind === 'stdout', external: external || unknown, textconv: textconv || unknown };
}

/** Select an archive format only from real argv roles; filenames and config values remain DATA. */
function gitArchiveFormat(g) {
  let format = 'tar';
  let explicit = false;
  let output = null;
  let terminal = false;
  let unknown = Boolean(g.incomplete);
  let afterDD = false;
  const values = new Set(['format', 'prefix', 'output', 'remote', 'exec', 'add-file', 'add-virtual-file']);
  for (let k = 0; k < g.args.length; k++) {
    const word = g.args[k];
    const literal = literalSourceWord(word);
    const text = literal ? literal.text : word.text;
    if (!afterDD && text === '--') { afterDD = true; continue; }
    if (afterDD || !text.startsWith('-')) continue;
    if (!afterDD && ['-l', '--list', '-h'].includes(text) && literal) { terminal = true; continue; }
    let option;
    let value;
    if (text.startsWith('--')) {
      const eq = text.indexOf('=');
      option = text.slice(2, eq < 0 ? undefined : eq);
      if (values.has(option)) value = eq < 0 ? g.args[++k] : { ...word, text: text.slice(eq + 1), literalValue: literal ? text.slice(eq + 1) : undefined };
      else if (!['verbose', 'worktree-attributes'].includes(option) && !/^-?[0-9]+$/.test(option)) unknown = true;
    } else if (/^-[o]/.test(text)) {
      option = 'output';
      value = text.length > 2 ? { ...word, text: text.slice(2), literalValue: literal ? text.slice(2) : undefined } : g.args[++k];
    } else if (!/^-(?:v|[0-9])+$/.test(text)) unknown = true;
    if (option && values.has(option) && !value) unknown = true;
    if (option === 'format') { explicit = true; if (literalSourceWord(value)) format = literalSourceWord(value).text; else unknown = true; }
    if (option === 'output') { if (literalSourceWord(value)) output = literalSourceWord(value).text; else if (!explicit) unknown = true; }
    if (!literal && !(option && value && word.dynamicMaySplit === false)) unknown = true;
  }
  if (!explicit && output) format = output.endsWith('.tar.gz') || output.endsWith('.tgz') ? 'tar.gz' :
    output.endsWith('.tar') ? 'tar' : output.includes('.') ? output.slice(output.lastIndexOf('.') + 1) : 'tar';
  return { format, unknown, terminal: terminal && !unknown };
}

/** Fsmonitor callback selections only matter for operations which consume or refresh an index. */
function gitIndexHelperActive(g) {
  const indexOperations = new Set(['status', 'diff', 'diff-files', 'diff-index', 'add', 'stage', 'commit',
    'update-index', 'checkout', 'switch', 'restore', 'reset', 'merge', 'pull', 'rebase', 'cherry-pick',
    'revert', 'stash', 'clean', 'ls-files', 'read-tree', 'write-tree', 'apply', 'rm', 'mv', 'am']);
  return indexOperations.has(g.sub);
}

/** Selected pager programs are executable source only for an operation which can page. */
function gitPagerSource(g, invocation) {
  if (g.pagerDisabled || g.terminal && g.helpKind === 'stdout') return false;
  const config = g.configs.filter(value => value.split('=')[0].toLowerCase() === 'pager.' + g.sub).at(-1);
  const commandSelection = config ? config.slice(config.indexOf('=') + 1) : null;
  const commandEnv = g.configEnvs.some(value => value.split('=')[0].toLowerCase() === 'pager.' + g.sub);
  const defaultPager = ['log', 'show', 'diff', 'branch', 'tag', 'help', 'shortlog', 'blame', 'grep', 'whatchanged', 'range-diff'].includes(g.sub);
  const active = g.pagerForced || commandEnv || commandSelection !== null && !/^(?:false|no|off|0)$/i.test(commandSelection) ||
    defaultPager && (commandSelection === null || !/^(?:false|no|off|0)$/i.test(commandSelection));
  if (!active) return false;
  const env = new Map((invocation.gitPagerEnvSources || []).map(source => [source.name, source.word]));
  const enabledProgram = word => { const literal = literalSourceWord(word); return !literal || !['', 'cat'].includes(literal.text); };
  if (env.has('GIT_PAGER')) return enabledProgram(env.get('GIT_PAGER'));
  if (commandEnv) return true;
  if (commandSelection !== null && !/^(?:true|yes|on|1|false|no|off|0)$/i.test(commandSelection)) {
    return !['', 'cat'].includes(commandSelection);
  }
  const core = g.configs.filter(value => value.split('=')[0].toLowerCase() === 'core.pager').at(-1);
  if (g.configEnvs.some(value => value.split('=')[0].toLowerCase() === 'core.pager')) return true;
  if (core !== undefined) return !['', 'cat'].includes(core.slice(core.indexOf('=') + 1));
  if (env.has('PAGER')) return enabledProgram(env.get('PAGER'));
  return commandSelection !== null;
}

/** IMAP folder values consume option-like DATA; only a proven stdout help flag is terminal. */
function imapSendRole(g) {
  let unknown = Boolean(g.incomplete || g.dynamicOpt);
  let terminal = false;
  let afterDD = false;
  const folders = [];
  for (let k = 0; k < g.args.length; k++) {
    const word = g.args[k], literal = literalSourceWord(word), text = literal?.text || word.text;
    if (!afterDD && text === '--' && literal) { afterDD = true; continue; }
    if (afterDD || !text.startsWith('-')) { unknown = true; continue; }
    if (text === '-h' && literal) { terminal = true; continue; }
    if (text === '--folder' || text.startsWith('--folder=') || /^-f/.test(text)) {
      const value = text === '--folder' || text === '-f' ? g.args[++k] :
        { ...word, text: text.startsWith('--folder=') ? text.slice(9) : text.slice(2) };
      folders.push(value);
      if (!literal || !literalSourceWord(value)) unknown = true;
    } else if (!literal || !['-q', '-v', '--quiet', '--verbose', '--curl', '--no-curl', '--draft', '--no-draft', '--list'].includes(text)) unknown = true;
  }
  return { terminal: terminal && !unknown, stdin: !(terminal && !unknown), unknown, folders };
}

/** Cookie input is conditional on HTTP/format/server matching, so uninspected files stay UNKNOWN. */
function gitHttpCookieVerdict(g) {
  const role = guard.gitHttpCookieRole(g);
  if (!role) return false;
  const repository = literalSourceWord(role.repositoryWord);
  if (role.argvUnknown) return 'UNKNOWN';
  const rewriteSelected = [...(g.configs || []), ...(g.configEnvs || [])].some(value => /^url\..+\.insteadof(?:=|$)/i.test(value));
  if (!role.configEnvironmentUnknown && repository && /^(?:ssh:\/\/|git:\/\/|git@|file:\/\/|\/|\.\.?\/)/.test(repository.text) &&
      !rewriteSelected) return false;
  let target;
  try { if (!repository || !/^https?:\/\//i.test(repository.text) || /[%*]/.test(repository.text)) return 'UNKNOWN'; target = new URL(repository.text); }
  catch { return 'UNKNOWN'; }
  const matches = [];
  for (const setting of role.settings) {
    if (!setting.scope) { matches.push({ ...setting, rank: [-1, -1], exact: false }); continue; }
    let scope;
    try {
      if (/[%*]/.test(setting.scope)) return 'UNKNOWN';
      scope = new URL(setting.scope);
      if (scope.search || scope.hash || scope.password) return 'UNKNOWN';
    } catch { return 'UNKNOWN'; }
    if (scope.protocol !== target.protocol || scope.hostname !== target.hostname || scope.port !== target.port ||
        scope.username && scope.username !== target.username) continue;
    const part = scope.pathname.replace(/\/$/, '');
    if (part && target.pathname !== part && !target.pathname.startsWith(part + '/')) continue;
    const exact = scope.pathname === target.pathname && scope.username === target.username;
    matches.push({ ...setting, rank: [part.length, scope.username ? 1 : 0], exact });
  }
  if (!matches.length) return role.configEnvironmentUnknown ? 'UNKNOWN' : false;
  matches.sort((a, b) => a.rank[0] - b.rank[0] || a.rank[1] - b.rank[1] || a.order - b.order);
  const selected = matches.at(-1), word = literalSourceWord(selected.word);
  // An exact URL-specific final empty value outranks unseen generic/path-prefix
  // values. Generic empty alone does not certify an unseen URL-specific fallback.
  if (selected.exact && ['value', 'env', 'configuration-env'].includes(selected.mode) && word?.text === '' && !g.dynamicOpt && !role.configEnvironmentUnknown && !rewriteSelected) return false;
  return 'UNKNOWN';
}

/** Generated HTTP metadata is DATA; opaque selection/source remains UNKNOWN, never inferred safe. */
function gitHttpMetadataVerdict(g, invocation) {
  const role = guard.gitHttpMetadataRole(g);
  if (!role) return false;
  const repository = literalSourceWord(role.repositoryWord);
  const rewriteSelected = [...(g.configs || []), ...(g.configEnvs || [])].some(value => /^url\..+\.insteadof(?:=|$)/i.test(value));
  if (repository && /^(?:ssh:\/\/|git:\/\/|git@|file:\/\/|\/|\.\.?\/)/.test(repository.text) && !rewriteSelected && !role.configEnvironmentUnknown) return false;
  let target;
  try { if (repository && /^https?:\/\//i.test(repository.text) && !/[%*]/.test(repository.text)) target = new URL(repository.text); } catch {}
  const unknownFields = new Set();
  const selected = { extraheader: [], useragent: [] }, ranks = {};
  for (const setting of role.settings) {
    let rank = [-1, -1], exact = false;
    if (setting.scope) {
      let scope;
      try { if (!target || /[%*]/.test(setting.scope)) throw Error('opaque URL scope'); scope = new URL(setting.scope); if (scope.search || scope.hash || scope.password) throw Error('opaque URL scope'); }
      catch { unknownFields.add(setting.field); continue; }
      if (scope.protocol !== target.protocol || scope.hostname !== target.hostname || scope.port !== target.port || scope.username && scope.username !== target.username) continue;
      const part = scope.pathname.replace(/\/$/, '');
      if (part && target.pathname !== part && !target.pathname.startsWith(part + '/')) continue;
      rank = [part.length, scope.username ? 1 : 0]; exact = scope.pathname === target.pathname && scope.username === target.username;
    }
    const old = ranks[setting.field];
    if (old && (rank[0] < old[0] || rank[0] === old[0] && rank[1] < old[1])) continue;
    ranks[setting.field] = rank;
    const value = { ...setting, uncertainSelection: !exact || !target || rewriteSelected };
    if (setting.field === 'useragent') selected.useragent = [value];
    else if (literalSourceWord(setting.word)?.text === '') selected.extraheader = [];
    else selected.extraheader.push(value);
  }
  const agent = role.environmentSources.find(source => source.name === 'GIT_HTTP_USER_AGENT');
  if (agent) { selected.useragent = [{ ...agent, uncertainSelection: !target || rewriteSelected }]; unknownFields.delete('useragent'); }
  const words = [...selected.extraheader, ...selected.useragent];
  const certain = outboundPayloadVerdict(invocation, words.filter(source => !source.uncertainSelection).map(source => source.word));
  const uncertain = outboundPayloadVerdict(invocation, words.filter(source => source.uncertainSelection).map(source => source.word));
  const verdict = certain || (uncertain ? 'UNKNOWN' : false) || (role.configEnvironmentUnknown || unknownFields.size ? 'UNKNOWN' : false);
  return verdict && (role.argvUnknown || role.configEnvironmentUnknown || !knownInvocationContext(invocation)) ? 'UNKNOWN' : verdict;
}

/** Persisting generated HTTP metadata is future selected DATA, not an immediate transport. */
function gitHttpMetadataWriteVerdict(g, invocation) {
  if (g.gitNamespaceInferred || g.sub !== 'config') return false;
  const operation = configOperation(g.args.map(word => literalSourceWord(word) || word));
  if (operation.read || operation.terminal || operation.rename || operation.deletion || operation.operandWords.length < 2) return false;
  const [key, value] = operation.operandWords;
  if (!/^http(?:\..+)?\.(?:extraheader|useragent)$/i.test(literalSourceWord(key)?.text || '')) return false;
  return operation.unknownOption || outboundPayloadVerdict(invocation, [value]) ? 'UNKNOWN' : false;
}

/** Positive selectors of local Git execution must be gated for their actual operation. */
function gitExecutableSource(g, invocation) {
  const actual = !g.gitNamespaceInferred;
  if (g.terminal && g.helpKind === 'stdout' && knownInvocationContext(invocation)) return false;
  if (gitPagerSource(g, invocation)) return true;
  if (actual && g.operationRole?.mode === 'query' && ['hook', 'interpret-trailers', 'mergetool'].includes(g.sub)) return false;
  if (g.sub === 'config' && configOperation(g.args).read) return false;
  const diff = (actual || g.sub !== 'diff-pairs') && ['diff', 'show', 'log', 'diff-tree', 'diff-index', 'diff-files', 'diff-pairs', 'format-patch', 'whatchanged'].includes(g.sub);
  const modes = diff ? gitDiffModes(g) : null;
  if (modes?.terminal && knownInvocationContext(invocation)) return false;
  const keys = [...g.configs, ...g.configEnvs].map(config => config.split('=')[0].toLowerCase());
  const uncertain = !knownInvocationContext(invocation) || g.dynamicOpt || g.incomplete;
  if (gitIndexHelperActive(g)) {
    const monitors = g.configs.filter(config => /^core\.fsmonitor(?:=|$)/i.test(config));
    const selected = monitors.at(-1);
    if (g.configEnvs.some(config => /^core\.fsmonitor(?:=|$)/i.test(config)) ||
        selected && (uncertain || !/^(?:false|no|off|0)$/i.test(selected.slice(selected.indexOf('=') + 1)))) return true;
  }
  if (g.sub === 'archive' && keys.some(key => /^tar\..+\.command$/.test(key))) {
    const archive = gitArchiveFormat(g);
    if (!archive.terminal && (uncertain || archive.unknown || keys.includes('tar.' + archive.format.toLowerCase() + '.command'))) return true;
  }
  if (diff && (keys.some(key => /^diff\.(?:external|.+\.command)$/.test(key)) ||
      [...g.gitEnvNames, ...(invocation.helperEnvNames || [])].includes('GIT_EXTERNAL_DIFF')) && (modes.external || uncertain)) return true;
  if (diff && keys.some(key => /^diff\..+\.textconv$/.test(key)) && (modes.textconv || uncertain)) return true;
  if (actual && ['grep', 'cat-file'].includes(g.sub) && keys.some(key => /^diff\..+\.textconv$/.test(key))) {
    const selected = guard.gitTypedArguments(g, g.sub === 'grep' ? {
      values: ['regexp', 'file', 'max-depth', 'threads', 'max-count'], shortValues: { e: 'regexp', f: 'file', A: 'context', B: 'context', C: 'context', m: 'max-count' },
      flags: ['textconv', 'no-textconv', 'cached', 'no-index', 'untracked', 'ignore-case', 'quiet', 'line-number', 'files-with-matches'], shortFlags: 'aIiwnlLqvEFGPzohH'
    } : { values: ['path'], flags: ['textconv', 'no-textconv', 'filters', 'batch', 'batch-check'], shortFlags: 'pet' });
    if (selected.unknown || selected.flags.filter(flag => ['textconv', 'no-textconv'].includes(flag)).at(-1) === 'textconv') return true;
  }
  if (actual && (['gc', 'repack', 'pack-objects'].includes(g.sub) || g.sub === 'maintenance' && g.args[0]?.text === 'run')) {
    if (g.configs.some(config => /^gc\.recentobjectshook=.+/i.test(config)) ||
        g.configEnvs.some(config => /^gc\.recentobjectshook(?:=|$)/i.test(config))) return true;
  }
  if (actual && ['merge', 'pull', 'rebase', 'cherry-pick', 'revert', 'am', 'merge-tree'].includes(g.sub) &&
      keys.some(key => /^merge\..+\.driver$/.test(key))) return true;
  if (actual && g.sub === 'submodule' && keys.some(key => /^submodule\..+\.update$/.test(key))) {
    const parsed = guard.gitTypedArguments(g, { values: ['branch', 'name', 'depth', 'jobs', 'reference'], shortValues: { b: 'branch', j: 'jobs' },
      flags: ['quiet', 'recursive', 'init', 'remote', 'force', 'checkout', 'merge', 'rebase', 'none', 'recommend-shallow', 'no-recommend-shallow'], shortFlags: 'qf' });
    const action = literalSourceWord(parsed.operands[0]);
    const override = parsed.flags.some(flag => ['checkout', 'merge', 'rebase', 'none'].includes(flag));
    if (parsed.unknown || action?.text === 'update' && !override &&
        (g.configEnvs.some(config => /^submodule\..+\.update(?:=|$)/i.test(config)) ||
         g.configs.some(config => /^submodule\..+\.update=!/i.test(config)))) return true;
  }
  if (actual && ['merge', 'pull', 'rebase', 'cherry-pick', 'revert'].includes(g.sub)) {
    const parsed = guard.gitTypedArguments(g, { values: ['strategy', 'strategy-option', 'onto', 'exec', 'mainline', 'message', 'file'],
      shortValues: { ...(['merge', 'pull', 'rebase'].includes(g.sub) ? { s: 'strategy' } : {}), X: 'strategy-option', x: 'exec', m: g.sub === 'merge' ? 'message' : 'mainline', F: 'file' },
      flags: ['no-edit', 'edit', 'no-commit', 'commit', 'ff', 'no-ff', 'ff-only', 'quiet', 'verbose', 'continue', 'abort', 'quit', 'skip', 'root', 'interactive'], shortFlags: 'qvns' });
    if (parsed.values.some(value => value.option === 'strategy' &&
        (!literalSourceWord(value.word) || !['ort', 'recursive', 'octopus', 'resolve', 'ours', 'subtree'].includes(literalSourceWord(value.word).text)))) return true;
  }
  if (keys.some(key => /^filter\..+\.(?:clean|smudge|process)$/.test(key)) &&
      (!['rev-parse', 'ls-files', 'ls-tree', 'config', 'version', 'show-ref', 'for-each-ref', 'merge-base', 'count-objects'].includes(g.sub) || uncertain)) return true;
  if (keys.some(key => /^core\.hookspath$/.test(key)) &&
      (!['log', 'diff', 'show', 'rev-parse', 'ls-files', 'ls-tree', 'config', 'version'].includes(g.sub) || uncertain)) return true;
  return keys.some(key => /^include(?:if\..+)?\.path$/.test(key));
}

/** Operation policy for official source/server/object roles not covered by staged filename checks. */
function gitOperationVerdict(g, invocation) {
  if (g.gitNamespaceInferred) return false;
  const role = g.operationRole;
  if (!role || role.terminal || role.mode === 'query' || g.sub === 'am' && role.mode === 'cleanup') return false;
  if (role.kind === 'generated-object') {
    const words = gitCommitObjectWords(g, role);
    const verdict = outboundPayloadVerdict(invocation, words.filter(source => !source.uncertainSelection).map(source => source.word)) ||
      (outboundPayloadVerdict(invocation, words.filter(source => source.uncertainSelection).map(source => source.word)) ? 'UNKNOWN' : false);
    if (verdict) return role.unknown ? 'UNKNOWN' : verdict;
    if (!role.unknown && role.messageFiles.some(word => literalSourceWord(word) && guard.isSecretPath(literalSourceWord(word).text))) return 'FORBIDDEN';
    return 'UNKNOWN';
  }
  if (role.kind === 'index-file-input') {
    if (role.unknown) return 'UNKNOWN';
    if (role.flags.includes('add') && role.operands.length && !role.values.length &&
        role.operands.every(word => literalSourceWord(word))) {
      return role.operands.some(word => guard.isSecretPath(literalSourceWord(word).text)) ? 'FORBIDDEN' : false;
    }
  }
  return 'UNKNOWN';
}

/** A persistent selected helper setting is future source, not an immediate send or execution. */
function gitConfigSourceWrite(g) {
  if (g.gitNamespaceInferred) return false;
  if (g.sub !== 'config') return false;
  const words = g.args.map(word => literalSourceWord(word) || word);
  const operation = configOperation(words);
  if (operation.read || operation.terminal) return false;
  const [keyWord, valueWord] = operation.operandWords;
  const key = literalSourceWord(keyWord)?.text.toLowerCase();
  const sourceKey = name => /^(?:core\.(?:editor|pager|hookspath|fsmonitor|askpass)|sequence\.editor|credential\.helper|pager\..+|diff\.(?:external|.+\.(?:command|textconv))|filter\..+\.(?:clean|smudge|process)|tar\..+\.command|gc\.recentobjectshook|trailer\..+\.(?:cmd|command)|hook\..+\.(?:command|event)|merge\..+\.driver|gpg\.(?:program|.+\.program)|submodule\..+\.update|http(?:\..+)?\.cookiefile)$/i.test(name || '');
  const sourceSection = name => /^(?:core|sequence|credential|pager|diff(?:\..+)?|filter\..+|tar\..+|gc|trailer\..+|hook\..+|merge\..+|gpg(?:\..+)?|submodule\..+|http(?:\..+)?)$/i.test(name || '');
  if (operation.rename) return sourceSection(key) || sourceSection(literalSourceWord(valueWord)?.text) ? 'UNKNOWN' : false;
  if (operation.deletion === 'section') return sourceSection(key) ? 'UNKNOWN' : false;
  if (!sourceKey(key)) return false;
  if (operation.deletion) return 'UNKNOWN';
  if (operation.operands.length < 2) return false; // Legacy one-key form is a getter.
  if (operation.unknownOption) return 'UNKNOWN';
  const value = literalSourceWord(valueWord)?.text;
  if (value === undefined) return 'UNKNOWN';
  if (key === 'core.fsmonitor' && /^(?:false|no|off|0)$/i.test(value)) return false;
  if ((key === 'core.pager' || /^pager\./.test(key)) && ['', 'cat'].includes(value)) return false;
  if (/^pager\./.test(key) && /^(?:false|no|off|0)$/i.test(value)) return false;
  if (key === 'core.hookspath' && value === '/dev/null') return false;
  if (key === 'credential.helper' && value === '') return false; // Documented reset of the helper list.
  if (/^submodule\..+\.update$/.test(key) && ['checkout', 'merge', 'rebase', 'none'].includes(value)) return false;
  if (/^hook\..+\.event$/.test(key) && value === '') return false; // Documented event-list reset.
  return 'UNKNOWN';
}

/** Identify section names whose renamed contents can activate a destination or transport override. */
function destinationSection(section) {
  return /^(?:remote(?:\..+)?|branch\..+|url\..+|include|includeif\..+|core)$/i.test(section);
}

/** Identify Git transport commands that can replace the executable used for a push. */
function transportConfig(key) {
  return /^(?:core\.sshcommand|core\.gitproxy)$/i.test(key);
}

/** Identify configuration keys that can change a push's repository or URL rewrite. */
function destinationConfig(key) {
  return REMOTE_URL_KEY_RE.test(key) || transportConfig(key) ||
    /^include\.path$/i.test(key) || /^includeif\..+\.path$/i.test(key) ||
    /^url\..+\.(?:insteadof|pushinsteadof)$/i.test(key) ||
    /^(?:remote\.pushdefault|branch\..+\.(?:remote|pushremote))$/i.test(key);
}
/** Check a literal -c override, including the URL base stored in rewrite keys. */
function externalConfig(config) {
  const eq = config.indexOf('=');
  const key = eq < 0 ? config : config.slice(0, eq);
  if (!destinationConfig(key)) return false;
  const rewrite = /^url\.(.+)\.(?:insteadof|pushinsteadof)$/i.exec(key);
  return destinationArg(rewrite ? rewrite[1] : eq < 0 ? '' : config.slice(eq + 1));
}


// curl の値を取る option（curl --help all で確認）。値の中の option 風の文字は実行しない。
const CURL_VALUE_LONG = new Set([
  'abstract-unix-socket', 'alt-svc', 'aws-sigv4', 'cacert', 'capath', 'cert', 'cert-type',
  'ciphers', 'config', 'connect-timeout', 'connect-to', 'continue-at', 'cookie', 'cookie-jar',
  'create-file-mode', 'crlfile', 'curves', 'data', 'data-ascii', 'data-binary', 'data-raw',
  'data-urlencode', 'delegation', 'dns-interface', 'dns-ipv4-addr', 'dns-ipv6-addr', 'dns-servers', 'doh-url',
  'dump-header', 'egd-file', 'engine', 'etag-compare', 'etag-save', 'expect100-timeout', 'form',
  'form-string', 'ftp-account', 'ftp-alternative-to-user', 'ftp-method', 'ftp-port', 'ftp-ssl-ccc-mode', 'happy-eyeballs-timeout-ms',
  'haproxy-clientip', 'header', 'help', 'hostpubmd5', 'hostpubsha256', 'hsts', 'interface',
  'ipfs-gateway', 'json', 'keepalive-time', 'key', 'key-type', 'krb', 'libcurl',
  'limit-rate', 'local-port', 'login-options', 'mail-auth', 'mail-from', 'mail-rcpt', 'max-filesize',
  'max-redirs', 'max-time', 'netrc-file', 'noproxy', 'oauth2-bearer', 'output', 'output-dir',
  'parallel-max', 'pass', 'pinnedpubkey', 'preproxy', 'proto', 'proto-default', 'proto-redir',
  'proxy', 'proxy-cacert', 'proxy-capath', 'proxy-cert', 'proxy-cert-type', 'proxy-ciphers', 'proxy-crlfile',
  'proxy-header', 'proxy-key', 'proxy-key-type', 'proxy-pass', 'proxy-pinnedpubkey', 'proxy-service-name', 'proxy-tls13-ciphers',
  'proxy-tlsauthtype', 'proxy-tlspassword', 'proxy-tlsuser', 'proxy-user', 'proxy1.0', 'pubkey', 'quote',
  'random-file', 'range', 'rate', 'referer', 'request', 'request-target', 'resolve',
  'retry', 'retry-delay', 'retry-max-time', 'sasl-authzid', 'service-name', 'socks4', 'socks4a',
  'socks5', 'socks5-gssapi-service', 'socks5-hostname', 'speed-limit', 'speed-time', 'stderr', 'telnet-option',
  'tftp-blksize', 'time-cond', 'tls-max', 'tls13-ciphers', 'tlsauthtype', 'tlspassword', 'tlsuser',
  'trace', 'trace-ascii', 'trace-config', 'unix-socket', 'upload-file', 'url', 'url-query',
  'user', 'user-agent', 'variable', 'write-out',
]);
const CURL_VALUE_SHORT = { 'E': 'cert', 'K': 'config', 'C': 'continue-at', 'b': 'cookie', 'c': 'cookie-jar', 'd': 'data', 'D': 'dump-header', 'F': 'form', 'P': 'ftp-port', 'H': 'header', 'h': 'help', 'm': 'max-time', 'o': 'output', 'x': 'proxy', 'U': 'proxy-user', 'Q': 'quote', 'r': 'range', 'e': 'referer', 'X': 'request', 'Y': 'speed-limit', 'y': 'speed-time', 't': 'telnet-option', 'z': 'time-cond', 'T': 'upload-file', 'u': 'user', 'A': 'user-agent', 'w': 'write-out' };
const CURL_FLAG_LONG = new Set([
  'anyauth', 'append', 'basic', 'ca-native', 'cert-status', 'compressed', 'compressed-ssh', 'create-dirs',
  'crlf', 'digest', 'disable', 'disable-eprt', 'disable-epsv', 'disallow-username-in-url', 'doh-cert-status', 'doh-insecure',
  'fail', 'fail-early', 'fail-with-body', 'false-start', 'form-escape', 'ftp-create-dirs', 'ftp-pasv', 'ftp-pret',
  'ftp-skip-pasv-ip', 'ftp-ssl-ccc', 'ftp-ssl-control', 'get', 'globoff', 'haproxy-protocol', 'head', 'http0.9',
  'http1.0', 'http1.1', 'http2', 'http2-prior-knowledge', 'http3', 'http3-only', 'ignore-content-length', 'include',
  'insecure', 'ipv4', 'ipv6', 'junk-session-cookies', 'list-only', 'location', 'location-trusted', 'mail-rcpt-allowfails',
  'manual', 'metalink', 'negotiate', 'netrc', 'netrc-optional', 'next', 'no-alpn', 'no-buffer',
  'no-clobber', 'no-keepalive', 'no-npn', 'no-progress-meter', 'no-sessionid', 'ntlm', 'ntlm-wb', 'parallel',
  'parallel-immediate', 'path-as-is', 'post301', 'post302', 'post303', 'progress-bar', 'proxy-anyauth', 'proxy-basic',
  'proxy-ca-native', 'proxy-digest', 'proxy-http2', 'proxy-insecure', 'proxy-negotiate', 'proxy-ntlm', 'proxy-ssl-allow-beast', 'proxy-ssl-auto-client-cert',
  'proxy-tlsv1', 'proxytunnel', 'raw', 'remote-header-name', 'remote-name', 'remote-name-all', 'remote-time', 'remove-on-error',
  'retry-all-errors', 'retry-connrefused', 'sasl-ir', 'show-error', 'silent', 'socks5-basic', 'socks5-gssapi', 'socks5-gssapi-nec',
  'ssl', 'ssl-allow-beast', 'ssl-auto-client-cert', 'ssl-no-revoke', 'ssl-reqd', 'ssl-revoke-best-effort', 'sslv2', 'sslv3',
  'styled-output', 'suppress-connect-headers', 'tcp-fastopen', 'tcp-nodelay', 'tftp-no-options', 'tlsv1', 'tlsv1.0', 'tlsv1.1',
  'tlsv1.2', 'tlsv1.3', 'tr-encoding', 'trace-ids', 'trace-time', 'use-ascii', 'verbose', 'version',
  'xattr',
]);
const CURL_LONG_NAMES = [...CURL_VALUE_LONG, ...CURL_FLAG_LONG];

/** curl 8.7.1: actual help/manual/version exits argument parsing before transfers. */
function curlTerminalQuery(words, incomplete) {
  if (incomplete) return false;
  const flags = '012346afgGiIjklLMnNOpqRsSvVZ:#';
  for (let k = 0; k < words.length; k++) {
    const word = literalSourceWord(words[k]);
    if (!word) return false;
    const text = word.text;
    if (text === '--') return false;
    if (text.startsWith('--')) {
      const eq = text.indexOf('=');
      const name = text.slice(2, eq < 0 ? undefined : eq);
      const matches = CURL_LONG_NAMES.includes(name) ? [name] : CURL_LONG_NAMES.filter(option => option.startsWith(name));
      if (matches.length !== 1) return false;
      const option = matches[0];
      if (['help', 'manual', 'version'].includes(option)) return true;
      // Keep the independent, uninspected explicit configuration source boundary.
      if (option === 'config') return false;
      if (CURL_VALUE_LONG.has(option) && eq < 0 && !literalSourceWord(words[++k])) return false;
    } else if (text.startsWith('-') && text !== '-') {
      for (let p = 1; p < text.length; p++) {
        if ('hMV'.includes(text[p])) return true;
        const option = CURL_VALUE_SHORT[text[p]];
        if (option === 'config') return false;
        if (option) {
          if (p === text.length - 1 && !literalSourceWord(words[++k])) return false;
          break;
        }
        if (!flags.includes(text[p])) return false;
      }
    }
  }
  return false;
}

/** Netrc toggles are independent; consume other options before interpreting a selector or reset. */
function curlImplicitNetrc(words, incomplete) {
  let required = false;
  let optional = false;
  let unknown = false;
  for (let k = 0; k < words.length; k++) {
    const word = words[k], t = word.text;
    if (t === '--') break;
    if (t.startsWith('--')) {
      const eq = t.indexOf('='), name = t.slice(2, eq < 0 ? undefined : eq);
      const base = name.startsWith('no-') ? name.slice(3) : name;
      const matches = CURL_LONG_NAMES.includes(base) ? [base] : CURL_LONG_NAMES.filter(option => option.startsWith(base));
      if (matches.length !== 1) { unknown ||= word.dynamic; continue; }
      const option = matches[0];
      if (['help', 'manual', 'version'].includes(option) && knownWord(word) && !unknown) return false;
      if (option === 'next') {
        if (required || optional) return unknown || incomplete ? 'UNKNOWN' : 'FORBIDDEN';
        required = false; optional = false;
      } else if (option === 'netrc' || option === 'netrc-optional') {
        if (!knownWord(word) || eq >= 0) unknown = true;
        else if (option === 'netrc') required = !name.startsWith('no-');
        else optional = !name.startsWith('no-');
      } else if (CURL_VALUE_LONG.has(option) && eq < 0) k++;
    } else if (t.startsWith('-')) {
      for (let p = 1; p < t.length; p++) {
        if (t[p] === 'h' || t[p] === 'V' || t[p] === 'M') { if (knownWord(word) && !unknown) return false; }
        if (t[p] === 'n') { if (knownWord(word)) required = true; else unknown = true; }
        if (t[p] === ':') {
          if (required || optional) return unknown || incomplete ? 'UNKNOWN' : 'FORBIDDEN';
          required = false; optional = false;
        }
        if (CURL_VALUE_SHORT[t[p]]) { if (p === t.length - 1) k++; break; }
      }
    }
  }
  return required || optional ? unknown || incomplete ? 'UNKNOWN' : 'FORBIDDEN' : false;
}

/** Recognize curl file payloads and opaque config input without reading either file. */
function curlReadsUpload(words, incomplete = false, actualClient = false) {
  // Additional words from splitting or pathname/brace expansion can introduce payload options,
  // including from a value consumed by a visible option. Never infer the unseen argv from env.
  if (actualClient && words.some(word => word.dynamic && word.dynamicMaySplit !== false || word.globExpanded || word.braceExpanded)) return 'UNKNOWN';
  if (curlTerminalQuery(words, incomplete)) return false;
  const implicitNetrc = curlImplicitNetrc(words, incomplete);
  if (implicitNetrc) return implicitNetrc;
  // xargs/find can provide an unseen filename to a trailing file-reading option.
  const fileOptions = new Set(['upload-file', 'data', 'data-ascii', 'data-binary', 'json',
    'header', 'proxy-header', 'data-urlencode', 'url-query', 'form', 'variable', 'cookie', 'netrc-file', 'etag-compare']);
  // ETag comparison is a last-value singleton per operation, unlike additive headers/data.
  // Its selected file is read by tool_operate.c into the outbound If-None-Match header.
  let etag = false;
  const etags = [];
  let cache = new Map();
  let operationUrl = false;
  const cacheVerdicts = [];
  const finishOperation = () => {
    etags.push(etag);
    if (operationUrl && [...cache.values()].some(Boolean)) cacheVerdicts.push('UNKNOWN');
    etag = false;
    cache = new Map();
    operationUrl = false;
  };
  const variables = new Map();
  let definitionVersion = 0;
  let unknownFileVersion = 0;
  const outbound = new Set(['data', 'data-ascii', 'data-binary', 'data-raw', 'data-urlencode', 'json',
    'form', 'form-string', 'header', 'proxy-header', 'url', 'url-query', 'request', 'request-target',
    'user', 'proxy-user', 'user-agent', 'referer', 'cookie', 'oauth2-bearer', 'ftp-account',
    'mail-auth', 'mail-from', 'mail-rcpt', 'quote', 'telnet-option']);
  /** Expand known inline values locally; file/env contents remain an unknown marker and are never read. */
  const expanded = (value) => {
    let file = false;
    let unknown = false;
    const text = value.replace(/\{\{([A-Za-z0-9_]+)(?::([^}]*))?\}\}/g, (whole, name, transforms, offset) => {
      let escapes = 0;
      for (let p = offset - 1; p >= 0 && value[p] === '\\'; p--) escapes++;
      if (escapes % 2) return whole;
      const variable = variables.get(name);
      file ||= unknownFileVersion > (variable ? variable.version : 0);
      unknown ||= unknownFileVersion > (variable ? variable.version : 0) || Boolean(variable?.unknown);
      if (!variable) return file ? '\0' : '';
      file ||= variable.file;
      let result = variable.text;
      if (result === null) return '\0';
      for (const transform of (transforms || '').split(/[,:]/).filter(Boolean)) {
        if (transform === 'trim') result = result.trim();
        else if (transform === 'json') result = JSON.stringify(result);
        else if (transform === 'url') result = encodeURIComponent(result);
        else if (transform === 'b64') result = Buffer.from(result).toString('base64');
        else if (transform === '64dec') result = Buffer.from(result, 'base64').toString();
        else { unknown = true; return '\0'; }
      }
      return result;
    });
    return { text, file, unknown };
  };
  /** Track definitions in order so unused or overwritten file variables do not imply an upload. */
  const variableDefinition = (value, expanding, word) => {
    const definition = /^%?([A-Za-z0-9_]+)(?:\[[0-9-]+\])?([=@])?(.*)$/s.exec(value);
    definitionVersion++;
    if (!definition) {
      const at = value.indexOf('@');
      const eq = value.indexOf('=');
      if (at >= 0 && (eq < 0 || at < eq)) unknownFileVersion = definitionVersion;
      return;
    }
    const source = expanding ? expanded(definition[3]) : { text: definition[3], file: false };
    variables.set(definition[1], { file: definition[2] === '@' || source.file, version: definitionVersion,
      unknown: !knownWord(word) || Boolean(source.unknown),
      text: definition[2] === '@' || !definition[2] || source.text.includes('\0') ? null : source.text });
  };
  /** Match file references using the option's own value, not text printed inside another value. */
  const payload = (option, value) => {
    if (option === 'config') return true; // config can supply upload options or a destination
    if (option === 'upload-file' || option === 'netrc-file') return Boolean(value);
    if (option === 'cookie') return Boolean(value) && !value.includes('=');
    if (['data', 'data-ascii', 'data-binary', 'json', 'header', 'proxy-header'].includes(option)) return value.startsWith('@');
    if (option === 'data-urlencode') return value.includes('@');
    // curl's url_query() selects raw '+' first, then data_urlencode() selects '=' before '@'.
    if (option === 'url-query') return !value.startsWith('+') && !value.includes('=') && value.includes('@');
    if (option === 'form') return /=\s*[@<]/.test(value);
    return false;
  };
  for (let k = 0; k < words.length; k++) {
    const optionWord = words[k];
    const t = optionWord.text;
    if (t === '--') { operationUrl ||= words.slice(k + 1).some(word => word.text !== ''); break; }
    // At an actual argv boundary a prefix-free scalar may be a URL or an upload/cookie flag.
    // Known option values are consumed below and do not reach this boundary as option words.
    if (actualClient && optionWord.dynamic && t.startsWith('\0')) return 'UNKNOWN';
    if (t.startsWith('--')) {
      const eq = t.indexOf('=');
      const fullName = t.slice(2, eq < 0 ? undefined : eq);
      const expanding = fullName.startsWith('expand-');
      const name = expanding ? fullName.slice(7) : fullName;
      if (optionWord.dynamic && name.includes('\0')) {
        const prefix = name.split('\0')[0];
        if ('cookie'.startsWith(prefix) || prefix.startsWith('cookie')) return 'UNKNOWN';
      }
      if (optionWord.dynamic && /^url-(?:query)?\0/.test(name)) return 'UNKNOWN';
      if (optionWord.dynamic && name.includes('\0') && ['hsts', 'alt-svc'].some(option => option.startsWith(name.split('\0')[0]))) return 'UNKNOWN';
      const matches = CURL_LONG_NAMES.includes(name) ? [name] : CURL_LONG_NAMES.filter((option) => option.startsWith(name));
      if (matches.length !== 1 && matches.includes('cookie')) return 'UNKNOWN';
      if (matches.length === 1 && matches[0] === 'next') { finishOperation(); continue; }
      if (matches.length !== 1 || !CURL_VALUE_LONG.has(matches[0])) continue;
      const option = matches[0];
      if (option === 'config') return 'UNKNOWN';
      const value = eq < 0 ? words[++k] : { ...optionWord, text: t.slice(eq + 1) };
      if (value) {
        if (option === 'variable') { variableDefinition(value.text, expanding, value); continue; }
        const source = expanding ? expanded(value.text) : { text: value.text, file: false };
        const verdict = !incomplete && knownWord(optionWord) && knownWord(value) && !source.unknown &&
          (option !== 'url-query' || name === option) ? 'FORBIDDEN' : 'UNKNOWN';
        if (option === 'etag-compare') {
          etag = source.text === '' && !source.file && !source.unknown ? false : verdict;
          continue;
        }
        if (option === 'url') operationUrl = true;
        if (option === 'alt-svc' || option === 'hsts') {
          // These last-value options load connection/cache conditions, not a raw file body.
          // Empty disables this file-input family only; other payload/source gates remain active.
          const literal = expanding ? null : literalSourceWord(value);
          cache.set(option, source.unknown || source.file || (literal ? literal.text !== '' : source.text !== '' || !knownWord(value)));
          continue;
        }
        // Cookie's '=' proves inline syntax only within one actual scalar argument. Its file form
        // reads local bytes; unknown/split input must never be mistaken for empty or inline DATA.
        if (option === 'netrc-file' && !literalSourceWord(value)) return 'UNKNOWN';
        if (option === 'cookie' && ((value.dynamic && value.dynamicMaySplit !== false) ||
            value.globExpanded || value.braceExpanded || value.tildeExpanded || value.ansiCUnknown ||
            source.unknown || (!source.file && source.text.includes('\0') && !source.text.includes('=')))) return 'UNKNOWN';
        // A scalar '+' or '=' proves inline query syntax; an unknown prefix or argv count does not.
        if (option === 'url-query' && ((value.dynamic && value.dynamicMaySplit !== false) ||
            (!source.file && !source.text.startsWith('+') && !source.text.includes('=') && source.text.includes('\0')))) return 'UNKNOWN';
        if (expanding && outbound.has(option) && SECRET_LITERALS.some((pattern) => pattern.test(source.text))) return verdict;
        if ((source.file && outbound.has(option)) || payload(option, source.text)) return verdict;
      } else if (option === 'etag-compare') etag = 'UNKNOWN';
      else if (option === 'alt-svc' || option === 'hsts') return 'UNKNOWN';
      else if (option === 'cookie' || option === 'netrc-file' || incomplete && fileOptions.has(option)) return 'UNKNOWN';
    } else if (t.startsWith('-')) {
      for (let p = 1; p < t.length; p++) {
        if (actualClient && optionWord.dynamic && t[p] === '\0') return 'UNKNOWN';
        if (t[p] === ':') { finishOperation(); continue; }
        const option = CURL_VALUE_SHORT[t[p]];
        if (!option) continue;
        if (option === 'config') return 'UNKNOWN';
        const value = p + 1 < t.length ? { ...optionWord, text: t.slice(p + 1) } : words[++k];
        if (option === 'cookie' && !value) return 'UNKNOWN';
        if (option === 'cookie' && value && ((value.dynamic && value.dynamicMaySplit !== false) ||
            value.globExpanded || value.braceExpanded || value.tildeExpanded || value.ansiCUnknown ||
            (value.text.includes('\0') && !value.text.includes('=')))) return 'UNKNOWN';
        if (value ? payload(option, value.text) : incomplete && fileOptions.has(option)) {
          return !incomplete && knownWord(optionWord) && knownWord(value) ? 'FORBIDDEN' : 'UNKNOWN';
        }
        break;
      }
    } else if (t !== '') operationUrl = true;
  }
  finishOperation();
  return etags.includes('FORBIDDEN') ? 'FORBIDDEN' : etags.includes('UNKNOWN') || cacheVerdicts.length ? 'UNKNOWN' : false;
}

// Wget 1.25.0 --help: consume option values so a printed option name is not executable syntax.
const WGET_VALUE_LONG = new Set([
  'execute', 'output-file', 'append-output', 'report-speed', 'input-file', 'base', 'config',
  'rejected-log', 'tries', 'retry-on-http-error', 'output-document', 'start-pos', 'progress',
  'timeout', 'dns-timeout', 'connect-timeout', 'read-timeout', 'wait', 'waitretry', 'quota',
  'bind-address', 'limit-rate', 'restrict-file-names', 'prefer-family', 'user', 'password',
  'use-askpass', 'local-encoding', 'remote-encoding', 'directory-prefix', 'cut-dirs',
  'http-user', 'http-password', 'default-page', 'header', 'compression', 'max-redirect',
  'proxy-user', 'proxy-password', 'referer', 'user-agent', 'load-cookies', 'save-cookies',
  'post-data', 'post-file', 'method', 'body-data', 'body-file', 'secure-protocol', 'certificate',
  'certificate-type', 'private-key', 'private-key-type', 'ca-certificate', 'ca-directory',
  'crl-file', 'pinnedpubkey', 'random-file', 'ciphers', 'hsts-file', 'ftp-user', 'ftp-password',
  'warc-file', 'warc-header', 'warc-max-size', 'warc-dedup', 'warc-tempdir', 'level', 'backups',
  'accept', 'reject', 'accept-regex', 'reject-regex', 'regex-type', 'domains', 'exclude-domains',
  'follow-tags', 'ignore-tags', 'include-directories', 'exclude-directories',
]);
const WGET_VALUE_SHORT = 'eoaiBtOTwQPUlARDIX';
const WGET_FLAG_LONG = new Set([
  'help', 'version', 'background', 'debug', 'quiet', 'verbose', 'no-verbose', 'no-config',
  'retry-connrefused', 'retry-on-host-error', 'no-clobber', 'no-netrc', 'continue', 'show-progress',
  'timestamping', 'no-if-modified-since', 'no-use-server-timestamps', 'server-response', 'spider',
  'no-dns-cache', 'inet4-only', 'inet6-only', 'unlink', 'xattr', 'ask-password', 'random-wait',
  'no-proxy', 'no-cache', 'adjust-extension', 'ignore-length', 'no-cookies', 'keep-session-cookies',
  'save-headers', 'auth-no-challenge', 'content-disposition', 'content-on-error', 'trust-server-names',
  'no-http-keep-alive', 'no-check-certificate', 'no-hsts', 'https-only', 'no-iri', 'no-warc-compression',
  'no-warc-digests', 'no-warc-keep-log', 'warc-cdx', 'no-glob', 'no-passive-ftp', 'preserve-permissions',
  'retr-symlinks', 'ftps-implicit', 'ftps-resume-ssl', 'ftps-clear-data-connection', 'ftps-fallback-to-ftp',
  'recursive', 'mirror', 'delete-after', 'convert-links', 'convert-file-only', 'backup-converted',
  'page-requisites', 'strict-comments', 'relative', 'follow-ftp', 'span-hosts', 'no-parent', 'ignore-case',
  'no-directories', 'force-directories', 'no-host-directories', 'protocol-directories', 'force-html',
]);
const WGET_FLAG_SHORT = 'hVbdqvncNS46rkmEpKpFHs';

/** Prove config/helper option roles while consuming values; option-looking DATA is never a flag. */
function wgetSourceBoundary(invocation) {
  let noConfig = false;
  // Environment names are fallbacks for an active --use-askpass, not an activation
  // by themselves once default config is disabled and option roles are fully known.
  let selected = false;
  let unknown = Boolean(invocation.incomplete);
  let terminal = false;
  let afterDD = false;
  for (let k = 0; k < invocation.args.length; k++) {
    const word = invocation.args[k];
    const text = word.text;
    if (word.dynamic && !quotedAttachedOptionValue(word, text, WGET_VALUE_SHORT, [...WGET_VALUE_LONG]) ||
        word.ansiCUnknown || word.globExpanded || word.braceExpanded) unknown = true;
    if (!afterDD && text === '--') { afterDD = true; continue; }
    if (!afterDD && text.startsWith('--')) {
      const eq = text.indexOf('=');
      const name = text.slice(2, eq < 0 ? undefined : eq);
      const names = [...WGET_VALUE_LONG, ...WGET_FLAG_LONG];
      const matches = names.includes(name) ? [name] : names.filter(option => option.startsWith(name));
      if (matches.length !== 1) { unknown = true; continue; }
      const option = matches[0];
      if (option === 'no-config' && eq < 0 && knownWord(word)) noConfig = true;
      if (['help', 'version'].includes(option) && eq < 0 && knownWord(word)) terminal = true;
      if (option === 'use-askpass') selected = true;
      if (WGET_VALUE_LONG.has(option) && option !== 'use-askpass') {
        const value = eq < 0 ? invocation.args[++k] : { ...word, text: text.slice(eq + 1) };
        if (!value || value.dynamic && value.dynamicMaySplit !== false || value?.globExpanded || value?.braceExpanded) unknown = true;
      } else if (eq >= 0 && option !== 'use-askpass') unknown = true;
      continue;
    }
    if (!afterDD && text.startsWith('-') && text !== '-') {
      for (let p = 1; p < text.length; p++) {
        if (WGET_VALUE_SHORT.includes(text[p])) {
          const value = p + 1 < text.length ? { ...word, text: text.slice(p + 1) } : invocation.args[++k];
          if (!value || value.dynamic && value.dynamicMaySplit !== false || value?.globExpanded || value?.braceExpanded) unknown = true;
          break;
        }
        if ('hV'.includes(text[p]) && knownWord(word)) terminal = true;
        if (!WGET_FLAG_SHORT.includes(text[p])) unknown = true;
      }
    }
  }
  return !noConfig || unknown || selected && !(terminal && knownInvocationContext(invocation));
}

/** Reject Wget's file bodies or opaque config while skipping literal values of other options. */
function wgetReadsUpload(words) {
  const opaque = new Set(['post-file', 'body-file', 'load-cookies', 'config', 'execute']);
  for (let k = 0; k < words.length; k++) {
    const t = words[k].text;
    if (t === '--') break;
    if (t.startsWith('--')) {
      const eq = t.indexOf('=');
      const name = t.slice(2, eq < 0 ? undefined : eq);
      const matches = WGET_VALUE_LONG.has(name) ? [name] : [...WGET_VALUE_LONG].filter((option) => option.startsWith(name));
      if (matches.length !== 1) continue;
      if (opaque.has(matches[0])) {
        const value = eq < 0 ? words[k + 1] : { ...words[k], text: t.slice(eq + 1) };
        return ['post-file', 'body-file', 'load-cookies'].includes(matches[0]) && knownWord(words[k]) && knownWord(value) ? 'FORBIDDEN' : 'UNKNOWN';
      }
      // --use-askpass has an optional attached value; the following word remains an option/URL.
      if (eq < 0 && matches[0] !== 'use-askpass') k++;
    } else if (t.startsWith('-')) {
      for (let p = 1; p < t.length; p++) {
        if (!WGET_VALUE_SHORT.includes(t[p])) continue;
        if (t[p] === 'e') return 'UNKNOWN';
        if (p === t.length - 1) k++;
        break;
      }
    }
  }
  return false;
}

/** Extract copy operands without mistaking an SSH/proxy option value for a destination. */
function remoteCopyDestination(invocation) {
  if (invocation.name === 'scp') {
    const operation = scpOperation(invocation);
    // SCP getopt stops at the first operand; later option-looking words remain filenames.
    if (operation.unknown || operation.operands.length < 2) return 'UNKNOWN';
    const roles = operation.operands.map(value => remoteCopyAddressRole('scp', value));
    if (roles.includes('UNKNOWN')) return 'UNKNOWN';
    return roles.at(-1) === 'REMOTE' ? 'FORBIDDEN' : false;
  }
  const shortValues = { scp: 'cDFiJloPSX', rsync: RSYNC_VALUE_SHORT };
  const shortFlags = { scp: '346ABCOpqRrsTv', rsync: RSYNC_FLAG_SHORT };
  const longValues = invocation.name === 'rsync' ? RSYNC_VALUE_LONG : new Set();
  const longFlags = invocation.name === 'rsync' ? RSYNC_FLAG_LONG : new Set();
  const literal = word => Boolean(word && !word.ansiCUnknown && !word.globExpanded && !word.braceExpanded && !word.tildeExpanded &&
    (knownWord(word) || typeof word.literalValue === 'string' && word.dynamicMaySplit === false));
  const textOf = word => typeof word.literalValue === 'string' && word.dynamicMaySplit === false ? word.literalValue : word.text;
  const operands = [];
  let unknown = Boolean(invocation.incomplete);
  let afterDD = false;
  for (let k = 0; k < invocation.args.length; k++) {
    const word = invocation.args[k];
    const t = textOf(word);
    if (!literal(word) && !quotedAttachedOptionValue(word, t, shortValues[invocation.name], [...longValues])) unknown = true;
    if (!afterDD && t === '--') { afterDD = true; continue; }
    if (!afterDD && t.startsWith('--')) {
      const eq = t.indexOf('=');
      const name = t.slice(2, eq < 0 ? undefined : eq);
      if (['help', 'version'].includes(name) && eq < 0 && !unknown) return false;
      if (longValues.has(name)) {
        const value = eq < 0 ? invocation.args[++k] : { ...word, text: t.slice(eq + 1) };
        if (!value || value.dynamicMaySplit && value.dynamic || value.globExpanded || value.braceExpanded) unknown = true;
      } else if (!longFlags.has(name) || eq >= 0) unknown = true;
      continue;
    }
    if (!afterDD && t.startsWith('-') && t !== '-') {
      for (let p = 1; p < t.length; p++) {
        if (shortValues[invocation.name].includes(t[p])) {
          const value = p + 1 < t.length ? { ...word, text: t.slice(p + 1) } : invocation.args[++k];
          if (!value || value.dynamicMaySplit && value.dynamic || value.globExpanded || value.braceExpanded) unknown = true;
          break;
        }
        if (!shortFlags[invocation.name].includes(t[p])) unknown = true;
      }
      continue;
    }
    operands.push(word);
  }
  const destination = operands[operands.length - 1];
  if (unknown || !literal(destination) || operands.length < 2) return 'UNKNOWN';
  const roles = operands.map(word => remoteCopyAddressRole(invocation.name, textOf(word)));
  if (roles.includes('UNKNOWN')) return 'UNKNOWN';
  return roles.at(-1) === 'REMOTE' ? 'FORBIDDEN' : false;
}

/** A local rsync file list transmits requested names on both upload and download routes. */
function rsyncFileListPayload(invocation) {
  if (invocation.name !== 'rsync') return false;
  const files = [];
  let remote = false;
  let unknown = Boolean(invocation.incomplete);
  let afterDD = false;
  for (let k = 0; k < invocation.args.length; k++) {
    const word = invocation.args[k];
    const literal = literalSourceWord(word);
    const text = literal ? literal.text : word.text;
    if (!literal && !quotedAttachedOptionValue(word, text, RSYNC_VALUE_SHORT, [...RSYNC_VALUE_LONG])) unknown = true;
    if (!afterDD && text === '--') { afterDD = true; continue; }
    if (!afterDD && ['--help', '--version'].includes(text) && !unknown) return false;
    if (!afterDD && text.startsWith('--')) {
      const eq = text.indexOf('=');
      const name = text.slice(2, eq < 0 ? undefined : eq);
      if (RSYNC_VALUE_LONG.has(name)) {
        const value = eq < 0 ? invocation.args[++k] : { ...word, text: text.slice(eq + 1), literalValue: literal ? text.slice(eq + 1) : undefined };
        if (!value || value.dynamic && value.dynamicMaySplit !== false || value?.globExpanded || value?.braceExpanded) unknown = true;
        if (name === 'files-from') files.push(value);
      } else if (!RSYNC_FLAG_LONG.has(name) && name !== 'from0' || eq >= 0) unknown = true;
      continue;
    }
    if (!afterDD && text.startsWith('-') && text !== '-') {
      for (let p = 1; p < text.length; p++) {
        if (RSYNC_VALUE_SHORT.includes(text[p])) {
          const value = p + 1 < text.length ? { ...word, text: text.slice(p + 1) } : invocation.args[++k];
          if (!literalSourceWord(value)) unknown = true;
          break;
        }
        if (!RSYNC_FLAG_SHORT.includes(text[p]) && text[p] !== '0') unknown = true;
      }
      continue;
    }
    const role = remoteCopyAddressRole('rsync', text);
    if (role === 'UNKNOWN') unknown = true;
    if (role === 'REMOTE') remote = true;
  }
  if (!files.length || !remote && !unknown) return false;
  if (unknown || files.some(word => !literalSourceWord(word) || literalSourceWord(word).text === '-' || literalSourceWord(word).text.startsWith(':'))) return 'UNKNOWN';
  return 'FORBIDDEN';
}

/** scp -S is local executable source even for downloads; only proven entirely local copies ignore it. */
/** OpenSSH 10.3p1 SCP forwards options before the first operand to its child SSH. */
function scpOperation(invocation) {
  let unknown = Boolean(invocation.incomplete);
  let afterDD = false;
  const operands = [];
  const sshArgs = [
    { text: '-oPermitLocalCommand=no', dynamic: false },
    { text: '-oRemoteCommand=none', dynamic: false },
  ];
  let connectionProgram;
  let directProgram;
  let legacy = false;
  let server = false;
  for (let k = 0; k < invocation.args.length; k++) {
    const word = invocation.args[k];
    const literal = literalSourceWord(word);
    const text = literal ? literal.text : word.text;
    if (!literal) unknown = true;
    if (!afterDD && text === '--') { afterDD = true; continue; }
    if (!afterDD && text.startsWith('-') && text !== '-') {
      if (text.startsWith('--')) { unknown = true; continue; }
      for (let p = 1; p < text.length; p++) {
        if ('cDFiJlMoPSX'.includes(text[p])) {
          const value = p + 1 < text.length ? { ...(literal || word), text: text.slice(p + 1), literalValue: undefined } : invocation.args[++k];
          if (!literalSourceWord(value)) unknown = true;
          if (text[p] === 'S') connectionProgram = value || null;
          if (text[p] === 'D') directProgram = value || null;
          if ('ciFJo'.includes(text[p])) {
            sshArgs.push({ ...(literal || word), text: '-' + text[p], literalValue: undefined }, value || { text: '\0', dynamic: true });
          }
          break;
        }
        if (text[p] === 'O') legacy = true;
        if (text[p] === 's') legacy = false;
        if ('ft'.includes(text[p])) server = true;
        if (!'12346ABCTdfOpqRrstv'.includes(text[p])) unknown = true;
      }
      continue;
    }
    // getopt stops here: later option-like operands are filenames, not SSH configuration.
    afterDD = true;
    operands.push(text);
  }
  const roles = operands.map(value => remoteCopyAddressRole('scp', value));
  if (roles.includes('UNKNOWN')) unknown = true;
  const remote = !server && (unknown || !knownInvocationContext(invocation) || operands.length < 2 || roles.includes('REMOTE'));
  const direct = remote && !legacy && directProgram !== undefined;
  return { sshArgs, operands, unknown, sshActive: remote && !direct,
    programActive: direct || remote && connectionProgram !== undefined };
}

function scpConnectionSource(invocation, selectedEnv = false) {
  if (invocation.name !== 'scp') return false;
  const operation = scpOperation(invocation);
  return selectedEnv ? operation.sshActive : operation.programActive;
}

/** Refine only SCP's raw copy match, leaving all selected-source checks below active. */
function knownSingleScpReceiveOnly(inspection) {
  if (inspection.invocations.length !== 1 || inspection.gits.length || inspection.problems.length) return false;
  const invocation = inspection.invocations[0];
  if (invocation.name !== 'scp' || invocation.nonExec || invocation.definitionName || invocation.functionCallName ||
      !knownInvocationContext(invocation) || invocation.scope?.parent || invocation.pipelineParticipant ||
      invocation.redirs.length || invocation.heredocBodies.length || !invocation.args.every(literalSourceWord)) return false;
  const first = invocation.words[0], last = invocation.words.at(-1);
  if (!first || !last || first.text !== invocation.nameWord?.text || !Number.isInteger(first.start) ||
      !Number.isInteger(last.start) || !last.raw || cmd.slice(0, first.start).trim() ||
      cmd.slice(last.start + last.raw.length).trim()) return false;
  const operation = scpOperation(invocation);
  return !operation.unknown && operation.operands.length >= 2 && remoteCopyDestination(invocation) === false;
}

/** Prove an SSH argv query role rather than confusing a consumed value/remote command with it. */
function sshAuthenticationQuery(invocation) {
  let terminal = false;
  let host = false;
  const valueOptions = 'BbcDEeFIiJLlmOopQRSWw';
  const flags = '46AaCfGgKkMNnqsTtVvXxYy';
  for (let k = 0; k < invocation.args.length; k++) {
    const word = invocation.args[k];
    if (!literalSourceWord(word)) return false;
    const text = word.text;
    if (text === '--') break;
    if (!text.startsWith('-') || text === '-') { if (host) break; host = true; continue; }
    for (let p = 1; p < text.length; p++) {
      const option = text[p];
      if ('GQV'.includes(option)) terminal = true;
      if (valueOptions.includes(option)) {
        const value = p + 1 < text.length ? { ...word, text: text.slice(p + 1) } : invocation.args[++k];
        if (!literalSourceWord(value)) return false;
        break;
      }
      if (!flags.includes(option)) return false;
    }
  }
  return terminal;
}

/** A daemon/local rsync route does not select SSH unless an actual remote shell overrides it. */
function rsyncAuthenticationRoute(invocation) {
  let selectedRsh = (invocation.helperEnvNames || []).includes('RSYNC_RSH');
  let unknown = Boolean(invocation.incomplete);
  let afterDD = false;
  const operands = [];
  if (invocation.args.length === 1 && knownWord(invocation.args[0]) && invocation.args[0].text === '--daemon') return false;
  for (let k = 0; k < invocation.args.length; k++) {
    const word = invocation.args[k];
    const text = word.text;
    if (!literalSourceWord(word) && !quotedAttachedOptionValue(word, text, RSYNC_VALUE_SHORT, [...RSYNC_VALUE_LONG])) unknown = true;
    if (!afterDD && text === '--') { afterDD = true; continue; }
    if (!afterDD && ['--help', '--version'].includes(text) && !unknown) return false;
    if (!afterDD && text.startsWith('--')) {
      const eq = text.indexOf('=');
      const option = text.slice(2, eq < 0 ? undefined : eq);
      if (option === 'rsh') selectedRsh = true;
      if (RSYNC_VALUE_LONG.has(option)) {
        const value = eq < 0 ? invocation.args[++k] : { ...word, text: text.slice(eq + 1) };
        if (!value || value.dynamic && value.dynamicMaySplit !== false || value?.globExpanded || value?.braceExpanded) unknown = true;
      } else if (!RSYNC_FLAG_LONG.has(option) || eq >= 0) unknown = true;
      continue;
    }
    if (!afterDD && text.startsWith('-') && text !== '-') {
      for (let p = 1; p < text.length; p++) {
        if (RSYNC_VALUE_SHORT.includes(text[p])) {
          if (text[p] === 'e') selectedRsh = true;
          const value = p + 1 < text.length ? { ...word, text: text.slice(p + 1) } : invocation.args[++k];
          if (!value || value.dynamic && value.dynamicMaySplit !== false || value?.globExpanded || value?.braceExpanded) unknown = true;
          break;
        }
        if (!RSYNC_FLAG_SHORT.includes(text[p])) unknown = true;
      }
      continue;
    }
    operands.push(text);
  }
  if (unknown || operands.length < 2) return true;
  return operands.some(value => {
    const role = remoteCopyAddressRole('rsync', value);
    if (role === 'UNKNOWN') return true;
    const daemon = /^rsync:\/\//i.test(value) || /^[^/:]+::/.test(value);
    return role === 'REMOTE' && (!daemon || selectedRsh);
  });
}

/** SSH_ASKPASS is also a local executable source for active native SSH transport consumers. */
function sshAuthenticationSource(invocation) {
  if (!(invocation.helperEnvNames || []).includes('SSH_ASKPASS') ||
      !['ssh', 'scp', 'sftp', 'rsync'].includes(invocation.name)) return false;
  if (!knownInvocationContext(invocation) || invocation.incomplete) return true;
  if (invocation.name === 'ssh') return !sshAuthenticationQuery(invocation);
  if (invocation.name === 'scp') return scpConnectionSource(invocation, true);
  if (invocation.name === 'rsync') return rsyncAuthenticationRoute(invocation);
  return !(invocation.args.length === 0 || invocation.args.length === 1 && knownWord(invocation.args[0]) &&
    ['-h', '--help'].includes(invocation.args[0].text));
}

/** Identify an executable network verb using parsed command names, never names printed as data. */
// Bounded gh 2.102.0 builtin option-arity facts. Operation membership is not a safety proof.
const GH_ARG_ROLES = new Map([
  ["agent-task",["","",{}]],
  ["agent-task create",["base custom-agent from-file","follow",{"b":"base","a":"custom-agent","F":"from-file"}]],
  ["agent-task list",["jq json limit template","web",{"q":"jq","L":"limit","t":"template","w":"web"}]],
  ["agent-task view",["jq json template","follow log web",{"q":"jq","t":"template","w":"web"}]],
  ["alias",["","",{}]],
  ["alias delete",["","all",{}]],
  ["alias import",["","clobber",{}]],
  ["alias list",["","",{}]],
  ["alias set",["","clobber shell",{"s":"shell"}]],
  ["api",["cache field header hostname input jq method preview raw-field template","allow-escape-sequences include paginate silent slurp verbose",{"F":"field","H":"header","i":"include","q":"jq","X":"method","p":"preview","f":"raw-field","t":"template"}]],
  ["attestation",["","",{}]],
  ["attestation download",["digest-alg hostname limit owner predicate-type repo","",{"d":"digest-alg","L":"limit","o":"owner","R":"repo"}]],
  ["attestation trusted-root",["hostname tuf-root tuf-url","verify-only",{}]],
  ["attestation verify",["bundle cert-identity cert-identity-regex cert-oidc-issuer custom-trusted-root digest-alg format hostname jq limit owner predicate-type repo signer-digest signer-repo signer-workflow source-digest source-ref template","bundle-from-oci deny-self-hosted-runners no-public-good",{"b":"bundle","i":"cert-identity-regex","d":"digest-alg","q":"jq","L":"limit","o":"owner","R":"repo","t":"template"}]],
  ["auth",["","",{}]],
  ["auth login",["git-protocol hostname scopes","clipboard insecure-storage skip-ssh-key web with-token",{"c":"clipboard","p":"git-protocol","h":"hostname","s":"scopes","w":"web"}]],
  ["auth logout",["hostname user","",{"h":"hostname","u":"user"}]],
  ["auth refresh",["hostname remove-scopes scopes","clipboard insecure-storage reset-scopes",{"c":"clipboard","h":"hostname","r":"remove-scopes","s":"scopes"}]],
  ["auth setup-git",["force hostname","",{"f":"force","h":"hostname"}]],
  ["auth status",["hostname jq json template","active show-token",{"a":"active","h":"hostname","t":"show-token"}]],
  ["auth switch",["hostname user","",{"h":"hostname","u":"user"}]],
  ["auth token",["hostname user","",{"h":"hostname","u":"user"}]],
  ["browse",["branch commit","actions blame no-browser projects releases settings wiki",{"a":"actions","b":"branch","c":"commit","n":"no-browser","p":"projects","r":"releases","s":"settings","w":"wiki"}]],
  ["cache",["","",{}]],
  ["cache delete",["ref succeed-on-no-caches","all",{"a":"all","r":"ref"}]],
  ["cache list",["jq json key limit order ref sort template","",{"q":"jq","k":"key","L":"limit","O":"order","r":"ref","S":"sort","t":"template"}]],
  ["codespace",["","",{}]],
  ["codespace code",["codespace repo repo-owner","insiders web",{"c":"codespace","R":"repo","w":"web"}]],
  ["codespace cp",["codespace profile repo repo-owner","expand recursive",{"c":"codespace","e":"expand","p":"profile","r":"recursive","R":"repo"}]],
  ["codespace create",["branch devcontainer-path display-name idle-timeout location machine repo retention-period","default-permissions status web",{"b":"branch","d":"display-name","l":"location","m":"machine","R":"repo","s":"status","w":"web"}]],
  ["codespace delete",["codespace days org repo repo-owner user","all force",{"c":"codespace","f":"force","o":"org","R":"repo","u":"user"}]],
  ["codespace edit",["codespace display-name machine repo repo-owner","",{"c":"codespace","d":"display-name","m":"machine","R":"repo"}]],
  ["codespace jupyter",["codespace repo repo-owner","",{"c":"codespace","R":"repo"}]],
  ["codespace list",["jq json limit org repo template user","web",{"q":"jq","L":"limit","o":"org","R":"repo","t":"template","u":"user","w":"web"}]],
  ["codespace logs",["codespace repo repo-owner","follow",{"c":"codespace","f":"follow","R":"repo"}]],
  ["codespace ports",["codespace jq json repo repo-owner template","",{"c":"codespace","q":"jq","R":"repo","t":"template"}]],
  ["codespace ports forward",["","all-interfaces",{}]],
  ["codespace ports visibility",["","",{}]],
  ["codespace rebuild",["codespace repo repo-owner","full",{"c":"codespace","R":"repo"}]],
  ["codespace ssh",["codespace debug-file profile repo repo-owner server-port","config debug",{"c":"codespace","d":"debug","R":"repo"}]],
  ["codespace stop",["codespace org repo repo-owner user","",{"c":"codespace","o":"org","R":"repo","u":"user"}]],
  ["codespace view",["codespace jq json repo repo-owner template","",{"c":"codespace","q":"jq","R":"repo","t":"template"}]],
  ["completion",["shell","",{"s":"shell"}]],
  ["config",["","",{}]],
  ["config clear-cache",["","",{}]],
  ["config get",["host","",{"h":"host"}]],
  ["config list",["host","",{"h":"host"}]],
  ["config set",["host","",{"h":"host"}]],
  ["copilot",["","remove",{}]],
  ["discussion",["","",{}]],
  ["discussion comment",["body body-file","delete edit yes",{"b":"body","F":"body-file"}]],
  ["discussion create",["body body-file category label title","",{"b":"body","F":"body-file","c":"category","l":"label","t":"title"}]],
  ["discussion edit",["add-label body body-file category remove-label title","",{"b":"body","F":"body-file","c":"category","t":"title"}]],
  ["discussion list",["after author category jq json label limit order search sort state template","answered web",{"A":"author","c":"category","q":"jq","l":"label","L":"limit","S":"search","s":"state","t":"template","w":"web"}]],
  ["discussion view",["after jq json limit order template","comments web",{"c":"comments","q":"jq","L":"limit","t":"template","w":"web"}]],
  ["extension",["","",{}]],
  ["extension browse",["","debug single-column",{"s":"single-column"}]],
  ["extension create",["precompiled","",{}]],
  ["extension exec",["","",{}]],
  ["extension install",["pin","force",{}]],
  ["extension list",["","",{}]],
  ["extension remove",["","",{}]],
  ["extension search",["jq json license limit order owner sort template","web",{"q":"jq","L":"limit","t":"template","w":"web"}]],
  ["extension upgrade",["","all dry-run force",{}]],
  ["gist",["","",{}]],
  ["gist clone",["","",{}]],
  ["gist create",["desc filename","public web",{"d":"desc","f":"filename","p":"public","w":"web"}]],
  ["gist delete",["","yes",{}]],
  ["gist edit",["add desc filename remove","",{"a":"add","d":"desc","f":"filename","r":"remove"}]],
  ["gist list",["filter limit","include-content public secret",{"L":"limit"}]],
  ["gist rename",["","",{}]],
  ["gist view",["filename","allow-escape-sequences files raw web",{"f":"filename","r":"raw","w":"web"}]],
  ["gpg-key",["","",{}]],
  ["gpg-key add",["title","",{"t":"title"}]],
  ["gpg-key delete",["","yes",{"y":"yes"}]],
  ["gpg-key list",["","",{}]],
  ["issue",["","",{}]],
  ["issue close",["comment duplicate-of reason","",{"c":"comment","r":"reason"}]],
  ["issue comment",["attach body body-file","create-if-none delete-last edit-last editor web yes",{"b":"body","F":"body-file","e":"editor","w":"web"}]],
  ["issue create",["assignee attach blocked-by blocking body body-file label milestone parent project recover template title type","editor web",{"a":"assignee","b":"body","F":"body-file","e":"editor","l":"label","m":"milestone","p":"project","T":"template","t":"title","w":"web"}]],
  ["issue delete",["","yes",{}]],
  ["issue develop",["base branch-repo name worktree","checkout list",{"b":"base","c":"checkout","l":"list","n":"name"}]],
  ["issue edit",["add-assignee add-blocked-by add-blocking add-label add-project add-sub-issue attach body body-file milestone parent remove-assignee remove-blocked-by remove-blocking remove-label remove-project remove-sub-issue title type","remove-milestone remove-parent remove-type",{"b":"body","F":"body-file","m":"milestone","t":"title"}]],
  ["issue list",["app assignee author jq json label limit mention milestone search state template type","web",{"a":"assignee","A":"author","q":"jq","l":"label","L":"limit","m":"milestone","S":"search","s":"state","t":"template","w":"web"}]],
  ["issue lock",["reason","",{"r":"reason"}]],
  ["issue pin",["","",{}]],
  ["issue reopen",["comment","",{"c":"comment"}]],
  ["issue status",["jq json template","",{"q":"jq","t":"template"}]],
  ["issue transfer",["","",{}]],
  ["issue unlock",["","",{}]],
  ["issue unpin",["","",{}]],
  ["issue view",["jq json template","comments web",{"c":"comments","q":"jq","t":"template","w":"web"}]],
  ["label",["","",{}]],
  ["label clone",["","force",{"f":"force"}]],
  ["label create",["color description","force",{"c":"color","d":"description","f":"force"}]],
  ["label delete",["","yes",{}]],
  ["label edit",["color description name","",{"c":"color","d":"description","n":"name"}]],
  ["label list",["jq json limit order search sort template","web",{"q":"jq","L":"limit","S":"search","t":"template","w":"web"}]],
  ["licenses",["","",{}]],
  ["org",["","",{}]],
  ["org list",["limit","",{"L":"limit"}]],
  ["pr",["repo","help",{"R":"repo"}]],
  ["pr checkout",["branch worktree","detach force recurse-submodules",{"b":"branch","f":"force"}]],
  ["pr checks",["interval jq json template","fail-fast required watch web",{"i":"interval","q":"jq","t":"template","w":"web"}]],
  ["pr close",["comment","delete-branch",{"c":"comment","d":"delete-branch"}]],
  ["pr comment",["attach body body-file","create-if-none delete-last edit-last editor web yes",{"b":"body","F":"body-file","e":"editor","w":"web"}]],
  ["pr create",["assignee attach base body body-file head label milestone project recover reviewer template title","draft dry-run editor fill fill-first fill-verbose no-maintainer-edit web",{"a":"assignee","B":"base","b":"body","F":"body-file","d":"draft","e":"editor","f":"fill","H":"head","l":"label","m":"milestone","p":"project","r":"reviewer","T":"template","t":"title","w":"web"}]],
  ["pr diff",["color exclude","allow-escape-sequences name-only patch web",{"e":"exclude","w":"web"}]],
  ["pr edit",["add-assignee add-label add-project add-reviewer attach base body body-file milestone remove-assignee remove-label remove-project remove-reviewer title","remove-milestone",{"B":"base","b":"body","F":"body-file","m":"milestone","t":"title"}]],
  ["pr list",["app assignee author base head jq json label limit search state template","draft web",{"a":"assignee","A":"author","B":"base","d":"draft","H":"head","q":"jq","l":"label","L":"limit","S":"search","s":"state","t":"template","w":"web"}]],
  ["pr lock",["reason","",{"r":"reason"}]],
  ["pr merge",["author-email body body-file match-head-commit subject","admin auto delete-branch disable-auto merge rebase squash",{"A":"author-email","b":"body","F":"body-file","d":"delete-branch","m":"merge","r":"rebase","s":"squash","t":"subject"}]],
  ["pr ready",["","undo",{}]],
  ["pr reopen",["comment","",{"c":"comment"}]],
  ["pr revert",["body body-file title","draft",{"b":"body","F":"body-file","d":"draft","t":"title"}]],
  ["pr review",["body body-file","approve comment request-changes",{"a":"approve","b":"body","F":"body-file","c":"comment","r":"request-changes"}]],
  ["pr status",["jq json template","conflict-status",{"c":"conflict-status","q":"jq","t":"template"}]],
  ["pr unlock",["","",{}]],
  ["pr update-branch",["","rebase",{}]],
  ["pr view",["jq json template","comments web",{"c":"comments","q":"jq","t":"template","w":"web"}]],
  ["preview",["","",{}]],
  ["preview prompter",["","",{}]],
  ["project",["","",{}]],
  ["project close",["format jq owner template","undo",{"q":"jq","t":"template"}]],
  ["project copy",["format jq source-owner target-owner template title","drafts",{"q":"jq","t":"template"}]],
  ["project create",["format jq owner template title","",{"q":"jq","t":"template"}]],
  ["project delete",["format jq owner template","",{"q":"jq","t":"template"}]],
  ["project edit",["description format jq owner readme template title visibility","",{"d":"description","q":"jq","t":"template"}]],
  ["project field-create",["data-type format jq name owner single-select-options template","",{"q":"jq","t":"template"}]],
  ["project field-delete",["format id jq template","",{"q":"jq","t":"template"}]],
  ["project field-list",["format jq limit owner template","",{"q":"jq","L":"limit","t":"template"}]],
  ["project item-add",["format jq owner template url","",{"q":"jq","t":"template"}]],
  ["project item-archive",["format id jq owner template","undo",{"q":"jq","t":"template"}]],
  ["project item-create",["body format jq owner template title","",{"q":"jq","t":"template"}]],
  ["project item-delete",["format id jq owner template","",{"q":"jq","t":"template"}]],
  ["project item-edit",["body date field field-id format id iteration-id jq number owner project-id single-select-option-id template text title url value","clear",{"q":"jq","t":"template"}]],
  ["project item-list",["field field-id format jq limit owner query template","",{"q":"jq","L":"limit","t":"template"}]],
  ["project link",["owner repo team","",{"R":"repo","T":"team"}]],
  ["project list",["format jq limit owner template","closed web",{"q":"jq","L":"limit","t":"template","w":"web"}]],
  ["project mark-template",["format jq owner template","undo",{"q":"jq","t":"template"}]],
  ["project unlink",["owner repo team","",{"R":"repo","T":"team"}]],
  ["project view",["format jq owner template","web",{"q":"jq","t":"template","w":"web"}]],
  ["release",["","",{}]],
  ["release create",["discussion-category notes notes-file notes-start-tag target title","draft fail-on-no-commits generate-notes latest notes-from-tag prerelease verify-tag",{"d":"draft","n":"notes","F":"notes-file","p":"prerelease","t":"title"}]],
  ["release delete",["","cleanup-tag yes",{"y":"yes"}]],
  ["release delete-asset",["","yes",{"y":"yes"}]],
  ["release download",["archive dir output pattern","allow-escape-sequences clobber skip-existing",{"A":"archive","D":"dir","O":"output","p":"pattern"}]],
  ["release edit",["discussion-category notes notes-file tag target title","draft latest prerelease verify-tag",{"n":"notes","F":"notes-file","t":"title"}]],
  ["release list",["jq json limit order template","exclude-drafts exclude-pre-releases",{"q":"jq","L":"limit","O":"order","t":"template"}]],
  ["release upload",["","clobber",{}]],
  ["release verify",["format jq template","",{"q":"jq","t":"template"}]],
  ["release verify-asset",["format jq template","",{"q":"jq","t":"template"}]],
  ["release view",["jq json template","web",{"q":"jq","t":"template","w":"web"}]],
  ["repo",["","",{}]],
  ["repo archive",["","yes",{"y":"yes"}]],
  ["repo autolink",["","",{}]],
  ["repo autolink create",["","numeric",{"n":"numeric"}]],
  ["repo autolink delete",["","yes",{}]],
  ["repo autolink list",["jq json template","web",{"q":"jq","t":"template","w":"web"}]],
  ["repo autolink view",["jq json template","",{"q":"jq","t":"template"}]],
  ["repo clone",["upstream-remote-name","no-upstream",{"u":"upstream-remote-name"}]],
  ["repo create",["description gitignore homepage license remote source team template","add-readme clone disable-issues disable-wiki include-all-branches internal private public push",{"c":"clone","d":"description","g":"gitignore","h":"homepage","l":"license","r":"remote","s":"source","t":"team","p":"template"}]],
  ["repo delete",["","yes",{}]],
  ["repo deploy-key",["","",{}]],
  ["repo deploy-key add",["title","allow-write",{"w":"allow-write","t":"title"}]],
  ["repo deploy-key delete",["","",{}]],
  ["repo deploy-key list",["jq json template","",{"q":"jq","t":"template"}]],
  ["repo edit",["add-topic default-branch description homepage remove-topic squash-merge-commit-message visibility","accept-visibility-change-consequences allow-forking allow-update-branch delete-branch-on-merge enable-advanced-security enable-auto-merge enable-discussions enable-issues enable-merge-commit enable-projects enable-rebase-merge enable-secret-scanning enable-secret-scanning-push-protection enable-squash-merge enable-wiki template",{"d":"description","h":"homepage"}]],
  ["repo fork",["fork-name org remote-name","clone default-branch-only remote",{}]],
  ["repo gitignore",["","",{}]],
  ["repo gitignore list",["","",{}]],
  ["repo gitignore view",["","",{}]],
  ["repo license",["","",{}]],
  ["repo license list",["","",{}]],
  ["repo license view",["","web",{"w":"web"}]],
  ["repo list",["jq json language limit template topic visibility","archived fork no-archived source",{"q":"jq","l":"language","L":"limit","t":"template"}]],
  ["repo read-dir",["jq json ref template","",{"q":"jq","t":"template"}]],
  ["repo read-file",["jq json output ref template","allow-escape-sequences clobber",{"q":"jq","o":"output","t":"template"}]],
  ["repo rename",["","yes",{"y":"yes"}]],
  ["repo set-default",["","unset view",{"u":"unset","v":"view"}]],
  ["repo sync",["branch source","force",{"b":"branch","s":"source"}]],
  ["repo unarchive",["","yes",{"y":"yes"}]],
  ["repo view",["branch jq json template","web",{"b":"branch","q":"jq","t":"template","w":"web"}]],
  ["ruleset",["","",{}]],
  ["ruleset check",["","default web",{"w":"web"}]],
  ["ruleset list",["limit org","parents web",{"L":"limit","o":"org","p":"parents","w":"web"}]],
  ["ruleset view",["org","parents web",{"o":"org","p":"parents","w":"web"}]],
  ["run",["","",{}]],
  ["run cancel",["","force",{}]],
  ["run delete",["","",{}]],
  ["run download",["dir name pattern","",{"D":"dir","n":"name","p":"pattern"}]],
  ["run list",["branch commit created event jq json limit status template user workflow","all",{"a":"all","b":"branch","c":"commit","e":"event","q":"jq","L":"limit","s":"status","t":"template","u":"user","w":"workflow"}]],
  ["run rerun",["job","debug failed",{"d":"debug","j":"job"}]],
  ["run view",["attempt job jq json template","exit-status log log-failed verbose web",{"a":"attempt","j":"job","q":"jq","t":"template","v":"verbose","w":"web"}]],
  ["run watch",["interval","compact exit-status",{"i":"interval"}]],
  ["search",["","",{}]],
  ["search code",["extension filename jq json language limit match owner repo size template","web",{"q":"jq","L":"limit","R":"repo","t":"template","w":"web"}]],
  ["search commits",["author author-date author-email author-name committer committer-date committer-email committer-name hash jq json limit order owner parent repo sort template tree visibility","merge web",{"q":"jq","L":"limit","R":"repo","t":"template","w":"web"}]],
  ["search issues",["app assignee author closed commenter comments created interactions involves jq json label language limit match mentions milestone order owner project reactions repo search-type sort state team-mentions template updated visibility","archived include-prs locked no-assignee no-label no-milestone no-project web",{"q":"jq","L":"limit","R":"repo","t":"template","w":"web"}]],
  ["search prs",["app assignee author base checks closed commenter comments created head interactions involves jq json label language limit match mentions merged-at milestone order owner project reactions repo review review-requested reviewed-by sort state team-mentions template updated visibility","archived draft locked merged no-assignee no-label no-milestone no-project web",{"B":"base","H":"head","q":"jq","L":"limit","R":"repo","t":"template","w":"web"}]],
  ["search repos",["created followers forks good-first-issues help-wanted-issues include-forks jq json language license limit match number-topics order owner size sort stars template topic updated visibility","archived web",{"q":"jq","L":"limit","t":"template","w":"web"}]],
  ["secret",["","",{}]],
  ["secret delete",["app env org","user",{"a":"app","e":"env","o":"org","u":"user"}]],
  ["secret list",["app env jq json org template","user",{"a":"app","e":"env","q":"jq","o":"org","t":"template","u":"user"}]],
  ["secret set",["app body env env-file org repos visibility","no-repos-selected no-store user",{"a":"app","b":"body","e":"env","f":"env-file","o":"org","r":"repos","u":"user","v":"visibility"}]],
  ["skill",["","",{}]],
  ["skill install",["agent dir pin scope","all allow-hidden-dirs force from-local upstream",{"f":"force"}]],
  ["skill list",["agent dir jq json scope template","",{"q":"jq","t":"template"}]],
  ["skill preview",["","allow-hidden-dirs",{}]],
  ["skill publish",["tag","dry-run fix",{}]],
  ["skill search",["jq json limit owner page template","",{"q":"jq","L":"limit","t":"template"}]],
  ["skill update",["dir","all dry-run force unpin",{}]],
  ["ssh-key",["","",{}]],
  ["ssh-key add",["title type","",{"t":"title"}]],
  ["ssh-key delete",["","yes",{"y":"yes"}]],
  ["ssh-key list",["","",{}]],
  ["status",["exclude org","",{"e":"exclude","o":"org"}]],
  ["variable",["","",{}]],
  ["variable delete",["env org","",{"e":"env","o":"org"}]],
  ["variable get",["env jq json org template","",{"e":"env","q":"jq","o":"org","t":"template"}]],
  ["variable list",["env jq json org template","",{"e":"env","q":"jq","o":"org","t":"template"}]],
  ["variable set",["body env env-file org repos visibility","",{"b":"body","e":"env","f":"env-file","o":"org","r":"repos","v":"visibility"}]],
  ["workflow",["","",{}]],
  ["workflow disable",["","",{}]],
  ["workflow enable",["","",{}]],
  ["workflow list",["jq json limit template","all",{"a":"all","q":"jq","L":"limit","t":"template"}]],
  ["workflow run",["field raw-field ref","json",{"F":"field","f":"raw-field","r":"ref"}]],
  ["workflow view",["ref","web yaml",{"r":"ref","w":"web","y":"yaml"}]],
]);
const GH_BUILTIN_ALIASES = new Map([["agent","agent-task"],["agent-tasks","agent-task"],["agents","agent-task"],["alias ls","alias list"],["at","attestation"],["cache ls","cache list"],["codespace ls","codespace list"],["config ls","config list"],["cs","codespace"],["cs ls","codespace list"],["discussion ls","discussion list"],["ext","extension"],["ext ls","extension list"],["ext uninstall","extension remove"],["extension ls","extension list"],["extension uninstall","extension remove"],["extensions","extension"],["extensions ls","extension list"],["extensions uninstall","extension remove"],["gist ls","gist list"],["gist new","gist create"],["gpg-key ls","gpg-key list"],["issue ls","issue list"],["issue new","issue create"],["label ls","label list"],["org ls","org list"],["pr co","pr checkout"],["pr ls","pr list"],["pr new","pr create"],["project ls","project list"],["release ls","release list"],["release new","release create"],["repo autolink ls","repo autolink list"],["repo autolink new","repo autolink create"],["repo deploy-key ls","repo deploy-key list"],["repo gitignore ls","repo gitignore list"],["repo license ls","repo license list"],["repo ls","repo list"],["repo new","repo create"],["rs","ruleset"],["rs ls","ruleset list"],["ruleset ls","ruleset list"],["run ls","run list"],["secret ls","secret list"],["secret remove","secret delete"],["skill add","skill install"],["skill ls","skill list"],["skill show","skill preview"],["skills","skill"],["skills add","skill install"],["skills ls","skill list"],["skills show","skill preview"],["ssh-key ls","ssh-key list"],["variable ls","variable list"],["variable remove","variable delete"],["workflow ls","workflow list"]]);

/** Resolve a builtin operation and option roles without executing GH or consulting user configuration. */
function ghCommandRoles(invocation) {
  const words = invocation.args;
  const metadata = [];
  let k = 0, unknown = !!invocation.incomplete;
  const boundary = word => !!word && word.dynamicMaySplit === false && !word.ansiCUnknown &&
    !word.globExpanded && !word.braceExpanded && !word.tildeExpanded;
  const takeRepo = () => {
    const word = words[k], literal = literalSourceWord(word), text = literal?.text || word?.text || '';
    if (!['--repo', '-R'].includes(text) && !text.startsWith('--repo=') && !/^-R./.test(text)) return false;
    const value = ['--repo', '-R'].includes(text) ? words[++k] : { ...word,
      text: text.startsWith('--repo=') ? text.slice(7) : text.slice(2),
      literalValue: typeof word.literalValue === 'string' ? word.literalValue.slice(text.startsWith('--repo=') ? 7 : 2) : word.literalValue };
    if (!boundary(word) || !boundary(value)) unknown = true;
    metadata.splice(0, metadata.length, value); k++; return true;
  };
  while (k < words.length && takeRepo()) { /* persistent repo consumes a DATA value */ }
  const first = literalSourceWord(words[k]);
  if (!first) return { unknown: true, metadata, values: [], operands: [] };
  if (['--help', '-h', '--version', 'help'].includes(first.text)) {
    return { terminal: !unknown, unknown, metadata, values: [], operands: [] };
  }
  let operation = null, used = 0;
  for (let count = 1; count <= 3 && k + count <= words.length; count++) {
    const parts = words.slice(k, k + count).map(literalSourceWord);
    if (parts.some(word => !word)) break;
    let name = parts.map(word => word.text).join(' ');
    // Builtin group aliases may precede a canonical child command.
    for (let prefix = count; prefix >= 1; prefix--) {
      const head = parts.slice(0, prefix).map(word => word.text).join(' ');
      if (GH_BUILTIN_ALIASES.has(head)) {
        name = GH_BUILTIN_ALIASES.get(head) + (prefix < count ? ' ' + parts.slice(prefix).map(word => word.text).join(' ') : '');
        break;
      }
    }
    if (GH_ARG_ROLES.has(name)) { operation = name; used = count; }
  }
  if (!operation) return { unknown: true, metadata, values: [], operands: [] };
  // These entrypoints forward argv to external bodies; their --help may belong to that body.
  if (['extension exec', 'copilot'].includes(operation)) return { operation, sourceUnknown: true, metadata, values: [], operands: [] };
  const [valueNames, flagNames, shortNames] = GH_ARG_ROLES.get(operation);
  const takesValue = new Set((valueNames + ' repo').split(' '));
  const flags = new Set((flagNames + ' help').split(' '));
  // Command-specific shorthands win: auth login -h consumes hostname, rather than selecting help.
  const short = { R: 'repo', h: 'help', ...shortNames };
  const values = [], operands = [], selectedFlags = new Map();
  // These builtin string flags select one effective value; earlier evaluated DATA is not sent.
  // Repeatable field/header/label collections keep all their values.
  const singleValueOptions = new Set(['body', 'title', 'body-file', 'notes', 'notes-file', 'input', 'from-file',
    'head', 'base', 'repo', 'hostname', 'env-file', 'env', 'org', 'visibility', 'app', 'ref', 'jq', 'template', 'recover']);
  let afterDD = false;
  for (k += used; k < words.length; k++) {
    const word = words[k], literal = literalSourceWord(word), text = literal?.text || word.text;
    if (!afterDD && text === '--' && literal) { afterDD = true; continue; }
    if (!afterDD && text.startsWith('-') && text !== '-') {
      let option, value;
      if (text.startsWith('--')) {
        const eq = text.indexOf('='); option = text.slice(2, eq < 0 ? undefined : eq);
        if (takesValue.has(option)) value = eq < 0 ? words[++k] : { ...word, text: text.slice(eq + 1),
          literalValue: typeof word.literalValue === 'string' ? word.literalValue.slice(eq + 1) : word.literalValue };
        else if (flags.has(option)) {
          if (!literal || eq >= 0 && !['true', 'false'].includes(text.slice(eq + 1))) unknown = true;
          const enabled = eq < 0 || text.slice(eq + 1) !== 'false';
          selectedFlags.set(option, enabled);
          if (option === 'help' && enabled && !unknown) return { operation, terminal: true, unknown: false, metadata, values, operands };
          continue;
        } else { unknown = true; continue; }
      } else {
        for (let p = 1; p < text.length; p++) {
          const name = short[text[p]];
          if (!name) { unknown = true; continue; }
          if (takesValue.has(name)) {
            option = name; value = p + 1 < text.length ? { ...word, text: text.slice(p + 1),
              literalValue: typeof word.literalValue === 'string' ? word.literalValue.slice(p + 1) : word.literalValue } : words[++k]; break;
          }
          if (!literal) unknown = true;
          selectedFlags.set(name, true);
          if (name === 'help' && !unknown) return { operation, terminal: true, unknown: false, metadata, values, operands };
        }
      }
      if (option) {
        if (!boundary(word) || !boundary(value)) unknown = true;
        if (option === 'repo') metadata.splice(0);
        if (singleValueOptions.has(option)) {
          for (let prior = values.length - 1; prior >= 0; prior--) if (values[prior].option === option) values.splice(prior, 1);
        }
        values.push({ option, word: value });
      }
    } else {
      if (!boundary(word)) unknown = true;
      operands.push(word);
    }
  }
  return { operation, unknown, metadata, values, operands, flags: selectedFlags };
}

/** Classify official operation roles separately from argv, local sources and payload provenance. */
function ghOfficialVerdict(invocation) {
  const role = ghCommandRoles(invocation);
  if (role.terminal) return false;
  if (role.unknown || role.sourceUnknown) return 'UNKNOWN';
  const operation = role.operation;
  const [group, action] = operation.split(' ');
  if (group === 'gist') return 'FORBIDDEN'; // Preserve the existing explicit gist policy, including its query scope.
  const selected = option => role.values.filter(value => value.option === option).map(value => value.word);
  const enabled = option => role.flags?.get(option) === true;
  const local = ['alias', 'config', 'completion', 'help', 'licenses'].includes(group);
  const repoSelected = role.metadata.length > 0 || selected('repo').length > 0;
  const apiRepoPlaceholder = operation === 'api' && role.operands.concat(selected('field')).some(word => {
    const literal = literalSourceWord(word); return !literal || /\{(?:owner|repo)\}|:(?:owner|repo)\b/.test(literal.text);
  });
  // The reference inventory omits inherited flags. Repository groups still select GH_REPO.
  const repoGroups = ['issue', 'pr', 'release', 'workflow', 'run', 'cache', 'label', 'discussion', 'agent-task', 'ruleset', 'browse'];
  const explicitRepoOperand = ['repo view', 'repo edit', 'repo delete', 'repo rename', 'repo fork'].includes(operation) && role.operands.length;
  const usesRepoEnvironment = operation === 'api' ? apiRepoPlaceholder :
    repoGroups.includes(group) || ['secret', 'variable'].includes(group) && !selected('org').length && !enabled('user') ||
    group === 'repo' && !explicitRepoOperand &&
      ['view', 'edit', 'delete', 'rename', 'fork', 'deploy-key', 'autolink'].includes(action);
  const ghMetadataSources = (invocation.ghEnvironmentSources || []).filter(source =>
    source.name === 'GH_REPO' ? !repoSelected && usesRepoEnvironment :
    source.name === 'GH_HOST' ? !selected('hostname').length : true);
  if (operation === 'config set' && role.operands.length >= 2) {
    const key = literalSourceWord(role.operands[0]), value = literalSourceWord(role.operands[1]);
    if (!key) return 'UNKNOWN';
    if (['pager', 'editor', 'browser', 'api_host', 'http_unix_socket'].includes(key.text)) {
      const hostPager = key.text === 'pager' && selected('host').length && selected('host').every(literalSourceWord);
      const disabledPager = key.text === 'pager' && value && ['', 'cat'].includes(value.text);
      if (!hostPager && !disabledPager) return 'UNKNOWN'; // Persistent source selection also affects later Bash calls.
    }
  }
  const fileOptions = operation === 'api' ? ['input'] :
    operation === 'agent-task create' ? ['from-file'] :
    ['secret set', 'variable set'].includes(operation) ? [] : // Existing set/collection policy is retained below.
    ['release create', 'release edit'].includes(operation) ? ['notes-file'] :
    ['issue create', 'issue edit', 'issue comment', 'pr create', 'pr edit', 'pr comment', 'pr review', 'pr merge', 'pr revert',
      'discussion create', 'discussion edit', 'discussion comment'].includes(operation) ? ['body-file', 'attach'] : [];
  let stdin = false;
  for (const option of fileOptions) for (const word of selected(option)) {
    const file = literalSourceWord(word);
    if (!file || !file.text) return 'UNKNOWN';
    if (file.text === '-') stdin = true;
    else return 'FORBIDDEN';
  }
  if (operation === 'api') for (const word of selected('field')) {
    const literal = literalSourceWord(word), eq = literal?.text.indexOf('=');
    if (literal && eq > 0 && literal.text.slice(eq + 1).startsWith('@')) {
      const source = literal.text.slice(eq + 2);
      if (!source) return 'UNKNOWN';
      if (source === '-') stdin = true;
      else return 'FORBIDDEN';
    }
  }
  if (['gpg-key add', 'ssh-key add', 'repo deploy-key add'].includes(operation)) {
    if (role.operands.length > 1) return 'UNKNOWN';
    if (!role.operands.length || literalSourceWord(role.operands[0])?.text === '-') stdin = true;
    else return literalSourceWord(role.operands[0]) ? 'FORBIDDEN' : 'UNKNOWN';
  }
  const localSkillValidation = operation === 'skill publish' && (enabled('dry-run') || enabled('fix'));
  if (operation === 'skill publish' && !localSkillValidation) {
    return role.operands.length && role.operands.every(literalSourceWord) ? 'FORBIDDEN' : 'UNKNOWN';
  }
  if (stdin) {
    const verdict = stdinPayloadVerdict(invocation, invocationSources.get(invocation) || [], true);
    if (verdict) return verdict;
    if (!shellStdinSource(invocation)) return 'UNKNOWN';
  }
  const selectedHelpers = invocation.ghHelperEnvironmentSources || [];
  const configRootNames = ['GH_CONFIG_DIR', 'XDG_CONFIG_HOME', ...(process.platform === 'win32' ? ['AppData'] : []), 'HOME'];
  const configRoot = configRootNames.map(name => selectedHelpers.find(source => source.name === name))
    .find(source => source && literalSourceWord(source.word)?.text !== '');
  if (!local && configRoot && !configRoot.word?.defaultGhConfigRoot) return 'UNKNOWN';
  const pageable = !local && (['list', 'view', 'diff', 'checks', 'status', 'search'].includes(action) || group === 'search');
  const ghPager = selectedHelpers.find(source => source.name === 'GH_PAGER');
  const pagerSource = ghPager ||
    (invocation.gitPagerEnvSources || []).find(source => source.name === 'PAGER');
  const pagerWord = pagerSource && literalSourceWord(pagerSource.word);
  // v2.102.0 issue list calls StartPager before Exporter.Write; --json is not a source-disabling proof.
  if (pageable && pagerSource && (!pagerWord || !['', 'cat'].includes(pagerWord.text))) return 'UNKNOWN';
  const configuredBefore = (invocationSources.get(invocation) || []).filter(prior => prior.name === 'gh' &&
    prior.order < invocation.order && !prior.nonExec && !prior.definitionName && !prior.functionCallName)
    .map(ghCommandRoles).filter(prior => prior.operation === 'config set' && !prior.terminal && !prior.unknown &&
      prior.operands.length >= 2 && !prior.values.some(value => value.option === 'host'));
  // Official root selection is GH_PAGER presence > config pager > PAGER. A consumed host setting is not global pager.
  if (pageable && !ghPager && configuredBefore.some(prior => literalSourceWord(prior.operands[0])?.text === 'pager')) return 'UNKNOWN';
  if (!local && configuredBefore.some(prior => ['http_unix_socket', 'api_host'].includes(literalSourceWord(prior.operands[0])?.text))) return 'UNKNOWN';
  if (group === 'browse' && !enabled('no-browser') || enabled('web') || enabled('editor')) return 'UNKNOWN';
  if (['auth login', 'auth refresh', 'auth setup-git'].includes(operation) ||
      ['attestation download', 'attestation verify', 'attestation trusted-root', 'extension create'].includes(operation)) {
    return 'UNKNOWN'; // Credential collection, artifact-derived requests or constructor-selected sources are uninspected.
  }
  if (['codespace ssh', 'codespace cp', 'codespace code', 'codespace jupyter', 'codespace ports forward',
    'extension install', 'extension upgrade', 'skill install', 'skill preview', 'skill update',
    'pr checkout', 'issue develop', 'repo clone'].includes(operation)) return 'UNKNOWN';
  if (operation === 'repo create' && (enabled('push') || enabled('clone') || selected('source').length || !role.operands.length) ||
      operation === 'repo fork' && role.flags?.get('clone') !== false) return 'UNKNOWN';
  // Retain a proven payload prohibition before the additional implicit-source uncertainty below.
  const scalarWords = local || localSkillValidation || group === 'browse' && enabled('no-browser') ? [] : role.metadata.concat(role.operands,
    role.values.filter(value => !fileOptions.includes(value.option) && !['jq', 'template'].includes(value.option)).map(value => value.word),
    ghMetadataSources.map(source => source.word));
  const scalar = outboundPayloadVerdict(invocation, scalarWords);
  if (scalar) return scalar;
  if (['issue create', 'pr create', 'issue comment', 'pr comment', 'discussion create', 'discussion comment', 'agent-task create'].includes(operation)) {
    const body = selected('body');
    const suppliedBody = body.length || selected('body-file').length || selected('from-file').length ||
      operation === 'agent-task create' && role.operands.length;
    const needsTitle = ['issue create', 'pr create', 'discussion create'].includes(operation);
    if (!suppliedBody || needsTitle && !selected('title').length || selected('template').length || selected('recover').length ||
        ['fill', 'fill-first', 'fill-verbose'].some(enabled)) return 'UNKNOWN';
    if (operation === 'pr create' && !selected('head').some(word => {
      const head = literalSourceWord(word); return head && head.text !== '';
    })) return 'UNKNOWN'; // Explicit nonempty head skips the documented implicit push/fork path.
  }
  if (localSkillValidation) return false; // No publishing, after independent source/context boundaries above.
  if (group === 'browse' && enabled('no-browser')) return role.metadata.concat(role.operands,
    role.values.map(value => value.word), ghMetadataSources.map(source => source.word)).every(literalSourceWord) ? false : 'UNKNOWN';
  // Local registration/getters do not send their scalar operands. Later invocation is independently classified.
  if (role.values.some(value => ['jq', 'template'].includes(value.option) && !literalSourceWord(value.word))) return 'UNKNOWN';
  // Reuse the specialized workflow/set/release contracts on canonical operation bytes.
  const canonical = operation.split(' ').map(text => ({ text, raw: "'" + text + "'", quoted: true, dynamic: false, dynamicMaySplit: false }));
  // Reuse effective roles, preserving original payload-word offsets and provenance.
  // Reparsing original argv would revive overwritten singleton values as transmitted data.
  const optionWord = text => ({ text, raw: "'" + text + "'", quoted: true, dynamic: false, dynamicMaySplit: false });
  const normalizedArgs = canonical.concat(role.metadata.flatMap(word => [optionWord('--repo'), word]),
    role.values.flatMap(value => [optionWord('--' + value.option), value.word]),
    [...role.flags].map(([name, enabled]) => optionWord('--' + name + (enabled ? '' : '=false'))),
    role.operands.length ? [optionWord('--'), ...role.operands] : []);
  const normalized = { ...invocation, args: normalizedArgs,
    ghStdinPayloadProven: stdin && Boolean(shellStdinSource(invocation)) };
  invocationSources.set(normalized, invocationSources.get(invocation) || []);
  if (['release', 'issue', 'pr', 'ssh-key', 'repo', 'secret', 'variable', 'workflow'].includes(group)) return ghFilePayload(normalized);
  return false;
}

function networkInvocation(invocation) {
  return ['curl', 'wget', 'nc', 'ncat', 'scp', 'sftp', 'rsync', 'telnet'].includes(invocation.name) ||
    (invocation.name === 'gh' && invocation.args[0] && invocation.args[0].text === 'gist');
}

/** Bounded GH writes share file/stdin payload roles while keeping literal option values as DATA. */
function ghFilePayload(invocation) {
  const words = invocation.args;
  let start = 0;
  let prefixUnknown = false;
  while (start < words.length) {
    const literal = literalSourceWord(words[start]), text = literal?.text || words[start].text;
    if (literal && ['--help', '-h'].includes(text)) return false;
    if (text === '--repo' || text.startsWith('--repo=') || text === '-R' || /^-R./.test(text)) {
      const value = text === '--repo' || text === '-R' ? words[++start] :
        { ...words[start], text: text.startsWith('--repo=') ? text.slice(7) : text.slice(2) };
      if (!literal || !literalSourceWord(value)) prefixUnknown = true;
      start++;
    } else break;
  }
  const groupWord = literalSourceWord(words[start]);
  if (!groupWord) return words.length ? 'UNKNOWN' : false;
  const group = groupWord.text;
  if (group.startsWith('-') && words.some((word, index) =>
      ['secret', 'variable'].includes(literalSourceWord(word)?.text) && literalSourceWord(words[index + 1])?.text === 'set' ||
      literalSourceWord(word)?.text === 'workflow' && literalSourceWord(words[index + 1])?.text === 'run')) return 'UNKNOWN';
  if (!['release', 'issue', 'pr', 'ssh-key', 'repo', 'secret', 'variable', 'workflow'].includes(group)) return false;
  if (group === 'repo') {
    if (!literalSourceWord(words[start + 1])) return 'UNKNOWN';
    if (literalSourceWord(words[start + 1]).text !== 'deploy-key') return false;
  }
  const specFor = action => {
    if (group === 'workflow') return action === 'run' ? {
      values: ['field', 'raw-field', 'ref'], short: { F: 'field', f: 'raw-field', r: 'ref' },
      files: [], flags: ['json'], shortFlags: '', min: 0, max: 1, assetStart: Infinity, workflow: true,
    } : null;
    if (['secret', 'variable'].includes(group)) return action === 'set' ? {
      values: ['body', 'env', 'env-file', 'org', 'repos', 'visibility', ...(group === 'secret' ? ['app'] : [])],
      short: { b: 'body', e: 'env', f: 'env-file', o: 'org', r: 'repos', v: 'visibility', ...(group === 'secret' ? { a: 'app' } : {}) },
      files: ['env-file'], flags: group === 'secret' ? ['user', 'no-repos-selected', 'no-store'] : [],
      shortFlags: group === 'secret' ? 'u' : '', min: 0, max: 1, assetStart: Infinity, setValue: true,
    } : null;
    if (group === 'ssh-key' && action === 'add' || group === 'repo' && action === 'add') return {
      values: group === 'ssh-key' ? ['title', 'type'] : ['title'], short: { t: 'title' }, files: [],
      flags: group === 'repo' ? ['allow-write'] : [], shortFlags: group === 'repo' ? 'w' : '', min: 0, max: 1, assetStart: 0, implicitStdin: true,
    };
    if (group === 'release' && action === 'upload') return {
      values: [], short: {}, files: [], flags: ['clobber'], shortFlags: '', min: 2, max: Infinity, assetStart: 1,
    };
    if (group === 'release' && action === 'create') return {
      values: ['discussion-category', 'notes', 'notes-file', 'notes-start-tag', 'target', 'title'],
      short: { n: 'notes', F: 'notes-file', t: 'title' }, files: ['notes-file'],
      flags: ['draft', 'fail-on-no-commits', 'generate-notes', 'latest', 'notes-from-tag', 'prerelease', 'verify-tag'],
      shortFlags: 'dp', min: 0, max: Infinity, assetStart: 1,
    };
    if (group === 'release' && action === 'edit') return {
      values: ['discussion-category', 'notes', 'notes-file', 'tag', 'target', 'title'],
      short: { n: 'notes', F: 'notes-file', t: 'title' }, files: ['notes-file'],
      flags: ['draft', 'latest', 'prerelease', 'verify-tag'], shortFlags: '',
      min: 1, max: 1, assetStart: Infinity,
    };
    if (group === 'release') return null;
    if (action !== 'create' && action !== 'edit') return null;
    const create = action === 'create';
    const values = create ? ['assignee', 'attach', 'body', 'body-file', 'label', 'milestone', 'project', 'recover', 'title'] :
      ['add-assignee', 'add-label', 'add-project', 'attach', 'body', 'body-file', 'milestone', 'remove-assignee', 'remove-label', 'remove-project', 'title'];
    const short = create ? { a: 'assignee', b: 'body', F: 'body-file', l: 'label', m: 'milestone', p: 'project', t: 'title' } :
      { b: 'body', F: 'body-file', m: 'milestone', t: 'title' };
    let flags = create ? ['editor', 'web'] : ['remove-milestone'];
    if (group === 'issue') {
      values.push(...(create ? ['blocked-by', 'blocking', 'parent', 'template', 'type'] :
        ['add-blocked-by', 'add-blocking', 'add-sub-issue', 'parent', 'remove-blocked-by', 'remove-blocking', 'remove-sub-issue', 'type']));
      if (create) short.T = 'template';
      else flags.push('remove-parent', 'remove-type');
    } else {
      values.push(...(create ? ['base', 'head', 'reviewer', 'template'] : ['base', 'add-reviewer', 'remove-reviewer']));
      short.B = 'base';
      if (create) { short.H = 'head'; short.r = 'reviewer'; short.T = 'template'; flags.push('draft', 'dry-run', 'fill', 'fill-first', 'fill-verbose', 'no-maintainer-edit'); }
    }
    return { values, short, files: ['body-file', 'attach'], flags, shortFlags: create ? group === 'issue' ? 'ew' : 'dewf' : '',
      min: group === 'issue' && !create ? 1 : 0, max: create ? 0 : group === 'issue' ? Infinity : 1, assetStart: Infinity };
  };
  let action;
  let spec;
  let afterDD = false;
  const operands = [];
  let unknown = !!invocation.incomplete || prefixUnknown;
  let sourceUnknown = false;
  let payload = false;
  let bodyWord = null;
  let envFileStdin = false;
  let noStore = false;
  let jsonStdin = false;
  let fieldStdin = false;
  const transmittedValueWords = [];
  const dataBoundary = word => Boolean(word && word.dynamicMaySplit === false && !word.ansiCUnknown &&
    !word.globExpanded && !word.braceExpanded && !word.tildeExpanded);
  for (let k = start + (group === 'repo' ? 2 : 1); k < words.length; k++) {
    const word = words[k];
    const text = literalSourceWord(word)?.text || word.text;
    if (!afterDD && text === '--') { afterDD = true; continue; }
    if (!afterDD && ['-h', '--help'].includes(text) && !unknown) return false;
    if (!afterDD && text.startsWith('-')) {
      let option;
      let value;
      if (text.startsWith('--')) {
        const eq = text.indexOf('=');
        option = text.slice(2, eq < 0 ? undefined : eq);
        if (option === 'repo' || spec?.values.includes(option)) value = eq < 0 ? words[++k] : { ...word, text: text.slice(eq + 1),
          literalValue: typeof word.literalValue === 'string' ? word.literalValue.slice(eq + 1) : word.literalValue };
        else if (option === 'help' || spec?.flags.includes(option)) {
          if (!knownWord(word) || eq >= 0 && !['true', 'false'].includes(text.slice(eq + 1))) unknown = true;
          if (option === 'help' && text.slice(eq + 1) === 'true' && !unknown) return false;
          if (spec?.setValue && option === 'no-store') noStore = eq < 0 || text.slice(eq + 1) !== 'false';
          if (spec?.workflow && option === 'json') jsonStdin = eq < 0 || text.slice(eq + 1) !== 'false';
          continue;
        } else { unknown = true; continue; }
      } else {
        for (let p = 1; p < text.length; p++) {
          option = text[p] === 'R' ? 'repo' : spec?.short[text[p]];
          if (option) { value = p + 1 < text.length ? { ...word, text: text.slice(p + 1),
            literalValue: typeof word.literalValue === 'string' ? word.literalValue.slice(p + 1) : word.literalValue } : words[++k]; break; }
          if (text[p] === 'h' && knownWord(word) && !unknown) return false;
          if (!knownWord(word) || !spec?.shortFlags.includes(text[p])) unknown = true;
        }
      }
      if (!option) continue;
      if (!value || !dataBoundary(word) || !dataBoundary(value)) unknown = true;
      if (spec?.files.includes(option)) {
        const file = literalSourceWord(value);
        if (spec.setValue && file?.text === '-') envFileStdin = true;
        else if (!file || file.text === '-' && !invocation.ghStdinPayloadProven) sourceUnknown = true;
        else if (file.text === '-') { /* The operation's actual fd 0 source was proved above. */ }
        else payload = true;
      } else if (spec?.workflow && ['field', 'raw-field'].includes(option)) {
        const scalar = literalSourceWord(value), pair = scalar?.text.indexOf('=');
        if (scalar && pair > 0) {
          const selected = scalar.text.slice(pair + 1);
          if (option === 'field' && selected.startsWith('@')) {
            if (selected === '@-') fieldStdin = true;
            else if (selected.length === 1) sourceUnknown = true;
            else payload = true;
          }
        } else if (scalar) sourceUnknown = true;
        transmittedValueWords.push(value);
      } else if (spec?.setValue && option === 'body') bodyWord = value;
      else if (spec && ['body', 'notes', 'title'].includes(option)) transmittedValueWords.push(value);
      else if (!literalSourceWord(value)) sourceUnknown = true;
      continue;
    }
    if (!action) {
      if (!literalSourceWord(word)) return 'UNKNOWN';
      action = text === 'new' ? 'create' : text;
      spec = specFor(action);
      if (!spec) return false; // Queries and other operations keep their existing guard conditions.
    } else {
      if (!literalSourceWord(word)) sourceUnknown = true;
      if (!dataBoundary(word)) unknown = true;
      operands.push(word);
    }
  }
  if (!spec) return unknown ? 'UNKNOWN' : false;
  if (unknown || sourceUnknown || operands.length < spec.min || operands.length > spec.max) return 'UNKNOWN';
  if (spec.workflow) {
    if (payload) return 'FORBIDDEN';
    const inline = outboundPayloadVerdict(invocation, transmittedValueWords);
    if (inline) return inline;
    if (jsonStdin || fieldStdin) {
      const stdin = stdinPayloadVerdict(invocation, invocationSources.get(invocation) || [], true);
      if (stdin) return stdin;
      return shellStdinSource(invocation) ? false : 'UNKNOWN'; // Proven literal fd 0 bytes are payload DATA, not executable source.
    }
    return operands.length ? false : 'UNKNOWN'; // Interactive selector/input collection is uninspected.
  }
  if (spec.setValue) {
    if (noStore) return 'UNKNOWN';
    if (payload) return 'FORBIDDEN';
    if (envFileStdin || !bodyWord || literalSourceWord(bodyWord)?.text === '') {
      return stdinPayloadVerdict(invocation, invocationSources.get(invocation) || [], true) || 'UNKNOWN';
    }
    if (!operands.length) return 'UNKNOWN';
    return outboundPayloadVerdict(invocation, [bodyWord]);
  }
  if (spec.implicitStdin && !operands.length || spec.implicitStdin && operands[0]?.text === '-') return invocation.ghStdinPayloadProven ? false : 'UNKNOWN';
  return payload || operands.length > spec.assetStart ? 'FORBIDDEN' :
    outboundPayloadVerdict(invocation, transmittedValueWords);
}

/** Select SSH commands/config sources that run locally, retaining proven non-executing query and DATA options. */
function sshCommandSources(invocation) {
  return sshOperation(invocation).sources;
}

/** The supported scalar ssh_config values may use its documented double quotes. */
function sshOptionScalar(word) {
  const literal = literalSourceWord(word);
  if (!literal) return null;
  const text = literal.text.trim();
  if (/^"[^"\\]*"$/.test(text)) return text.slice(1, -1).toLowerCase();
  return /^[^\s"'\\]+$/.test(text) ? text.toLowerCase() : null;
}

/** Read SSH's option boundary before and after the host, stopping at the actual remote command. */
function sshOperation(invocation) {
  if (invocation.name === 'scp') {
    const operation = scpOperation(invocation);
    if (!operation.sshActive) return { sources: [], stdin: false, remoteWords: [] };
    // SCP already selected the remote endpoint; its path operands are not SSH remote argv.
    const result = sshOperation({ ...invocation, name: 'ssh',
      args: [...operation.sshArgs, { text: '__scp_remote__', dynamic: false }],
      incomplete: invocation.incomplete || operation.unknown });
    return { ...result, stdin: false, remoteWords: [],
      sources: operation.unknown || !knownInvocationContext(invocation)
        ? result.sources.map(source => ({ ...source, dynamic: true, literalValue: undefined })) : result.sources };
  }
  if (invocation.name !== 'ssh') return { sources: [], stdin: false, remoteWords: [] };
  const options = new Map();
  const valueOptions = 'BbcDEeFIiJLlmOopQRSWw';
  let query = false;
  let earlyQuery = false;
  let requestedQuery = false;
  let requestedEarlyQuery = false;
  let argvUncertain = false;
  let selectedConfig = false;
  let configFile;
  let unknown = false;
  let host = false;
  let detached = false;
  let remoteWords = [];
  let noRemoteCommand = false;
  for (let k = 0; k < invocation.args.length; k++) {
    const word = invocation.args[k];
    const text = word.text;
    if (text === '--') {
      remoteWords = invocation.args.slice(k + (host ? 1 : 2));
      host = host || Boolean(invocation.args[k + 1]);
      break;
    }
    const provenOperand = typeof word.literalValue === 'string' && word.dynamicMaySplit === false && !word.literalValue.startsWith('-');
    if (word.dynamic && !provenOperand && (word.dynamicMaySplit !== false ||
        text.startsWith('\0') && !(host && word.dynamicMaySplit === false))) argvUncertain = true;
    if (!text.startsWith('-') || text === '-') {
      if (host) { remoteWords = invocation.args.slice(k); break; }
      host = true; continue;
    }
    for (let p = 1; p < text.length; p++) {
      if (text[p] === 'G') { requestedQuery = true; if (!argvUncertain) query = true; }
      if (text[p] === 'Q' || text[p] === 'V') { requestedEarlyQuery = true; if (!argvUncertain) earlyQuery = true; }
      if (text[p] === 'n' || text[p] === 'f') detached = true;
      if (text[p] === 'N') noRemoteCommand = true;
      if (!valueOptions.includes(text[p])) continue;
      const original = p + 1 < text.length ? { ...word, text: text.slice(p + 1), literalValue: undefined } : invocation.args[++k];
      const value = literalSourceWord(original) || original;
      if (value?.dynamic && (value.dynamicMaySplit !== false || (p + 1 < text.length && value.text.startsWith('\0')))) argvUncertain = true;
      if (text[p] === 'F') { selectedConfig = true; configFile = value; }
      if (text[p] === 'o') {
        const match = value && /^\s*([^=\s]+)\s*(?:=\s*|\s+)([\s\S]*)$/.exec(value.text);
        if (!match || value.dynamicMaySplit && value.dynamic) unknown = true;
        else if (!options.has(match[1].toLowerCase())) options.set(match[1].toLowerCase(), { ...value, text: match[2], literalValue: undefined });
      }
      if (text[p] === 'J' && value && !options.has('proxyjump')) options.set('proxyjump', value);
      // -I directly assigns the provider, while -o PKCS11Provider obeys first-value wins.
      if (text[p] === 'I') options.set('pkcs11provider', value || { text: '\0', dynamic: true });
      break;
    }
  }
  if (selectedConfig ? earlyQuery : requestedEarlyQuery) return { sources: [], stdin: false, remoteWords: [] };
  if (selectedConfig && (argvUncertain || !configFile || configFile.dynamic || !['none', '/dev/null'].includes(configFile.text))) {
    deny('SSH の -F config が未知の実行 source（Match exec 等）を選び、egress ガードで検査できません (fail-closed)。' + UNKNOWN_OWNER_GATE);
  }
  if (selectedConfig ? query : requestedQuery) return { sources: [], stdin: false, remoteWords: [] };
  if (unknown) deny('SSH の -o option が動的で、ローカル実行 source を確かめられません (fail-closed)。' + UNKNOWN_OWNER_GATE);
  for (const key of ['pkcs11provider', 'securitykeyprovider']) {
    const source = options.get(key);
    const value = sshOptionScalar(source);
    if (source && value !== 'none' && !(key === 'securitykeyprovider' && value === 'internal')) {
      deny('SSH の明示 provider option が選ぶローカル library / environment source と副作用を検査できません。queryまたは意味を確認したnone/internal指定が同目的・同条件を保てなければ' + UNKNOWN_OWNER_GATE);
    }
  }
  const sources = [];
  for (const key of ['proxycommand', 'knownhostscommand', 'localcommand']) {
    const source = options.get(key);
    if (!source || source.text.toLowerCase() === 'none') continue;
    if (key === 'localcommand' && sshOptionScalar(options.get('permitlocalcommand')) === 'no') continue;
    if (key === 'proxycommand' && options.has('proxyjump') &&
        [...options.keys()].indexOf('proxyjump') < [...options.keys()].indexOf(key)) {
      const jump = literalSourceWord(options.get('proxyjump'));
      if (!jump) deny('SSH の ProxyJump / ProxyCommand の実選択が未知で、command source の無効を証明できません (fail-closed)。' + UNKNOWN_OWNER_GATE);
      if (jump.text.toLowerCase() !== 'none') continue;
    }
    // OpenSSH expands these bytes before execution; the shell parser cannot prove the resulting argv.
    sources.push({ ...source, dynamic: source.dynamic || source.text.includes('%') || /\$\{/.test(source.text), mediated: true,
      sshCommandSource: key });
  }
  if (sshOptionScalar(options.get('sessiontype')) === 'none') noRemoteCommand = true;
  if (noRemoteCommand) remoteWords = [];
  else if (options.has('remotecommand')) remoteWords.push(options.get('remotecommand'));
  return { sources, stdin: host && !detached, remoteWords, argvUncertain };
}

/** Identify network clients that actually consume pipeline/stdin data, excluding explicit query/receive-only modes. */
function networkReadsStdin(invocation) {
  if (invocation.name === 'ssh') return sshReadsInput(invocation);
  if (!['nc', 'ncat', 'telnet'].includes(invocation.name)) return false;
  const values = invocation.name === 'ncat' ? 'pwsidmgGqox' : 'piwsqmxXPTG';
  const longValues = new Set(['source-port', 'source', 'wait', 'idle-timeout', 'delay', 'max-conns', 'proxy', 'proxy-type', 'proxy-auth']);
  for (const name of ['output', 'hex-dump', 'allow', 'allowfile', 'deny', 'denyfile', 'proxy-dns', 'ssl-cert', 'ssl-key',
    'ssl-trustfile', 'ssl-ciphers', 'ssl-servername', 'ssl-alpn']) longValues.add(name);
  let operand = false;
  for (let k = 0; k < invocation.args.length; k++) {
    const text = invocation.args[k].text;
    if (text === '--') return invocation.args.length > k + 1;
    if (text.startsWith('--')) {
      const eq = text.indexOf('=');
      const name = text.slice(2, eq < 0 ? undefined : eq);
      if (['help', 'version', 'recv-only'].includes(name)) return false;
      if (eq < 0 && longValues.has(name)) k++;
    } else if (text.startsWith('-')) {
      for (let p = 1; p < text.length; p++) {
        if ((invocation.name !== 'ncat' && text[p] === 'd') || ['h', 'z'].includes(text[p])) return false;
        if (values.includes(text[p])) { if (p === text.length - 1) k++; break; }
      }
    } else operand = true;
  }
  return operand;
}

/** Recognize a small non-executing sed script subset; opaque scripts can read or execute hidden sources. */
function simpleSedScript(text) {
  if (/^\s*(?:[0-9]+(?:,[0-9]+)?\s*)?[pdq=]\s*$/.test(text)) return true;
  if (text[0] !== 's' || !text[1]) return false;
  const delimiter = text[1];
  let count = 0;
  for (let k = 2; k < text.length; k++) {
    if (text[k] === '\\') { k++; continue; }
    if (text[k] === delimiter && ++count === 2) return /^[gIp0-9]*$/.test(text.slice(k + 1));
  }
  return false;
}

/** Classify pipeline producers without treating sed/grep/awk program text or literal printf output as filenames. */
function pipelineInput(invocation) {
  const refs = invocation.redirs.filter((redir) => ['<', '<>'].includes(redir.op)).map((redir) => redir.word);
  const name = invocation.name;
  const executable = invocation.nameWord?.text || '';
  let unknown = refs.some((word) => word.dynamic) || invocation.dynamicName || invocation.pathChangedBefore || invocation.unknownContextBefore ||
    (executable.includes('/') && !['/usr/bin/' + name, '/bin/' + name].includes(executable));
  if (['printf', 'echo', ':', 'true', 'false', 'pwd'].includes(name)) {
    unknown = unknown || invocation.args.some((word) => word.dynamic) || (name === 'printf' && /^-v/.test(invocation.args[0]?.text || ''));
    return { refs, unknown };
  }
  if (!['cat', 'head', 'tail', 'base64', 'xxd', 'sed', 'grep', 'awk'].includes(name)) return { refs, unknown: true };
  let program = !['sed', 'grep', 'awk'].includes(name);
  let afterDD = false;
  for (let k = 0; k < invocation.args.length; k++) {
    const word = invocation.args[k];
    const text = word.text;
    if (!afterDD && text === '--') { afterDD = true; continue; }
    if (!afterDD && text.startsWith('-')) {
      if (['sed', 'grep'].includes(name)) {
        const long = /^--(expression|regexp|file)(?:=([\s\S]*))?$/.exec(text);
        const short = !text.startsWith('--') && /^-[A-Za-z]*?[ef]/.exec(text);
        if (long || short) {
          const option = long ? long[1] === 'file' ? 'f' : 'e' : short[0].slice(-1);
          const value = long ? long[2] === undefined ? invocation.args[++k] : { ...word, text: long[2] } :
            short[0].length < text.length ? { ...word, text: text.slice(short[0].length) } : invocation.args[++k];
          program = true;
          if (name === 'grep' && option === 'f' && value) refs.push(value);
          unknown = unknown || !value || Boolean(value?.dynamic) || (name === 'sed' && (option === 'f' || !simpleSedScript(value?.text || '')));
        } else if (name === 'grep' && /^-[ABCm]$/.test(text)) {
          const value = invocation.args[++k];
          unknown = unknown || !value || Boolean(value?.dynamic && value.dynamicMaySplit !== false);
        } else if (!/^-[A-Za-z]+$/.test(text) || (name === 'sed' && /[^nEruaHl]/.test(text.slice(1)))) unknown = true;
      } else if (['head', 'tail'].includes(name) && /^-[nc]$/.test(text)) {
        const value = invocation.args[++k];
        unknown = unknown || !value || Boolean(value?.dynamic && value.dynamicMaySplit !== false);
      }
      else if (name === 'awk' && text === '-F') k++;
      else if (name === 'awk' && text === '-v') k++;
      else if (!/^-[A-Za-z0-9]+$/.test(text) || (['sed', 'grep', 'awk'].includes(name) && /[fie]/.test(text.slice(1)))) unknown = true;
      continue;
    }
    if (!program) {
      program = true;
      if (name === 'sed') unknown = unknown || word.dynamic || !simpleSedScript(text);
      if (name === 'awk') unknown = unknown || word.dynamic || !/^\s*(?:1|\{\s*print(?:\s+\$0|\s+"[^"\\]*")?\s*;?\s*\})\s*$/.test(text);
      continue;
    }
    refs.push(word);
  }
  return { refs, unknown: unknown || refs.some((word) => word.dynamic) };
}

/** Retain refusals for related input, distinguishing proven file operands from opaque source/context. */
function stdinPayloadVerdict(invocation, all, allFiles = false) {
  const refs = invocation.redirs.filter((redir) => ['<', '<>'].includes(redir.op)).map((redir) => redir.word);
  if (refs.some((word) => word.dynamic)) return 'UNKNOWN';
  if (allFiles && refs.length || SECRET_FILE_RE.test(withoutTemplateTokens(refs.map((word) => parserLiteral(word.text)).join(' ')))) {
    return contextualVerdict(invocation, 'FORBIDDEN');
  }
  if (invocation.redirs.some((redir) => redir.op === '<<<' && redir.word.dynamic) ||
      invocation.heredocBodies.some((body) => !body.quoted && /[$`]/.test(body.body))) return 'UNKNOWN';
  const ids = invocation.pipelineIds || [];
  const producers = all.filter((other) => other !== invocation && other.order < invocation.order &&
    (other.pipelineIds || []).some((id) => ids.includes(id)));
  for (const producer of producers) {
    const source = pipelineInput(producer);
    if (source.unknown) return 'UNKNOWN';
    if (allFiles && source.refs.length || SECRET_FILE_RE.test(withoutTemplateTokens(source.refs.map((word) => parserLiteral(word.text)).join(' ')))) {
      // The boolean guard did not establish cwd across a cd-like operation; classification must not claim it did.
      return knownInvocationContext(producer) && knownInvocationContext(invocation) ? 'FORBIDDEN' : 'UNKNOWN';
    }
  }
  return false;
}

/** Keep the existing network-client selection separate from the reusable stdin DATA role. */
function unsafeNetworkInput(invocation, all) {
  return networkReadsStdin(invocation) ? stdinPayloadVerdict(invocation, all) : false;
}

const invocationSources = new WeakMap();
const pendingSshCommandSources = [];
/** Check only producers inside this exact payload word in this source and execution order. */
function outboundPayloadVerdict(invocation, words) {
  const source = invocationSources.get(invocation) || [];
  const substitutionScope = (producer) => {
    for (let scope = producer.scope; scope?.parent; scope = scope.parent) {
      if (scope.parent === invocation.scope) return true;
    }
    return false;
  };
  for (const word of words) {
    if (!word) return 'UNKNOWN';
    if (literalSourceWord(word)) continue;
    if (!word.dynamic || word.dynamicMaySplit !== false || !Number.isInteger(word.start) || !word.raw ||
        /[<>]\(/.test(word.raw)) return 'UNKNOWN';
    const end = word.start + word.raw.length;
    const producers = source.filter(producer => producer !== invocation && !producer.definitionName &&
      producer.order < invocation.order && substitutionScope(producer) &&
      producer.nameWord?.start > word.start && producer.nameWord.start < end);
    if (!producers.length) return 'UNKNOWN';
    let secret = false;
    for (const producer of producers) {
      const input = pipelineInput(producer);
      // A function/callback or arbitrary program has no supported stdout proof. Output
      // redirection likewise prevents treating a coincident read as transmitted data.
      if (producer.functionCallName || input.unknown || !knownInvocationContext(producer) ||
          producer.redirs.some(redir => !['<', '<>'].includes(redir.op)) ||
          producer.heredocBodies.length && !(producer.name === 'cat' && !producer.args.length &&
            !producer.redirs.length && !producer.pipelineParticipant && producer.heredocBodies.length === 1 &&
            producer.heredocBodies[0].quoted && producer.heredocBodies[0].fdKnown &&
            [null, '0'].includes(producer.heredocBodies[0].fd))) return 'UNKNOWN';
      if (input.refs.some(ref => knownWord(ref) && guard.isSecretPath(ref.text))) secret = true;
    }
    if (secret) return contextualVerdict(invocation, 'FORBIDDEN');
  }
  return false;
}

/** CLI options suppress configured push options; inspect selected config DATA by its original word. */
function gitPushPayloadWords(g, invocation) {
  const push = pushRepository(g.args);
  if (push.payloadWords.length) return push.payloadWords;
  if (g.configEnvs.some(config => /^push\.pushoption(?:=|$)/i.test(config))) return [null];
  return (invocation?.args || []).filter(word => /^push\.pushoption=/i.test(word.text))
    .map(word => ({ ...word, text: word.text.slice(word.text.indexOf('=') + 1) }));
}

/** Detect SSH sessions that can consume stdin, skipping option values and excluding explicit -n/-f. */
function sshReadsInput(invocation) {
  return sshOperation(invocation).stdin;
}

/** Fail closed for an unresolved executable when its arguments identify a possible upload. */
function dynamicNetworkShape(invocation) {
  return invocation.dynamicName && (curlReadsUpload(invocation.args, invocation.incomplete) || wgetReadsUpload(invocation.args) ||
    (invocation.args[0] && invocation.args[0].text === 'gist') ||
    invocation.args.some((word) => /^-b(?:$|[^-])/.test(word.text) ||
      /^(?:https?|ftp|sftp|ssh|git):\/\//i.test(word.text) || destinationArg(word.text)));
}

/** Reject possible network children when launcher options leave the executable boundary uncertain. */
function opaqueLauncherNetwork(invocation) {
  if (!invocation.launcherUnknown) return false;
  const words = invocation.launcherArgs || [];
  return curlReadsUpload(words, invocation.incomplete) || wgetReadsUpload(words) || words.some((word) =>
    ['curl', 'wget', 'nc', 'ncat', 'scp', 'sftp', 'rsync', 'telnet', 'gh'].includes(word.text.split('/').pop()) ||
    /^(?:https?|ftp|sftp|ssh|git):\/\//i.test(word.text) || destinationArg(word.text));
}

/** Detect SFTP command/batch sessions without treating consumed SSH option values as hostnames. */
function sftpSession(words) {
  const valueOptions = 'BbcDFiJloPRSsX';
  let afterDD = false;
  for (let k = 0; k < words.length; k++) {
    const t = words[k].text;
    if (!afterDD && t === '--') { afterDD = true; continue; }
    if (!afterDD && t.startsWith('-')) {
      for (let p = 1; p < t.length; p++) {
        if (t[p] === 'b') return true;
        if (valueOptions.includes(t[p])) { if (p === t.length - 1) k++; break; }
      }
      continue;
    }
    return true; // SFTP accepts [user@]host with no ':' and then reads interactive/stdin commands.
  }
  return false;
}

/** Detect netcat execution options without interpreting consumed port/address/proxy values as flags. */
function reverseShell(invocation) {
  const shortValues = invocation.name === 'ncat' ? 'pwsimgG' : 'piwsqmxXP';
  const longValues = new Set(['source-port', 'source', 'wait', 'idle-timeout', 'delay', 'max-conns',
    'proxy', 'proxy-type', 'proxy-auth', 'ssl-cert', 'ssl-key', 'ssl-trustfile']);
  for (let k = 0; k < invocation.args.length; k++) {
    const t = invocation.args[k].text;
    if (t === '--') break;
    if (t.startsWith('--')) {
      const eq = t.indexOf('=');
      const option = t.slice(2, eq < 0 ? undefined : eq);
      if (option === 'exec' || (invocation.name === 'ncat' && option === 'sh-exec')) {
        const value = eq < 0 ? invocation.args[k + 1] : { ...invocation.args[k], text: t.slice(eq + 1) };
        return knownWord(invocation.args[k]) && knownWord(value) ? 'FORBIDDEN' : 'UNKNOWN';
      }
      if (eq < 0 && longValues.has(option)) k++;
    } else if (t.startsWith('-')) {
      for (let p = 1; p < t.length; p++) {
        if (t[p] === 'e' || (invocation.name === 'ncat' && t[p] === 'c')) {
          const value = p + 1 < t.length ? { ...invocation.args[k], text: t.slice(p + 1) } : invocation.args[k + 1];
          return knownWord(invocation.args[k]) && knownWord(value) ? 'FORBIDDEN' : 'UNKNOWN';
        }
        if (shortValues.includes(t[p])) { if (p === t.length - 1) k++; break; }
      }
    }
  }
  return false;
}

/** Quote a known argument solely for the parser; the resulting source is never executed. */
function parserLiteral(text) {
  return "'" + text.replace(/'/g, "'\\''") + "'";
}

/** Keep GNU env -S control punctuation as argument data while retaining its quote concatenation. */
function envSplitSource(source) {
  let quote = null;
  let result = '';
  for (let k = 0; k < source.length; k++) {
    const ch = source[k];
    if (ch === '\\') { result += ch + (source[++k] || ''); continue; }
    if (quote) { result += ch; if (ch === quote) quote = null; continue; }
    if (ch === "'" || ch === '"') { quote = ch; result += ch; continue; }
    result += ';|&<>()'.includes(ch) ? '\\' + ch : ch;
  }
  return result;
}

/** Reconstruct env -S argv, including literal trailing arguments, without executing its contents. */
function envSplitInspection(invocation, script) {
  const parsed = guard.parseShell(envSplitSource(script.text));
  const words = parsed.cmds.flatMap((command) => command.words);
  const tail = invocation.words.filter((word) => word.start > script.start);
  return guard.inspect(['env', ...words.map((word) => word.text), ...tail.map((word) => word.text)].map(parserLiteral).join(' '),
    sourceInspectionOptions(invocation, { initialFunctionSourceNames: [] }));
}

/** Carry exported function selectors into reparsed source before command lookup/unwrap. */
function sourceInspectionOptions(invocation, extra = {}) {
  const privileged = ['bash', 'sh'].includes(invocation.name) && invocation.shellPrivileged === true;
  const childShell = ['bash', 'sh', 'zsh', 'dash', 'ksh', 'mksh', 'fish'].includes(invocation.name);
  return {
    initialHelperEnvNames: invocation.helperEnvNames,
    initialGitIdentitySources: invocation.gitIdentitySources || [],
    initialGitConfigSources: invocation.gitConfigurationSources || [],
    initialGitHttpSources: invocation.gitHttpMetadataSources || [],
    initialPagerSources: invocation.gitPagerEnvSources || [],
    initialShellStartupSources: invocation.shellStartupEnvironmentSources || [],
    initialGhSources: (invocation.ghEnvironmentSources || []).concat(invocation.ghHelperEnvironmentSources || []),
    initialPromptSources: childShell ? invocation.tracePromptEnvSources || [] :
      [{ name: 'PS4', word: invocation.tracePromptWord }],
    initialTraceMode: childShell ? invocation.shellXtrace ?? null : invocation.traceModeBefore ?? false,
    initialPromptVars: childShell ? true : invocation.promptVarsBefore ?? true,
    initialFunctionSourceNames: privileged ? [] : invocation.exportedFunctionNames || [],
    // -p suppresses this child's imports, but preserves encoded environment entries
    // which a later nonprivileged child can import again.
    initialExportedFunctionNames: invocation.exportedFunctionNames || [],
    initialExportedFunctionUnknown: !!invocation.exportedFunctionUnknown,
    ...extra,
  };
}

const inspectedGits = [];
const gitInvocationContexts = new Map();
/** Classify only the evidence supported for this Git invocation, without changing its refusal. */
function gitVerdict(g, verdict) {
  const invocation = gitInvocationContexts.get(g);
  return verdict === 'FORBIDDEN' && (!invocation || !knownInvocationContext(invocation) ||
    g.unknownContextBefore || g.cdLikeBefore || g.dynamicOpt) ? 'UNKNOWN' : verdict;
}
/** Parse interpreter strings as code, retaining ordinary literal arguments as data. */
function collectNetworkInvocations(inspection, depth = 0) {
  if (depth > 16) deny('文字列の interpreter が深く入れ子になっていて、egress ガードで検査できません (fail-closed)。' + UNKNOWN_OWNER_GATE);
  if (inspection.problems.length) deny(guard.problemMessage(inspection.problems, 'egress ガード') + UNKNOWN_OWNER_GATE);
  inspectedGits.push(...inspection.gits);
  for (const invocation of inspection.invocations) invocationSources.set(invocation, inspection.invocations);
  for (const g of inspection.gits) gitInvocationContexts.set(g,
    inspection.invocations.find((invocation) => invocation.order === g.invocationOrder));
  const activeCommits = inspection.gits.filter(g => g.sub === 'commit' && !guard.parseCommitArgs(g.args).terminal);
  for (const g of inspection.gits) {
    if (g.gitNamespaceUnknown) deny(`Git namespace (${g.sub}) が選ぶ external helper / alias の実行 source・lookup・argv/context を検査できません。alias 不在や query風の子argvはsource認証ではありません。同目的・同条件の対応済みbuiltin/queryがなければownerに実helper/body・対象・cwd/env/config/sourceと不明点を確認してください。` + UNKNOWN_OWNER_GATE, 'UNKNOWN');
    const httpMetadata = gitHttpMetadataVerdict(g, gitInvocationContexts.get(g));
    if (httpMetadata) deny(httpMetadata === 'FORBIDDEN' ?
      'Git HTTP の header / User-Agent を生成する同じ source 内の読取が、禁止された secret filename operand に当たります。実通信の成立や内容の妥当性を確認したものではありません。' :
      'Git HTTP の header / User-Agent が選ぶ生成 source・stdout・URL scope・argv/config/environment を確定できません。未使用operation/queryや既知の通常literalを同条件で使えなければownerに対象・cwd/env/config/sourceと不明点を確認してください。' + UNKNOWN_OWNER_GATE, httpMetadata);
    if (gitHttpCookieVerdict(g)) deny('Git HTTP client が選ぶ http.cookieFile / Git config environment の file input・URL scope・format・server matching を検査できません。通常ファイルも非秘密の証明ではありません。未使用operation/queryや同条件を保つ対応済みselectorにできなければownerに対象・cwd/env/config/sourceと不明点を確認してください。' + UNKNOWN_OWNER_GATE, 'UNKNOWN');
    if (gitHttpMetadataWriteVerdict(g, gitInvocationContexts.get(g))) deny('Git config の generated header / User-Agent は将来の HTTP 呼出しで選ばれうる DATA です。実送信や即実行と断定せず、生成source・stdout・future URL/config/context を検査できないためownerにkey・操作・cwd/env/config/sourceと不明点を確認してください。' + UNKNOWN_OWNER_GATE, 'UNKNOWN');
    if (gitConfigSourceWrite(g)) deny('Git config の actual setter/delete/rename が、将来の Git 呼出しで選ぶ helper/callback/program の source または fallback を変更します。設定保存だけを即実行や送信と断定せず、future context・本文・副作用が未検査なので判断不能です。getterや意味を証明したdisable設定を使って同目的を保てなければownerにkey・操作・cwd/env/config/sourceと不明点を確認してください。' + UNKNOWN_OWNER_GATE);
    const operation = gitOperationVerdict(g, gitInvocationContexts.get(g));
    if (operation) deny(operation === 'FORBIDDEN' ?
      `Git ${g.sub} の typed object/index input が既存の禁止された secret filename/source policy に当たります。native操作の成立を確認したものではありません。` :
      `Git ${g.sub} の ${g.operationRole.kind} が選ぶ executable/source・child repository・object/ref/input・destination/config 条件を検査できません。literal な callbackやprogram名も本文や当該操作contextの認証にはなりません。同目的・同条件を保てる対応済みquery/source-free形式がなければownerに対象・cwd/env/config/sourceと不明点を確認してください。` + UNKNOWN_OWNER_GATE,
      gitVerdict(g, operation));
    const decision = guard.gitObjectInputDecision(g);
    if (decision) deny(decision.reason, gitVerdict(g, decision.category));
    if (gitExecutableSource(g, gitInvocationContexts.get(g))) {
      deny('当該 Git 操作の config / environment が選ぶ外部 diff・変換・filter・hook・fsmonitor・archive・include の実行 source を検査できません。commit の有無とは独立に、active helper の本文と副作用は判断不能です。' + UNKNOWN_OWNER_GATE);
    }
    if (g.sub === 'difftool' && !g.terminal) {
      deny('Git difftool の extcmd・既定 tool・env/config が選ぶ外部実行 source と副作用を検査できません。helper を呼ばない対応済み diff が同目的・同条件を保てる場合に検討し、保てなければ owner に確認してください。' + UNKNOWN_OWNER_GATE);
    }
    if (gitEditorCanRun(g)) {
      deny('Git の message / sequence editor を呼べる操作で、実際に編集を抑止する対応済み argv 条件を確認できません。既定・env/config override の editor source は内部を検査できません。同目的を保つ actual inline/file/reuse message や no-edit 形式を検討し、保てなければ owner に対象・操作・cwd/env/config/source を確認してください。個別操作の承認は hook 無効化の承認ではありません。');
    }
    const pager = guard.grepPagerEffect(g);
    const beforeCommit = activeCommits.some(commit => !Number.isInteger(g.invocationOrder) ||
      !Number.isInteger(commit.invocationOrder) || g.invocationOrder <= commit.invocationOrder);
    const configKey = beforeCommit && guard.preCommitConfigKey(g);
    if (configKey) {
      deny(`commit 前または当該 commit の Git config key (${configKey}) が選ぶ実行条件・外部 source と index の維持を検査できません。key 自体を危険と断定したものではありません。対応済みの表示・identity key 以外の override を除いて同目的・同条件を保てなければ owner に確認してください。` + UNKNOWN_OWNER_GATE);
    }
    if (pager.opensFiles || beforeCommit && pager.unknown) {
      deny('commit 前の git grep が開く外部 pager または argv/source の選択を検査できず、index の維持を確認できません。pager を開かない対応済みの同目的形式にできなければ owner に対象・操作・cwd/env/config/source を確認してください。個別操作の了承は hook 無効化の了承ではありません。');
    }
  }
  const result = [];
  for (const invocation of inspection.invocations) {
    if (invocation.nonExec || invocation.definitionName) continue;
    if (nativeSocketRedirection(invocation)) deny('Bash の /dev/tcp・/dev/udp redirection または socket を選びうる動的 target は未対応の network channel です。read/write/FD と秘密 filename の有無だけでは送信条件を確認できません。' + UNKNOWN_OWNER_GATE);
    // Known local functions select the separately parsed body, not the external client
    // or builtin sharing their name. Call redirections above still take effect.
    if (invocation.functionCallName) continue;
    if (['.', 'source'].includes(invocation.name)) deny('dot / source が実行する filename の本文と副作用を検査できません。literal な filename も実行 source の内容を証明しません。' + UNKNOWN_OWNER_GATE);
    if (arrayReaderCallback(invocation)) deny('mapfile / readarray の -C callback または callback を選びうる argv は未対応の実行 source です。callback が literal でも内部や副作用を検査できません。同目的を保てる callback-free 形式を検討してください。' + UNKNOWN_OWNER_GATE);
    if (rsyncRemoteHelper(invocation)) deny('remote rsync の -e / --rsh / RSYNC_RSH が選ぶ helper source、または remote/local の argv 条件を検査できません。download でも helper はローカルで実行されます。' + UNKNOWN_OWNER_GATE);
    if (scpConnectionSource(invocation)) deny('scp の -S connection program または有効な -D local SFTP server が選ぶ実行 source と副作用を検査できません。download でも helper は実行され得ます。local-only の operands/argv を証明できない形も判断不能です。' + UNKNOWN_OWNER_GATE);
    if (sshAuthenticationSource(invocation)) deny('SSH_ASKPASS が actual SSH / SCP / SFTP / rsync remote-shell の authentication route で選ぶローカル helper source を検査できません。download と不明な route も判断不能です。' + UNKNOWN_OWNER_GATE);
    result.push(invocation);
    const scripts = [];
    const gitCommand = inspection.gits.find((g) => g.invocationOrder === invocation.order);
    if (gitCommand && gitAskpassSource(gitCommand, invocation)) deny('Git の GIT_ASKPASS / SSH_ASKPASS / core.askPass が選ぶ credential program を検査できません。push と authentication を伴い得る remote query 等ではローカル helper が実行され得ます。' + UNKNOWN_OWNER_GATE);
    if (gitCommand) scripts.push(...credentialHelperSources(gitCommand));
    scripts.push(...sshCommandSources(invocation));
    if (invocation.splitString) {
      for (const script of invocation.splitWords) result.push(...collectNetworkInvocations(envSplitInspection(invocation, script), depth + 1));
    }
    if (['bash', 'sh', 'zsh', 'dash', 'ksh', 'mksh', 'fish'].includes(invocation.name)) {
      if (terminalBashQuery(invocation)) continue;
      if (invocation.shellLogin !== false) {
        deny('login shell の profile / logout source と実装ごとの startup 選択を検査できません。--noprofile だけでは logout source が無効と確認できません。目的と条件を保つ非 login の対応済み source へ書き換えられなければ' + UNKNOWN_OWNER_GATE);
      }
      if (invocation.name === 'bash' && invocation.shellDebugger !== false) {
        deny('Bash debugger が選ぶ追加 startup source を検査できません。debugger を使わない同目的の対応済み source を検討してください。' + UNKNOWN_OWNER_GATE);
      }
      if (invocation.name === 'zsh' || invocation.name === 'fish') {
        deny('当該 interpreter の system startup / configuration / autoload source を検査できません。zsh -f または fish --no-config だけでは全 source の無効を証明しません。対応済み Bash の直接 source で同目的を保てなければ' + UNKNOWN_OWNER_GATE);
      }
      if (invocation.name === 'bash' && invocation.shellInteractive === true && invocation.shellPosix !== true && invocation.shellNoRc !== true) {
        deny('interactive Bash の bashrc / rcfile startup source を検査できません。実 --norc を使う対応済み source が同目的と条件を保てる場合に検討してください。' + UNKNOWN_OWNER_GATE);
      }
      if (['ksh', 'mksh'].includes(invocation.name) &&
          (invocation.shellInteractive !== false || invocation.shellPrivileged !== false)) {
        deny('ksh / mksh の interactive または privileged startup / default rc source と実装条件を検査できません。Bash の startup 規則で代用していません。' + UNKNOWN_OWNER_GATE);
      }
      if (invocation.shellInteractive === true && !invocation.shellCommandMode && invocation.shellReadsStdin) {
        deny('interactive shell が stdin の各 command 前後に選ぶ prompt / callback source を検査できません。--norc / --noprofile は prompt source の無効を証明しません。目的を保つ非 interactive の対応済み source を検討してください。' + UNKNOWN_OWNER_GATE);
      }
      if (invocation.exportedFunctionUnknown && !(['bash', 'sh'].includes(invocation.name) && invocation.shellPrivileged === true)) {
        deny('child shell に渡る exported function の名前・選択を確定できず、本文や実行条件を検査できません。対応する直接 source または実 env -i で同じ目的を保てる場合に検討してください。' + UNKNOWN_OWNER_GATE);
      }
      const activeStartupSource = (name) => (invocation.shellStartupEnvironmentSources || [])
        .some(source => source.name === name && literalSourceWord(source.word)?.text !== '');
      if (invocation.name === 'bash' && activeStartupSource('BASH_ENV') &&
          invocation.shellInteractive !== true && invocation.shellPrivileged !== true && invocation.shellPosix !== true) {
        deny('child Bash の BASH_ENV が選ぶ startup filename / expansion / code source を検査できません。-c の本文が literal でも startup source は先に実行され得ます。' + UNKNOWN_OWNER_GATE);
      }
      if (['bash', 'sh', 'dash', 'ksh', 'mksh'].includes(invocation.name) &&
          activeStartupSource('ENV') && invocation.shellInteractive !== false &&
          invocation.shellPrivileged !== true && (invocation.name !== 'bash' || invocation.shellPosix !== false)) {
        deny('interactive child shell の ENV が選ぶ startup filename・展開・本文を検査できません。literal な -c source も、それより先に実行され得る startup source を証明しません。' + UNKNOWN_OWNER_GATE);
      }
      if (invocation.shellSourceUnknown || invocation.incomplete) deny('シェルの option / argv 境界から実行する source を確定できず、egress ガードで検査できません (fail-closed)。' + UNKNOWN_OWNER_GATE);
      scripts.push(...invocation.shellScripts.map((script) => ({ ...script, initialPositionals: invocation.shellPositionals })));
      if (!invocation.shellCommandMode && invocation.shellReadsStdin) {
        const stdinSource = shellStdinSource(invocation);
        if (!stdinSource) deny('シェルが実行する stdin の完全な effective fd 0 source を検査できません。pipeline / file / FD redirection / heredoc / 競合入力の実行内容は判断不能です。' + UNKNOWN_OWNER_GATE);
        scripts.push(stdinSource);
      } else if (!invocation.shellCommandMode) {
        deny('シェルが実行する filename / executable source の内容を検査できません。literal な名前も source 本文の証明にはなりません。' + UNKNOWN_OWNER_GATE);
      }
    } else if (invocation.name === 'eval') {
      const args = invocation.args[0] && invocation.args[0].text === '--' ? invocation.args.slice(1) : invocation.args;
      const literalArgs = args.map(literalSourceWord);
      if (invocation.incomplete || literalArgs.some(word => !word)) deny('eval の executable argv が dynamic / split / glob / brace / ANSI-C source を含み、連結後の実行文字列を確定できません。' + UNKNOWN_OWNER_GATE);
      scripts.push({ text: literalArgs.map((word) => word.text).join(' ') });
    }
    if (invocation.trapSourceUnknown) deny('trap に登録する source が確定できず、egress ガードで検査できません (fail-closed)。' + UNKNOWN_OWNER_GATE);
    scripts.push(...invocation.trapScripts.map((script) => ({ ...script, mediated: true })));
    if (invocation.aliasSourceUnknown) deny('alias に登録する source が確定できず、egress ガードで検査できません (fail-closed)。' + UNKNOWN_OWNER_GATE);
    scripts.push(...(invocation.aliasScripts || []).map((script) => ({ ...script, mediated: true })));
    for (const script of scripts) {
      const literal = literalSourceWord(script);
      if (!literal) deny('interpreter / helper の executable source bytes または argv boundary を確定できません。' + UNKNOWN_OWNER_GATE);
      if (script.sshCommandSource) pendingSshCommandSources.push(script.sshCommandSource);
      const options = sourceInspectionOptions(invocation, { initialPositionals: script.initialPositionals });
      const nested = script.mediated ? guard.inspectMediatedSource(script, options) :
        guard.inspect(literal.text, options);
      if (script.mediated) for (const nestedInvocation of nested.invocations) {
        nestedInvocation.helperEnvNames = [...new Set((nestedInvocation.helperEnvNames || []).concat(invocation.helperEnvNames || []))];
      }
      if (script.gitContext) for (const g of nested.gits) {
        g.gitEnvNames = [...new Set(g.gitEnvNames.concat(script.gitContext.gitEnvNames))];
        g.configs.push(...script.gitContext.configs.filter((config) => destinationConfig(config.split('=')[0])));
        g.configEnvs.push(...script.gitContext.configEnvs);
      }
      result.push(...collectNetworkInvocations(nested, depth + 1));
    }
  }
  return result;
}

/** Return a typed refusal for the same executable egress shapes, including uninspectable source variants. */
function parsedExfil(invocation) {
  // xargs/find can supply both the operation and every payload argument. Even a visible
  // query/help word cannot prove what the generated argv will select for these clients.
  if (invocation.incomplete && ['curl', 'wget', 'gh'].includes(invocation.name)) return 'UNKNOWN';
  let verdict = false;
  if (invocation.name === 'gh') verdict = ghOfficialVerdict(invocation);
  if (invocation.name === 'curl') {
    verdict = curlReadsUpload(invocation.args, invocation.incomplete, true);
    // Only the actual first literal argv -q/--disable prevents curl's implicit curlrc load.
    if (!verdict && !(knownWord(invocation.args[0]) && ['-q', '--disable'].includes(invocation.args[0].text))) verdict = 'UNKNOWN';
  }
  if (invocation.name === 'wget') verdict = wgetReadsUpload(invocation.args) || (wgetSourceBoundary(invocation) ? 'UNKNOWN' : false);
  if (['nc', 'ncat'].includes(invocation.name)) verdict = reverseShell(invocation);
  // Bare-host SFTP enters command mode; its batch/stdin can contain put without a visible path.
  if (invocation.name === 'sftp') verdict = sftpSession(invocation.args) ? 'UNKNOWN' : false;
  if (['scp', 'rsync'].includes(invocation.name)) verdict = invocation.incomplete ? 'UNKNOWN' :
    rsyncFileListPayload(invocation) || remoteCopyDestination(invocation);
  return contextualVerdict(invocation, verdict);
}

if (SCP_TEXT_COPY_SHAPE.test(cmd) && !knownSingleScpReceiveOnly(insp)) {
  deny('文字列に SCP copy に似た形があり、単一の既知 external actor・argv/context・receive/local destination を証明できません。他の送信・helper/source 条件とは独立した textual backstop です (egress guard)。' + UNKNOWN_OWNER_GATE);
}
const invocations = collectNetworkInvocations(insp);
for (const invocation of invocations) {
  const remote = sshOperation(invocation);
  if (remote.remoteWords.length) {
    const verdict = remote.argvUncertain ? 'UNKNOWN' : outboundPayloadVerdict(invocation, remote.remoteWords);
    if (verdict) deny(verdict === 'FORBIDDEN' ?
      'SSH remote command の引数を生成する同じ source 内の読取が、禁止された secret filename operand に当たります。-n による stdin 抑止とは独立した送信データです。内容や実送信の成立を確認したものではありません。' :
      'SSH remote command の引数を生成する source・program・stdout・argv/context を確定できません。-n は remote command DATA の検査を省略する条件ではありません。' + UNKNOWN_OWNER_GATE, verdict);
  }
}
/** Select only identity values which can enter this commit object, preserving scalar precedence. */
function gitCommitObjectWords(g, parsed) {
  const selected = [...parsed.inlineObjectWords];
  const env = new Map((g.gitIdentitySources || []).map(source => [source.name, source.word]));
  const configs = new Map();
  for (const config of g.configSelections || []) {
    const carrier = config.word;
    const eq = config.text.indexOf('='), key = config.text.slice(0, eq < 0 ? undefined : eq).toLowerCase();
    if (/^(?:user|author|committer)\.(?:name|email)$/.test(key)) {
      const word = config.mode === 'env' ? carrier : eq < 0 ? null : { ...carrier, text: carrier.text.slice(eq + 1) };
      if (config.mode !== 'env' && word && typeof word.literalValue === 'string') word.literalValue = word.literalValue.slice(eq + 1);
      configs.set(key, word);
    }
  }
  for (const person of ['author', 'committer']) {
    for (const field of ['name', 'email', 'date']) {
      if (person === 'author' && selected.some(source => source.kind === (field === 'date' ? 'date' : 'author'))) continue;
      const variable = 'GIT_' + person.toUpperCase() + '_' + field.toUpperCase();
      if (env.has(variable)) selected.push({ kind: variable, word: env.get(variable) });
      else if (field !== 'date') {
        const key = configs.has(person + '.' + field) ? person + '.' + field : 'user.' + field;
        if (configs.has(key)) selected.push({ kind: key, word: configs.get(key) });
        else if (field === 'email' && env.has('EMAIL')) selected.push({ kind: 'EMAIL', word: env.get('EMAIL'), uncertainSelection: true });
      }
    }
  }
  return selected;
}
for (const g of inspectedGits) {
  if (g.sub !== 'commit') continue;
  const parsed = guard.parseCommitArgs(g.args);
  if (parsed.terminal) continue;
  const invocation = gitInvocationContexts.get(g);
  const sources = gitCommitObjectWords(g, parsed);
  const verdict = outboundPayloadVerdict(invocation, sources.filter(source => !source.uncertainSelection).map(source => source.word)) ||
    (outboundPayloadVerdict(invocation, sources.filter(source => source.uncertainSelection).map(source => source.word)) ? 'UNKNOWN' : false);
  if (verdict) deny(verdict === 'FORBIDDEN' ?
    'Git commit の message・trailer・identity を生成する同じ source 内の読取が、禁止された secret filename operand に当たります。staged path とは独立して commit object に入る DATA です。内容の妥当性や実送信の成立を確認したものではありません。' :
    'Git commit の message・trailer・identity を生成する source・program・stdout・argv/context を確定できません。staged filename 検査だけでは commit metadata DATA を検査できません。' + UNKNOWN_OWNER_GATE, gitVerdict(g, verdict));
}
for (const g of inspectedGits) {
  if (g.sub !== 'push' || g.terminal && g.helpKind === 'stdout') continue;
  const invocation = gitInvocationContexts.get(g);
  let verdict = outboundPayloadVerdict(invocation, gitPushPayloadWords(g, invocation));
  if (verdict === 'FORBIDDEN' && unknownPushDestination(g)) verdict = 'UNKNOWN';
  if (verdict) deny(verdict === 'FORBIDDEN' ?
    'Git push option の値を生成する同じ source 内の読取が、禁止された secret filename operand に当たります。repository・ref・index とは独立して server に送る DATA です。内容や実送信の成立を確認したものではありません。' :
    'Git push option の値を生成する source・program・stdout・argv/context を確定できません。repository・ref・index の判定だけでは送信データを検査できません。' + UNKNOWN_OWNER_GATE, gitVerdict(g, verdict));
}
if (invocations.some((invocation) =>
  ['curl', 'wget', 'nc', 'ncat', 'scp', 'sftp', 'rsync', 'telnet', 'gh', 'ssh'].includes(invocation.name) &&
  invocation.args.some((word) => word.ansiCUnknown))) {
  deny('ネットワーク client の ANSI-C 引数が解読できず、送信 source を確かめられません (fail-closed)。' + UNKNOWN_OWNER_GATE);
}
// Reapply the same literal inventory after shell quote/escape concatenation; never expand variables.
const parsedWords = insp.invocations.concat(invocations).flatMap((invocation) =>
  invocation.words.concat(invocation.redirs.map((redir) => redir.word)));
if (parsedWords.some((word) => SECRET_LITERALS.some((pattern) => pattern.test(word.text)))) {
  deny('シェルの引用符・escape を戻した引数が既存の secret literal inventory に当たります。値の有効性や実際の漏洩を確認したものではありません (egress guard)。必要な操作は owner に対象・内容を確認してください。', 'FORBIDDEN');
}
const parsedExfilVerdict = firstVerdict(invocations, parsedExfil);
if (parsedExfilVerdict || invocations.some(dynamicNetworkShape) || invocations.some(opaqueLauncherNetwork)) {
  const verdict = parsedExfilVerdict || 'UNKNOWN';
  deny(verdict === 'FORBIDDEN' ?
    '読み取れた実行コマンドが、既存の禁止形式 (gist / 実行付き network client / ファイル payload・copy 等) に当たります。実送信の成立を確認したものではありません (egress guard)。必要な操作は owner に対象・内容を確認してください。' :
    'network client の config・argv・実行 source または context が不足し、送信形式を確認できません (egress guard, fail-closed)。owner に対象・操作・cwd・env/config/source と不明点を確認してください。', verdict);
}
const networkInputVerdict = firstVerdict(invocations, (invocation) => unsafeNetworkInput(invocation, invocations));
if (networkInputVerdict) {
  deny(networkInputVerdict === 'FORBIDDEN' ?
    'stdin を消費する network client と、その入力の secret filename operand が同じ読取・pipeline 関係に当たり、既存の禁止形式です。ファイル内容や実送信の成立を確認したものではありません (egress guard)。必要な操作は owner に対象・内容を確認してください。' :
    'stdin を消費する network client の入力について source・argv・実行 identity・cwd/context を確認できません (egress guard, fail-closed)。owner に対象・操作・cwd・env/config/source と不明点を確認してください。', networkInputVerdict);
}
// Parsing literal helper text can reveal a prohibited payload; it does not authenticate the
// selected shell, callee body, startup/function/PATH context, or native activation conditions.
// Preserve confirmed payload verdicts above before the remaining active-source fallback.
if (pendingSshCommandSources.length) {
  deny('SSH / SCP の有効な command-valued option が選ぶ shell・callee 本文・startup/function/PATH・実行条件を検査できません。literal source を parse しただけでは副作用の証明になりません。known none・forced inactive・local-only/query 条件が同目的を保てなければ' + UNKNOWN_OWNER_GATE);
}
const parsedFileRefs = invocations.flatMap((invocation) => {
  const readsFiles = ['cat', 'head', 'tail', 'base64', 'xxd'].includes(invocation.name);
  return (readsFiles ? invocation.args : []).concat(invocation.redirs.filter((redir) => redir.op !== '<<<').map((redir) => redir.word)).map((word) => word.text);
});
const secretEvidence = [cmd, ...parsedFileRefs].join('\n');
if (SECRET_FILE_RE.test(withoutTemplateTokens(secretEvidence)) &&
    invocations.some((invocation) => networkInvocation(invocation) || invocation.dynamicName || invocation.launcherUnknown)) {
  deny('secret filename evidence と network command が同一コマンドにありますが、読取から送信への関係を確認できません (egress guard)。owner に対象・操作・cwd・source と不明点を確認してください。');
}
// SSH identity options are authentication input; selected commands/config sources were inspected above.
const sshReadEvidence = invocations.flatMap((invocation) => {
  const readsFiles = ['cat', 'head', 'tail', 'base64', 'xxd'].includes(invocation.name);
  return (readsFiles ? invocation.args : []).concat(invocation.redirs
    .filter((redir) => ['<', '<>'].includes(redir.op)).map((redir) => redir.word))
    .map((word) => word.text.replace(/(^|\/)\.env\.example$/i, '$1'));
}).join('\n');
if (SECRET_FILE_RE.test(sshReadEvidence) &&
    invocations.some((invocation) => invocation.name === 'ssh' && sshReadsInput(invocation))) {
  deny('secret filename evidence と stdin を消費し得る SSH セッションが同一コマンドにありますが、送信への関係を確認できません (egress guard)。owner に対象・操作・cwd・source と不明点を確認してください。');
}

for (const g of inspectedGits) {
  if (['add', 'stage'].includes(g.sub) && !g.terminal) {
    const added = guard.parseAddArgs(g.args);
    if (!added.terminal && added.unsafePathspec) {
      deny(`git ${g.sub} の pathspec が実行時に決まり、秘密ファイルの追加を事前に確かめられません (${added.reason}, fail-closed)。` + UNKNOWN_OWNER_GATE);
    }
    if (!added.terminal && added.runtimeBlanket) {
      deny('git add / stage の実行時 option が包括追加の -A / --all に解決され、既存の包括追加禁止に当たります。必要な操作は owner に対象・操作を確認してください。', gitVerdict(g, 'FORBIDDEN'));
    }
    if (!added.terminal) {
      if (added.pathspecs.some((word) => guard.isSecretPath(word.literalPath))) {
        deny('git add / stage の literal pathspec が既存の secret filename 禁止に当たります。ファイル内容を確認したものではありません。必要な操作は owner に対象・操作を確認してください。', gitVerdict(g, 'FORBIDDEN'));
      }
      const inspectCwd = guard.resolveDir(baseDir, g.cdirs);
      const roots = new Set([process.env.CLAUDE_PROJECT_DIR || process.cwd(), baseDir, inspectCwd].map((dir) => path.resolve(dir)));
      if (added.pathspecs.some((word) => typeof word.literalValue === 'string' &&
          (['.', '..'].includes(word.literalPath) || roots.has(path.resolve(inspectCwd, word.literalPath))))) {
        deny('git add / stage の実行時 literal pathspec が既存の包括追加対象に解決されます。必要な操作は owner に対象・操作・cwd を確認してください。', gitVerdict(g, 'FORBIDDEN'));
      }
    }
  }
  const a = g.args.map((w) => w.text);
  const firstWord = a.find((x) => !x.startsWith('-'));
  if (g.sub === 'remote' && !g.terminal) {
    let action;
    let afterDD = false;
    for (const word of g.args) {
      if (!afterDD && word.text === '--') { afterDD = true; continue; }
      if (!afterDD && word.text.startsWith('-') && !word.dynamic) continue;
      action = word;
      break;
    }
    if ((action && action.dynamic) || (!action && g.incomplete)) {
      deny('git remote の action が動的で、宛先を書き換える操作かどうかを確かめられません (fail-closed)。' + UNKNOWN_OWNER_GATE);
    }
  }
  const remoteWrite = g.sub === 'remote' && (firstWord === 'add' || firstWord === 'set-url');
  const configWrite = g.sub === 'config' && writesDestinationConfig(g.args);
  if (g.sub === 'fast-import' && !(g.args.length === 1 && !g.args[0].dynamic && ['-h', '--help'].includes(g.args[0].text))) {
    deny('git fast-import の stdin から作られる履歴と ref を、このガードで検査できません (fail-closed)。owner に対象・操作・source と不明点を確認してください。');
  }
  if (['send-pack', 'http-push'].includes(g.sub) && !(g.terminal && g.helpKind === 'stdout')) {
    deny(`git ${g.sub} の送信先と対象履歴は、このガードの supported inspection 外で確認できません (fail-closed)。owner に対象・操作・source と不明点を確認してください。`);
  }
  if (g.outboundRole && !g.outboundRole.terminal) {
    const role = g.outboundRole;
    const directory = guard.resolveDir(baseDir, g.cdirs);
    const confirmedFile = word => {
      const literal = literalSourceWord(word);
      if (!literal || !directory) return false;
      try { const stat = fs.statSync(path.resolve(directory, literal.text)); return stat.isFile() || stat.isDirectory(); }
      catch { return false; }
    };
    const verdict = g.sub === 'send-email' && !role.unknown && !role.noSend && role.files.length &&
      role.files.every(confirmedFile) ? 'FORBIDDEN' : 'UNKNOWN';
    deny(verdict === 'FORBIDDEN' ?
      'Git send-email の static file/directory operands は既存の file-egress policy の送信 source です。mail の妥当性や実送信の成立を確認したものではありません。' :
      `Git ${g.sub} の source・argv・設定・宛先・実行条件を検査できません。dry-run 等の非送信 mode も helper/source の保証ではありません。同目的・同条件を保つ対応済み形式がなければ owner に対象・操作・cwd/env/config/source と不明点を確認してください。` + UNKNOWN_OWNER_GATE,
      gitVerdict(g, verdict));
  }
  if (g.sub === 'imap-send' && !imapSendRole(g).terminal) {
    const invocation = gitInvocationContexts.get(g);
    const verdict = stdinPayloadVerdict(invocation, invocationSources.get(invocation) || []) || 'UNKNOWN';
    deny(verdict === 'FORBIDDEN' ?
      'Git imap-send が読む stdin の同じ source 内に、禁止された secret filename の読取が結び付いています。mail の妥当性や実送信の成立を確認したものではありません。' :
      'Git imap-send の stdin・mail input・設定・宛先・認証の実行条件を検査できません。同目的・同条件を保つ対応済みの送信形式がなければ owner に対象・操作・cwd/env/config/source と不明点を確認してください。' + UNKNOWN_OWNER_GATE,
    gitVerdict(g, verdict));
  }
  if (g.sub === 'push' && g.incomplete) {
    deny('xargs / find などの入力から git push に追加される引数は、egress ガードで宛先を確かめられません (fail-closed)。' + UNKNOWN_OWNER_GATE);
  }
  const push = g.sub === 'push' ? pushRepository(g.args) : null;
  const repo = push && push.repository;
  if (g.sub === 'push' && unknownPushDestination(g, push)) {
    deny('git push の宛先や transport command が変数・置換や config / GIT_CONFIG / GIT_SSH / GIT_PROXY_COMMAND の override で作られていて、egress ガードで確かめられません (fail-closed)。' + UNKNOWN_OWNER_GATE);
  }
  const pushUrl = g.sub === 'push' && (a.some((x) => URL_ARG_RE.test(x)) ||
    (repo && destinationArg(repo.text)) || g.configs.some(externalConfig));
  if (remoteWrite || configWrite || pushUrl) {
    const verdict = gitVerdict(g, remoteWrite ?
      g.args.every(knownWord) ? 'FORBIDDEN' : 'UNKNOWN' : configWrite ?
      g.args.every(knownWord) ? configWrite : 'UNKNOWN' :
      repo && knownWord(repo) && destinationArg(repo.text) ? 'FORBIDDEN' : 'UNKNOWN');
    deny(
      verdict === 'FORBIDDEN' ?
        '読み取れた Git 操作が、既存の宛先変更・protected config key の書込/削除・外部 repository operand への push 禁止に当たります。実送信の成立を確認したものではありません (egress guard)。必要な操作は owner に対象・内容を確認してください。' :
        'Git の宛先・section/config source・引数や context を確定できません。URL 文字列だけでは実際の送信を確認したものではありません (egress guard, fail-closed)。owner に対象・操作・cwd・env/config/source と不明点を確認してください。',
      verdict,
    );
  }
}

process.exit(0);
