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
  /\b(scp|sftp)\b[^\n]*\s[^\s]+:[^\s]/,                  // local -> remote コピー
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
    if (destinationArg(text)) remote = true;
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

/** Positive selectors of local Git execution must be gated for their actual operation. */
function gitExecutableSource(g, invocation) {
  if (g.terminal && g.helpKind === 'stdout' && knownInvocationContext(invocation)) return false;
  if (g.sub === 'config' && configOperation(g.args).read) return false;
  const diff = ['diff', 'show', 'log', 'diff-tree', 'diff-index', 'diff-files', 'format-patch', 'whatchanged'].includes(g.sub);
  const modes = diff ? gitDiffModes(g) : null;
  if (modes?.terminal && knownInvocationContext(invocation)) return false;
  const keys = [...g.configs, ...g.configEnvs].map(config => config.split('=')[0].toLowerCase());
  const uncertain = !knownInvocationContext(invocation) || g.dynamicOpt || g.incomplete;
  if (diff && (keys.some(key => /^diff\.(?:external|.+\.command)$/.test(key)) ||
      [...g.gitEnvNames, ...(invocation.helperEnvNames || [])].includes('GIT_EXTERNAL_DIFF')) && (modes.external || uncertain)) return true;
  if (diff && keys.some(key => /^diff\..+\.textconv$/.test(key)) && (modes.textconv || uncertain)) return true;
  if (keys.some(key => /^filter\..+\.(?:clean|smudge|process)$/.test(key)) &&
      (!['rev-parse', 'ls-files', 'ls-tree', 'config', 'version', 'show-ref', 'for-each-ref', 'merge-base', 'count-objects'].includes(g.sub) || uncertain)) return true;
  if (keys.some(key => /^core\.hookspath$/.test(key)) &&
      (!['log', 'diff', 'show', 'rev-parse', 'ls-files', 'ls-tree', 'config', 'version'].includes(g.sub) || uncertain)) return true;
  if (!g.pagerDisabled && (g.pagerForced || ['log', 'show', 'diff', 'branch', 'tag', 'help'].includes(g.sub)) &&
      (keys.includes('core.pager') || keys.includes('pager.' + g.sub))) return true;
  return keys.some(key => /^include(?:if\..+)?\.path$/.test(key));
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

/** Recognize curl file payloads and opaque config input without reading either file. */
function curlReadsUpload(words, incomplete = false, actualClient = false) {
  // Additional words from splitting or pathname/brace expansion can introduce payload options,
  // including from a value consumed by a visible option. Never infer the unseen argv from env.
  if (actualClient && words.some(word => word.dynamic && word.dynamicMaySplit !== false || word.globExpanded || word.braceExpanded)) return 'UNKNOWN';
  // xargs/find can provide an unseen filename to a trailing file-reading option.
  const fileOptions = new Set(['upload-file', 'data', 'data-ascii', 'data-binary', 'json',
    'header', 'proxy-header', 'data-urlencode', 'url-query', 'form', 'variable', 'cookie']);
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
    if (option === 'upload-file') return Boolean(value);
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
    if (t === '--') break;
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
      const matches = CURL_LONG_NAMES.includes(name) ? [name] : CURL_LONG_NAMES.filter((option) => option.startsWith(name));
      if (matches.length !== 1 && matches.includes('cookie')) return 'UNKNOWN';
      if (matches.length !== 1 || !CURL_VALUE_LONG.has(matches[0])) continue;
      const option = matches[0];
      if (option === 'config') return 'UNKNOWN';
      const value = eq < 0 ? words[++k] : { ...optionWord, text: t.slice(eq + 1) };
      if (value) {
        if (option === 'variable') { variableDefinition(value.text, expanding, value); continue; }
        const source = expanding ? expanded(value.text) : { text: value.text, file: false };
        const verdict = !incomplete && knownWord(optionWord) && knownWord(value) && !source.unknown &&
          (option !== 'url-query' || name === option) ? 'FORBIDDEN' : 'UNKNOWN';
        // Cookie's '=' proves inline syntax only within one actual scalar argument. Its file form
        // reads local bytes; unknown/split input must never be mistaken for empty or inline DATA.
        if (option === 'cookie' && ((value.dynamic && value.dynamicMaySplit !== false) ||
            value.globExpanded || value.braceExpanded || value.tildeExpanded || value.ansiCUnknown ||
            source.unknown || (!source.file && source.text.includes('\0') && !source.text.includes('=')))) return 'UNKNOWN';
        // A scalar '+' or '=' proves inline query syntax; an unknown prefix or argv count does not.
        if (option === 'url-query' && ((value.dynamic && value.dynamicMaySplit !== false) ||
            (!source.file && !source.text.startsWith('+') && !source.text.includes('=') && source.text.includes('\0')))) return 'UNKNOWN';
        if (expanding && outbound.has(option) && SECRET_LITERALS.some((pattern) => pattern.test(source.text))) return verdict;
        if ((source.file && outbound.has(option)) || payload(option, source.text)) return verdict;
      } else if (option === 'cookie' || incomplete && fileOptions.has(option)) return 'UNKNOWN';
    } else if (t.startsWith('-')) {
      for (let p = 1; p < t.length; p++) {
        if (actualClient && optionWord.dynamic && t[p] === '\0') return 'UNKNOWN';
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
    }
  }
  return false;
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
  const opaque = new Set(['post-file', 'body-file', 'config', 'execute']);
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
        return ['post-file', 'body-file'].includes(matches[0]) && knownWord(words[k]) && knownWord(value) ? 'FORBIDDEN' : 'UNKNOWN';
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
  return destinationArg(textOf(destination)) ? 'FORBIDDEN' : false;
}

/** scp -S is local executable source even for downloads; only proven entirely local copies ignore it. */
function scpConnectionSource(invocation, selectedEnv = false) {
  if (invocation.name !== 'scp') return false;
  let selected = selectedEnv;
  let unknown = Boolean(invocation.incomplete);
  let afterDD = false;
  const operands = [];
  for (let k = 0; k < invocation.args.length; k++) {
    const word = invocation.args[k];
    const literal = literalSourceWord(word);
    const text = literal ? literal.text : word.text;
    if (!literal) unknown = true;
    if (!afterDD && text === '--') { afterDD = true; continue; }
    if (!afterDD && text.startsWith('-') && text !== '-') {
      if (text.startsWith('--')) { unknown = true; continue; }
      for (let p = 1; p < text.length; p++) {
        if ('cDFiJloPSX'.includes(text[p])) {
          if (text[p] === 'S') selected = true;
          const value = p + 1 < text.length ? { ...word, text: text.slice(p + 1) } : invocation.args[++k];
          if (!literalSourceWord(value)) unknown = true;
          break;
        }
        if (!'346ABCOpqRrsTv'.includes(text[p])) unknown = true;
      }
      continue;
    }
    operands.push(text);
  }
  return selected && (unknown || !knownInvocationContext(invocation) || operands.length < 2 ||
    operands.some(value => destinationArg(value) || /^scp:\/\//i.test(value)));
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
    const daemon = /^rsync:\/\//i.test(value) || /^[^/:]+::/.test(value);
    return destinationArg(value) && (!daemon || selectedRsh);
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
function networkInvocation(invocation) {
  return ['curl', 'wget', 'nc', 'ncat', 'scp', 'sftp', 'rsync', 'telnet'].includes(invocation.name) ||
    (invocation.name === 'gh' && invocation.args[0] && invocation.args[0].text === 'gist');
}

/** Inspect gh api payload options, keeping raw fields and consumed option values as data. */
function ghApiUpload(invocation) {
  if (invocation.args[0]?.text !== 'api') return false;
  const values = new Set(['field', 'raw-field', 'header', 'hostname', 'input', 'jq', 'method', 'preview', 'template', 'cache']);
  const shortValues = { F: 'field', f: 'raw-field', H: 'header', q: 'jq', X: 'method', p: 'preview', t: 'template' };
  let verdict = false;
  for (let k = 1; k < invocation.args.length; k++) {
    const word = invocation.args[k];
    const text = word.text;
    if (text === '--') break;
    if (word.dynamic && (word.dynamicMaySplit !== false || text.startsWith('\0'))) verdict ||= 'UNKNOWN';
    let option;
    let value;
    if (text.startsWith('--')) {
      const eq = text.indexOf('=');
      option = text.slice(2, eq < 0 ? undefined : eq);
      if (option === 'help' && eq < 0) return false;
      if (!values.has(option)) continue;
      value = eq < 0 ? invocation.args[++k] : { ...word, text: text.slice(eq + 1) };
    } else if (text.startsWith('-')) {
      for (let p = 1; p < text.length; p++) {
        option = shortValues[text[p]];
        if (!option) continue;
        value = p + 1 < text.length ? { ...word, text: text.slice(p + 1) } : invocation.args[++k];
        break;
      }
    }
    if (!option) continue;
    if (value?.dynamic && value.dynamicMaySplit !== false) verdict ||= 'UNKNOWN';
    if (option === 'input' && (value || invocation.incomplete)) {
      verdict ||= !invocation.incomplete && knownWord(word) && knownWord(value) ? 'FORBIDDEN' : 'UNKNOWN';
    }
    if (option === 'field') {
      const eq = value ? value.text.indexOf('=') : -1;
      const payload = eq < 0 ? '' : value.text.slice(eq + 1);
      if ((!value && invocation.incomplete) || /^@/.test(payload) ||
          Boolean(value?.dynamic && (value.dynamicMaySplit !== false || eq < 0 || payload.startsWith('\0')))) {
        verdict ||= !invocation.incomplete && knownWord(word) && knownWord(value) && /^@/.test(payload) ? 'FORBIDDEN' : 'UNKNOWN';
      }
    }
  }
  return verdict;
}

/** Bounded GH writes share file/stdin payload roles while keeping literal option values as DATA. */
function ghFilePayload(invocation) {
  const words = invocation.args;
  if (!literalSourceWord(words[0])) return words.length ? 'UNKNOWN' : false;
  const group = words[0].text;
  if (!['release', 'issue', 'pr'].includes(group)) return false;
  const specFor = action => {
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
  let unknown = !!invocation.incomplete;
  let payload = false;
  const dataBoundary = word => Boolean(word && word.dynamicMaySplit === false && !word.ansiCUnknown &&
    !word.globExpanded && !word.braceExpanded && !word.tildeExpanded);
  for (let k = 1; k < words.length; k++) {
    const word = words[k];
    const text = word.text;
    if (!afterDD && text === '--') { afterDD = true; continue; }
    if (!afterDD && ['-h', '--help'].includes(text) && !unknown) return false;
    if (!afterDD && text.startsWith('-')) {
      let option;
      let value;
      if (text.startsWith('--')) {
        const eq = text.indexOf('=');
        option = text.slice(2, eq < 0 ? undefined : eq);
        if (option === 'repo' || spec?.values.includes(option)) value = eq < 0 ? words[++k] : { ...word, text: text.slice(eq + 1) };
        else if (option === 'help' || spec?.flags.includes(option)) {
          if (!knownWord(word) || eq >= 0 && !['true', 'false'].includes(text.slice(eq + 1))) unknown = true;
          if (option === 'help' && text.slice(eq + 1) === 'true' && !unknown) return false;
          continue;
        } else { unknown = true; continue; }
      } else {
        for (let p = 1; p < text.length; p++) {
          option = text[p] === 'R' ? 'repo' : spec?.short[text[p]];
          if (option) { value = p + 1 < text.length ? { ...word, text: text.slice(p + 1) } : words[++k]; break; }
          if (text[p] === 'h' && knownWord(word) && !unknown) return false;
          if (!knownWord(word) || !spec?.shortFlags.includes(text[p])) unknown = true;
        }
      }
      if (!option) continue;
      if (!value || !dataBoundary(word) || !dataBoundary(value)) unknown = true;
      if (option === 'repo' && !knownWord(value)) unknown = true;
      if (spec?.files.includes(option)) {
        if (!knownWord(value) || value.text === '-') unknown = true;
        else payload = true;
      }
      continue;
    }
    if (!action) {
      if (!literalSourceWord(word)) return 'UNKNOWN';
      action = text === 'new' ? 'create' : text;
      spec = specFor(action);
      if (!spec) return false; // Queries and other operations keep their existing guard conditions.
    } else {
      if (!knownWord(word)) unknown = true;
      operands.push(word);
    }
  }
  if (!spec) return unknown ? 'UNKNOWN' : false;
  if (unknown || operands.length < spec.min || operands.length > spec.max) return 'UNKNOWN';
  return payload || operands.length > spec.assetStart ? 'FORBIDDEN' : false;
}

/** Select SSH commands/config sources that run locally, retaining proven non-executing query and DATA options. */
function sshCommandSources(invocation) {
  return sshOperation(invocation).sources;
}

/** Read SSH's option boundary before and after the host, stopping at the actual remote command. */
function sshOperation(invocation) {
  if (invocation.name !== 'ssh') return { sources: [], stdin: false, remoteWords: [] };
  const options = new Map();
  const valueOptions = 'bcDEeFIiJLlmOopQRSWw';
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
      const value = p + 1 < text.length ? { ...word, text: text.slice(p + 1) } : invocation.args[++k];
      if (value?.dynamic && (value.dynamicMaySplit !== false || (p + 1 < text.length && value.text.startsWith('\0')))) argvUncertain = true;
      if (text[p] === 'F') { selectedConfig = true; configFile = value; }
      if (text[p] === 'o') {
        const match = value && /^\s*([^=\s]+)\s*(?:=\s*|\s+)([\s\S]*)$/.exec(value.text);
        if (!match || value.dynamicMaySplit && value.dynamic) unknown = true;
        else if (!options.has(match[1].toLowerCase())) options.set(match[1].toLowerCase(), { ...value, text: match[2] });
      }
      if (text[p] === 'J' && value && !options.has('proxyjump')) options.set('proxyjump', value);
      break;
    }
  }
  if (selectedConfig ? earlyQuery : requestedEarlyQuery) return { sources: [], stdin: false, remoteWords: [] };
  if (selectedConfig && (argvUncertain || !configFile || configFile.dynamic || !['none', '/dev/null'].includes(configFile.text))) {
    deny('SSH の -F config が未知の実行 source（Match exec 等）を選び、egress ガードで検査できません (fail-closed)。' + UNKNOWN_OWNER_GATE);
  }
  if (selectedConfig ? query : requestedQuery) return { sources: [], stdin: false, remoteWords: [] };
  if (unknown) deny('SSH の -o option が動的で、ローカル実行 source を確かめられません (fail-closed)。' + UNKNOWN_OWNER_GATE);
  const sources = [];
  for (const key of ['proxycommand', 'knownhostscommand', 'localcommand']) {
    const source = options.get(key);
    if (!source || source.text.toLowerCase() === 'none') continue;
    if (key === 'localcommand' && options.get('permitlocalcommand')?.text.toLowerCase() === 'no') continue;
    if (key === 'proxycommand' && options.has('proxyjump') && [...options.keys()].indexOf('proxyjump') < [...options.keys()].indexOf(key)) continue;
    // OpenSSH expands these bytes before execution; the shell parser cannot prove the resulting argv.
    sources.push({ ...source, dynamic: source.dynamic || source.text.includes('%') || /\$\{/.test(source.text), mediated: true });
  }
  if (options.get('sessiontype')?.text.toLowerCase() === 'none') noRemoteCommand = true;
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
function unsafeNetworkInput(invocation, all) {
  if (!networkReadsStdin(invocation)) return false;
  const refs = invocation.redirs.filter((redir) => ['<', '<>'].includes(redir.op)).map((redir) => redir.word);
  if (refs.some((word) => word.dynamic)) return 'UNKNOWN';
  if (SECRET_FILE_RE.test(withoutTemplateTokens(refs.map((word) => parserLiteral(word.text)).join(' ')))) {
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
    if (SECRET_FILE_RE.test(withoutTemplateTokens(source.refs.map((word) => parserLiteral(word.text)).join(' ')))) {
      // The boolean guard did not establish cwd across a cd-like operation; classification must not claim it did.
      return knownInvocationContext(producer) && knownInvocationContext(invocation) ? 'FORBIDDEN' : 'UNKNOWN';
    }
  }
  return false;
}

const invocationSources = new WeakMap();
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
          producer.redirs.some(redir => !['<', '<>'].includes(redir.op)) || producer.heredocBodies.length) return 'UNKNOWN';
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
  return {
    initialHelperEnvNames: invocation.helperEnvNames,
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
    const decision = guard.gitObjectInputDecision(g);
    if (decision) deny(decision.reason, gitVerdict(g, decision.category));
    if (gitExecutableSource(g, gitInvocationContexts.get(g))) {
      deny('当該 Git 操作の config / environment が選ぶ外部 diff・変換・filter・hook・include の実行 source を検査できません。commit の有無とは独立に、active helper の本文と副作用は判断不能です。' + UNKNOWN_OWNER_GATE);
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
    if (beforeCommit && (pager.opensFiles || pager.unknown)) {
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
    if (scpConnectionSource(invocation)) deny('scp の -S が選ぶローカルの connection program と副作用を検査できません。download でも helper は実行され得ます。local-only の operands/argv を証明できない形も判断不能です。' + UNKNOWN_OWNER_GATE);
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
      if (invocation.exportedFunctionUnknown && !(['bash', 'sh'].includes(invocation.name) && invocation.shellPrivileged === true)) {
        deny('child shell に渡る exported function の名前・選択を確定できず、本文や実行条件を検査できません。対応する直接 source または実 env -i で同じ目的を保てる場合に検討してください。' + UNKNOWN_OWNER_GATE);
      }
      if (invocation.name === 'bash' && (invocation.helperEnvNames || []).includes('BASH_ENV') &&
          invocation.shellInteractive !== true && invocation.shellPrivileged !== true && invocation.shellPosix !== true) {
        deny('child Bash の BASH_ENV が選ぶ startup filename / expansion / code source を検査できません。-c の本文が literal でも startup source は先に実行され得ます。' + UNKNOWN_OWNER_GATE);
      }
      if (['bash', 'sh', 'dash', 'ksh', 'mksh'].includes(invocation.name) &&
          (invocation.helperEnvNames || []).includes('ENV') && invocation.shellInteractive !== false &&
          invocation.shellPrivileged !== true) {
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
  if (invocation.name === 'gh') verdict = invocation.args[0]?.text === 'gist' ?
    knownWord(invocation.args[0]) ? 'FORBIDDEN' : 'UNKNOWN' : ghApiUpload(invocation) || ghFilePayload(invocation);
  if (invocation.name === 'curl') {
    verdict = curlReadsUpload(invocation.args, invocation.incomplete, true);
    // Only the actual first literal argv -q/--disable prevents curl's implicit curlrc load.
    if (!verdict && !(knownWord(invocation.args[0]) && ['-q', '--disable'].includes(invocation.args[0].text))) verdict = 'UNKNOWN';
  }
  if (invocation.name === 'wget') verdict = wgetReadsUpload(invocation.args) || (wgetSourceBoundary(invocation) ? 'UNKNOWN' : false);
  if (['nc', 'ncat'].includes(invocation.name)) verdict = reverseShell(invocation);
  // Bare-host SFTP enters command mode; its batch/stdin can contain put without a visible path.
  if (invocation.name === 'sftp') verdict = sftpSession(invocation.args) ? 'UNKNOWN' : false;
  if (['scp', 'rsync'].includes(invocation.name)) verdict = invocation.incomplete ? 'UNKNOWN' : remoteCopyDestination(invocation);
  return contextualVerdict(invocation, verdict);
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
  if (['send-pack', 'http-push'].includes(g.sub)) {
    deny(`git ${g.sub} の送信先と対象履歴は、このガードの supported inspection 外で確認できません (fail-closed)。owner に対象・操作・source と不明点を確認してください。`);
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
