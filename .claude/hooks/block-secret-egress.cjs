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
 * 設計 (低誤検知): 日常操作を壊さないため、拒否は以下に限定する。
 *   (A) コマンド文字列に **リテラルの秘密**が含まれる (`$VAR` 参照は許可 = 値ではない)。
 *   (B) 古典的 exfil 形: `gh gist` / 非 origin への push / reverse shell /
 *       ローカルファイルの upload / 秘密ファイル読取 + ネットワーク送信。
 * 通常の `curl https://api...` (GET) や named remote への `git push` は通す。
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

if (SECRET_FILE_RE.test(withoutTemplateTokens(cmd)) && NET_VERB_RE.test(cmd)) {
  deny(
    '秘密ファイル名の形 (.env / *token*.json / *.key 等) とネットワーク名が同じ文字列に含まれています。\n' +
    '読取から送信への関係をこの照合だけでは確認できないためブロックしました (egress guard)。owner に対象・操作・cwd・source を確認してください。',
  );
}

// git の形を、git の呼び出しごとにも見る（global option や引用符を挟んだ形も同じに読む）。
const insp = guard.inspect(cmd);
if (insp.problems.length) deny(guard.problemMessage(insp.problems, 'egress ガード') + UNKNOWN_OWNER_GATE);
const URL_ARG_RE = /^(https?:\/\/|ssh:\/\/|git:\/\/|git@)/;
// Git は最初の `:` より前に `/` が無い宛先を scp 形と読む。`./a:b` はローカル。
const SCP_ARG_RE = /^[^/:]+:/;
const REMOTE_URL_KEY_RE = /^remote\..+\.(?:url|pushurl)$/i;
/** Require a static word before treating an existing refusal as a confirmed prohibited form. */
function knownWord(word) {
  return Boolean(word && !word.dynamic && !word.ansiCUnknown && !word.text.includes('\0'));
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
        const value = eq < 0 ? words[++k] : { text: t.slice(eq + 1), dynamic: w.dynamic };
        if (!positional && eq < 0 && value && value.dynamic && value.dynamicMaySplit !== false) indeterminate = true;
        if (matches[0] === 'repo') explicit = value;
      } else if (!positional && w.dynamic) indeterminate = true;
      continue;
    }
    if (!afterDD && t.startsWith('-')) {
      // -o と、前に値を取らない short option を束ねた形 (`-vo value`)。
      if (/^-[vqdnfu46]*o/.test(t)) {
        if (/^-[vqdnfu46]*o$/.test(t)) {
          const value = words[++k];
          if (!positional && value && value.dynamic && value.dynamicMaySplit !== false) indeterminate = true;
        }
      } else if (!positional && w.dynamic) indeterminate = true;
      continue;
    }
    if (!afterDD && !positional && w.dynamic) indeterminate = true;
    if (!positional) positional = w;
  }
  // --repo は位置引数の repository が無い時だけ使われる。
  return { repository: positional || explicit, indeterminate };
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
  for (let k = 0; k < words.length; k++) {
    const t = words[k].text;
    if (!afterDD && t === '--') { afterDD = true; continue; }
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
      if (/^(?:--get(?:-all|-regexp|-urlmatch|-color|-colorbool)?|--list)$/.test(t)) read = true;
      continue;
    }
    if (!afterDD && t.startsWith('-')) {
      if (/^-[z]*[fbt]$/.test(t)) k++;
      if (t === '-l') read = true;
      continue;
    }
    if (!afterDD && !actionSeen && ['get', 'list', 'unset', 'remove-section', 'set', 'rename-section', 'edit'].includes(t)) {
      actionSeen = true;
      rename = t === 'rename-section';
      deletion = t === 'unset' ? 'key' : t === 'remove-section' ? 'section' : null;
      read = ['get', 'list'].includes(t);
      continue;
    }
    operands.push(t);
    operandWords.push(words[k]);
    // config は key 以降を value / value-pattern として扱う（--get という値もある）。
    afterDD = true;
  }
  return { read, rename, deletion, operands, operandWords };
}

/** Classify destination writes while keeping getters and consumed option values outside the refusal. */
function writesDestinationConfig(words) {
  const { read, rename, deletion, operands, operandWords } = configOperation(words);
  // Removing a selected destination exposes fallback URLs/configuration just like replacing it.
  if (deletion) {
    if (!(operands.length > 0 && (operandWords[0].dynamic ||
        (deletion === 'key' ? destinationConfig(operands[0]) : destinationSection(operands[0]))))) return false;
    if (deletion === 'section' || !knownWord(operandWords[0])) return 'UNKNOWN';
  } else {
    if (!(!read && operands.length > 1 && (rename ?
        operandWords[1].dynamic || destinationSection(operands[1]) : destinationConfig(operands[0])))) return false;
    if (rename || !knownWord(operandWords[0])) return 'UNKNOWN';
  }
  // An include or transport key selects executable/config source whose effect is not inspected here.
  return transportConfig(operands[0]) || /^include(?:if\..+)?\.path$/i.test(operands[0]) ? 'UNKNOWN' : 'FORBIDDEN';
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
function curlReadsUpload(words, incomplete = false) {
  // xargs/find can provide an unseen filename to a trailing file-reading option.
  const fileOptions = new Set(['upload-file', 'data', 'data-ascii', 'data-binary', 'json',
    'header', 'proxy-header', 'data-urlencode', 'url-query', 'form', 'variable']);
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
    if (t.startsWith('--')) {
      const eq = t.indexOf('=');
      const fullName = t.slice(2, eq < 0 ? undefined : eq);
      const expanding = fullName.startsWith('expand-');
      const name = expanding ? fullName.slice(7) : fullName;
      if (optionWord.dynamic && /^url-(?:query)?\0/.test(name)) return 'UNKNOWN';
      const matches = CURL_LONG_NAMES.includes(name) ? [name] : CURL_LONG_NAMES.filter((option) => option.startsWith(name));
      if (matches.length !== 1 || !CURL_VALUE_LONG.has(matches[0])) continue;
      const option = matches[0];
      if (option === 'config') return 'UNKNOWN';
      const value = eq < 0 ? words[++k] : { ...optionWord, text: t.slice(eq + 1) };
      if (value) {
        if (option === 'variable') { variableDefinition(value.text, expanding, value); continue; }
        const source = expanding ? expanded(value.text) : { text: value.text, file: false };
        const verdict = !incomplete && knownWord(optionWord) && knownWord(value) && !source.unknown &&
          (option !== 'url-query' || name === option) ? 'FORBIDDEN' : 'UNKNOWN';
        // A scalar '+' or '=' proves inline query syntax; an unknown prefix or argv count does not.
        if (option === 'url-query' && ((value.dynamic && value.dynamicMaySplit !== false) ||
            (!source.file && !source.text.startsWith('+') && !source.text.includes('=') && source.text.includes('\0')))) return 'UNKNOWN';
        if (expanding && outbound.has(option) && SECRET_LITERALS.some((pattern) => pattern.test(source.text))) return verdict;
        if ((source.file && outbound.has(option)) || payload(option, source.text)) return verdict;
      } else if (incomplete && fileOptions.has(option)) return 'UNKNOWN';
    } else if (t.startsWith('-')) {
      for (let p = 1; p < t.length; p++) {
        const option = CURL_VALUE_SHORT[t[p]];
        if (!option) continue;
        if (option === 'config') return 'UNKNOWN';
        const value = p + 1 < t.length ? { ...optionWord, text: t.slice(p + 1) } : words[++k];
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
  const shortValues = { scp: 'cDFiJloPSX', sftp: 'BcDFiJloPRSs', rsync: 'efBMT' };
  const longValues = new Set(['rsh', 'rsync-path', 'filter', 'include', 'exclude', 'include-from', 'exclude-from',
    'files-from', 'compare-dest', 'copy-dest', 'link-dest', 'password-file', 'address', 'port', 'timeout',
    'contimeout', 'bwlimit', 'chown', 'chmod', 'usermap', 'groupmap', 'out-format', 'log-file',
    'backup-dir', 'suffix', 'temp-dir']);
  const operands = [];
  let afterDD = false;
  for (let k = 0; k < invocation.args.length; k++) {
    const t = invocation.args[k].text;
    if (!afterDD && t === '--') { afterDD = true; continue; }
    if (!afterDD && t.startsWith('--')) {
      const eq = t.indexOf('=');
      if (eq < 0 && longValues.has(t.slice(2))) k++;
      continue;
    }
    if (!afterDD && t.startsWith('-')) {
      for (let p = 1; p < t.length; p++) {
        if (shortValues[invocation.name].includes(t[p])) { if (p === t.length - 1) k++; break; }
      }
      continue;
    }
    operands.push(invocation.args[k]);
  }
  const destination = operands[operands.length - 1];
  return destination && destinationArg(destination.text) ? knownWord(destination) ? 'FORBIDDEN' : 'UNKNOWN' : false;
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

/** Select SSH commands/config sources that run locally, retaining proven non-executing query and DATA options. */
function sshCommandSources(invocation) {
  return sshOperation(invocation).sources;
}

/** Read SSH's option boundary before and after the host, stopping at the actual remote command. */
function sshOperation(invocation) {
  if (invocation.name !== 'ssh') return { sources: [], stdin: false };
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
  for (let k = 0; k < invocation.args.length; k++) {
    const word = invocation.args[k];
    const text = word.text;
    if (text === '--') { host = host || Boolean(invocation.args[k + 1]); break; }
    const provenOperand = typeof word.literalValue === 'string' && word.dynamicMaySplit === false && !word.literalValue.startsWith('-');
    if (word.dynamic && !provenOperand && (word.dynamicMaySplit !== false || text.startsWith('\0'))) argvUncertain = true;
    if (!text.startsWith('-')) { if (host) break; host = true; continue; }
    for (let p = 1; p < text.length; p++) {
      if (text[p] === 'G') { requestedQuery = true; if (!argvUncertain) query = true; }
      if (text[p] === 'Q' || text[p] === 'V') { requestedEarlyQuery = true; if (!argvUncertain) earlyQuery = true; }
      if (text[p] === 'n' || text[p] === 'f') detached = true;
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
  if (selectedConfig ? earlyQuery : requestedEarlyQuery) return { sources: [], stdin: false };
  if (selectedConfig && (argvUncertain || !configFile || configFile.dynamic || !['none', '/dev/null'].includes(configFile.text))) {
    deny('SSH の -F config が未知の実行 source（Match exec 等）を選び、egress ガードで検査できません (fail-closed)。' + UNKNOWN_OWNER_GATE);
  }
  if (selectedConfig ? query : requestedQuery) return { sources: [], stdin: false };
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
  return { sources, stdin: host && !detached };
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
  return guard.inspect(['env', ...words.map((word) => word.text), ...tail.map((word) => word.text)].map(parserLiteral).join(' '));
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
  for (const g of inspection.gits) gitInvocationContexts.set(g,
    inspection.invocations.find((invocation) => invocation.order === g.invocationOrder));
  const activeCommits = inspection.gits.filter(g => g.sub === 'commit' && !guard.parseCommitArgs(g.args).terminal);
  for (const g of inspection.gits) {
    const decision = guard.gitObjectInputDecision(g);
    if (decision) deny(decision.reason, gitVerdict(g, decision.category));
    const pager = guard.grepPagerEffect(g);
    const beforeCommit = activeCommits.some(commit => !Number.isInteger(g.invocationOrder) ||
      !Number.isInteger(commit.invocationOrder) || g.invocationOrder <= commit.invocationOrder);
    if (beforeCommit && (pager.opensFiles || pager.unknown)) {
      deny('commit 前の git grep が開く外部 pager または argv/source の選択を検査できず、index の維持を確認できません。pager を開かない対応済みの同目的形式にできなければ owner に対象・操作・cwd/env/config/source を確認してください。個別操作の了承は hook 無効化の了承ではありません。');
    }
  }
  const result = [];
  for (const invocation of inspection.invocations) {
    if (invocation.nonExec || invocation.definitionName) continue;
    result.push(invocation);
    const scripts = [];
    const gitCommand = inspection.gits.find((g) => g.invocationOrder === invocation.order);
    if (gitCommand) scripts.push(...credentialHelperSources(gitCommand));
    scripts.push(...sshCommandSources(invocation));
    if (invocation.splitString) {
      for (const script of invocation.splitWords) result.push(...collectNetworkInvocations(envSplitInspection(invocation, script), depth + 1));
    }
    if (['bash', 'sh', 'zsh', 'dash', 'ksh', 'mksh', 'fish'].includes(invocation.name)) {
      if (invocation.shellCommandMode && invocation.shellSourceUnknown) {
        deny('シェルの command mode の source が option の境界から確定できず、egress ガードで検査できません (fail-closed)。' + UNKNOWN_OWNER_GATE);
      }
      scripts.push(...invocation.shellScripts.map((script) => ({ ...script, initialPositionals: invocation.shellPositionals })));
      if (!invocation.shellCommandMode && invocation.shellReadsStdin) {
        scripts.push(...invocation.redirs.filter((redir) => redir.op === '<<<')
          .map((redir) => ({ ...redir.word, initialPositionals: invocation.shellPositionals })));
      }
    } else if (invocation.name === 'eval') {
      const args = invocation.args[0] && invocation.args[0].text === '--' ? invocation.args.slice(1) : invocation.args;
      scripts.push({ text: args.map((word) => word.text).join(' ') });
    }
    if (invocation.trapSourceUnknown) deny('trap に登録する source が確定できず、egress ガードで検査できません (fail-closed)。' + UNKNOWN_OWNER_GATE);
    scripts.push(...invocation.trapScripts.map((script) => ({ ...script, mediated: true })));
    if (invocation.aliasSourceUnknown) deny('alias に登録する source が確定できず、egress ガードで検査できません (fail-closed)。' + UNKNOWN_OWNER_GATE);
    scripts.push(...(invocation.aliasScripts || []).map((script) => ({ ...script, mediated: true })));
    for (const script of scripts) {
      const nested = script.mediated ? guard.inspectMediatedSource(script) :
        guard.inspect(script.text, { initialPositionals: script.initialPositionals });
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
  let verdict = false;
  if (invocation.name === 'gh') verdict = invocation.args[0]?.text === 'gist' ?
    knownWord(invocation.args[0]) ? 'FORBIDDEN' : 'UNKNOWN' : ghApiUpload(invocation);
  if (invocation.name === 'curl') verdict = curlReadsUpload(invocation.args, invocation.incomplete);
  if (invocation.name === 'wget') verdict = wgetReadsUpload(invocation.args);
  if (['nc', 'ncat'].includes(invocation.name)) verdict = reverseShell(invocation);
  // Bare-host SFTP enters command mode; its batch/stdin can contain put without a visible path.
  if (invocation.name === 'sftp') verdict = sftpSession(invocation.args) ? 'UNKNOWN' : false;
  if (['scp', 'rsync'].includes(invocation.name)) verdict = invocation.incomplete ? 'UNKNOWN' : remoteCopyDestination(invocation);
  return contextualVerdict(invocation, verdict);
}

const invocations = collectNetworkInvocations(insp);
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
  const unknownPushDestination = g.sub === 'push' && (push.indeterminate || (repo && repo.dynamic) ||
    g.configEnvs.some((config) => destinationConfig(config.split('=')[0])) ||
    g.configs.some((config) => transportConfig(config.split('=')[0])) ||
    g.gitEnvNames.some((name) => /^GIT_CONFIG(?:_|$)/.test(name) || /^GIT_(?:SSH(?:_COMMAND)?|PROXY_COMMAND)$/.test(name)));
  if (unknownPushDestination) {
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
