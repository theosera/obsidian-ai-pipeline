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
      permissionDecisionReason: 'git ガードの共通の部品 (lib/git-guard-common.cjs) を読み込めませんでした (fail-closed)。egress ガードを通せないため実行をブロックします。',
    },
  }));
  process.exit(0);
}
const { deny } = guard;

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
  for (const invocation of inspected.invocations) for (const script of invocation.trapScripts) {
    if (!script.dynamic) codeSources.set(`${script.start}:${script.raw}`, script.text);
  }
  for (const word of sourceWords) {
    const config = /^credential(?:\..+)?\.helper=(.*)$/is.exec(word.text);
    if (config) codeSources.set(`${word.start}:${word.raw}`, config[1].startsWith('!') ? config[1].slice(1) :
      config[1].startsWith('/') ? config[1] : `__credential_helper__${config[1]}`);
  }
  for (const g of inspected.gits) if (g.sub === 'config') {
    const operation = configOperation(g.args);
    if (!operation.read && !operation.rename && operation.operands.length > 1 && /^credential(?:\..+)?\.helper$/i.test(operation.operands[0])) {
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
      if (word.dynamic || (!templateFilename && !headerData && !templateDataSource)) continue;
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

const { cmd } = guard.readInput('egress ガード');
if (!cmd) process.exit(0);

if (SECRET_LITERALS.some((re) => re.test(cmd))) {
  deny(
    'コマンド内にリテラルの秘密 (token / key / client secret 等) が含まれています。\n' +
    '自リポ外への秘密送信を防ぐためブロックしました (egress guard)。env 変数参照 ($VAR) を' +
    '使うか、本当に必要なら手動で実行してください。',
  );
}

if (EXFIL_SHAPES.some((re) => re.test(cmd))) {
  deny(
    '外向き送信 (gist / 非 origin への push / reverse shell / ローカルファイル upload 等) を検出しました。\n' +
    'スクショ型インジェクションによる秘密持ち出しを防ぐためブロックしました (egress guard)。' +
    '正当な操作なら内容を確認のうえ手動で実行してください。',
  );
}

if (SECRET_FILE_RE.test(withoutTemplateTokens(cmd)) && NET_VERB_RE.test(cmd)) {
  deny(
    '秘密ファイル (.env / *token*.json / *.key 等) の読取とネットワーク送信が同一コマンドに含まれています。\n' +
    '秘密の外部送信を防ぐためブロックしました (egress guard)。',
  );
}

// git の形を、git の呼び出しごとにも見る（global option や引用符を挟んだ形も同じに読む）。
const insp = guard.inspect(cmd);
if (insp.problems.length) deny(guard.problemMessage(insp.problems, 'egress ガード'));
const URL_ARG_RE = /^(https?:\/\/|ssh:\/\/|git:\/\/|git@)/;
// Git は最初の `:` より前に `/` が無い宛先を scp 形と読む。`./a:b` はローカル。
const SCP_ARG_RE = /^[^/:]+:/;
const REMOTE_URL_KEY_RE = /^remote\..+\.(?:url|pushurl)$/i;
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
      if (/^(?:--get(?:-all|-regexp|-urlmatch|-color|-colorbool)?|--list|--unset(?:-all)?|--remove-section)$/.test(t)) read = true;
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
      read = ['get', 'list', 'unset', 'remove-section'].includes(t);
      continue;
    }
    operands.push(t);
    operandWords.push(words[k]);
    // config は key 以降を value / value-pattern として扱う（--get という値もある）。
    afterDD = true;
  }
  return { read, rename, operands, operandWords };
}

/** Distinguish destination-config writes from getters without treating option values as actions. */
function writesDestinationConfig(words) {
  const { read, rename, operands, operandWords } = configOperation(words);
  return !read && operands.length > 1 && (rename ?
    operandWords[1].dynamic || destinationSection(operands[1]) : destinationConfig(operands[0]));
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
      deny('credential helper の source が --config-env の値から作られ、egress ガードで検査できません (fail-closed)。');
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
    if (!operation.read && !operation.rename && operation.operands.length > 1 && helperKey(operation.operands[0])) {
      values.push(operation.operands[1]);
    }
  }
  return values.filter(Boolean).map((helper) => {
    if (helper.includes('\0')) deny('credential helper の source が変数・置換を含み、egress ガードで検査できません (fail-closed)。');
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
    'header', 'proxy-header', 'data-urlencode', 'form', 'variable']);
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
    const text = value.replace(/\{\{([A-Za-z0-9_]+)(?::([^}]*))?\}\}/g, (whole, name, transforms, offset) => {
      let escapes = 0;
      for (let p = offset - 1; p >= 0 && value[p] === '\\'; p--) escapes++;
      if (escapes % 2) return whole;
      const variable = variables.get(name);
      file ||= unknownFileVersion > (variable ? variable.version : 0);
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
        else return '\0';
      }
      return result;
    });
    return { text, file };
  };
  /** Track definitions in order so unused or overwritten file variables do not imply an upload. */
  const variableDefinition = (value, expanding) => {
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
      text: definition[2] === '@' || !definition[2] || source.text.includes('\0') ? null : source.text });
  };
  /** Match file references using the option's own value, not text printed inside another value. */
  const payload = (option, value) => {
    if (option === 'config') return true; // config can supply upload options or a destination
    if (option === 'upload-file') return Boolean(value);
    if (['data', 'data-ascii', 'data-binary', 'json', 'header', 'proxy-header'].includes(option)) return value.startsWith('@');
    if (option === 'data-urlencode') return value.includes('@');
    if (option === 'form') return /=\s*[@<]/.test(value);
    return false;
  };
  for (let k = 0; k < words.length; k++) {
    const t = words[k].text;
    if (t === '--') break;
    if (t.startsWith('--')) {
      const eq = t.indexOf('=');
      const fullName = t.slice(2, eq < 0 ? undefined : eq);
      const expanding = fullName.startsWith('expand-');
      const name = expanding ? fullName.slice(7) : fullName;
      const matches = CURL_LONG_NAMES.includes(name) ? [name] : CURL_LONG_NAMES.filter((option) => option.startsWith(name));
      if (matches.length !== 1 || !CURL_VALUE_LONG.has(matches[0])) continue;
      const option = matches[0];
      if (option === 'config') return true;
      const value = eq < 0 ? words[++k] : { text: t.slice(eq + 1) };
      if (value) {
        if (option === 'variable') { variableDefinition(value.text, expanding); continue; }
        const source = expanding ? expanded(value.text) : { text: value.text, file: false };
        if (expanding && outbound.has(option) && SECRET_LITERALS.some((pattern) => pattern.test(source.text))) return true;
        if ((source.file && outbound.has(option)) || payload(option, source.text)) return true;
      } else if (incomplete && fileOptions.has(option)) return true;
    } else if (t.startsWith('-')) {
      for (let p = 1; p < t.length; p++) {
        const option = CURL_VALUE_SHORT[t[p]];
        if (!option) continue;
        if (option === 'config') return true;
        const value = p + 1 < t.length ? { text: t.slice(p + 1) } : words[++k];
        if (value ? payload(option, value.text) : incomplete && fileOptions.has(option)) return true;
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
      if (opaque.has(matches[0])) return true;
      // --use-askpass has an optional attached value; the following word remains an option/URL.
      if (eq < 0 && matches[0] !== 'use-askpass') k++;
    } else if (t.startsWith('-')) {
      for (let p = 1; p < t.length; p++) {
        if (!WGET_VALUE_SHORT.includes(t[p])) continue;
        if (t[p] === 'e') return true;
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
    operands.push(t);
  }
  return operands.length > 0 && destinationArg(operands[operands.length - 1]);
}

/** Identify an executable network verb using parsed command names, never names printed as data. */
function networkInvocation(invocation) {
  return ['curl', 'wget', 'nc', 'ncat', 'scp', 'sftp', 'rsync', 'telnet'].includes(invocation.name) ||
    (invocation.name === 'gh' && invocation.args[0] && invocation.args[0].text === 'gist');
}

/** Detect SSH sessions that can consume stdin, skipping option values and excluding explicit -n/-f. */
function sshReadsInput(invocation) {
  const valueOptions = 'bcDEeFIiJLlmOopQRSWw';
  for (let k = 0; k < invocation.args.length; k++) {
    const t = invocation.args[k].text;
    if (t === '--') return Boolean(invocation.args[k + 1]);
    if (!t.startsWith('-')) return true; // first positional argument is the remote destination
    for (let p = 1; p < t.length; p++) {
      if (t[p] === 'n' || t[p] === 'f' || t[p] === 'G') return false;
      if (valueOptions.includes(t[p])) { if (p === t.length - 1) k++; break; }
    }
  }
  return false;
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
      if (option === 'exec' || (invocation.name === 'ncat' && option === 'sh-exec')) return true;
      if (eq < 0 && longValues.has(option)) k++;
    } else if (t.startsWith('-')) {
      for (let p = 1; p < t.length; p++) {
        if (t[p] === 'e' || (invocation.name === 'ncat' && t[p] === 'c')) return true;
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
/** Parse interpreter strings as code, retaining ordinary literal arguments as data. */
function collectNetworkInvocations(inspection, depth = 0) {
  if (depth > 16) deny('文字列の interpreter が深く入れ子になっていて、egress ガードで検査できません (fail-closed)。');
  if (inspection.problems.length) deny(guard.problemMessage(inspection.problems, 'egress ガード'));
  inspectedGits.push(...inspection.gits);
  const result = [];
  for (const invocation of inspection.invocations) {
    if (invocation.nonExec || invocation.definitionName) continue;
    result.push(invocation);
    const scripts = [];
    const gitCommand = inspection.gits.find((g) => g.invocationOrder === invocation.order);
    if (gitCommand) scripts.push(...credentialHelperSources(gitCommand));
    if (invocation.splitString) {
      for (const script of invocation.splitWords) result.push(...collectNetworkInvocations(envSplitInspection(invocation, script), depth + 1));
    }
    if (['bash', 'sh', 'zsh', 'dash', 'ksh', 'mksh', 'fish'].includes(invocation.name)) {
      if (invocation.shellCommandMode && invocation.shellSourceUnknown) {
        deny('シェルの command mode の source が option の境界から確定できず、egress ガードで検査できません (fail-closed)。');
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
    if (invocation.trapSourceUnknown) deny('trap に登録する source が確定できず、egress ガードで検査できません (fail-closed)。');
    scripts.push(...invocation.trapScripts.map((script) => ({ ...script, mediated: true })));
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

/** Apply the classic egress shapes to executable names reconstructed by the shell parser. */
function parsedExfil(invocation) {
  if (invocation.name === 'gh') return invocation.args[0] && invocation.args[0].text === 'gist';
  if (invocation.name === 'curl') return curlReadsUpload(invocation.args, invocation.incomplete);
  if (invocation.name === 'wget') return wgetReadsUpload(invocation.args);
  if (['nc', 'ncat'].includes(invocation.name)) return reverseShell(invocation);
  // Bare-host SFTP enters command mode; its batch/stdin can contain put without a visible path.
  if (invocation.name === 'sftp') return sftpSession(invocation.args);
  if (['scp', 'rsync'].includes(invocation.name)) return invocation.incomplete || remoteCopyDestination(invocation);
  return false;
}

const invocations = collectNetworkInvocations(insp);
// Reapply the same literal inventory after shell quote/escape concatenation; never expand variables.
const parsedWords = insp.invocations.concat(invocations).flatMap((invocation) =>
  invocation.words.concat(invocation.redirs.map((redir) => redir.word)));
if (parsedWords.some((word) => SECRET_LITERALS.some((pattern) => pattern.test(word.text)))) {
  deny('シェルの引用符・escape を戻した引数にリテラルの秘密 (token / key / client secret 等) が含まれています (egress guard)。');
}
if (invocations.some(parsedExfil) || invocations.some(dynamicNetworkShape) || invocations.some(opaqueLauncherNetwork)) {
  deny('シェルの引用符・escape を戻した実行コマンドに、外向き送信 (gist / reverse shell / ローカルファイル upload 等) を検出しました (egress guard)。');
}
const parsedFileRefs = invocations.flatMap((invocation) => {
  const readsFiles = ['cat', 'head', 'tail', 'base64', 'xxd'].includes(invocation.name);
  return (readsFiles ? invocation.args : []).concat(invocation.redirs.map((redir) => redir.word)).map((word) => word.text);
});
const secretEvidence = [cmd, ...parsedFileRefs].join('\n');
if (SECRET_FILE_RE.test(withoutTemplateTokens(secretEvidence)) &&
    invocations.some((invocation) => networkInvocation(invocation) || invocation.dynamicName || invocation.launcherUnknown)) {
  deny('秘密ファイルの読取と、シェルの引用符・escape を戻したネットワーク送信コマンドが同一コマンドに含まれています (egress guard)。');
}
// SSH identity/config options are authentication input; only local file readers/input redirects identify upload.
const sshReadEvidence = invocations.flatMap((invocation) => {
  const readsFiles = ['cat', 'head', 'tail', 'base64', 'xxd'].includes(invocation.name);
  return (readsFiles ? invocation.args : []).concat(invocation.redirs
    .filter((redir) => ['<', '<>'].includes(redir.op)).map((redir) => redir.word))
    .map((word) => word.text.replace(/(^|\/)\.env\.example$/i, '$1'));
}).join('\n');
if (SECRET_FILE_RE.test(sshReadEvidence) &&
    invocations.some((invocation) => invocation.name === 'ssh' && sshReadsInput(invocation))) {
  deny('秘密ファイルの読取と SSH セッションが同一コマンドに含まれ、SSH の stdin に秘密を送る可能性があります (egress guard)。');
}

for (const g of inspectedGits) {
  const a = g.args.map((w) => w.text);
  const firstWord = a.find((x) => !x.startsWith('-'));
  const remoteWrite = g.sub === 'remote' && (firstWord === 'add' || firstWord === 'set-url');
  const configWrite = g.sub === 'config' && writesDestinationConfig(g.args);
  if (['send-pack', 'http-push'].includes(g.sub)) {
    deny(`git ${g.sub} は履歴を直接送る plumbing command で、egress ガードの検査対象外です。送信をブロックします (fail-closed)。`);
  }
  if (g.sub === 'push' && g.incomplete) {
    deny('xargs / find などの入力から git push に追加される引数は、egress ガードで宛先を確かめられません (fail-closed)。');
  }
  const push = g.sub === 'push' ? pushRepository(g.args) : null;
  const repo = push && push.repository;
  const unknownPushDestination = g.sub === 'push' && (push.indeterminate || (repo && repo.dynamic) ||
    g.configEnvs.some((config) => destinationConfig(config.split('=')[0])) ||
    g.configs.some((config) => transportConfig(config.split('=')[0])) ||
    g.gitEnvNames.some((name) => /^GIT_CONFIG(?:_|$)/.test(name) || /^GIT_(?:SSH(?:_COMMAND)?|PROXY_COMMAND)$/.test(name)));
  if (unknownPushDestination) {
    deny('git push の宛先や transport command が変数・置換や config / GIT_CONFIG / GIT_SSH / GIT_PROXY_COMMAND の override で作られていて、egress ガードで確かめられません (fail-closed)。');
  }
  const pushUrl = g.sub === 'push' && (a.some((x) => URL_ARG_RE.test(x)) ||
    (repo && destinationArg(repo.text)) || g.configs.some(externalConfig));
  if (remoteWrite || configWrite || pushUrl) {
    deny(
      '外向き送信 (gist / 非 origin への push / reverse shell / ローカルファイル upload 等) を検出しました。\n' +
      'スクショ型インジェクションによる秘密持ち出しを防ぐためブロックしました (egress guard)。' +
      '正当な操作なら内容を確認のうえ手動で実行してください。',
    );
  }
}

process.exit(0);
