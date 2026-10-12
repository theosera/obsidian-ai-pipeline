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
// .env.example はテンプレートなので秘密ファイル扱いしない。
const isExampleOnly = (cmd) => /\.env\.example\b/i.test(cmd) && !/\.env(\b|\.)(?!example)/i.test(cmd);

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

if (!isExampleOnly(cmd) && SECRET_FILE_RE.test(cmd) && NET_VERB_RE.test(cmd)) {
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

/** Distinguish config writes from getters without treating an option value as an action. */
function writesRemoteUrl(words) {
  const valueOpts = ['file', 'blob', 'type', 'default', 'value', 'url', 'comment'];
  const operands = [];
  let read = false;
  let afterDD = false;
  let actionSeen = false;
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
      read = ['get', 'list', 'unset', 'remove-section'].includes(t);
      continue;
    }
    operands.push(t);
    // config は key 以降を value / value-pattern として扱う（--get という値もある）。
    afterDD = true;
  }
  return !read && operands.length > 1 && REMOTE_URL_KEY_RE.test(operands[0]);
}

/** Identify configuration keys that can change a push's repository or URL rewrite. */
function destinationConfig(key) {
  return REMOTE_URL_KEY_RE.test(key) ||
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

for (const g of insp.gits) {
  const a = g.args.map((w) => w.text);
  const firstWord = a.find((x) => !x.startsWith('-'));
  const remoteWrite = g.sub === 'remote' && (firstWord === 'add' || firstWord === 'set-url');
  const configWrite = g.sub === 'config' && writesRemoteUrl(g.args);
  const push = g.sub === 'push' ? pushRepository(g.args) : null;
  const repo = push && push.repository;
  const unknownPushDestination = g.sub === 'push' && (push.indeterminate || (repo && repo.dynamic) ||
    g.configEnvs.some((config) => destinationConfig(config.split('=')[0])) ||
    g.gitEnvNames.some((name) => /^GIT_CONFIG(?:_|$)/.test(name)));
  if (unknownPushDestination) {
    deny('git push の宛先が変数・置換や --config-env / GIT_CONFIG 環境変数で作られていて、egress ガードで確かめられません (fail-closed)。');
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
