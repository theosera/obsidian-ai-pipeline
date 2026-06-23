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
 */
const fs = require('node:fs');

function readStdin() {
  try { return fs.readFileSync(0, 'utf8'); } catch { return ''; }
}

// (A) リテラル秘密。`$GITHUB_TOKEN` 等の env 参照は値ではないので **当たらない**
// (値クラスに `$` を含めない / 代入値が `$` 始まりなら除外)。ops-logging の mask()
// 規則と整合。新形式を足したらここと Python 版・mask() を同時に更新する。
const SECRET_LITERALS = [
  /gh[pousr]_[A-Za-z0-9]{20,}/,                 // GitHub token
  /github_pat_[A-Za-z0-9_]{20,}/,               // GitHub fine-grained PAT
  /\bsk-[A-Za-z0-9]{20,}/,                       // OpenAI / Anthropic style
  /\bAKIA[0-9A-Z]{16}\b/,                        // AWS access key id
  /\bxox[baprs]-[A-Za-z0-9-]{10,}/,             // Slack
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,         // PEM private key
  /:\/\/[^/\s:@]+:[^/\s@]{3,}@/,                 // URL 埋め込み user:pass@
  /Authorization:\s*Bearer\s+[A-Za-z0-9._-]{10,}/i,
  // KEY=<literal value> 形 (値が `$` 始まり = env 参照なら除外)。
  /(CLIENT_SECRET|REFRESH_TOKEN|API_KEY|ACCESS_TOKEN|PRIVATE_KEY|PASSWORD|GMAIL_CLIENT_SECRET)\s*[=:]\s*['"]?(?!\$)[A-Za-z0-9._\-/+]{8,}/i,
];

// (B) 古典的 exfil 形。
const EXFIL_SHAPES = [
  /\bgh\s+gist\b/,                                       // gh gist create/...
  /\b(nc|ncat)\b[^\n]*\s-e\b/,                           // reverse shell
  /\bgit\s+remote\s+add\b/,                              // 外部 remote 追加
  /\bgit\s+push\s+(https?:\/\/|git@|ssh:\/\/)/,          // 明示 URL への push (named remote でない)
  /\bcurl\b[^\n]*\s(--data-binary|--upload-file|-T|-F|-d|--data)\b[^\n]*@/,  // ローカルファイル upload
  /\b(scp|sftp)\b[^\n]*\s[^\s]+:[^\s]/,                  // local -> remote コピー
  /\brsync\b[^\n]*\s[^\s]+:[^\s]/,
];

// (B') 秘密ファイル読取 + ネットワーク送信の組合せ (例: `cat .env | curl ...`)。
const SECRET_FILE_RE = /(\.env(\.|\b)|x_tokens\.json|credentials[^/\s]*\.json|service-account[^/\s]*\.json|[^/\s]*token[^/\s]*\.json|\.pem\b|\.key\b|id_(rsa|ed25519)\b|secrets\.(json|ya?ml)\b)/i;
const NET_VERB_RE = /\b(curl|wget|nc|ncat|scp|sftp|rsync|telnet)\b|\bgh\s+gist\b/i;
// .env.example はテンプレートなので秘密ファイル扱いしない。
const isExampleOnly = (cmd) => /\.env\.example\b/i.test(cmd) && !/\.env(\b|\.)(?!example)/i.test(cmd);

function deny(reason) {
  process.stdout.write(JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: reason,
    },
  }));
  process.exit(0);
}

let cmd = '';
try {
  const j = JSON.parse(readStdin() || '{}');
  cmd = (j.tool_input && j.tool_input.command) || '';
} catch { process.exit(0); }
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

process.exit(0);
