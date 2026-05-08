/**
 * X 側で削除されたフォルダ (orphan_on_x) について、
 * (a) Vault 側を保持 / (b) `_archived/` へ退避 / (s) 次回再判定 を
 * AI が推奨し、ユーザーが y/n 確定するハンドラ。
 *
 * AI バックエンド:
 *   - デフォルト: Claude Code CLI (`claude -p`) — hands_on_generator.ts と同方式
 *   - 環境変数 `X_SESSION_AI_BIN` で local LLM や別 CLI に差し替え可能
 *   - 環境変数 `X_SESSION_AI_DISABLE=true` で AI 判定をスキップ (推奨は "keep")
 *
 * AI 出力フォーマット:
 *   1 行目: "RECOMMEND: keep" or "RECOMMEND: archive"
 *   2 行目以降: 理由 (ユーザー画面に表示)
 */

import { spawn, spawnSync } from 'child_process';
import path from 'path';
import { OrphanOnX, OrphanResolver, OrphanResolution } from './x_session_sync';

export interface AskFn {
  (prompt: string): Promise<string>;
}

const PROMPT_TEMPLATE = `あなたは X (Twitter) ブックマーク管理アシスタントです。
ユーザーの X 上で次のフォルダが削除されました。Vault 内の対応フォルダを残すべきか判定してください。

# 削除された X フォルダ
- 名前: {{xFolderName}}
- session_id: {{sessionId}}

# Vault 側の状況
- 配下 .md 件数: {{mdCount}}
- 最新ポスト更新日 (mtime): {{latestPostDate}}
- Vault 相対パス: {{vaultPath}}

# 判定ルール
- (a) keep: Vault 側を残す。最近 (30日以内) アクセスされている / 件数が多い / 参照価値が高そうなら推奨
- (b) archive: \`_archived/{session_id}/\` に退避。古い・空に近い・他フォルダで代替できそうなら推奨

# 出力フォーマット (厳守)
1 行目: "RECOMMEND: keep" または "RECOMMEND: archive"
2 行目以降: 1〜2 文の理由。日本語で。

それ以外の前置き・後置き・コードブロックは絶対に出力しないこと。
`;

function renderPrompt(orphan: OrphanOnX): string {
  return PROMPT_TEMPLATE
    .replace('{{xFolderName}}', orphan.session.x_folder_name ?? '(unknown)')
    .replace('{{sessionId}}', orphan.session.session_id)
    .replace('{{mdCount}}', String(orphan.mdCount))
    .replace('{{latestPostDate}}', orphan.latestPostDate ?? '(unknown)')
    .replace('{{vaultPath}}', orphan.session.vault_path ?? '(unknown)');
}

interface AiVerdict {
  recommend: 'keep' | 'archive';
  reason: string;
  source: 'ai' | 'fallback';
}

/** AI CLI 呼び出しのウォールクロックタイムアウト (ms)。0 で無制限 (非推奨)。 */
const AI_CALL_TIMEOUT_MS = Number(process.env.X_SESSION_AI_TIMEOUT_MS) || 60_000;

async function callAiBackend(prompt: string): Promise<AiVerdict> {
  if (process.env.X_SESSION_AI_DISABLE === 'true' || process.env.X_SESSION_AI_DISABLE === '1') {
    return {
      recommend: 'keep',
      reason: 'AI 判定が無効化 (X_SESSION_AI_DISABLE)。安全側 (keep) を推奨します。',
      source: 'fallback',
    };
  }
  const bin = process.env.X_SESSION_AI_BIN || 'claude';
  // 疎通チェックも timeout 付き (auth プロンプトで永久に止まるのを防止)
  const probe = spawnSync(bin, ['--version'], { encoding: 'utf8', timeout: 5_000 });
  if (probe.error || probe.status !== 0) {
    return {
      recommend: 'keep',
      reason: `AI CLI (${bin}) が呼べないため安全側 (keep) を推奨します。`,
      source: 'fallback',
    };
  }
  // spawn にネイティブ timeout が無いので setTimeout で SIGTERM を送る。
  // ハング (network / interactive auth プロンプト / モデル無応答) で sync 全体が
  // 止まるのを避ける。タイムアウト時は空応答 → parseAiOutput が "keep" にフォールバック。
  const out = await new Promise<string>((resolve) => {
    const proc = spawn(bin, ['-p', prompt], { stdio: ['ignore', 'pipe', 'pipe'] });
    const chunks: Buffer[] = [];
    let settled = false;
    const settle = (v: string) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(v);
    };
    const timer = setTimeout(() => {
      try { proc.kill('SIGTERM'); } catch { /* noop */ }
      // SIGTERM 後 close が来るかもだが、待たずにタイムアウト扱いで resolve
      settle('');
    }, AI_CALL_TIMEOUT_MS);
    proc.stdout.on('data', d => chunks.push(d));
    proc.on('error', () => settle(''));
    proc.on('close', () => settle(Buffer.concat(chunks).toString('utf8')));
  });
  return parseAiOutput(out);
}

export function parseAiOutput(raw: string): AiVerdict {
  const trimmed = raw.trim();
  if (!trimmed) {
    return { recommend: 'keep', reason: 'AI 応答が空でした。安全側 (keep) を推奨。', source: 'fallback' };
  }
  const lines = trimmed.split('\n').map(l => l.trim()).filter(l => l.length > 0);
  const head = lines[0] ?? '';
  const m = head.match(/^RECOMMEND:\s*(keep|archive)/i);
  if (!m) {
    return {
      recommend: 'keep',
      reason: `AI 応答のフォーマットが不正 ("${head.slice(0, 60)}...")。安全側 (keep) を推奨。`,
      source: 'fallback',
    };
  }
  const reason = lines.slice(1).join(' ').slice(0, 400) || '(理由なし)';
  return {
    recommend: m[1].toLowerCase() === 'archive' ? 'archive' : 'keep',
    reason,
    source: 'ai',
  };
}

/**
 * 対話式 orphan resolver の標準実装。
 * AI 推奨 + 理由を表示し、ユーザーに y/n/s で確認する。
 *
 * @param askFn  pipeline/prompt.ts の askQuestion を渡す
 */
export function createInteractiveOrphanResolver(askFn: AskFn): OrphanResolver {
  return {
    async resolveOrphan(orphan: OrphanOnX): Promise<OrphanResolution> {
      console.log(`\n⚠️  X 側で削除されたフォルダを検出: "${orphan.session.x_folder_name}"`);
      console.log(`   session_id: ${orphan.session.session_id}`);
      console.log(`   Vault: ${orphan.session.vault_path ?? '(不明)'}`);
      console.log(`   配下 .md: ${orphan.mdCount} 件 / 最新更新: ${orphan.latestPostDate ?? '(不明)'}`);

      const prompt = renderPrompt(orphan);
      console.log('🤖 AI 判定中...');
      const verdict = await callAiBackend(prompt);
      const tag = verdict.source === 'fallback' ? '(fallback)' : '';
      console.log(`   AI 推奨 ${tag}: ${verdict.recommend === 'archive' ? 'アーカイブ' : '保持'}`);
      console.log(`   理由: ${verdict.reason}`);

      const defaultLabel = verdict.recommend === 'archive' ? '[a]rchive 推奨' : '[k]eep 推奨';
      const ans = (await askFn(
        `操作を選択 (${defaultLabel}) [k=保持 / a=アーカイブ / s=スキップ次回再判定]: `
      )).trim().toLowerCase();
      if (ans === 'a' || ans === 'archive') return 'archive';
      if (ans === 's' || ans === 'skip') return 'skip';
      if (ans === 'k' || ans === 'keep') return 'keep';
      // 空入力 (= readline EOF / 非対話 / pipe 実行 / Enter のみ) は破壊的な
      // archive を勝手に走らせない。Codex review P1 の指摘通り、unattended な
      // run を想定して必ず "keep" にフォールバックする。
      // AI 推奨を尊重したいユーザーは明示的に 'a' を入力する必要がある。
      console.log('   明示入力なし: 安全側 "keep" を採用します。');
      return 'keep';
    },
  };
}

export const __test = {
  renderPrompt,
  parseAiOutput,
};
