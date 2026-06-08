/**
 * `--agent="<task>"` の CLI エントリ。
 *
 * index.ts (dispatch 専任) から Anthropic クライアント構築・承認ゲート配線・結果表示を
 * 切り出した薄いアダプタ。Tool Use は Anthropic ネイティブ tool use を使うため
 * ANTHROPIC_API_KEY を要求する (未設定なら明示エラー)。
 */
import Anthropic from '@anthropic-ai/sdk';
import type { PipelineConfig } from '../types';
import { runToolUseAgent } from './agent';
import { createTerminalApprovalGate } from './approval';

export async function runAgentCli(opts: {
  task: string;
  config: PipelineConfig;
  ask: (question: string) => Promise<string>;
}): Promise<void> {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    throw new Error(
      'Tool Use エージェントは Anthropic ネイティブ tool use を使用します。' +
      'ANTHROPIC_API_KEY を環境変数に設定してください。'
    );
  }

  const anthropic = new Anthropic({ apiKey });
  // tool use は anthropic 経路で実行。provider=anthropic ならその smartModel を、
  // それ以外の provider 設定でも tool 対応モデルへフォールバックする。
  const model = opts.config.provider === 'anthropic' ? opts.config.smartModel : 'claude-sonnet-4-6';

  console.log('\n🤖 Tool Use エージェント (Vault サンドボックス / 各操作に人間承認)');
  console.log(`   model: ${model}`);
  console.log(`   task : ${opts.task}\n`);

  const result = await runToolUseAgent(opts.task, {
    client: { create: (body) => anthropic.messages.create(body) },
    approve: createTerminalApprovalGate(opts.ask),
    model,
  });

  console.log('\n========== エージェント結果 ==========');
  console.log(`停止理由: ${result.stoppedReason} / ターン: ${result.turns}`);
  console.log(`ツール呼び出し: ${result.toolCalls.length} 件`);
  for (const call of result.toolCalls) {
    const mark = call.ok ? '✅' : call.approved ? '⚠️' : '⛔';
    console.log(`  ${mark} ${call.name} — ${call.detail}`);
  }
  console.log('\n--- 最終応答 ---');
  console.log(result.finalText || '(テキスト応答なし)');
}
