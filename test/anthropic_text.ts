/**
 * Claude 5 系の応答の読み方 (`anthropic_text.ts`) のテスト。
 *
 * 重点:
 *   - 応答の頭に thinking ブロックが来ても、text ブロックを type で読んで答えを取る
 *     (`content[0]` を答えとして読む旧い形に戻すと落ちる = 逆の確かめの対象)
 *   - refusal は content より先に判定する
 *   - thinking だけで max_tokens に達した応答は「答えなし」と分かる
 *   - effort は Claude 5 系だけに付ける (Claude Haiku 4.5 等に送ると 400)
 */
import assert from 'node:assert';
import type Anthropic from '@anthropic-ai/sdk';
import { readAnthropicText, supportsEffort, lowEffortFor } from '../anthropic_text';
import { TestRunner, type TestSuiteResult } from './helpers';

type Reply = Pick<Anthropic.Message, 'content' | 'stop_reason'>;

// --- Anthropic.Message の content の最小モック (unknown キャストで必要な欄だけ用意) ---
function reply(content: unknown[], stopReason: Anthropic.StopReason | null): Reply {
  return { content, stop_reason: stopReason } as unknown as Reply;
}
const thinkingBlock = { type: 'thinking', thinking: '', signature: 'sig-1' };
const textBlock = (text: string) => ({ type: 'text', text, citations: null });

export function run(): TestSuiteResult {
  const runner = new TestRunner();

  runner.section('readAnthropicText');

  runner.test('thinking が先に来ても text ブロックを答えとして読む', () => {
    const result = readAnthropicText(reply([thinkingBlock, textBlock('{"proposedPath":"AI/LLM"}')], 'end_turn'));
    assert.deepStrictEqual(result, { ok: true, text: '{"proposedPath":"AI/LLM"}' });
  });

  runner.test('text だけの応答 (Claude 4 系の形) も読める・前後の空白は落とす', () => {
    const result = readAnthropicText(reply([textBlock('  要約です。\n')], 'end_turn'));
    assert.deepStrictEqual(result, { ok: true, text: '要約です。' });
  });

  runner.test('text ブロックが複数なら順に繋げる (間に字を足さない)', () => {
    const result = readAnthropicText(reply([thinkingBlock, textBlock('{"a":'), textBlock('1}')], 'end_turn'));
    assert.deepStrictEqual(result, { ok: true, text: '{"a":1}' });
  });

  runner.test('refusal は content より先に判定する (text が在っても答えにしない)', () => {
    const result = readAnthropicText(reply([textBlock('partial')], 'refusal'));
    assert.deepStrictEqual(result, { ok: false, reason: 'refusal', stopReason: 'refusal' });
  });

  runner.test('thinking だけで max_tokens に達したら no_text', () => {
    const result = readAnthropicText(reply([thinkingBlock], 'max_tokens'));
    assert.deepStrictEqual(result, { ok: false, reason: 'no_text', stopReason: 'max_tokens' });
  });

  runner.test('空白だけの text は no_text', () => {
    const result = readAnthropicText(reply([thinkingBlock, textBlock('   ')], 'end_turn'));
    assert.deepStrictEqual(result, { ok: false, reason: 'no_text', stopReason: 'end_turn' });
  });

  runner.section('effort (Claude 5 系だけに付ける)');

  runner.test('Claude 5 系は effort を受け付ける', () => {
    for (const model of ['claude-sonnet-5-5', 'claude-haiku-5-5', 'claude-opus-5-5', 'claude-sonnet-5']) {
      assert.strictEqual(supportsEffort(model), true, model);
    }
  });

  runner.test('Claude 4 系・退役モデル・ローカル・似た名前には付けない', () => {
    for (const model of ['claude-haiku-4-5-20251001', 'claude-sonnet-4-6', 'claude-3-7-sonnet-20250219', 'local-model', 'claude-sonnet-50']) {
      assert.strictEqual(supportsEffort(model), false, model);
    }
  });

  runner.test('lowEffortFor は対応モデルにだけ output_config を返す', () => {
    assert.deepStrictEqual(lowEffortFor('claude-haiku-5-5'), { output_config: { effort: 'low' } });
    assert.deepStrictEqual(lowEffortFor('claude-haiku-4-5-20251001'), {});
  });

  return runner.report();
}
