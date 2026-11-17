/**
 * OpenAI の推論の指定 (`openai_params.ts`) のテスト。
 *
 * 重点:
 *   - `reasoning_effort: 'none'` は確かめた 2 つのモデルだけに付ける
 *   - 保存済みの設定や env で来うる別のモデル (gpt-4o 系・none を受けないモデル・似た名前) には付けない
 */
import assert from 'node:assert';
import { supportsNoReasoning, noReasoningFor } from '../openai_params';
import { TestRunner, type TestSuiteResult } from './helpers';

export function run(): TestSuiteResult {
  const runner = new TestRunner();

  runner.section('reasoning_effort none (確かめたモデルだけに付ける)');

  runner.test('gpt-6-luna と gpt-6.1-terra は none を付ける', () => {
    for (const model of ['gpt-6-luna', 'gpt-6.1-terra']) {
      assert.strictEqual(supportsNoReasoning(model), true, model);
    }
  });

  runner.test('旧い既定・none を受けないモデル・似た名前・他社には付けない', () => {
    for (const model of ['gpt-4o', 'gpt-4o-mini', 'gpt-6.1-sol', 'gpt-6-luna-x', 'gpt-6.1-terra-pro', 'xgpt-6-luna', 'gemini-2.5-flash', 'local-model']) {
      assert.strictEqual(supportsNoReasoning(model), false, model);
    }
  });

  runner.test('noReasoningFor は対応モデルにだけ reasoning_effort を返す', () => {
    assert.deepStrictEqual(noReasoningFor('gpt-6-luna'), { reasoning_effort: 'none' });
    assert.deepStrictEqual(noReasoningFor('gpt-4o-mini'), {});
  });

  return runner.report();
}
