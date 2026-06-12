import assert from 'node:assert';
import { evaluatePolicy } from '../pipeline/policy';
import { TestRunner, type TestSuiteResult } from './helpers';

/**
 * evaluatePolicy のサイトポリシー判定テスト。
 * OneTab 取り込みで「どの URL を取り込まない (manual_skip) か」を回帰防止で固定する。
 * とくに YouTube は動画で技術記事化しないため、通常 URL・短縮 URL (youtu.be)・
 * サブドメインのいずれも manual_skip になることを保証する。
 */
export function run(): TestSuiteResult {
  const runner = new TestRunner();

  runner.section('evaluatePolicy - YouTube は取り込まない (manual_skip)');

  runner.test('youtube.com (watch URL) は manual_skip', () => {
    assert.strictEqual(evaluatePolicy('https://www.youtube.com/watch?v=abc123'), 'manual_skip');
  });

  runner.test('youtu.be 短縮 URL も manual_skip', () => {
    assert.strictEqual(evaluatePolicy('https://youtu.be/abc123'), 'manual_skip');
  });

  runner.test('m.youtube.com / music.youtube.com などサブドメインも manual_skip', () => {
    assert.strictEqual(evaluatePolicy('https://m.youtube.com/watch?v=abc'), 'manual_skip');
    assert.strictEqual(evaluatePolicy('https://music.youtube.com/watch?v=abc'), 'manual_skip');
  });

  runner.test('youtu.be ルールは別ホスト (notyoutu.be) に誤マッチしない', () => {
    assert.strictEqual(evaluatePolicy('https://notyoutu.be/article'), 'public_auto');
  });

  runner.section('evaluatePolicy - その他カテゴリ');

  runner.test('x.com は manual_skip', () => {
    assert.strictEqual(evaluatePolicy('https://x.com/user/status/1'), 'manual_skip');
  });

  runner.test('x.com ルールは netflix.com に誤マッチしない (旧 includes バグの回帰防止)', () => {
    assert.strictEqual(evaluatePolicy('https://www.netflix.com/title/123'), 'public_auto');
  });

  runner.test('note.com は public_review', () => {
    assert.strictEqual(evaluatePolicy('https://note.com/someone/n/abc'), 'public_review');
  });

  runner.test('通常の技術ブログは public_auto', () => {
    assert.strictEqual(evaluatePolicy('https://example.com/blog/post'), 'public_auto');
  });

  return runner.report();
}
