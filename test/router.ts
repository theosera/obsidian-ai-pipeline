import assert from 'node:assert';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { setVaultRoot } from '../config';
import { getRoutedPath } from '../router';
import { TestRunner, type TestSuiteResult } from './helpers';

export function run(): TestSuiteResult {
  const runner = new TestRunner();
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-router-test-'));
  setVaultRoot(tmpDir);

  try {
    // =====================================================
    // 'none' ルール
    // =====================================================
    runner.section("getRoutedPath - 'none' rule");

    runner.test("ルール未定義 (none) はベースカテゴリがそのまま返る", () => {
      const result = getRoutedPath('Engineer/LLM', '2026-04-15', {});
      assert.strictEqual(result, 'Engineer' + path.sep + 'LLM');
    });

    runner.test("明示的に 'none' のルールはベースそのまま", () => {
      const result = getRoutedPath('Notes/Obsidian', '2026-04-15', {
        'Notes/Obsidian': 'none',
      });
      assert.strictEqual(result, 'Notes' + path.sep + 'Obsidian');
    });

    // =====================================================
    // 'monthly' ルール
    // =====================================================
    runner.section("getRoutedPath - 'monthly' rule");

    runner.test("'monthly' は YYYY-MM を追記", () => {
      const result = getRoutedPath('Engineer/LLM', '2026-04-15', {
        'Engineer/LLM': 'monthly',
      });
      assert.strictEqual(result, 'Engineer' + path.sep + 'LLM/2026-04');
    });

    runner.test("'monthly' で月は0パディングされる", () => {
      const result = getRoutedPath('Engineer/LLM', '2026-01-05', {
        'Engineer/LLM': 'monthly',
      });
      assert.strictEqual(result, 'Engineer' + path.sep + 'LLM/2026-01');
    });

    runner.test("'monthly' で12月", () => {
      const result = getRoutedPath('Engineer/LLM', '2026-12-31', {
        'Engineer/LLM': 'monthly',
      });
      assert.strictEqual(result, 'Engineer' + path.sep + 'LLM/2026-12');
    });

    // =====================================================
    // 'quarterly' ルール
    // =====================================================
    runner.section("getRoutedPath - 'quarterly' rule");

    runner.test("1月は Q1", () => {
      const result = getRoutedPath('Engineer/AWS', '2026-01-15', {
        'Engineer/AWS': 'quarterly',
      });
      assert.strictEqual(result, 'Engineer' + path.sep + 'AWS/2026-Q1');
    });

    runner.test("4月は Q2", () => {
      const result = getRoutedPath('Engineer/AWS', '2026-04-15', {
        'Engineer/AWS': 'quarterly',
      });
      assert.strictEqual(result, 'Engineer' + path.sep + 'AWS/2026-Q2');
    });

    runner.test("7月は Q3", () => {
      const result = getRoutedPath('Engineer/AWS', '2026-07-15', {
        'Engineer/AWS': 'quarterly',
      });
      assert.strictEqual(result, 'Engineer' + path.sep + 'AWS/2026-Q3');
    });

    runner.test("12月は Q4", () => {
      const result = getRoutedPath('Engineer/AWS', '2026-12-31', {
        'Engineer/AWS': 'quarterly',
      });
      assert.strictEqual(result, 'Engineer' + path.sep + 'AWS/2026-Q4');
    });

    // =====================================================
    // howto/how フォルダ例外
    // =====================================================
    runner.section('getRoutedPath - howto/how 例外');

    runner.test('howto を含むパスは quarterly ルールでも昇格しない', () => {
      const result = getRoutedPath(
        'Engineer/AGENT_assistant_VibeCoding/ClaudeCode/howto',
        '2026-04-15',
        { 'Engineer/AGENT_assistant_VibeCoding/ClaudeCode/howto': 'quarterly' }
      );
      assert.ok(
        !result.includes('2026-Q2'),
        'howto フォルダは日付フォルダが追加されてはいけない'
      );
    });

    runner.test('howto の途中パスも例外扱い', () => {
      const result = getRoutedPath(
        'Engineer/ClaudeCode/howto/HandsOn',
        '2026-04-15',
        { 'Engineer/ClaudeCode/howto/HandsOn': 'monthly' }
      );
      assert.ok(!result.includes('2026-04'));
    });

    runner.test('how 単体 (howtoではない) も例外扱い', () => {
      const result = getRoutedPath('Engineer/Tips/how', '2026-04-15', {
        'Engineer/Tips/how': 'monthly',
      });
      assert.ok(!result.includes('2026-04'));
    });

    // =====================================================
    // 日付ハンドリング
    // =====================================================
    runner.section('getRoutedPath - 日付ハンドリング');

    runner.test('publishDateStr が undefined でも落ちない', () => {
      const result = getRoutedPath('Engineer/LLM', undefined, {
        'Engineer/LLM': 'quarterly',
      });
      // 現在日から四半期が計算されるので、'Engineer/LLM/YYYY-Qn' 形式
      assert.match(result, /Engineer.LLM\/\d{4}-Q[1-4]$/);
    });

    // =====================================================
    // パストラバーサル防御の波及
    // =====================================================
    runner.section('getRoutedPath - パストラバーサル防御');

    runner.test('baseCategory に .. が入っていたら fallback に置換される', () => {
      const result = getRoutedPath('../../etc/passwd', '2026-04-15', {});
      // ensureSafePath でフォールバック先 Clippings/Inbox になる
      assert.strictEqual(result, 'Clippings/Inbox');
    });

    runner.test('絶対パスが入っていたら fallback に置換される', () => {
      const result = getRoutedPath('/etc/passwd', '2026-04-15', {});
      assert.strictEqual(result, 'Clippings/Inbox');
    });
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }

  return runner.report();
}
