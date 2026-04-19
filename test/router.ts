import assert from 'node:assert';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { setVaultRoot } from '../config';
import { getRoutedPath, stripDateSuffix } from '../router';
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
      const base = 'Engineer/AGENT_assistant_VibeCoding/ClaudeCode/howto';
      const result = getRoutedPath(base, '2026-04-15', { [base]: 'quarterly' });
      // ensureSafePath 経由で path.sep 区切りに正規化された形で完全一致する
      const expected = base.split('/').join(path.sep);
      assert.strictEqual(result, expected);
    });

    runner.test('howto の途中パスも例外扱い', () => {
      const base = 'Engineer/ClaudeCode/howto/HandsOn';
      const result = getRoutedPath(base, '2026-04-15', { [base]: 'monthly' });
      const expected = base.split('/').join(path.sep);
      assert.strictEqual(result, expected);
    });

    runner.test('how 単体 (howtoではない) も例外扱い', () => {
      const base = 'Engineer/Tips/how';
      const result = getRoutedPath(base, '2026-04-15', { [base]: 'monthly' });
      const expected = base.split('/').join(path.sep);
      assert.strictEqual(result, expected);
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
      // path separator を正確にマッチさせる (. を使わない)
      assert.match(result, /^Engineer[\\/]LLM[\\/]\d{4}-Q[1-4]$/);
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

    // =====================================================
    // stripDateSuffix - 新規フォルダ提案スコープ判定用
    // =====================================================
    runner.section('stripDateSuffix - date suffix detection');

    runner.test('/YYYY-Qn を剥がせる', () => {
      assert.strictEqual(stripDateSuffix('Engineer/DDD/2026-Q2'), 'Engineer/DDD');
    });

    runner.test('/YYYY-MM を剥がせる', () => {
      assert.strictEqual(stripDateSuffix('Engineer/AGENT/2026-04'), 'Engineer/AGENT');
    });

    runner.test('Q1〜Q4 すべて検出される', () => {
      for (const q of ['Q1', 'Q2', 'Q3', 'Q4']) {
        assert.strictEqual(
          stripDateSuffix(`Engineer/AWS/2026-${q}`),
          'Engineer/AWS',
          `quarter ${q} not stripped`
        );
      }
    });

    runner.test('01〜12 月すべて検出される', () => {
      for (const m of ['01', '02', '06', '09', '11', '12']) {
        assert.strictEqual(
          stripDateSuffix(`Engineer/AWS/2026-${m}`),
          'Engineer/AWS',
          `month ${m} not stripped`
        );
      }
    });

    runner.test('日付 suffix がなければそのまま返す', () => {
      assert.strictEqual(stripDateSuffix('Engineer/DDD'), 'Engineer/DDD');
      assert.strictEqual(stripDateSuffix('Notes/Obsidian_ツール&活用'), 'Notes/Obsidian_ツール&活用');
    });

    runner.test('Q5以上や月13以上は剥がさない (誤検出防止)', () => {
      // 仕様上 Q1-Q9 を許容しているので Q5 は剥がれる
      assert.strictEqual(stripDateSuffix('Foo/2026-Q5'), 'Foo');
      // 13月は不正なので剥がさない
      assert.strictEqual(stripDateSuffix('Foo/2026-13'), 'Foo/2026-13');
      // 00月も不正
      assert.strictEqual(stripDateSuffix('Foo/2026-00'), 'Foo/2026-00');
    });

    runner.test('深い階層の末尾日付も剥がせる', () => {
      assert.strictEqual(
        stripDateSuffix('Engineer/AGENT_assistant_VibeCoding/ClaudeCode/2026-04'),
        'Engineer/AGENT_assistant_VibeCoding/ClaudeCode'
      );
    });

    runner.test('ベースカテゴリ自体が日付っぽい名前でも誤動作しない', () => {
      // パスの末尾セグメントが /YYYY-Qn パターンでない限り剥がさない
      assert.strictEqual(stripDateSuffix('Logs/2026'), 'Logs/2026');
    });
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }

  return runner.report();
}
