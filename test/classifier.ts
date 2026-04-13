import assert from 'node:assert';
import { ruleBasedClassify, getBestMatch } from '../classifier';
import { TestRunner, type TestSuiteResult } from './helpers';

/**
 * Note: ruleBasedClassify は「個人フォルダ分類ルール」という性質上、
 * 具体的なキーワード→フォルダのマッピングは頻繁に変わる設定データに相当する。
 * ここでは個別マッピングを網羅せず、**構造的な振る舞い (structural behavior)** のみ固定する:
 *   - 除外ロジック (ドメイン / タイトルベース)
 *   - isHowTo サブフォルダ振り分け
 *   - isCloudNews 例外
 *   - 代表キーワード1件 (regression smoke)
 *   - 大文字小文字非依存
 *   - マッチしない入力のフォールバック (null)
 *   - undefined 安全性
 */
export function run(): TestSuiteResult {
  const runner = new TestRunner();

  // =====================================================
  // ruleBasedClassify: structural behavior
  // =====================================================
  runner.section('ruleBasedClassify - 除外ロジック');

  runner.test('ドメインベース除外: speakerdeck.com', () => {
    assert.strictEqual(
      ruleBasedClassify('https://speakerdeck.com/user/presentation', 'Any Title'),
      '__EXCLUDED__'
    );
  });

  runner.test('タイトルベース除外: "05_知的生産ワークフローObsidian"', () => {
    assert.strictEqual(
      ruleBasedClassify('https://example.com', '05_知的生産ワークフローObsidian の使い方'),
      '__EXCLUDED__'
    );
  });

  runner.section('ruleBasedClassify - 構造的振る舞い');

  runner.test('代表キーワード (MCP): base folder が返る', () => {
    // ruleBasedClassify が動作していることの smoke test。
    // 個別マッピングの詳細はテストしない (設定データに相当するため)。
    assert.strictEqual(
      ruleBasedClassify(undefined, 'MCP サーバーの構築'),
      'Engineer/AGENT_assistant_AgenticEngineering/MCP'
    );
  });

  runner.test('大文字小文字非依存で動作する', () => {
    // URL/title は小文字化されて評価されることの確認
    assert.strictEqual(
      ruleBasedClassify('https://example.com/MCP/spec', 'Spec'),
      'Engineer/AGENT_assistant_AgenticEngineering/MCP'
    );
  });

  runner.test('isHowTo 判定で howto サブフォルダに振られる', () => {
    // '使い方' / '入門' / 'チュートリアル' 等を含むと howto 配下に振られる構造を確認
    const result = ruleBasedClassify(undefined, 'Claude Code 使い方ガイド');
    assert.ok(result !== null, 'マッチしていない');
    assert.ok(
      result!.endsWith('/howto'),
      `howto サブフォルダに振られていない: ${result}`
    );
  });

  runner.test('isCloudNews 例外: クラウドニュースはマッチしない', () => {
    // 'ニュース' / '発表' / 'リリース' を含むクラウド系記事は
    // 分類対象外として null に落ちる構造を確認
    assert.strictEqual(
      ruleBasedClassify(undefined, 'AWS 新機能のニュース'),
      null
    );
  });

  runner.test('マッチしない入力は null を返す', () => {
    assert.strictEqual(
      ruleBasedClassify('https://example.com', '完全に無関係な内容'),
      null
    );
  });

  runner.test('undefined 入力を安全に処理する', () => {
    assert.strictEqual(ruleBasedClassify(undefined, undefined), null);
  });

  // =====================================================
  // getBestMatch: 曖昧一致アルゴリズム
  // =====================================================
  runner.section('getBestMatch - fuzzy matching');

  runner.test('完全一致はそのまま返る', () => {
    const folders = ['Engineer/LLM', 'Engineer/AWS', 'Notes/Obsidian'];
    assert.strictEqual(getBestMatch('Engineer/LLM', folders), 'Engineer/LLM');
  });

  runner.test('空の folder リストでは入力をそのまま返す', () => {
    assert.strictEqual(getBestMatch('Engineer/LLM', []), 'Engineer/LLM');
  });

  runner.test('閾値を超える類似度なら補正される', () => {
    const folders = ['Engineer/AGENT_assistant_VibeCoding/ClaudeCode'];
    const result = getBestMatch(
      'Engineer/AGENT_assistant_VibeCoding/ClaudeCod',
      folders
    );
    assert.strictEqual(result, 'Engineer/AGENT_assistant_VibeCoding/ClaudeCode');
  });

  runner.test('閾値未満の類似度では入力がそのまま返る', () => {
    const folders = ['Foo/Bar/Baz', 'Qux/Quux/Corge'];
    const result = getBestMatch('TotallyUnrelated', folders);
    assert.strictEqual(result, 'TotallyUnrelated');
  });

  return runner.report();
}
