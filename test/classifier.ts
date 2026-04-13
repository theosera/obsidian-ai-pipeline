import assert from 'node:assert';
import { ruleBasedClassify, getBestMatch } from '../classifier';
import { TestRunner, type TestSuiteResult } from './helpers';

export function run(): TestSuiteResult {
  const runner = new TestRunner();

  // =====================================================
  // ruleBasedClassify: 除外ドメイン・タイトル
  // =====================================================
  runner.section('ruleBasedClassify - 除外ルール');

  runner.test('speakerdeck.com URL は __EXCLUDED__', () => {
    assert.strictEqual(
      ruleBasedClassify('https://speakerdeck.com/user/presentation', 'My Deck'),
      '__EXCLUDED__'
    );
  });

  runner.test('docswell.com URL は __EXCLUDED__', () => {
    assert.strictEqual(
      ruleBasedClassify('https://docswell.com/s/x/slides', 'something'),
      '__EXCLUDED__'
    );
  });

  runner.test('"05_知的生産ワークフローObsidian" タイトルは __EXCLUDED__', () => {
    assert.strictEqual(
      ruleBasedClassify('https://example.com', '05_知的生産ワークフローObsidian の使い方'),
      '__EXCLUDED__'
    );
  });

  // =====================================================
  // ruleBasedClassify: LLM 生存戦略系
  // =====================================================
  runner.section('ruleBasedClassify - LLM生存戦略');

  runner.test('「エンジニアとして」は AI時代の働き方', () => {
    assert.strictEqual(
      ruleBasedClassify(undefined, 'エンジニアとして生き残る'),
      '_LLMによる生存戦略/AI時代の働き方'
    );
  });

  runner.test('「生存戦略」は AI時代の働き方', () => {
    assert.strictEqual(
      ruleBasedClassify(undefined, 'AI時代の生存戦略'),
      '_LLMによる生存戦略/AI時代の働き方'
    );
  });

  runner.test('「ガバナンス」は AIガバナンス_リスク管理', () => {
    assert.strictEqual(
      ruleBasedClassify(undefined, 'AIガバナンスの全体像'),
      '_LLMによる生存戦略/AIガバナンス_リスク管理'
    );
  });

  // =====================================================
  // ruleBasedClassify: AGENT 経済圏
  // =====================================================
  runner.section('ruleBasedClassify - AGENT経済圏');

  runner.test('「エージェント経済」は AGENT経済圏', () => {
    assert.strictEqual(
      ruleBasedClassify(undefined, 'エージェント経済圏の台頭'),
      'AGENT経済圏'
    );
  });

  runner.test('「swarm」は AGENT経済圏', () => {
    assert.strictEqual(
      ruleBasedClassify(undefined, 'OpenAI Swarm を試す'),
      'AGENT経済圏'
    );
  });

  // =====================================================
  // ruleBasedClassify: Agentic Engineering
  // =====================================================
  runner.section('ruleBasedClassify - Agentic Engineering');

  runner.test('MCP キーワードは MCP 配下', () => {
    assert.strictEqual(
      ruleBasedClassify(undefined, 'MCP サーバーの構築'),
      'Engineer/AGENT_assistant_AgenticEngineering/MCP'
    );
  });

  runner.test('mcp URL も MCP 配下 (case insensitive)', () => {
    assert.strictEqual(
      ruleBasedClassify('https://example.com/mcp/spec', 'Spec'),
      'Engineer/AGENT_assistant_AgenticEngineering/MCP'
    );
  });

  runner.test('harness キーワードは HarnessEngineering', () => {
    assert.strictEqual(
      ruleBasedClassify(undefined, 'Agent harness design patterns'),
      'Engineer/AGENT_assistant_AgenticEngineering/HarnessEngineering'
    );
  });

  runner.test('「マルチエージェント」は Agentic Engineering ベース', () => {
    assert.strictEqual(
      ruleBasedClassify(undefined, 'マルチエージェント協調'),
      'Engineer/AGENT_assistant_AgenticEngineering'
    );
  });

  // =====================================================
  // ruleBasedClassify: Vibe Coding
  // =====================================================
  runner.section('ruleBasedClassify - Vibe Coding');

  runner.test('「Claude Code」は ClaudeCode 配下', () => {
    assert.strictEqual(
      ruleBasedClassify(undefined, 'Claude Code の新機能'),
      'Engineer/AGENT_assistant_VibeCoding/ClaudeCode'
    );
  });

  runner.test('「Claude Code Hooks」は Hooks 特殊ディレクトリへ', () => {
    assert.strictEqual(
      ruleBasedClassify(undefined, 'Claude Code Hooks 入門'),
      'Engineer/AGENT_assistant_AgenticEngineering/_AIエージェント要件定義/ClaudeCode/Hooks'
    );
  });

  runner.test('「Claude Code Skills」は Agent_Skills 配下', () => {
    assert.strictEqual(
      ruleBasedClassify(undefined, 'Claude Code Skills を作る'),
      'Engineer/AGENT_assistant_AgenticEngineering/_AIエージェント要件定義/Agent_Skills/ClaudeCode'
    );
  });

  runner.test('「Claude Code 使い方」は howto に振り分け', () => {
    assert.strictEqual(
      ruleBasedClassify(undefined, 'Claude Code 使い方ガイド'),
      'Engineer/AGENT_assistant_VibeCoding/ClaudeCode/howto'
    );
  });

  runner.test('「Antigravity 入門」は howto に振り分け', () => {
    assert.strictEqual(
      ruleBasedClassify(undefined, 'Google Antigravity 入門チュートリアル'),
      'Engineer/AGENT_assistant_VibeCoding/Google Antigravity/howto'
    );
  });

  runner.test('「Codex」(not how-to) は CodexCLI ベース', () => {
    assert.strictEqual(
      ruleBasedClassify(undefined, 'Codex CLI の設計思想'),
      'Engineer/AGENT_assistant_VibeCoding/CodexCLI'
    );
  });

  // =====================================================
  // ruleBasedClassify: その他のカテゴリ
  // =====================================================
  runner.section('ruleBasedClassify - その他カテゴリ');

  runner.test('「ローカルLLM」は OSS_SLM', () => {
    assert.strictEqual(
      ruleBasedClassify(undefined, 'ローカルLLM 量子化のテクニック'),
      '_LLM/_LLM-OSS_SLM'
    );
  });

  runner.test('「RAG」は RAG 特殊ディレクトリへ', () => {
    assert.strictEqual(
      ruleBasedClassify(undefined, 'RAG システムの構築'),
      '_LLM/_LLM-OSS_SLM/RAG_LLM_LangChain/RAG'
    );
  });

  runner.test('「AWS」(ニュースでない) は AWS', () => {
    // 注: "RAG" を含むと先に RAG ルールにマッチするため除外
    assert.strictEqual(
      ruleBasedClassify(undefined, 'AWS Bedrock の実装パターン'),
      'AWS'
    );
  });

  runner.test('「AWS のニュース」はマッチしない (null)', () => {
    // isCloudNews で除外される想定
    assert.strictEqual(
      ruleBasedClassify(undefined, 'AWS 新機能のニュース'),
      null
    );
  });

  runner.test('「Obsidian」は Obsidian ツール&活用', () => {
    assert.strictEqual(
      ruleBasedClassify(undefined, 'Obsidian ノートテクニック'),
      'Notes/Obsidian_ツール&活用'
    );
  });

  runner.test('マッチしない入力は null', () => {
    assert.strictEqual(
      ruleBasedClassify('https://example.com', '完全に無関係な内容'),
      null
    );
  });

  runner.test('undefined 入力も安全に処理される', () => {
    assert.strictEqual(ruleBasedClassify(undefined, undefined), null);
  });

  // =====================================================
  // getBestMatch: 曖昧一致
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
    // 非常に近いが微妙にタイポした入力
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
