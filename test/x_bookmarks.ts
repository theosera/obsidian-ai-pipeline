/**
 * X ブックマーク関連モジュールの統合単体テスト。
 * - x_folder_mapper: 強制親フォルダ・承認済みマッピング・共通キーワード検出
 * - x_bookmarks_db: in-memory SQLite で UPSERT / カウント
 * - x_bookmarks_scraper: tweet 変換 (DOM スクレイプは Playwright 必須なのでテスト外)
 */
import assert from 'node:assert';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { setVaultRoot } from '../config';
import {
  sanitizeFolderName,
  mapFolderToVaultPath,
  detectCommonKeywords,
  loadForcedParents,
  loadApprovedMappings,
  writeGroupingProposal,
} from '../x_folder_mapper';
import { XBookmarksDb } from '../x_bookmarks_db';
import { __test as scraperInternals } from '../x_bookmarks_scraper';
import { TestRunner, type TestSuiteResult } from './helpers';

export function run(): TestSuiteResult {
  const runner = new TestRunner();
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-xbm-test-'));
  setVaultRoot(tmpDir);

  try {
    // =====================================================
    // sanitizeFolderName
    // =====================================================
    runner.section('sanitizeFolderName');

    runner.test('空文字は _Unfiled', () => {
      assert.strictEqual(sanitizeFolderName(''), '_Unfiled');
    });

    runner.test('パスセパレータ / は - に置換', () => {
      assert.strictEqual(sanitizeFolderName('a/b\\c'), 'a-b-c');
    });

    runner.test('制御文字を除去', () => {
      assert.strictEqual(sanitizeFolderName('AI\x00Tools\n'), 'AITools');
    });

    runner.test('80字で切詰', () => {
      const long = 'a'.repeat(200);
      assert.strictEqual(sanitizeFolderName(long).length, 80);
    });

    runner.test('日本語はそのまま保持', () => {
      assert.strictEqual(sanitizeFolderName('AI関連'), 'AI関連');
    });

    // =====================================================
    // mapFolderToVaultPath - Tier 1 (強制親キーワード)
    // =====================================================
    runner.section('mapFolderToVaultPath - Tier 1 forced parents');

    runner.test('完全一致するキーワードは親フォルダ直下', () => {
      assert.strictEqual(
        mapFolderToVaultPath('Claude Code', ['Claude Code'], {}),
        'Claude Code'
      );
    });

    runner.test('キーワードを含むフォルダは "親/残り" に階層化', () => {
      assert.strictEqual(
        mapFolderToVaultPath('Claude Code Tips', ['Claude Code'], {}),
        'Claude Code/Tips'
      );
    });

    runner.test('複数のキーワードでも正しくマッチ', () => {
      assert.strictEqual(
        mapFolderToVaultPath('Obsidian Plugins', ['Claude Code', 'Obsidian'], {}),
        'Obsidian/Plugins'
      );
    });

    runner.test('部分一致は禁止 (AI は AIRI にマッチしない)', () => {
      assert.strictEqual(
        mapFolderToVaultPath('AIRI', ['AI'], {}),
        'AIRI'
      );
    });

    runner.test('単語境界マッチ (AI は "AI Agent" にはマッチ)', () => {
      assert.strictEqual(
        mapFolderToVaultPath('AI Agent', ['AI'], {}),
        'AI/Agent'
      );
    });

    runner.test('複数キーワード重複時は長いキーワード優先', () => {
      // "Claude Code Tips" は "Claude Code" と "Code" の両方にマッチし得るが、
      // 長い "Claude Code" が優先される。
      assert.strictEqual(
        mapFolderToVaultPath('Claude Code Tips', ['Claude Code', 'Code'], {}),
        'Claude Code/Tips'
      );
    });

    runner.test('日本語混在キーワード "MCP" は "MCP連携" にマッチ', () => {
      assert.strictEqual(
        mapFolderToVaultPath('MCP連携', ['MCP'], {}),
        'MCP/連携'
      );
    });

    runner.test('大小文字無視 (親はキーワード正規形・残りは入力ケース保持)', () => {
      // マッチング自体はケース非依存だが、親フォルダ名は forcedParents の正規形を使い、
      // 残りの部分は入力フォルダ名のケースをそのまま保持する。
      assert.strictEqual(
        mapFolderToVaultPath('claude code tips', ['Claude Code'], {}),
        'Claude Code/tips'
      );
    });

    // =====================================================
    // mapFolderToVaultPath - Tier 2 (承認済みマッピング)
    // =====================================================
    runner.section('mapFolderToVaultPath - Tier 2 approved mappings');

    runner.test('承認済みマッピングは完全一致で適用', () => {
      assert.strictEqual(
        mapFolderToVaultPath('Random Stuff', [], { 'Random Stuff': 'Misc/Random' }),
        'Misc/Random'
      );
    });

    runner.test('Tier 1 が優先 (強制親と承認マップ両方マッチでも強制親勝ち)', () => {
      assert.strictEqual(
        mapFolderToVaultPath('AI Tools', ['AI'], { 'AI Tools': 'Other/AITools' }),
        'AI/Tools'
      );
    });

    runner.test('未マッチはサニタイズ済み raw 名で返る', () => {
      assert.strictEqual(
        mapFolderToVaultPath('LangChain', [], {}),
        'LangChain'
      );
    });

    runner.test('空フォルダ名は _Unfiled', () => {
      assert.strictEqual(mapFolderToVaultPath('', [], {}), '_Unfiled');
    });

    // =====================================================
    // detectCommonKeywords
    // =====================================================
    runner.section('detectCommonKeywords');

    runner.test('3 フォルダ未満のキーワードは提案しない', () => {
      const proposals = detectCommonKeywords(['AI Tools', 'AI Ethics'], []);
      assert.strictEqual(proposals.find(p => p.keyword.toLowerCase() === 'ai'), undefined);
    });

    runner.test('3 フォルダ以上の共通キーワードを検出', () => {
      const proposals = detectCommonKeywords(
        ['AI Tools', 'AI Ethics', 'AI Agents', 'LangChain'],
        []
      );
      const ai = proposals.find(p => p.keyword.toLowerCase() === 'ai');
      assert.ok(ai, 'AI が検出されるべき');
      assert.strictEqual(ai!.folders.length, 3);
    });

    runner.test('強制親で吸収済みのフォルダは提案対象外', () => {
      const proposals = detectCommonKeywords(
        ['AI Tools', 'AI Ethics', 'AI Agents', 'LangChain'],
        ['AI']
      );
      assert.strictEqual(proposals.find(p => p.keyword.toLowerCase() === 'ai'), undefined);
    });

    runner.test('ストップワードは除外', () => {
      const proposals = detectCommonKeywords(
        ['the cat', 'the dog', 'the bird', 'the fish'],
        []
      );
      assert.strictEqual(proposals.find(p => p.keyword.toLowerCase() === 'the'), undefined);
    });

    runner.test('提案は出現フォルダ数の多い順', () => {
      const proposals = detectCommonKeywords(
        ['AI Tools', 'AI Ethics', 'AI Agents', 'AI Safety', 'LLM Tools', 'LLM Models', 'LLM Eval'],
        []
      );
      assert.ok(proposals.length >= 2);
      assert.ok(proposals[0].folders.length >= proposals[1].folders.length);
    });

    // =====================================================
    // loadForcedParents / loadApprovedMappings (空ファイル)
    // =====================================================
    runner.section('loadForcedParents / loadApprovedMappings (file IO)');

    runner.test('未存在ファイルでは空配列/空オブジェクトを返す', () => {
      assert.deepStrictEqual(loadForcedParents(), []);
      assert.deepStrictEqual(loadApprovedMappings(), {});
    });

    runner.test('正常な x_forced_parents.json を読み込む', () => {
      const dir = path.join(tmpDir, '__skills', 'pipeline');
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(
        path.join(dir, 'x_forced_parents.json'),
        JSON.stringify(['Claude Code', 'Obsidian', '']),
        'utf8'
      );
      const loaded = loadForcedParents();
      // 空文字は除外される
      assert.deepStrictEqual(loaded, ['Claude Code', 'Obsidian']);
    });

    runner.test('壊れた JSON では空配列を返す (例外を投げない)', () => {
      const dir = path.join(tmpDir, '__skills', 'pipeline');
      fs.writeFileSync(path.join(dir, 'x_forced_parents.json'), 'not json {{', 'utf8');
      assert.deepStrictEqual(loadForcedParents(), []);
    });

    runner.test('writeGroupingProposal は空配列なら何もしない', () => {
      const result = writeGroupingProposal([]);
      assert.strictEqual(result, '');
    });

    runner.test('writeGroupingProposal は提案を analysis 配下に書く', () => {
      const result = writeGroupingProposal([
        { keyword: 'AI', folders: ['AI Tools', 'AI Ethics', 'AI Agents'] },
      ]);
      assert.ok(result.endsWith('.md'));
      assert.ok(fs.existsSync(result));
      const content = fs.readFileSync(result, 'utf8');
      assert.ok(content.includes('AI'));
      assert.ok(content.includes('AI Tools'));
    });

    // =====================================================
    // XBookmarksDb (in-memory)
    // =====================================================
    runner.section('XBookmarksDb (in-memory)');

    runner.test('空 DB では getKnownTweetIds が空 Set', () => {
      const db = new XBookmarksDb(':memory:');
      assert.strictEqual(db.getKnownTweetIds().size, 0);
      db.close();
    });

    runner.test('upsertBookmark → getKnownTweetIds で取り出せる', () => {
      const db = new XBookmarksDb(':memory:');
      db.upsertBookmark({
        tweetId: '12345',
        url: 'https://x.com/foo/status/12345',
        author: 'foo',
        tweetText: 'hello',
        xFolderName: 'Claude Code/Tips',
      });
      const ids = db.getKnownTweetIds();
      assert.strictEqual(ids.size, 1);
      assert.ok(ids.has('12345'));
      db.close();
    });

    runner.test('同一 tweet_id の UPSERT は重複行を作らない', () => {
      const db = new XBookmarksDb(':memory:');
      db.upsertBookmark({ tweetId: 'a', url: 'https://x.com/a/status/a' });
      db.upsertBookmark({ tweetId: 'a', url: 'https://x.com/a/status/a', author: 'updated' });
      assert.strictEqual(db.count(), 1);
      db.close();
    });

    runner.test('getFolderCounts はフォルダ別件数を返す', () => {
      const db = new XBookmarksDb(':memory:');
      db.upsertBookmark({ tweetId: '1', url: 'https://x.com/a/status/1', xFolderName: 'AI' });
      db.upsertBookmark({ tweetId: '2', url: 'https://x.com/a/status/2', xFolderName: 'AI' });
      db.upsertBookmark({ tweetId: '3', url: 'https://x.com/a/status/3', xFolderName: 'MCP' });
      const counts = db.getFolderCounts();
      const ai = counts.find(c => c.folder === 'AI');
      const mcp = counts.find(c => c.folder === 'MCP');
      assert.strictEqual(ai?.count, 2);
      assert.strictEqual(mcp?.count, 1);
      db.close();
    });

    // =====================================================
    // x_bookmarks_scraper: rawToScrapedBookmark (DOM 部はテスト外)
    // =====================================================
    runner.section('x_bookmarks_scraper: rawToScrapedBookmark');

    runner.test('RawTweet を ScrapedBookmark に変換', () => {
      const raw = {
        tweetId: '999',
        url: 'https://x.com/foo/status/999',
        authorHandle: 'foo',
        authorDisplayName: 'Foo Bar',
        text: 'これはテスト投稿です',
        createdAt: '2026-04-19T10:00:00.000Z',
        likeCount: 42,
        retweetCount: 5,
        replyCount: 3,
        expandedUrls: ['https://example.com'],
      };
      const sb = scraperInternals.rawToScrapedBookmark(raw, 'Claude Code/Tips');
      assert.strictEqual(sb.xTweetId, '999');
      assert.strictEqual(sb.xFolderName, 'Claude Code/Tips');
      assert.strictEqual(sb.url, 'https://x.com/foo/status/999');
      assert.strictEqual(sb.date, '2026-04-19');
      assert.ok(sb.title?.includes('Foo Bar'));
      assert.ok(sb.title?.includes('@foo'));
      assert.ok(sb.content?.includes('> これはテスト投稿です'));
      assert.ok(sb.content?.includes('https://example.com'));
      assert.ok(sb.content?.includes('❤️ 42'));
    });

    runner.test('createdAt が null でも date は undefined で安全', () => {
      const raw = {
        tweetId: '1',
        url: 'https://x.com/a/status/1',
        authorHandle: 'a',
        authorDisplayName: 'A',
        text: 'x',
        createdAt: null,
        likeCount: null,
        retweetCount: null,
        replyCount: null,
        expandedUrls: [],
      };
      const sb = scraperInternals.rawToScrapedBookmark(raw, 'Misc');
      assert.strictEqual(sb.date, undefined);
      // メトリクス全 null なら エンゲージメントセクションは含まれない
      assert.ok(!sb.content?.includes('エンゲージメント'));
    });

    return runner.report();
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}
