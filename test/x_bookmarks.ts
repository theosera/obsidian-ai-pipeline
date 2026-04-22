/**
 * X ブックマーク関連モジュールの統合単体テスト。
 * - x_folder_mapper: 強制親フォルダ・承認済みマッピング・共通キーワード検出
 * - x_bookmarks_db:  in-memory SQLite で UPSERT / カウント
 * - x_bookmarks_api: tweet→ApiBookmark 変換 / トークン期限判定 / URL 組立
 * - x_auth_server:   PKCE code_challenge / 認可URL組立
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
import { __test as apiInternals } from '../x_bookmarks_api';
import { __test as authInternals } from '../x_auth_server';
import {
  expandedExternalLinks,
  buildBookmarkMarkdown,
} from '../packages/core/src/markdown/markdown-builder.js';
import type { XPost } from '../packages/core/src/types/shared.js';
import {
  loadForcedParents as loadCodexForcedParents,
  resolveForcedParent,
  hasWordBoundaryMatch,
} from '../packages/core/src/x-folder-grouping/forced-parents.js';
import { resolveXBookmarkSaveDirectory } from '../packages/core/src/path/x-bookmark-path-resolver.js';
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

    runner.test('writeGroupingProposal のファイル名は claude_ prefix を持つ (対照実験)', () => {
      const result = writeGroupingProposal([
        { keyword: 'X', folders: ['X Tools', 'X Ethics', 'X Agents'] },
      ]);
      assert.ok(
        path.basename(result).startsWith('x_folder_grouping_proposal_claude_'),
        `想定 prefix と不一致: ${path.basename(result)}`
      );
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
    // x_bookmarks_api: tweetToApiBookmark
    // =====================================================
    runner.section('x_bookmarks_api: tweetToApiBookmark');

    runner.test('XPost を ApiBookmark に変換 (基本)', () => {
      const post = {
        id: '999',
        text: 'これはテスト投稿です',
        author_id: 'u1',
        created_at: '2026-04-19T10:00:00.000Z',
        public_metrics: { like_count: 42, retweet_count: 5, reply_count: 3 },
        entities: {
          urls: [{ url: 'https://t.co/abc', expanded_url: 'https://example.com' }],
        },
      };
      const author = { id: 'u1', name: 'Foo Bar', username: 'foo' };
      const bm = apiInternals.tweetToApiBookmark(post, author, 'Claude Code/Tips');
      assert.strictEqual(bm.xTweetId, '999');
      assert.strictEqual(bm.xFolderName, 'Claude Code/Tips');
      assert.strictEqual(bm.url, 'https://x.com/foo/status/999');
      assert.strictEqual(bm.date, '2026-04-19');
      assert.ok(bm.title?.includes('Foo Bar'));
      assert.ok(bm.title?.includes('@foo'));
      assert.ok(bm.content?.includes('> これはテスト投稿です'));
      assert.ok(bm.content?.includes('https://example.com'));
      assert.ok(bm.content?.includes('❤️ 42'));
    });

    runner.test('author 未解決時は @unknown にフォールバック', () => {
      const post = { id: '1', text: 'x', author_id: 'u1' };
      const bm = apiInternals.tweetToApiBookmark(post, undefined, 'Misc');
      assert.ok(bm.url.includes('/unknown/status/1'));
      assert.ok(bm.title?.includes('@unknown'));
    });

    runner.test('created_at / metrics が空ならセクション省略', () => {
      const post = { id: '2', text: 'hello', author_id: 'u1' };
      const author = { id: 'u1', username: 'a', name: 'A' };
      const bm = apiInternals.tweetToApiBookmark(post, author, 'Misc');
      assert.strictEqual(bm.date, undefined);
      assert.ok(!bm.content?.includes('エンゲージメント'));
    });

    runner.test('expandBookmarksPage が includes.users を解決して複数件返す', () => {
      const page = {
        data: [
          { id: '1', text: 'a', author_id: 'u1' },
          { id: '2', text: 'b', author_id: 'u2' },
        ],
        includes: {
          users: [
            { id: 'u1', name: 'User1', username: 'user1' },
            { id: 'u2', name: 'User2', username: 'user2' },
          ],
        },
      };
      const out = apiInternals.expandBookmarksPage(page, 'Folder');
      assert.strictEqual(out.length, 2);
      assert.ok(out[0].title?.includes('@user1'));
      assert.ok(out[1].title?.includes('@user2'));
      assert.strictEqual(out[0].xFolderName, 'Folder');
    });

    // =====================================================
    // x_bookmarks_api: isTokenExpired
    // =====================================================
    runner.section('x_bookmarks_api: isTokenExpired');

    runner.test('expires_in 不明なら expired=false', () => {
      assert.strictEqual(
        apiInternals.isTokenExpired({
          access_token: 't',
          obtained_at: new Date().toISOString(),
        }),
        false
      );
    });

    runner.test('期限切れ間近(60秒マージン内) は true', () => {
      const obtained = new Date(Date.now() - 7200 * 1000).toISOString();
      assert.strictEqual(
        apiInternals.isTokenExpired(
          { access_token: 't', expires_in: 7200, obtained_at: obtained },
          Date.now()
        ),
        true
      );
    });

    runner.test('取得直後は false', () => {
      const obtained = new Date().toISOString();
      assert.strictEqual(
        apiInternals.isTokenExpired(
          { access_token: 't', expires_in: 7200, obtained_at: obtained },
          Date.now()
        ),
        false
      );
    });

    // =====================================================
    // x_bookmarks_api: URL builders
    // =====================================================
    runner.section('x_bookmarks_api: URL builders');

    runner.test('bookmarks URL にクエリが正しく載る', () => {
      const u = new URL(apiInternals.buildBookmarksUrl('12345'));
      assert.strictEqual(u.pathname, '/2/users/12345/bookmarks');
      assert.strictEqual(u.searchParams.get('max_results'), '100');
      assert.ok(u.searchParams.get('tweet.fields')?.includes('created_at'));
      assert.strictEqual(u.searchParams.get('expansions'), 'author_id');
    });

    runner.test('pagination_token が与えられれば付与される', () => {
      const u = new URL(apiInternals.buildFolderBookmarksUrl('12345', '888', 'tokenXYZ'));
      assert.strictEqual(u.pathname, '/2/users/12345/bookmarks/folders/888');
      assert.strictEqual(u.searchParams.get('pagination_token'), 'tokenXYZ');
    });

    runner.test('folders URL は max_results のみ', () => {
      const u = new URL(apiInternals.buildFoldersUrl('12345'));
      assert.strictEqual(u.pathname, '/2/users/12345/bookmarks/folders');
      assert.strictEqual(u.searchParams.get('max_results'), '100');
    });

    // =====================================================
    // x_auth_server: PKCE
    // =====================================================
    runner.section('x_auth_server: PKCE / authorize URL');

    runner.test('code_challenge は verifier の SHA-256 base64url', () => {
      const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
      const challenge = authInternals.codeChallengeFromVerifier(verifier);
      // RFC 7636 の参考値 (小文字). 我々の実装は base64url (パディングなし)
      assert.match(challenge, /^[A-Za-z0-9_-]+$/);
      // 同一入力で決定性
      assert.strictEqual(challenge, authInternals.codeChallengeFromVerifier(verifier));
    });

    runner.test('randomBase64Url は一意で URL-safe', () => {
      const a = authInternals.randomBase64Url();
      const b = authInternals.randomBase64Url();
      assert.notStrictEqual(a, b);
      assert.match(a, /^[A-Za-z0-9_-]+$/);
    });

    runner.test('authorize URL に必須パラメータが揃う', () => {
      const url = authInternals.buildAuthorizeUrl({
        clientId: 'cid',
        redirectUri: 'http://localhost:3737/auth/callback',
        state: 'S',
        codeChallenge: 'C',
        scopes: ['tweet.read', 'users.read', 'bookmark.read', 'offline.access'],
      });
      const u = new URL(url);
      assert.strictEqual(u.origin + u.pathname, 'https://x.com/i/oauth2/authorize');
      assert.strictEqual(u.searchParams.get('response_type'), 'code');
      assert.strictEqual(u.searchParams.get('client_id'), 'cid');
      assert.strictEqual(u.searchParams.get('state'), 'S');
      assert.strictEqual(u.searchParams.get('code_challenge'), 'C');
      assert.strictEqual(u.searchParams.get('code_challenge_method'), 'S256');
      assert.ok(u.searchParams.get('scope')?.includes('bookmark.read'));
      assert.ok(u.searchParams.get('scope')?.includes('offline.access'));
    });

    // =====================================================
    // Codex markdown-builder: entities → expanded URLs
    // =====================================================
    runner.section('codex markdown-builder: expandedExternalLinks');

    const basePost = (overrides: Partial<XPost> = {}): XPost => ({
      id: '100',
      text: 'hello',
      author_id: 'u1',
      created_at: '2026-04-22T00:00:00.000Z',
      public_metrics: {
        like_count: 0,
        reply_count: 0,
        retweet_count: 0,
        quote_count: 0,
      },
      ...overrides,
    });

    runner.test('entities 未指定なら空配列', () => {
      assert.deepStrictEqual(expandedExternalLinks(basePost()), []);
    });

    runner.test('expanded_url があれば優先採用', () => {
      const post = basePost({
        entities: {
          urls: [{ url: 'https://t.co/abc', expanded_url: 'https://example.com' }],
        },
      });
      assert.deepStrictEqual(expandedExternalLinks(post), ['https://example.com']);
    });

    runner.test('expanded_url 不在なら t.co にフォールバック', () => {
      const post = basePost({
        entities: { urls: [{ url: 'https://t.co/xyz' }] },
      });
      assert.deepStrictEqual(expandedExternalLinks(post), ['https://t.co/xyz']);
    });

    runner.test('x.com / twitter.com の自己リンクは除外', () => {
      const post = basePost({
        entities: {
          urls: [
            { url: 'https://t.co/1', expanded_url: 'https://x.com/foo/status/1' },
            { url: 'https://t.co/2', expanded_url: 'https://twitter.com/bar/status/2' },
            { url: 'https://t.co/3', expanded_url: 'https://external.example.com/a' },
          ],
        },
      });
      assert.deepStrictEqual(expandedExternalLinks(post), ['https://external.example.com/a']);
    });

    runner.test('重複 URL は除外', () => {
      const post = basePost({
        entities: {
          urls: [
            { url: 'https://t.co/a', expanded_url: 'https://example.com' },
            { url: 'https://t.co/b', expanded_url: 'https://example.com' },
          ],
        },
      });
      assert.deepStrictEqual(expandedExternalLinks(post), ['https://example.com']);
    });

    runner.test('複数リンクは入力順を保持', () => {
      const post = basePost({
        entities: {
          urls: [
            { url: 'https://t.co/1', expanded_url: 'https://first.example.com/a' },
            { url: 'https://t.co/2', expanded_url: 'https://second.example.com/b' },
            { url: 'https://t.co/3', expanded_url: 'https://third.example.com/c' },
          ],
        },
      });
      assert.deepStrictEqual(expandedExternalLinks(post), [
        'https://first.example.com/a',
        'https://second.example.com/b',
        'https://third.example.com/c',
      ]);
    });

    runner.section('codex markdown-builder: buildBookmarkMarkdown');

    runner.test('含まれるリンクセクションが entities から生成される', () => {
      const md = buildBookmarkMarkdown({
        post: basePost({
          text: 'see this',
          entities: {
            urls: [{ url: 'https://t.co/1', expanded_url: 'https://example.com' }],
          },
        }),
        author: { id: 'u1', name: 'Foo', username: 'foo' },
        bookmarkFolder: 'F',
        syncedAt: '2026-04-22T01:00:00.000Z',
      });
      assert.ok(md.includes('## 含まれるリンク'));
      assert.ok(md.includes('- https://example.com'));
    });

    runner.test('entities なしなら含まれるリンクセクションは出ない', () => {
      const md = buildBookmarkMarkdown({
        post: basePost({ text: 'plain' }),
        author: { id: 'u1', name: 'Foo', username: 'foo' },
        bookmarkFolder: 'F',
        syncedAt: '2026-04-22T01:00:00.000Z',
      });
      assert.ok(!md.includes('## 含まれるリンク'));
    });

    // =====================================================
    // Codex markdown-builder: expandedExternalLinks 追加エッジケース
    // =====================================================
    runner.section('codex markdown-builder: expandedExternalLinks (additional edge cases)');

    runner.test('entities.urls が空配列なら空配列を返す', () => {
      const post = basePost({ entities: { urls: [] } });
      assert.deepStrictEqual(expandedExternalLinks(post), []);
    });

    runner.test('url も expanded_url も空文字なら除外', () => {
      const post = basePost({
        entities: {
          urls: [{ url: '', expanded_url: '' }],
        },
      });
      assert.deepStrictEqual(expandedExternalLinks(post), []);
    });

    runner.test('複数の外部リンクは挿入順を保持', () => {
      const post = basePost({
        entities: {
          urls: [
            { url: 'https://t.co/1', expanded_url: 'https://alpha.example.com' },
            { url: 'https://t.co/2', expanded_url: 'https://beta.example.com' },
            { url: 'https://t.co/3', expanded_url: 'https://gamma.example.com' },
          ],
        },
      });
      assert.deepStrictEqual(expandedExternalLinks(post), [
        'https://alpha.example.com',
        'https://beta.example.com',
        'https://gamma.example.com',
      ]);
    });

    runner.test('x.com ベアホスト (パスなし) は hostname 一致で除外', () => {
      const post = basePost({
        entities: { urls: [{ url: 'https://x.com', expanded_url: 'https://x.com' }] },
      });
      assert.deepStrictEqual(expandedExternalLinks(post), []);
    });

    runner.test('twitter.com ベアホスト (パスなし) は hostname 一致で除外', () => {
      const post = basePost({
        entities: { urls: [{ url: 'https://twitter.com', expanded_url: 'https://twitter.com' }] },
      });
      assert.deepStrictEqual(expandedExternalLinks(post), []);
    });

    runner.test('x.com サブドメイン (www.x.com / mobile.twitter.com) も除外', () => {
      const post = basePost({
        entities: {
          urls: [
            { url: 'https://t.co/1', expanded_url: 'https://www.x.com/a' },
            { url: 'https://t.co/2', expanded_url: 'https://mobile.twitter.com/b' },
            { url: 'https://t.co/3', expanded_url: 'https://external.example.com/c' },
          ],
        },
      });
      assert.deepStrictEqual(expandedExternalLinks(post), ['https://external.example.com/c']);
    });

    runner.test('ホスト名偶然 "x.com" を含むだけの外部URLは除外されない (box.com)', () => {
      // 旧 substring フィルタ (url.includes("x.com/")) の false positive 回帰防止
      const post = basePost({
        entities: { urls: [{ url: 'https://t.co/z', expanded_url: 'https://box.com/file' }] },
      });
      assert.deepStrictEqual(expandedExternalLinks(post), ['https://box.com/file']);
    });

    runner.test('パスに "x.com/" を含むが hostname は別の URL は除外されない', () => {
      // 旧 substring フィルタだと archive 系 URL が誤 drop されていた
      const post = basePost({
        entities: {
          urls: [{
            url: 'https://t.co/q',
            expanded_url: 'https://archive.org/web/20260101/https://x.com/user',
          }],
        },
      });
      assert.deepStrictEqual(
        expandedExternalLinks(post),
        ['https://archive.org/web/20260101/https://x.com/user'],
      );
    });

    runner.test('expanded_url が空文字列の場合は url にフォールバック (||)', () => {
      // 旧 ?? は空文字を valid 扱いして fallback せず、結果として entry が drop されていた
      const post = basePost({
        entities: {
          urls: [{ url: 'https://t.co/short', expanded_url: '' }],
        },
      });
      assert.deepStrictEqual(expandedExternalLinks(post), ['https://t.co/short']);
    });

    runner.test('malformed URL (new URL でエラー) は落とさず保持 (互換挙動)', () => {
      // new URL() が投げる系はスキップせず、hostname 不明として通過させる
      // → dedup と filter は走るが self-link 判定はスキップ
      const post = basePost({
        entities: { urls: [{ url: 'not-a-url', expanded_url: 'not-a-url' }] },
      });
      assert.deepStrictEqual(expandedExternalLinks(post), ['not-a-url']);
    });

    runner.test('expanded_url が undefined で url が空文字の場合スキップ', () => {
      const post = basePost({
        entities: {
          urls: [
            { url: '', expanded_url: undefined },
            { url: 'https://t.co/ok', expanded_url: 'https://valid.example.com' },
          ],
        },
      });
      assert.deepStrictEqual(expandedExternalLinks(post), ['https://valid.example.com']);
    });

    runner.test('外部リンクと自己リンクが混在しても外部リンクのみ返す', () => {
      const post = basePost({
        entities: {
          urls: [
            { url: 'https://t.co/1', expanded_url: 'https://github.com/foo/bar' },
            { url: 'https://t.co/2', expanded_url: 'https://x.com/foo/status/999' },
            { url: 'https://t.co/3', expanded_url: 'https://twitter.com/baz/status/1' },
            { url: 'https://t.co/4', expanded_url: 'https://docs.example.com/readme' },
          ],
        },
      });
      assert.deepStrictEqual(expandedExternalLinks(post), [
        'https://github.com/foo/bar',
        'https://docs.example.com/readme',
      ]);
    });

    // =====================================================
    // Codex markdown-builder: buildBookmarkMarkdown 追加エッジケース
    // =====================================================
    runner.section('codex markdown-builder: buildBookmarkMarkdown (additional edge cases)');

    runner.test('entities.urls が空配列なら含まれるリンクセクションは出ない', () => {
      const md = buildBookmarkMarkdown({
        post: basePost({ entities: { urls: [] } }),
        author: { id: 'u1', name: 'Foo', username: 'foo' },
        bookmarkFolder: 'F',
        syncedAt: '2026-04-22T01:00:00.000Z',
      });
      assert.ok(!md.includes('## 含まれるリンク'));
    });

    runner.test('複数リンクはすべて箇条書きで含まれるリンクセクションに現れる', () => {
      const md = buildBookmarkMarkdown({
        post: basePost({
          text: 'links',
          entities: {
            urls: [
              { url: 'https://t.co/1', expanded_url: 'https://alpha.example.com' },
              { url: 'https://t.co/2', expanded_url: 'https://beta.example.com' },
            ],
          },
        }),
        author: { id: 'u1', name: 'Foo', username: 'foo' },
        bookmarkFolder: 'F',
        syncedAt: '2026-04-22T01:00:00.000Z',
      });
      assert.ok(md.includes('- https://alpha.example.com'));
      assert.ok(md.includes('- https://beta.example.com'));
    });

    runner.test('含まれるリンクセクションは ## Metrics より前に位置する', () => {
      const md = buildBookmarkMarkdown({
        post: basePost({
          text: 'order check',
          entities: {
            urls: [{ url: 'https://t.co/1', expanded_url: 'https://example.com' }],
          },
        }),
        author: { id: 'u1', name: 'Foo', username: 'foo' },
        bookmarkFolder: 'F',
        syncedAt: '2026-04-22T01:00:00.000Z',
      });
      const linksPos = md.indexOf('## 含まれるリンク');
      const metricsPos = md.indexOf('## Metrics');
      assert.ok(linksPos !== -1, '含まれるリンクセクションが存在する');
      assert.ok(metricsPos !== -1, 'Metrics セクションが存在する');
      assert.ok(linksPos < metricsPos, '含まれるリンクは Metrics より前にある');
    });

    runner.test('著者名に " が含まれる場合 YAML でエスケープされる', () => {
      const md = buildBookmarkMarkdown({
        post: basePost({ text: 'escape test' }),
        author: { id: 'u1', name: 'Say "Hello"', username: 'quoter' },
        bookmarkFolder: 'F',
        syncedAt: '2026-04-22T01:00:00.000Z',
      });
      // YAML title should have escaped quotes
      assert.ok(md.includes('\\"Hello\\"'), `YAML title should escape quotes, got: ${md.split('\n').find(l => l.startsWith('title:'))}`);
    });

    runner.test('author 未指定時は Unknown Author / unknown で Markdown が生成される', () => {
      const md = buildBookmarkMarkdown({
        post: basePost({
          text: 'no author',
          entities: {
            urls: [{ url: 'https://t.co/1', expanded_url: 'https://example.com' }],
          },
        }),
        bookmarkFolder: 'F',
        syncedAt: '2026-04-22T01:00:00.000Z',
      });
      assert.ok(md.includes('Unknown Author'));
      assert.ok(md.includes('@unknown'));
      // links section should still appear
      assert.ok(md.includes('## 含まれるリンク'));
      assert.ok(md.includes('- https://example.com'));
    });

    runner.test('YAML frontmatter に必須フィールドが揃う', () => {
      const md = buildBookmarkMarkdown({
        post: basePost({ id: '42', text: 'fm check' }),
        author: { id: 'u1', name: 'Alice', username: 'alice' },
        bookmarkFolder: 'MyFolder',
        syncedAt: '2026-04-22T01:00:00.000Z',
      });
      assert.ok(md.startsWith('---\n'), 'YAML front matter starts');
      assert.ok(md.includes('post_id: "42"'));
      assert.ok(md.includes('author_username: "alice"'));
      assert.ok(md.includes('bookmark_folder: "MyFolder"'));
      assert.ok(md.includes('synced_at: "2026-04-22T01:00:00.000Z"'));
    });

    runner.test('Metrics セクションに like/reply/repost/quote が出力される', () => {
      const post = basePost({
        public_metrics: {
          like_count: 10,
          reply_count: 3,
          retweet_count: 5,
          quote_count: 2,
        },
      });
      const md = buildBookmarkMarkdown({
        post,
        author: { id: 'u1', name: 'Bob', username: 'bob' },
        bookmarkFolder: 'F',
        syncedAt: '2026-04-22T01:00:00.000Z',
      });
      assert.ok(md.includes('- Likes: 10'));
      assert.ok(md.includes('- Replies: 3'));
      assert.ok(md.includes('- Reposts: 5'));
      assert.ok(md.includes('- Quotes: 2'));
    });

    // =====================================================
    // codex forced-parents: hasWordBoundaryMatch
    // =====================================================
    runner.section('codex forced-parents: hasWordBoundaryMatch');

    runner.test('空のキーワードは常に false', () => {
      assert.strictEqual(hasWordBoundaryMatch('AI Agent', ''), false);
      assert.strictEqual(hasWordBoundaryMatch('AI Agent', '   '), false);
    });

    runner.test('完全一致はマッチ', () => {
      assert.strictEqual(hasWordBoundaryMatch('Claude Code', 'Claude Code'), true);
    });

    runner.test('単語境界マッチ (AI は "AI Agent" にマッチ)', () => {
      assert.strictEqual(hasWordBoundaryMatch('AI Agent', 'AI'), true);
    });

    runner.test('部分一致は不一致 (AI は "AIRI" にマッチしない)', () => {
      assert.strictEqual(hasWordBoundaryMatch('AIRI', 'AI'), false);
    });

    runner.test('日本語隣接は境界として扱う (MCP は "MCP連携" にマッチ)', () => {
      assert.strictEqual(hasWordBoundaryMatch('MCP連携', 'MCP'), true);
    });

    runner.test('大小文字無視', () => {
      assert.strictEqual(hasWordBoundaryMatch('claude code tips', 'Claude Code'), true);
    });

    // =====================================================
    // codex forced-parents: resolveForcedParent
    // =====================================================
    runner.section('codex forced-parents: resolveForcedParent');

    runner.test('空の forcedParents は null', () => {
      assert.strictEqual(resolveForcedParent('Claude Code Tips', []), null);
    });

    runner.test('マッチなしは null', () => {
      assert.strictEqual(resolveForcedParent('LangChain', ['Claude Code', 'Obsidian']), null);
    });

    runner.test('完全一致なら child は空文字', () => {
      assert.deepStrictEqual(
        resolveForcedParent('Claude Code', ['Claude Code']),
        { parent: 'Claude Code', child: '' }
      );
    });

    runner.test('単語境界マッチで parent + child 分割', () => {
      assert.deepStrictEqual(
        resolveForcedParent('Claude Code Tips', ['Claude Code']),
        { parent: 'Claude Code', child: 'Tips' }
      );
    });

    runner.test('日本語混在: MCP連携 → { MCP, 連携 }', () => {
      assert.deepStrictEqual(
        resolveForcedParent('MCP連携', ['MCP']),
        { parent: 'MCP', child: '連携' }
      );
    });

    runner.test('長いキーワードが優先 (Claude Code > Code)', () => {
      assert.deepStrictEqual(
        resolveForcedParent('Claude Code Tips', ['Code', 'Claude Code']),
        { parent: 'Claude Code', child: 'Tips' }
      );
    });

    runner.test('空文字キーワードはスキップ', () => {
      assert.deepStrictEqual(
        resolveForcedParent('AI Agent', ['', 'AI']),
        { parent: 'AI', child: 'Agent' }
      );
    });

    runner.test('大小文字無視マッチ (キーワード表記が正規形で返る)', () => {
      const result = resolveForcedParent('claude code tips', ['Claude Code']);
      assert.ok(result);
      assert.strictEqual(result!.parent, 'Claude Code');
      assert.strictEqual(result!.child, 'tips');
    });

    runner.test('空フォルダ名は null', () => {
      assert.strictEqual(resolveForcedParent('', ['Claude Code']), null);
      assert.strictEqual(resolveForcedParent('   ', ['Claude Code']), null);
    });

    // =====================================================
    // codex forced-parents: loadForcedParents (file IO)
    // =====================================================
    runner.section('codex forced-parents: loadForcedParents');

    runner.test('未存在ファイルは空配列', () => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'codex-fp-test-'));
      try {
        assert.deepStrictEqual(loadCodexForcedParents(dir), []);
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });

    runner.test('正常な x_forced_parents.json を読み込み空文字を除外', () => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'codex-fp-test-'));
      try {
        const subdir = path.join(dir, '__skills', 'pipeline');
        fs.mkdirSync(subdir, { recursive: true });
        fs.writeFileSync(
          path.join(subdir, 'x_forced_parents.json'),
          JSON.stringify(['Claude Code', 'Obsidian', '', '  ']),
          'utf8'
        );
        assert.deepStrictEqual(loadCodexForcedParents(dir), ['Claude Code', 'Obsidian']);
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });

    runner.test('壊れた JSON は空配列 (例外を投げない)', () => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'codex-fp-test-'));
      try {
        const subdir = path.join(dir, '__skills', 'pipeline');
        fs.mkdirSync(subdir, { recursive: true });
        fs.writeFileSync(
          path.join(subdir, 'x_forced_parents.json'),
          '{this is: not valid [[[',
          'utf8'
        );
        assert.deepStrictEqual(loadCodexForcedParents(dir), []);
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });

    runner.test('配列以外 (object) は空配列', () => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'codex-fp-test-'));
      try {
        const subdir = path.join(dir, '__skills', 'pipeline');
        fs.mkdirSync(subdir, { recursive: true });
        fs.writeFileSync(
          path.join(subdir, 'x_forced_parents.json'),
          JSON.stringify({ not: 'an array' }),
          'utf8'
        );
        assert.deepStrictEqual(loadCodexForcedParents(dir), []);
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });

    // =====================================================
    // codex path resolver: forcedParents integration
    // =====================================================
    runner.section('codex path resolver: forcedParents priority');

    runner.test('forcedParents マッチは vault/sourceRoot/parent/child に展開', () => {
      const result = resolveXBookmarkSaveDirectory({
        vaultPath: '/vault',
        sourceRoot: 'Clippings/X',
        childFolderName: 'Claude Code Tips',
        postDate: new Date('2026-04-22T00:00:00Z'),
        folderPostCount: 1,
        forcedParents: ['Claude Code'],
      });
      assert.strictEqual(result, '/vault/Clippings/X/Claude Code/Tips');
    });

    runner.test('forcedParents 完全一致は vault/sourceRoot/parent のみ', () => {
      const result = resolveXBookmarkSaveDirectory({
        vaultPath: '/vault',
        sourceRoot: 'Clippings/X',
        childFolderName: 'Claude Code',
        postDate: new Date('2026-04-22T00:00:00Z'),
        folderPostCount: 1,
        forcedParents: ['Claude Code'],
      });
      assert.strictEqual(result, '/vault/Clippings/X/Claude Code');
    });

    runner.test('forcedParents 未指定 / マッチなしは child 直下 (従来挙動)', () => {
      const result = resolveXBookmarkSaveDirectory({
        vaultPath: '/vault',
        sourceRoot: 'Clippings/X',
        childFolderName: 'LangChain',
        postDate: new Date('2026-04-22T00:00:00Z'),
        folderPostCount: 1,
        forcedParents: ['Claude Code', 'Obsidian'],
      });
      assert.strictEqual(result, '/vault/Clippings/X/LangChain');
    });

    runner.test('forcedParents は FolderMapping より優先', () => {
      const result = resolveXBookmarkSaveDirectory({
        vaultPath: '/vault',
        sourceRoot: 'Clippings/X',
        childFolderName: 'Claude Code Tips',
        postDate: new Date('2026-04-22T00:00:00Z'),
        folderPostCount: 1,
        forcedParents: ['Claude Code'],
        mapping: {
          version: 1,
          generated_at: '2026-04-22T00:00:00Z',
          source_root: 'Clippings/X',
          groups: [
            {
              parent_folder: 'SomeOther',
              match_type: 'prefix',
              token: 'Claude',
              children: ['Claude Code Tips'],
            },
          ],
        },
      });
      // forcedParents 優先 → "Claude Code/Tips" (mapping の "SomeOther/Claude Code Tips" ではない)
      assert.strictEqual(result, '/vault/Clippings/X/Claude Code/Tips');
    });

    runner.test('forcedParents + date bucket (quarterly) 併用', () => {
      const result = resolveXBookmarkSaveDirectory({
        vaultPath: '/vault',
        sourceRoot: 'Clippings/X',
        childFolderName: 'Claude Code Tips',
        postDate: new Date('2026-04-22T00:00:00Z'),
        folderPostCount: 15, // quarterly threshold (10+)
        forcedParents: ['Claude Code'],
      });
      assert.strictEqual(result, '/vault/Clippings/X/Claude Code/Tips/2026-Q2');
    });

    return runner.report();
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}