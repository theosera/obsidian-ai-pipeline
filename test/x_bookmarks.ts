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
  prioritizeForcedParents,
} from '../x_folder_mapper';
import { buildFolderTree, renderFolderTree } from '../x_folder_tree';
import { parseSelection } from '../x_interactive_picker';
import { fetchBookmarksViaApi, saveTokens, type FetchOptions } from '../x_bookmarks_api';
import {
  writePartialReport,
  savePartialLatest,
  loadPartialLatest,
  findPartialByXFolderId,
  PartialFolderRecord,
} from '../x_bookmarks_partial';
import {
  newSessionId,
  writeSessionMarker,
  readSessionMarker,
  walkSessionMarkers,
  getOrCreateSession,
  lookupVaultPath,
} from '../x_session_registry';
import { runSyncPhase, __test as syncInternals } from '../x_session_sync';
import { __test as aiInternals, createInteractiveOrphanResolver } from '../x_session_ai';
import { XBookmarksDb, getDb } from '../x_bookmarks_db';
import Database from 'better-sqlite3';
import { __test as apiInternals } from '../x_bookmarks_api';
import { __test as authInternals } from '../x_auth_server';
import { __test as videoInternals } from '../x_video_frames';
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

export async function run(): Promise<TestSuiteResult> {
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

    runner.test('upsertBookmark は noteTweetText を保存する', () => {
      const db = new XBookmarksDb(':memory:');
      const fullText = 'X Premium 長文の全文がここに入る (25000字想定)。';
      db.upsertBookmark({
        tweetId: 'long1',
        url: 'https://x.com/a/status/long1',
        tweetText: 'X Premium 長文の全文がここに…',
        noteTweetText: fullText,
      });
      // PRAGMA で内部状態を確認 (rich query) — schema に note_tweet_text 列が存在するか
      const row = (db as any).db.prepare(
        'SELECT note_tweet_text FROM bookmarks WHERE tweet_id = ?'
      ).get('long1') as { note_tweet_text: string };
      assert.strictEqual(row.note_tweet_text, fullText);
      db.close();
    });

    runner.test('CodeRabbit critical: session_id 列無し DB を開いてもデータ消失しない (上書き禁止)', () => {
      // pre-PR DB は bookmarks テーブルに session_id 列が無い。
      // SCHEMA 内に CREATE INDEX idx_session ON bookmarks(session_id) を書くと、
      // CREATE TABLE IF NOT EXISTS が no-op になった後で index 作成が "no such column"
      // で throw → getDb() の catch が DB を corrupted 退避 → ユーザーキャッシュ消失。
      // 当テストは index 文を SCHEMA から外し、migrate 内で column 追加後に張る、
      // という回帰防止用。
      const dbDir = path.join(tmpDir, 'session-migration-test');
      fs.mkdirSync(dbDir, { recursive: true });
      const dbPath = path.join(dbDir, 'x_bookmarks.db');

      // 旧 DB を擬似生成: bookmarks テーブルだけ作って既存行を入れる (session_id 列なし)
      const legacy = new Database(dbPath);
      legacy.exec(`
        CREATE TABLE bookmarks (
          tweet_id TEXT PRIMARY KEY,
          url TEXT NOT NULL UNIQUE,
          author TEXT,
          tweet_text TEXT,
          note_tweet_text TEXT,
          created_at TEXT,
          x_folder_name TEXT,
          vault_path TEXT,
          saved_at TEXT NOT NULL,
          engagement_likes INTEGER,
          engagement_retweets INTEGER,
          engagement_replies INTEGER
        );
      `);
      legacy.prepare(
        'INSERT INTO bookmarks (tweet_id, url, saved_at) VALUES (?, ?, ?)'
      ).run('legacy-1', 'https://x.com/a/status/legacy-1', new Date().toISOString());
      legacy.close();

      // ここで XBookmarksDb constructor を回す。SCHEMA に idx_session が残っていると
      // throw して呼出側 (getDb) が DB を corrupted 退避してしまう。修正後は通る。
      const reopened = new XBookmarksDb(dbPath);
      try {
        // 既存行が消えていない (=ユーザーキャッシュ無事)
        const known = reopened.getKnownTweetIds();
        assert.ok(known.has('legacy-1'), '旧データが消失している (回帰)');
        // session_id 列が migrate で追加されている
        const cols = (reopened as any).db
          .prepare('PRAGMA table_info(bookmarks)')
          .all() as { name: string }[];
        assert.ok(cols.some(c => c.name === 'session_id'), 'session_id 列が追加されている');
        // idx_session が存在する
        const idx = (reopened as any).db
          .prepare("PRAGMA index_list('bookmarks')")
          .all() as { name: string }[];
        assert.ok(idx.some(i => i.name === 'idx_session'), 'idx_session が migration で作成されている');
      } finally {
        reopened.close();
      }
    });

    runner.test('reassignBookmarkSession は session_id / vault_path / x_folder_name を更新する', () => {
      const db = new XBookmarksDb(':memory:');
      db.upsertBookmark({
        tweetId: 'rebind-1',
        url: 'https://x.com/a/status/rebind-1',
        sessionId: 'old-session',
        vaultPath: 'old/path/file.md',
        xFolderName: 'OldFolder',
      });
      db.reassignBookmarkSession({
        tweetId: 'rebind-1',
        sessionId: 'new-session',
        vaultPath: 'new/path/file.md',
        xFolderName: 'NewFolder',
      });
      const row = (db as any).db.prepare(
        'SELECT session_id, vault_path, x_folder_name FROM bookmarks WHERE tweet_id = ?'
      ).get('rebind-1') as { session_id: string; vault_path: string; x_folder_name: string };
      assert.strictEqual(row.session_id, 'new-session');
      assert.strictEqual(row.vault_path, 'new/path/file.md');
      assert.strictEqual(row.x_folder_name, 'NewFolder');
      db.close();
    });

    runner.test('reassignBookmarkSession に xFolderName=null を渡すと既存値を保持 (COALESCE)', () => {
      const db = new XBookmarksDb(':memory:');
      db.upsertBookmark({
        tweetId: 'rebind-2',
        url: 'https://x.com/a/status/rebind-2',
        sessionId: 'old',
        xFolderName: 'PreservedFolder',
      });
      db.reassignBookmarkSession({
        tweetId: 'rebind-2',
        sessionId: 'new',
        vaultPath: 'p',
        xFolderName: null,
      });
      const row = (db as any).db.prepare(
        'SELECT x_folder_name FROM bookmarks WHERE tweet_id = ?'
      ).get('rebind-2') as { x_folder_name: string };
      assert.strictEqual(row.x_folder_name, 'PreservedFolder', 'null を渡したら既存値を保持');
      db.close();
    });

    runner.test('既存 (note_tweet_text 列無し) DB に対しても constructor migration で復活する', () => {
      // ファイル backed DB で本物の constructor → migration パスを通す。
      // (in-memory + private 直叩きだと「constructor が migration を呼び忘れた」
      //  リグレッションを検出できない)
      const dbDir = path.join(tmpDir, 'migration-test');
      fs.mkdirSync(dbDir, { recursive: true });
      const dbPath = path.join(dbDir, 'x_bookmarks.db');

      // 1) 通常通り作成 → カラムあり
      const db1 = new XBookmarksDb(dbPath);
      const internal1 = (db1 as any).db as import('better-sqlite3').Database;
      // 2) "古い DB" を擬似生成: カラムを drop
      try {
        internal1.exec('ALTER TABLE bookmarks DROP COLUMN note_tweet_text');
      } catch (e: any) {
        const msg = String(e?.message ?? e);
        // SQLite < 3.35 (better-sqlite3 古バンドル) のみ DROP COLUMN 未対応で skip
        // それ以外のエラー (lock, schema drift 等) は隠蔽すると regression を見逃すので throw
        if (!/DROP COLUMN|near "DROP"|syntax error/i.test(msg)) {
          db1.close();
          throw e;
        }
        console.warn(`   ⏭️  skip migration test: DROP COLUMN unsupported (${msg})`);
        db1.close();
        return;
      }
      const colsAfterDrop = internal1.prepare("PRAGMA table_info(bookmarks)").all() as { name: string }[];
      assert.ok(!colsAfterDrop.some(c => c.name === 'note_tweet_text'), 'precondition: column dropped');
      db1.close();

      // 3) もう一度 new XBookmarksDb(filePath) で開く → constructor が migration を実行
      const db2 = new XBookmarksDb(dbPath);
      const internal2 = (db2 as any).db as import('better-sqlite3').Database;
      const colsReopened = internal2.prepare("PRAGMA table_info(bookmarks)").all() as { name: string }[];
      assert.ok(
        colsReopened.some(c => c.name === 'note_tweet_text'),
        'constructor が note_tweet_text を再追加するべき'
      );
      db2.close();
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

    runner.test('note_tweet があれば全文を本文に使い、xNoteTweetText に記録', () => {
      const truncated = 'これは長文ツイート…';
      const fullText = 'これは長文ツイートで、X Premium 加入者は最大25,000字まで投稿できます。truncated な text フィールドには冒頭しか入りませんが、note_tweet.text には全文が入ります。';
      const post = {
        id: '777',
        text: truncated,
        author_id: 'u1',
        note_tweet: { text: fullText },
      };
      const author = { id: 'u1', username: 'foo', name: 'Foo' };
      const bm = apiInternals.tweetToApiBookmark(post, author, 'LongForm');
      // 本文は note_tweet 由来 (全文)
      assert.ok(bm.content?.includes(fullText.split('\n')[0]));
      // truncate 文字列は本文に含まれない (置き換えられている)
      assert.ok(!bm.content?.includes('長文ツイート…'));
      // xNoteTweetText に full text が保存されている
      assert.strictEqual(bm.xNoteTweetText, fullText);
      // textContent も full text に
      assert.strictEqual(bm.textContent, fullText);
    });

    runner.test('note_tweet が無ければ従来通り text を使い、xNoteTweetText 未設定', () => {
      const post = { id: '778', text: '通常ツイート', author_id: 'u1' };
      const bm = apiInternals.tweetToApiBookmark(post, { id: 'u1', username: 'a', name: 'A' }, 'Misc');
      assert.strictEqual(bm.textContent, '通常ツイート');
      assert.strictEqual(bm.xNoteTweetText, undefined);
    });

    runner.test('media resolver で動画があれば xVideoUrl / xVideoDurationMs をセット', () => {
      const post = {
        id: 'v1', text: '動画ツイート', author_id: 'u1',
        attachments: { media_keys: ['mk1'] },
      };
      const author = { id: 'u1', username: 'a', name: 'A' };
      const resolver = (key: string) => key === 'mk1' ? {
        media_key: 'mk1', type: 'video',
        duration_ms: 28500,
        variants: [
          { url: 'low.mp4', bit_rate: 320000 },
          { url: 'hi.mp4', bit_rate: 2176000 },
        ],
      } : undefined;
      const bm = apiInternals.tweetToApiBookmark(post, author, 'Misc', resolver);
      assert.strictEqual(bm.xVideoUrl, 'hi.mp4');
      assert.strictEqual(bm.xVideoDurationMs, 28500);
    });

    runner.test('media resolver で video が無ければ xVideoUrl 未設定', () => {
      const post = {
        id: 'p1', text: '画像のみ', author_id: 'u1',
        attachments: { media_keys: ['mk1'] },
      };
      const resolver = (key: string) => ({
        media_key: 'mk1', type: 'photo',
      });
      const bm = apiInternals.tweetToApiBookmark(
        post, { id: 'u1', username: 'a', name: 'A' }, 'Misc', resolver
      );
      assert.strictEqual(bm.xVideoUrl, undefined);
      assert.strictEqual(bm.xVideoDurationMs, undefined);
    });

    runner.test('media resolver 未指定なら従来通り xVideoUrl 未設定', () => {
      const post = {
        id: 'v2', text: '動画あるが resolver 無し', author_id: 'u1',
        attachments: { media_keys: ['mk1'] },
      };
      const bm = apiInternals.tweetToApiBookmark(
        post, { id: 'u1', username: 'a', name: 'A' }, 'Misc'
      );
      assert.strictEqual(bm.xVideoUrl, undefined);
    });

    runner.test('expandBookmarksPage が includes.media を解決して xVideoUrl をセット', () => {
      const page = {
        data: [
          { id: 'v1', text: '動画', author_id: 'u1', attachments: { media_keys: ['mk1'] } },
          { id: 'p1', text: '画像', author_id: 'u1', attachments: { media_keys: ['mk2'] } },
        ],
        includes: {
          users: [{ id: 'u1', name: 'A', username: 'a' }],
          media: [
            { media_key: 'mk1', type: 'video', duration_ms: 5000, variants: [
              { url: 'a.mp4', bit_rate: 1000 }, { url: 'b.mp4', bit_rate: 2000 },
            ]},
            { media_key: 'mk2', type: 'photo' },
          ],
        },
      };
      const out = apiInternals.expandBookmarksPage(page, 'Folder');
      assert.strictEqual(out[0].xVideoUrl, 'b.mp4');
      assert.strictEqual(out[0].xVideoDurationMs, 5000);
      assert.strictEqual(out[1].xVideoUrl, undefined);
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
      assert.ok(u.searchParams.get('tweet.fields')?.includes('note_tweet'));
      assert.ok(u.searchParams.get('tweet.fields')?.includes('attachments'));
      assert.ok(u.searchParams.get('expansions')?.includes('author_id'));
      assert.ok(u.searchParams.get('expansions')?.includes('attachments.media_keys'));
      assert.ok(u.searchParams.get('media.fields')?.includes('variants'));
    });

    runner.test('folder bookmarks URL は索引専用でクエリパラメータを持たない', () => {
      // /folders/:id は X API 側で id/folder_id 以外の query を 400 で拒否する。
      // 本文は buildTweetsLookupUrl 経由でハイドレートする。
      const u = new URL(apiInternals.buildFolderBookmarksUrl('12345', '888'));
      assert.strictEqual(u.pathname, '/2/users/12345/bookmarks/folders/888');
      assert.strictEqual(u.search, '');
    });

    runner.test('tweets lookup URL は ids と本文系 expansions を持つ', () => {
      const u = new URL(apiInternals.buildTweetsLookupUrl(['111', '222']));
      assert.strictEqual(u.pathname, '/2/tweets');
      assert.strictEqual(u.searchParams.get('ids'), '111,222');
      assert.ok(u.searchParams.get('tweet.fields')?.includes('note_tweet'));
      assert.ok(u.searchParams.get('expansions')?.includes('attachments.media_keys'));
      assert.ok(u.searchParams.get('media.fields')?.includes('variants'));
      assert.ok(u.searchParams.get('user.fields')?.includes('username'));
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

    runner.test('forcedParents の悪意ある値 (../..) は sourceRoot を脱出しない', () => {
      // x_forced_parents.json は user-maintained で、壊れた/悪意ある値が
      // 入る可能性がある。sanitizeSegment で `/`, `\`, `..`, 制御文字を除去
      // して path.join が vault 外に書き込むのを防ぐ。
      const result = resolveXBookmarkSaveDirectory({
        vaultPath: '/vault',
        sourceRoot: 'Clippings/X',
        childFolderName: '../../etc Tips',
        postDate: new Date('2026-04-22T00:00:00Z'),
        folderPostCount: 1,
        forcedParents: ['../../etc'],
      });
      // "../../etc" → sanitize → "etc" ("/" と ".." が削除)
      assert.strictEqual(result, '/vault/Clippings/X/etc/Tips');
    });

    runner.test('forcedParents のスラッシュ含む値 (A/B) は単一セグメント化', () => {
      const result = resolveXBookmarkSaveDirectory({
        vaultPath: '/vault',
        sourceRoot: 'Clippings/X',
        childFolderName: 'A/B sub',
        postDate: new Date('2026-04-22T00:00:00Z'),
        folderPostCount: 1,
        forcedParents: ['A/B'],
      });
      // "A/B" → sanitize → "A-B" (スラッシュをハイフン置換)
      assert.strictEqual(result, '/vault/Clippings/X/A-B/sub');
    });

    // =====================================================
    // x_video_frames: pure helpers
    // =====================================================
    runner.section('x_video_frames: computeSampleTimestamps');

    runner.test('frameCount=4, duration=20s → [4, 8, 12, 16]', () => {
      const ts = videoInternals.computeSampleTimestamps(20, 4);
      assert.deepStrictEqual(ts, [4, 8, 12, 16]);
    });

    runner.test('frameCount=3, duration=12s → [3, 6, 9]', () => {
      const ts = videoInternals.computeSampleTimestamps(12, 3);
      assert.deepStrictEqual(ts, [3, 6, 9]);
    });

    runner.test('duration=0 / frameCount=0 → []', () => {
      assert.deepStrictEqual(videoInternals.computeSampleTimestamps(0, 4), []);
      assert.deepStrictEqual(videoInternals.computeSampleTimestamps(20, 0), []);
    });

    runner.section('x_video_frames: pickVideoMedia / pickBestVariantUrl');

    runner.test('pickVideoMedia は最初の video を返す', () => {
      const media = [
        { media_key: 'a', type: 'photo' as const },
        { media_key: 'b', type: 'video' as const, duration_ms: 5000 },
        { media_key: 'c', type: 'video' as const, duration_ms: 10000 },
      ];
      const v = videoInternals.pickVideoMedia(media);
      assert.strictEqual(v?.media_key, 'b');
    });

    runner.test('pickVideoMedia は animated_gif も拾う', () => {
      const v = videoInternals.pickVideoMedia([
        { media_key: 'g', type: 'animated_gif' as const, duration_ms: 3000 },
      ]);
      assert.strictEqual(v?.media_key, 'g');
    });

    runner.test('pickVideoMedia は video が無ければ undefined', () => {
      const v = videoInternals.pickVideoMedia([
        { media_key: 'a', type: 'photo' as const },
      ]);
      assert.strictEqual(v, undefined);
    });

    runner.test('pickBestVariantUrl は最高 bit_rate を選ぶ', () => {
      const url = videoInternals.pickBestVariantUrl({
        media_key: 'k', type: 'video',
        variants: [
          { url: 'low.mp4', bit_rate: 320000 },
          { url: 'hi.mp4', bit_rate: 2176000 },
          { url: 'mid.mp4', bit_rate: 832000 },
        ],
      });
      assert.strictEqual(url, 'hi.mp4');
    });

    runner.test('pickBestVariantUrl は variants 無しなら undefined', () => {
      const url = videoInternals.pickBestVariantUrl({ media_key: 'k', type: 'video' });
      assert.strictEqual(url, undefined);
    });

    runner.section('x_video_frames: isVideoFramesEnabled');

    runner.test('X_VIDEO_FRAMES=true で有効', () => {
      // try/finally + delete-on-undefined パターン:
      // 1) `process.env.X = undefined` は文字列 "undefined" を保存してしまう
      // 2) 途中で assert が throw すると env が残ったままになり後続テストに漏れる
      const prev = process.env.X_VIDEO_FRAMES;
      try {
        process.env.X_VIDEO_FRAMES = 'true';
        assert.strictEqual(videoInternals.isVideoFramesEnabled(), true);
        process.env.X_VIDEO_FRAMES = '1';
        assert.strictEqual(videoInternals.isVideoFramesEnabled(), true);
        process.env.X_VIDEO_FRAMES = 'TRUE';
        assert.strictEqual(videoInternals.isVideoFramesEnabled(), true);
      } finally {
        if (prev === undefined) delete process.env.X_VIDEO_FRAMES;
        else process.env.X_VIDEO_FRAMES = prev;
      }
    });

    runner.test('X_VIDEO_FRAMES 未設定 / false で無効', () => {
      const prev = process.env.X_VIDEO_FRAMES;
      try {
        delete process.env.X_VIDEO_FRAMES;
        assert.strictEqual(videoInternals.isVideoFramesEnabled(), false);
        process.env.X_VIDEO_FRAMES = 'false';
        assert.strictEqual(videoInternals.isVideoFramesEnabled(), false);
        process.env.X_VIDEO_FRAMES = '0';
        assert.strictEqual(videoInternals.isVideoFramesEnabled(), false);
        process.env.X_VIDEO_FRAMES = '';
        assert.strictEqual(videoInternals.isVideoFramesEnabled(), false);
      } finally {
        if (prev === undefined) delete process.env.X_VIDEO_FRAMES;
        else process.env.X_VIDEO_FRAMES = prev;
      }
    });

    runner.section('x_video_frames: renderKeyFramesSection');

    runner.test('feature_disabled は空文字 (本文に何も追記しない)', () => {
      const md = videoInternals.renderKeyFramesSection({ frames: [], skipped: 'feature_disabled' });
      assert.strictEqual(md, '');
    });

    runner.test('成功時は ## キーフレーム 見出しと wikilink 付き', () => {
      const md = videoInternals.renderKeyFramesSection({
        frames: [
          { absolutePath: '/v/_attachments/x-bookmarks/123/frame-01.webp',
            vaultRelative: '_attachments/x-bookmarks/123/frame-01.webp', timestampSec: 4 },
          { absolutePath: '/v/_attachments/x-bookmarks/123/frame-02.webp',
            vaultRelative: '_attachments/x-bookmarks/123/frame-02.webp', timestampSec: 8 },
        ],
        durationSec: 20,
      });
      assert.ok(md.includes('## キーフレーム (動画 0:20)'));
      assert.ok(md.includes('![[_attachments/x-bookmarks/123/frame-01.webp|360]]'));
      assert.ok(md.includes('_0:04_'));
      assert.ok(md.includes('_0:08_'));
    });

    runner.test('skip 時は理由付き見出しを出す', () => {
      const md = videoInternals.renderKeyFramesSection({
        frames: [], durationSec: 90, skipped: 'too_long', message: '90.0s > 60s cap'
      });
      assert.ok(md.includes('## キーフレーム'));
      assert.ok(md.includes('取得失敗'));
      assert.ok(md.includes('too_long'));
      assert.ok(md.includes('90.0s > 60s cap'));
    });

    runner.test('ffmpeg_failed は必ず取得失敗見出しを出す (frames が空配列であること前提)', () => {
      // x_video_frames.ts:315 で partial frames を返さないようになっているため
      // 失敗時は必ず frames=[] となる。renderKeyFramesSection は frames.length===0
      // を取得失敗判定に使うので、ffmpeg_failed の場合は確実に 取得失敗 見出しが出る
      const md = videoInternals.renderKeyFramesSection({
        frames: [], durationSec: 20, skipped: 'ffmpeg_failed',
        message: 'frame 3 extraction failed (exit=1)',
      });
      assert.ok(md.includes('取得失敗'));
      assert.ok(md.includes('ffmpeg_failed'));
    });

    runner.section('x_video_frames: alreadyExtracted');

    runner.test('全フレーム揃っていれば true', () => {
      const dir = path.join(tmpDir, 'frames-test-1');
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(path.join(dir, 'frame-01.webp'), 'x');
      fs.writeFileSync(path.join(dir, 'frame-02.webp'), 'x');
      fs.writeFileSync(path.join(dir, 'frame-03.webp'), 'x');
      assert.strictEqual(videoInternals.alreadyExtracted(dir, 3), true);
    });

    runner.test('1 枚でも欠ければ false', () => {
      const dir = path.join(tmpDir, 'frames-test-2');
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(path.join(dir, 'frame-01.webp'), 'x');
      // frame-02 は無い
      fs.writeFileSync(path.join(dir, 'frame-03.webp'), 'x');
      assert.strictEqual(videoInternals.alreadyExtracted(dir, 3), false);
    });

    runner.test('formatTimestamp は分:秒形式', () => {
      assert.strictEqual(videoInternals.formatTimestamp(0), '0:00');
      assert.strictEqual(videoInternals.formatTimestamp(8.7), '0:08');
      assert.strictEqual(videoInternals.formatTimestamp(65), '1:05');
      assert.strictEqual(videoInternals.formatTimestamp(125.4), '2:05');
    });

    // =====================================================
    // x_folder_tree: buildFolderTree
    // =====================================================
    runner.section('x_folder_tree: buildFolderTree');

    runner.test('空フォルダ入力でも unfiled は必ず末尾に出る', () => {
      const tree = buildFolderTree([], [], {});
      assert.strictEqual(tree.totalFolders, 0);
      assert.strictEqual(tree.groups.length, 1);
      assert.strictEqual(tree.groups[0].kind, 'unfiled');
      assert.strictEqual(tree.groups[0].index, '1');
    });

    runner.test('forced parent でグルーピングされ remainder が children に入る', () => {
      const tree = buildFolderTree(
        [
          { id: 'f1', name: 'Claude Code' },
          { id: 'f2', name: 'Claude Code Tips' },
          { id: 'f3', name: 'Claude Code Hooks' },
        ],
        ['Claude Code'],
        {}
      );
      const forced = tree.groups.find(g => g.kind === 'forced');
      assert.ok(forced, 'forced グループが存在する');
      assert.strictEqual(forced!.label, 'Claude Code');
      assert.strictEqual(forced!.children.length, 3);
      const tips = forced!.children.find(c => c.rawName === 'Claude Code Tips');
      assert.strictEqual(tips?.remainder, 'Tips');
      const root = forced!.children.find(c => c.rawName === 'Claude Code');
      assert.strictEqual(root?.remainder, '');
    });

    runner.test('頻度優先: より多くマッチするキーワードが親になる (Code 2 > Claude Code 1)', () => {
      // 'Code' は 2 フォルダ、'Claude Code' は 1 フォルダにマッチ → Code 親が勝つ
      // 全フォルダが 'Code' 親に吸収され、'Claude Code' 親は生成されない
      const tree = buildFolderTree(
        [
          { id: 'f1', name: 'Claude Code Tips' },
          { id: 'f2', name: 'Random Code Snippet' },
        ],
        ['Code', 'Claude Code'],
        {}
      );
      const codeOnly = tree.groups.find(g => g.label === 'Code');
      const cc = tree.groups.find(g => g.label === 'Claude Code');
      assert.strictEqual(codeOnly?.children.length, 2);
      assert.strictEqual(cc, undefined, '長いキーワードでも頻度負けすれば親にならない');
    });

    runner.test('頻度同点なら長一致 tiebreak (Claude Code = Code = 1 → Claude Code 親)', () => {
      // 'Code' / 'Claude Code' どちらも 1 フォルダのみマッチ → tiebreak 長い方が勝つ
      const tree = buildFolderTree(
        [{ id: 'f1', name: 'Claude Code Tips' }],
        ['Code', 'Claude Code'],
        {}
      );
      const cc = tree.groups.find(g => g.label === 'Claude Code');
      assert.strictEqual(cc?.children.length, 1);
      assert.strictEqual(cc?.children[0].rawName, 'Claude Code Tips');
    });

    runner.test('approved mapping が Tier 2 として親パス先頭でグルーピングされる', () => {
      const tree = buildFolderTree(
        [
          { id: 'f1', name: 'AI Tools' },
          { id: 'f2', name: 'AI Ethics' },
        ],
        [],
        { 'AI Tools': 'AI/Tools', 'AI Ethics': 'AI/Ethics' }
      );
      const approved = tree.groups.find(g => g.kind === 'approved');
      assert.ok(approved, 'approved グループが存在する');
      assert.strictEqual(approved!.label, 'AI');
      assert.strictEqual(approved!.children.length, 2);
    });

    runner.test('動的検出 (Tier 3) は 3 件以上で起動', () => {
      const tree = buildFolderTree(
        [
          { id: 'f1', name: 'Foo Tools' },
          { id: 'f2', name: 'Foo Ethics' },
          { id: 'f3', name: 'Foo Agents' },
          { id: 'f4', name: 'Bar Tools' },
        ],
        [],
        {}
      );
      const dynamic = tree.groups.find(g => g.kind === 'dynamic');
      assert.ok(dynamic, '動的検出グループが存在する');
      assert.strictEqual(dynamic!.label.toLowerCase(), 'foo');
      assert.strictEqual(dynamic!.children.length, 3);
    });

    runner.test('orphan は (その他) としてまとめられる', () => {
      const tree = buildFolderTree(
        [
          { id: 'f1', name: 'LangChain' },
          { id: 'f2', name: 'Whatever' },
        ],
        [],
        {}
      );
      const orphan = tree.groups.find(g => g.kind === 'orphan');
      assert.ok(orphan);
      assert.strictEqual(orphan!.label, '(その他)');
      assert.strictEqual(orphan!.children.length, 2);
    });

    runner.test('通番が [1] [1.1] [1.2] ... のように一貫して付く', () => {
      const tree = buildFolderTree(
        [
          { id: 'f1', name: 'Claude Code' },
          { id: 'f2', name: 'Claude Code Tips' },
          { id: 'f3', name: 'LangChain' },
        ],
        ['Claude Code'],
        {}
      );
      // [1] forced "Claude Code" / [1.1] [1.2] / [2] orphan / [2.1] LangChain / [3] unfiled
      const forced = tree.groups[0];
      assert.strictEqual(forced.index, '1');
      assert.strictEqual(forced.children[0].index, '1.1');
      assert.strictEqual(forced.children[1].index, '1.2');
      const last = tree.groups[tree.groups.length - 1];
      assert.strictEqual(last.kind, 'unfiled');
      assert.match(last.index, /^\d+$/);
    });

    runner.test('1 フォルダが複数の親候補にマッチしても 1 グループのみに所属する', () => {
      // forced が先に取り、Tier 3 の動的検出は残りだけを対象にする
      const tree = buildFolderTree(
        [
          { id: 'f1', name: 'Claude Code Tips' },
          { id: 'f2', name: 'Code Hooks' },
          { id: 'f3', name: 'Code Plugins' },
          { id: 'f4', name: 'Code Notes' },
        ],
        ['Claude Code'],
        {}
      );
      const allChildren = tree.groups.flatMap(g => g.children.map(c => c.folderId));
      const counts = new Map<string | null, number>();
      for (const id of allChildren) counts.set(id, (counts.get(id) ?? 0) + 1);
      for (const [id, n] of counts) {
        assert.strictEqual(n, 1, `folder ${id} が ${n} 回登場している (重複)`);
      }
    });

    runner.section('x_folder_tree: renderFolderTree');

    runner.test('レンダリング結果に [1] のような通番と総件数が含まれる', () => {
      const tree = buildFolderTree(
        [{ id: 'f1', name: 'Claude Code Tips' }],
        ['Claude Code'],
        {}
      );
      const out = renderFolderTree(tree);
      assert.ok(out.includes('[1]'));
      assert.ok(out.includes('Claude Code'));
      assert.ok(out.includes('合計 1 フォルダ'));
      assert.ok(out.includes('_Unfiled'));
      assert.ok(out.includes('q'), 'ヘルプに q が出る');
    });

    runner.test('remainder が空のフォルダは "(= ...)" suffix を出さない', () => {
      const tree = buildFolderTree(
        [{ id: 'f1', name: 'Claude Code' }],
        ['Claude Code'],
        {}
      );
      const out = renderFolderTree(tree);
      // "Claude Code" 単独行に "(= " が付くと冗長になるので付けない
      const lines = out.split('\n').filter(l => l.includes('[1.1]'));
      assert.strictEqual(lines.length, 1);
      assert.ok(!lines[0].includes('(='));
    });

    // =====================================================
    // x_interactive_picker: parseSelection
    // =====================================================
    runner.section('x_interactive_picker: parseSelection');

    function makeTree() {
      return buildFolderTree(
        [
          { id: 'cc-root', name: 'Claude Code' },
          { id: 'cc-tips', name: 'Claude Code Tips' },
          { id: 'cc-hooks', name: 'Claude Code Hooks' },
          { id: 'lang', name: 'LangChain' },
        ],
        ['Claude Code'],
        {}
      );
      // 期待 Tree: [1] forced Claude Code (3 children) / [2] orphan (1 child) / [3] unfiled
    }

    runner.test('"q" は cancelled=true', () => {
      const r = parseSelection('q', makeTree());
      assert.strictEqual(r.cancelled, true);
      assert.strictEqual(r.folderIds.length, 0);
    });

    runner.test('"all" で全フォルダ + Unfiled が選択される', () => {
      const r = parseSelection('all', makeTree());
      assert.strictEqual(r.cancelled, false);
      assert.strictEqual(r.folderIds.length, 4);
      assert.strictEqual(r.includeUnfiled, true);
    });

    runner.test('グループ単独 "1" で配下の全 child が選ばれる', () => {
      const r = parseSelection('1', makeTree());
      assert.deepStrictEqual(r.folderIds.sort(), ['cc-hooks', 'cc-root', 'cc-tips']);
      assert.strictEqual(r.includeUnfiled, false);
    });

    runner.test('サブフォルダ "1.2" で 1 件のみ選ばれる', () => {
      const r = parseSelection('1.2', makeTree());
      assert.strictEqual(r.folderIds.length, 1);
      // children は入力順なので 1.1=cc-root, 1.2=cc-tips
      assert.strictEqual(r.folderIds[0], 'cc-tips');
    });

    runner.test('範囲 "1-2" で複数グループの child を集約', () => {
      const r = parseSelection('1-2', makeTree());
      // [1] = 3 children, [2] = LangChain
      assert.strictEqual(r.folderIds.length, 4);
    });

    runner.test('カンマ区切り "1.1, 2" で複合指定', () => {
      const r = parseSelection('1.1, 2', makeTree());
      assert.strictEqual(r.folderIds.length, 2);
      assert.ok(r.folderIds.includes('cc-root'));
      assert.ok(r.folderIds.includes('lang'));
    });

    runner.test('unfiled グループ番号を選ぶと includeUnfiled=true (folder ID は付かない)', () => {
      const tree = makeTree();
      const unfiledIdx = tree.groups.find(g => g.kind === 'unfiled')!.index;
      const r = parseSelection(unfiledIdx, tree);
      assert.strictEqual(r.includeUnfiled, true);
      assert.strictEqual(r.folderIds.length, 0);
    });

    runner.test('重複指定は dedupe される', () => {
      const r = parseSelection('1, 1.1, 1.1', makeTree());
      // [1] が cc-root/cc-tips/cc-hooks を全て入れた後、1.1 (=cc-root) を追加 → dedupe
      assert.strictEqual(r.folderIds.length, 3);
    });

    runner.test('存在しないグループ番号は例外', () => {
      assert.throws(() => parseSelection('99', makeTree()), /存在しません/);
    });

    runner.test('存在しないサブ番号は例外', () => {
      assert.throws(() => parseSelection('1.99', makeTree()), /存在しません/);
    });

    runner.test('不正トークンは例外', () => {
      assert.throws(() => parseSelection('abc', makeTree()), /不正な入力/);
    });

    runner.test('空入力は例外', () => {
      assert.throws(() => parseSelection('', makeTree()), /空/);
    });

    runner.test('範囲の to < from は例外', () => {
      assert.throws(() => parseSelection('5-2', makeTree()), /不正な範囲/);
    });

    runner.test('unfiled の "n.1" 形式は吸収される (ergonomics)', () => {
      const tree = makeTree();
      const unfiledIdx = tree.groups.find(g => g.kind === 'unfiled')!.index;
      const r = parseSelection(`${unfiledIdx}.1`, tree);
      assert.strictEqual(r.includeUnfiled, true);
      assert.strictEqual(r.folderIds.length, 0);
    });

    runner.test('unfiled の "n.2" 以降は入力ミスとして例外', () => {
      const tree = makeTree();
      const unfiledIdx = tree.groups.find(g => g.kind === 'unfiled')!.index;
      assert.throws(() => parseSelection(`${unfiledIdx}.2`, tree), /存在しません/);
      assert.throws(() => parseSelection(`${unfiledIdx}.999`, tree), /存在しません/);
    });

    // =====================================================
    // x_bookmarks_api: fetchBookmarksViaApi (selectedFolders + includeUnfiled)
    // =====================================================
    runner.section('x_bookmarks_api: selectedFolders + includeUnfiled');

    await runner.testAsync('selectedFolders + includeUnfiled: 他フォルダのツイートを Unfiled に誤分類しない (Codex P1)', async () => {
      // セットアップ: トークン保存 + 環境変数
      saveTokens({
        access_token: 'fake-token',
        refresh_token: 'fake-refresh',
        expires_in: 7200,
        obtained_at: new Date().toISOString(),
      });
      const prevClientId = process.env.X_CLIENT_ID;
      process.env.X_CLIENT_ID = 'test-client';

      try {
        // 想定シナリオ:
        //   X 側に folder A (id=fa) と folder B (id=fb)
        //   tweet T_A1 は folder A に
        //   tweet T_B1 は folder B に
        //   tweet T_U1 はどのフォルダにも未割当
        //   /bookmarks (Unfiled extraction) は T_A1 / T_B1 / T_U1 すべて返す
        //
        // ユーザーは folder A だけ選択 + includeUnfiled=true
        // 期待:
        //   results に T_A1 (folder A 由来) と T_U1 (Unfiled) のみ含まれる
        //   T_B1 は folderTweetIds に積まれて Unfiled 扱いされない
        //   (修正前は T_B1 が Unfiled として results に紛れ込んでいた)

        const callLog: string[] = [];
        const mockFetch: typeof fetch = (async (input: any) => {
          const url = typeof input === 'string' ? input : input.url;
          callLog.push(url);
          const respond = (body: any, status = 200) => new Response(JSON.stringify(body), {
            status,
            headers: { 'content-type': 'application/json' },
          });
          if (url.includes('/users/me')) {
            return respond({ data: { id: 'u1', username: 'tester' } });
          }
          // 索引: フォルダ → ツイートID列のみ
          if (url.includes('/bookmarks/folders/fa')) {
            return respond({ data: [{ id: 'T_A1' }] });
          }
          if (url.includes('/bookmarks/folders/fb')) {
            return respond({ data: [{ id: 'T_B1' }] });
          }
          if (url.includes('/bookmarks/folders')) {
            // フォルダ一覧 (他フォルダ列挙で叩かれる)
            return respond({
              data: [{ id: 'fa', name: 'FolderA' }, { id: 'fb', name: 'FolderB' }],
            });
          }
          // ハイドレーション: /2/tweets?ids=... (folder A 由来 ID のみ来る想定)
          if (url.includes('/tweets?')) {
            return respond({
              data: [{ id: 'T_A1', text: 'in folder A', author_id: 'u1' }],
              includes: { users: [{ id: 'u1', name: 'A', username: 'a' }] },
            });
          }
          if (url.includes('/bookmarks')) {
            // /users/:id/bookmarks (Unfiled 抽出元) は従来通り本文込み
            return respond({
              data: [
                { id: 'T_A1', text: 'in folder A', author_id: 'u1' },
                { id: 'T_B1', text: 'in folder B', author_id: 'u1' },
                { id: 'T_U1', text: 'truly unfiled', author_id: 'u1' },
              ],
              includes: { users: [{ id: 'u1', name: 'A', username: 'a' }] },
            });
          }
          throw new Error(`unexpected fetch url: ${url}`);
        }) as any;

        const results = await fetchBookmarksViaApi({
          selectedFolders: [{ id: 'fa', name: 'FolderA' }],
          includeUnfiled: true,
          fetchFn: mockFetch,
        });

        const tweetIds = results.map(r => r.xTweetId).sort();
        // T_A1 (folder A から) + T_U1 (Unfiled) のみ
        // T_B1 は別フォルダにあるので Unfiled として誤分類されてはならない
        assert.deepStrictEqual(
          tweetIds,
          ['T_A1', 'T_U1'],
          `T_B1 が Unfiled に誤分類されている: ${JSON.stringify(tweetIds)}`
        );

        // T_U1 は Unfiled grouping
        const tu1 = results.find(r => r.xTweetId === 'T_U1');
        assert.strictEqual(tu1?.xFolderName, '_Unfiled');
        // T_A1 は FolderA grouping
        const ta1 = results.find(r => r.xTweetId === 'T_A1');
        assert.strictEqual(ta1?.xFolderName, 'FolderA');

        // /bookmarks/folders/fb が ID 収集目的で叩かれているはず
        assert.ok(
          callLog.some(u => u.includes('/bookmarks/folders/fb')),
          `他フォルダ fb の ID 収集が走っていない: ${callLog.join(', ')}`
        );
      } finally {
        if (prevClientId === undefined) delete process.env.X_CLIENT_ID;
        else process.env.X_CLIENT_ID = prevClientId;
      }
    });

    await runner.testAsync('selectedFolders + includeUnfiled=false: 他フォルダ列挙は行わない (コスト節約)', async () => {
      saveTokens({
        access_token: 'fake-token',
        refresh_token: 'fake-refresh',
        expires_in: 7200,
        obtained_at: new Date().toISOString(),
      });
      const prevClientId = process.env.X_CLIENT_ID;
      process.env.X_CLIENT_ID = 'test-client';

      try {
        const callLog: string[] = [];
        const mockFetch: typeof fetch = (async (input: any) => {
          const url = typeof input === 'string' ? input : input.url;
          callLog.push(url);
          const respond = (body: any) => new Response(JSON.stringify(body), {
            status: 200, headers: { 'content-type': 'application/json' },
          });
          if (url.includes('/users/me')) return respond({ data: { id: 'u1', username: 'tester' } });
          // 索引: ID 列のみ
          if (url.includes('/bookmarks/folders/fa')) {
            return respond({ data: [{ id: 'T_A1' }] });
          }
          // ハイドレーション
          if (url.includes('/tweets?')) {
            return respond({
              data: [{ id: 'T_A1', text: 'a', author_id: 'u1' }],
              includes: { users: [{ id: 'u1', username: 'a', name: 'A' }] },
            });
          }
          throw new Error(`unexpected fetch url: ${url}`);
        }) as any;

        await fetchBookmarksViaApi({
          selectedFolders: [{ id: 'fa', name: 'FolderA' }],
          includeUnfiled: false,
          fetchFn: mockFetch,
        });

        // フォルダ一覧 (/bookmarks/folders) も /bookmarks (Unfiled) も叩かれない
        assert.ok(
          !callLog.some(u => u.match(/\/bookmarks\/folders($|\?)/)),
          `余分なフォルダ一覧コール: ${callLog.join(', ')}`
        );
        assert.ok(
          !callLog.some(u => u.match(/\/bookmarks(\?|$)/) && !u.includes('/folders/')),
          `余分な Unfiled コール: ${callLog.join(', ')}`
        );
      } finally {
        if (prevClientId === undefined) delete process.env.X_CLIENT_ID;
        else process.env.X_CLIENT_ID = prevClientId;
      }
    });

    // =====================================================
    // x_folder_mapper: prioritizeForcedParents (occurrence-frequency)
    // =====================================================
    runner.section('x_folder_mapper: prioritizeForcedParents');

    runner.test('出現頻度が多いキーワードが優先される', () => {
      // "Code" は 3 フォルダ, "Claude Code" は 1 フォルダにマッチ → "Code" が先頭
      const sorted = prioritizeForcedParents(
        ['Claude Code', 'Code'],
        ['Claude Code Tips', 'Random Code', 'My Code Notes', 'Code Garden']
      );
      assert.strictEqual(sorted[0], 'Code', `expected Code first, got ${sorted.join(',')}`);
    });

    runner.test('同点なら長いキーワードが優先 (tiebreak)', () => {
      const sorted = prioritizeForcedParents(
        ['Code', 'Claude Code'],
        ['Claude Code', 'Claude Code Tips']  // 両方 2 件マッチ
      );
      assert.strictEqual(sorted[0], 'Claude Code');
    });

    runner.test('長さも同点なら配列順 (元の優先度を尊重)', () => {
      const sorted = prioritizeForcedParents(
        ['BB', 'AA'],
        ['AAX', 'BBX']
      );
      assert.strictEqual(sorted[0], 'BB');
    });

    runner.test('空文字キーワードは除外される', () => {
      const sorted = prioritizeForcedParents(['', '  ', 'AI'], ['AI Agent']);
      assert.deepStrictEqual(sorted, ['AI']);
    });

    runner.test('mapFolderToVaultPath は allFolderNames があれば頻度優先で動く', () => {
      // forced=['Claude Code', 'Code']
      //   "Claude Code Notes" は両方マッチ可能
      //   全体 ["Claude Code Notes", "Random Code", "Code Hub"] では Code が 3 件 / Claude Code は 1 件
      //   → 頻度優先なら "Code Hub" 等は Code 親に落ち、"Claude Code Notes" も Code 親 (Claude Code よりスコア高)
      assert.strictEqual(
        mapFolderToVaultPath(
          'Claude Code Notes',
          ['Claude Code', 'Code'],
          {},
          { allFolderNames: ['Claude Code Notes', 'Random Code', 'Code Hub'] }
        ),
        'Code/Claude Notes'
      );
    });

    runner.test('mapFolderToVaultPath は allFolderNames 無しなら従来通り長さ優先', () => {
      // 後方互換: 既存呼出しは挙動を変えない
      assert.strictEqual(
        mapFolderToVaultPath('Claude Code Tips', ['Claude Code', 'Code'], {}),
        'Claude Code/Tips'
      );
    });

    // =====================================================
    // x_session_registry
    // =====================================================
    runner.section('x_session_registry');

    runner.test('newSessionId は UUID v4 形式', () => {
      const id = newSessionId();
      assert.match(id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
      assert.notStrictEqual(newSessionId(), id);
    });

    runner.test('writeSessionMarker / readSessionMarker は roundtrip する', () => {
      const dir = path.join(tmpDir, 'marker-test-1');
      fs.mkdirSync(dir, { recursive: true });
      const sessionId = newSessionId();
      writeSessionMarker(dir, {
        session_id: sessionId,
        x_folder_id: 'fa',
        x_folder_name: 'Folder A',
        created_at: new Date().toISOString(),
        last_synced_at: new Date().toISOString(),
      });
      const read = readSessionMarker(dir);
      assert.strictEqual(read?.session_id, sessionId);
      assert.strictEqual(read?.x_folder_id, 'fa');
    });

    runner.test('writeSessionMarker は既存マーカーの session_id を維持する (idempotent)', () => {
      const dir = path.join(tmpDir, 'marker-test-2');
      fs.mkdirSync(dir, { recursive: true });
      const original = newSessionId();
      writeSessionMarker(dir, {
        session_id: original,
        x_folder_id: 'fa',
        x_folder_name: 'A',
        created_at: 'c1',
        last_synced_at: 't1',
      });
      // 別の session_id で上書きしようとしても、既存値が優先される
      writeSessionMarker(dir, {
        session_id: 'should-not-override',
        x_folder_id: 'fa',
        x_folder_name: 'A',
        created_at: 'c1',
        last_synced_at: 't2',
      });
      assert.strictEqual(readSessionMarker(dir)?.session_id, original);
    });

    runner.test('walkSessionMarkers は再帰走査で全マーカーを集める', () => {
      const root = path.join(tmpDir, 'walk-root');
      fs.mkdirSync(path.join(root, 'a/b/c'), { recursive: true });
      fs.mkdirSync(path.join(root, 'a/d'), { recursive: true });
      writeSessionMarker(path.join(root, 'a/b/c'), {
        session_id: newSessionId(),
        x_folder_id: 'fc',
        x_folder_name: 'C',
        created_at: 'c',
        last_synced_at: 'c',
      });
      writeSessionMarker(path.join(root, 'a/d'), {
        session_id: newSessionId(),
        x_folder_id: 'fd',
        x_folder_name: 'D',
        created_at: 'c',
        last_synced_at: 'c',
      });
      const found = walkSessionMarkers(root);
      assert.strictEqual(found.length, 2);
      const ids = found.map(f => f.marker.x_folder_id).sort();
      assert.deepStrictEqual(ids, ['fc', 'fd']);
    });

    runner.test('readSessionMarker は壊れた JSON で null を返す', () => {
      const dir = path.join(tmpDir, 'bad-marker');
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(path.join(dir, '_session.json'), '{not valid', 'utf8');
      assert.strictEqual(readSessionMarker(dir), null);
    });

    // =====================================================
    // x_session_sync
    // =====================================================
    runner.section('x_session_sync: runSyncPhase');

    /**
     * sync テストは同じ vault root (tmpDir) を共有する関係で、テスト間で
     * folder_sessions が累積する。各テスト先頭で DELETE して隔離する。
     */
    function resetSessionsForSyncTest() {
      (getDb() as any).db.exec('DELETE FROM folder_sessions');
    }

    await runner.testAsync('X 側新規フォルダ → session 発行 + marker 作成', async () => {
      resetSessionsForSyncTest();
      const baseFolder = 'Clippings/X-Bookmarks-test';
      const fakeListing = async () => ({
        userId: 'u1',
        username: 'tester',
        folders: [{ id: 'fnew', name: 'NewFolder' }],
      });
      const result = await runSyncPhase({
        baseFolder,
        fetchFolderListing: fakeListing,
      });
      assert.strictEqual(result.newSessions, 1);
      const baseAbs = path.join(tmpDir, baseFolder);
      const targetDir = path.join(baseAbs, 'NewFolder');
      assert.ok(fs.existsSync(path.join(targetDir, '_session.json')), '_session.json が作成されている');
    });

    await runner.testAsync('X 側で削除された folder → resolver=keep で status=orphaned_on_x', async () => {
      resetSessionsForSyncTest();
      const baseFolder = 'Clippings/X-Bookmarks-test-2';
      await runSyncPhase({
        baseFolder,
        fetchFolderListing: async () => ({
          userId: 'u1', username: 't',
          folders: [{ id: 'fdel', name: 'WillBeDeleted' }],
        }),
      });
      const result = await runSyncPhase({
        baseFolder,
        fetchFolderListing: async () => ({ userId: 'u1', username: 't', folders: [] }),
        resolver: { resolveOrphan: async () => 'keep' as const },
      });
      assert.strictEqual(result.orphansOnX, 1);
      const sess = getDb().listFolderSessions().find((s) => s.x_folder_name === 'WillBeDeleted');
      assert.strictEqual(sess?.status, 'orphaned_on_x');
    });

    await runner.testAsync('resolver=archive で _archived/ に移動 + status=archived', async () => {
      resetSessionsForSyncTest();
      const baseFolder = 'Clippings/X-Bookmarks-test-3';
      await runSyncPhase({
        baseFolder,
        fetchFolderListing: async () => ({
          userId: 'u1', username: 't',
          folders: [{ id: 'farch', name: 'ToArchive' }],
        }),
      });
      const baseAbs = path.join(tmpDir, baseFolder);
      assert.ok(fs.existsSync(path.join(baseAbs, 'ToArchive')));

      const result = await runSyncPhase({
        baseFolder,
        fetchFolderListing: async () => ({ userId: 'u1', username: 't', folders: [] }),
        resolver: { resolveOrphan: async () => 'archive' as const },
      });
      assert.strictEqual(result.orphansOnX, 1);
      const sess = getDb().listFolderSessions().find((s) => s.x_folder_name === 'ToArchive');
      assert.strictEqual(sess?.status, 'archived');
      assert.ok(!fs.existsSync(path.join(baseAbs, 'ToArchive')), '元のディレクトリは消えている');
      assert.ok(
        fs.existsSync(path.join(baseAbs, '_archived', sess!.session_id)),
        'archive 先に移動されている'
      );
    });

    runner.test('reassignMisplacedFiles: ファイル移動を frontmatter から検知して bookmarks 行を更新', () => {
      const baseFolder = 'Clippings/X-Bookmarks-reassign';
      const baseAbs = path.join(tmpDir, baseFolder);
      const folderA = path.join(baseAbs, 'FolderA');
      const folderB = path.join(baseAbs, 'FolderB');
      fs.mkdirSync(folderA, { recursive: true });
      fs.mkdirSync(folderB, { recursive: true });

      const sessionA = newSessionId();
      const sessionB = newSessionId();
      writeSessionMarker(folderA, {
        session_id: sessionA, x_folder_id: 'fa', x_folder_name: 'A',
        created_at: 'c', last_synced_at: 'c',
      });
      writeSessionMarker(folderB, {
        session_id: sessionB, x_folder_id: 'fb', x_folder_name: 'B',
        created_at: 'c', last_synced_at: 'c',
      });
      // sessionA に属する .md (元) を folderB に置く (= ユーザーが移動した想定)
      const mdContent = `---
title: "test"
session_id: "${sessionA}"
x_tweet_id: "12345"
---
body
`;
      const mdPath = path.join(folderB, 'moved.md');
      fs.writeFileSync(mdPath, mdContent, 'utf8');

      // 事前 DB row 投入
      getDb().upsertBookmark({
        tweetId: '12345',
        url: 'https://x.com/u/status/12345',
        sessionId: sessionA,
        vaultPath: path.join(baseFolder, 'FolderA', 'orig.md'),
      });

      const count = syncInternals.reassignMisplacedFiles(baseAbs);
      assert.strictEqual(count, 1);

      // .md frontmatter が sessionB に書き換わっている
      const updated = fs.readFileSync(mdPath, 'utf8');
      assert.ok(updated.includes(`session_id: "${sessionB}"`), '.md が新 session_id に書き換わる');
      // bookmarks 行も sessionB に更新されている
      const row = (getDb() as any).db.prepare(
        'SELECT session_id FROM bookmarks WHERE tweet_id = ?'
      ).get('12345') as { session_id: string };
      assert.strictEqual(row.session_id, sessionB);
    });

    // =====================================================
    // x_session_ai: parseAiOutput
    // =====================================================
    runner.section('x_session_ai: parseAiOutput');

    runner.test('正常な "RECOMMEND: keep" 応答をパース', () => {
      const v = aiInternals.parseAiOutput('RECOMMEND: keep\n最近 .md が更新されており参照価値が高い。');
      assert.strictEqual(v.recommend, 'keep');
      assert.strictEqual(v.source, 'ai');
      assert.ok(v.reason.includes('参照価値'));
    });

    runner.test('正常な "RECOMMEND: archive" 応答をパース', () => {
      const v = aiInternals.parseAiOutput('RECOMMEND: archive\n古いフォルダで配下に新規ポストもない。');
      assert.strictEqual(v.recommend, 'archive');
      assert.strictEqual(v.source, 'ai');
    });

    runner.test('フォーマット不正は keep にフォールバック', () => {
      const v = aiInternals.parseAiOutput('わからない');
      assert.strictEqual(v.recommend, 'keep');
      assert.strictEqual(v.source, 'fallback');
    });

    runner.test('空応答は keep にフォールバック', () => {
      const v = aiInternals.parseAiOutput('');
      assert.strictEqual(v.recommend, 'keep');
      assert.strictEqual(v.source, 'fallback');
    });

    runner.test('大小文字は無視 (RECOMMEND: ARCHIVE も拾う)', () => {
      const v = aiInternals.parseAiOutput('RECOMMEND: ARCHIVE\n理由。');
      assert.strictEqual(v.recommend, 'archive');
    });

    // =====================================================
    // x_session_ai: createInteractiveOrphanResolver (Codex P1)
    // =====================================================
    runner.section('x_session_ai: interactive resolver');

    const fakeOrphan = () => ({
      session: {
        session_id: 'sess-test',
        x_folder_id: 'fa',
        x_folder_name: 'Test',
        vault_path: 'Clippings/X-Bookmarks/Test',
        parent_keyword: null,
        status: 'active' as const,
        created_at: 'c',
        last_synced_at: 't',
      },
      vaultAbsoluteDir: '/tmp/Test',
      mdCount: 5,
      latestPostDate: '2026-04-01',
    });

    await runner.testAsync('Codex P1: 空入力では AI 推奨に関わらず keep にフォールバックする', async () => {
      const prevDisable = process.env.X_SESSION_AI_DISABLE;
      process.env.X_SESSION_AI_DISABLE = 'true'; // 実 LLM を呼ばずに verdict 固定
      try {
        const askEmpty = async () => '';
        const resolver = createInteractiveOrphanResolver(askEmpty);
        const result = await resolver.resolveOrphan(fakeOrphan());
        assert.strictEqual(
          result, 'keep',
          'AI fallback verdict が keep の場合も含めて、空入力は明示的に keep にする'
        );
      } finally {
        if (prevDisable === undefined) delete process.env.X_SESSION_AI_DISABLE;
        else process.env.X_SESSION_AI_DISABLE = prevDisable;
      }
    });

    await runner.testAsync('明示 "a" 入力なら archive を返す', async () => {
      const prevDisable = process.env.X_SESSION_AI_DISABLE;
      process.env.X_SESSION_AI_DISABLE = 'true';
      try {
        const resolver = createInteractiveOrphanResolver(async () => 'a');
        assert.strictEqual(await resolver.resolveOrphan(fakeOrphan()), 'archive');
      } finally {
        if (prevDisable === undefined) delete process.env.X_SESSION_AI_DISABLE;
        else process.env.X_SESSION_AI_DISABLE = prevDisable;
      }
    });

    await runner.testAsync('明示 "s" 入力なら skip を返す', async () => {
      const prevDisable = process.env.X_SESSION_AI_DISABLE;
      process.env.X_SESSION_AI_DISABLE = 'true';
      try {
        const resolver = createInteractiveOrphanResolver(async () => 's');
        assert.strictEqual(await resolver.resolveOrphan(fakeOrphan()), 'skip');
      } finally {
        if (prevDisable === undefined) delete process.env.X_SESSION_AI_DISABLE;
        else process.env.X_SESSION_AI_DISABLE = prevDisable;
      }
    });

    // =====================================================
    // x_session_sync: archive failure rollback (Codex P2)
    // =====================================================
    runner.section('x_session_sync: archive failure rollback');

    await runner.testAsync('Codex P2: archive 先が既存なら status は orphaned_on_x のまま (DB が嘘をつかない)', async () => {
      resetSessionsForSyncTest();
      const baseFolder = 'Clippings/X-Bookmarks-archfail';
      const baseAbs = path.join(tmpDir, baseFolder);

      // 1 周目: フォルダ作成
      await runSyncPhase({
        baseFolder,
        fetchFolderListing: async () => ({
          userId: 'u1', username: 't',
          folders: [{ id: 'fconflict', name: 'Conflict' }],
        }),
      });

      // archive 先を pre-occupy (同 session_id のディレクトリが既に存在 = 衝突)
      const sessRow = getDb().listFolderSessions().find((s) => s.x_folder_name === 'Conflict')!;
      const conflictDest = path.join(baseAbs, '_archived', sessRow.session_id);
      fs.mkdirSync(conflictDest, { recursive: true });
      fs.writeFileSync(path.join(conflictDest, 'old-file.md'), 'pre-existing', 'utf8');

      // 2 周目: X 側で削除 + resolver=archive → 衝突で move 失敗
      await runSyncPhase({
        baseFolder,
        fetchFolderListing: async () => ({ userId: 'u1', username: 't', folders: [] }),
        resolver: { resolveOrphan: async () => 'archive' as const },
      });

      const after = getDb().getFolderSession(sessRow.session_id)!;
      assert.strictEqual(
        after.status, 'orphaned_on_x',
        `archive 失敗時は status=archived ではなく orphaned_on_x に倒す (実際: ${after.status})`
      );
      // 元のディレクトリは無傷で残っている
      assert.ok(
        fs.existsSync(path.join(baseAbs, 'Conflict')),
        '元フォルダは renameSync 失敗で残っているはず'
      );
      // pre-existing archive content は破壊されない
      assert.ok(
        fs.existsSync(path.join(conflictDest, 'old-file.md')),
        'archive 先の既存ファイルは破壊されない'
      );
    });

    await runner.testAsync('Codex P2: Vault に実体無し (orphaned_on_vault) でも archive 指示は status=archived', async () => {
      // vault_path が DB にあるが実体は既に消えている = 完全な orphan
      // この場合 archive 対象がないので "archived" 扱いで問題ない
      resetSessionsForSyncTest();
      const baseFolder = 'Clippings/X-Bookmarks-novault';
      const baseAbs = path.join(tmpDir, baseFolder);
      await runSyncPhase({
        baseFolder,
        fetchFolderListing: async () => ({
          userId: 'u1', username: 't',
          folders: [{ id: 'fghost', name: 'Ghost' }],
        }),
      });
      const sessRow = getDb().listFolderSessions().find((s) => s.x_folder_name === 'Ghost')!;
      // ユーザーが Vault からも消した想定
      fs.rmSync(path.join(baseAbs, 'Ghost'), { recursive: true, force: true });

      await runSyncPhase({
        baseFolder,
        fetchFolderListing: async () => ({ userId: 'u1', username: 't', folders: [] }),
        resolver: { resolveOrphan: async () => 'archive' as const },
      });
      const after = getDb().getFolderSession(sessRow.session_id)!;
      assert.strictEqual(after.status, 'archived');
    });

    // =====================================================
    // x_bookmarks_json_export
    // =====================================================
    runner.section('x_bookmarks_json_export');

    {
      const { deriveGroup, buildExportPayload, exportBookmarksJson } =
        await import('../x_bookmarks_json_export');

      runner.test('deriveGroup: <base>/<group>/<sub> → <group>', () => {
        assert.strictEqual(deriveGroup('X_Bookmarks/Claude/Tips', 'X_Bookmarks'), 'Claude');
      });
      runner.test('deriveGroup: <base> 自身 → _Unfiled', () => {
        assert.strictEqual(deriveGroup('X_Bookmarks', 'X_Bookmarks'), '_Unfiled');
      });
      runner.test('deriveGroup: base 外 → _Unfiled', () => {
        assert.strictEqual(deriveGroup('Clippings/Other', 'X_Bookmarks'), '_Unfiled');
      });
      runner.test('deriveGroup: trailing slash 許容', () => {
        assert.strictEqual(deriveGroup('X_Bookmarks/Claude/', 'X_Bookmarks'), 'Claude');
      });
      runner.test('deriveGroup: null → _Unfiled', () => {
        assert.strictEqual(deriveGroup(null, 'X_Bookmarks'), '_Unfiled');
      });

      runner.test('buildExportPayload: row schema + ai_summary 列が常に null', () => {
        // in-memory DB をセットアップして 1 件 upsert
        const db = new XBookmarksDb(':memory:');
        db.upsertBookmark({
          tweetId: 'tw1',
          url: 'https://x.com/foo/status/1',
          author: 'foo',
          tweetText: 'hello',
          createdAt: '2026-05-01',
          xFolderName: 'Claude Code Tips',
          vaultPath: 'X_Bookmarks/Claude Code/Tips',
          engagementLikes: 3,
          engagementRetweets: 1,
          engagementReplies: 0,
        });
        const payload = buildExportPayload({ db, baseFolder: 'X_Bookmarks' });
        assert.strictEqual(payload.version, 1);
        assert.strictEqual(payload.base_folder, 'X_Bookmarks');
        assert.strictEqual(payload.rows.length, 1);
        const row = payload.rows[0];
        assert.strictEqual(row.tweet_id, 'tw1');
        assert.strictEqual(row.author, 'foo');
        assert.strictEqual(row.group, 'Claude Code');
        assert.strictEqual(row.engagement_likes, 3);
        assert.strictEqual(row.ai_summary, null, 'AI 要約は常に null (列のみ確保)');
        assert.ok(typeof row.added_at === 'string' && row.added_at.length > 0,
          'added_at は INSERT 時にセットされる');
        db.close();
      });

      runner.test('upsertBookmark: re-upsert は added_at を保持 / saved_at は更新', async () => {
        const db = new XBookmarksDb(':memory:');
        db.upsertBookmark({
          tweetId: 'reup',
          url: 'https://x.com/reup/status/1',
          xFolderName: 'F',
          vaultPath: 'X_Bookmarks/F',
        });
        const first = buildExportPayload({ db, baseFolder: 'X_Bookmarks' }).rows[0];
        // ISO ms 解像度の差を担保するため最低 5ms 待つ
        await new Promise(r => setTimeout(r, 5));
        db.upsertBookmark({
          tweetId: 'reup',
          url: 'https://x.com/reup/status/1',
          xFolderName: 'F',
          vaultPath: 'X_Bookmarks/F',
          tweetText: 'updated body',
        });
        const second = buildExportPayload({ db, baseFolder: 'X_Bookmarks' }).rows[0];
        assert.strictEqual(second.added_at, first.added_at, 'added_at は不変');
        assert.notStrictEqual(second.saved_at, first.saved_at, 'saved_at は再 upsert で更新');
        assert.strictEqual(second.tweet_text, 'updated body');
        db.close();
      });

      runner.test('exportBookmarksJson: atomic 書き出し ( .tmp 残らず JSON parseable )', () => {
        const subVault = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-xbm-export-'));
        try {
          const db = new XBookmarksDb(':memory:');
          db.upsertBookmark({
            tweetId: 'tw2',
            url: 'https://x.com/bar/status/2',
            xFolderName: 'F',
            vaultPath: 'X_Bookmarks/F',
          });
          const payload = buildExportPayload({ db, baseFolder: 'X_Bookmarks' });
          const out = exportBookmarksJson({
            db,
            vaultRoot: subVault,
            baseFolder: 'X_Bookmarks',
            payload,
          });
          assert.ok(fs.existsSync(out), 'JSON ファイル存在');
          assert.ok(!fs.existsSync(out + '.tmp'), '.tmp が残らない');
          const parsed = JSON.parse(fs.readFileSync(out, 'utf8'));
          assert.strictEqual(parsed.rows.length, 1);
          db.close();
        } finally {
          fs.rmSync(subVault, { recursive: true, force: true });
        }
      });
    }

    // =====================================================
    // x_group_page_template
    // =====================================================
    runner.section('x_group_page_template');

    {
      const { renderGroupPage, replaceAutoBlock, SENTINEL_START, SENTINEL_END } =
        await import('../x_group_page_template');
      const args = { group: 'Claude', jsonRelativePath: 'X_Bookmarks/.x_bookmarks.json' };

      runner.test('renderGroupPage: header + sentinel + dataviewjs を含む', () => {
        const md = renderGroupPage(args);
        assert.ok(md.startsWith('# Claude\n'), 'h1 header');
        assert.ok(md.includes(SENTINEL_START), 'start sentinel');
        assert.ok(md.includes(SENTINEL_END), 'end sentinel');
        assert.ok(md.includes('```dataviewjs'), 'dataviewjs fence');
        assert.ok(md.includes('summary'), 'AI summary 列が常にある');
        assert.ok(md.includes('X_Bookmarks/.x_bookmarks.json'), 'JSON path');
      });

      runner.test('renderGroupPage: 追加日列 + クリック式ソートを含む', () => {
        const md = renderGroupPage(args);
        assert.ok(md.includes('"added"'), 'added (追加日) 列ラベル');
        assert.ok(md.includes('added_at'), 'JSON キー added_at');
        assert.ok(md.includes('th.onclick'), '列ヘッダクリックハンドラ');
        assert.ok(md.includes('sortDesc = !sortDesc'), '昇順/降順トグル');
        assert.ok(md.includes('▼') && md.includes('▲'), 'ソート方向マーカー');
      });

      runner.test('replaceAutoBlock: sentinel 区間だけ差し替え (ユーザー本文保護)', () => {
        const existing = `# Claude\n\nユーザーメモ\n\n${SENTINEL_START}\nOLD\n${SENTINEL_END}\n\n下のメモ\n`;
        const updated = replaceAutoBlock(existing, args);
        assert.ok(updated.includes('ユーザーメモ'), '前段ユーザー本文保護');
        assert.ok(updated.includes('下のメモ'), '後段ユーザー本文保護');
        assert.ok(!updated.includes('OLD'), '旧 auto block は除去');
        assert.ok(updated.includes('```dataviewjs'), '新 auto block 挿入');
      });

      runner.test('replaceAutoBlock: sentinel 無し → 末尾に追記', () => {
        const existing = `# Claude\n\nユーザーが手書きしたメモ\n`;
        const updated = replaceAutoBlock(existing, args);
        assert.ok(updated.includes('ユーザーが手書きしたメモ'), 'ユーザー本文保護');
        assert.ok(updated.includes(SENTINEL_START), '新規 sentinel 追加');
      });

      runner.test('replaceAutoBlock: idempotent (2 回適用しても出力は安定)', () => {
        const existing = renderGroupPage(args);
        const once = replaceAutoBlock(existing, args);
        const twice = replaceAutoBlock(once, args);
        assert.strictEqual(once, twice, '2 回適用しても変化しない');
      });
    }

    // =====================================================
    // x_group_page_writer
    // =====================================================
    runner.section('x_group_page_writer');

    {
      const { writeAllGroupPages } = await import('../x_group_page_writer');
      const writerVault = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-xbm-writer-'));
      try {
        const payload = {
          version: 1 as const,
          generated_at: new Date().toISOString(),
          base_folder: 'X_Bookmarks',
          rows: [
            {
              tweet_id: 'a', url: 'https://x.com/a/status/1', author: null,
              tweet_text: null, note_tweet_text: null, created_at: null, saved_at: '',
              added_at: null,
              engagement_likes: null, engagement_retweets: null, engagement_replies: null,
              x_folder_name: null, vault_path: 'X_Bookmarks/Claude/Tips',
              group: 'Claude', ai_summary: null,
            },
            {
              tweet_id: 'b', url: 'https://x.com/b/status/2', author: null,
              tweet_text: null, note_tweet_text: null, created_at: null, saved_at: '',
              added_at: null,
              engagement_likes: null, engagement_retweets: null, engagement_replies: null,
              x_folder_name: null, vault_path: 'X_Bookmarks/UI_LP作成',
              group: 'UI_LP作成', ai_summary: null,
            },
          ],
        };

        runner.test('writeAllGroupPages: 新規グループは created', () => {
          const results = writeAllGroupPages({
            vaultRoot: writerVault,
            baseFolder: 'X_Bookmarks',
            payload,
          });
          assert.strictEqual(results.length, 2);
          for (const r of results) assert.strictEqual(r.action, 'created');
          assert.ok(fs.existsSync(path.join(writerVault, 'X_Bookmarks', 'Claude', 'Claude.md')));
          assert.ok(fs.existsSync(path.join(writerVault, 'X_Bookmarks', 'UI_LP作成', 'UI_LP作成.md')));
        });

        runner.test('writeAllGroupPages: 2 回目は unchanged (idempotent)', () => {
          const results = writeAllGroupPages({
            vaultRoot: writerVault,
            baseFolder: 'X_Bookmarks',
            payload,
          });
          for (const r of results) assert.strictEqual(r.action, 'unchanged');
        });

        runner.test('writeSingleGroupPage: sentinel 無し既存ファイルは appended', () => {
          // ユーザーが手書きで MD を置いていた想定
          const handwritten = path.join(writerVault, 'X_Bookmarks', 'Handwritten');
          fs.mkdirSync(handwritten, { recursive: true });
          fs.writeFileSync(path.join(handwritten, 'Handwritten.md'),
            '# Handwritten\n\nユーザーの手書きメモ\n', 'utf8');
          const handPayload = {
            ...payload,
            rows: [{
              tweet_id: 'h', url: 'https://x.com/h/status/1', author: null,
              tweet_text: null, note_tweet_text: null, created_at: null, saved_at: '',
              added_at: null,
              engagement_likes: null, engagement_retweets: null, engagement_replies: null,
              x_folder_name: null, vault_path: 'X_Bookmarks/Handwritten',
              group: 'Handwritten', ai_summary: null,
            }],
          };
          const results = writeAllGroupPages({
            vaultRoot: writerVault,
            baseFolder: 'X_Bookmarks',
            payload: handPayload,
          });
          assert.strictEqual(results[0].action, 'appended');
          const content = fs.readFileSync(path.join(handwritten, 'Handwritten.md'), 'utf8');
          assert.ok(content.includes('ユーザーの手書きメモ'), '手書き本文は保護される');
          assert.ok(content.includes('```dataviewjs'), 'auto block が追記される');
        });

        runner.test('writeSingleGroupPage: ".." を含む group は invalid-group で拒否', () => {
          const evilPayload = {
            ...payload,
            rows: [{
              tweet_id: 'evil', url: 'https://x.com/evil/status/1', author: null,
              tweet_text: null, note_tweet_text: null, created_at: null, saved_at: '',
              added_at: null,
              engagement_likes: null, engagement_retweets: null, engagement_replies: null,
              x_folder_name: null, vault_path: 'X_Bookmarks/../escape',
              group: '..', ai_summary: null,
            }],
          };
          const results = writeAllGroupPages({
            vaultRoot: writerVault,
            baseFolder: 'X_Bookmarks',
            payload: evilPayload,
          });
          assert.strictEqual(results[0].action, 'invalid-group');
          assert.ok(!fs.existsSync(path.join(writerVault, '..md')),
            'base 外への path traversal は発生しない');
        });
      } finally {
        fs.rmSync(writerVault, { recursive: true, force: true });
      }
    }

    // =====================================================
    // x_rule_deriver
    // =====================================================
    runner.section('x_rule_deriver');

    {
      const { deriveForcedParents, writeForcedParents } =
        await import('../x_rule_deriver');

      runner.test('deriveForcedParents: group に 2+ session があれば候補化', () => {
        const sessions = [
          { session_id: 's1', x_folder_id: 'f1', x_folder_name: 'Claude Code Tips',
            vault_path: 'X_Bookmarks/Claude Code/Tips', parent_keyword: null,
            status: 'active' as const, created_at: '', last_synced_at: '' },
          { session_id: 's2', x_folder_id: 'f2', x_folder_name: 'Claude Code Hooks',
            vault_path: 'X_Bookmarks/Claude Code/Hooks', parent_keyword: null,
            status: 'active' as const, created_at: '', last_synced_at: '' },
          { session_id: 's3', x_folder_id: 'f3', x_folder_name: 'Standalone',
            vault_path: 'X_Bookmarks/Standalone', parent_keyword: null,
            status: 'active' as const, created_at: '', last_synced_at: '' },
        ];
        const r = deriveForcedParents({
          sessions, baseFolder: 'X_Bookmarks', forcedParents: [],
        });
        assert.deepStrictEqual(r.proposed, ['Claude Code']);
        assert.deepStrictEqual(r.toAdd, ['Claude Code']);
        assert.deepStrictEqual(r.evidence.get('Claude Code'),
          ['Claude Code Hooks', 'Claude Code Tips']);
      });

      runner.test('deriveForcedParents: Claude / Claude Code / ClaudeCode は別キーワード', () => {
        const sessions = [
          { session_id: 'a1', x_folder_id: 'x1', x_folder_name: 'Claude Memos',
            vault_path: 'X_Bookmarks/Claude/Memos', parent_keyword: null,
            status: 'active' as const, created_at: '', last_synced_at: '' },
          { session_id: 'a2', x_folder_id: 'x2', x_folder_name: 'Claude Notes',
            vault_path: 'X_Bookmarks/Claude/Notes', parent_keyword: null,
            status: 'active' as const, created_at: '', last_synced_at: '' },
          { session_id: 'b1', x_folder_id: 'y1', x_folder_name: 'Claude Code Tips',
            vault_path: 'X_Bookmarks/Claude Code/Tips', parent_keyword: null,
            status: 'active' as const, created_at: '', last_synced_at: '' },
          { session_id: 'b2', x_folder_id: 'y2', x_folder_name: 'Claude Code Hooks',
            vault_path: 'X_Bookmarks/Claude Code/Hooks', parent_keyword: null,
            status: 'active' as const, created_at: '', last_synced_at: '' },
          { session_id: 'c1', x_folder_id: 'z1', x_folder_name: 'ClaudeCode 試行',
            vault_path: 'X_Bookmarks/ClaudeCode/試行1', parent_keyword: null,
            status: 'active' as const, created_at: '', last_synced_at: '' },
          { session_id: 'c2', x_folder_id: 'z2', x_folder_name: 'ClaudeCode 別',
            vault_path: 'X_Bookmarks/ClaudeCode/試行2', parent_keyword: null,
            status: 'active' as const, created_at: '', last_synced_at: '' },
        ];
        const r = deriveForcedParents({
          sessions, baseFolder: 'X_Bookmarks', forcedParents: [],
        });
        // 順序はソート済み (localeCompare)
        assert.deepStrictEqual(r.proposed, ['Claude', 'Claude Code', 'ClaudeCode']);
      });

      runner.test('writeForcedParents: .bak を残す', () => {
        const v = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-deriver-'));
        try {
          const dir = path.join(v, '__skills', 'pipeline');
          fs.mkdirSync(dir, { recursive: true });
          fs.writeFileSync(path.join(dir, 'x_forced_parents.json'), '["OLD"]\n', 'utf8');
          writeForcedParents(['OLD', 'NEW'], { vaultRoot: v });
          assert.ok(fs.existsSync(path.join(dir, 'x_forced_parents.json.bak')));
          const cur = JSON.parse(fs.readFileSync(path.join(dir, 'x_forced_parents.json'), 'utf8'));
          assert.deepStrictEqual(cur, ['OLD', 'NEW']);
        } finally {
          fs.rmSync(v, { recursive: true, force: true });
        }
      });
    }

    // =====================================================
    // x_folder_invariant
    // =====================================================
    runner.section('x_folder_invariant');

    {
      const { listLeafFolders, checkFolderCountInvariant } =
        await import('../x_folder_invariant');
      const invVault = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-inv-'));
      try {
        // base 配下に 2 リーフ (Tips, Hooks) と 1 中間 (Claude Code) を作成
        const base = path.join(invVault, 'X_Bookmarks');
        fs.mkdirSync(path.join(base, 'Claude Code', 'Tips'), { recursive: true });
        fs.mkdirSync(path.join(base, 'Claude Code', 'Hooks'), { recursive: true });
        fs.mkdirSync(path.join(base, '_Unfiled'), { recursive: true });   // 無視
        fs.mkdirSync(path.join(base, '2026-Q1'), { recursive: true });    // 日付ベース無視

        runner.test('listLeafFolders: 中間ノードは除外、リーフのみ', () => {
          const leaves = listLeafFolders({ vaultRoot: invVault, baseFolder: 'X_Bookmarks' });
          assert.deepStrictEqual(leaves.sort(), ['Claude Code/Hooks', 'Claude Code/Tips']);
        });

        runner.test('checkFolderCountInvariant: X 数 == leaf 数で matched=true', () => {
          const check = checkFolderCountInvariant({
            vaultRoot: invVault,
            baseFolder: 'X_Bookmarks',
            xFolderNames: ['Claude Code Tips', 'Claude Code Hooks'],
          });
          assert.strictEqual(check.matched, true);
          assert.strictEqual(check.xFolderCount, 2);
          assert.strictEqual(check.leafFolderCount, 2);
        });

        runner.test('checkFolderCountInvariant: 差分があれば matched=false', () => {
          const check = checkFolderCountInvariant({
            vaultRoot: invVault,
            baseFolder: 'X_Bookmarks',
            xFolderNames: ['Claude Code Tips'],
          });
          assert.strictEqual(check.matched, false);
        });
      } finally {
        fs.rmSync(invVault, { recursive: true, force: true });
      }
    }

    // =====================================================
    // x_migrate_legacy
    // =====================================================
    runner.section('x_migrate_legacy');

    {
      const { runMigrateLegacy } = await import('../x_migrate_legacy');

      runner.test('runMigrateLegacy: 旧パス無しなら no-op', () => {
        const v = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-mig-noop-'));
        try {
          const r = runMigrateLegacy({ vaultRoot: v });
          assert.strictEqual(r.skipped, true);
          assert.strictEqual(r.filesMoved, 0);
        } finally {
          fs.rmSync(v, { recursive: true, force: true });
        }
      });

      runner.test('runMigrateLegacy: 旧パスを _Archived/ に移動 + .md count', () => {
        const v = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-mig-move-'));
        setVaultRoot(v); // db helper が vault root を見るため
        try {
          const legacy = path.join(v, 'Clippings', 'X-Bookmarks', 'Old');
          fs.mkdirSync(legacy, { recursive: true });
          fs.writeFileSync(path.join(legacy, 'x.md'), '# x', 'utf8');
          fs.writeFileSync(path.join(legacy, 'y.md'), '# y', 'utf8');

          const r = runMigrateLegacy({ vaultRoot: v });
          assert.strictEqual(r.skipped, false);
          assert.strictEqual(r.filesMoved, 2);
          assert.ok(!fs.existsSync(path.join(v, 'Clippings', 'X-Bookmarks')),
            '旧パスは消えている');
          assert.ok(r.archivedPath && fs.existsSync(r.archivedPath),
            'archive 先に存在');
          assert.ok(fs.existsSync(path.join(r.archivedPath!, 'Old', 'x.md')),
            '中身が移動されている');
        } finally {
          setVaultRoot(tmpDir); // 戻す
          fs.rmSync(v, { recursive: true, force: true });
        }
      });
    }

    // =====================================================
    // x_bookmarks_partial: 取得欠損レポート / 最新 JSON
    // =====================================================
    runner.section('x_bookmarks_partial');

    runner.test('writePartialReport: 空配列なら何もせず空文字を返す', () => {
      const result = writePartialReport([]);
      assert.strictEqual(result, '');
    });

    runner.test('writePartialReport: 提案を 分類結果レポート/ 配下に書く', () => {
      const result = writePartialReport([
        {
          xFolderId: 'fa',
          xFolderName: 'FolderA',
          fetchedCount: 7,
          reason: 'folder_next_token_unsupported',
          detectedAt: '2026-05-12T01:02:03.000Z',
        },
      ]);
      assert.ok(result.length > 0);
      assert.ok(fs.existsSync(result), `report file should exist: ${result}`);
      const body = fs.readFileSync(result, 'utf8');
      assert.ok(body.includes('FolderA'));
      assert.ok(body.includes('`fa`'));
      assert.ok(body.includes('7'));
    });

    runner.test('writePartialReport: ファイル名は claude_ prefix を持つ (対照実験)', () => {
      const result = writePartialReport([
        {
          xFolderId: 'fb',
          xFolderName: 'FolderB',
          fetchedCount: 1,
          reason: 'folder_next_token_unsupported',
          detectedAt: '2026-05-12T01:02:03.000Z',
        },
      ]);
      assert.ok(
        path.basename(result).startsWith('x_bookmarks_partial_claude_'),
        `expected claude_ prefix, got ${path.basename(result)}`
      );
    });

    runner.test('savePartialLatest / loadPartialLatest: roundtrip + 空書き出しで前回状態をクリア', () => {
      const records: PartialFolderRecord[] = [
        {
          xFolderId: 'fc',
          xFolderName: 'C',
          fetchedCount: 3,
          reason: 'folder_next_token_unsupported',
          detectedAt: '2026-05-12T00:00:00.000Z',
        },
      ];
      savePartialLatest(records);
      const loaded = loadPartialLatest();
      assert.strictEqual(loaded.length, 1);
      assert.strictEqual(loaded[0].xFolderId, 'fc');

      // 空書き出しで「解消」を表現できる (上書きセマンティクス)
      savePartialLatest([]);
      assert.deepStrictEqual(loadPartialLatest(), []);
    });

    runner.test('findPartialByXFolderId: 該当のみ返す / 不在は undefined', () => {
      const records: PartialFolderRecord[] = [
        { xFolderId: 'fa', xFolderName: 'A', fetchedCount: 1, reason: 'folder_next_token_unsupported', detectedAt: 't' },
        { xFolderId: 'fb', xFolderName: 'B', fetchedCount: 2, reason: 'folder_next_token_unsupported', detectedAt: 't' },
      ];
      assert.strictEqual(findPartialByXFolderId('fa', records)?.xFolderName, 'A');
      assert.strictEqual(findPartialByXFolderId('zz', records), undefined);
    });

    runner.test('loadPartialLatest: ファイル不在なら空配列 (例外を投げない)', () => {
      // 専用 vault root を切って未生成状態を再現
      const isolated = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-xbm-partial-empty-'));
      const prev = tmpDir;
      setVaultRoot(isolated);
      try {
        assert.deepStrictEqual(loadPartialLatest(), []);
      } finally {
        setVaultRoot(prev);
        fs.rmSync(isolated, { recursive: true, force: true });
      }
    });

    // =====================================================
    // x_bookmarks_api: partialCollector を介した next_token 検出
    // =====================================================
    runner.section('x_bookmarks_api: partialCollector');

    await runner.testAsync('partialCollector: meta.next_token を返したフォルダを記録する', async () => {
      saveTokens({
        access_token: 'fake-token',
        refresh_token: 'fake-refresh',
        expires_in: 7200,
        obtained_at: new Date().toISOString(),
      });
      const prevClientId = process.env.X_CLIENT_ID;
      process.env.X_CLIENT_ID = 'test-client';

      try {
        const mockFetch: typeof fetch = (async (input: any) => {
          const url = typeof input === 'string' ? input : input.url;
          const respond = (body: any) =>
            new Response(JSON.stringify(body), {
              status: 200,
              headers: { 'content-type': 'application/json' },
            });
          if (url.includes('/users/me')) return respond({ data: { id: 'u1', username: 't' } });
          if (url.includes('/bookmarks/folders/fa')) {
            // next_token あり = partial を記録すべき
            return respond({ data: [{ id: 'T_A1' }], meta: { next_token: 'NEXT' } });
          }
          if (url.includes('/bookmarks/folders/fb')) {
            // next_token なし = partial に入らない
            return respond({ data: [{ id: 'T_B1' }] });
          }
          if (url.includes('/tweets?')) {
            return respond({
              data: [
                { id: 'T_A1', text: 'a', author_id: 'u1' },
                { id: 'T_B1', text: 'b', author_id: 'u1' },
              ],
              includes: { users: [{ id: 'u1', username: 'u', name: 'U' }] },
            });
          }
          throw new Error(`unexpected fetch url: ${url}`);
        }) as any;

        const partial: PartialFolderRecord[] = [];
        await fetchBookmarksViaApi({
          selectedFolders: [
            { id: 'fa', name: 'FolderA' },
            { id: 'fb', name: 'FolderB' },
          ],
          includeUnfiled: false,
          fetchFn: mockFetch,
          partialCollector: partial,
        } satisfies FetchOptions);

        // FolderA だけ partial として記録される
        assert.strictEqual(partial.length, 1, `expected 1 partial, got ${JSON.stringify(partial)}`);
        assert.strictEqual(partial[0].xFolderId, 'fa');
        assert.strictEqual(partial[0].xFolderName, 'FolderA');
        assert.strictEqual(partial[0].reason, 'folder_next_token_unsupported');
        assert.strictEqual(partial[0].fetchedCount, 1);
      } finally {
        if (prevClientId === undefined) delete process.env.X_CLIENT_ID;
        else process.env.X_CLIENT_ID = prevClientId;
      }
    });

    await runner.testAsync('partialCollector 未指定: 既存挙動を壊さない', async () => {
      saveTokens({
        access_token: 'fake-token',
        refresh_token: 'fake-refresh',
        expires_in: 7200,
        obtained_at: new Date().toISOString(),
      });
      const prevClientId = process.env.X_CLIENT_ID;
      process.env.X_CLIENT_ID = 'test-client';

      try {
        const mockFetch: typeof fetch = (async (input: any) => {
          const url = typeof input === 'string' ? input : input.url;
          const respond = (body: any) =>
            new Response(JSON.stringify(body), {
              status: 200,
              headers: { 'content-type': 'application/json' },
            });
          if (url.includes('/users/me')) return respond({ data: { id: 'u1', username: 't' } });
          if (url.includes('/bookmarks/folders/fa')) {
            return respond({ data: [{ id: 'T_A1' }], meta: { next_token: 'NEXT' } });
          }
          if (url.includes('/tweets?')) {
            return respond({
              data: [{ id: 'T_A1', text: 'a', author_id: 'u1' }],
              includes: { users: [{ id: 'u1', username: 'u', name: 'U' }] },
            });
          }
          throw new Error(`unexpected fetch url: ${url}`);
        }) as any;

        // partialCollector 未指定でも throw しないこと
        const results = await fetchBookmarksViaApi({
          selectedFolders: [{ id: 'fa', name: 'FolderA' }],
          includeUnfiled: false,
          fetchFn: mockFetch,
        });
        assert.strictEqual(results.length, 1);
      } finally {
        if (prevClientId === undefined) delete process.env.X_CLIENT_ID;
        else process.env.X_CLIENT_ID = prevClientId;
      }
    });

    return runner.report();
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}