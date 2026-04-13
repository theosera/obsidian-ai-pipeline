import assert from 'node:assert';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { setVaultRoot } from '../config';
import { escapeFrontmatter, saveMarkdown } from '../storage';
import type { ArticleData } from '../types';
import { TestRunner, type TestSuiteResult } from './helpers';

export function run(): TestSuiteResult {
  const runner = new TestRunner();
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-storage-test-'));
  setVaultRoot(tmpDir);

  try {
    // =====================================================
    // escapeFrontmatter: YAMLセーフ化
    // =====================================================
    runner.section('escapeFrontmatter');

    runner.test('空文字列は空のまま', () => {
      assert.strictEqual(escapeFrontmatter(''), '');
    });

    runner.test('プレーン文字列はそのまま', () => {
      assert.strictEqual(escapeFrontmatter('Hello World'), 'Hello World');
    });

    runner.test('ダブルクォートはエスケープされる', () => {
      assert.strictEqual(escapeFrontmatter('a "quoted" word'), 'a \\"quoted\\" word');
    });

    runner.test('バックスラッシュはエスケープされる', () => {
      assert.strictEqual(escapeFrontmatter('C:\\path'), 'C:\\\\path');
    });

    runner.test('バックスラッシュとクォートが混在しても二重エスケープにならない', () => {
      // バックスラッシュを先にエスケープしてからクォートを処理するため、\\\"となる
      assert.strictEqual(escapeFrontmatter('\\"'), '\\\\\\"');
    });

    runner.test('改行はスペースに変換される', () => {
      assert.strictEqual(escapeFrontmatter('line1\nline2'), 'line1 line2');
    });

    runner.test('CRは除去される', () => {
      assert.strictEqual(escapeFrontmatter('a\r\nb'), 'a b');
    });

    runner.test('YAMLセパレータ --- は無害化される', () => {
      assert.strictEqual(escapeFrontmatter('title --- subtitle'), 'title \\-\\-\\- subtitle');
    });

    runner.test('null/undefined 入力を空文字に正規化', () => {
      assert.strictEqual(escapeFrontmatter(null as any), '');
      assert.strictEqual(escapeFrontmatter(undefined as any), '');
    });

    // =====================================================
    // saveMarkdown: エンドツーエンド
    // =====================================================
    runner.section('saveMarkdown - e2e');

    runner.test('正常な記事が vault 配下に保存される', () => {
      const article: ArticleData = {
        url: 'https://example.com/article',
        title: 'Test Article',
        content: '# Heading\n\nBody text',
        excerpt: 'Short description',
        date: '2026-04-15',
        siteName: 'Example Site',
      };
      const filePath = saveMarkdown(article, 'Engineer/LLM');
      assert.ok(fs.existsSync(filePath), 'ファイルが作成されていない');
      assert.ok(filePath.startsWith(tmpDir), 'vault 外に書き出されている');
      assert.ok(filePath.endsWith('.md'));
    });

    runner.test('保存されたファイルに有効なフロントマターが含まれる', () => {
      const article: ArticleData = {
        url: 'https://example.com/fm-test',
        title: 'Frontmatter Test',
        content: 'body',
        excerpt: 'excerpt',
        date: '2026-04-15',
        siteName: 'SiteName',
      };
      const filePath = saveMarkdown(article, 'Engineer/Test');
      const content = fs.readFileSync(filePath, 'utf8');

      assert.ok(content.startsWith('---\n'), 'フロントマター開始が正しくない');
      assert.ok(content.includes('title: "Frontmatter Test"'));
      assert.ok(content.includes('source: "https://example.com/fm-test"'));
      assert.ok(content.includes('published: 2026-04-15'));
      assert.ok(content.includes('description: "excerpt"'));
      assert.ok(content.includes('- "clippings"'));
      assert.ok(content.includes('\n---\n'), 'フロントマター終了が正しくない');
      assert.ok(content.includes('body'), '本文が含まれていない');
    });

    runner.test('タイトル内の制御文字が除去される', () => {
      const article: ArticleData = {
        url: 'https://example.com',
        title: 'Dirty\x00Title\x1f',
        content: 'x',
      };
      const filePath = saveMarkdown(article, 'Engineer/Test');
      const baseName = path.basename(filePath);
      assert.ok(!baseName.includes('\x00'));
      assert.ok(!baseName.includes('\x1f'));
      assert.ok(baseName.includes('DirtyTitle'));
    });

    runner.test('タイトル内のパス区切り文字が除去される', () => {
      const article: ArticleData = {
        url: 'https://example.com',
        title: 'Risky/../Title',
        content: 'x',
      };
      const filePath = saveMarkdown(article, 'Engineer/Test');
      const baseName = path.basename(filePath);
      // スラッシュはファイル名から除去される (ドットはファイル名に残るがパス区切りではないので安全)
      assert.ok(!baseName.includes('/'));
      assert.ok(baseName.includes('Risky'));
      assert.ok(baseName.includes('Title'));
    });

    runner.test('タイトル未指定なら "Untitled" になる', () => {
      const article: ArticleData = {
        url: 'https://example.com',
        content: 'x',
      };
      const filePath = saveMarkdown(article, 'Engineer/Test');
      assert.ok(path.basename(filePath).startsWith('Untitled'));
    });

    runner.test('不正な folderPath は Clippings/Inbox にフォールバック', () => {
      const article: ArticleData = {
        url: 'https://example.com',
        title: 'Traversal',
        content: 'x',
      };
      const filePath = saveMarkdown(article, '../../../etc/passwd');
      // ensureSafePath により Clippings/Inbox に置換される
      assert.ok(filePath.includes('Clippings'));
      assert.ok(filePath.startsWith(tmpDir), 'vault 外に書き出されている');
    });

    runner.test('タイトルの "(ダブルクォート)" が YAML エスケープされる', () => {
      const article: ArticleData = {
        url: 'https://example.com',
        title: 'This is a "quoted" title',
        content: 'x',
      };
      const filePath = saveMarkdown(article, 'Engineer/Test');
      const content = fs.readFileSync(filePath, 'utf8');
      assert.ok(
        content.includes('title: "This is a \\"quoted\\" title"'),
        'ダブルクォートがフロントマター内でエスケープされていない'
      );
    });
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }

  return runner.report();
}
