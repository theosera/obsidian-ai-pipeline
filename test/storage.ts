import assert from 'node:assert';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { setVaultRoot } from '../config';
import { escapeFrontmatter, saveMarkdown, getKnownUrls, resetKnownUrlsCache } from '../storage';
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
      // 親ディレクトリを完全一致で検証 (部分一致ではない)
      const expectedDir = path.join(tmpDir, 'Clippings', 'Inbox');
      assert.strictEqual(
        path.dirname(filePath),
        expectedDir,
        `fallback パスが Clippings/Inbox に解決されていない: ${filePath}`
      );
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

    // =====================================================
    // getKnownUrls (grep 脱依存・Node 純粋実装の回帰防止)
    // =====================================================
    runner.section('getKnownUrls - pure Node implementation');

    function makeMd(filePath: string, frontmatter: string): void {
      fs.mkdirSync(path.dirname(filePath), { recursive: true });
      fs.writeFileSync(filePath, `---\n${frontmatter}\n---\n\nbody\n`, 'utf8');
    }

    runner.test('空ディレクトリは空 Set を返す', () => {
      const sub = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-known-empty-'));
      setVaultRoot(sub);
      resetKnownUrlsCache();
      try {
        assert.strictEqual(getKnownUrls().size, 0);
      } finally {
        fs.rmSync(sub, { recursive: true, force: true });
        setVaultRoot(tmpDir);
        resetKnownUrlsCache();
      }
    });

    runner.test('.md の source: URL を frontmatter から抽出する', () => {
      const sub = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-known-basic-'));
      setVaultRoot(sub);
      resetKnownUrlsCache();
      try {
        makeMd(path.join(sub, 'Clippings', 'a.md'), 'title: "A"\nsource: "https://example.com/a"');
        makeMd(path.join(sub, 'Clippings', 'sub', 'b.md'), 'title: "B"\nsource: "https://example.com/b"');
        const urls = getKnownUrls();
        assert.ok(urls.has('https://example.com/a'), 'a.md の URL が拾えていない');
        assert.ok(urls.has('https://example.com/b'), 'サブディレクトリの URL が拾えていない');
        assert.strictEqual(urls.size, 2);
      } finally {
        fs.rmSync(sub, { recursive: true, force: true });
        setVaultRoot(tmpDir);
        resetKnownUrlsCache();
      }
    });

    runner.test('末尾スラッシュは strip される (旧 grep 実装と同挙動)', () => {
      const sub = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-known-slash-'));
      setVaultRoot(sub);
      resetKnownUrlsCache();
      try {
        makeMd(path.join(sub, 'a.md'), 'source: "https://example.com/a/"');
        const urls = getKnownUrls();
        assert.ok(urls.has('https://example.com/a'), 'トレーリングスラッシュ未 strip');
        assert.ok(!urls.has('https://example.com/a/'), 'スラッシュ付きが残っている');
      } finally {
        fs.rmSync(sub, { recursive: true, force: true });
        setVaultRoot(tmpDir);
        resetKnownUrlsCache();
      }
    });

    runner.test('クォート無しの source: 行も拾う (旧 .md 手動編集ケース)', () => {
      const sub = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-known-unquoted-'));
      setVaultRoot(sub);
      resetKnownUrlsCache();
      try {
        makeMd(path.join(sub, 'a.md'), 'source: https://example.com/unquoted');
        const urls = getKnownUrls();
        assert.ok(urls.has('https://example.com/unquoted'));
      } finally {
        fs.rmSync(sub, { recursive: true, force: true });
        setVaultRoot(tmpDir);
        resetKnownUrlsCache();
      }
    });

    runner.test('.md 以外のファイルは無視する', () => {
      const sub = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-known-non-md-'));
      setVaultRoot(sub);
      resetKnownUrlsCache();
      try {
        fs.mkdirSync(path.join(sub, 'data'), { recursive: true });
        fs.writeFileSync(path.join(sub, 'data', 'config.txt'), 'source: "https://should-not-match.com"', 'utf8');
        fs.writeFileSync(path.join(sub, 'data', 'notes.json'), '{"source": "https://json.example.com"}', 'utf8');
        makeMd(path.join(sub, 'real.md'), 'source: "https://md.example.com"');
        const urls = getKnownUrls();
        assert.ok(urls.has('https://md.example.com'));
        assert.ok(!urls.has('https://should-not-match.com'));
        assert.ok(!urls.has('https://json.example.com'));
      } finally {
        fs.rmSync(sub, { recursive: true, force: true });
        setVaultRoot(tmpDir);
        resetKnownUrlsCache();
      }
    });

    runner.test('frontmatter に source: が無い .md は素通り (空 Set)', () => {
      const sub = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-known-no-source-'));
      setVaultRoot(sub);
      resetKnownUrlsCache();
      try {
        fs.writeFileSync(path.join(sub, 'plain.md'), '---\ntitle: "no source here"\n---\nbody\n', 'utf8');
        fs.writeFileSync(path.join(sub, 'empty.md'), 'just body, no frontmatter\n', 'utf8');
        assert.strictEqual(getKnownUrls().size, 0);
      } finally {
        fs.rmSync(sub, { recursive: true, force: true });
        setVaultRoot(tmpDir);
        resetKnownUrlsCache();
      }
    });

    runner.test('symlink (ディレクトリ) は追わない (ループ防止)', () => {
      // 対象 OS が symlink をサポートしている前提のテスト。Windows でも管理者なら
      // 可能だが、テスト環境次第。エラー時は skip。
      const sub = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-known-symlink-'));
      setVaultRoot(sub);
      resetKnownUrlsCache();
      try {
        makeMd(path.join(sub, 'real', 'a.md'), 'source: "https://real.example.com"');
        // 自分自身を指す symlink (もし追ったら無限ループになる)
        try {
          fs.symlinkSync(path.join(sub, 'real'), path.join(sub, 'link-to-self'));
        } catch {
          console.log('   ⏭️  symlink 作成不可の環境のため skip');
          return;
        }
        const urls = getKnownUrls();
        // 同じ URL を 1 回だけ拾えていれば、symlink 経由で 2 重カウントされていない
        assert.strictEqual(urls.size, 1);
        assert.ok(urls.has('https://real.example.com'));
      } finally {
        fs.rmSync(sub, { recursive: true, force: true });
        setVaultRoot(tmpDir);
        resetKnownUrlsCache();
      }
    });

    runner.test('キャッシュ: 2 回目の呼び出しは同一インスタンスを返す', () => {
      const sub = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-known-cache-'));
      setVaultRoot(sub);
      resetKnownUrlsCache();
      try {
        makeMd(path.join(sub, 'a.md'), 'source: "https://a.example.com"');
        const first = getKnownUrls();
        const second = getKnownUrls();
        assert.strictEqual(first, second, '同一参照を返していない (キャッシュ無効)');
        // resetKnownUrlsCache 後は別インスタンス
        resetKnownUrlsCache();
        const third = getKnownUrls();
        assert.notStrictEqual(first, third, 'リセット後も同じインスタンスを返している');
      } finally {
        fs.rmSync(sub, { recursive: true, force: true });
        setVaultRoot(tmpDir);
        resetKnownUrlsCache();
      }
    });

    runner.test('読み取れないディレクトリは黙ってスキップする (例外を投げない)', () => {
      const sub = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-known-perm-'));
      setVaultRoot(sub);
      resetKnownUrlsCache();
      try {
        makeMd(path.join(sub, 'a.md'), 'source: "https://a.example.com"');
        const lockedDir = path.join(sub, 'locked');
        fs.mkdirSync(lockedDir);
        // 読み取り権限を剥奪 (chmod 不可な FS なら skip)
        let chmodWorked = true;
        try {
          fs.chmodSync(lockedDir, 0o000);
        } catch {
          chmodWorked = false;
        }
        try {
          const urls = getKnownUrls();
          assert.ok(urls.has('https://a.example.com'));
        } finally {
          if (chmodWorked) fs.chmodSync(lockedDir, 0o755);
        }
      } finally {
        fs.rmSync(sub, { recursive: true, force: true });
        setVaultRoot(tmpDir);
        resetKnownUrlsCache();
      }
    });
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }

  return runner.report();
}
