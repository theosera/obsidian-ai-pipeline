import assert from 'node:assert';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { setVaultRoot, getVaultRoot, setDryRun, isDryRun } from '../config';
import { ensureSafePath, safeRename } from '../storage';
import { TestRunner, type TestSuiteResult } from './helpers';

export function run(): TestSuiteResult {
  const runner = new TestRunner();
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-sec-test-'));

  try {
    // =====================================================
    // 1. VAULT_ROOT 設定ファイル化テスト
    // =====================================================
    runner.section('VAULT_ROOT 設定ファイル化');

    runner.test('setVaultRoot / getVaultRoot が正しく動作する', () => {
      setVaultRoot(tmpDir);
      assert.strictEqual(getVaultRoot(), path.resolve(tmpDir));
    });

    runner.test('相対パスが resolve される', () => {
      setVaultRoot('./relative/path');
      assert.ok(path.isAbsolute(getVaultRoot()));
      setVaultRoot(tmpDir); // 戻す
    });

    // =====================================================
    // 2. パストラバーサル防御テスト
    // =====================================================
    runner.section('パストラバーサル防御');

    runner.test('.. セグメントを含むパスは拒否される', () => {
      assert.strictEqual(ensureSafePath('../etc/passwd'), 'Clippings/Inbox');
    });

    runner.test('多重 .. トラバーサルは拒否される', () => {
      assert.strictEqual(ensureSafePath('../../etc/passwd'), 'Clippings/Inbox');
    });

    runner.test('中間の .. トラバーサルは拒否される', () => {
      assert.strictEqual(ensureSafePath('foo/../../../etc/passwd'), 'Clippings/Inbox');
    });

    runner.test('絶対パス (/) は拒否される', () => {
      assert.strictEqual(ensureSafePath('/etc/passwd'), 'Clippings/Inbox');
    });

    runner.test('チルダ (~) パスは拒否される', () => {
      assert.strictEqual(ensureSafePath('~/secret'), 'Clippings/Inbox');
    });

    runner.test('Windows ドライブレターは拒否される', () => {
      assert.strictEqual(ensureSafePath('C:\\Windows\\System32'), 'Clippings/Inbox');
    });

    runner.test('URLエンコードされた .. (%2e%2e) は拒否される', () => {
      assert.strictEqual(ensureSafePath('%2e%2e/etc/passwd'), 'Clippings/Inbox');
    });

    runner.test('URLエンコードされた / (%2f) + .. は拒否される', () => {
      assert.strictEqual(ensureSafePath('foo%2f..%2f..%2fetc%2fpasswd'), 'Clippings/Inbox');
    });

    runner.test('正常なパスは保持される', () => {
      assert.strictEqual(ensureSafePath('Engineer/LLM'), 'Engineer' + path.sep + 'LLM');
    });

    runner.test('日本語パスは保持される', () => {
      assert.strictEqual(ensureSafePath('Engineer/AGENT経済圏'), 'Engineer' + path.sep + 'AGENT経済圏');
    });

    runner.test('空文字列はフォールバックされる', () => {
      assert.strictEqual(ensureSafePath(''), 'Clippings/Inbox');
    });

    runner.test('nullバイトは除去される', () => {
      const result = ensureSafePath('Engineer/\x00LLM');
      assert.ok(!result.includes('\x00'));
      assert.strictEqual(result, 'Engineer' + path.sep + 'LLM');
    });

    runner.test('制御文字は除去される', () => {
      const result = ensureSafePath('Engineer/\x0dLLM');
      assert.ok(!result.includes('\x0d'));
    });

    runner.test('極端に長いパスは拒否される', () => {
      assert.strictEqual(ensureSafePath('a'.repeat(600)), 'Clippings/Inbox');
    });

    runner.test('Unicode NFC/NFD 正規化が統一される', () => {
      const nfc = 'テスト'.normalize('NFC');
      const nfd = 'テスト'.normalize('NFD');
      assert.strictEqual(ensureSafePath(nfc), ensureSafePath(nfd));
    });

    runner.test('. セグメントはフィルタされる（拒否ではなく除去）', () => {
      assert.strictEqual(ensureSafePath('Engineer/./LLM'), 'Engineer' + path.sep + 'LLM');
    });

    runner.test('バックスラッシュ区切りも処理される', () => {
      const result = ensureSafePath('Engineer\\..\\etc');
      assert.strictEqual(result, 'Clippings/Inbox');
    });

    runner.test('__EXCLUDED__ はそのまま通る (classifier の特殊値)', () => {
      const result = ensureSafePath('__EXCLUDED__');
      assert.strictEqual(result, '__EXCLUDED__');
    });

    // =====================================================
    // 3. Dry-Run テスト
    // =====================================================
    runner.section('Dry-Run');

    runner.test('setDryRun(true) が有効になる', () => {
      setDryRun(true);
      assert.strictEqual(isDryRun(), true);
    });

    runner.test('dry-run モードではファイルが移動されない', () => {
      setDryRun(true);
      const srcFile = path.join(tmpDir, 'test_src.md');
      const destFile = path.join(tmpDir, 'test_dest.md');
      fs.writeFileSync(srcFile, 'test content');

      safeRename(srcFile, destFile);

      assert.strictEqual(fs.existsSync(srcFile), true, 'ソースファイルが残っているべき');
      assert.strictEqual(fs.existsSync(destFile), false, '移動先ファイルは作られないべき');

      fs.unlinkSync(srcFile);
    });

    runner.test('setDryRun(false) で通常モードに戻る', () => {
      setDryRun(false);
      assert.strictEqual(isDryRun(), false);
    });

    runner.test('通常モードではファイルが実際に移動される', () => {
      setDryRun(false);
      const srcFile = path.join(tmpDir, 'test_real_src.md');
      const destFile = path.join(tmpDir, 'test_real_dest.md');
      fs.writeFileSync(srcFile, 'real content');

      safeRename(srcFile, destFile);

      assert.strictEqual(fs.existsSync(srcFile), false, 'ソースファイルは移動済み');
      assert.strictEqual(fs.existsSync(destFile), true, '移動先にファイルが存在するべき');

      fs.unlinkSync(destFile);
    });
  } finally {
    // cleanup
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }

  return runner.report();
}
