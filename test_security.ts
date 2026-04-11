import assert from 'node:assert';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { setVaultRoot, getVaultRoot, setDryRun, isDryRun } from './config';
import { ensureSafePath, safeRename } from './storage';

let passed = 0;
let failed = 0;

function test(name: string, fn: () => void): void {
  try {
    fn();
    console.log(`  ✅ ${name}`);
    passed++;
  } catch (err: any) {
    console.error(`  ❌ ${name}`);
    console.error(`     ${err.message}`);
    failed++;
  }
}

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-test-'));

try {
  // =====================================================
  // 1. VAULT_ROOT 設定ファイル化テスト
  // =====================================================
  console.log('\n--- VAULT_ROOT 設定ファイル化テスト ---');

  test('setVaultRoot / getVaultRoot が正しく動作する', () => {
    setVaultRoot(tmpDir);
    assert.strictEqual(getVaultRoot(), path.resolve(tmpDir));
  });

  test('相対パスが resolve される', () => {
    setVaultRoot('./relative/path');
    assert.ok(path.isAbsolute(getVaultRoot()));
    setVaultRoot(tmpDir); // 戻す
  });

  // =====================================================
  // 2. パストラバーサル防御テスト
  // =====================================================
  console.log('\n--- パストラバーサル防御テスト ---');

  test('.. セグメントを含むパスは拒否される', () => {
    assert.strictEqual(ensureSafePath('../etc/passwd'), 'Clippings/Inbox');
  });

  test('多重 .. トラバーサルは拒否される', () => {
    assert.strictEqual(ensureSafePath('../../etc/passwd'), 'Clippings/Inbox');
  });

  test('中間の .. トラバーサルは拒否される', () => {
    assert.strictEqual(ensureSafePath('foo/../../../etc/passwd'), 'Clippings/Inbox');
  });

  test('絶対パス (/) は拒否される', () => {
    assert.strictEqual(ensureSafePath('/etc/passwd'), 'Clippings/Inbox');
  });

  test('チルダ (~) パスは拒否される', () => {
    assert.strictEqual(ensureSafePath('~/secret'), 'Clippings/Inbox');
  });

  test('Windows ドライブレターは拒否される', () => {
    assert.strictEqual(ensureSafePath('C:\\Windows\\System32'), 'Clippings/Inbox');
  });

  test('URLエンコードされた .. (%2e%2e) は拒否される', () => {
    assert.strictEqual(ensureSafePath('%2e%2e/etc/passwd'), 'Clippings/Inbox');
  });

  test('URLエンコードされた / (%2f) + .. は拒否される', () => {
    assert.strictEqual(ensureSafePath('foo%2f..%2f..%2fetc%2fpasswd'), 'Clippings/Inbox');
  });

  test('正常なパスは保持される', () => {
    assert.strictEqual(ensureSafePath('Engineer/LLM'), 'Engineer' + path.sep + 'LLM');
  });

  test('日本語パスは保持される', () => {
    assert.strictEqual(ensureSafePath('Engineer/AGENT経済圏'), 'Engineer' + path.sep + 'AGENT経済圏');
  });

  test('空文字列はフォールバックされる', () => {
    assert.strictEqual(ensureSafePath(''), 'Clippings/Inbox');
  });

  test('nullバイトは除去される', () => {
    const result = ensureSafePath('Engineer/\x00LLM');
    assert.ok(!result.includes('\x00'));
    assert.strictEqual(result, 'Engineer' + path.sep + 'LLM');
  });

  test('制御文字は除去される', () => {
    const result = ensureSafePath('Engineer/\x0dLLM');
    assert.ok(!result.includes('\x0d'));
  });

  test('極端に長いパスは拒否される', () => {
    assert.strictEqual(ensureSafePath('a'.repeat(600)), 'Clippings/Inbox');
  });

  test('Unicode NFC/NFD 正規化が統一される', () => {
    // "テスト" in NFC vs NFD
    const nfc = 'テスト'.normalize('NFC');
    const nfd = 'テスト'.normalize('NFD');
    assert.strictEqual(ensureSafePath(nfc), ensureSafePath(nfd));
  });

  test('. セグメントはフィルタされる（拒否ではなく除去）', () => {
    assert.strictEqual(ensureSafePath('Engineer/./LLM'), 'Engineer' + path.sep + 'LLM');
  });

  test('バックスラッシュ区切りも処理される', () => {
    const result = ensureSafePath('Engineer\\..\\etc');
    assert.strictEqual(result, 'Clippings/Inbox'); // .. を含むので拒否
  });

  test('__EXCLUDED__ はそのまま通る (classifier の特殊値)', () => {
    // __EXCLUDED__ は .. や / で始まらないので通る
    const result = ensureSafePath('__EXCLUDED__');
    assert.strictEqual(result, '__EXCLUDED__');
  });

  // =====================================================
  // 3. Dry-Run テスト
  // =====================================================
  console.log('\n--- Dry-Run テスト ---');

  test('setDryRun(true) が有効になる', () => {
    setDryRun(true);
    assert.strictEqual(isDryRun(), true);
  });

  test('dry-run モードではファイルが移動されない', () => {
    setDryRun(true);
    const srcFile = path.join(tmpDir, 'test_src.md');
    const destFile = path.join(tmpDir, 'test_dest.md');
    fs.writeFileSync(srcFile, 'test content');

    safeRename(srcFile, destFile);

    assert.strictEqual(fs.existsSync(srcFile), true, 'ソースファイルが残っているべき');
    assert.strictEqual(fs.existsSync(destFile), false, '移動先ファイルは作られないべき');

    // cleanup
    fs.unlinkSync(srcFile);
  });

  test('setDryRun(false) で通常モードに戻る', () => {
    setDryRun(false);
    assert.strictEqual(isDryRun(), false);
  });

  test('通常モードではファイルが実際に移動される', () => {
    setDryRun(false);
    const srcFile = path.join(tmpDir, 'test_real_src.md');
    const destFile = path.join(tmpDir, 'test_real_dest.md');
    fs.writeFileSync(srcFile, 'real content');

    safeRename(srcFile, destFile);

    assert.strictEqual(fs.existsSync(srcFile), false, 'ソースファイルは移動済み');
    assert.strictEqual(fs.existsSync(destFile), true, '移動先にファイルが存在するべき');

    // cleanup
    fs.unlinkSync(destFile);
  });

  // =====================================================
  // 結果サマリー
  // =====================================================
  console.log(`\n========================================`);
  console.log(`テスト結果: ${passed} passed, ${failed} failed`);
  if (failed > 0) {
    console.log('❌ テストに失敗があります！');
    process.exit(1);
  } else {
    console.log('🎉 全テスト合格！');
  }

} finally {
  // Cleanup
  fs.rmSync(tmpDir, { recursive: true, force: true });
}
