/**
 * config.ts のユニットテスト。
 * 現状は getPipelineDbDir (PIPELINE_DB_DIR 上書き / 既定パス / ディレクトリ自動生成) を検証する。
 */
import assert from 'node:assert';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { getPipelineDbDir, setVaultRoot, peekVaultRoot } from '../config';
import { TestRunner, type TestSuiteResult } from './helpers';

export function run(): TestSuiteResult {
  const runner = new TestRunner();
  runner.section('config: getPipelineDbDir');

  // env も module-global の vaultRoot もプロセス全体の状態なので、スイート終了時に必ず
  // 元へ戻す (他スイートへ汚染しない)。特に vaultRoot は本スイートが削除済み tmpdir を
  // 指したまま残ると後続スイートを壊しうる。
  const savedEnv = process.env.PIPELINE_DB_DIR;
  const savedVaultRoot = peekVaultRoot();

  runner.test('PIPELINE_DB_DIR 未設定なら <vault>/__skills/pipeline を使い、無ければ作る', () => {
    const vault = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-'));
    try {
      delete process.env.PIPELINE_DB_DIR;
      setVaultRoot(vault);
      const dir = getPipelineDbDir();
      assert.strictEqual(dir, path.join(vault, '__skills', 'pipeline'));
      assert.ok(fs.existsSync(dir), 'ディレクトリが作成される');
    } finally {
      fs.rmSync(vault, { recursive: true, force: true });
    }
  });

  runner.test('PIPELINE_DB_DIR があれば絶対パスに解決し vault 非依存で使う', () => {
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'dbdir-'));
    try {
      // vault 配下ではない外部パス (= iCloud 外 / .nosync シナリオ) を指す。
      const target = path.join(outside, 'pipeline.nosync');
      process.env.PIPELINE_DB_DIR = target;
      const dir = getPipelineDbDir();
      assert.strictEqual(dir, path.resolve(target));
      assert.ok(fs.existsSync(dir), 'override 先ディレクトリが作成される');
    } finally {
      fs.rmSync(outside, { recursive: true, force: true });
    }
  });

  runner.test('PIPELINE_DB_DIR が空白のみなら未設定扱いで既定パスにフォールバック', () => {
    const vault = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-'));
    try {
      process.env.PIPELINE_DB_DIR = '   ';
      setVaultRoot(vault);
      const dir = getPipelineDbDir();
      assert.strictEqual(dir, path.join(vault, '__skills', 'pipeline'));
    } finally {
      fs.rmSync(vault, { recursive: true, force: true });
    }
  });

  if (savedEnv === undefined) delete process.env.PIPELINE_DB_DIR;
  else process.env.PIPELINE_DB_DIR = savedEnv;
  setVaultRoot(savedVaultRoot);

  return runner.report();
}
