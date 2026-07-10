/**
 * dry-run zero-write 統合テスト (P0)。
 *
 * 契約: `--dry-run` はパイプラインの計画をプレビューするだけで **Vault ツリーを
 * 一切変更しない**。従来は runner がレポートディレクトリ / Vault スナップショット /
 * 失敗ログ / 分類レポートを、router が folder_rules.json を dry-run でも書いていた。
 *
 * 本スイートは Vault サブツリー全体 (ファイル内容 + ディレクトリ) をハッシュし、
 * パイプラインが各書き込み座標で呼ぶ関数群を dry-run 下で走らせた前後で
 * ハッシュが一致することを検証する。
 *
 * さらに **positive control** (同じ操作を dry-run 無しで走らせるとハッシュが変わる)
 * を置き、「dry-run だから変わらない」のか「そもそも何も書かないテスト」なのかを
 * 区別できるようにする (テスト自体の有効性の担保)。
 */
import assert from 'node:assert';
import fs from 'fs';
import path from 'path';
import os from 'os';
import crypto from 'crypto';
import { setVaultRoot, setDryRun, isDryRun } from '../config';
import { updateVaultTreeSnapshot, safeRename, resetFoldersCache, resetKnownUrlsCache } from '../storage';
import { loadFolderRules, updateThresholds } from '../router';
import { setupOutputDirs, writeFailureLog } from '../pipeline/runner';
import { ProcessingResult } from '../types';
import { FailureRecord } from '../pipeline/types';
import { TestRunner, type TestSuiteResult } from './helpers';

/**
 * Vault サブツリー全体を決定論的にハッシュする。
 * ディレクトリ (空でも) とファイル (内容 sha256) の双方を含めるので、
 * 「空ディレクトリが 1 個増えた」「ファイル 1 行変わった」も検出する。
 * symlink は追わない。
 */
function hashVaultTree(root: string): string {
  const entries: string[] = [];
  function walk(dir: string, rel: string): void {
    const items = fs
      .readdirSync(dir, { withFileTypes: true })
      .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const it of items) {
      const full = path.join(dir, it.name);
      const relPath = rel ? path.join(rel, it.name) : it.name;
      if (it.isDirectory()) {
        entries.push(`D:${relPath}`);
        walk(full, relPath);
      } else if (it.isFile()) {
        const h = crypto.createHash('sha256').update(fs.readFileSync(full)).digest('hex');
        entries.push(`F:${relPath}:${h}`);
      } else {
        entries.push(`O:${relPath}`);
      }
    }
  }
  walk(root, '');
  return crypto.createHash('sha256').update(entries.join('\n')).digest('hex');
}

/**
 * router の MONTHLY 昇格 (閾値 20) を確実に発火させる Vault を作る。
 * `Engineer/LLM` に 19 件の .md を置き、バッチ 2 件を足して vaultCount=21≥20。
 * 各 .md は frontmatter に date を持つので migrate は `Engineer/LLM/2026-03` へ動かす。
 */
function buildVault(): string {
  const vault = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-dryrun-test-'));

  // 昇格対象カテゴリ (既存 19 件)
  const catDir = path.join(vault, 'Engineer', 'LLM');
  fs.mkdirSync(catDir, { recursive: true });
  for (let i = 1; i <= 19; i++) {
    const md = `---\ntitle: "Article ${i}"\ndate: 2026-03-15\n---\n\nbody ${i}\n`;
    fs.writeFileSync(path.join(catDir, `article_${i}.md`), md, 'utf8');
  }

  // 無関係な既存フォルダ (ツリーの一部として不変であることを確認するため)
  fs.mkdirSync(path.join(vault, 'Notes', 'Obsidian'), { recursive: true });
  fs.writeFileSync(path.join(vault, 'Notes', 'Obsidian', 'keep.md'), '# keep\n', 'utf8');

  // saveFolderRules / snapshot の書き込み先 (通常実行では既存前提)
  fs.mkdirSync(path.join(vault, '__skills', 'pipeline'), { recursive: true });
  fs.writeFileSync(
    path.join(vault, '__skills', 'pipeline', 'folder_rules.json'),
    JSON.stringify({}, null, 2),
    'utf8'
  );

  return vault;
}

/** 昇格を発火させるバッチ結果 (Engineer/LLM に 2 件提案)。 */
function promotionResults(): ProcessingResult[] {
  const mk = (id: number): ProcessingResult => ({
    id,
    status: 'success',
    url: `https://example.com/${id}`,
    title: `New ${id}`,
    classification: {
      proposedPath: 'Engineer/LLM',
      isNewFolder: false,
      reasoning: 'test',
    },
    articleContext: { url: `https://example.com/${id}`, title: `New ${id}`, date: '2026-03-20' },
  });
  return [mk(101), mk(102)];
}

/**
 * パイプラインが各書き込み座標で呼ぶ関数群を順に実行する。
 * dry-run 下では Vault へ何も書かず、通常時は書き込む——という差分を測るための共通手順。
 */
function exercisePipelineWriteSurface(vault: string): void {
  const { REPORTS_DIR, INTERNAL_LOGS_DIR } = setupOutputDirs();

  // runner: 実行直後の Vault スナップショット
  updateVaultTreeSnapshot();

  // runner: 失敗ログ
  const failures: FailureRecord[] = [
    { url: 'https://example.com/failed', title: 'failed item', reason: 'fetch error' },
  ];
  writeFailureLog(failures, INTERNAL_LOGS_DIR, 'onetab', '20260710');

  // router: 閾値昇格 (migrate + folder_rules.json 永続化)
  const rules = loadFolderRules();
  updateThresholds(promotionResults(), rules);

  // runner: 分類レポート .md 書出
  fs.writeFileSync(path.join(REPORTS_DIR, 'report.md'), '# preview report\n', 'utf8');

  // interactive/router: 個別ファイル移動。昇格対象カテゴリ (Engineer/LLM) の
  // ファイルは通常実行の migrate で既に動くため、それとは無関係な Notes/Obsidian
  // のファイルを対象にする (dry-run では no-op、通常実行では rename されるべき)。
  safeRename(
    path.join(vault, 'Notes', 'Obsidian', 'keep.md'),
    path.join(vault, 'Notes', 'Obsidian', 'keep_moved.md')
  );
}

export function run(): TestSuiteResult {
  const runner = new TestRunner();
  const prevDry = isDryRun();

  try {
    // =====================================================
    // dry-run: Vault ツリーは前後で完全一致
    // =====================================================
    runner.section('dry-run zero-write: Vault ツリー不変');

    runner.test('dry-run 下の全書き込み座標を通しても Vault ハッシュが一致する', () => {
      const vault = buildVault();
      try {
        setVaultRoot(vault);
        resetFoldersCache();
        resetKnownUrlsCache();

        const before = hashVaultTree(vault);

        setDryRun(true);
        exercisePipelineWriteSurface(vault);
        setDryRun(false);

        const after = hashVaultTree(vault);
        assert.strictEqual(after, before, 'dry-run で Vault ツリーが変化した (zero-write 契約違反)');
      } finally {
        fs.rmSync(vault, { recursive: true, force: true });
      }
    });

    runner.test('dry-run では folder_rules.json が昇格で書き換わらない', () => {
      const vault = buildVault();
      try {
        setVaultRoot(vault);
        resetFoldersCache();
        const rulesPath = path.join(vault, '__skills', 'pipeline', 'folder_rules.json');
        const before = fs.readFileSync(rulesPath, 'utf8');

        setDryRun(true);
        const rules = loadFolderRules();
        const updated = updateThresholds(promotionResults(), rules);
        setDryRun(false);

        // 返り値 (in-memory) では昇格が反映される (routing プレビュー精度のため)
        assert.strictEqual(updated['Engineer/LLM'], 'monthly', 'in-memory では昇格しているべき');
        // だが永続ファイルは無改変
        assert.strictEqual(fs.readFileSync(rulesPath, 'utf8'), before, 'dry-run で folder_rules.json が書き換わった');
      } finally {
        fs.rmSync(vault, { recursive: true, force: true });
      }
    });

    runner.test('dry-run では Vault 内にレポート/スナップショット/ログのディレクトリを作らない', () => {
      const vault = buildVault();
      try {
        setVaultRoot(vault);
        resetFoldersCache();

        setDryRun(true);
        const { REPORTS_DIR } = setupOutputDirs();
        updateVaultTreeSnapshot();
        setDryRun(false);

        // 出力先は Vault 外 (一時ディレクトリ) に切り替わっている
        assert.ok(
          !REPORTS_DIR.startsWith(vault + path.sep),
          `dry-run のレポート出力先が Vault 内を指している: ${REPORTS_DIR}`
        );
        // Vault 側にはレポート/履歴ディレクトリが生成されていない
        assert.ok(
          !fs.existsSync(path.join(vault, '__skills', 'context')),
          'dry-run で __skills/context 配下が作られた'
        );
      } finally {
        fs.rmSync(vault, { recursive: true, force: true });
      }
    });

    // =====================================================
    // positive control: 通常実行なら同じ操作でハッシュが変わる
    // =====================================================
    runner.section('positive control: 通常実行では Vault ツリーが変わる');

    runner.test('dry-run 無しで同じ書き込み座標を通すと Vault ハッシュが変化する', () => {
      const vault = buildVault();
      try {
        setVaultRoot(vault);
        resetFoldersCache();
        resetKnownUrlsCache();

        const before = hashVaultTree(vault);

        setDryRun(false);
        exercisePipelineWriteSurface(vault);

        const after = hashVaultTree(vault);
        assert.notStrictEqual(
          after,
          before,
          '通常実行でも Vault が変化しない — テストが書き込みを検出できていない (無効なテスト)'
        );
      } finally {
        resetFoldersCache();
        resetKnownUrlsCache();
        fs.rmSync(vault, { recursive: true, force: true });
      }
    });
  } finally {
    setDryRun(prevDry);
    resetFoldersCache();
    resetKnownUrlsCache();
  }

  return runner.report();
}
