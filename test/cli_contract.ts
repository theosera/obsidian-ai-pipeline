/**
 * CLI 契約テスト (P0)。
 *
 * モジュール単体の品質に対して手薄だった「CLI 起動境界」の回帰を固める:
 *   - P0-1: `sync-rules.ts` は import しても副作用 (top-level 実行) を起こさない。
 *           従来は index.ts が import した瞬間に syncRulesFromSnippets が走り、
 *           VAULT_ROOT 未設定の fresh clone では `pnpm start -- --config` すら
 *           getVaultRoot() の throw で起動不能だった。
 *   - P0-3: `--rescue <report>` が独立フラグとして認識され、レポートパスが
 *           位置引数として保持される (OneTab .txt と誤認しない)。
 *           `rescue-from-report.ts` は import しても main を実行しない (main-guard)。
 */
import assert from 'node:assert';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { setVaultRoot, peekVaultRoot } from '../config';
import { parseArgs } from '../cli';
import { parseReportItems, isXBookmarksReport, runRescueFromReport } from '../rescue-from-report';
import { TestRunner, type TestSuiteResult } from './helpers';

// 子プロセスで本物の interactiveReviewLoop を走らせる。runner と同じく発行時のラベルで
// レポートを書き、対話で 1 件の分類を直させる (直したレポートの書き直しが試験の対象)。
const CHILD_EDIT_REPORT = `
  const fs = await import('node:fs');
  const [interactiveUrl, reportUrl, reportPath, kind] = process.argv.slice(1);
  const { interactiveReviewLoop } = await import(interactiveUrl);
  const { generateReport, reportLabelFor } = await import(reportUrl);
  const isXBookmarks = kind === 'x';
  const url = isXBookmarks ? 'https://x.com/i/web/status/123' : 'https://example.com/a';
  const results = [{
    id: 1, status: 'success', url, title: 't',
    classification: { proposedPath: 'Before/Folder', isNewFolder: false, reasoning: 'r' },
  }];
  fs.writeFileSync(reportPath, generateReport(results, {}, reportLabelFor(isXBookmarks)), 'utf8');
  await interactiveReviewLoop(results, reportPath, { isXBookmarks });
`;

/** 対話に e → 1 → newFolder → q と答え、子プロセスが正常に終わるのを待つ。 */
async function editReportInChild(
  reportPath: string,
  kind: 'x' | 'onetab',
  vaultRoot: string,
  newFolder: string
): Promise<void> {
  const answers: Array<[prompt: string, answer: string]> = [
    ['Command [y/e/q]: ', 'e'],
    ['Enter the item ID', '1'],
    ['Enter new folder path', newFolder],
    ['Command [y/e/q]: ', 'q'],
  ];
  const child = spawn(
    process.execPath,
    [
      '--import', 'tsx', '--input-type=module', '-e', CHILD_EDIT_REPORT,
      new URL('../pipeline/interactive.ts', import.meta.url).href,
      new URL('../pipeline/report.ts', import.meta.url).href,
      reportPath, kind,
    ],
    {
      cwd: path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..'),
      env: { ...process.env, VAULT_ROOT: vaultRoot },
    }
  );
  let output = '';
  let errors = '';
  let consumed = 0;
  child.stdin.on('error', () => undefined); // 子が先に落ちた場合は下の終了コードで失敗させる
  child.stdout.on('data', (chunk) => {
    output += String(chunk);
    // プロンプトが出てから 1 行ずつ答える (まとめて流すと readline が質問の無い行を捨てる)
    while (answers.length > 0) {
      const [prompt, answer] = answers[0];
      const at = output.indexOf(prompt, consumed);
      if (at < 0) break;
      consumed = at + prompt.length;
      answers.shift();
      child.stdin.write(`${answer}\n`);
      if (answers.length === 0) child.stdin.end();
    }
  });
  child.stderr.on('data', (chunk) => {
    errors += String(chunk);
  });
  const code = await new Promise<number | null>((resolve, reject) => {
    const timer = setTimeout(() => child.kill('SIGKILL'), 30_000);
    child.once('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once('close', (exitCode) => {
      clearTimeout(timer);
      resolve(exitCode);
    });
  });
  assert.strictEqual(code, 0, `子プロセスが失敗した: ${errors}`);
  assert.strictEqual(answers.length, 0, `プロンプトに答え切れていない: ${output}`);
}

export async function run(): Promise<TestSuiteResult> {
  const runner = new TestRunner();
  const prevVault = peekVaultRoot();
  const prevEnvVault = process.env.VAULT_ROOT;
  // parseReportItems は ensureSafePath 経由で realpath 検証 (Phase 6) を通すため、
  // 実在するディレクトリを vault root にする必要がある。
  const parseVault = fs.mkdtempSync(path.join(os.tmpdir(), 'rescue-parse-vault-'));

  try {
    // =====================================================
    // P0-1: sync-rules import 副作用なし
    // =====================================================
    runner.section('P0-1: sync-rules.ts の import は副作用を起こさない');

    await runner.testAsync('VAULT_ROOT 未設定でも import が throw しない (top-level 実行なし)', async () => {
      // fresh clone 相当: vault root を完全に未設定へ
      setVaultRoot(null);
      delete process.env.VAULT_ROOT;

      // 旧実装ではこの import 時点で syncRulesFromSnippets → getVaultRoot() が
      // throw していた。main-guard 化後は import は純粋 (実行しない)。
      const mod = await import('../sync-rules');
      assert.strictEqual(
        typeof mod.syncRulesFromSnippets,
        'function',
        'syncRulesFromSnippets が export されていない'
      );
    });

    // =====================================================
    // P0-3: --rescue の引数ルーティング
    // =====================================================
    runner.section('P0-3: --rescue フラグのパース');

    runner.test('--rescue <report> はフラグ ON + レポートパスを位置引数に保持', () => {
      const args = parseArgs(['--rescue', '/vault/reports/OneTab分類結果レポート-20260710.md']);
      assert.strictEqual(args.rescue, true, '--rescue が認識されていない');
      assert.strictEqual(
        args.filePath,
        '/vault/reports/OneTab分類結果レポート-20260710.md',
        'レポートパスが位置引数として保持されていない'
      );
    });

    runner.test('--rescue <report> --dry-run で dryRun も立つ', () => {
      const args = parseArgs(['--rescue', 'r.md', '--dry-run']);
      assert.strictEqual(args.rescue, true);
      assert.strictEqual(args.dryRun, true);
      assert.strictEqual(args.filePath, 'r.md');
    });

    runner.test('通常の OneTab 実行では rescue は false', () => {
      const args = parseArgs(['../context/OneTab_20260710.txt']);
      assert.strictEqual(args.rescue, false, 'rescue が誤って立っている');
      assert.strictEqual(args.filePath, '../context/OneTab_20260710.txt');
    });

    // =====================================================
    // P0-3: レポート .md パース (parseReportItems)
    // =====================================================
    runner.section('P0-3: parseReportItems (レポート → 保存対象)');

    // parseReportItems は folder に ensureSafePath を掛けるため VAULT_ROOT が要る
    setVaultRoot(parseVault);

    runner.test('フォルダ見出し配下のリンク行を束ねる', () => {
      const report = [
        '# OneTab分類結果レポート',
        '',
        '## 📁 分類結果詳細',
        '',
        '### Engineer/LLM',
        '- [1] [Attention Is All You Need](https://arxiv.org/abs/1706.03762)',
        '- [2] [GPT-4 Technical Report](https://example.com/gpt4)',
        '',
        '### Notes/Obsidian',
        '- [3] [Dataview Guide](https://example.com/dataview)',
      ].join('\n');

      const items = parseReportItems(report);
      assert.strictEqual(items.length, 3, `3 件パースされるべき (got ${items.length})`);
      assert.strictEqual(items[0].folder, 'Engineer/LLM');
      assert.strictEqual(items[0].url, 'https://arxiv.org/abs/1706.03762');
      assert.strictEqual(items[0].title, 'Attention Is All You Need');
      assert.strictEqual(items[2].folder, 'Notes/Obsidian');
    });

    runner.test('✨(新規提案) バッジは folder 名から除去される', () => {
      const report = ['### Engineer/NewGenre ✨(新規提案)', '- [1] [t](https://example.com/x)'].join('\n');
      const items = parseReportItems(report);
      assert.strictEqual(items.length, 1);
      assert.strictEqual(items[0].folder, 'Engineer/NewGenre');
    });

    runner.test('フォルダ見出しより前のリンク行は無視される', () => {
      const report = ['- [1] [orphan](https://example.com/orphan)', '### Engineer/LLM', '- [2] [ok](https://example.com/ok)'].join('\n');
      const items = parseReportItems(report);
      assert.strictEqual(items.length, 1, 'フォルダ未確定のリンクは拾わない');
      assert.strictEqual(items[0].url, 'https://example.com/ok');
    });

    runner.test('パストラバーサルを含む見出しは安全なフォールバックへ落ちる', () => {
      const report = ['### ../../etc/passwd', '- [1] [evil](https://example.com/evil)'].join('\n');
      const items = parseReportItems(report);
      assert.strictEqual(items.length, 1);
      assert.strictEqual(items[0].folder, 'Clippings/Inbox', 'ensureSafePath フォールバックに落ちていない');
    });

    runner.test('リンクの無いレポートは空配列', () => {
      const items = parseReportItems('# 空レポート\n\n本文だけ\n');
      assert.strictEqual(items.length, 0);
    });

    // =====================================================
    // P0-3 (Codex P2): rescue は X ブックマークレポートを拒否する
    // =====================================================
    runner.section('P0-3: rescue は X ブックマークレポートを拒否 (per-tweet .md 誤生成の防止)');

    runner.test('isXBookmarksReport: X-Bookmarks レポートを検出 / OneTab は検出しない', () => {
      assert.strictEqual(isXBookmarksReport('# X-Bookmarks分類結果レポート\n\n## 📊'), true);
      assert.strictEqual(isXBookmarksReport('# OneTab分類結果レポート\n\n## 📊'), false);
      // H1 以外の位置に文字列があっても誤検出しない
      assert.strictEqual(isXBookmarksReport('本文中に X-Bookmarks という語がある'), false);
    });

    await runner.testAsync('runRescueFromReport は X レポートを fetch せず throw する', async () => {
      const xReportPath = path.join(parseVault, 'X-Bookmarks分類結果レポート-20260710.md');
      fs.writeFileSync(
        xReportPath,
        ['# X-Bookmarks分類結果レポート', '', '## 📁 分類結果詳細', '', '### Engineer/LLM', '- [1] [t](https://x.com/i/web/status/123)'].join('\n'),
        'utf8'
      );
      await assert.rejects(
        () => runRescueFromReport({ reportPath: xReportPath }),
        /X ブックマーク/,
        'X レポートは拒否されるべき (throw)'
      );
    });

    // =====================================================
    // P0-3: 対話の [e] で直した後も、レポートの見出しは発行時のラベルのまま
    // =====================================================
    runner.section('P0-3: 対話で分類を直した後のレポートも発行時の見出しを保つ');

    await runner.testAsync('X: 直した後も X の見出しで、rescue は取得せずに拒否する', async () => {
      const reportPath = path.join(parseVault, 'X-Bookmarks分類結果レポート-edited.md');
      await editReportInChild(reportPath, 'x', parseVault, 'Edited/Folder');
      const content = fs.readFileSync(reportPath, 'utf8');
      assert.match(content, /^### Edited\/Folder\s*$/m, '直した分類がレポートに書き戻されている');
      // 見出しが OneTab に戻ると下の rescue が Web 取得へ進むため、先に見出しで止める
      assert.strictEqual(isXBookmarksReport(content), true, '直した後も X-Bookmarks の見出し');
      await assert.rejects(() => runRescueFromReport({ reportPath }), /X ブックマーク/);
    });

    await runner.testAsync('OneTab: 直した後も OneTab の見出しで、rescue の対象を読める', async () => {
      const reportPath = path.join(parseVault, 'OneTab分類結果レポート-edited.md');
      await editReportInChild(reportPath, 'onetab', parseVault, 'Edited/Folder');
      const content = fs.readFileSync(reportPath, 'utf8');
      assert.ok(content.startsWith('# OneTab分類結果レポート\n'), 'OneTab の見出し');
      assert.strictEqual(isXBookmarksReport(content), false);
      assert.deepStrictEqual(
        parseReportItems(content).map((item) => [item.folder, item.url]),
        [['Edited/Folder', 'https://example.com/a']]
      );
    });
  } finally {
    // vault root / env を元に戻す
    setVaultRoot(prevVault);
    if (prevEnvVault === undefined) delete process.env.VAULT_ROOT;
    else process.env.VAULT_ROOT = prevEnvVault;
    fs.rmSync(parseVault, { recursive: true, force: true });
  }

  return runner.report();
}
