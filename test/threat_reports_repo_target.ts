/**
 * resolveRepoTarget のユニットテスト。
 * web (owner/repo スラッグ) と CLI (ローカルパス) の両入力が同じ正準キーに収束し、
 * ローカルチェックアウトの実体ルートを正しく解決することを検証する。
 * child_process / fs は注入 (remoteResolver / existsDir) で置き換える。
 */
import assert from 'node:assert';
import path from 'node:path';
import { TestRunner, type TestSuiteResult } from './helpers';
import { resolveRepoTarget, parseRepoSlug } from '../threat_reports_repo_target';

export async function run(): Promise<TestSuiteResult> {
  const runner = new TestRunner();

  runner.section('parseRepoSlug');

  runner.test('SSH / HTTPS / .git 付きから owner/repo を抽出', () => {
    assert.strictEqual(parseRepoSlug('git@github.com:theosera/obsidian-ai-pipeline.git'), 'theosera/obsidian-ai-pipeline');
    assert.strictEqual(parseRepoSlug('https://github.com/theosera/pipeline-youtube-SDK'), 'theosera/pipeline-youtube-SDK');
    assert.strictEqual(parseRepoSlug('ssh://git@github.com/o/r.git'), 'o/r');
  });

  runner.test('解釈できない URL は null', () => {
    assert.strictEqual(parseRepoSlug('not-a-url'), null);
  });

  runner.section('resolveRepoTarget');

  runner.test('spec 省略 → cwd を走査、key は remote から導出', () => {
    const t = resolveRepoTarget(undefined, {
      cwd: '/home/user/obsidian-ai-pipeline',
      remoteResolver: () => 'git@github.com:theosera/obsidian-ai-pipeline.git',
      existsDir: () => false,
    });
    assert.strictEqual(t.key, 'theosera/obsidian-ai-pipeline');
    assert.strictEqual(t.root, '/home/user/obsidian-ai-pipeline');
  });

  runner.test('owner/repo スラッグ → 兄弟ディレクトリのチェックアウトを root に解決', () => {
    // web セッション: 対象 3 リポが /home/user/<name> に並ぶ。
    const t = resolveRepoTarget('theosera/claude_openai_mcp_connector', {
      cwd: '/home/user/obsidian-ai-pipeline',
      existsDir: (p) => p === '/home/user/claude_openai_mcp_connector',
      remoteResolver: () => null,
    });
    assert.strictEqual(t.key, 'theosera/claude_openai_mcp_connector', 'key はスラッグそのもの');
    assert.strictEqual(t.root, '/home/user/claude_openai_mcp_connector', 'root は兄弟チェックアウト');
  });

  runner.test('スラッグだがチェックアウトが見つからない → cwd にフォールバック (key は維持)', () => {
    const t = resolveRepoTarget('theosera/some-other-repo', {
      cwd: '/home/user/obsidian-ai-pipeline',
      existsDir: () => false,
      remoteResolver: () => null,
    });
    assert.strictEqual(t.key, 'theosera/some-other-repo');
    assert.strictEqual(t.root, '/home/user/obsidian-ai-pipeline');
  });

  runner.test('ローカルパス指定 (CLI) → そのパスを root、key は remote から導出', () => {
    const abs = '/home/user/pipeline-youtube-SDK';
    const t = resolveRepoTarget(abs, {
      cwd: '/home/user/obsidian-ai-pipeline',
      existsDir: (p) => p === abs,
      remoteResolver: (root) => (root === abs ? 'https://github.com/theosera/pipeline-youtube-SDK.git' : null),
    });
    assert.strictEqual(t.key, 'theosera/pipeline-youtube-SDK');
    assert.strictEqual(t.root, abs);
  });

  runner.test('remote が取れないローカルパス → local/<basename> にフォールバック', () => {
    const abs = '/tmp/scratch-repo';
    const t = resolveRepoTarget(abs, {
      cwd: '/home/user/obsidian-ai-pipeline',
      existsDir: (p) => p === abs,
      remoteResolver: () => null,
    });
    assert.strictEqual(t.key, 'local/scratch-repo');
    assert.strictEqual(t.root, abs);
  });

  runner.test('web (スラッグ) と CLI (パス) が同じ正準キーに収束する', () => {
    const sibling = '/home/user/claude_openai_mcp_connector';
    const remote = 'git@github.com:theosera/claude_openai_mcp_connector.git';
    const fromWeb = resolveRepoTarget('theosera/claude_openai_mcp_connector', {
      cwd: '/home/user/obsidian-ai-pipeline',
      existsDir: (p) => p === sibling,
      remoteResolver: () => remote,
    });
    const fromCli = resolveRepoTarget(sibling, {
      cwd: '/home/user/obsidian-ai-pipeline',
      existsDir: (p) => p === sibling,
      remoteResolver: () => remote,
    });
    assert.strictEqual(fromWeb.key, fromCli.key, '同じ repo_key');
    assert.strictEqual(path.resolve(fromWeb.root), path.resolve(fromCli.root), '同じ走査ルート');
  });

  return runner.report();
}
