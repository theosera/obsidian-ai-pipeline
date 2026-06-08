/**
 * Tool Use 実行レイヤーのテスト。
 *
 * 重点 (セキュリティ不変条件):
 *   - Vault サンドボックス: `..` / 絶対パスは検証で拒否され実行されない
 *   - 最小権限: 未知ツール名は拒否 / create は上書き不可
 *   - Human-in-the-Loop: y/yes 以外 (空 / n / EOF) は fail-closed で実行ブロック
 *   - エージェントループ: 検証→承認→実行→tool_result 返却が end_turn まで回る。
 *     拒否時はローカル実行が**走らない**ことをモックで検証する。
 */
import assert from 'node:assert';
import fs from 'fs';
import path from 'path';
import os from 'os';
import type Anthropic from '@anthropic-ai/sdk';
import { setVaultRoot } from '../config';
import { TOOL_DEFINITIONS, validateToolUse, executeValidated } from '../tool-use/tools';
import { createTerminalApprovalGate, denyAllGate } from '../tool-use/approval';
import { runToolUseAgent, type MessagesClient } from '../tool-use/agent';
import type { ToolUseRequest, ValidatedToolCall } from '../tool-use/types';
import { TestRunner, type TestSuiteResult } from './helpers';

// --- Anthropic.Message モックビルダー (unknown キャストで最小フィールドのみ用意) ---
function msgToolUse(name: string, input: unknown, id = 'tu_1'): Anthropic.Message {
  return {
    id: 'm_tooluse', type: 'message', role: 'assistant', model: 'test',
    content: [{ type: 'tool_use', id, name, input }],
    stop_reason: 'tool_use', stop_sequence: null,
    usage: { input_tokens: 1, output_tokens: 1 },
  } as unknown as Anthropic.Message;
}

function msgText(text: string): Anthropic.Message {
  return {
    id: 'm_text', type: 'message', role: 'assistant', model: 'test',
    content: [{ type: 'text', text, citations: null }],
    stop_reason: 'end_turn', stop_sequence: null,
    usage: { input_tokens: 1, output_tokens: 1 },
  } as unknown as Anthropic.Message;
}

function mockClient(responses: Anthropic.Message[]): {
  client: MessagesClient;
  bodies: Anthropic.MessageCreateParamsNonStreaming[];
} {
  const bodies: Anthropic.MessageCreateParamsNonStreaming[] = [];
  let i = 0;
  const client: MessagesClient = {
    create: async (body) => {
      bodies.push(body);
      const r = responses[Math.min(i, responses.length - 1)];
      i++;
      return r;
    },
  };
  return { client, bodies };
}

function hasToolResult(body: Anthropic.MessageCreateParamsNonStreaming, toolUseId: string): boolean {
  return body.messages.some(
    (m) =>
      m.role === 'user' &&
      Array.isArray(m.content) &&
      m.content.some((b) => typeof b === 'object' && b.type === 'tool_result' && b.tool_use_id === toolUseId)
  );
}

export async function run(): Promise<TestSuiteResult> {
  const runner = new TestRunner();
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-tooluse-test-'));
  setVaultRoot(tmpDir);

  try {
    // =====================================================
    // ツール定義 (Step 2)
    // =====================================================
    runner.section('TOOL_DEFINITIONS');

    runner.test('許可ツールは read/create の 2 つだけ (最小権限)', () => {
      const names = TOOL_DEFINITIONS.map((t) => t.name).sort();
      assert.deepStrictEqual(names, ['create_obsidian_note', 'read_obsidian_note']);
    });

    runner.test('各ツールは input_schema (type=object) と required を持つ', () => {
      for (const tool of TOOL_DEFINITIONS) {
        assert.strictEqual(tool.input_schema.type, 'object');
        assert.ok(typeof tool.description === 'string' && tool.description.length > 0);
      }
    });

    // =====================================================
    // 検証: サンドボックス境界 (Step 1)
    // =====================================================
    runner.section('validateToolUse (sandbox)');

    const req = (name: string, input: unknown): ToolUseRequest => ({ id: 'tu_1', name, input });

    runner.test('未知ツール名は拒否される', () => {
      const r = validateToolUse(req('delete_everything', {}));
      assert.strictEqual(r.ok, false);
    });

    runner.test('read: .. トラバーサルは拒否される', () => {
      const r = validateToolUse(req('read_obsidian_note', { path: '../etc/passwd' }));
      assert.strictEqual(r.ok, false);
    });

    runner.test('read: 絶対パスは拒否される', () => {
      const r = validateToolUse(req('read_obsidian_note', { path: '/etc/passwd' }));
      assert.strictEqual(r.ok, false);
    });

    runner.test('read: path 欠落は拒否される', () => {
      const r = validateToolUse(req('read_obsidian_note', {}));
      assert.strictEqual(r.ok, false);
    });

    runner.test('read: 正常パスは Vault 内座標へ解決される', () => {
      const r = validateToolUse(req('read_obsidian_note', { path: 'Inbox/note.md' }));
      assert.strictEqual(r.ok, true);
      if (r.ok) assert.ok(r.value.absolutePath.startsWith(tmpDir + path.sep));
    });

    runner.test('create: .. トラバーサルは拒否される', () => {
      const r = validateToolUse(req('create_obsidian_note', { filename: '../escape.md', content: 'x' }));
      assert.strictEqual(r.ok, false);
    });

    runner.test('create: content 非文字列は拒否される', () => {
      const r = validateToolUse(req('create_obsidian_note', { filename: 'a.md', content: 42 }));
      assert.strictEqual(r.ok, false);
    });

    runner.test('create: Vault 外への symlink ディレクトリ経由は検証で拒否される (Codex P1)', () => {
      const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'outside-symlink-'));
      try {
        fs.symlinkSync(outside, path.join(tmpDir, 'link'), 'dir');
        // 宛先 (link/escape.md) はまだ存在しないが、最近接既存祖先 link は Vault 外へ
        // 向く symlink なので validateToolUse は拒否しなければならない。
        const r = validateToolUse(req('create_obsidian_note', { filename: 'link/escape.md', content: 'x' }));
        assert.strictEqual(r.ok, false);
        assert.strictEqual(fs.existsSync(path.join(outside, 'escape.md')), false, 'Vault 外にファイルが作られてはいけない');
      } finally {
        fs.rmSync(path.join(tmpDir, 'link'), { force: true });
        fs.rmSync(outside, { recursive: true, force: true });
      }
    });

    runner.test('create: 検証を迂回しても実行レイヤーが symlink 越えを拒否する (defense-in-depth)', () => {
      const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'outside-exec-'));
      try {
        fs.symlinkSync(outside, path.join(tmpDir, 'link2'), 'dir');
        // validate を通さず手組みした ValidatedToolCall (TOCTOU で symlink が差し替わった
        // 状況を模す) でも、executeValidated は書き込み前に realpath 再検証で弾く。
        const forged: ValidatedToolCall = {
          id: 'tu_forged', name: 'create_obsidian_note',
          input: { filename: 'link2/escape.md', content: 'x' },
          absolutePath: path.join(tmpDir, 'link2', 'escape.md'), preview: 'forged',
        };
        const res = executeValidated(forged);
        assert.strictEqual(res.ok, false);
        assert.strictEqual(fs.existsSync(path.join(outside, 'escape.md')), false, 'Vault 外にファイルが作られてはいけない');
      } finally {
        fs.rmSync(path.join(tmpDir, 'link2'), { force: true });
        fs.rmSync(outside, { recursive: true, force: true });
      }
    });

    // =====================================================
    // 実行: read / create (Step 3)
    // =====================================================
    runner.section('executeValidated');

    runner.test('create は Vault 内に新規ノートを書き込む', () => {
      const v = validateToolUse(req('create_obsidian_note', { filename: 'agent/made.md', content: '# hi\nbody' }));
      assert.ok(v.ok);
      if (!v.ok) return;
      const res = executeValidated(v.value);
      assert.strictEqual(res.ok, true);
      const onDisk = fs.readFileSync(path.join(tmpDir, 'agent', 'made.md'), 'utf8');
      assert.strictEqual(onDisk, '# hi\nbody');
    });

    runner.test('create は既存ファイルを上書きしない (create ≠ modify)', () => {
      const v = validateToolUse(req('create_obsidian_note', { filename: 'agent/made.md', content: 'OVERWRITE' }));
      assert.ok(v.ok);
      if (!v.ok) return;
      const res = executeValidated(v.value);
      assert.strictEqual(res.ok, false);
      // 元の内容が保持されている
      const onDisk = fs.readFileSync(path.join(tmpDir, 'agent', 'made.md'), 'utf8');
      assert.strictEqual(onDisk, '# hi\nbody');
    });

    runner.test('read は作成済みノートを読み戻せる', () => {
      const v = validateToolUse(req('read_obsidian_note', { path: 'agent/made.md' }));
      assert.ok(v.ok);
      if (!v.ok) return;
      const res = executeValidated(v.value);
      assert.strictEqual(res.ok, true);
      if (res.ok) assert.strictEqual(res.value, '# hi\nbody');
    });

    runner.test('read: 存在しないファイルは ok:false', () => {
      const v = validateToolUse(req('read_obsidian_note', { path: 'nope/missing.md' }));
      assert.ok(v.ok);
      if (!v.ok) return;
      const res = executeValidated(v.value);
      assert.strictEqual(res.ok, false);
    });

    // =====================================================
    // Human-in-the-Loop ゲート (Step 4 / 最重要) — fail-closed
    // =====================================================
    runner.section('approval gate (fail-closed)');

    const dummyCall: ValidatedToolCall = {
      id: 'tu_1', name: 'create_obsidian_note',
      input: { filename: 'x.md', content: 'y' },
      absolutePath: path.join(tmpDir, 'x.md'), preview: 'CREATE x.md',
    };
    const gateWith = (answer: string) => createTerminalApprovalGate(async () => answer);

    await runner.testAsync("'y' で承認", async () => {
      assert.strictEqual(await gateWith('y')(dummyCall), true);
    });
    await runner.testAsync("'Y' / 'yes' でも承認", async () => {
      assert.strictEqual(await gateWith('Y')(dummyCall), true);
      assert.strictEqual(await gateWith('yes')(dummyCall), true);
    });
    await runner.testAsync("空 Enter は拒否 (デフォルト No)", async () => {
      assert.strictEqual(await gateWith('')(dummyCall), false);
    });
    await runner.testAsync("'n' は拒否", async () => {
      assert.strictEqual(await gateWith('n')(dummyCall), false);
    });
    await runner.testAsync('想定外入力は拒否 (fail-closed)', async () => {
      assert.strictEqual(await gateWith('maybe')(dummyCall), false);
    });
    await runner.testAsync('denyAllGate は常に拒否', async () => {
      assert.strictEqual(await denyAllGate(dummyCall), false);
    });

    // =====================================================
    // エージェントループ (Step 3 オーケストレーション)
    // =====================================================
    runner.section('runToolUseAgent (loop)');

    await runner.testAsync('承認時: 検証→実行→tool_result 返却で end_turn まで回る', async () => {
      const { client, bodies } = mockClient([
        msgToolUse('create_obsidian_note', { filename: 'loop/ok.md', content: 'looped' }),
        msgText('done'),
      ]);
      const result = await runToolUseAgent('make a note', {
        client, approve: async () => true, model: 'test', maxTurns: 5,
      });
      assert.strictEqual(result.stoppedReason, 'end_turn');
      assert.strictEqual(result.toolCalls.length, 1);
      assert.strictEqual(result.toolCalls[0].approved, true);
      assert.strictEqual(result.toolCalls[0].ok, true);
      assert.strictEqual(result.finalText, 'done');
      // ファイルが実際に作られた
      assert.ok(fs.existsSync(path.join(tmpDir, 'loop', 'ok.md')));
      // 2 回目の API 呼び出しに tool_result がフィードバックされている
      assert.ok(hasToolResult(bodies[1], 'tu_1'));
    });

    await runner.testAsync('拒否時: ローカル実行は走らず is_error が返る', async () => {
      const target = path.join(tmpDir, 'loop', 'denied.md');
      const { client } = mockClient([
        msgToolUse('create_obsidian_note', { filename: 'loop/denied.md', content: 'should not exist' }),
        msgText('ok, skipped'),
      ]);
      const result = await runToolUseAgent('make a note', {
        client, approve: denyAllGate, model: 'test', maxTurns: 5,
      });
      assert.strictEqual(result.toolCalls[0].approved, false);
      assert.strictEqual(result.toolCalls[0].ok, false);
      assert.strictEqual(fs.existsSync(target), false, '拒否されたのでファイルは作られない');
    });

    await runner.testAsync('サンドボックス違反は承認を求めずに拒否される', async () => {
      let approveCalls = 0;
      const { client } = mockClient([
        msgToolUse('create_obsidian_note', { filename: '../escape.md', content: 'x' }),
        msgText('cannot'),
      ]);
      const result = await runToolUseAgent('escape', {
        client,
        approve: async () => { approveCalls++; return true; },
        model: 'test', maxTurns: 5,
      });
      assert.strictEqual(approveCalls, 0, '検証で弾かれるので承認は呼ばれない');
      assert.strictEqual(result.toolCalls[0].ok, false);
      assert.strictEqual(fs.existsSync(path.join(tmpDir, 'escape.md')), false);
    });
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }

  return runner.report();
}
