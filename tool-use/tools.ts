/**
 * Tool Use 実行レイヤー: ツール定義 (Step 2) + サンドボックス化された検証/実行 (Step 1+3)。
 *
 * セキュリティ不変条件 (絶対遵守):
 *   1. **最小権限** — ツールは `read_obsidian_note` / `create_obsidian_note` の 2 つだけ。
 *   2. **Vault サンドボックス** — 全ファイル座標は `resolveVaultPath` (storage.ts の
 *      7 フェーズ防御) を通す。Vault 外を指したら**実行せず拒否**する (黙ってクランプしない)。
 *   3. **OS ネイティブ非利用** — `child_process` / shell / AppleScript / ネットワークを
 *      一切 import しない。副作用は Vault 配下の `fs` 読み書きのみ。
 *   4. **create は上書き不可** — 既存ファイルがあれば拒否 (create ≠ modify = 権限分離)。
 *
 * 検証 (`validateToolUse`) と実行 (`executeValidated`) を**分離**しているのは、
 * Human-in-the-Loop ゲート (approval.ts) に「解決済みの実座標」を提示してから実行する
 * ためで、人間が承認するのは生のモデル出力ではなく検証済みの操作になる。
 */
import fs from 'fs';
import path from 'path';
import type Anthropic from '@anthropic-ai/sdk';
import { resolveVaultPath } from '../storage';
import { getVaultRoot } from '../config';
import type {
  Result,
  ToolUseRequest,
  ValidatedToolCall,
  ReadNoteInput,
  CreateNoteInput,
} from './types';

/** read で 1 ファイルから読む最大バイト数 (コンテキスト爆発と巨大ファイル DoS の抑止)。 */
const MAX_READ_BYTES = 256 * 1024;
/** create で書ける最大文字数 (暴走生成の上限)。 */
const MAX_WRITE_CHARS = 1_000_000;

/**
 * API リクエストに載せるツール JSON スキーマ (Step 2)。
 * Anthropic ネイティブ tool use の `tools` パラメータにそのまま渡す。
 * description は「Vault 内に限定される」ことをモデルにも明示し、無駄な越権要求を減らす。
 */
export const TOOL_DEFINITIONS: Anthropic.Tool[] = [
  {
    name: 'read_obsidian_note',
    description:
      'Read a single UTF-8 text file from inside the Obsidian Vault and return its content. ' +
      'The path MUST be relative to the Vault root (e.g. "Inbox/idea.md"). ' +
      'Absolute paths, "~" and any ".." traversal are rejected. Files outside the Vault cannot be read.',
    input_schema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'Vault-root-relative path of the note to read (e.g. "Projects/2026/plan.md").',
        },
      },
      required: ['path'],
    },
  },
  {
    name: 'create_obsidian_note',
    description:
      'Create a NEW Markdown note inside the Obsidian Vault. Writes `content` to `filename` ' +
      '(relative to the Vault root). Fails if the file already exists (this tool never overwrites). ' +
      'Absolute paths, "~" and ".." traversal are rejected; the note can only be created inside the Vault.',
    input_schema: {
      type: 'object',
      properties: {
        filename: {
          type: 'string',
          description: 'Vault-root-relative filename for the new note (e.g. "Inbox/2026-06-08-meeting.md").',
        },
        content: {
          type: 'string',
          description: 'Markdown body to write into the new note.',
        },
      },
      required: ['filename', 'content'],
    },
  },
];

/** モデル出力 (unknown) を狭めるための最小型ガード。 */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function validateReadInput(input: unknown): Result<ReadNoteInput> {
  if (!isRecord(input) || typeof input.path !== 'string' || input.path.trim() === '') {
    return { ok: false, error: 'read_obsidian_note expects { path: <non-empty string> }' };
  }
  return { ok: true, value: { path: input.path } };
}

function validateCreateInput(input: unknown): Result<CreateNoteInput> {
  if (!isRecord(input) || typeof input.filename !== 'string' || input.filename.trim() === '') {
    return { ok: false, error: 'create_obsidian_note expects a non-empty string "filename"' };
  }
  if (typeof input.content !== 'string') {
    return { ok: false, error: 'create_obsidian_note expects a string "content"' };
  }
  if (input.content.length > MAX_WRITE_CHARS) {
    return { ok: false, error: `content too large (${input.content.length} > ${MAX_WRITE_CHARS} chars)` };
  }
  return { ok: true, value: { filename: input.filename, content: input.content } };
}

/**
 * 生の tool_use 要求を検証し、Vault 内座標へ解決する (Step 1 のサンドボックス境界)。
 * - 未知のツール名 → 拒否 (最小権限)
 * - 入力スキーマ不一致 → 拒否
 * - パスが Vault 外 → 拒否 (`resolveVaultPath` の strict 判定)
 *
 * 成功時は Human-in-the-Loop ゲートと実行に渡す `ValidatedToolCall` を返す。
 */
export function validateToolUse(req: ToolUseRequest): Result<ValidatedToolCall> {
  const vaultRoot = getVaultRoot();

  if (req.name === 'read_obsidian_note') {
    const parsed = validateReadInput(req.input);
    if (!parsed.ok) return parsed;
    const resolved = resolveVaultPath(parsed.value.path);
    if (!resolved.ok) {
      return { ok: false, error: `path rejected by Vault sandbox: ${resolved.reason}` };
    }
    return {
      ok: true,
      value: {
        id: req.id,
        name: 'read_obsidian_note',
        input: parsed.value,
        absolutePath: resolved.absolute,
        preview: `READ  ${resolved.safeRelative}  (in ${vaultRoot})`,
      },
    };
  }

  if (req.name === 'create_obsidian_note') {
    const parsed = validateCreateInput(req.input);
    if (!parsed.ok) return parsed;
    const resolved = resolveVaultPath(parsed.value.filename);
    if (!resolved.ok) {
      return { ok: false, error: `path rejected by Vault sandbox: ${resolved.reason}` };
    }
    const bytes = Buffer.byteLength(parsed.value.content, 'utf8');
    return {
      ok: true,
      value: {
        id: req.id,
        name: 'create_obsidian_note',
        input: parsed.value,
        absolutePath: resolved.absolute,
        preview: `CREATE ${resolved.safeRelative}  (${bytes} bytes, in ${vaultRoot})`,
      },
    };
  }

  return { ok: false, error: `unknown tool "${req.name}" — only read_obsidian_note / create_obsidian_note are allowed` };
}

/** File Read 実行: Vault 内の 1 ファイルを読む。検証済み座標前提。 */
function executeReadNote(call: Extract<ValidatedToolCall, { name: 'read_obsidian_note' }>): Result<string> {
  let stat: fs.Stats;
  try {
    stat = fs.statSync(call.absolutePath);
  } catch {
    return { ok: false, error: `file not found: ${call.input.path}` };
  }
  if (!stat.isFile()) {
    return { ok: false, error: `not a regular file: ${call.input.path}` };
  }
  if (stat.size > MAX_READ_BYTES) {
    return { ok: false, error: `file too large to read (${stat.size} > ${MAX_READ_BYTES} bytes): ${call.input.path}` };
  }
  try {
    const content = fs.readFileSync(call.absolutePath, 'utf8');
    return { ok: true, value: content };
  } catch (e) {
    return { ok: false, error: `read failed: ${(e as Error).message}` };
  }
}

/** File Write 実行: Vault 内に**新規**ノートを作る (上書き不可)。検証済み座標前提。 */
function executeCreateNote(call: Extract<ValidatedToolCall, { name: 'create_obsidian_note' }>): Result<string> {
  if (fs.existsSync(call.absolutePath)) {
    return { ok: false, error: `refusing to overwrite existing file: ${call.input.filename} (this tool only creates new notes)` };
  }
  try {
    fs.mkdirSync(path.dirname(call.absolutePath), { recursive: true });
    // wx フラグ: 「存在しないこと」を OS レベルで保証して TOCTOU 競合での上書きも防ぐ。
    fs.writeFileSync(call.absolutePath, call.input.content, { encoding: 'utf8', flag: 'wx' });
    return { ok: true, value: `Created note: ${call.input.filename}` };
  } catch (e) {
    return { ok: false, error: `write failed: ${(e as Error).message}` };
  }
}

/** 検証済み呼び出しを実行する (Step 3 の実体)。承認ゲート通過後にのみ呼ぶこと。 */
export function executeValidated(call: ValidatedToolCall): Result<string> {
  switch (call.name) {
    case 'read_obsidian_note':
      return executeReadNote(call);
    case 'create_obsidian_note':
      return executeCreateNote(call);
  }
}
