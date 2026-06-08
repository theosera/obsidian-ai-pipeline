/**
 * Tool Use (Function Calling) 実行レイヤーの Tier1 型定義。
 *
 * 設計方針 (ai-coding-conventions §1/§3): 構造は**型で表現**し、ツールの「許可集合」
 * `ToolName` を union で固定する (= 最小権限のコンパイル時保証 — 列挙されていない
 * ツール名はそもそも型に存在しないため、新ツールはここに 1 件追加しない限り増やせない)。
 *
 * このリポは Zod 非導入のため API 境界は手動バリデーション (`tools.ts::validateToolUse`)
 * で行うが、戻り値は必ず `Result<T, E>` 判別 union に載せ「成功/失敗をフィールド存在で
 * 表す」曖昧さを排除する。
 */

/** 成功/失敗を型で明示する判別 union (ai-coding-conventions §3 union_error)。 */
export type Result<T, E = string> =
  | { ok: true; value: T }
  | { ok: false; error: E };

/**
 * 許可ツールの**閉じた集合** (最小権限 / Step 1)。
 * - `read_obsidian_note`   : Vault 内の指定ファイルを読む (File Read)
 * - `create_obsidian_note` : Vault 内に**新規**メモを作る (File Write / 上書き不可)
 *
 * これ以外は型として存在しない。OS ネイティブ連携 (AppleScript / メール / shell 実行)
 * は意図的に**型にすら含めない** = 実装経路を持たせない。
 */
export type ToolName = 'read_obsidian_note' | 'create_obsidian_note';

/** `read_obsidian_note` の入力 (Vault ルートからの相対パス)。 */
export interface ReadNoteInput {
  /** Vault ルートからの相対パス。絶対パス / `..` は実行レイヤーで拒否される。 */
  path: string;
}

/** `create_obsidian_note` の入力。 */
export interface CreateNoteInput {
  /** Vault ルートからの相対ファイル名/パス (例: "Inbox/idea.md")。 */
  filename: string;
  /** 書き込むノート本文 (Markdown)。 */
  content: string;
}

/**
 * モデル応答から抽出した **生の** tool_use ブロック。
 * `name` / `input` は未検証 (モデル出力 = untrusted) で、`validateToolUse` を通すまで
 * 信用しない。
 */
export interface ToolUseRequest {
  id: string;
  name: string;
  input: unknown;
}

/**
 * バリデーション済みのツール呼び出し (判別 union)。`absolutePath` は 7 フェーズ防御を
 * 通過済みの Vault 内座標、`preview` は Human-in-the-Loop ゲートで人間に提示する 1 行要約。
 */
export type ValidatedToolCall =
  | {
      id: string;
      name: 'read_obsidian_note';
      input: ReadNoteInput;
      absolutePath: string;
      preview: string;
    }
  | {
      id: string;
      name: 'create_obsidian_note';
      input: CreateNoteInput;
      absolutePath: string;
      preview: string;
    };

/**
 * 1 つのツール実行結果。`tool_use_id` でモデルの tool_use ブロックと対応づけ、
 * `tool_result` として会話へ返す。`isError` はモデルにエラーを伝える Anthropic の規約。
 */
export interface ToolOutcome {
  toolUseId: string;
  content: string;
  isError: boolean;
}

/** Human-in-the-Loop ゲート: 検証済み呼び出しと解決済み座標を見て承認/拒否を返す。 */
export type ApprovalGate = (call: ValidatedToolCall) => Promise<boolean>;
