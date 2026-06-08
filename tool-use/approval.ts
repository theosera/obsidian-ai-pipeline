/**
 * Human-in-the-Loop 承認ゲート (Step 4 / 最重要)。
 *
 * 不変条件: モデルがツールを呼ぶたびに、ローカルでのファイル操作の**前に**必ず
 * ターミナルで人間の承認を取る。`y` / `yes` を明示入力しない限り**絶対に実行しない**。
 *
 * 設計上の判断 — fail-closed (`[y/N]`):
 *   タスク指示は `[Y/n]` と書かれているが、その本質要件は「Y を入力しない限り絶対に
 *   実行が走らない」こと。よってデフォルトは **No** とし、空 Enter / EOF / 想定外入力は
 *   すべて拒否に倒す。誤って Enter を連打しても破壊的操作が走らない安全側に倒す方が、
 *   この要件の意図に忠実である。
 *
 * I/O は `ask` を注入する (config wizard と同じ流儀)。テストでは入力をシミュレートでき、
 * 本番では `pipeline/prompt.ts::askQuestion` を渡す。
 */
import type { ApprovalGate, ValidatedToolCall } from './types';

/** 承認とみなす入力 (大文字小文字無視・前後空白除去後の完全一致)。 */
const AFFIRMATIVE = new Set(['y', 'yes']);

function describe(call: ValidatedToolCall): string {
  if (call.name === 'read_obsidian_note') {
    return `読み込み (File Read): ${call.input.path}`;
  }
  const lines = call.input.content.split('\n').length;
  return `新規メモ作成 (File Write): ${call.input.filename}  [${lines} 行]`;
}

/**
 * ターミナル `[y/N]` 承認ゲートを生成する。
 *
 * @param ask 1 行入力を取る関数 (本番: askQuestion / テスト: モック)。
 */
export function createTerminalApprovalGate(ask: (question: string) => Promise<string>): ApprovalGate {
  return async (call: ValidatedToolCall): Promise<boolean> => {
    console.log('\n──────────────────────────────────────────────');
    console.log('🔐 ツール実行の承認が必要です (Human-in-the-Loop)');
    console.log(`   操作: ${describe(call)}`);
    console.log(`   解決先: ${call.absolutePath}`);
    console.log('──────────────────────────────────────────────');

    const answer = (await ask('このツールを実行しますか? [y/N]: ')).trim().toLowerCase();
    const approved = AFFIRMATIVE.has(answer);
    console.log(approved ? '   ✅ 承認 — 実行します。' : '   ⛔ 拒否 — 実行をブロックしました。');
    return approved;
  };
}

/** テスト/非対話バッチ用: 常に拒否する fail-closed ゲート (明示注入専用)。 */
export const denyAllGate: ApprovalGate = async () => false;
