import readline from 'readline';

/**
 * プロンプト入力抽象層。
 *
 * index.ts から対話 I/O を分離する単一責任モジュール。ここだけが stdin/stdout を
 * 直接扱い、上位 (runner / interactive / config wizard 等) は askQuestion() 経由で
 * 対話する。
 *
 * stdin EOF 対応:
 *   - パイプ実行や非対話環境では stdin が早期に閉じられる。
 *   - rl.close() 後に rl.question() を呼ぶと ERR_USE_AFTER_CLOSE が飛ぶため、
 *     閉鎖フラグを保持し以降の問いに対しては空文字を即座に resolve する。
 *   - 呼び出し側は「空文字 = 入力なし = quit 相当」として扱うことで、
 *     非対話環境でも安全に終了できる。
 */

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

let rlClosed = false;
rl.on('close', () => {
  rlClosed = true;
});

export function askQuestion(question: string): Promise<string> {
  return new Promise((resolve) => {
    if (rlClosed) {
      resolve('');
      return;
    }
    try {
      rl.question(question, (answer) => resolve(answer ?? ''));
    } catch {
      // rl がすでに閉じられているが rlClosed イベントが遅延した場合のフォールバック
      resolve('');
    }
  });
}

export function isPromptClosed(): boolean {
  return rlClosed;
}

export function closePrompt(): void {
  if (!rlClosed) {
    rl.close();
  }
}
