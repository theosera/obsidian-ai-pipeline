import readline from 'readline';

/**
 * プロンプト入力抽象層。
 *
 * index.ts から対話 I/O を分離する単一責任モジュール。ここだけが stdin/stdout を
 * 直接扱い、上位 (runner / interactive / config wizard 等) は askQuestion() 経由で
 * 対話する。
 *
 * Lazy init:
 *   readline.createInterface は副作用を伴う (stdin を即座にバインド)。
 *   テスト等で prompt.ts が transitively import されても stdin を奪わないよう、
 *   最初の askQuestion() 呼出し時に遅延初期化する。
 *
 * Pending question drain:
 *   stdin が閉じられると rl.question の callback は fire しない (Node.js の仕様)。
 *   pending resolver リストを保持し、close イベントで全てを空文字で resolve する
 *   ことでハングを防止する。
 */

let rl: readline.Interface | null = null;
let rlClosed = false;
const pending: Array<(v: string) => void> = [];

function getRl(): readline.Interface {
  if (!rl) {
    rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });
    rl.on('close', () => {
      rlClosed = true;
      while (pending.length) pending.shift()!('');
    });
  }
  return rl;
}

export function askQuestion(question: string): Promise<string> {
  return new Promise((resolve) => {
    if (rlClosed) return resolve('');
    pending.push(resolve);
    try {
      getRl().question(question, (answer) => {
        const idx = pending.indexOf(resolve);
        if (idx >= 0) pending.splice(idx, 1);
        resolve(answer ?? '');
      });
    } catch {
      const idx = pending.indexOf(resolve);
      if (idx >= 0) pending.splice(idx, 1);
      resolve('');
    }
  });
}

export function isPromptClosed(): boolean {
  return rlClosed;
}

export function closePrompt(): void {
  if (rl && !rlClosed) {
    rl.close();
  }
}
