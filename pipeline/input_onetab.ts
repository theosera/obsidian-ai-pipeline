import fs from 'fs';
import { evaluatePolicy } from './policy';
import { ParsedEntry, FailureRecord } from './types';

/**
 * OneTab エクスポート .txt を ParsedEntry[] に変換。
 *
 * 入力フォーマット: 各行が `<URL> | <title>` (OneTab のエクスポート形式)。
 *
 * フィルタリング:
 *   - 空行 / パイプ区切りが無い行は黙って読み飛ばし
 *   - knownUrls に含まれる URL は重複スキップ (Vault 内既存記事を二重保存しない)
 *   - evaluatePolicy が manual_skip を返した URL はスキップ
 *
 * ログ副作用: 読み込み/スキップの進捗を console.log で逐次出す。
 * 純粋関数ではないが、大量 URL の進捗可視化が UX として必須なので許容する。
 */
export function readOneTabFile(
  filePath: string,
  knownUrls: Set<string>
): { entries: ParsedEntry[]; failures: FailureRecord[] } {
  const entries: ParsedEntry[] = [];
  const failures: FailureRecord[] = [];

  const content = fs.readFileSync(filePath, 'utf-8');
  const allLines = content.split('\n').filter((l) => l.trim() !== '');

  for (let i = 0; i < allLines.length; i++) {
    const line = allLines[i];
    const pipeIdx = line.indexOf(' | ');
    if (pipeIdx === -1) continue;

    const url = line.substring(0, pipeIdx).trim();
    const title = line.substring(pipeIdx + 3).trim();

    // Vault 内の重複 URL チェック。末尾スラッシュ違いを同一視して FP を減らす。
    const checkUrl = url.endsWith('/') ? url.slice(0, -1) : url;
    if (knownUrls.has(checkUrl)) {
      console.log(
        `[${i + 1}/${allLines.length}] ${title.substring(0, 30)}... Skipped (Duplicate in Vault)`
      );
      failures.push({ url, title, reason: 'Duplicate: Already exists in Vault' });
      continue;
    }

    const policy = evaluatePolicy(url);
    if (policy === 'manual_skip') {
      console.log(`[${i + 1}/${allLines.length}] ${title.substring(0, 30)}... Skipped (manual_skip)`);
      failures.push({ url, title, reason: 'Site Policy: manual_skip' });
    } else {
      entries.push({ url, title, policy });
    }
  }

  return { entries, failures };
}
