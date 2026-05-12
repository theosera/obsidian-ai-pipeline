/**
 * X API v2 の取得欠損 (partial fetch) を可視化するモジュール。
 *
 * 目的:
 *   - `/bookmarks/folders/{id}` が `meta.next_token` を返したのに
 *     X API がそれ以外の query を一切受け付けず追加取得できないケースを記録する。
 *   - 結果としてフォルダ内ブックマークの一部が DB に入らない (silent loss) 問題を
 *     人間が後から把握できるよう、(a) MD レポート と (b) hands-on バナー用の
 *     機械可読 JSON の 2 系統に書き出す。
 *
 * 設計:
 *   - DB スキーマには手を入れない (per-run の状態は in-memory コレクタ + 派生ファイル)。
 *   - レポート (.md) は既存 `writeGroupingProposal` と同じ
 *     `<vault>/__skills/context/分類結果レポート/` に書き出して見つけやすくする。
 *   - JSON は `<vault>/__skills/pipeline/x_bookmarks_partial_latest.json` に
 *     **最新 1 世代のみ** 保存。hands_on_generator が x_folder_id 単位で参照する。
 *   - Codex 側との対照実験を壊さないよう、レポート MD のファイル名に `claude_` を入れる。
 */

import fs from 'fs';
import path from 'path';
import { getVaultRoot } from './config';

export interface PartialFolderRecord {
  /** X 側フォルダ ID (folder_sessions.x_folder_id と一致) */
  xFolderId: string;
  /** X 側フォルダ表示名 (raw) */
  xFolderName: string;
  /** このフォルダから今回の sync で実際に取得できたツイート数 */
  fetchedCount: number;
  /** 検出理由。現状 `/bookmarks/folders/{id}` の next_token 不対応のみ。 */
  reason: 'folder_next_token_unsupported';
  /** 検出時刻 (ISO 8601) */
  detectedAt: string;
}

export interface PartialLatestPayload {
  version: 1;
  generatedAt: string;
  records: PartialFolderRecord[];
}

function reportDir(): string {
  return path.join(getVaultRoot(), '__skills', 'context', '分類結果レポート');
}

function latestJsonPath(): string {
  return path.join(getVaultRoot(), '__skills', 'pipeline', 'x_bookmarks_partial_latest.json');
}

/**
 * 欠損レポートを `分類結果レポート/x_bookmarks_partial_claude_YYYYMMDD.md` として書き出す。
 * `records` が空なら何もせず空文字を返す。
 */
export function writePartialReport(records: PartialFolderRecord[]): string {
  if (records.length === 0) return '';
  const dir = reportDir();
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  const dateStr = new Date().toISOString().split('T')[0].replace(/-/g, '');
  const file = path.join(dir, `x_bookmarks_partial_claude_${dateStr}.md`);

  let md = `# X ブックマーク 取得欠損レポート (partial fetch)\n\n`;
  md += `生成日時: ${new Date().toISOString()}\n\n`;
  md += `以下のフォルダは X API v2 が \`meta.next_token\` を返したものの、\n`;
  md += `\`/bookmarks/folders/{id}\` がページネーション引数を受け付けないため\n`;
  md += `追加取得できませんでした (silent loss の可能性)。\n\n`;
  md += `**対処の選択肢**:\n`;
  md += `1. 当該フォルダ内のブックマーク数を X UI 上で目視確認し、\n`;
  md += `   このリストの \`取得済み\` と差分を取る\n`;
  md += `2. 欠落分が運用上問題なら、UI 経由の取得 (ブラウザ拡張 / GraphQL 直叩き)\n`;
  md += `   を別途検討する\n\n`;
  md += `| X フォルダ ID | フォルダ名 | 取得済み | 検出時刻 |\n`;
  md += `| --- | --- | --- | --- |\n`;
  for (const r of records) {
    const safeName = r.xFolderName.replace(/\|/g, '\\|');
    md += `| \`${r.xFolderId}\` | ${safeName} | ${r.fetchedCount} | ${r.detectedAt} |\n`;
  }
  md += `\n---\n`;
  md += `本ファイルは sync 毎に上書きされる前提です (日付別)。\n`;

  fs.writeFileSync(file, md, 'utf8');
  return file;
}

/**
 * hands-on 生成側 / 他ツールから x_folder_id 単位で参照するための機械可読 JSON。
 * **常に最新 1 世代のみ** 保持 (差分追跡は MD レポート側が担う)。
 * 空配列でも書き出すことで「前回の partial 状態を消す」セマンティクスを持たせる。
 */
export function savePartialLatest(records: PartialFolderRecord[]): string {
  const p = latestJsonPath();
  const dir = path.dirname(p);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const payload: PartialLatestPayload = {
    version: 1,
    generatedAt: new Date().toISOString(),
    records,
  };
  const tmp = `${p}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(payload, null, 2), 'utf8');
  fs.renameSync(tmp, p);
  return p;
}

/**
 * 最新 partial 一覧を読み込み。ファイル不在 / 破損時は空配列。
 */
export function loadPartialLatest(): PartialFolderRecord[] {
  const p = latestJsonPath();
  if (!fs.existsSync(p)) return [];
  try {
    const raw = JSON.parse(fs.readFileSync(p, 'utf8')) as PartialLatestPayload;
    if (raw.version !== 1 || !Array.isArray(raw.records)) return [];
    return raw.records;
  } catch {
    return [];
  }
}

/**
 * x_folder_id が partial だったかを問い合わせる。
 * hands_on_generator など「フォルダ単位」で扱う側のための薄いヘルパー。
 */
export function findPartialByXFolderId(
  xFolderId: string,
  records?: PartialFolderRecord[]
): PartialFolderRecord | undefined {
  const list = records ?? loadPartialLatest();
  return list.find(r => r.xFolderId === xFolderId);
}

export const __test = {
  reportDir,
  latestJsonPath,
};
