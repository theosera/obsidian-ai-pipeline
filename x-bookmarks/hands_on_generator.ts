/**
 * X ブックマーク群を素材に、Claude Code CLI (OAuth サブスク枠) を呼び出して
 * ハンズオン形式のチュートリアル .md を生成する。
 *
 * 前提:
 *   - ローカルに Claude Code CLI (`claude`) がインストールされ OAuth 認証済み
 *   - 対象フォルダの X ブックマークが既に Vault + SQLite DB に投入済み
 *
 * 素材の抽出元:
 *   <vault>/__skills/pipeline/x_bookmarks.db の bookmarks テーブル。
 *   vault_path が "<X_Bookmarks base>/<folder>/" で始まる行を対象に、
 *   `--since=YYYY-MM-DD` 指定時は created_at の前方一致フィルタも併用する。
 *
 * 生成先:
 *   <vault>/Permanent Note/09_X_Bookmarks/<folder-slug>-YYYYMMDD.md
 *   (旧出力: <vault>/__skills/context/ハンズオン/ は 2026-05 リファクタで廃止)
 */
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { spawn, spawnSync } from 'child_process';
import { getVaultRoot, getPipelineDbDir } from '../config';
import { neutralizeUntrusted, UNTRUSTED_OPEN_TAG, UNTRUSTED_CLOSE_TAG } from './untrusted_text';
import Database from 'better-sqlite3';

interface BookmarkRow {
  tweet_id: string;
  url: string;
  author: string | null;
  tweet_text: string | null;
  created_at: string | null;
  x_folder_name: string | null;
  vault_path: string | null;
}

export interface HandsOnOptions {
  /** 対象 Vault フォルダ (例: "X_Bookmarks/Claude Code") */
  folder: string;
  /** YYYY-MM-DD 形式、指定日以降のポストのみ */
  since?: string;
  /** テスト用: claude コマンドを呼び出さずプロンプトを返すだけ */
  dryRun?: boolean;
  /** テスト用: claude コマンドパス上書き */
  claudeBin?: string;
}

const PROMPT_TEMPLATE_PATH = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  'prompts',
  'hands_on.md'
);

function dbPath(): string {
  // db.ts と同じ getPipelineDbDir() 経由にする。PIPELINE_DB_DIR 上書き時に
  // sync (db.ts) の書込先と --hands-on の読込先が食い違わないようにするため
  // (食い違うと「x_bookmarks.db not found」または stale DB 読み込みになる)。
  return path.join(getPipelineDbDir(), 'x_bookmarks.db');
}

function loadBookmarksForFolder(folder: string, since?: string): BookmarkRow[] {
  const p = dbPath();
  if (!fs.existsSync(p)) {
    throw new Error(`x_bookmarks.db が見つかりません: ${p}\n  先に --x-bookmarks で同期してください。`);
  }
  const db = new Database(p, { readonly: true });
  try {
    const likePattern = `${folder.replace(/\/+$/, '')}/%`;
    const exactPattern = folder.replace(/\/+$/, '');
    const params: any[] = [likePattern, exactPattern];
    let sql = `
      SELECT tweet_id, url, author, tweet_text, created_at, x_folder_name, vault_path
      FROM bookmarks
      WHERE (vault_path LIKE ? OR vault_path = ?)
    `;
    if (since) {
      sql += ` AND created_at >= ?`;
      params.push(since);
    }
    sql += ` ORDER BY created_at DESC`;
    return db.prepare(sql).all(...params) as BookmarkRow[];
  } finally {
    db.close();
  }
}

/**
 * ポスト群を 1 つの素材ブロックにまとめる。
 *
 * `tweet_text` / `author` / `url` は **第三者が書いた untrusted データ** (X API 由来)。
 * ここを素通しすると、プロンプト末尾に置かれた本文がそのまま「最後の指示」として
 * モデルに読まれる (間接プロンプトインジェクション)。`neutralizeUntrusted` で
 * 隠蔽キャリア・偽区切り・fence 偽装を落としてから連結する。
 *
 * 注意: サニタイズで落ちるのは**構造的な**偽装だけ。見た目に違和感のない
 * 「説得型」の命令文は落ちない (`untrusted_text.ts` の既知の限界)。命令として
 * 解釈させない役割はプロンプト側の fence + 優先順位規則が担う。
 */
export function buildCorpus(rows: BookmarkRow[]): string {
  if (rows.length === 0) return '(素材なし)';
  return rows
    .map((r, i) => {
      const author = r.author ? neutralizeUntrusted(r.author) : '';
      const head = `### Post ${i + 1}${author ? ` by @${author}` : ''}${r.created_at ? ` (${r.created_at})` : ''}`;
      const body = neutralizeUntrusted(r.tweet_text ?? '').trim();
      return `${head}\n${body}\n元ポスト: ${neutralizeUntrusted(r.url)}\n`;
    })
    .join('\n---\n\n');
}

/**
 * テンプレートが「`{{corpus}}` を untrusted fence で囲んでいる」ことを検証する。
 *
 * fence はプロンプト側 (`prompts/hands_on.md`) に書いてあるので、テンプレートを
 * 編集した人が誤って外すと、コードは無傷のまま防御だけが消える。ここで
 * **構造として強制**し、外れていたら生成させない (fail-closed)。
 */
function assertCorpusIsFenced(tpl: string): void {
  const open = tpl.indexOf(UNTRUSTED_OPEN_TAG);
  const close = tpl.indexOf(UNTRUSTED_CLOSE_TAG);
  const corpus = tpl.indexOf('{{corpus}}');
  if (open === -1 || close === -1 || corpus === -1 || !(open < corpus && corpus < close)) {
    throw new Error(
      `プロンプトテンプレートが壊れています: {{corpus}} が ${UNTRUSTED_OPEN_TAG} … ` +
        `${UNTRUSTED_CLOSE_TAG} の内側にありません (${PROMPT_TEMPLATE_PATH})。\n` +
        '  untrusted なポスト本文を fence 無しで渡すことになるため生成を中止しました。'
    );
  }
}

/**
 * プレースホルダを置換する。
 *
 * 置換値は必ず**関数**で渡す: 文字列を渡すと `$&` / `` $` `` / `$'` / `$1` が
 * 置換パターンとして解釈され、ポスト本文からテンプレートの他の部分を複製・
 * 再構成できてしまう (fence の外へ本文を貼り出す経路になる)。
 */
export function renderPrompt(folder: string, corpus: string, date: string): string {
  const tpl = fs.readFileSync(PROMPT_TEMPLATE_PATH, 'utf8');
  assertCorpusIsFenced(tpl);
  return tpl
    .replace(/\{\{folder\}\}/g, () => folder)
    .replace(/\{\{corpus\}\}/g, () => corpus)
    .replace(/\{\{date\}\}/g, () => date);
}

function folderSlug(folder: string): string {
  // "X_Bookmarks/Claude Code" → "Claude Code"
  const last = folder.split('/').filter(Boolean).pop() ?? 'unfiled';
  return last.replace(/[\/\\:*?"<>|]/g, '_').replace(/\s+/g, ' ').trim().slice(0, 80);
}

/**
 * `claude` をテキスト生成専用に落とすための引数。**プロンプトの直前に置く。**
 *
 * `claude -p` は agentic ランタイムなので、素で呼ぶと「呼び出し元の権限を持った
 * エージェント」に第三者のポスト本文を渡すことになる。`-p` は非対話なので
 * 承認ダイアログも出せない (= 事前承認済みのツールは無言で走る)。
 *
 *   --tools ''             組込ツールを全て無効化 (= ファイル/シェル/ネットワーク到達なし)
 *   --strict-mcp-config    --mcp-config で渡したものだけを使う = MCP サーバを一切ロードしない
 *   --permission-mode manual  自動承認しない。-p は問い合わせできないので実質すべて拒否
 *   --safe-mode            CLAUDE.md / skills / plugins / hooks / MCP など全カスタマイズを無効化
 *
 * `--safe-mode` は隔離のためだけでなく**出力品質のため**でもある: 無しで実測すると
 * ユーザー層 `~/.claude/CLAUDE.md` の指示 (「回答末尾に JST 時刻を出す」等) が
 * 生成物に混入し、そのまま Vault のノートへ書き込まれる。
 *
 * これに加えて `cwd` を使い捨ての一時ディレクトリにし、リポジトリの
 * `.claude/settings.json` / `settings.local.json` / hooks / CLAUDE.md を
 * 探索させない (下の `generateHandsOn` を参照)。
 *
 * **効いているのは主に `--tools ''`** (ツールを 1 つも持たせない) であって、
 * cwd 隔離と `--safe-mode` は多層防御の残り 2 枚。設定探索を止めても、
 * 「モデルが何を書くか」自体は素材に影響される (= 出力汚染は残る。だから
 * プロンプト側の fence と併用する)。
 */
const CLAUDE_TEXT_ONLY_ARGS: readonly string[] = [
  '-p',
  '--safe-mode',
  '--tools', '',
  '--strict-mcp-config',
  '--permission-mode', 'manual',
];

function preflightClaudeCli(bin: string): void {
  // `claude --version` で疎通確認
  const res = spawnSync(bin, ['--version'], { encoding: 'utf8' });
  if (res.error || res.status !== 0) {
    throw new Error(
      `claude CLI が見つかりません (${bin})。\n` +
        '  - Claude Code をインストール: https://claude.ai/code\n' +
        '  - OAuth サインイン: `claude`'
    );
  }
}

export async function generateHandsOn(options: HandsOnOptions): Promise<string> {
  const folder = options.folder.replace(/\/+$/, '');
  const slug = folderSlug(folder);
  const today = new Date();
  const dateStr = today.toISOString().split('T')[0];
  const dateCompact = dateStr.replace(/-/g, '');

  const rows = loadBookmarksForFolder(folder, options.since);
  if (rows.length === 0) {
    throw new Error(`対象フォルダに素材がありません: ${folder}${options.since ? ` (since=${options.since})` : ''}`);
  }
  console.log(`📝 ${rows.length} 件のポストを素材にします。`);

  const corpus = buildCorpus(rows);
  const prompt = renderPrompt(folder, corpus, dateStr);

  const outDir = path.join(getVaultRoot(), 'Permanent Note', '09_X_Bookmarks');
  if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
  const outPath = path.join(outDir, `${slug}-${dateCompact}.md`);

  if (options.dryRun) {
    fs.writeFileSync(outPath + '.prompt.txt', prompt, 'utf8');
    console.log(`🧪 dry-run: プロンプトを保存しました ${outPath}.prompt.txt`);
    return outPath + '.prompt.txt';
  }

  const claudeBin = options.claudeBin ?? 'claude';
  preflightClaudeCli(claudeBin);

  console.log(`🤖 claude CLI を呼び出し中 (プロンプト ${prompt.length} 文字)...`);

  // 空の一時ディレクトリで走らせる: claude はここを起点に project 設定
  // (.claude/settings.json / settings.local.json / hooks) と CLAUDE.md を探すので、
  // 空ディレクトリなら「このリポジトリで事前承認したツール」を継承しない。
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'x-hands-on-'));
  let generated: string;
  try {
    generated = await new Promise<string>((resolve, reject) => {
      const proc = spawn(claudeBin, [...CLAUDE_TEXT_ONLY_ARGS, prompt], {
        cwd: workDir,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      const chunks: Buffer[] = [];
      const errChunks: Buffer[] = [];
      proc.stdout.on('data', d => chunks.push(d));
      proc.stderr.on('data', d => errChunks.push(d));
      proc.on('error', reject);
      proc.on('close', code => {
        if (code !== 0) {
          reject(
            new Error(
              `claude CLI が異常終了 (code=${code}): ${Buffer.concat(errChunks).toString('utf8').slice(0, 1000)}`
            )
          );
        } else {
          resolve(Buffer.concat(chunks).toString('utf8'));
        }
      });
    });
  } finally {
    fs.rmSync(workDir, { recursive: true, force: true });
  }

  fs.writeFileSync(outPath, generated, 'utf8');
  console.log(`✅ ハンズオンを生成しました: ${outPath}`);
  return outPath;
}
