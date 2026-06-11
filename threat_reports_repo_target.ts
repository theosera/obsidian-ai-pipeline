/**
 * `/sec-review` の該当性レビュー対象リポジトリを **正準キー (owner/repo スラッグ)** に
 * 解決する。web チャット (GitHub リポ指定) と Claude Code CLI (ローカルパス指定) の
 * どちらの入力からも **同じ repo_key** に収束させることが目的。
 *
 * 設計:
 *   - DB 上の per-repo 管理キー = `owner/repo` スラッグ (例 `theosera/obsidian-ai-pipeline`)。
 *   - スキャン用の実体ルート (`root`) = ローカルチェックアウトの絶対パス。buildRepoProfile が
 *     fs/grep でこのルートを決定的に走査する。
 *   - git remote が取れないローカルリポは `local/<basename>` にフォールバック (衝突回避)。
 *
 * Trust Boundary: 本モジュールはレポート本文を一切扱わない (リポ識別のみ)。git 呼び出しは
 * `remote.origin.url` の読取だけ (副作用なし)。テストでは `remoteResolver` / `existsDir` を
 * 注入して child_process / fs なしで回せる。
 */

import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

/**
 * per-repo 化以前に作られた `ai_relevance_note` / `relevance_reviewed_at` は
 * **obsidian-ai-pipeline に対するレビュー結果**だった。スキーマ移行時にこのキーへ
 * 割り当てて履歴を失わないようにする (threat_reports_db.ts の migrate が参照)。
 */
export const LEGACY_REPO_KEY = 'theosera/obsidian-ai-pipeline';

export interface RepoTarget {
  /** DB 上の正準キー。`owner/repo` または `local/<basename>`。 */
  key: string;
  /** buildRepoProfile が走査するローカル実体ルート (絶対パス)。 */
  root: string;
}

/** `owner/repo` 形 (パスではなく GitHub スラッグ) の判定。 */
const SLUG_RE = /^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/;

/**
 * git remote URL から `owner/repo` を抽出する。
 * 対応: `git@github.com:owner/repo.git` / `https://github.com/owner/repo(.git)` /
 *       `ssh://git@github.com/owner/repo.git`。末尾 `.git` は除去。
 */
export function parseRepoSlug(remoteUrl: string): string | null {
  const cleaned = remoteUrl.trim().replace(/\.git$/, '');
  const m = cleaned.match(/[:/]([A-Za-z0-9._-]+)\/([A-Za-z0-9._-]+)$/);
  return m ? `${m[1]}/${m[2]}` : null;
}

function defaultRemoteResolver(root: string): string | null {
  try {
    const out = execFileSync('git', ['-C', root, 'config', '--get', 'remote.origin.url'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    return out.trim() || null;
  } catch {
    return null;
  }
}

export interface ResolveOptions {
  /** 基準ディレクトリ (省略時 process.cwd())。ローカルチェックアウト探索の起点。 */
  cwd?: string;
  /** git remote 解決の差し替え (テスト用)。 */
  remoteResolver?: (root: string) => string | null;
  /** ディレクトリ存在判定の差し替え (テスト用)。 */
  existsDir?: (p: string) => boolean;
}

function defaultExistsDir(p: string): boolean {
  try {
    return fs.statSync(p).isDirectory();
  } catch {
    return false;
  }
}

function repoKeyFromRoot(root: string, remoteResolver: (r: string) => string | null): string {
  const url = remoteResolver(root);
  const slug = url ? parseRepoSlug(url) : null;
  return slug ?? `local/${path.basename(path.resolve(root))}`;
}

/**
 * `owner/repo` スラッグに対応するローカルチェックアウトを探す。
 * web セッションでは対象 3 リポが cwd の **兄弟ディレクトリ** として checkout される
 * (例 cwd=/home/user/obsidian-ai-pipeline に対し /home/user/claude_openai_mcp_connector)。
 * 見つからなければ cwd を最後の手段として返す (key はスラッグのまま)。
 */
function locateLocalCheckout(slug: string, cwd: string, existsDir: (p: string) => boolean): string {
  const name = slug.split('/')[1];
  const here = path.resolve(cwd);
  const sibling = path.join(path.dirname(here), name);
  if (existsDir(sibling)) return sibling;
  if (path.basename(here) === name) return here;
  return here;
}

/**
 * レビュー対象リポジトリの指定を `{ key, root }` に解決する。
 *
 * 入力 `spec`:
 *   - undefined / 空      → 現在のリポ (cwd)。key は git remote から導出。
 *   - `owner/repo` スラッグ → key=スラッグ、root=ローカルチェックアウト (兄弟ディレクトリ)。
 *   - ローカルパス        → root=そのパス、key は git remote から導出。
 *
 * スラッグ形と実在ディレクトリが衝突した場合 (例 cwd 配下に偶然 `owner/repo` という
 * ディレクトリがある) は **実在パスを優先** する (= そこを走査する方が安全)。
 */
export function resolveRepoTarget(spec: string | undefined, opts: ResolveOptions = {}): RepoTarget {
  const cwd = opts.cwd ?? process.cwd();
  const remoteResolver = opts.remoteResolver ?? defaultRemoteResolver;
  const existsDir = opts.existsDir ?? defaultExistsDir;

  const trimmed = spec?.trim();
  if (!trimmed) {
    return { key: repoKeyFromRoot(cwd, remoteResolver), root: path.resolve(cwd) };
  }

  const asPath = path.resolve(cwd, trimmed);
  if (existsDir(asPath)) {
    return { key: repoKeyFromRoot(asPath, remoteResolver), root: asPath };
  }
  if (SLUG_RE.test(trimmed)) {
    const slug = trimmed.replace(/\.git$/, '');
    return { key: slug, root: locateLocalCheckout(slug, cwd, existsDir) };
  }
  // パスとして指定されたが存在しない → cwd を走査しつつ key は導出 (誤指定の安全側)。
  return { key: repoKeyFromRoot(cwd, remoteResolver), root: path.resolve(cwd) };
}
