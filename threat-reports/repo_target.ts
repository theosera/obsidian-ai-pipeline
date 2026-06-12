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
 * 割り当てて履歴を失わないようにする (db.ts の migrate が参照)。
 */
export const LEGACY_REPO_KEY = 'theosera/obsidian-ai-pipeline';

export interface RepoTarget {
  /** DB 上の正準キー。`owner/repo` または `local/<basename>`。 */
  key: string;
  /** buildRepoProfile が走査するローカル実体ルート (絶対パス)。 */
  root: string;
  /**
   * root が「指定リポの実チェックアウト」であることを確認できたか。
   * false = 見つからず cwd にフォールバックした状態 (= リポ識別はできるが fs 走査は
   * 別リポになる)。buildRepoProfile を走らせる analyze 側は located を必ず確認し、
   * located=false なら誤走査を避けて拒否する。レビュー済みフラグ付与 (key のみ) は located 不問。
   */
  located: boolean;
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
 * web セッションでは対象リポが cwd の **兄弟ディレクトリ** として checkout される
 * (例 cwd=/home/user/obsidian-ai-pipeline に対し /home/user/claude_openai_mcp_connector)。
 *
 * **basename 一致だけでは不十分** (Codex P2): owner 違いの同名リポ (fork 等) を指定すると、
 * 別 owner のチェックアウトを走査しつつノートを要求 owner キーで保存してしまう。よって候補の
 * **remote slug が要求 slug と一致 (大小文字無視)** することを確認できた場合のみ返す。確認
 * できない (remote 無し / owner 不一致) 場合は null → caller が located=false で誤走査を防ぐ。
 */
function locateLocalCheckout(
  slug: string,
  cwd: string,
  existsDir: (p: string) => boolean,
  remoteResolver: (root: string) => string | null,
): string | null {
  const name = slug.split('/')[1];
  const here = path.resolve(cwd);
  const candidates: string[] = [];
  const sibling = path.join(path.dirname(here), name);
  if (existsDir(sibling)) candidates.push(sibling);
  if (path.basename(here) === name) candidates.push(here);

  const want = slug.toLowerCase();
  for (const dir of candidates) {
    const url = remoteResolver(dir);
    const got = url ? parseRepoSlug(url) : null;
    if (got && got.toLowerCase() === want) return dir;
  }
  return null;
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
    // 指定なし = 現在のリポ (cwd 自身が実チェックアウト)。
    return { key: repoKeyFromRoot(cwd, remoteResolver), root: path.resolve(cwd), located: true };
  }

  const asPath = path.resolve(cwd, trimmed);
  if (existsDir(asPath)) {
    return { key: repoKeyFromRoot(asPath, remoteResolver), root: asPath, located: true };
  }
  if (SLUG_RE.test(trimmed)) {
    const slug = trimmed.replace(/\.git$/, '');
    const checkout = locateLocalCheckout(slug, cwd, existsDir, remoteResolver);
    // key は任意の owner/repo を受け付ける (= 3 リポに限定しない)。ただし checkout が
    // 見つからなければ located=false: 該当性判定はこのリポに対しては実行できない
    // (fs 走査対象が無い)。レビュー済みフラグ等 key だけの操作は引き続き可能。
    return { key: slug, root: checkout ?? path.resolve(cwd), located: checkout !== null };
  }
  // パスとして指定されたが存在しない → cwd へフォールバック (located=false で誤走査回避)。
  return { key: repoKeyFromRoot(cwd, remoteResolver), root: path.resolve(cwd), located: false };
}

export interface DiscoverOptions {
  /** 起点 (省略時 process.cwd())。この cwd 自身 + 兄弟ディレクトリを走査する。 */
  cwd?: string;
  remoteResolver?: (root: string) => string | null;
  existsDir?: (p: string) => boolean;
  /** ディレクトリ列挙 (テスト用)。既定 fs.readdirSync。 */
  listDir?: (p: string) => string[];
  /** `<root>/.git` 存在で git リポ判定 (テスト用)。既定 fs.existsSync。 */
  isGitRepo?: (root: string) => boolean;
}

/**
 * ローカルに clone 済みのリポジトリを列挙する (`/sec-review` の対象リポ選択メニュー用)。
 * cwd 自身と、その **兄弟ディレクトリ** (web セッションで対象リポが並ぶ場所) のうち
 * `.git` を持つものを正準キー付きで返す。3 リポに限定せず、ローカルに在るものを全部出す。
 */
export function discoverLocalRepos(opts: DiscoverOptions = {}): RepoTarget[] {
  const cwd = path.resolve(opts.cwd ?? process.cwd());
  const remoteResolver = opts.remoteResolver ?? defaultRemoteResolver;
  const existsDir = opts.existsDir ?? defaultExistsDir;
  const listDir = opts.listDir ?? ((p) => {
    try { return fs.readdirSync(p); } catch { return []; }
  });
  const isGitRepo = opts.isGitRepo ?? ((root) => {
    try { return fs.existsSync(path.join(root, '.git')); } catch { return false; }
  });

  const parent = path.dirname(cwd);
  const roots = new Set<string>();
  if (isGitRepo(cwd)) roots.add(cwd);
  for (const name of listDir(parent)) {
    const root = path.join(parent, name);
    if (existsDir(root) && isGitRepo(root)) roots.add(root);
  }
  return [...roots]
    .map((root) => ({ key: repoKeyFromRoot(root, remoteResolver), root, located: true }))
    .sort((a, b) => a.key.localeCompare(b.key));
}
