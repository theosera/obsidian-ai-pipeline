/**
 * Level 2 (検知) の補強: 各 finding を対象リポに **決定的に grep** し、該当しうる
 * file:line を「候補」として収集する。relevance.ts の判定 LLM へ finding 固有の
 * ground-truth な所在ヒントを与え、下書きノートに「該当ファイル+行の候補」を載せる
 * (consumption policy §4 の証拠点 #2 の機械生成)。
 *
 * Trust Boundary (本モジュールの設計上の不変条件):
 *   1. **検索種は untrusted な finding 本文から抽出するが、抽出は決定的**
 *      (識別子風トークンのみ) で、**literal substring 一致**にしか使わない
 *      (正規表現化しない = ReDoS / メタ文字注入なし)。本文中の指示・URL・コードは
 *      実行も fetch もしない。
 *   2. **返すのは file:line と一致語のみ。行の内容 (content) は一切返さない**。
 *      これにより、悪意ある finding が「秘密値の所在を grep させてノート経由で
 *      exfil する」経路を塞ぐ (ノートは vault repo に書き出されるため)。
 *   3. 秘密ファイル (.env / *.key / *.pem / credentials* / *_tokens.json 等) と
 *      node_modules / .git / ビルド成果物は走査対象から除外する。
 *   4. 走査はファイル数 / バイト / ヒット件数を上限で必ず打ち切る (bounded, never hang)。
 */

import fs from 'fs';
import path from 'path';

/** 1 件の grep ヒット。**行内容は持たない** (file:line と一致語のみ)。 */
export interface EvidenceHit {
  /** 走査ルートからの相対パス (POSIX 区切り)。 */
  file: string;
  /** 1-based 行番号。 */
  line: number;
  /** 一致した検索語 (finding 由来。秘密値ではない)。 */
  term: string;
}

export interface RepoScanner {
  /** 与えた検索語群に literal 一致する候補 file:line を返す (bounded)。 */
  find(terms: string[]): EvidenceHit[];
  /** プリロードしたテキストファイル数。 */
  filesLoaded: number;
  /** 上限到達で走査を打ち切ったか (= カバレッジ不完全の可能性)。 */
  truncated: boolean;
}

export interface ScannerOptions {
  /** プリロードする最大ファイル数。 */
  maxFiles?: number;
  /** プリロードする最大総バイト数。 */
  maxTotalBytes?: number;
  /** 1 ファイルあたりの最大バイト数 (超過はスキップ)。 */
  maxFileBytes?: number;
}

const DEFAULT_MAX_FILES = 4000;
const DEFAULT_MAX_TOTAL_BYTES = 32 * 1024 * 1024; // 32 MB
const DEFAULT_MAX_FILE_BYTES = 512 * 1024; // 512 KB

/** 走査語の最小/最大長と最大件数。短すぎる語はノイズ源なので除外する。 */
const MIN_TERM_LEN = 4;
const MAX_TERM_LEN = 64;
const MAX_TERMS = 12;

/** find() の上限。 */
const MAX_HITS_TOTAL = 50;
const MAX_HITS_PER_TERM = 5;

/** NUL バイト (バイナリ判定用)。ソースに生の制御文字を埋め込まない。 */
const NUL_CHAR = String.fromCharCode(0);

/** 走査から除外するディレクトリ名 (どの階層でも)。 */
const EXCLUDED_DIRS = new Set([
  '.git', 'node_modules', 'dist', 'build', 'out', 'coverage',
  '.next', '.turbo', '.cache', 'vendor', '.venv', '__pycache__',
]);

/** プリロードするテキスト拡張子 (バイナリ/巨大ファイルを読まないための allowlist)。 */
const TEXT_EXTENSIONS = new Set([
  '.ts', '.tsx', '.js', '.jsx', '.cjs', '.mjs', '.json', '.jsonc',
  '.yml', '.yaml', '.toml', '.ini', '.cfg', '.conf',
  '.py', '.sh', '.bash', '.rb', '.go', '.rs', '.java', '.kt',
  '.md', '.mdx', '.txt', '.sql', '.graphql', '.proto',
]);

/**
 * 秘密ファイルの判定 (ファイル名ベース)。一致するファイルは **走査対象から除外** する
 * (ノート経由の secret exfil を防ぐ二重防御。content を返さない設計と合わせる)。
 */
export function isSecretFile(name: string): boolean {
  const lower = name.toLowerCase();
  if (lower === '.env' || lower.startsWith('.env.')) return true;
  if (lower.endsWith('.key') || lower.endsWith('.pem') || lower.endsWith('.p12') || lower.endsWith('.pfx')) return true;
  if (lower.startsWith('credentials') || lower.startsWith('id_rsa') || lower.startsWith('id_ed25519')) return true;
  if (lower.endsWith('_tokens.json') || lower === 'x_tokens.json') return true;
  return false;
}

/**
 * finding の構造化フィールド群から **決定的に** 検索語を抽出する。
 * 採用するのは「コード識別子らしい」トークンのみ (ドット付き API / camelCase /
 * snake_case / ファイルパス・拡張子) — 一般的な英単語や散文を grep 種にしないことで、
 * (a) 偽陽性の洪水を避け、(b) `AKIA...` のような秘密パターンを untrusted text から
 * grep させられる経路を作らない (ドット/アンダースコア/大文字の山が無い語は弾く)。
 */
export function extractSearchTerms(fields: Array<string | null | undefined>): string[] {
  const text = fields.filter((f): f is string => typeof f === 'string' && f.length > 0).join('\n');
  const seen = new Set<string>();
  const out: string[] = [];

  // 候補トークン: バッククォート内 / ドット付き API / 識別子 / ファイルパス。
  // 文字集合を [A-Za-z0-9._/$-] に限定し、literal 一致専用 (regex 化しない)。
  const candidateRe = /[A-Za-z0-9_$][A-Za-z0-9._/$-]{2,}/g;
  const matches = text.match(candidateRe) ?? [];

  const isCodeLike = (t: string): boolean => {
    // ドット or スラッシュ or アンダースコア を含む、もしくは内部に大文字の山がある
    // (camelCase/PascalCase)。いずれも無い純粋な小文字英単語は除外 (= 散文ノイズ)。
    if (/[._/]/.test(t)) return true;
    if (/[a-z][A-Z]/.test(t)) return true; // readFileSync, ensureSafePath
    return false;
  };

  for (const raw of matches) {
    // 前後の区切り文字を剥がす (".foo." → "foo")。
    const t = raw.replace(/^[._/$-]+/, '').replace(/[._/$-]+$/, '');
    if (t.length < MIN_TERM_LEN || t.length > MAX_TERM_LEN) continue;
    if (!isCodeLike(t)) continue;
    if (seen.has(t)) continue;
    seen.add(t);
    out.push(t);
    if (out.length >= MAX_TERMS) break;
  }
  return out;
}

/** 走査ルート配下の対象テキストファイルを再帰列挙する (bounded, 除外規則適用)。 */
function listTextFiles(root: string, opts: Required<ScannerOptions>): { files: string[]; truncated: boolean } {
  const files: string[] = [];
  const stack: string[] = [root];

  while (stack.length > 0) {
    const dir = stack.pop() as string;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue; // 読めないディレクトリはスキップ (best-effort)
    }
    for (const ent of entries) {
      const full = path.join(dir, ent.name);
      if (ent.isSymbolicLink()) continue; // symlink は辿らない (脱出/循環防止)
      if (ent.isDirectory()) {
        if (EXCLUDED_DIRS.has(ent.name)) continue;
        stack.push(full);
        continue;
      }
      if (!ent.isFile()) continue;
      if (isSecretFile(ent.name)) continue;
      if (!TEXT_EXTENSIONS.has(path.extname(ent.name).toLowerCase())) continue;
      files.push(full);
      if (files.length >= opts.maxFiles) return { files, truncated: true };
    }
  }
  return { files, truncated: false };
}

/**
 * 走査ルートのテキストファイルを **1 度だけ** プリロードし、以後 finding ごとの
 * literal 一致を in-memory で行う scanner を返す。finding が複数あっても fs 走査は 1 回。
 */
export function buildRepoScanner(root: string, options: ScannerOptions = {}): RepoScanner {
  const opts: Required<ScannerOptions> = {
    maxFiles: options.maxFiles ?? DEFAULT_MAX_FILES,
    maxTotalBytes: options.maxTotalBytes ?? DEFAULT_MAX_TOTAL_BYTES,
    maxFileBytes: options.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES,
  };

  const loaded: Array<{ rel: string; lines: string[] }> = [];
  let totalBytes = 0;

  const { files, truncated: listTruncated } = listTextFiles(root, opts);
  let truncated = listTruncated;

  for (const full of files) {
    if (totalBytes >= opts.maxTotalBytes) { truncated = true; break; }
    let stat: fs.Stats;
    try { stat = fs.statSync(full); } catch { continue; }
    if (stat.size > opts.maxFileBytes) continue;
    let content: string;
    try { content = fs.readFileSync(full, 'utf8'); } catch { continue; }
    if (content.indexOf(NUL_CHAR) !== -1) continue; // NUL を含む = バイナリ混入をスキップ
    totalBytes += stat.size;
    loaded.push({ rel: path.relative(root, full).split(path.sep).join('/'), lines: content.split('\n') });
  }

  const find = (terms: string[]): EvidenceHit[] => {
    const hits: EvidenceHit[] = [];
    const perTerm = new Map<string, number>();
    const filtered = terms.filter(t => t.length >= MIN_TERM_LEN && t.length <= MAX_TERM_LEN);
    if (filtered.length === 0) return hits;
    for (const { rel, lines } of loaded) {
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        for (const term of filtered) {
          if ((perTerm.get(term) ?? 0) >= MAX_HITS_PER_TERM) continue;
          if (line.includes(term)) {
            hits.push({ file: rel, line: i + 1, term });
            perTerm.set(term, (perTerm.get(term) ?? 0) + 1);
            if (hits.length >= MAX_HITS_TOTAL) return hits;
          }
        }
      }
    }
    return hits;
  };

  return { find, filesLoaded: loaded.length, truncated };
}

/**
 * 判定 LLM の prompt に載せる grep 証拠セクション (trusted な所在ヒント)。
 * **行内容は無く file:line と一致語のみ**である旨を明示する (LLM に「確証」と誤認
 * させない / content が無いことを伝える)。
 */
export function formatEvidenceForPrompt(hits: EvidenceHit[]): string {
  if (hits.length === 0) {
    return '(対象リポ内に finding 由来の識別子の一致候補は見つからなかった)';
  }
  const byTerm = new Map<string, string[]>();
  for (const h of hits) {
    const list = byTerm.get(h.term) ?? [];
    if (list.length < MAX_HITS_PER_TERM) list.push(`${h.file}:${h.line}`);
    byTerm.set(h.term, list);
  }
  const lines = Array.from(byTerm.entries()).map(([term, locs]) => `- "${term}" → ${locs.join(', ')}`);
  return [
    '注: これは「finding の識別子が対象リポのどこに出現するか」の所在候補のみ。',
    '行の内容は含まない。出現 = 脆弱性の確証ではなく、人手確認の起点に過ぎない。',
    ...lines,
  ].join('\n');
}

/**
 * 下書きノートの末尾に付ける「候補 file:line」(<=maxItems 件、重複除去)。
 * **LLM 出力ではなく決定的に付加**するため、note の truncation に巻き込まれない。
 */
export function formatCandidatesForNote(hits: EvidenceHit[], maxItems = 3): string {
  if (hits.length === 0) return '';
  const seen = new Set<string>();
  const locs: string[] = [];
  for (const h of hits) {
    const loc = `${h.file}:${h.line}`;
    if (seen.has(loc)) continue;
    seen.add(loc);
    locs.push(loc);
    if (locs.length >= maxItems) break;
  }
  return ` | 候補(要確認): ${locs.join(', ')}`;
}
